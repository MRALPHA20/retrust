"""ReTrust V1 exposure: evidence-based T x A x H x U with explicit bounds.

Unknown factors are intervals, never guessed fractions. Network topology is
required context; it cannot establish whether an attack path is reachable.
Duplicate advisory records are grouped by CVE unless an explicit reviewed
path ID is supplied. A reviewed group uses its greatest contribution, keeping
repeated evidence from manufacturing independent attack paths.
"""

from dataclasses import dataclass, field
from . import cvss

CONSEQUENCES = {
    'safety': ('Safety or environmental harm', 1.0),
    'control': ('Major loss of process control', .8),
    'recoverable': ('Significant but recoverable disruption', .5),
    'minor': ('Minor operational disruption', .2),
    'negligible': ('No material operational consequence', 0.0),
}
PREREQUISITES = {
    'satisfiable': ('An attacker can satisfy them', 1.0),
    'unsatisfiable': ('Verified impossible in this threat model', 0.0),
    'unknown': ('Not established', None),
}
INTERFACES = {
    'exposed': ('Reachable', 1.0),
    'blocked': ('Verified blocked across all relevant paths', 0.0),
    'unknown': ('Not established', None),
}
REMEDIATIONS = {
    'affected': ('Confirmed affected, not fixed', 1.0),
    'applied': ('Fix verified present on this firmware', 0.0),
    'not_affected': ('Selected product and firmware verified not affected', 0.0),
    'mitigated': ('Protective control present; applicability still needs checking', None),
    'available': ('Fix exists but is not applied', 1.0),
    'planned': ('Remediation planned, not implemented', None),
    'unknown': ('Not established or under investigation', None),
}
ASSESSMENT_TYPES = {'purchase': 'New equipment purchase', 'installed': 'Installed asset'}
CONCENTRATION = (1.0, .20, .10)


@dataclass(frozen=True)
class Bounds:
    low: float
    high: float

    @property
    def resolved(self):
        return abs(self.high - self.low) < 1e-12

    def values(self):
        return [self.low, self.high]


@dataclass
class Exposure:
    safety_min: float
    safety_max: float
    coverage: float
    paths: list = field(default_factory=list)
    missing: list = field(default_factory=list)
    evidence: list = field(default_factory=list)

    @property
    def provisional(self):
        return bool(self.missing)


def _probability(value):
    if value is None:
        return None
    value = float(value)
    if not 0 <= value <= 1:
        raise ValueError('Threat estimates must be between 0 and 1')
    return value


def threat(finding):
    """Maximum available KEV, LEV and EPSS; None means no source is available."""
    kev = 1.0 if finding.in_kev or finding.ransomware else (
        0.0 if getattr(finding, 'kev_available', True) else None)
    available = [v for v in (kev, _probability(finding.lev), _probability(finding.epss))
                 if v is not None]
    return max(available) if available else None


def threat_bounds(finding):
    value = threat(finding)
    if value == 1:
        return Bounds(1, 1)
    complete = (getattr(finding, 'kev_available', True)
                and finding.lev is not None and finding.epss is not None)
    return Bounds(value or 0.0, value if complete else 1.0)


def impact(finding, consequence=None):
    """Declared credible OT consequence; CVSS severity is recorded separately."""
    if consequence is None:
        return None
    if consequence not in CONSEQUENCES:
        raise ValueError('Unknown operational consequence')
    return CONSEQUENCES[consequence][1]


def demands_conditions(vector):
    if vector is None:
        return None
    # A missing prerequisite metric is unresolved, rather than "no conditions".
    if (vector.privileges not in (None, 'none')
            or vector.interaction not in (None, 'none')
            or vector.requirements == 'present' or vector.complexity == 'high'):
        return True
    if (vector.privileges is None or vector.interaction is None
            or (vector.version.startswith('4') and vector.requirements is None)):
        return None
    return False


def reach_bounds(finding, interface='unknown', network=None, prerequisites='unknown'):
    if interface not in INTERFACES or prerequisites not in PREREQUISITES:
        raise ValueError('Unknown reachability or prerequisite status')
    if interface == 'blocked':
        return Bounds(0, 0)
    vector = cvss.parse(finding.vector) if finding.vector else None
    conditions = demands_conditions(vector)
    if conditions is True and prerequisites == 'unsatisfiable':
        return Bounds(0, 0)
    if interface == 'exposed' and (conditions is False or prerequisites == 'satisfiable'):
        return Bounds(1, 1)
    return Bounds(0, 1)


def reach(finding, interface='unknown', network=None, prerequisites='unknown'):
    """Conservative endpoint; use reach_bounds to retain unresolved evidence."""
    return reach_bounds(finding, interface, network, prerequisites).high


def applicability_bounds(finding, assessment_type='purchase', remediation='unknown'):
    if remediation not in REMEDIATIONS:
        raise ValueError('Unknown firmware applicability status')
    if remediation in ('applied', 'not_affected'):
        return Bounds(0, 0)
    if remediation in ('affected', 'available') or finding.decided:
        return Bounds(1, 1)
    return Bounds(0, 1)


def applicability(finding, assessment_type='purchase', remediation='unknown'):
    return applicability_bounds(finding, assessment_type, remediation).high


def factors(finding, consequence=None, interface='unknown', assessment_type='purchase',
            remediation='unknown', network=None, prerequisites='unknown'):
    review = getattr(finding, 'review', {}) or {}
    # Finding-specific reviews take precedence over product-wide assertions.
    consequence = review.get('consequence', consequence)
    interface = review.get('interface', interface)
    prerequisites = review.get('prerequisites', prerequisites)
    remediation = review.get('remediation', remediation)
    h = impact(finding, consequence)
    return {'T': threat_bounds(finding),
            'A': reach_bounds(finding, interface, network, prerequisites),
            'H': Bounds(0, 1) if h is None else Bounds(h, h),
            'U': applicability_bounds(finding, assessment_type, remediation)}


def risk_bounds(finding, consequence=None, interface='unknown', assessment_type='purchase',
                remediation='unknown', network=None, prerequisites='unknown'):
    values = factors(finding, consequence, interface, assessment_type, remediation, network, prerequisites)
    low = high = 1.0
    for bounds in values.values():
        low *= bounds.low
        high *= bounds.high
    return Bounds(low, high)


def risk(finding, consequence=None, interface='unknown', assessment_type='purchase',
         remediation='unknown', network=None, prerequisites='unknown'):
    """Conservative Z endpoint; unresolved factors are preserved in risk_bounds."""
    return risk_bounds(finding, consequence, interface, assessment_type, remediation,
                       network, prerequisites).high


def concentrate(risks):
    risks = list(risks)
    if any(not 0 <= value <= 1 for value in risks):
        raise ValueError('Path contributions must be between 0 and 1')
    return min(1.0, sum(w * z for w, z in zip(CONCENTRATION, sorted(risks, reverse=True))))


def analyse(findings, consequence=None, interface='unknown', assessment_type='purchase',
            remediation='unknown', network=None, prerequisites='unknown'):
    if not findings:
        return Exposure(100, 100, 0, evidence=['No advisory findings to measure; absence is not proof of safety'])
    groups = {}
    missing = set()
    unresolved = {name: set() for name in ('T', 'A', 'H', 'U')}
    measured = total = 0
    for finding in findings:
        values = factors(finding, consequence, interface, assessment_type, remediation, network, prerequisites)
        z = risk_bounds(finding, consequence, interface, assessment_type, remediation, network, prerequisites)
        key = getattr(finding, 'path_id', None) or finding.cve
        group = groups.setdefault(key, {'path_id': key, 'grouping': 'reviewed path' if getattr(finding, 'path_id', None) else 'CVE review unit',
                                       'cves': set(), 'advisories': set(), 'z_min': 0, 'z_max': 0, 'inputs': []})
        group['cves'].add(finding.cve)
        group['advisories'].add(finding.advisory_id)
        group['z_min'] = max(group['z_min'], z.low)
        group['z_max'] = max(group['z_max'], z.high)
        measured += sum(v.resolved for v in values.values())
        total += 4
        absent = [name for name, bounds in values.items() if not bounds.resolved]
        if not z.resolved:
            for name in absent:
                unresolved[name].add(finding.cve)
        group['inputs'].append({'cve': finding.cve, 'advisory': finding.advisory_id,
                                'factors': {name: bounds.values() for name, bounds in values.items()},
                                'missing': absent, 'kev': bool(finding.in_kev),
                                'kev_available': getattr(finding, 'kev_available', True),
                                'lev': finding.lev, 'epss': finding.epss,
                                'cvss_vector': finding.vector, 'cvss_severity': finding.cvss,
                                'firmware_range': finding.version_range, 'version_checked': finding.decided,
                                'review': dict(getattr(finding, 'review', {}) or {}),
                                'source_dates': dict(getattr(finding, 'source_dates', {}) or {})})
    labels = {
        'T': 'Exploitation data is incomplete; refresh or review the threat sources',
        'A': 'Ask the network owner whether an attacker can reach the weakness and meet its requirements',
        'H': 'Ask an operations engineer what exploiting each weakness could do to the process',
        'U': 'Confirm the exact firmware and whether the published fixes are installed',
    }
    for name, cves in unresolved.items():
        if cves:
            sample = ', '.join(sorted(cves)[:3])
            more = f' and {len(cves)-3} more' if len(cves) > 3 else ''
            missing.add(f'{labels[name]} ({sample}{more})')
    if network is None:
        missing.add('Network context has not been supplied')
    paths = []
    for group in groups.values():
        group['cves'] = sorted(group['cves'])
        group['advisories'] = sorted(group['advisories'])
        paths.append(group)
    paths.sort(key=lambda p: (-p['z_max'], p['path_id']))
    r_min = concentrate([p['z_min'] for p in paths])
    r_max = concentrate([p['z_max'] for p in paths])
    evidence = ['R = min(1, Z1 + 0.20 Z2 + 0.10 Z3)',
                f'{len(paths)} review unit(s) across {len(findings)} advisory finding(s); duplicate advisories count once per unit',
                'Default units are CVEs; independence of different CVEs is not established by this grouping',
                f'Exposure safety range: {100*(1-r_max):.1f}–{100*(1-r_min):.1f}/100',
                f'Network context: {network or "Unknown"}; topology alone does not prove reachability',
                'T = max(KEV, LEV, EPSS); A is verified reachability; H is declared credible OT consequence; U is unremediated applicability']
    if missing:
        evidence.append('Verify unresolved inputs before using the result as a purchase recommendation')
    return Exposure(100*(1-r_max), 100*(1-r_min), measured/total, paths, sorted(missing), evidence)


def measure(findings, consequence=None, interface='unknown', assessment_type='purchase',
            remediation='unknown', network=None, prerequisites='unknown'):
    result = analyse(findings, consequence, interface, assessment_type, remediation, network, prerequisites)
    return result.safety_min, result.coverage, result.evidence


def worst(findings, consequence=None, interface='unknown', assessment_type='purchase',
          remediation='unknown', network=None, prerequisites='unknown'):
    result = analyse(findings, consequence, interface, assessment_type, remediation, network, prerequisites)
    return max((p['z_max'] for p in result.paths), default=None)
