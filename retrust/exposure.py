"""ReTrust V1 exposure: evidence-based T x A x H x U with explicit bounds.

Unknown factors are intervals, never guessed fractions. Network topology is
required context; it cannot establish whether an attack path is reachable.
Duplicate advisory records are grouped by CVE unless an explicit reviewed
path ID is supplied. A reviewed group uses its greatest contribution, keeping
repeated evidence from manufacturing independent attack paths.
"""

from dataclasses import dataclass, field
from . import cvss

# Plain answers a buyer can give without a glossary. The wording is the only
# thing that changed here: the rubric values are the specification's.
CONSEQUENCES = {
    'safety': ('Someone could be hurt, or the environment harmed', 1.0),
    'control': ('We would lose control of the process', .8),
    'recoverable': ('Production stops, but we can recover', .5),
    'minor': ('Minor disruption we can work around', .2),
    'negligible': ('No real effect on the process', 0.0),
}
# The specification groups "Yes" with "No additional requirements" as one
# answer, because both mean the same thing for A: nothing stands in the way.
# Splitting them left a buyer with no way to say a weakness needs nothing.
PREREQUISITES = {
    'satisfiable': ('Yes, or it needs nothing extra', 1.0),
    'unsatisfiable': ('No, we checked and they could not', 0.0),
    'unknown': ('Not sure', None),
}
INTERFACES = {
    'exposed': ('Yes, something could reach it', 1.0),
    'blocked': ('No, we checked every route and blocked them', 0.0),
    'unknown': ('Not sure', None),
}
REMEDIATIONS = {
    'affected': ('Affected, and not fixed', 1.0),
    'applied': ('We installed the fix and checked it', 0.0),
    'not_affected': ('The maker says this version is not affected', 0.0),
    'mitigated': ('We added a protection, but have not checked it covers this', None),
    'available': ('A fix exists, but we have not installed it', 1.0),
    'planned': ('We plan to fix it, but have not yet', None),
    'unknown': ('Not sure, or still checking', None),
}
ASSESSMENT_TYPES = {'purchase': 'Buying it', 'installed': 'Already installed'}
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
    # Declared answers that could not apply to every finding. An answer the
    # tool quietly ignores is worse than one it refuses: the operator believes
    # they have ruled something out when they have not.
    inapplicable: list = field(default_factory=list)
    # False when a declared answer bore on nothing at all, so a caller can
    # decline to cite it as a reason the verdict holds.
    prerequisites_applied: bool = True

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


# The spec's step A1: read the flaw's own attack vector first, because it
# decides WHICH question establishes reachability. "The affected service is
# reachable" is an answer about the network; it cannot establish that an
# attacker has the local execution or the physical contact that an AV:L or
# AV:P flaw additionally requires.
REMOTE_VECTORS = ('network', 'adjacent')


def reach_bounds(finding, interface='unknown', network=None, prerequisites='unknown'):
    if interface not in INTERFACES or prerequisites not in PREREQUISITES:
        raise ValueError('Unknown reachability or prerequisite status')
    if interface == 'blocked':
        return Bounds(0, 0)
    vector = cvss.parse(finding.vector) if finding.vector else None
    conditions = demands_conditions(vector)
    if conditions is True and prerequisites == 'unsatisfiable':
        return Bounds(0, 0)
    # "The affected service is reachable" settles a NETWORK question, so on its
    # own it resolves only a remotely-reachable flaw. A local or physical flaw
    # additionally needs execution on the box or hands on the cabinet, and the
    # network answer says nothing about either -- without that, an AV:P flaw
    # would score exactly like an unauthenticated remote one. An explicit
    # "the attacker can meet what this weakness requires" does cover that
    # access, so it still resolves any vector.
    remotely_reachable = vector is None or vector.attack_vector in REMOTE_VECTORS
    if interface == 'exposed' and (
            prerequisites == 'satisfiable'
            or (conditions is False and remotely_reachable)):
        return Bounds(1, 1)
    return Bounds(0, 1)


def reach(finding, interface='unknown', network=None, prerequisites='unknown'):
    """Conservative endpoint; use reach_bounds to retain unresolved evidence."""
    return reach_bounds(finding, interface, network, prerequisites).high


def applicability_bounds(finding, assessment_type='purchase', remediation='unknown'):
    if remediation not in REMEDIATIONS:
        raise ValueError('Unknown firmware applicability status')
    if remediation in ('applied', 'not_affected'):
        # The spec's U table zeroes a SELECTED version verified patched or
        # not affected, so the claim needs a selected firmware -- and
        # `decided` is emphatically not that test. `match.findings` drops
        # every finding whose range excludes the supplied version, so a
        # surviving finding with decided=True is one the range check says IS
        # affected. Gating the claim on it made the proof of affectedness the
        # licence for believing the device was patched: an internet-exposed,
        # safety-critical, CVSS 10.0, confirmed-affected device read PREFER
        # 99.2. The honest test is whether a firmware was named at all.
        # Three cases, and only one of them resolves:
        #   no firmware named        -> the claim is about nothing; unresolved
        #   named, range says AFFECTED -> our own evidence contradicts the
        #                               claim; refuse to pick a side silently
        #   named, range not decided -> nothing contradicts it; honour it
        if finding.version_supplied and not finding.decided:
            return Bounds(0, 0)
        return Bounds(0, 1)
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
    # A reviewed path id must claim EVERY record of its CVEs: grouping by
    # "path_id or cve" alone would split one CVE into two units when a reviewer
    # tagged only some of its advisory records, and the same flaw would then
    # enter R twice as Z1 + 0.20 Z2.
    reviewed = {f.cve: f.path_id for f in findings if getattr(f, 'path_id', None)}
    for finding in findings:
        values = factors(finding, consequence, interface, assessment_type, remediation, network, prerequisites)
        z = risk_bounds(finding, consequence, interface, assessment_type, remediation, network, prerequisites)
        key = getattr(finding, 'path_id', None) or reviewed.get(finding.cve) or finding.cve
        group = groups.setdefault(key, {'path_id': key, 'grouping': 'reviewed path' if key != finding.cve else 'CVE review unit',
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
    # Each item names the question that closes it, in the words the form uses,
    # so a buyer reading the checklist knows exactly where to go. The T item is
    # the exception and says so: no answer from the owner can supply missing
    # exploitation data, only a feed refresh can.
    labels = {
        'T': 'Exploitation data is missing for these. Refresh the data sources'
             ' -- this is not something you can answer',
        'A': 'Answer "Could anything reach it to attack it?" and "Would an'
             ' attacker need anything else first?" -- ask whoever runs the network',
        'H': 'Answer "If it were attacked, what is the worst that could happen?"'
             ' -- ask operations or safety',
        'U': 'Answer "Is the firmware you are getting already fixed?" -- and give'
             ' the exact firmware version',
    }
    if remediation in ('applied', 'not_affected'):
        disputed = sorted({f.cve for f in findings
                           if f.version_supplied and f.decided})
        if disputed:
            sample = ', '.join(disputed[:3])
            more = f' and {len(disputed)-3} more' if len(disputed) > 3 else ''
            missing.add(
                'The firmware you gave is inside the affected range published '
                f'for {sample}{more}, which contradicts "{REMEDIATIONS[remediation][0]}". '
                'Re-check the version, or ask the vendor to confirm the fix in writing')
    for name, cves in unresolved.items():
        if cves:
            sample = ', '.join(sorted(cves)[:3])
            more = f' and {len(cves)-3} more' if len(cves) > 3 else ''
            missing.add(f'{labels[name]} ({sample}{more})')
    if network is None:
        missing.add('Answer "Where will it sit?" -- recorded as context, and'
                    ' needed before a verdict is given')
    paths = []
    for group in groups.values():
        group['cves'] = sorted(group['cves'])
        group['advisories'] = sorted(group['advisories'])
        paths.append(group)
    paths.sort(key=lambda p: (-p['z_max'], p['path_id']))
    r_min = concentrate([p['z_min'] for p in paths])
    r_max = concentrate([p['z_max'] for p in paths])
    # "An attacker could not meet what this weakness requires" is a claim about
    # conditions. A weakness that demands none -- no privileges, no user
    # interaction, no attack requirement -- has nothing for that answer to rule
    # out, so it stays reachable and the answer is vacuous. Saying so matters:
    # the alternative is a report citing "verified impossible" among the
    # assertions SUPPORTING a high-exposure verdict, which reads backwards.
    inapplicable, prerequisites_applied = [], True
    if prerequisites == 'unsatisfiable':
        unconditioned = sorted({f.cve for f in findings
                                if demands_conditions(cvss.parse(f.vector)
                                                      if f.vector else None) is not True})
        conditioned = {f.cve for f in findings} - set(unconditioned)
        prerequisites_applied = bool(conditioned)
        if unconditioned:
            sample = ', '.join(unconditioned[:3])
            more = f' and {len(unconditioned)-3} more' if len(unconditioned) > 3 else ''
            inapplicable.append(
                f'{len(unconditioned)} of {len(groups)} weakness(es) need nothing'
                f' extra to exploit ({sample}{more}), so "an attacker could not'
                ' meet what it requires" does not apply to them and did not'
                ' reduce their reachability'
                + ('' if conditioned else
                   '. That answer changed nothing in this assessment'))

    evidence = ['R = min(1, Z1 + 0.20 Z2 + 0.10 Z3)',
                f'{len(paths)} review unit(s) across {len(findings)} advisory finding(s); duplicate advisories count once per unit',
                'Default units are CVEs; independence of different CVEs is not established by this grouping',
                f'Exposure safety range: {100*(1-r_max):.1f}–{100*(1-r_min):.1f}/100',
                f'Network context: {network or "Unknown"}; topology alone does not prove reachability',
                'T = max(KEV, LEV, EPSS); A is verified reachability; H is declared credible OT consequence; U is unremediated applicability']
    evidence.extend(inapplicable)
    if missing:
        evidence.append('Verify unresolved inputs before using the result as a purchase recommendation')
    return Exposure(100*(1-r_max), 100*(1-r_min), measured/total, paths, sorted(missing),
                    evidence, inapplicable, prerequisites_applied)


def measure(findings, consequence=None, interface='unknown', assessment_type='purchase',
            remediation='unknown', network=None, prerequisites='unknown'):
    result = analyse(findings, consequence, interface, assessment_type, remediation, network, prerequisites)
    return result.safety_min, result.coverage, result.evidence


def worst(findings, consequence=None, interface='unknown', assessment_type='purchase',
          remediation='unknown', network=None, prerequisites='unknown'):
    result = analyse(findings, consequence, interface, assessment_type, remediation, network, prerequisites)
    return max((p['z_max'] for p in result.paths), default=None)
