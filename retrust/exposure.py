"""Concentrated exposure: judge a product by its worst few flaws, not its average.

A weighted mean over every finding has a structural problem for a buyer: a
product with one catastrophic flaw and forty minor ones averages out like a
product with forty-one middling ones. Averaging is exactly what a purchase
decision least wants, because the decision turns on the worst thing that can
happen, not the typical thing.

So exposure is built per finding and then concentrated:

    z = T' x A x H x U        one number per vulnerability, 0-1, higher is worse
    T' = 0.40 + 0.60 T        threat amplifies, it never zeroes the rest
    R = min(1, z1 + 0.20 z2 + 0.10 z3)
    E = 100 (1 - R)           0-100, higher is safer

    T  threat         ransomware, KEV, LEV and EPSS -- the strongest of them.
                      Evidence; never asked. Mapped onto [0.40, 1] so an
                      unexploited critical still counts.
    A  reachability   how far the flaw's own CVSS vector gets an attacker,
                      narrowed by what the operator has verified about the
                      interface. A buyer's claim can only ever narrow it.
    H  impact         the flaw's own CVSS severity, scaled by what a compromise
                      would cost this process. The operator knows the second
                      half and ReTrust cannot, so it is asked -- and with
                      nothing declared the severity stands undiscounted.
    U  applicability  does the flaw still apply to the firmware being bought
                      or run. "A fix exists" and "the fix is on the box" are
                      different facts and must not score alike.

R sums the worst path at full weight with two discounted further paths. The
leading coefficient is 1.00, not the 0.70 this previously used, and that fix
matters in both directions:

ONE path. At 0.70 z1 a single maximal flaw -- reachable, unfixed, confirmed
exploited, process-ending -- produced E = 30 rather than 0, because 30% of the
score was being reserved for flaws the product did not happen to have. Credit
for absent vulnerabilities is the one case a buyer most needs us to get right.

MANY paths, which is the normal case. A real device has several routes in, so
the second and third add on top of the first rather than diluting it.

Two consequences are deliberate and worth stating, because both cost something:

  * R clips at 1, so a product with three severe paths reaches exactly
    E = 0.0 and stops being distinguishable from a worse one. 5.7% of a
    representative 582-product sample lands there, including three of the
    five demo devices -- Moxa EDS-405A, Rockwell ControlLogix and Schneider
    M340 all clip, leaving them separated only by the other three pillars.
    Below E = 0 there is no ranking.
  * Only three paths are counted. Three severe flaws and three hundred score
    alike. An earlier revision added `+ 0.10 mean(the rest)` inside the min
    for exactly this reason; it is one term to restore if breadth should count
    again, and TAIL_WEIGHT is kept for that. Note it does not address the
    clipping above -- an extra positive term can only reach the ceiling
    sooner. Separating the worst products needs a form that does not clip.

Both follow from the specified formula rather than from an oversight.

Every rubric value below is a declared starting point to validate against
labelled OT incidents, not an established standard. They are named constants
for exactly that reason.
"""

from . import cvss

# What a compromise would cost the process. Operator judgement: ReTrust has no
# way to know a plant's consequences, so it asks rather than assuming them.
CONSEQUENCES = {
    "safety":      ("Safety or environmental harm", 1.0),
    "control":     ("Major loss of process control", 0.8),
    "recoverable": ("Significant but recoverable disruption", 0.5),
    "minor":       ("Minor operational disruption", 0.2),
    "negligible":  ("Negligible operational effect", 0.0),
}

# What the operator has established about reaching the vulnerable interface.
# This only ever narrows what the CVSS vector already claims -- saying
# "blocked" cannot make a flaw more reachable than its own vector says.
INTERFACES = {
    "exposed": ("Reachable", 1.00),
    "blocked": ("Verified blocked", 0.10),
    "unknown": ("Not established", 1.00),
}

# How the firmware under assessment stands against a finding that has a fix.
REMEDIATIONS = {
    "applied":   ("Fix verified present on this firmware", 0.0),
    "mitigated": ("Compensating control implemented and verified", 0.4),
    "available": ("Fix exists but is not applied", 1.0),
    "planned":   ("Remediation planned, not implemented", 1.0),
    "unknown":   ("Not established", 1.0),
}

ASSESSMENT_TYPES = {
    "purchase":  "New equipment purchase",
    "installed": "Installed asset",
}

# How far the CVSS attack vector gets an attacker on its own.
VECTOR_REACH = {"network": 1.0, "adjacent": 0.6, "local": 0.3, "physical": 0.1}

# Where the device sits, as the operator reports it. Folded into reachability
# rather than scored as its own pillar: a deployment an attacker cannot route
# to makes a flaw less reachable, which is the same statement A already makes.
# Counting it twice would double the influence of one declared fact.
NETWORK_REACH = {"isolated": 0.3, "it_ot": 0.7, "internet_ot": 1.0}

# A vector we could not read is not evidence of either extreme.
UNRATED_REACH = 0.6

# No KEV entry and no modelled estimate at all. The corpus median EPSS is
# 0.007, so absent exploitation signal means low -- but not zero, because
# absence of evidence of exploitation is not evidence of its absence.
UNRATED_THREAT = 0.10

# Confirmed exploitation, short of ransomware use. An observation, so it
# outranks any model: no estimate may be read as more certain than a sighting.
KEV_THREAT = 0.90

# The most a model may claim on its own. LEV and EPSS are estimates, and the
# gap to 1.0 is the room kept for the evidence that would confirm them.
MODEL_CEILING = 0.80

# Threat amplifies; it does not decide alone. EPSS is a 30-day probability and
# its OT median is 0.007, so multiplying by it raw collapsed every unexploited
# flaw to nothing -- a critical, reachable, unfixed vulnerability scored as
# harmless because nobody had attacked it yet. T is therefore mapped onto
# [FLOOR, 1]: a published OT flaw always carries weight, and confirmed
# exploitation multiplies it up to full.
THREAT_FLOOR = 0.40

# A finding with no CVSS at all. Published but unrated is not harmless, and not
# a crisis either; the old severity pillar called the same gap neutral.
UNRATED_IMPACT = 0.65

# The concentration weights. The leading 1.00 is the fix described above: the
# worst path counts in full, so a lone maximal flaw can reach E = 0.
CONCENTRATION = (1.00, 0.20, 0.10)

# Unused by `concentrate` under the specified formula, which counts three paths
# and no more. Kept named because restoring breadth is a one-term change --
# `+ TAIL_WEIGHT * mean(ordered[3:])` inside the min -- and a reader comparing
# this against the earlier model needs to find the constant it referred to.
TAIL_WEIGHT = 0.10


def threat(finding):
    """T: is this being exploited? The strongest signal, read from evidence.

    Four sources, and the maximum rather than a blend. KEV and ransomware use
    are observations; LEV estimates whether exploitation has already happened;
    EPSS forecasts the next thirty days. They do not share a horizon, so
    averaging them is meaningless -- and it would let a model talk down
    something somebody watched happen. Taking the strongest is the composite
    the LEV paper itself specifies, and `lev.Estimate.composite` has computed
    it for the LEV report since before it reached the score.

    LEV is the signal this deliberately adds. Its corpus median is 0.167
    against EPSS's 0.007, so for the great majority of OT findings it is the
    only non-trivial exploitation evidence that exists.
    """
    if finding.ransomware:
        return 1.0
    if finding.in_kev:
        return KEV_THREAT
    modelled = [v for v in (finding.lev, finding.epss) if v is not None]
    if not modelled:
        return UNRATED_THREAT
    return min(MODEL_CEILING, max(modelled))


def impact(finding, consequence=None):
    """H: what the flaw itself permits, scaled by what it would cost this process.

    Two things, deliberately. The reviewer's H is the operator's process
    consequence, but a single plant-wide class cannot distinguish a flaw that
    crashes a web page from one that rewrites ladder logic -- the review says
    as much. So severity carries the per-finding half, and the declared
    consequence scales it. With nothing declared the flaw's own severity stands
    undiscounted, which is the conservative reading and is reported as such.
    """
    severity = (finding.cvss / 10.0) if finding.cvss is not None else UNRATED_IMPACT
    if consequence is None:
        return severity
    return severity * CONSEQUENCES[consequence][1]


def reach(finding, interface="unknown", network=None):
    """A: what the flaw's own vector allows, narrowed by where it is deployed.

    Both operator inputs can only narrow: the vector sets the ceiling, and a
    buyer's claim about their plant never raises it.
    """
    vector = cvss.parse(finding.vector) if finding.vector else None
    base = VECTOR_REACH.get(vector.attack_vector, UNRATED_REACH) if vector \
        else UNRATED_REACH
    return (base * INTERFACES.get(interface, INTERFACES["unknown"])[1]
            * NETWORK_REACH.get(network, 1.0))


def applicability(finding, assessment_type="purchase", remediation="unknown"):
    """U: does this still apply to the firmware being bought or run?

    Patch availability belongs to P, not U. Only an explicit operator
    assertion that every in-scope finding is fixed or mitigated changes U;
    buying a product that has a fix available does not assume it will ship.
    """
    if remediation in ("applied", "mitigated"):
        return REMEDIATIONS[remediation][1]
    return 1.0


def risk(finding, consequence=None, interface="unknown",
         assessment_type="purchase", remediation="unknown", network=None):
    """z for one finding, 0-1, higher is worse."""
    amplified = THREAT_FLOOR + (1.0 - THREAT_FLOOR) * threat(finding)
    return (amplified * reach(finding, interface, network)
            * impact(finding, consequence)
            * applicability(finding, assessment_type, remediation))


def concentrate(risks):
    """R: the worst path at full weight, plus two discounted further paths.

    Missing paths contribute nothing, so a product with one finding scores
    that finding -- which is the whole point of the leading 1.00.
    """
    if not risks:
        return 0.0
    ordered = sorted(risks, reverse=True)
    return min(1.0, sum(weight * value
                        for weight, value in zip(CONCENTRATION, ordered)))


def measure(findings, consequence=None, interface="unknown",
            assessment_type="purchase", remediation="unknown", network=None):
    """The E term as (score, coverage, evidence).

    Coverage says how much of this rests on evidence rather than on a declared
    assumption, so a reader can see that an unanswered consequence question is
    the reason a number looks harsh.
    """
    if not findings:
        return 100.0, 0.0, ["no advisory findings to measure"]

    risks = [risk(f, consequence, interface, assessment_type, remediation,
                  network) for f in findings]
    worst = concentrate(risks)
    score = 100.0 * (1.0 - worst)

    ordered = sorted(zip(risks, findings), key=lambda pair: -pair[0])
    evidence = [
        "worst " + ", ".join(f"{f.cve} {z:.2f}" for z, f in ordered[:3]),
        f"exposure concentrated on the worst {min(3, len(risks))} of "
        f"{len(risks)} finding(s)" + (
            f", with {len(risks) - 3} more in the tail" if len(risks) > 3 else ""),
    ]

    # Coverage: the two terms ReTrust reads itself are always measured; the two
    # the operator supplies are not, and that is said rather than hidden.
    remediation_measured = remediation in ("applied", "mitigated", "available")
    measured = 2 + (consequence is not None) + remediation_measured
    if consequence is None:
        evidence.append(
            "process consequence not supplied, so exposure is shown at full "
            "impact -- declare it to narrow this")
    else:
        evidence.append(f"consequence: {CONSEQUENCES[consequence][0]}")
    if network is not None:
        evidence.append(f"deployment: {network} (operator-reported, unverified)")
    if interface != "unknown":
        evidence.append(f"interface: {INTERFACES[interface][0]}")
    if remediation != "unknown":
        evidence.append(f"remediation: {REMEDIATIONS[remediation][0]}")
    evidence.append(f"assessed as: {ASSESSMENT_TYPES.get(assessment_type, assessment_type)}")
    return score, measured / 4.0, evidence
