"""Turn findings into a procurement verdict.

Three layers, in this order:

    1. hard gates   a disqualifying fact (sanctions, an exploited unpatched CVE)
                    ends the assessment. Gates are not weighted terms, because a
                    weighted disqualifier can be averaged away by good scores.
    2. pillars      each scores 0-100 (higher is better) and reports how much
                    evidence it had, so a thin pillar says so instead of
                    defaulting to a confident middle.
    3. composite    a weighted PRODUCT of the pillars, shown as a band:

                        S = E^0.60 x P^0.20 x V^0.15 x C^0.05

                    Multiplicative, not a mean, so dangerous exposure cannot be
                    bought back with good vendor and certification scores --
                    the rule the gates enforce, applied to the weighted part.

Two rules keep this defensible:

  * We never score raw CVE counts. A vendor that discloses diligently would
    score worse than one that stays quiet, which is exactly backwards.
  * Every number carries the evidence it came from, so a reviewer can disagree
    with a weight without having to distrust the whole result.
"""

from dataclasses import dataclass, field
import hashlib
import json

from . import cvss, exposure as exposure_model, weakness

BANDS = [(70, "PREFER"), (40, "CONDITIONAL"), (0, "AVOID")]

# Bumped when a change to the maths would move a score, so an old vector is
# never silently re-read under new rules.
SCORING_VERSION = "RT4"


def vector(assessment_type="purchase", version=None, network_exposure=None,
           interface="unknown", consequence=None, remediation="unknown",
           snapshot="", prerequisites="unknown"):
    """A compact, reproducible record of the choices behind one score.

    Borrowed from CVSS: a result nobody can reproduce is an opinion. This
    records what the operator declared, what firmware was scored and which data
    snapshot answered, so the same string re-run on the same index gives the
    same verdict -- and a reviewer can see at a glance which facts were
    supplied and which were left unresolved.
    """
    parts = [SCORING_VERSION, f"AT:{assessment_type}"]
    for code, value in (("FW", version), ("NX", network_exposure),
                        ("IF", interface), ("PQ", prerequisites),
                        ("OC", consequence), ("RS", remediation),
                        ("DS", snapshot)):
        parts.append(f"{code}:{value if value else 'unset'}")
    return "/".join(parts)


def provenance_token(provenance):
    """Fingerprint the source-provenance rows attached to an assessment.

    This identifies the recorded source/count/capture metadata, not the full
    advisory database bytes. Reports retain the detailed rows alongside it.
    """
    rows = sorted((str(row.get("source", "")), str(row.get("detail", "")),
                   str(row.get("captured", ""))) for row in provenance or [])
    if not rows:
        return ""
    packed = json.dumps(rows, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(packed.encode("utf-8")).hexdigest()[:12]


@dataclass
class Pillar:
    name: str
    score: float            # 0-100, higher is better
    coverage: float         # 0-1, how much of the input carried usable evidence
    evidence: list = field(default_factory=list)
    scored: bool = True


@dataclass
class Assessment:
    product: str
    verdict: str
    score: float | None
    pillars: list = field(default_factory=list)
    gates: list = field(default_factory=list)
    findings_count: int = 0
    undecided_count: int = 0
    confidence: float = 0.0     # 0-1, from the evidence-quality pillar
    network_exposure: str | None = None
    # Distinct CVEs arriving from the vendor's own advisories against those
    # arriving in third-party component bundles, where per-CVE reachability
    # on the device was never established.
    first_party_count: int = 0
    third_party_count: int = 0
    # Facts that demand a human look but do not gate: a KEV-listed CVE inside
    # a component bundle is the canonical one. Rendered beside the gates.
    cautions: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    # (findings, advisories, certificates, gates) -- lets sensitivity re-score
    # this product under other weightings without redoing the lookups.
    inputs: tuple | None = None
    # A compact, reproducible record of the choices behind this score, so a
    # result can be re-run and disputed by somebody who was not there.
    vector: str = ""
    assessment_type: str = "purchase"
    consequence: str | None = None
    interface: str = "unknown"
    remediation: str = "unknown"
    prerequisites: str = "unknown"
    # The operator answers a banded verdict rests on, in the vocab tables'
    # own words. Empty for evidence-only verdicts. A reviewer reads this to
    # see exactly which unverifiable claims the band depends on.
    assertions: list = field(default_factory=list)
    # The highest single z behind this score. Reported because R clips at 1:
    # once three paths are severe enough every worse product reads E = 0, and
    # this is what still separates them.
    worst_risk: float | None = None
    score_min: float | None = None
    score_max: float | None = None
    exposure_min: float | None = None
    exposure_max: float | None = None
    provisional: bool = False
    verification: list = field(default_factory=list)
    paths: list = field(default_factory=list)


def _exploitation(findings):
    """Penalise confirmed and predicted exploitation, not volume.

    CISA KEV records exploitation seen in the wild; EPSS estimates its
    probability. On the CISA OT corpus the two agree sharply -- KEV-listed OT
    CVEs have a median EPSS around 0.70 against 0.007 overall -- so using both
    is a convergent signal rather than double counting.
    """
    if not findings:
        # No findings is absent evidence, not good news: coverage 0 excludes
        # this pillar from the composite instead of scoring silence as safety.
        return Pillar("Exploitation", 100.0, 0.0,
                      ["no advisory findings to measure"])

    kev = {f.cve for f in findings if f.in_kev}
    ransomware = {f.cve for f in findings if f.ransomware}
    scored = [f for f in findings if f.epss is not None]
    # KEV and ransomware are known for every finding, so the pillar always
    # measures something when findings exist; EPSS only sharpens it. Tying
    # coverage to EPSS alone would drop this (highest-weighted) pillar whenever
    # EPSS is NULL -- common on the OT corpus -- and renormalize the composite
    # onto the lower pillars, scoring a product with LESS data strictly lower.
    coverage = 1.0 if findings else 0.0

    penalty = 0.0
    evidence = []
    if kev:
        penalty += 45 + min(15, 3 * len(kev))
        evidence.append(f"{len(kev)} CVE(s) in CISA KEV (confirmed exploitation)")
    if ransomware:
        penalty += 15
        evidence.append(f"{len(ransomware)} linked to ransomware campaigns")

    if scored:
        peak = max(f.epss for f in scored)
        likely = {f.cve for f in scored if f.epss >= 0.1}
        penalty += 40 * peak
        evidence.append(f"peak EPSS {peak:.3f}")
        if likely:
            evidence.append(f"{len(likely)} CVE(s) with EPSS >= 0.10")
    else:
        evidence.append("no EPSS score for these CVEs; judged on KEV and "
                        "ransomware signals only")

    return Pillar("Exploitation", max(0.0, 100 - penalty), coverage, evidence)


def _severity(findings):
    """How bad is the worst flaw, and how common are bad flaws?

    Peak CVSS alone does not work here. Nearly every OT product has at least one
    9.8, so a "100 - peak * 10" rule scored 0 for almost everything and
    discriminated between nothing -- it acted as a flat penalty rather than a
    measurement. Sensitivity analysis made that obvious: the pillar returned
    0.0, 2.0, 0.0, 2.0 across four very different products.

    So severity combines two things a buyer would actually distinguish: how
    severe the worst issue is, and what share of this product's issues are
    critical. A product with one critical among forty is not the same risk as
    one where four in five are critical.
    """
    scored = [f for f in findings if f.cvss is not None]
    if not findings:
        return Pillar("Severity", 100.0, 0.0, ["no advisory findings to measure"])
    if not scored:
        return Pillar("Severity", 50.0, 0.0, ["no CVSS data; scored neutral"])

    peak = max(f.cvss for f in scored)
    critical = [f for f in scored if f.cvss >= 9.0]
    high = [f for f in scored if 7.0 <= f.cvss < 9.0]

    # CVSS below 4 is barely worth weighting; 10 is the ceiling.
    peak_share = min(1.0, max(0.0, (peak - 4.0) / 6.0))
    critical_share = len(critical) / len(scored)
    evidence = [f"highest CVSS {peak:.1f}",
                f"{len(critical)}/{len(scored)} rated critical (9.0+), {len(high)} high"]

    # How the flaw is reached matters as much as how bad it is. A 9.8 needing
    # physical access to a device in a locked cabinet is a different purchase
    # from a 9.8 reachable over the network with no credentials, and the base
    # score cannot tell those apart. Every score block in CISA's corpus carries
    # its vector, so this is read rather than assumed.
    vectors = [v for v in (cvss.parse(f.vector) for f in scored) if v]
    if vectors:
        reachable = [v for v in vectors if v.wormable]
        penalty = (55 * peak_share + 30 * critical_share
                   + 15 * len(reachable) / len(vectors))
        evidence.append(
            f"{len(reachable)}/{len(vectors)} reachable over the network with no "
            "credentials and no user action")
        if physical := sum(1 for v in vectors if v.attack_vector == "physical"):
            evidence.append(f"{physical} need physical access to the device")
    else:
        # An index built before vectors were stored weighs what it has, and says
        # so. Silently scoring reachability as zero would read as "none of these
        # are reachable", which is a claim about the product rather than the data.
        penalty = 60 * peak_share + 40 * critical_share
        evidence.append("no CVSS vectors in this index, so how the flaws are "
                        "reached was not weighed")

    return Pillar("Severity", max(0.0, 100 - penalty),
                  len(scored) / len(findings), evidence)


# Vendors that run a CSAF trusted provider of their own, verified via the BSI
# CSAF aggregator (wid.cert-bund.de) on 2026-09-27. Publishing machine-readable
# advisories yourself, rather than relying on CISA to republish, is real and
# checkable evidence of a functioning product-security programme.
CSAF_PUBLISHERS = {
    "siemens": "https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json",
    "schneider": "https://www.se.com/.well-known/csaf/provider-metadata.json",
    "abb": "https://psirt.abb.com/.well-known/csaf/provider-metadata.json",
    "hitachienergy": "https://aggregator.cert-bund.de/",
    "sick": "https://www.sick.com/.well-known/csaf/provider-metadata.json",
    "kunbus": "https://psirt.kunbus.com/.well-known/csaf/provider-metadata.json",
    "nozominetworks": "https://csaf.data.security.nozominetworks.com/provider-metadata.json",
}


def _vendor_practice(findings, advisories, vendor_key=None):
    """Reward observable disclosure behaviour, never advisory volume.

    Careful about what this can actually measure. Advisory *content* quality
    (does the CVE carry CVSS and a CWE?) looks appealing but is nearly constant
    on this corpus, because CISA normalises what it republishes -- so scoring it
    alone returned ~100 for every vendor and quietly added free points to
    products that deserved none.

    What does vary, and is genuinely the vendor's own doing, is whether they run
    a CSAF trusted provider themselves rather than leaving disclosure to CISA.
    """
    if not findings:
        return Pillar("Vendor practice", 50.0, 0.0,
                      ["no advisories to judge disclosure practice from"])

    with_cvss = sum(1 for f in findings if f.cvss is not None)
    with_cwe = sum(1 for f in findings if f.cwe)
    quality = (with_cvss / len(findings) + with_cwe / len(findings)) / 2
    # Coverage is how much of what this pillar reads was actually present. A
    # feed the registry knows about is itself evidence, so a vendor that
    # publishes always has coverage; otherwise it rides on the completeness of
    # the content. Hard-coding 1.0 let the pillar score a product whose
    # advisories carried neither CVSS nor CWE as though it had measured them.
    publishes = (vendor_key or "") in CSAF_PUBLISHERS
    coverage = 1.0 if publishes else (with_cvss + with_cwe) / (2 * len(findings))

    # The publisher list is drawn from the CSAF ecosystem's own registries
    # and is necessarily partial, so absence earns no penalty beyond missing
    # the bonus: quality of what WAS published carries the pillar.
    score = 70 * quality + (30 if publishes else 0)

    evidence = [
        f"{len(advisories)} advisor{'y' if len(advisories) == 1 else 'ies'} in this assessment",
        f"{with_cvss}/{len(findings)} advisory findings carry CVSS, {with_cwe}/{len(findings)} carry a CWE",
    ]
    evidence.append(
        "runs its own CSAF advisory feed" if publishes else
        "no self-published CSAF feed in this tool's registry list; absence here is not evidence of absence")
    return Pillar("Vendor practice", min(100.0, score), coverage, evidence)


def _evidence_quality(findings):
    """How much of this assessment rests on data we could actually read?

    Deliberately not a risk measure. It answers "how much should you trust the
    three pillars above?", which most tools leave implicit. A product whose
    version ranges we could not parse scores low here even if it looks clean --
    the right response is review, not confidence.
    """
    if not findings:
        return Pillar("Evidence quality", 50.0, 0.0,
                      ["nothing found, so there is nothing to corroborate"])

    decided = sum(1 for f in findings if f.decided)
    with_cvss = sum(1 for f in findings if f.cvss is not None)
    with_epss = sum(1 for f in findings if f.epss is not None)
    n = len(findings)
    quality = (decided / n + with_cvss / n + with_epss / n) / 3

    evidence = [
        f"{decided}/{n} version ranges checked against the firmware you gave"
        if decided else
        f"none of the {n} version ranges could be confirmed against firmware; "
        "supply or verify the version, and review these findings",
        f"{with_cvss}/{n} scored by the vendor, {with_epss}/{n} covered by EPSS",
    ]
    if 0 < decided < n:
        evidence.append(f"{n - decided} range(s) need manual review")
    return Pillar("Evidence quality", 100 * quality, quality, evidence)


def _patchability(findings):
    """Can the buyer actually fix what is wrong with this product?

    Two products with identical CVE lists are not equally risky if one ships
    vendor fixes and the other offers only workarounds. CSAF states this per
    vulnerability, so we read it rather than infer it.
    """
    if not findings:
        return Pillar("Patch availability", 100.0, 0.0,
                      ["no advisory findings to measure"])

    n = len(findings)
    fixed = sum(1 for f in findings if f.fixed)
    # CISA files some shipped patches under "mitigation"; Finding.fixed reads
    # the text. Said out loud so "0/10 have a vendor fix" is never printed
    # about a product the vendor fixed through a support channel.
    texted = sum(1 for f in findings
                 if f.fixed and f.remediation != "vendor_fix")
    workaround = sum(1 for f in findings if not f.fixed
                     and f.remediation in ("mitigation", "workaround"))
    none_available = sum(1 for f in findings
                         if not f.fixed and f.remediation == "none_available")
    known = fixed + workaround + none_available

    if not known:
        return Pillar("Patch availability", 50.0, 0.0,
                      ["advisories do not state remediation status"])

    # A vendor fix counts fully; a workaround counts part-way; nothing counts zero.
    score = 100 * (fixed + 0.4 * workaround) / known
    evidence = [f"{fixed}/{n} advisory findings have a vendor fix"]
    if texted:
        evidence.append(f"{texted} of those are filed as mitigations whose text"
                        " names shipped firmware")
    if workaround:
        evidence.append(f"{workaround} offer only a mitigation or workaround")
    if none_available:
        evidence.append(f"{none_available} have no remedy available")
    return Pillar("Patch availability", score, known / n, evidence)


def _certification(certificates):
    """Certification is positive evidence only; its absence is never a penalty.

    Most OT products are never submitted for certification, so treating a
    missing certificate as a negative would punish the majority for a choice
    their vendor made about paperwork. An uncertified product scores the same
    neutral value as one we have no data for -- the difference shows in coverage.
    """
    if not certificates:
        # Coverage 0 excludes the pillar from the composite. Scoring the gap
        # as a neutral 50 let a vendor with one certificate out-rank an
        # equally certified vendor the loaded lists happened not to cover.
        return Pillar("Certification", 50.0, 0.0,
                      ["no certificate found in the loaded sources (ISASecure,"
                       " Common Criteria, curated) -- excluded from the score"
                       " rather than scored neutral"])

    schemes = sorted({c["scheme"] for c in certificates})
    product_level = [c for c in certificates if c.get("matches_product")]
    iec_component = any("4-2" in c["scheme"] for c in certificates)
    iec_process = any("4-1" in c["scheme"] for c in certificates)

    score = 50.0
    if iec_process:
        score += 15                      # vendor builds to a certified process
    if iec_component:
        score += 20                      # some component of theirs is certified
    if product_level:
        score += 15                      # this product specifically

    evidence = [f"vendor holds {len(certificates)} certificate(s): {', '.join(schemes)}"]
    if product_level:
        evidence.append(f"{len(product_level)} appear(s) to cover this product directly")
    else:
        evidence.append("none matched this specific product, so this is vendor-level evidence")

    return Pillar("Certification", min(100.0, score), 1.0, evidence)


# A user's view of the product's deployment. This is deliberately recorded as
# an assumption: ReTrust does not scan or verify a buyer's plant network.
NETWORK_EXPOSURES = {
    "isolated": ("Isolated", 100.0,
                 "No routed path from enterprise IT or the internet into OT."),
    "ot_only": ("OT network only", 50.0, "Connected to other industrial equipment."),
    "remote_vendor": ("Remote vendor access", 50.0, "A supplier can connect remotely."),
    "it_ot": ("IT–OT", 60.0,
              "OT is connected to enterprise IT through a network boundary."),
    "internet_ot": ("Internet–OT", 20.0,
                    "A routed path from the internet can reach the OT environment."),
}


# The operator-supplied vocabularies live beside the model that scores them.
# Re-exported here so a renderer reads one module for the whole scoring
# vocabulary and a new choice cannot appear in a form the model rejects.
CONSEQUENCES = exposure_model.CONSEQUENCES
INTERFACES = exposure_model.INTERFACES
REMEDIATIONS = exposure_model.REMEDIATIONS
PREREQUISITES = exposure_model.PREREQUISITES
ASSESSMENT_TYPES = exposure_model.ASSESSMENT_TYPES


def _network_exposure(value):
    """Score the operator-reported route into the OT environment."""
    if value is None:
        return Pillar("Network exposure", 50.0, 0.0,
                      ["Network context is required to complete the assessment; ask the network owner."],
                      scored=False)
    if value not in NETWORK_EXPOSURES:
        raise ValueError(f"network exposure must be one of {', '.join(NETWORK_EXPOSURES)}")
    label, _, description = NETWORK_EXPOSURES[value]
    result = 50.0  # Context only; topology is not a reachability discount.
    return Pillar("Network exposure", result, 1.0,
                  [f"Operator-reported: {label}. {description}",
                   "Context only: actual reachability determines A. ReTrust does not inspect the plant network."], scored=False)


def narrows(network_exposure=None, consequence=None, interface="unknown",
            remediation="unknown", prerequisites="unknown"):
    """Did the operator supply anything that can narrow exposure?

    `assessment_type` is absent on purpose: it is recorded, never scored, so it
    cannot move a number and must not trip the clamp below.
    """
    return bool(network_exposure) or consequence is not None \
        or interface != "unknown" or remediation != "unknown" \
        or prerequisites != "unknown"


def _exposure(findings, consequence=None, interface="unknown",
              assessment_type="purchase", remediation="unknown", network=None,
              prerequisites="unknown"):
    """The E term: concentrated exposure, as a Pillar."""
    score, coverage, evidence = exposure_model.measure(
        findings, consequence, interface, assessment_type, remediation, network,
        prerequisites)
    return Pillar("Exposure", score, coverage, evidence)


# Pillars enter the product as 1-100, never 0: a single zero would annihilate
# the result and make every other measurement irrelevant. The floor keeps a
# catastrophic pillar catastrophic (E=0 lands near 5/100, deep in AVOID)
# without letting one unmeasured term decide the whole assessment.
FLOOR = 1.0


def _composite(usable, weights):
    """S = product(pillar ** exponent), exponents renormalized over what we measured.

    Same missing-evidence rule as before: a pillar with no evidence is excluded
    and the remaining exponents are renormalized to sum to 1, so a product with
    less data is neither flattered nor punished by a phantom neutral value.
    """
    total = sum(weights.get(spec.key, 0) for spec, _ in usable) or 1.0
    product = 1.0
    for spec, pillar in usable:
        product *= max(pillar.score, FLOOR) ** (weights.get(spec.key, 0) / total)
    return product


@dataclass(frozen=True)
class PillarSpec:
    """One scored pillar: its config key, its label, its weight and how to measure it.

    Everything about a pillar lives here, so adding one is a single entry rather
    than edits to four lists that must stay in step. The previous shape paired a
    list of scorer calls against a parallel list of weight keys by index, which
    would have silently attached the wrong weight to the wrong pillar the first
    time someone inserted one in the middle.
    """

    key: str            # the name used in the config file
    name: str           # the label shown in reports
    weight: float       # default weight, overridable per user
    measure: object     # (findings, advisories, certificates, vendor_key) -> Pillar


PILLARS = [
    # Exposure subsumes what exploitation and severity used to score separately:
    # threat, reachability, process consequence and applicability are the four
    # terms of one per-finding risk, concentrated on the worst few.
    PillarSpec("exposure", "Exposure", 0.60,
               lambda findings, advisories, certificates, vendor_key:
                   _exposure(findings)),
    PillarSpec("patchability", "Patch availability", 0.20,
               lambda findings, advisories, certificates, vendor_key:
                   _patchability(findings)),
    PillarSpec("vendor_practice", "Vendor practice", 0.15,
               lambda findings, advisories, certificates, vendor_key:
                   _vendor_practice(findings, advisories, vendor_key)),
    PillarSpec("certification", "Certification", 0.05,
               lambda findings, advisories, certificates, vendor_key:
                   _certification(certificates)),
]

# Weights are deliberately editable; these are defaults, not truth.
#
# Evidence quality is deliberately absent. It measures how much we know, not how
# risky the product is, so letting it into the weighted mean would mean "we have
# good data about how bad this is" raises the score. It is reported alongside the
# verdict as confidence instead.
DEFAULT_WEIGHTS = {spec.key: spec.weight for spec in PILLARS}


def _cautions(third_party):
    """What a component bundle demands of a human, without gating.

    A KEV-listed CVE inside a bundle is confirmed exploitation of the
    component somewhere -- whether it is reachable on this device is exactly
    what the bundle does not establish. Gating on it would punish the vendors
    who disclose their component stacks; ignoring it would hide confirmed
    exploitation. So it is raised beside the gates, named, and handed to the
    buyer with the question that actually decides it.
    """
    cautions = []
    reach = (". Whether the affected component is reachable on this device"
             " decides the risk -- ask the vendor (the RFQ annex does).")

    def _name(cves):
        return ", ".join(cves[:5]) + (" and more" if len(cves) > 5 else "")

    kev = sorted({f.cve for f in third_party if f.in_kev and not f.fixed})
    if kev:
        cautions.append({
            "caution": "KEV-listed CVE(s) in third-party component bundles",
            "detail": f"{len(kev)} CVE(s) with confirmed exploitation and no"
                      f" vendor fix arrive via component bundle advisories: "
                      + _name(kev) + reach,
            "source": "CISA KEV against component bundle advisories"})

    ransom = sorted({f.cve for f in third_party if f.ransomware and not f.fixed})
    if ransom:
        cautions.append({
            "caution": "Ransomware-linked CVE(s) in third-party component bundles",
            "detail": f"{len(ransom)} CVE(s) tied to ransomware campaigns arrive"
                      f" via component bundles: " + _name(ransom) + reach,
            "source": "CISA KEV ransomware flag against component bundles"})

    # The same shape the unfixable-critical gate fires on, but third-party.
    crit = sorted({f.cve for f in third_party
                   if f.remediation == "none_available" and (f.cvss or 0) >= 9.0
                   and ((f.epss or 0) >= 0.5 or f.in_kev)})
    if crit:
        cautions.append({
            "caution": "Critical unfixable CVE(s) in third-party component bundles",
            "detail": f"{len(crit)} CVE(s) rated 9.0+ with high exploitation"
                      f" likelihood and no vendor remedy arrive via component"
                      f" bundles: " + _name(crit) + reach,
            "source": "CSAF remediation status, CVSS and FIRST EPSS, in bundles"})
    return cautions


def check_gates(findings, vendor, screening_gates=()):
    """Facts that end the assessment regardless of everything else."""
    gates = list(screening_gates)

    unpatched_kev = {f.cve for f in findings if f.in_kev}
    if unpatched_kev:
        gates.append({
            "gate": "Known exploited vulnerability",
            "detail": f"{len(unpatched_kev)} CVE(s) appear in CISA's KEV catalogue: "
                      + ", ".join(sorted(unpatched_kev)[:5]),
            "source": "CISA Known Exploited Vulnerabilities catalogue",
        })

    ransomware = {f.cve for f in findings if f.ransomware}
    if ransomware:
        gates.append({
            "gate": "Ransomware-linked vulnerability",
            "detail": f"{len(ransomware)} CVE(s) tied to known ransomware campaigns",
            "source": "CISA KEV ransomware flag",
        })

    # Critical, likely to be exploited, and nothing the buyer can do about it.
    # Weighted scoring alone could not reach AVOID here: pillars the vendor does
    # well on offset the one that makes the product unbuyable. That is exactly
    # what a gate is for.
    unfixable = [f for f in findings
                 if f.remediation == "none_available"
                 and (f.cvss or 0) >= 9.0
                 and ((f.epss or 0) >= 0.5 or f.in_kev)]
    if unfixable:
        gates.append({
            "gate": "Critical vulnerability with no available fix",
            "detail": f"{len({f.cve for f in unfixable})} CVE(s) rated 9.0+ with high exploitation "
                      f"likelihood and no vendor remedy: "
                      + ", ".join(sorted({f.cve for f in unfixable})[:5]),
            "source": "CSAF remediation status, CVSS and FIRST EPSS",
        })

    return gates


def blocked(product_label, gates, unresolved_reason=""):
    """A vendor that fails screening is AVOID, resolved or not.

    Screening runs on the vendor name alone, so it does not depend on the
    product being in the advisory corpus. A sanctioned supplier absent from
    CISA's data must still be stopped -- otherwise the gate only protects you
    against vendors you were already going to hear about.
    """
    notes = ["Screening decided this outright; no score was computed."]
    if unresolved_reason:
        notes.append(
            f"The product itself was not found in the advisory corpus "
            f"({unresolved_reason}), but that does not change the gate.")
    return Assessment(product=product_label, verdict="AVOID", score=None,
                      gates=list(gates), notes=notes)


def not_assessed(product_label, reason):
    """A product we could not resolve gets no score at all.

    Returning a number here would be worse than useless: every pillar treats
    "no CVEs found" as good news, so an unresolvable product would score near
    100 and rank top of a comparison. Absence of data is not a clean bill of
    health, and the verdict has to say so.
    """
    return Assessment(
        product=product_label, verdict="NOT ASSESSED", score=None,
        notes=[f"Could not assess this product: {reason}.",
               "This is not a good result or a bad one -- it means ReTrust has "
               "nothing to go on. Try the manufacturer's order number."],
    )


def assess(product_label, findings, advisories=(), weights=None, today_year=2026,
           certificates=(), screening_gates=(), bands=None, vendor_key=None,
           network_exposure=None, consequence=None, interface="unknown",
           assessment_type="purchase", remediation="unknown", version=None,
           snapshot="", prerequisites="unknown"):
    """Score a resolved product. Returns an Assessment.

    The last four arguments are facts only the asset owner has: what a
    compromise would cost their process, whether they have verified the
    vulnerable interface is unreachable, whether this is a purchase or an
    installed asset, and whether a fix is actually on the box. ReTrust supplies
    the vulnerability intelligence; it never asks the operator to score a
    vendor or guess a percentage. Network context and verified reachability are main assessment inputs. Unknown
    answers produce a provisional range and VERIFY until the material gaps close.
    """
    weights = weights or DEFAULT_WEIGHTS
    declared = dict(
        network_exposure=network_exposure, assessment_type=assessment_type,
        consequence=consequence, interface=interface, remediation=remediation,
        prerequisites=prerequisites,
        vector=vector(assessment_type, version, network_exposure, interface,
                      consequence, remediation, snapshot, prerequisites))

    # Findings from the vendor's own advisories against those arriving in
    # third-party component bundles. The bundles establish that a component
    # ships on the device, not that each of its hundreds of CVEs is reachable
    # there -- so the pillars measure the first-party set when one exists,
    # and the bundle set is reported and cautioned rather than allowed to
    # swamp the score. A vendor that honestly discloses its Linux side must
    # not score worse than one that stays quiet about having one.
    first = [f for f in findings if not f.third_party]
    third = [f for f in findings if f.third_party]
    base = first if first else findings
    undecided = [f for f in base if not f.decided]

    exposure = exposure_model.analyse(base, consequence, interface, assessment_type,
                                     remediation, network_exposure, prerequisites)
    measured = []
    all_pillars = []
    for spec in PILLARS:
        if spec.key == "exposure":
            pillar = Pillar("Exposure", exposure.safety_min, exposure.coverage, exposure.evidence)
        else:
            pillar = spec.measure(base, advisories, certificates, vendor_key)
        measured.append((spec, pillar))
        all_pillars.append(pillar)

    # Threat and severity now feed Exposure rather than scoring separately, but
    # a reader still wants to see them. Reported as diagnostics -- shown with
    # their numbers, excluded from the product -- so folding them in cost no
    # explanation. Scoring them again here would double-count them.
    diagnostics = []
    for diagnostic in (_exploitation(base), _severity(base),
                       _network_exposure(network_exposure)):
        diagnostic.scored = False
        diagnostics.append(diagnostic)

    confidence = _evidence_quality(base)
    pillars = all_pillars + diagnostics + [confidence]

    # One rule for missing evidence, every pillar alike: coverage 0 means the
    # pillar measured nothing, so it is excluded and the rest renormalized --
    # never scored as a phantom neutral that moves rankings. `scored` is the
    # participation flag every renderer and the sensitivity table read, so
    # the exclusion is visible everywhere the same way.
    usable = [(spec, pillar) for spec, pillar in measured if pillar.coverage > 0 or (spec.key == "exposure" and base)]
    dropped = [spec.name for spec, pillar in measured if pillar.coverage == 0 and not (spec.key == "exposure" and base)]
    for spec, pillar in measured:
        if pillar.coverage == 0 and not (spec.key == "exposure" and base):
            pillar.scored = False

    # Gates run on first-party findings only: a KEV inside a third-party bundle
    # is a CAUTION, never a gate. Running the gate on `base` (which falls back
    # to the bundle when there are no first-party findings) would make the very
    # same bundled KEV gate or caution depending on whether a first-party
    # finding happens to exist.
    #
    # Network exposure is a deployment ASSUMPTION, not vulnerability evidence,
    # so it can no longer make a blank product scoreable: it is an input to
    # Exposure, and Exposure has coverage 0 when there are no findings.
    # Certification is assurance, not risk evidence: a certificate with ZERO
    # advisory findings must not produce a confident verdict banded on the
    # Certification pillar alone -- that is "absence of data reads as safety",
    # the exact inversion this tool exists to prevent (found live: a product
    # with no findings and one vendor certificate rendered PREFER 85.0).
    risk_usable = [(spec, p) for spec, p in usable if spec.key != "certification"]
    gates = check_gates(first, product_label, screening_gates)
    cautions = _cautions(third)

    if not risk_usable:
        notes = ["No pillar had measurable risk evidence, so no score is"
                 " computed. Absence of findings is not a clean bill of"
                 " health: nobody may have published about this product."]
        if any(pillar.coverage > 0 for spec, pillar in measured
               if spec.key == "certification"):
            notes.append(
                "A certificate is on file, but assurance with no advisory"
                " record to weigh it against is not scored -- a certificate"
                " cannot stand in for the missing risk evidence.")
        if gates:
            notes.insert(0, "Screening gates still apply without a score.")
        return Assessment(
            product=product_label, verdict="AVOID" if gates else "NOT ASSESSED",
            score=None, pillars=pillars, gates=gates, cautions=cautions,
            findings_count=len({f.cve for f in findings}),
            first_party_count=len({f.cve for f in first}),
            third_party_count=len({f.cve for f in third} - {f.cve for f in first}),
            notes=notes, **declared)

    composite = _composite(usable, weights)

    upper_usable = [(spec, Pillar(p.name, exposure.safety_max, p.coverage, p.evidence)
                              if spec.key == "exposure" else p) for spec, p in usable]
    upper = _composite(upper_usable, weights)
    prefer_threshold = (bands or BANDS)[0][0]
    cap_note = None
    unmitigable = sorted({
        f.cve for group in weakness.classify(base)
        if group.name in weakness.UNMITIGABLE
        for f in base if f.cve in group.cves and not f.fixed})
    if unmitigable and upper >= prefer_threshold:
        # A credential baked into firmware with no fix shipped is not a
        # weighting question: whatever the other pillars say, this product
        # cannot be preferred while that stands.
        composite = min(composite, prefer_threshold - 0.1)
        cap_note = (
            "Capped below PREFER: " + ", ".join(unmitigable[:4])
            + (" and more" if len(unmitigable) > 4 else "")
            + (" are hardcoded-credential class flaws" if len(unmitigable) > 1
               else " is a hardcoded-credential class flaw")
            + " with no vendor fix. The operator cannot engineer around"
            + (" them" if len(unmitigable) > 1 else " it")
            + " for the life of the asset, so no weighting can make this"
            " product preferred.")

    if unmitigable:
        upper = min(upper, prefer_threshold - 0.1)
    verdict = ("AVOID" if gates else "VERIFY" if exposure.provisional else
               next(b for t, b in (bands or BANDS) if composite >= t))

    # When declared answers carried a verdict out of VERIFY, say which answers
    # it rests on and what the evidence said alone. The answers are assertions
    # ReTrust cannot check, so a banded verdict that depends on them must carry
    # that dependency on its face -- a reviewer should never have to diff two
    # assessments to discover that a dropdown decided the band.
    assertions = []
    if interface != "unknown":
        assertions.append(f"attack reachability: {INTERFACES[interface][0]}")
    if prerequisites != "unknown":
        assertions.append(
            f"exploitation prerequisites: {PREREQUISITES[prerequisites][0]}")
    if consequence is not None:
        assertions.append(f"operational consequence: {CONSEQUENCES[consequence][0]}")
    if remediation != "unknown":
        assertions.append(f"firmware remediation: {REMEDIATIONS[remediation][0]}")
    assertion_note = None
    if assertions and verdict not in ("VERIFY", "NOT ASSESSED") and not gates:
        alone = exposure_model.analyse(base)
        eo_low = _composite([(spec, Pillar(pl.name, alone.safety_min, pl.coverage,
                                           pl.evidence) if spec.key == "exposure"
                              else pl) for spec, pl in usable], weights)
        eo_high = _composite([(spec, Pillar(pl.name, alone.safety_max, pl.coverage,
                                            pl.evidence) if spec.key == "exposure"
                               else pl) for spec, pl in usable], weights)
        assertion_note = (
            f"This {verdict} rests on operator assertions ReTrust cannot"
            " verify: " + "; ".join(assertions) + ". On the published evidence"
            f" alone this product is VERIFY, {eo_low:.1f}-{eo_high:.1f}/100."
            " Retain supporting evidence for each answer before procurement.")

    notes = []
    if cap_note:
        notes.append(cap_note)
    if exposure.provisional:
        notes.append("This is a provisional score range, not a purchase recommendation. "
                     "Ask a technical owner to resolve the checks listed below. "
                     "The lower endpoint is the conservative case.")
    if assertion_note:
        notes.append(assertion_note)
    elif narrows(network_exposure, consequence, interface, remediation, prerequisites):
        notes.append("Site answers are operator-reported assertions, not independently verified "
                     "by ReTrust. Retain supporting evidence for each finding before procurement.")
    if first and third:
        notes.append(
            f"{len({f.cve for f in third})} of the CVEs in scope arrive via"
            f" third-party component bundle advisories; the pillars above"
            f" measure the {len({f.cve for f in first})} first-party CVE(s)."
            " A bundle establishes the component ships on the device, not"
            " that each of its CVEs is reachable there -- the cautions below"
            " say what still needs a human.")
    if not first and third:
        notes.append(
            "Every finding arrives via component bundles, so the pillars were"
            " measured on the bundle set -- treat the score as describing the"
            " component stack, not the vendor's own firmware.")
    if len(base) != len({f.cve for f in base}):
        notes.append(
            f"{len({f.cve for f in base})} distinct CVEs across {len(base)} "
            "advisory findings. Pillar coverage and proportions use advisory "
            "findings; exploitation counts and gates use distinct CVEs."
        )
    if undecided:
        notes.append(
            f"The version check is pending for {len({f.cve for f in undecided})}"
            " CVE(s): their ranges were not confirmed against firmware. Supply"
            " a firmware version, then review any that remain undecided."
        )
    if dropped:
        notes.append(
            ", ".join(dropped) + (" had" if len(dropped) > 1 else " had")
            + " no evidence to measure, so "
            + ("their exponents were" if len(dropped) > 1 else "its exponent was")
            + " excluded and the remaining pillars renormalized -- one rule"
            " for every pillar, never a phantom neutral score.")
    if consequence is None:
        notes.append(
            "No process consequence was established, so exposure includes"
            " a range from no material effect to full impact. Ask an engineer"
            " to establish the credible consequence for each finding.")
    if any(f.fixed for f in base) and remediation not in ("applied", "mitigated"):
        notes.append(
            "A fix is available for one or more findings, but exposure still"
            " treats them as applicable until the selected firmware or a"
            " verified fix is established. Protective controls affect reachability, not firmware applicability. Fix availability contributes"
            " to patchability, not a second exposure discount.")

    # What kind of flaws these are, which is a different question from how many
    # or how bad. Notes rather than a scoring term: a credential baked into
    # firmware is not three points off a composite, it is something the operator
    # cannot engineer around for the life of the asset.
    notes.extend(weakness.notes(weakness.classify(base)))

    return Assessment(
        product=product_label, verdict=verdict, score=round(composite, 1),
        # Distinct CVEs, not findings: one CVE named by two advisories is one
        # thing to fix, and every label that shows this says "CVE(s)".
        pillars=pillars, gates=gates, cautions=cautions,
        findings_count=len({f.cve for f in findings}),
        first_party_count=len({f.cve for f in first}),
        third_party_count=len({f.cve for f in third} - {f.cve for f in first}),
        undecided_count=len({f.cve for f in undecided}),
        confidence=round(confidence.coverage, 2),
        assertions=assertions if assertion_note else [],
        worst_risk=max((p["z_max"] for p in exposure.paths), default=None),
        score_min=round(composite, 1), score_max=round(upper, 1),
        exposure_min=exposure.safety_min, exposure_max=exposure.safety_max,
        provisional=exposure.provisional, verification=exposure.missing,
        paths=exposure.paths,
        notes=notes, **declared,
    )
