"""Turn findings into a procurement verdict.

Three layers, in this order:

    1. hard gates   a disqualifying fact (sanctions, an exploited unpatched CVE)
                    ends the assessment. Gates are not weighted terms, because a
                    weighted disqualifier can be averaged away by good scores.
    2. pillars      each scores 0-100 (higher is better) and reports how much
                    evidence it had, so a thin pillar says so instead of
                    defaulting to a confident middle.
    3. composite    a weighted mean of the pillars, shown as a band.

Two rules keep this defensible:

  * We never score raw CVE counts. A vendor that discloses diligently would
    score worse than one that stays quiet, which is exactly backwards.
  * Every number carries the evidence it came from, so a reviewer can disagree
    with a weight without having to distrust the whole result.
"""

from dataclasses import dataclass, field

from . import cvss, weakness

BANDS = [(70, "PREFER"), (40, "CONDITIONAL"), (0, "AVOID")]


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
    "it_ot": ("IT–OT", 60.0,
              "OT is connected to enterprise IT through a network boundary."),
    "internet_ot": ("Internet–OT", 20.0,
                    "A routed path from the internet can reach the OT environment."),
}


def _network_exposure(value):
    """Score the operator-reported route into the OT environment."""
    if value is None:
        return Pillar("Network exposure", 50.0, 0.0,
                      ["network context not supplied; this optional pillar was not scored"],
                      scored=False)
    if value not in NETWORK_EXPOSURES:
        raise ValueError(f"network exposure must be one of {', '.join(NETWORK_EXPOSURES)}")
    label, result, description = NETWORK_EXPOSURES[value]
    return Pillar("Network exposure", result, 1.0,
                  [f"Operator-reported: {label}. {description}",
                   "ReTrust has not independently verified the plant network."])


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
    PillarSpec("exploitation", "Exploitation", 0.270,
               lambda findings, advisories, certificates, vendor_key:
                   _exploitation(findings)),
    PillarSpec("severity", "Severity", 0.180,
               lambda findings, advisories, certificates, vendor_key:
                   _severity(findings)),
    PillarSpec("patchability", "Patch availability", 0.180,
               lambda findings, advisories, certificates, vendor_key:
                   _patchability(findings)),
    PillarSpec("vendor_practice", "Vendor practice", 0.135,
               lambda findings, advisories, certificates, vendor_key:
                   _vendor_practice(findings, advisories, vendor_key)),
    PillarSpec("certification", "Certification", 0.135,
               lambda findings, advisories, certificates, vendor_key:
                   _certification(certificates)),
    # Optional input: without it the five existing pillars are renormalized,
    # preserving scores for callers who have not supplied plant context.
    PillarSpec("network_exposure", "Network exposure", 0.10,
               lambda findings, advisories, certificates, vendor_key:
                   _network_exposure(None)),
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
           network_exposure=None):
    """Score a resolved product. Returns an Assessment."""
    weights = weights or DEFAULT_WEIGHTS

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

    measured = []
    all_pillars = []
    for spec in PILLARS:
        if spec.key == "network_exposure":
            pillar = _network_exposure(network_exposure)
            all_pillars.append(pillar)
            if network_exposure is not None:
                measured.append((spec, pillar))
            continue
        pillar = spec.measure(base, advisories, certificates, vendor_key)
        measured.append((spec, pillar))
        all_pillars.append(pillar)
    confidence = _evidence_quality(base)
    pillars = all_pillars + [confidence]

    # One rule for missing evidence, every pillar alike: coverage 0 means the
    # pillar measured nothing, so it is excluded and the rest renormalized --
    # never scored as a phantom neutral that moves rankings. `scored` is the
    # participation flag every renderer and the sensitivity table read, so
    # the exclusion is visible everywhere the same way.
    usable = [(spec, pillar) for spec, pillar in measured if pillar.coverage > 0]
    dropped = [spec.name for spec, pillar in measured if pillar.coverage == 0]
    for _, pillar in measured:
        if pillar.coverage == 0:
            pillar.scored = False

    # Gates and the empty-evidence test run on first-party findings, and the
    # "has evidence" test ignores network exposure:
    #  - network exposure is a deployment ASSUMPTION the operator typed, not
    #    vulnerability evidence, so a product with no advisory findings must
    #    stay NOT ASSESSED even when it is supplied -- otherwise "isolated"
    #    alone scores a blank product PREFER 100.
    #  - a KEV inside a third-party bundle is a CAUTION, never a gate; running
    #    the gate on `base` (which falls back to the bundle when there are no
    #    first-party findings) would make the very same bundled KEV gate or
    #    caution depending on whether a first-party finding happens to exist.
    risk_usable = [(spec, pillar) for spec, pillar in usable
                   if spec.key != "network_exposure"]
    gates = check_gates(first, product_label, screening_gates)
    cautions = _cautions(third)

    if not risk_usable:
        notes = ["No pillar had measurable evidence, so no score is computed."
                 " Absence of findings is not a clean bill of health: nobody"
                 " may have published about this product."]
        if gates:
            notes.insert(0, "Screening gates still apply without a score.")
        return Assessment(
            product=product_label, verdict="AVOID" if gates else "NOT ASSESSED",
            score=None, pillars=pillars, gates=gates, cautions=cautions,
            findings_count=len({f.cve for f in findings}),
            first_party_count=len({f.cve for f in first}),
            third_party_count=len({f.cve for f in third} - {f.cve for f in first}),
            notes=notes)

    total = sum(weights.get(spec.key, 0) for spec, _ in usable) or 1.0
    composite = sum(pillar.score * weights.get(spec.key, 0)
                    for spec, pillar in usable) / total

    # Certification is positive evidence only: its ABSENCE is excluded, never a
    # penalty, so its PRESENCE must not lower the composite either -- otherwise
    # a vendor holding a mid-tier certificate scores below one holding none,
    # and the pillar that is meant to reward certification punishes it. It may
    # lift the score, never drag it. (This asymmetry is unique to
    # certification; a low patchability or severity SHOULD lower a score.)
    if any(spec.key == "certification" for spec, _ in usable):
        others = [(spec, p) for spec, p in usable if spec.key != "certification"]
        if others:
            base_total = sum(weights.get(spec.key, 0) for spec, _ in others) or 1.0
            without_cert = sum(p.score * weights.get(spec.key, 0)
                               for spec, p in others) / base_total
            composite = max(composite, without_cert)

    prefer_threshold = (bands or BANDS)[0][0]
    cap_note = None
    unmitigable = sorted({
        f.cve for group in weakness.classify(base)
        if group.name in weakness.UNMITIGABLE
        for f in base if f.cve in group.cves and not f.fixed})
    if unmitigable and composite >= prefer_threshold:
        # A credential baked into firmware with no fix shipped is not a
        # weighting question: whatever the other pillars say, this product
        # cannot be preferred while that stands.
        composite = prefer_threshold - 0.1
        cap_note = (
            "Capped below PREFER: " + ", ".join(unmitigable[:4])
            + (" and more" if len(unmitigable) > 4 else "")
            + " are hardcoded-credential class flaws with no vendor fix."
            " The operator cannot engineer around them for the life of the"
            " asset, so no weighting can make this product preferred.")

    verdict = "AVOID" if gates else next(b for t, b in (bands or BANDS)
                                         if composite >= t)

    notes = []
    if cap_note:
        notes.append(cap_note)
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
            + ("their weights were" if len(dropped) > 1 else "its weight was")
            + " excluded and the remaining pillars renormalized -- one rule"
            " for every pillar, never a phantom neutral score.")
    if network_exposure is None:
        share = weights.get("network_exposure", 0.0) / (sum(weights.values()) or 1.0)
        notes.append(f"Network exposure was not provided; its configured {share:.1%} "
                     "weight was excluded and the other pillars were renormalized.")

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
        network_exposure=network_exposure,
        notes=notes,
    )
