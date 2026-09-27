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

from __future__ import annotations

from dataclasses import dataclass, field

# Weights are deliberately editable; these are defaults, not truth.
#
# Evidence quality is deliberately absent. It measures how much we know, not how
# risky the product is, so letting it into the weighted mean would mean "we have
# good data about how bad this is" raises the score. It is reported alongside the
# verdict as confidence instead.
DEFAULT_WEIGHTS = {
    "exploitation": 0.30,
    "severity": 0.20,
    "patchability": 0.20,
    "vendor_practice": 0.15,
    "certification": 0.15,
}

BANDS = [(70, "PREFER"), (40, "CONDITIONAL"), (0, "AVOID")]


@dataclass
class Pillar:
    name: str
    score: float            # 0-100, higher is better
    coverage: float         # 0-1, how much of the input carried usable evidence
    evidence: list = field(default_factory=list)


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
        return Pillar("Exploitation", 100.0, 1.0, ["no known CVEs for this product"])

    kev = [f for f in findings if f.in_kev]
    ransomware = [f for f in findings if f.ransomware]
    scored = [f for f in findings if f.epss is not None]
    coverage = len(scored) / len(findings)

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
        likely = [f for f in scored if f.epss >= 0.1]
        penalty += 40 * peak
        evidence.append(f"peak EPSS {peak:.3f}")
        if likely:
            evidence.append(f"{len(likely)} CVE(s) with EPSS >= 0.10")
    else:
        evidence.append("no EPSS data for these CVEs")

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
        return Pillar("Severity", 100.0, 1.0, ["no known CVEs for this product"])
    if not scored:
        return Pillar("Severity", 50.0, 0.0, ["no CVSS data; scored neutral"])

    peak = max(f.cvss for f in scored)
    critical = [f for f in scored if f.cvss >= 9.0]
    high = [f for f in scored if 7.0 <= f.cvss < 9.0]

    # CVSS below 4 is barely worth weighting; 10 is the ceiling.
    peak_share = min(1.0, max(0.0, (peak - 4.0) / 6.0))
    critical_share = len(critical) / len(scored)
    penalty = 60 * peak_share + 40 * critical_share

    evidence = [f"highest CVSS {peak:.1f}",
                f"{len(critical)}/{len(scored)} rated critical (9.0+), {len(high)} high"]
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

    publishes = (vendor_key or "") in CSAF_PUBLISHERS
    score = (35 if publishes else 0) + 45 * quality + (20 if publishes else 0)

    evidence = [
        f"{len(advisories)} advisor{'y' if len(advisories) == 1 else 'ies'} in this assessment",
        f"{with_cvss}/{len(findings)} CVEs carry CVSS, {with_cwe}/{len(findings)} carry a CWE",
    ]
    evidence.append(
        "runs its own CSAF advisory feed" if publishes else
        "no CSAF feed of its own found; disclosure relies on CISA republishing")
    return Pillar("Vendor practice", min(100.0, score), 1.0, evidence)


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

    evidence = [f"{decided}/{n} version ranges parsed cleanly",
                f"{with_cvss}/{n} scored by the vendor, {with_epss}/{n} covered by EPSS"]
    if decided < n:
        evidence.append(f"{n - decided} range(s) need manual review")
    return Pillar("Evidence quality", 100 * quality, quality, evidence)


def _patchability(findings):
    """Can the buyer actually fix what is wrong with this product?

    Two products with identical CVE lists are not equally risky if one ships
    vendor fixes and the other offers only workarounds. CSAF states this per
    vulnerability, so we read it rather than infer it.
    """
    if not findings:
        return Pillar("Patch availability", 100.0, 1.0, ["no known CVEs to remediate"])

    counts = {}
    for finding in findings:
        counts[finding.remediation] = counts.get(finding.remediation, 0) + 1
    n = len(findings)
    fixed = counts.get("vendor_fix", 0)
    workaround = counts.get("mitigation", 0) + counts.get("workaround", 0)
    none_available = counts.get("none_available", 0)
    known = fixed + workaround + none_available

    if not known:
        return Pillar("Patch availability", 50.0, 0.0,
                      ["advisories do not state remediation status; scored neutral"])

    # A vendor fix counts fully; a workaround counts part-way; nothing counts zero.
    score = 100 * (fixed + 0.4 * workaround) / known
    evidence = [f"{fixed}/{n} CVEs have a vendor fix"]
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
        return Pillar("Certification", 50.0, 0.0,
                      ["no IEC 62443 or Common Criteria certificate found for this vendor",
                       "absence of certification is not evidence of insecurity"])

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


def check_gates(findings, vendor, screening_gates=()):
    """Facts that end the assessment regardless of everything else."""
    gates = list(screening_gates)

    unpatched_kev = [f for f in findings if f.in_kev]
    if unpatched_kev:
        gates.append({
            "gate": "Known exploited vulnerability",
            "detail": f"{len(unpatched_kev)} CVE(s) appear in CISA's KEV catalogue: "
                      + ", ".join(sorted({f.cve for f in unpatched_kev})[:5]),
            "source": "CISA Known Exploited Vulnerabilities catalogue",
        })

    ransomware = [f for f in findings if f.ransomware]
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
            "detail": f"{len(unfixable)} CVE(s) rated 9.0+ with high exploitation "
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
           certificates=(), screening_gates=(), bands=None, vendor_key=None):
    """Score a resolved product. Returns an Assessment."""
    weights = weights or DEFAULT_WEIGHTS
    undecided = [f for f in findings if not f.decided]

    risk_pillars = [
        _exploitation(findings),
        _severity(findings),
        _patchability(findings),
        _vendor_practice(findings, advisories, vendor_key),
        _certification(certificates),
    ]
    keys = ["exploitation", "severity", "patchability", "vendor_practice", "certification"]
    confidence = _evidence_quality(findings)
    pillars = risk_pillars + [confidence]

    total = sum(weights.get(k, 0) for k in keys) or 1.0
    composite = sum(p.score * weights.get(k, 0) for p, k in zip(risk_pillars, keys)) / total

    gates = check_gates(findings, product_label, screening_gates)
    verdict = "AVOID" if gates else next(b for t, b in (bands or BANDS)
                                         if composite >= t)

    notes = []
    if undecided:
        notes.append(
            f"{len(undecided)} finding(s) had a version range this tool could not "
            "parse and were kept in scope rather than assumed safe; review them."
        )
    if not findings:
        notes.append(
            "No advisories name this product. That is not proof it is secure -- it "
            "may simply mean nobody has published about it."
        )

    return Assessment(
        product=product_label, verdict=verdict, score=round(composite, 1),
        pillars=pillars, gates=gates, findings_count=len(findings),
        undecided_count=len(undecided), confidence=round(confidence.coverage, 2),
        notes=notes,
    )
