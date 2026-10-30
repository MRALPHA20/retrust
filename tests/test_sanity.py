"""The model properties a broken ranking would violate.

Every test here is the generalised form of a failure an external ICS review
actually caught: a hardcoded-credential PLC ranked PREFER, a phantom neutral
certification score moving rankings between equally certified vendors, a
vendor punished for disclosing its Linux side, a KEV gate fired on a bundled
component CVE whose reachability nobody established. These are properties of
the model, not of today's corpus, so they hold whatever the data says.
"""

import pytest

from retrust import score
from retrust.match import Finding


def _finding(cve="CVE-2026-0001", **overrides):
    base = dict(cve=cve, advisory_id="ICSA-26-001-01", cvss=7.0, cwe="CWE-787",
                epss=0.02, in_kev=False, ransomware=False,
                version_range="vers:intdot/<2.0", decided=True,
                remediation="vendor_fix", vector=None, fix_text=False,
                third_party=False)
    base.update(overrides)
    return Finding(**base)


GOOD_CERTS = [{"scheme": "IEC 62443-4-1", "matches_product": False},
              {"scheme": "IEC 62443-4-2", "matches_product": True}]


def test_an_unmitigable_flaw_without_a_fix_is_never_preferred():
    """Hardcoded credentials with no vendor fix: no weighting reaches PREFER."""
    findings = [_finding(),
                _finding("CVE-2026-0002", cwe="CWE-798", cvss=5.9,
                         remediation="mitigation")]
    assessment = score.assess("PLC", findings, {"ICSA-26-001-01"},
                              certificates=GOOD_CERTS)
    assert assessment.verdict != "PREFER"
    assert any("Capped below PREFER" in n for n in assessment.notes)
    # ...and the same flaw WITH a shipped fix lifts the cap.
    fixed = [_finding(),
             _finding("CVE-2026-0002", cwe="CWE-798", cvss=5.9,
                      remediation="mitigation", fix_text=True)]
    relieved = score.assess("PLC", fixed, {"ICSA-26-001-01"},
                            certificates=GOOD_CERTS)
    assert not any("Capped" in n for n in relieved.notes)


def test_a_pillar_without_evidence_cannot_move_a_ranking():
    """No certification DATA is excluded; it must never act as a score."""
    findings = [_finding()]
    with_data = score.assess("A", findings, {"ICSA-26-001-01"},
                             certificates=GOOD_CERTS)
    without = score.assess("B", findings, {"ICSA-26-001-01"}, certificates=[])
    cert = next(p for p in without.pillars if p.name == "Certification")
    assert not cert.scored
    # Missing evidence is scored at MISSING_PILLAR with its full exponent. It
    # is never dropped and renormalized, because that let absence lift a score.
    keys = {spec.name: spec.key for spec in score.PILLARS}
    weights = score.DEFAULT_WEIGHTS
    by_key = {keys[p.name]: p for p in without.pillars if p.name in keys}
    total = sum(weights[k] for k in keys.values())
    expected = 1.0
    for key in keys.values():
        pillar = by_key[key]
        level = pillar.score if pillar.scored else score.MISSING_PILLAR
        expected *= max(level, score.FLOOR) ** (weights[key] / total)
    assert without.score == pytest.approx(expected, abs=0.1)
    assert with_data.score > without.score   # absence never beats evidence


def test_disclosing_a_component_stack_never_lowers_the_score():
    """The anti-transparency-penalty invariant, stated as arithmetic.

    A vendor that honestly publishes a 300-CVE Linux-side bundle must score
    no worse than one that stays quiet about having a Linux side at all.
    """
    own = [_finding()]
    bundle = [_finding(f"CVE-2026-{n:04}", third_party=True, cvss=9.8,
                       epss=0.9, remediation="none_available")
              for n in range(100, 160)]
    quiet = score.assess("Quiet", own, {"ICSA-26-001-01"})
    honest = score.assess("Honest", own + bundle, {"ICSA-26-001-01", "B"})
    assert honest.score >= quiet.score
    assert honest.third_party_count == 60
    assert any("component bundle" in n for n in honest.notes)


def test_a_bundled_kev_cautions_and_a_first_party_kev_gates():
    own_kev = [_finding(in_kev=True, remediation="mitigation")]
    gated = score.assess("X", own_kev, {"ICSA-26-001-01"})
    assert gated.verdict == "AVOID" and gated.gates

    bundled_kev = [_finding(),
                   _finding("CVE-2026-0002", third_party=True, in_kev=True,
                            remediation="mitigation")]
    cautioned = score.assess("Y", bundled_kev, {"ICSA-26-001-01"})
    assert not cautioned.gates
    assert cautioned.cautions
    assert "CVE-2026-0002" in cautioned.cautions[0]["detail"]
    # A bundled KEV the vendor already fixed needs no caution either.
    fixed = [_finding(),
             _finding("CVE-2026-0002", third_party=True, in_kev=True,
                      remediation="vendor_fix")]
    assert not score.assess("Z", fixed, {"ICSA-26-001-01"}).cautions


def test_absence_from_the_publisher_list_is_not_a_practice_penalty():
    """Perfect disclosure quality reaches 70 without a known feed; the feed
    is a bonus, never the pillar."""
    findings = [_finding()]
    pillar = score._vendor_practice(findings, {"ICSA-26-001-01"},
                                    vendor_key="nobody-knows-them")
    assert pillar.score >= 70.0
    assert any("not evidence of absence" in e for e in pillar.evidence)


def test_a_filed_as_mitigation_shipped_fix_counts_as_fixed():
    findings = [_finding(remediation="mitigation", fix_text=True)]
    pillar = score._patchability(findings)
    assert pillar.score == 100.0
    assert any("names shipped firmware" in e for e in pillar.evidence)


def test_undecided_is_counted_in_cves_never_in_rows():
    """"1,034 in scope - 1,063 need review" must be impossible."""
    findings = [_finding(decided=False),
                _finding(advisory_id="B", decided=False)]   # same CVE, two rows
    assessment = score.assess("X", findings, {"ICSA-26-001-01", "B"})
    assert assessment.undecided_count <= assessment.findings_count
    assert assessment.undecided_count == 1


def test_no_findings_is_never_a_verdict():
    # No evidence never bands: VERIFY across the full range, and the headline
    # is its conservative low end, so silence cannot read as safety.
    assessment = score.assess("Ghost", [], {"A"})
    assert assessment.verdict == "VERIFY" and assessment.evidence_free
    assert assessment.score == assessment.score_min < 10


def test_network_exposure_alone_never_produces_a_score():
    """A deployment assumption is not vulnerability evidence: a product with no
    findings must stay an evidence-free VERIFY even when network exposure is
    supplied, and the answer must not move its range."""
    ranges = set()
    for exposure in ("isolated", "it_ot", "internet_ot"):
        a = score.assess("Blank", [], network_exposure=exposure)
        assert a.verdict == "VERIFY" and a.evidence_free, exposure
        assert a.score == a.score_min < 10, exposure
        ranges.add((a.score_min, a.score_max))
    assert len(ranges) == 1


def test_missing_epss_does_not_drop_the_exposure_pillar():
    """Threat is only one term of Exposure, so missing EPSS must not drop it.

    KEV and ransomware are known for every finding and severity comes from the
    advisory, so Exposure always has coverage when findings exist -- a product
    with less EPSS data must not score lower by having the pillar that carries
    60% of the weight renormalized away."""
    no_epss = [_finding("C1", epss=None, cvss=5.0),
               _finding("C2", epss=None, cvss=6.0)]
    with_epss = [_finding("C1", epss=0.02, cvss=5.0),
                 _finding("C2", epss=0.03, cvss=6.0)]
    a = score.assess("A", no_epss, {"ICSA-26-001-01"})
    b = score.assess("B", with_epss, {"ICSA-26-001-01"})
    exposure = next(p for p in a.pillars if p.name == "Exposure")
    assert exposure.scored and exposure.coverage > 0
    # The verdict must not flip on EPSS availability alone, and missing EPSS
    # must never score better than having it: T stays unresolved, so the
    # conservative end of the range is lower.
    assert a.verdict == b.verdict
    assert a.score <= b.score


def test_a_bundled_kev_cautions_even_with_no_first_party_findings():
    """An all-third-party product's KEV must caution, not gate -- the gate/
    caution choice cannot depend on whether a first-party finding happens to
    exist."""
    all_third = [_finding("C1", third_party=True, in_kev=True,
                          remediation="mitigation")]
    a = score.assess("X", all_third, {"ICSA-26-001-01"})
    assert not a.gates
    assert a.cautions


def test_third_party_ransomware_and_criticals_caution_not_vanish():
    """Every class the gate fires on, as third-party, must at least caution."""
    ransom = [_finding("C1", third_party=True, ransomware=True,
                       remediation="mitigation")]
    crit = [_finding("C2", third_party=True, cvss=9.8, epss=0.9,
                     remediation="none_available")]
    assert any("Ransomware" in c["caution"] for c in score.assess(
        "R", ransom, {"A"}).cautions)
    assert any("Critical" in c["caution"] for c in score.assess(
        "C", crit, {"A"}).cautions)


def test_party_counts_partition_the_distinct_cve_set():
    """A CVE from both a first-party advisory and a bundle is counted once."""
    shared = [_finding("CVE-X", third_party=False),
              _finding("CVE-X", advisory_id="BUNDLE", third_party=True)]
    a = score.assess("X", shared, {"ICSA-26-001-01", "BUNDLE"})
    assert a.first_party_count + a.third_party_count == a.findings_count


def test_patchability_buckets_partition_exactly_once():
    """fixed / workaround / none_available must never double-count a finding."""
    fs = [_finding("C1", remediation="vendor_fix"),
          _finding("C2", remediation="mitigation"),
          _finding("C3", remediation="none_available")]
    p = score._patchability(fs)
    assert 0.0 <= p.coverage <= 1.0
