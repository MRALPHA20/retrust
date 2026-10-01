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
    # The excluded pillar's phantom 50 must appear nowhere: the no-data score
    # equals the renormalized mean of the pillars that DID measure something.
    keys = {spec.name: spec.key for spec in score.PILLARS}
    weights = score.DEFAULT_WEIGHTS
    scored = [p for p in without.pillars
              if p.scored and p.name != "Evidence quality"]
    expected = (sum(p.score * weights[keys[p.name]] for p in scored)
                / sum(weights[keys[p.name]] for p in scored))
    assert without.score == pytest.approx(expected, abs=0.1)
    assert with_data.score != without.score   # evidence moved it; absence did not


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
    assessment = score.assess("Ghost", [], {"A"})
    assert assessment.verdict == "NOT ASSESSED"
    assert assessment.score is None
