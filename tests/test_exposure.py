"""The concentrated exposure model, and the properties it must keep.

These pin the decisions behind ReTrust-OT V1 so a later edit cannot quietly
undo one: that threat amplifies rather than decides, that an operator's claim
about their own plant can only ever narrow the risk, that breadth still counts
after the worst three, and that the product form cannot be annihilated by one
unmeasured pillar.
"""

import pytest

from retrust import exposure, score
from retrust.match import Finding


def _finding(cve="CVE-2026-0001", cvss=9.8, epss=0.01, in_kev=False,
             ransomware=False, remediation="none_available", vector=None,
             fix_text=False):
    return Finding(cve=cve, advisory_id="A", cvss=cvss, cwe="CWE-787",
                   epss=epss, in_kev=in_kev, ransomware=ransomware,
                   version_range="", decided=True, remediation=remediation,
                   vector=vector, fix_text=fix_text)


# --- T: threat amplifies, it never zeroes the rest ---------------------------

def test_an_unexploited_critical_still_carries_weight():
    """The bug this guards: multiplying by raw EPSS collapsed every unexploited
    flaw to nothing, so a critical, reachable, unfixed vulnerability scored as
    harmless purely because nobody had attacked it yet."""
    remote = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    quiet = _finding(cvss=9.8, epss=0.005, vector=remote)   # OT median is 0.007
    assert exposure.risk(quiet) > 0.3
    # Confirmed exploitation must still be clearly worse than silence.
    assert exposure.risk(_finding(cvss=9.8, epss=0.005, in_kev=True,
                                  vector=remote)) > exposure.risk(quiet)
    # And a vector we cannot read is neither extreme.
    assert 0 < exposure.reach(_finding(vector=None)) < 1.0


def test_ransomware_is_the_top_of_the_threat_scale():
    assert exposure.threat(_finding(ransomware=True)) == 1.0
    assert exposure.threat(_finding(in_kev=True)) < 1.0


# --- H: severity carries the per-finding half of impact ----------------------

def test_severity_still_reaches_the_score():
    """z has no severity term of its own, so it enters through H. Without this
    a 9.8 and a 4.0 with equal EPSS scored identically."""
    assert exposure.risk(_finding(cvss=9.8)) > exposure.risk(_finding(cvss=4.0))


def test_an_undeclared_consequence_is_conservative_and_not_a_guess():
    """Unset must not silently become either extreme: it leaves the flaw's own
    severity undiscounted, which is the harsher reading, and says so."""
    undeclared = exposure.risk(_finding(cvss=9.8))
    assert undeclared == pytest.approx(exposure.risk(_finding(cvss=9.8),
                                                     consequence="safety"))
    assert exposure.risk(_finding(cvss=9.8), consequence="negligible") == 0.0


# --- the operator can only ever narrow --------------------------------------

@pytest.mark.parametrize("narrowing", [
    {"consequence": "minor"},
    {"interface": "blocked"},
    {"network": "isolated"},
    {"remediation": "applied"},
])
def test_declared_facts_can_only_lower_the_risk(narrowing):
    base = exposure.risk(_finding())
    assert exposure.risk(_finding(), **narrowing) <= base


# --- U: available is not applied --------------------------------------------

def test_a_fix_that_exists_is_not_a_fix_that_is_installed():
    fixed = _finding(remediation="vendor_fix")
    purchase = exposure.applicability(fixed, "purchase")
    installed = exposure.applicability(fixed, "installed")
    assert purchase == installed == 1.0
    assert exposure.applicability(fixed, "purchase", "available") == 1.0
    assert exposure.applicability(fixed, "installed", "applied") == 0.0
    assert exposure.applicability(fixed, "purchase", "planned") == 1.0


def test_planned_remediation_is_not_current_evidence_or_risk_reduction():
    finding = _finding(remediation="vendor_fix")
    risk_now = exposure.risk(finding, assessment_type="purchase")
    risk_planned = exposure.risk(finding, assessment_type="purchase",
                                 remediation="planned")
    assert risk_planned == risk_now
    assert exposure.measure([finding], remediation="planned")[1] == \
        exposure.measure([finding], remediation="unknown")[1]


# --- concentration, and the breadth it must not lose ------------------------

def test_the_worst_three_dominate():
    assert exposure.concentrate([1.0]) == pytest.approx(0.70)
    assert exposure.concentrate([1.0, 1.0, 1.0]) == pytest.approx(1.0)


def test_a_long_tail_of_equally_bad_findings_still_counts():
    """Top-three alone cannot tell three severe flaws from three hundred."""
    three = exposure.concentrate([0.8] * 3)
    many = exposure.concentrate([0.8] * 300)
    assert many > three
    # but breadth can never outvote the worst case
    assert many - three <= exposure.TAIL_WEIGHT + 1e-9


def test_concentration_is_bounded():
    assert exposure.concentrate([1.0] * 500) <= 1.0
    assert exposure.concentrate([]) == 0.0


# --- the product form -------------------------------------------------------

def test_one_bad_pillar_cannot_be_bought_back():
    """The point of a product rather than a mean: dangerous exposure must not be
    compensated by a good vendor and a certificate."""
    weights = score.DEFAULT_WEIGHTS
    specs = {spec.key: spec for spec in score.PILLARS}
    terrible = [(specs["exposure"], score.Pillar("Exposure", 2.0, 1.0)),
                (specs["patchability"], score.Pillar("Patch availability", 100.0, 1.0)),
                (specs["vendor_practice"], score.Pillar("Vendor practice", 100.0, 1.0)),
                (specs["certification"], score.Pillar("Certification", 100.0, 1.0))]
    assert score._composite(terrible, weights) < 40      # still AVOID


def test_the_floor_stops_one_pillar_annihilating_the_score():
    """A zero in a product is absorbing. The floor keeps a catastrophic pillar
    catastrophic without letting it erase every other measurement."""
    weights = score.DEFAULT_WEIGHTS
    specs = {spec.key: spec for spec in score.PILLARS}
    zeroed = [(specs["exposure"], score.Pillar("Exposure", 0.0, 1.0)),
              (specs["patchability"], score.Pillar("Patch availability", 70.0, 1.0))]
    result = score._composite(zeroed, weights)
    assert 0 < result < 20


# --- the reproducible vector ------------------------------------------------

def test_the_vector_records_every_choice_and_is_stable():
    first = score.vector("installed", "3.1.6", "it_ot", "blocked", "control",
                         "applied", "2026-10-05")
    assert first == score.vector("installed", "3.1.6", "it_ot", "blocked",
                                 "control", "applied", "2026-10-05")
    assert first.startswith(score.SCORING_VERSION)
    for fragment in ("AT:installed", "FW:3.1.6", "NX:it_ot", "IF:blocked",
                     "OC:control", "RS:applied"):
        assert fragment in first
    # An unanswered question reads as unset, never as a default that scored.
    assert "OC:unset" in score.vector()


def test_assessment_vector_keeps_supplied_firmware_and_provenance():
    token = score.provenance_token([
        {"source": "CISA KEV", "detail": "12 entries", "captured": "2026-10-01"}])
    result = score.assess("PLC", [_finding(cvss=5.0)], version="3.1.6",
                          snapshot=token)
    assert "FW:3.1.6" in result.vector
    assert f"DS:{token}" in result.vector
    assert token == score.provenance_token([
        {"source": "CISA KEV", "detail": "12 entries", "captured": "2026-10-01"}])
    assert token != score.provenance_token([
        {"source": "CISA KEV", "detail": "13 entries", "captured": "2026-10-01"}])
