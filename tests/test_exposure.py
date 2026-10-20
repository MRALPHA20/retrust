"""The concentrated exposure model, and the properties it must keep.

These pin the decisions behind ReTrust-OT V1 so a later edit cannot quietly
undo one: that threat amplifies rather than decides, that an operator's claim
about their own plant can only ever narrow the risk, that breadth still counts
after the worst three, and that the product form cannot be annihilated by one
unmeasured pillar.
"""

import pytest

from retrust import cvss, exposure, score
from retrust.match import Finding


def _finding(cve="CVE-2026-0001", cvss=9.8, epss=0.01, in_kev=False,
             ransomware=False, remediation="none_available", vector=None,
             fix_text=False, lev=None):
    return Finding(cve=cve, advisory_id="A", cvss=cvss, cwe="CWE-787",
                   epss=epss, in_kev=in_kev, ransomware=ransomware,
                   version_range="", decided=True, remediation=remediation,
                   vector=vector, fix_text=fix_text, lev=lev)


# --- T: four signals, the strongest wins -------------------------------------

def test_lev_reaches_the_score():
    """The gap this closes: 12,003 LEV estimates sat unread by the score.

    `lev.Estimate.composite` had computed max(KEV, LEV, EPSS) for the LEV
    report since before the score existed, but `threat` read only KEV and
    EPSS -- so the one exploitation signal with a non-trivial corpus median
    (0.167, against EPSS's 0.007) was published on its own page and ignored
    where it mattered.
    """
    assert exposure.threat(_finding(epss=0.008, lev=None)) == pytest.approx(0.008)
    assert exposure.threat(_finding(epss=0.008, lev=0.24)) == pytest.approx(0.24)


def test_an_observation_outranks_any_model():
    """KEV is a sighting; LEV and EPSS are estimates. No estimate may beat one."""
    assert exposure.threat(_finding(in_kev=True, lev=0.99, epss=0.99)) == \
        pytest.approx(exposure.KEV_THREAT)
    assert exposure.threat(_finding(lev=0.99, epss=0.99)) == \
        pytest.approx(exposure.MODEL_CEILING)
    assert exposure.MODEL_CEILING < exposure.KEV_THREAT


def test_no_signal_at_all_is_not_zero_threat():
    assert exposure.threat(_finding(epss=None, lev=None)) == exposure.UNRATED_THREAT


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

def test_the_worst_path_counts_in_full():
    """A single maximal flaw has to be able to reach maximal risk.

    At the previous 0.70 leading weight this returned 0.70 -- E = 30 -- because
    30% of the score was reserved for flaws the product did not happen to have.
    One reachable, unfixed, confirmed-exploited, process-ending vulnerability is
    the case a buyer most needs the number to get right.
    """
    assert exposure.concentrate([1.0]) == pytest.approx(1.0)
    assert exposure.concentrate([0.48]) == pytest.approx(0.48)


def test_further_paths_add_to_the_worst_one():
    """A real device has several routes in, so paths two and three add on top.

    The two figures are the specification's own worked example: one path at
    0.48 gives E = 52, and adding 0.20 and 0.10 gives E = 47.
    """
    assert exposure.concentrate([0.48]) == pytest.approx(0.48)
    assert exposure.concentrate([0.48, 0.20, 0.10]) == pytest.approx(0.53)
    assert exposure.concentrate([0.4, 0.4, 0.4]) > exposure.concentrate([0.4])


def test_breadth_beyond_three_paths_is_not_counted():
    """Pins what the specified R gives up, so nobody rediscovers it as a bug.

    R = min(1, z1 + 0.20 z2 + 0.10 z3) counts three paths and clips at 1, so
    three severe flaws and three hundred score alike, and 5.7% of a 582-product
    sample lands at exactly E = 0 where ranking stops. This is a consequence of
    the chosen formula, not an oversight: restoring breadth is one term,
    `+ TAIL_WEIGHT * mean(ordered[3:])` inside the min.
    """
    assert exposure.concentrate([0.8] * 3) == exposure.concentrate([0.8] * 300)
    assert exposure.concentrate([0.8] * 3) == pytest.approx(1.0)


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


# --- the unmitigable invariant, stated as a property ------------------------

def test_an_unfixable_credential_can_never_read_prefer():
    """The cap engages only when the composite would otherwise reach PREFER, so
    asserting the cap NOTE is testing the mechanism. The invariant is the thing:
    a credential the operator cannot change must never earn a favourable
    verdict, whether that is because the cap fired or because the score never
    got there."""
    strong = [_finding(cve="CVE-2026-1000", cvss=2.0, epss=0.0,
                       remediation="vendor_fix", fix_text=True)]
    creds = _finding(cve="CVE-2026-2000", cvss=9.8, epss=0.9,
                     remediation="none_available")
    creds.cwe = "CWE-798"                      # hardcoded credentials, no fix
    assessment = score.assess("x", strong + [creds], {"A"},
                              certificates=[{"scheme": "IEC 62443-4-2",
                                             "matches_product": True}])
    assert assessment.verdict != "PREFER"


# --- A: the exploitation conditions CVSS itself records ----------------------

_NEEDS_NOTHING = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
_NEEDS_ACCOUNT = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
_NEEDS_A_CLICK = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
_NEEDS_CONDITIONS = "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H"


@pytest.mark.parametrize("vector", [_NEEDS_ACCOUNT, _NEEDS_A_CLICK,
                                    _NEEDS_CONDITIONS])
def test_ruling_out_the_conditions_narrows_a_flaw_that_has_them(vector):
    """Privileges, user interaction and v4 attack requirements, read as one."""
    finding = _finding(vector=vector)
    assert exposure.reach(finding, prerequisites="unsatisfiable") < \
        exposure.reach(finding)


@pytest.mark.parametrize("vector", [_NEEDS_NOTHING, None])
def test_a_flaw_that_demands_nothing_cannot_be_ruled_out(vector):
    """The trap this avoids, and the reason the question is read per finding.

    The operator answers once for the product, but an unauthenticated,
    no-interaction flaw never had a condition to verify impossible. Applying
    the answer flatly would discount exactly the findings that need no
    conditions met -- the most dangerous ones -- on the strength of a claim
    about different findings entirely.
    """
    finding = _finding(vector=vector)
    assert exposure.reach(finding, prerequisites="unsatisfiable") == \
        pytest.approx(exposure.reach(finding))


def test_saying_the_conditions_are_satisfiable_changes_nothing():
    """Confirming the worst case is already the assumption, so it cannot move."""
    finding = _finding(vector=_NEEDS_ACCOUNT)
    assert exposure.reach(finding, prerequisites="satisfiable") == \
        pytest.approx(exposure.reach(finding, prerequisites="unknown"))


def test_demands_conditions_reads_all_three_cvss_generations():
    assert not exposure.demands_conditions(cvss.parse(_NEEDS_NOTHING))
    assert exposure.demands_conditions(cvss.parse(_NEEDS_ACCOUNT))
    assert exposure.demands_conditions(cvss.parse(_NEEDS_A_CLICK))
    assert exposure.demands_conditions(cvss.parse(_NEEDS_CONDITIONS))
    # v2 spells privileges "Au" and never asked about interaction at all.
    assert exposure.demands_conditions(cvss.parse("AV:N/AC:L/Au:S/C:C/I:C/A:C"))
    assert not exposure.demands_conditions(cvss.parse("AV:N/AC:L/Au:N/C:C/I:C/A:C"))
    assert not exposure.demands_conditions(None)


# --- the worst single flaw, reported because exposure clips ------------------

def test_the_worst_flaw_still_separates_products_the_score_has_flattened():
    """Three severe paths clip R at 1, so E = 0 for every product past that.

    Moxa EDS-405A, Rockwell ControlLogix and Schneider M340 all clip, leaving
    5.9/5.9/6.0 -- which is not a ranking. The highest single z keeps working
    after exposure has bottomed out.
    """
    bad = [_finding(cve=f"CVE-2026-{i:04d}", cvss=9.8, in_kev=True,
                    vector=_NEEDS_NOTHING) for i in range(3)]
    worse = bad + [_finding(cve="CVE-2026-9999", cvss=10.0, ransomware=True,
                            vector=_NEEDS_NOTHING)]
    assert exposure.concentrate([exposure.risk(f) for f in bad]) == \
        exposure.concentrate([exposure.risk(f) for f in worse]) == 1.0
    assert exposure.worst(worse) > exposure.worst(bad)


def test_the_worst_flaw_is_none_when_there_is_nothing_to_rank():
    assert exposure.worst([]) is None
