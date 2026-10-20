"""Operator-reported OT network exposure is an optional, traceable score input."""

import pytest

from retrust import report, score, serve
from retrust.match import Finding


def _pillar(assessment, name):
    return next(p for p in assessment.pillars if p.name == name)


def _findings():
    """A minimal evidence base, so the core pillars have coverage.

    Empty findings no longer score -- absent evidence is excluded, not read
    as safety -- so these tests measure the exposure pillar against a real,
    tiny finding set instead of a vacuum.
    """
    return [Finding(cve="CVE-2026-0001", advisory_id="A", cvss=7.0, cwe=None,
                    epss=0.02, in_kev=False, ransomware=False,
                    version_range="", decided=True, remediation="vendor_fix")]


def test_network_exposure_is_an_input_not_a_weighted_pillar():
    """It narrows reachability inside Exposure instead of carrying its own weight.

    Scoring it separately double-counted one declared fact: "an attacker cannot
    route here" is the same statement reachability already makes.
    """
    assert sum(score.DEFAULT_WEIGHTS.values()) == pytest.approx(1.0)
    assert "network_exposure" not in score.DEFAULT_WEIGHTS


def test_omitting_network_exposure_preserves_the_scored_pillars():
    assessment = score.assess("Example", _findings(), {"A"})
    assert assessment.score is not None
    assert assessment.network_exposure is None
    network = _pillar(assessment, "Network exposure")
    assert not network.scored and network.coverage == 0


def test_declaring_the_deployment_can_only_narrow_reachability():
    """An operator's claim about their plant never makes a flaw worse.

    Saying nothing is already the conservative reading -- full reachability --
    so every declaration either improves the score or leaves it alone, and a
    tighter deployment must score at least as well as a looser one.
    """
    undeclared = score.assess("Example", _findings(), {"A"}).score
    scores = {level: score.assess("Example", _findings(), {"A"},
                                  network_exposure=level).score
              for level in ("isolated", "it_ot", "internet_ot")}
    assert scores["isolated"] > scores["it_ot"] > scores["internet_ot"]
    # Internet-exposed is the no-narrowing case, which is what silence assumed.
    assert scores["internet_ot"] == pytest.approx(undeclared, abs=0.1)
    assert all(value >= undeclared - 0.1 for value in scores.values())
    assert "Operator-reported" in _pillar(
        score.assess("Example", _findings(), {"A"}, network_exposure="it_ot"),
        "Network exposure").evidence[0]


def test_network_exposure_rejects_unknown_values():
    with pytest.raises(ValueError, match="network exposure"):
        score.assess("Example", _findings(), {"A"}, network_exposure="public")


def test_web_form_explains_and_retains_the_selected_network_context():
    form = serve._score_form("ABB", "AC 800M", "", network_exposure="it_ot")
    assert 'name="network_exposure"' in form
    assert 'value="it_ot" selected' in form
    assert "Operator-reported, not verified" in form
    # The whole owner-input group travels with it.
    for field in ("assessment_type", "consequence", "interface", "remediation"):
        assert f'name="{field}"' in form
    assert "Isolated" in form and "IT–OT" in form and "Internet–OT" in form


def test_report_shows_the_declared_deployment_as_a_diagnostic():
    """Still shown, with its number -- but marked not scored, because it is an
    input to Exposure rather than a term of its own."""
    assessment = score.assess(
        "Example", _findings(), {"A"},
        certificates=[{"scheme": "IEC 62443-4-1", "matches_product": False}],
        network_exposure="internet_ot")
    markup = report._pillar_table(assessment, score.DEFAULT_WEIGHTS)
    assert "Network access" in markup
    assert "Internet–OT" in markup
    assert "not scored" in markup


def test_a_declared_network_is_shown_as_used_not_discarded():
    """A reviewer reading "not scored" against a network exposure they had just
    declared reasonably concluded it was ignored. It is not: declaring it moved
    this product 21.6 points. The row now names where the input is used instead
    of only saying it carries no weight of its own."""
    from retrust import report
    declared = score.assess("Example", _findings(), {"A"},
                            network_exposure="isolated")
    markup = report._pillar_table(declared, score.DEFAULT_WEIGHTS)
    assert "within exposure" in markup
    # The three inputs to exposure say so; evidence quality still does not.
    assert report.FEEDS_EXPOSURE == {"Exploitation", "Severity", "Network exposure"}
    # And the declaration must actually change the number, not just the label.
    plain = score.assess("Example", _findings(), {"A"})
    assert declared.score > plain.score


# --- the declaration clamp --------------------------------------------------

_AV_NETWORK = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def _finding(cve, cvss, epss, remediation):
    return Finding(cve=cve, advisory_id="A", cvss=cvss, cwe="CWE-125",
                   epss=epss, in_kev=False, ransomware=False, version_range="",
                   decided=True, remediation=remediation, vector=_AV_NETWORK)


def _near_the_line():
    """A product that earns CONDITIONAL on evidence and PREFER if you declare.

    Two patched findings lift patch availability, one unpatched network-
    reachable medium holds exposure down, and the undeclared composite lands
    at 67.0 -- just under the PREFER threshold. That gap is the only state in
    which the clamp has anything to do, and a product has to be assembled
    deliberately to sit in it.
    """
    return [_finding("CVE-2026-0001", 4.0, 0.001, "vendor_fix"),
            _finding("CVE-2026-0002", 4.0, 0.001, "vendor_fix"),
            _finding("CVE-2026-9001", 7.0, 0.02, "none_available")]


RANK = {"AVOID": 0, "CONDITIONAL": 1, "PREFER": 2}


def test_the_fixture_really_sits_below_the_line():
    """Guards the tests below: a fixture that already earns PREFER proves nothing."""
    earned = score.assess("Example", _near_the_line(), {"A"})
    assert earned.verdict == "CONDITIONAL"
    assert 60 < earned.score < 70


@pytest.mark.parametrize("declaration", [
    {"network_exposure": "isolated"},
    {"network_exposure": "it_ot"},
    {"interface": "blocked"},
    {"remediation": "applied"},
    {"consequence": "negligible"},
    {"network_exposure": "isolated", "interface": "blocked",
     "remediation": "applied", "consequence": "negligible"},
])
def test_no_declaration_can_promote_the_verdict(declaration):
    """The bug this guards, measured on 489 real products with the clamp off:

    declarations produced 1,657 promotions, 552 of them AVOID straight to
    PREFER. Nobody can check "isolated" or "verified blocked", and because the
    discount scales each product's own vector mix it also reordered 118 of 119
    products in a comparison -- so an unverifiable dropdown was deciding
    procurement outcomes. With the clamp on, the same scan gives zero.
    """
    findings = _near_the_line()
    earned = score.assess("Example", findings, {"A"})
    declared = score.assess("Example", findings, {"A"}, **declaration)
    assert RANK[declared.verdict] <= RANK[earned.verdict]


def test_the_clamp_leaves_the_score_free_to_move_inside_the_band():
    """Clamping the band, not the number: declarations must still rank candidates.

    A clamp on the score would throw the refinement away. Clamping the band
    keeps the number usable for comparing candidates while keeping the verdict
    on evidence.
    """
    findings = _near_the_line()
    earned = score.assess("Example", findings, {"A"})
    declared = score.assess("Example", findings, {"A"},
                            network_exposure="isolated")
    assert declared.score > earned.score
    assert declared.verdict == earned.verdict


def test_the_clamp_says_why_it_fired():
    """A number the tool silently refused to honour would be worse than no clamp."""
    declared = score.assess("Example", _near_the_line(), {"A"},
                            network_exposure="isolated")
    assert any("on evidence alone" in note for note in declared.notes)


def test_a_product_that_earns_prefer_is_not_clamped():
    """The clamp must not cap a verdict the evidence already supports."""
    clean = [_finding("CVE-2026-0001", 2.0, 0.0001, "vendor_fix")]
    earned = score.assess("Example", clean, {"A"})
    declared = score.assess("Example", clean, {"A"}, network_exposure="isolated")
    assert earned.verdict == declared.verdict == "PREFER"
    assert not any("on evidence alone" in note for note in declared.notes)


def test_only_a_real_declaration_trips_the_clamp():
    """`narrows` is the guard: with nothing declared there is nothing to clamp."""
    assert not score.narrows()
    assert not score.narrows(interface="unknown", remediation="unknown")
    assert score.narrows(network_exposure="isolated")
    assert score.narrows(consequence="safety")
    assert score.narrows(interface="blocked")
    assert score.narrows(remediation="applied")
