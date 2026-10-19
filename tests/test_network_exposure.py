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
