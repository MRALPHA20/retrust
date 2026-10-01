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


def test_default_weights_reserve_ten_percent_for_network_exposure():
    assert sum(score.DEFAULT_WEIGHTS.values()) == pytest.approx(1.0)
    assert score.DEFAULT_WEIGHTS["network_exposure"] == pytest.approx(0.10)


def test_omitting_network_exposure_preserves_the_scored_pillars():
    assessment = score.assess("Example", _findings(), {"A"})
    assert assessment.score is not None
    assert assessment.network_exposure is None
    network = _pillar(assessment, "Network exposure")
    assert not network.scored and network.coverage == 0


@pytest.mark.parametrize(
    ("exposure", "pillar_score"),
    [("isolated", 100), ("it_ot", 60), ("internet_ot", 20)],
)
def test_network_exposure_adds_a_weighted_pillar(exposure, pillar_score):
    base = score.assess("Example", _findings(), {"A"})
    assessment = score.assess("Example", _findings(), {"A"},
                              network_exposure=exposure)
    assert _pillar(assessment, "Network exposure").score == pillar_score
    assert "Operator-reported" in _pillar(assessment, "Network exposure").evidence[0]
    # The pillar moves the composite in its own direction: a worse exposure
    # must never raise the score, a perfect one never lower it.
    if pillar_score < base.score:
        assert assessment.score < base.score
    else:
        assert assessment.score >= base.score


def test_network_exposure_rejects_unknown_values():
    with pytest.raises(ValueError, match="network exposure"):
        score.assess("Example", _findings(), {"A"}, network_exposure="public")


def test_web_form_explains_and_retains_the_selected_network_context():
    form = serve._score_form("ABB", "AC 800M", "", network_exposure="it_ot")
    assert 'name="network_exposure"' in form
    assert 'value="it_ot" selected' in form
    assert "Default weight 10%" in form
    assert "Isolated" in form and "IT–OT" in form and "Internet–OT" in form


def test_report_shows_the_network_pillar_and_its_weight():
    # A certificate keeps every pillar covered, so the configured weights show
    # unrenormalized in the table.
    assessment = score.assess(
        "Example", _findings(), {"A"},
        certificates=[{"scheme": "IEC 62443-4-1", "matches_product": False}],
        network_exposure="internet_ot")
    markup = report._pillar_table(assessment, score.DEFAULT_WEIGHTS)
    assert "Network exposure" in markup
    assert "Internet–OT" in markup
    assert '<td class="n">0.100</td>' in markup
