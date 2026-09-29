"""Operator-reported OT network exposure is an optional, traceable score input."""

import pytest

from retrust import report, score, serve


def _pillar(assessment, name):
    return next(p for p in assessment.pillars if p.name == name)


def test_default_weights_reserve_ten_percent_for_network_exposure():
    assert sum(score.DEFAULT_WEIGHTS.values()) == pytest.approx(1.0)
    assert score.DEFAULT_WEIGHTS["network_exposure"] == pytest.approx(0.10)


def test_omitting_network_exposure_preserves_the_five_pillar_score():
    assessment = score.assess("Example", [])
    assert assessment.score == pytest.approx(85.0)
    assert assessment.network_exposure is None
    network = _pillar(assessment, "Network exposure")
    assert not network.scored and network.coverage == 0


@pytest.mark.parametrize(
    ("exposure", "pillar_score", "composite"),
    [("isolated", 100, 86.5), ("it_ot", 60, 82.5),
     ("internet_ot", 20, 78.5)],
)
def test_network_exposure_adds_a_ten_percent_pillar(exposure, pillar_score, composite):
    assessment = score.assess("Example", [], network_exposure=exposure)
    assert _pillar(assessment, "Network exposure").score == pillar_score
    assert assessment.score == pytest.approx(composite)
    assert "Operator-reported" in _pillar(assessment, "Network exposure").evidence[0]


def test_network_exposure_rejects_unknown_values():
    with pytest.raises(ValueError, match="network exposure"):
        score.assess("Example", [], network_exposure="public")


def test_web_form_explains_and_retains_the_selected_network_context():
    form = serve._score_form("ABB", "AC 800M", "", network_exposure="it_ot")
    assert 'name="network_exposure"' in form
    assert 'value="it_ot" selected' in form
    assert "Default weight 10%" in form
    assert "Isolated" in form and "IT–OT" in form and "Internet–OT" in form


def test_report_shows_the_network_pillar_and_its_weight():
    assessment = score.assess("Example", [], network_exposure="internet_ot")
    markup = report._pillar_table(assessment, score.DEFAULT_WEIGHTS)
    assert "Network exposure" in markup
    assert "Internet–OT" in markup
    assert '<td class="n">0.100</td>' in markup
