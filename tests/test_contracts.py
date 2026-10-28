"""Contract layer: the public names exist and the CSS split is stable."""

import inspect

import pytest

from retrust import components, design, evidenceview, report

def test_report_css_keeps_its_public_names():
    # The split names other modules import must still exist; the web page
    # assembles RESULT_CSS (not the light THEME) and the export both.
    from retrust import webui
    assert report.THEME and report.RESULT_CSS and report.EXPORT_CSS
    assert report.RESULT_CSS in webui.STYLESHEET and report.THEME not in webui.STYLESHEET
    assert report.RESULT_CSS in report.export_css() and report.THEME in report.export_css()


def test_dark_theme_css_contains_every_spec_hex():
    css = design.theme_css(design.DARK, ":root")
    assert css.startswith(":root{")
    for hexv in ("#0B0E13", "#0F131A", "#131821", "#1E2633", "#263042",
                 "#6F7F99", "#E6EAF0", "#C5CCD8", "#8B96A8", "#5CCBEE",
                 "#9BE0F5", "#06121A", "#2FBFA0", "#F0A53A", "#FF6B5E",
                 "#A78BFA", "#1A0604"):
        assert hexv in css


def test_theme_css_has_derived_and_scale_tokens():
    css = design.theme_css(design.LIGHT, ":root[data-theme=dark]")
    assert css.startswith(":root[data-theme=dark]{")
    for status in ("prefer", "conditional", "avoid", "verify"):
        for part in ("fill", "edge", "track"):
            assert "--%s-%s:#" % (status, part) in css
    for name in ("--avoid-alert:", "--overlay-shadow:", "--s2:2px",
                 "--s48:48px", "--r-sm:2px", "--r-card:6px",
                 "--t-fast:120ms", "--t-load:200ms", "--font-sans:",
                 "--font-mono:"):
        assert name in css
    assert css.count("{") == 1 and css.endswith("}\n")


def test_alpha():
    assert design.alpha("#FF6B5E", 0.14) == "#FF6B5E24"
    assert design.alpha("#ff6b5e", 0.5) == "#FF6B5E80"
    assert design.alpha("#000000", 0) == "#00000000"
    assert design.alpha("#000000", 1) == "#000000FF"
    with pytest.raises(ValueError):
        design.alpha("#FFF", 0.5)
    with pytest.raises(ValueError):
        design.alpha("#FFFFFF", 1.5)


def test_base_and_print_css_are_not_empty():
    assert design.BASE_CSS != "" and design.PRINT_CSS != ""


def test_webview_constructs_with_defaults():
    view = report.WebView()
    assert isinstance(view.evidence, evidenceview.EvidenceView)
    assert view.advisories == {} and view.checks == {} and view.field_ids == {}
    assert view.actions_html == view.order_number == view.version == ""
    assert report.WebView().evidence is not view.evidence


def test_esc_escapes_quotes_and_angle_brackets():
    assert components.esc('<a href="x">&\'') == (
        "&lt;a href=&quot;x&quot;&gt;&amp;&#x27;")


def test_evidenceview_contract_signatures():
    # The signatures report.py calls are pinned here; behaviour is in
    # test_evidence_view.
    def names(fn):
        return [p.name for p in inspect.signature(fn).parameters.values()
                if p.kind is p.POSITIONAL_OR_KEYWORD]
    assert names(evidenceview.shown) == ["findings", "assessment", "view"]
    assert names(evidenceview.rank) == ["findings", "assessment", "view"]
    assert names(evidenceview.counts) == ["findings", "assessment"]
    assert names(evidenceview.exposure_card) == ["assessment"]
    assert names(evidenceview.evidence_card) == ["findings", "assessment", "view"]
    assert names(evidenceview.drawers) == ["findings", "assessment", "view",
                                           "advisories"]


def test_glyphs():
    assert set(components.GLYPH) == {"PREFER", "CONDITIONAL", "AVOID",
                                    "VERIFY", "OK"}
