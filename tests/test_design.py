"""Spec 2.1 tokens, WCAG contrast claims and base/print CSS invariants."""
import pytest

from design_lint import css_lint
from retrust import design

SPEC_DARK = {
    "ground": "#0B0E13", "bar": "#0F131A", "surface": "#131821",
    "raised": "#1E2633", "rule": "#263042", "rule-row": "#1E2633",
    "control-border": "#6F7F99", "text": "#E6EAF0", "text-2": "#C5CCD8",
    "muted": "#8B96A8", "action": "#5CCBEE", "action-hover": "#9BE0F5",
    "on-action": "#06121A", "prefer": "#2FBFA0", "conditional": "#F0A53A",
    "avoid": "#FF6B5E", "verify": "#A78BFA", "on-avoid": "#1A0604",
}


def _rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))


def luminance(h):
    def lin(c):
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (lin(c) for c in _rgb(h))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def ratio(a, b):
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def composite(fg, alpha, bg):
    f, b = _rgb(fg), _rgb(bg)
    out = [alpha * x + (1 - alpha) * y for x, y in zip(f, b)]
    return "#%02X%02X%02X" % tuple(int(round(c * 255)) for c in out)


def test_dark_tokens_match_spec():
    assert design.DARK == SPEC_DARK


D = design.DARK


@pytest.mark.parametrize("fg,bg,claimed", [
    ("text", "surface", 14.7), ("muted", "surface", 6.0),
    ("muted", "raised", 5.1), ("action", "surface", 9.5),
    ("prefer", "surface", 7.7), ("conditional", "surface", 8.6),
    ("avoid", "surface", 6.4), ("verify", "surface", 6.5),
])
def test_spec_contrast_claims_on_dark(fg, bg, claimed):
    assert ratio(D[fg], D[bg]) == pytest.approx(claimed, abs=0.15)


def test_spec_button_claims():
    assert ratio(D["on-action"], D["action"]) == pytest.approx(10.1, abs=0.15)
    assert ratio(D["on-avoid"], D["avoid"]) == pytest.approx(7.0, abs=0.15)


def test_control_border_dark():
    # Spec prose says 4.4:1; the 3:1 non-text floor is what is required.
    r = ratio(D["control-border"], D["surface"])
    assert r >= 3.0 and r == pytest.approx(4.4, abs=0.3)


L = design.LIGHT


@pytest.mark.parametrize("fg", ["text", "text-2", "muted", "action",
                                "action-hover", "prefer", "conditional",
                                "avoid", "verify"])
@pytest.mark.parametrize("bg", ["ground", "surface", "bar", "raised"])
def test_light_text_pairs(fg, bg):
    if bg == "raised" and fg in ("prefer", "conditional", "avoid", "verify"):
        pytest.skip("status text is not placed on raised")
    assert ratio(L[fg], L[bg]) >= 4.5, (fg, bg, ratio(L[fg], L[bg]))


def test_light_button_pairs_and_borders():
    assert ratio(L["on-action"], L["action"]) >= 4.5
    assert ratio(L["on-avoid"], L["avoid"]) >= 4.5
    for bg in ("surface", "ground"):
        assert ratio(L["control-border"], L[bg]) >= 3.0


@pytest.mark.parametrize("theme", [design.DARK, design.LIGHT],
                         ids=["dark", "light"])
def test_composited_tints(theme):
    for st in design.STATUSES:
        fill = composite(theme[st], 0.14, theme["surface"])
        assert ratio(theme[st], fill) >= 4.5, st
    alert = composite(theme["avoid"], 0.10, theme["ground"])
    assert ratio(theme["text-2"], alert) >= 4.5


def test_theme_css_shape():
    css = design.theme_css(design.DARK, ":root")
    assert css.startswith(":root{") and "--avoid-alert:#FF6B5E1A" in css


def test_base_css_rules_present():
    css = design.BASE_CSS
    assert "prefers-reduced-motion:reduce" in css
    assert "transition:none" in css and "animation:none" in css
    assert ":focus-visible{outline:2px solid var(--action);outline-offset:2px}" in css
    assert "pointer:coarse" in css and "min-height:44px" in css
    assert "max-width:1360px" in css and ".sr-only" in css and ".skip-link" in css
    assert "tabular-nums" in css and "rt-pulse" in css
    assert "{{" not in css


def test_print_css_rules_present():
    css = design.PRINT_CSS
    assert css.startswith("@media print{")
    assert "--ground:#FFFFFF" in css and "--avoid:#B42318" in css
    assert "break-inside:avoid" in css
    assert "thead{display:table-header-group}" in css
    assert css.count("{") == css.count("}")


def test_print_css_hides_site_chrome_not_the_identity_header():
    """A bare `header` selector also hid <header class="rt-identity">, so a
    printed verdict carried no product. Every hiding selector must name real
    classes (rt-card / rt-toast, not card / toast)."""
    css = design.PRINT_CSS
    hide = next(rule for rule in css.split(chr(10)) if "display:none!important" in rule
                and "[popover]" in rule)
    selectors = [part.strip() for part in hide.split("{")[0].split(",")]
    assert "header" not in selectors and ".rt-header" in selectors
    assert "rt-identity" not in hide
    assert ".card{" not in css and ".toast" not in hide.replace(".rt-toast", "")
    assert ".rt-card{break-inside:avoid}" in css


@pytest.mark.parametrize("css", [design.BASE_CSS, design.PRINT_CSS,
                                 design.theme_css(design.DARK),
                                 design.theme_css(design.LIGHT)])
def test_css_is_lint_clean(css):
    assert css_lint(css) == []


def test_css_lint_catches_problems():
    bad = ("a{background:url(data:x)}@import 'x';b{font-size:11px}"
           "c{font-size:.5rem}d{border-radius:8px}e{border-radius:50%}"
           "f{border-radius:999px}g{font:11px/1.3 x}h{border-radius:4px 7px}")
    assert len(css_lint(bad)) == 8
    assert css_lint("a{font-size:.75rem;border-radius:50%;border-radius:6px}") == []
    assert css_lint("a{background:url(http://x)}") != []
