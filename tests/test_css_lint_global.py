"""Global CSS lint over the two assembled stylesheets (Redesign-plan WP12).

`webui.STYLESHEET` is what every web page ships; `report.export_css()` is what
the self-contained export ships. The per-module tests lint the pieces; this one
lints what actually reaches a browser, including the cross-module rules the
pieces cannot see: shadows, gradients, reserved status hues and motion.
"""
import re

import pytest

from design_lint import css_lint
from retrust import report, webui

SHEETS = {"web": webui.STYLESHEET, "export": report.export_css()}


# ---------------------------------------------------------------------------
# A tiny rule walker. Not a CSS parser: the stylesheets are plain strings
# with no braces inside string values, so brace depth is enough.

def rules(css):
    """List of (at_rules, selector, body) for every block, nesting flattened."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    stack, buf, out = [], "", []
    for ch in css:
        if ch == "{":
            stack.append(buf.strip())
            buf = ""
        elif ch == "}":
            if buf.strip():
                out.append((tuple(stack[:-1]), stack[-1], buf.strip()))
            buf = ""
            stack.pop()
        else:
            buf += ch
    return out


def selectors(selector):
    return [part.strip() for part in selector.split(",") if part.strip()]


def style_rules(css):
    """Style rules only: no @font-face / @keyframes bodies or their steps."""
    return [(at, sel, body) for at, sel, body in rules(css)
            if not sel.startswith("@")
            and not any(a.startswith(("@keyframes", "@font-face")) for a in at)]


# ---------------------------------------------------------------------------
# 1. The shared lint: no data: URLs, @import, http; type floor; radius ceiling.

@pytest.mark.parametrize("name", SHEETS)
def test_shared_lint_is_clean(name):
    assert css_lint(SHEETS[name]) == []


# ---------------------------------------------------------------------------
# 2. Shadows are for things that float. A focus ring and the selected-row edge
#    are zero-blur indicators, not elevation, so they are listed separately.

OVERLAY = re.compile(
    r"\.rt-menu__list|\.rt-toast(?![\w-])|\.rt-suggest(?![\w-])"
    r"|\.ev-drawer|\.rt-confirm|\.rt-tip__bubble|\.rt-popover")
INDICATOR = re.compile(r":focus-visible|:focus-within|\.rt-suggest__row")
DROP_SHADOW = re.compile(r"-?\d+px\s+-?\d+px\s+[1-9]\d*px")


@pytest.mark.parametrize("name", SHEETS)
def test_box_shadow_only_on_overlays(name):
    bad = []
    for _, sel, body in style_rules(SHEETS[name]):
        for decl in re.findall(r"box-shadow\s*:\s*([^;]+)", body):
            if decl.strip() == "none":
                continue
            for part in selectors(sel):
                if OVERLAY.search(part):
                    continue
                if INDICATOR.search(part) and not DROP_SHADOW.search(decl) \
                        and "overlay-shadow" not in decl:
                    continue
                bad.append("%s { box-shadow: %s }" % (part, decl.strip()))
    assert bad == []


# ---------------------------------------------------------------------------
# 3. No gradients except the hatching that marks "unknown / range".

@pytest.mark.parametrize("name", SHEETS)
def test_no_gradients_except_hatching(name):
    bad = []
    seen = 0
    for _, sel, body in style_rules(SHEETS[name]):
        for kind in re.findall(r"([\w-]*gradient)\(", body):
            seen += 1
            if kind != "repeating-linear-gradient":
                bad.append("%s uses %s" % (sel, kind))
    assert bad == []
    assert seen, "no gradient found at all; the walker is broken"


# ---------------------------------------------------------------------------
# 4. Reserved hues carry status and nothing else. The families below are the
#    selectors that, in the CSS as it stands, say "verdict", "status", "fix",
#    "gap", "unknown" or "destructive". A new decorative use fails here.

STATUS_HUE = re.compile(r"var\(--(prefer|conditional|avoid|verify)(-fill|-edge|-track|-alert)?\)")
ACTION_VAR = re.compile(r"var\(--action(?:-hover)?\)")
COLOUR_PROP = re.compile(r"(?:^|;)\s*(?:color|background(?:-color)?|border(?:-[a-z]+)*"
                         r"|fill|stroke|text-decoration-color)\s*:\s*([^;]+)")

STATUS_FAMILIES = [
    r"\.rt-badge",                                     # verdict badge
    r"\.rt-chip",                                      # fix / KEV / warning chips
    r"\.rt-alert",                                     # blocker / review / error alerts
    r"\.rt-gap(?![\w-])|\.rt-gap__",                   # gap cards (not .rt-gaps)
    r"\.rt-q__(?:gap|tag)",                            # supplier-question gap tags
    r"\.rt-cond--unknown",                             # unknown condition value
    r"\.rt-field--(?:error|unverified|unknown|select)|\.rt-field__(?:error|flag|ok)",
    r"\.rt-meta--unverified",                          # "not verified" firmware chip
    r"\.rt-toast",                                     # toast status glyphs
    r"\.rt-band__(?:seg|range)",                       # verdict band and unknown range
    r"\.rt-pillar(?:__fill|__miss|--neutral)|\.rt-pillars__note",  # pillar meters and gaps
    r"\.rt-score__line--verify",                       # "verification open" score line
    r"\.rt-strip__tick",                               # check mark of the all-clear strip
    r"\.rt-snap--",                                    # snapshot status dot
    r"\.rt-supplier-review",                           # supplier review needed flag
    r"\.rt-cmp__(?:gate|val--neutral|hatch)",          # comparison gate and unknown bars
    r"\.rt-btn--destructive",                          # clear shortlist: avoid means destroy
    r"\.ev-(?:range|unk)(?![\w-])",                    # unknown / range values in evidence
    r"^\.note$",                                       # caution notice (conditional edge)
]
STATUS_RE = re.compile("|".join("(?:%s)" % f for f in STATUS_FAMILIES))


@pytest.mark.parametrize("name", SHEETS)
def test_reserved_hues_only_in_status_selectors(name):
    bad = set()
    for _, sel, body in style_rules(SHEETS[name]):
        if STATUS_HUE.search(body):
            bad.update(p for p in selectors(sel) if not STATUS_RE.search(p))
    assert sorted(bad) == [], "decorative use of a reserved status hue"


def test_the_whitelist_is_not_stale():
    """Every family still matches a real rule, so the list cannot rot into a free pass."""
    used = [part for _, sel, body in style_rules(SHEETS["web"])
            if STATUS_HUE.search(body) for part in selectors(sel)]
    for family in STATUS_FAMILIES:
        assert any(re.search(family, part) for part in used), family


def test_the_whitelist_rejects_a_decorative_selector():
    for decorative in (".rt-card", ".rt-header", ".rt-nav a", ".rt-panel-label", "h2",
                       ".rt-gaps", ".rt-pillar__name", ".rt-score__num"):
        assert not STATUS_RE.search(decorative), decorative


# Selectors that are the status mark itself. Links and focus rings inside an
# alert are interactive, not status, and may use the action colour.
STATUS_MARK = re.compile(
    r"\.rt-badge|\.rt-chip(?![\w-]*__)|\.rt-gap(?![\w-])|\.rt-toast__glyph|\.rt-snap"
    r"|\.rt-band__seg|\.rt-pillar__fill--(?:prefer|conditional|avoid)|\.ev-(?:range|unk)(?![\w-])"
    r"|--(?:prefer|conditional|avoid|verify|unverified|unknown|error|neutral)(?![\w-])")


@pytest.mark.parametrize("name", SHEETS)
def test_action_colour_is_not_used_for_status(name):
    bad = []
    for _, sel, body in style_rules(SHEETS[name]):
        for m in COLOUR_PROP.finditer(body):
            if not ACTION_VAR.search(m.group(1)):
                continue
            bad.extend("%s { %s }" % (p, m.group(0).strip("; "))
                       for p in selectors(sel) if STATUS_MARK.search(p))
    assert bad == []


# ---------------------------------------------------------------------------
# 5. Motion. The base sheet ends with one universal reduced-motion rule that
#    kills every transition and animation, so a transition added anywhere else
#    is neutralised without anyone having to remember a per-component override.

@pytest.mark.parametrize("name", SHEETS)
def test_motion_is_neutralised_by_reduced_motion(name):
    css = SHEETS[name]
    reduced = [(sel, body) for at, sel, body in style_rules(css)
               if any("prefers-reduced-motion" in a and "reduce" in a for a in at)]
    universal = [body for sel, body in reduced if sel.replace(" ", "") == "*,*::before,*::after"]
    assert universal, "no universal reduced-motion rule"
    body = universal[0].replace(" ", "")
    assert "transition:none!important" in body and "animation:none!important" in body
    moving = [sel for at, sel, b in style_rules(css)
              if re.search(r"(?<![-\w])(?:transition|animation)\s*:", b)
              and not any("prefers-reduced-motion" in a for a in at)]
    assert moving, "the lint found no motion at all; the walker is broken"
    # Nothing inside the block re-enables motion.
    for sel, b in reduced:
        for decl in re.findall(r"(?:transition|animation)\s*:\s*([^;]+)", b):
            assert decl.strip().startswith(("none", "visibility 0s")), sel
