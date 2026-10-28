"""Design tokens and colour maths for the Control Room redesign.

This module is the contract layer (WP0): the names below are stable, WP1 fills
in BASE_CSS and PRINT_CSS. Nothing in the running app imports it yet.

Decisions confirmed by the user (Redesign-plan.md section 7):

D1  JavaScript is in scope (WP9): one same-origin external script
    /static/retrust.js, CSP script-src 'self'; connect-src 'self', no inline
    scripts, no on*= handlers, no external URLs. Every page must still work
    with JS disabled.
D2  Fonts: self-host IBM Plex. The export uses local() plus the system stack.
D3  Type floor is 12px; the spec's 11px sizes become 12px.
D4  Ranking: keep the existing evidence selection and order (top 10 by EPSS).
    batch.to_detail is untouched. An explicit sort= applies to the full
    in-scope list before the cap; no sort keeps today's order.
D5  Nav has 4 items: Assess, Compare, Search, Methodology.
D6  Shortlist is URL-only: no persistence, count chip or drag reorder.

CSS assembly order (A2). CSS is always plain string constants, never f-strings,
so it is fingerprinted and unit-testable.

  Web page:
    theme_css(DARK, ":root") + assets.font_face_css(served=True) + BASE_CSS
    + components.CSS + evidenceview.CSS + report.RESULT_CSS
    + webui.SHELL_CSS + webui.PAGE_CSS + PRINT_CSS
  Export:
    theme_css(LIGHT, ":root") + theme_css(DARK, ":root[data-theme=dark]")
    + font_face_css(served=False) + BASE_CSS + components.CSS
    + evidenceview.CSS + report.RESULT_CSS + report.EXPORT_CSS
  The dark selector stays only for screenshot.capture_both_themes; there is no
  prefers-color-scheme auto-dark.
"""

# Spec 2.1 / 2.6, exact. Keys are token names without the leading "--".
DARK = {
    "ground": "#0B0E13",
    "bar": "#0F131A",
    "surface": "#131821",
    "raised": "#1E2633",
    "rule": "#263042",
    "rule-row": "#1E2633",
    "control-border": "#6F7F99",
    "text": "#E6EAF0",
    "text-2": "#C5CCD8",
    "muted": "#8B96A8",
    "action": "#5CCBEE",
    "action-hover": "#9BE0F5",
    "on-action": "#06121A",
    "prefer": "#2FBFA0",
    "conditional": "#F0A53A",
    "avoid": "#FF6B5E",
    "verify": "#A78BFA",
    "on-avoid": "#1A0604",
}

# Spec 5.5 plus the plan's proposals (WP1 table) for tokens the spec leaves open.
LIGHT = {
    "ground": "#FFFFFF",
    "bar": "#EEF1F4",
    "surface": "#F6F8FA",
    "raised": "#E5E9EF",
    "rule": "#D5DBE3",
    "rule-row": "#E3E7ED",
    "control-border": "#6B7686",
    "text": "#111827",
    "text-2": "#374151",
    "muted": "#5B6472",
    "action": "#0B6E8E",
    "action-hover": "#095A74",
    "on-action": "#FFFFFF",
    "prefer": "#0F7A64",
    "conditional": "#8A5A00",
    "avoid": "#B42318",
    "verify": "#5B3FC4",
    "on-avoid": "#FFFFFF",
}

STATUSES = ("prefer", "conditional", "avoid", "verify")

# Spec 2.3 spacing scale in px, emitted as --s2 .. --s48.
SPACING = (2, 4, 6, 8, 10, 12, 16, 20, 24, 32, 48)

FONT_SANS = "'IBM Plex Sans',system-ui,sans-serif"
FONT_MONO = "'IBM Plex Mono',ui-monospace,Menlo,monospace"

# Filled in by WP1.
BASE_CSS = ""
PRINT_CSS = ""


def alpha(hex_color, a):
    """Return an 8-digit #RRGGBBAA hex for a #RRGGBB colour at opacity a (0..1).

    Precomputed rather than color-mix() so older browsers and the screenshot
    renderer need no support for it. Output is upper-case.
    """
    h = hex_color.lstrip("#")
    if len(h) != 6:
        raise ValueError("expected #RRGGBB, got %r" % (hex_color,))
    int(h, 16)
    if not 0 <= a <= 1:
        raise ValueError("alpha must be within 0..1, got %r" % (a,))
    return "#" + h.upper() + "%02X" % int(round(a * 255))


def theme_css(tokens, selector=":root"):
    """Return CSS custom properties for one theme under `selector`.

    Includes the tokens given, the derived status tints (fill 14%, edge 50%,
    track 35%), --avoid-alert (10%), --overlay-shadow, and the theme-independent
    spacing, radius, motion and font tokens.
    """
    decls = ["--%s:%s" % (name, value) for name, value in tokens.items()]
    for status in STATUSES:
        base = tokens[status]
        decls.append("--%s-fill:%s" % (status, alpha(base, 0.14)))
        decls.append("--%s-edge:%s" % (status, alpha(base, 0.50)))
        decls.append("--%s-track:%s" % (status, alpha(base, 0.35)))
    decls.append("--avoid-alert:%s" % alpha(tokens["avoid"], 0.10))
    decls.append("--overlay-shadow:0 8px 24px rgba(0,0,0,.5),0 0 0 1px %s"
                 % tokens["control-border"])
    for px in SPACING:
        decls.append("--s%d:%dpx" % (px, px))
    decls += ["--r-sm:2px", "--r-md:3px", "--r-lg:4px", "--r-card:6px",
              "--t-fast:120ms", "--t-load:200ms",
              "--font-sans:" + FONT_SANS, "--font-mono:" + FONT_MONO]
    return selector + "{" + ";".join(decls) + "}\n"
