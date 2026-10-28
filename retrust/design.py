"""Design tokens and colour maths for the Control Room redesign.

The tokens, colour maths and the base and print stylesheets every surface shares.

Decisions confirmed by the user (Redesign-plan.md section 7):

D1  JavaScript is in scope: one same-origin external script
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

# Spec 5.5 plus the plan's proposals. prefer is #0C6F5C, not the spec's #0F7A64: that fails 4.5:1 on its own 14% fill (4.09).
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
    "prefer": "#0C6F5C",
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


# Plain string, never an f-string: braces stay literal and the text can be
# fingerprinted. Sizes are rem (1rem = 16px) so browser text zoom works; the
# 12px (.75rem) floor is D3 and is enforced by tests/design_lint.py.
BASE_CSS = """*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%;text-size-adjust:100%}
body{margin:0;background:var(--ground);color:var(--text);font-family:var(--font-sans);font-weight:400;font-size:.875rem;line-height:1.45}
h1,h2,h3,h4,p,ul,ol,dl,dd,figure,blockquote{margin:0}
ul,ol{padding:0;list-style:none}
table{border-collapse:collapse;border-spacing:0}
th{font-weight:inherit;text-align:left}
img,svg{max-width:100%}
button,input,select,textarea{font:inherit;color:inherit}
button{cursor:pointer}
b,strong{font-weight:600}
a{color:var(--action);text-decoration:underline;text-underline-offset:2px}
a:hover{color:var(--action-hover)}
code,kbd,samp,pre{font-family:var(--font-mono);font-size:.8125rem;line-height:1.4}
code{background:var(--bar);border-radius:var(--r-sm);padding:1px var(--s4)}
pre{background:var(--bar);border:1px solid var(--rule);border-radius:var(--r-lg);padding:var(--s12);overflow-x:auto}
pre code{background:none;padding:0}
.wrap{max-width:1360px;margin:0 auto;padding-left:var(--s24);padding-right:var(--s24)}
.t-score{font-family:var(--font-mono);font-weight:500;font-size:4.5rem;line-height:1;font-variant-numeric:tabular-nums}
.t-title{font-family:var(--font-sans);font-weight:600;font-size:1.625rem;line-height:1.25}
.t-section{font-family:var(--font-sans);font-weight:600;font-size:1.125rem;line-height:1.3}
.t-label{font-family:var(--font-sans);font-weight:400;font-size:.75rem;line-height:1.4;color:var(--muted)}
.t-panel{font-family:var(--font-mono);font-weight:500;font-size:.75rem;line-height:1.3;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.t-mono{font-family:var(--font-mono);font-weight:400;font-size:.8125rem;line-height:1.4}
.t-mono-sm{font-family:var(--font-mono);font-weight:400;font-size:.75rem;line-height:1.3}
.t-verdict{font-family:var(--font-mono);font-weight:600;font-size:.75rem;line-height:1;text-transform:uppercase;letter-spacing:.08em}
.num{font-family:var(--font-mono);font-variant-numeric:tabular-nums}
th.n,td.n{text-align:right;font-family:var(--font-mono);font-variant-numeric:tabular-nums;white-space:nowrap}
:focus-visible{outline:2px solid var(--action);outline-offset:2px}
table :focus-visible,.tw :focus-visible{outline-offset:-2px}
.sr-only{position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
.skip-link{position:absolute;left:var(--s8);top:-4rem;z-index:100;background:var(--action);color:var(--on-action);padding:var(--s8) var(--s16);border-radius:var(--r-lg);font-weight:600;text-decoration:none}
.skip-link:focus{top:var(--s8);color:var(--on-action)}
.tw{overflow-x:auto;max-width:100%}
.tw:focus-visible{outline-offset:-2px}
.skeleton{background:var(--raised);border-radius:var(--r-md);animation:rt-pulse 1.2s ease-in-out infinite}
@keyframes rt-pulse{0%,100%{opacity:.6}50%{opacity:1}}
@media (pointer:coarse){
a.btn,button,summary,select,[role=button],[role=tab],input[type=button],input[type=submit]{min-height:44px;min-width:44px}
input:not([type=checkbox]):not([type=radio]),select,textarea{min-height:44px;font-size:1rem}
}
@media (prefers-reduced-motion:reduce){
*,*::before,*::after{transition:none!important;animation:none!important;scroll-behavior:auto!important}
}
"""

# Print switches to the LIGHT tokens (spec 5.5) and drops interactive chrome.
PRINT_CSS = "@media print{" + theme_css(LIGHT, ":root") + """body{background:#fff;color:var(--text)}
header,nav,.skip-link,.search,[role=search],.actions,form,[popover],dialog,.popover,.toast{display:none!important}
.card{break-inside:avoid}
tr{break-inside:avoid}
thead{display:table-header-group}
.tw{overflow:visible}
a{color:var(--action)}
}
"""
