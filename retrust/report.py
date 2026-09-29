"""Render an assessment as a self-contained HTML report.

The report is the deliverable a buyer attaches to a purchase decision, so every
number shows the evidence behind it and every abstention is stated plainly. No
external assets, so it can be emailed or opened offline.

The look follows ISA-101, the control-room HMI standard the scoring rules
already cite: the field stays low-chroma grey and saturated colour is spent only
on a verdict, a gate or a meter fill, because a panel where everything is
coloured is a panel where nothing stands out. Identifiers are set in monospace
throughout -- they are part numbers, and should read like the plate they are
stamped on.
"""

import html
import re
from datetime import date

from . import score

# One palette, written once and emitted three times. The bare :root is the
# light default; the two dark selectors let the reader's OS preference and an
# explicit data-theme each win, the latter being what the screenshot tool
# stamps to shoot both themes deterministically.
LIGHT = ("--field:#e6e9eb;--panel:#f2f4f5;--sunk:#d8dcdf;--rule:#b5bcc2;"
         "--ink:#1a2026;--soft:#58626c;--faint:#868f99;"
         "--prefer:#1c7a4a;--cond:#a86e00;--avoid:#b02a20")
DARK = ("--field:#191e23;--panel:#222930;--sunk:#13171b;--rule:#38414a;"
        "--ink:#e2e6ea;--soft:#9aa4ae;--faint:#6f7983;"
        "--prefer:#45b07a;--cond:#d79a26;--avoid:#e06054")

# System faces only. A webfont would be a network fetch, and this file has to
# render from a mail attachment on a machine that cannot reach the internet.
FACES = ("--sans:ui-sans-serif,system-ui,sans-serif;"
         "--mono:ui-monospace,SFMono-Regular,Menlo,monospace")

# Sizing hangs off the root, not off body, so one number moves the whole scale.
THEME = (f":root{{font-size:17px;{FACES};{LIGHT}}}\n"
         f"@media(prefers-color-scheme:dark){{:root:not([data-theme=light]){{{DARK}}}}}\n"
         f":root[data-theme=dark]{{{DARK}}}\n")

CSS = THEME + """
*{box-sizing:border-box}
body{margin:0;background:var(--field);color:var(--ink);font:1rem/1.6 var(--sans)}
.wrap{max-width:58rem;margin:0 auto;padding:2.5rem 1.4rem 4rem}
h1{font-size:1.75rem;font-weight:700;letter-spacing:-.015em;
 margin:0 0 1.4rem;padding-bottom:.5rem;border-bottom:2px solid var(--rule)}
h2{font-size:1.2rem;font-weight:700;letter-spacing:-.01em;
 margin:0 0 .8rem;padding-bottom:.4rem;border-bottom:1px solid var(--rule)}
/* Engraved legends, as on the front of control gear. */
.meta,th,td.na,.sources h2{font-family:var(--mono);font-size:.78rem;font-weight:600;
 letter-spacing:.08em;text-transform:uppercase}
.meta{color:var(--faint)}
/* Identifiers: CVE and advisory ids, order numbers, version ranges. They do
   not wrap -- half a part number at the end of a line is not a part number. */
code,.id{font-family:var(--mono);font-size:.92em;font-variant-numeric:tabular-nums}
code{white-space:nowrap}
/* The state stripe. This is the panel indicator lamp, and it is how a reader
   skims a comparison of six candidates. --vc is set once per block, so the
   verdict word and every meter fill below it inherit the same state colour. */
.block{border-left:4px solid var(--vc);padding-left:1.3rem;margin:2.8rem 0 0}
.verdict{display:flex;align-items:baseline;gap:1rem;flex-wrap:wrap;
 border:1px solid var(--rule);background:var(--panel);padding:1rem 1.2rem;margin:0 0 1rem}
.verdict .v{font:700 1.55rem/1 var(--sans);color:var(--vc)}
.verdict .s{font:600 1.2rem/1 var(--mono);font-variant-numeric:tabular-nums}
.verdict .n{color:var(--soft);font-size:.95rem}
.gate{border:1px solid var(--rule);border-left:3px solid var(--avoid);
 background:var(--panel);padding:.8rem 1rem;margin:.6rem 0}
.gate b{color:var(--avoid)}
.gate .src{display:block;margin-top:.3rem;font-size:.82rem;color:var(--faint)}
.tw{overflow-x:auto;margin:1rem 0}
.tw:focus-visible{outline:2px solid var(--ink);outline-offset:3px}
.table-scroll-hint{display:none}
@media(max-width:700px){.tw table{min-width:760px}.table-scroll-hint{display:block;font-size:12px;color:var(--faint);padding:8px 12px;margin:0}}
table{border-collapse:collapse;width:100%;font-size:.93rem;background:var(--panel);
 border:1px solid var(--rule);font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:.55rem .75rem;border-bottom:1px solid var(--rule);vertical-align:top}
th{line-height:1.4;white-space:nowrap;color:var(--soft);background:var(--sunk)}
tbody tr:last-child td{border-bottom:none}
td.n{text-align:right;font-family:var(--mono);white-space:nowrap}
td.na{color:var(--faint)}
td.rng{max-width:15rem;overflow-wrap:anywhere;color:var(--soft)}
tr.cand td:first-child{border-left:4px solid var(--vc)}
td.v{color:var(--vc);font-weight:700}
/* Meters read as one state per block rather than as a decorative accent. */
.bar{display:block;position:relative;height:9px;min-width:5rem;overflow:hidden;
 background:var(--sunk);border:1px solid var(--rule)}
.bar i{position:absolute;inset:0 auto 0 0;background:var(--vc,var(--faint))}
/* Evidence quality is reported but not scored, so its meter stays inert grey. */
tr.unscored{background:var(--sunk)}
tr.unscored .bar{background:var(--panel)}
tr.unscored .bar i{background:var(--faint)}
.ev{margin:.2rem 0 0;padding-left:1.1rem;color:var(--soft);font-size:.9rem}
/* Secondary panels separate on a hairline and a recessed ground, the way a
   mimic diagram does. It also survives the thing that happens to this file:
   printed in grey scale and stapled to a purchase order. */
.note{border:1px solid var(--rule);border-left:3px solid var(--cond);background:var(--panel);
 padding:.75rem 1rem;margin:.6rem 0;font-size:.95rem;color:var(--soft)}
.stability{border:1px solid var(--rule);border-left:3px solid var(--rule);background:var(--panel);
 padding:.7rem 1rem;margin:0 0 1rem;font-size:.92rem;color:var(--soft)}
/* Only the fragile case is coloured. A robust result is the normal condition,
   and a green stripe on an AVOID block would read as a second, contradicting
   verdict rather than as the weight note it is. */
.stability.fragile{border-left-color:var(--cond)}
.tnote{font-size:.86rem;color:var(--faint);margin:0 0 1rem}
.sources{margin-top:3rem;font-size:.9rem;color:var(--soft)}
.sources h2{font-size:.82rem;color:var(--faint)}
.sources dl{display:grid;grid-template-columns:auto 1fr;gap:.3rem 1.2rem;margin:.8rem 0}
.sources dt{font-family:var(--mono);font-size:.82rem;color:var(--faint);
 font-variant-numeric:tabular-nums}
.sources dd{margin:0}
footer{margin-top:3rem;padding-top:1rem;border-top:1px solid var(--rule);
 font-size:.84rem;color:var(--faint)}
"""

# Identifiers turn up in prose too -- a KEV gate names the CVEs it fired on --
# and they should read as part numbers there as well. Substituted after
# escaping, and matching bare id shapes only, so it cannot introduce markup.
IDENTIFIER = re.compile(r"\b((?:CVE|ICSA|ICSMA|SSA|VDE)-[0-9][0-9A-Z-]*[0-9A-Z])")

# Derived from the one pillar registry, so a new pillar shows a weight here
# without anyone remembering to update a second list.
PILLAR_KEYS = {spec.name: spec.key for spec in score.PILLARS}


def _weight_share(pillar_name, weights):
    """The share this pillar carries, or None when it is not scored at all."""
    key = PILLAR_KEYS.get(pillar_name)
    if key is None or not weights:
        return None
    total = sum(weights.values()) or 1.0
    return weights.get(key, 0.0) / total

def _footer_sources(provenance, weights, config_source):
    """Provenance and weights, so a reader can reproduce or dispute the result."""
    if not (provenance or weights):
        return ""
    parts = ['<section class="sources"><h2>How this was produced</h2>']
    if provenance:
        parts.append("<dl>")
        for row in provenance:
            parts.append(f'<dt>{_esc(row["captured"])}</dt>'
                         f'<dd><b>{_esc(row["source"])}</b> &mdash; {_esc(row["detail"])}</dd>')
        parts.append("</dl>")
    if weights:
        total = sum(weights.values()) or 1
        shown = ", ".join(f"{k} {v / total:.0%}" for k, v in weights.items())
        parts.append(f'<p>Weights ({_esc(config_source)}): {_esc(shown)}. '
                     'Change them in the config file and re-run; the sensitivity '
                     'figures above show how much that would matter.</p>')
    parts.append("</section>")
    return "".join(parts)


VERDICT_COLOR = {"PREFER": "var(--prefer)", "CONDITIONAL": "var(--cond)",
                 "AVOID": "var(--avoid)", "NOT ASSESSED": "var(--faint)"}
# A verdict this table does not know is an unknown state, and an unknown state
# is inert -- not --soft, which is secondary text everywhere else in the sheet
# and would light a stripe in a colour that means nothing.
INERT = VERDICT_COLOR["NOT ASSESSED"]


def _esc(text):
    return html.escape(str(text))


def _ids(escaped):
    """Set the identifiers inside an already-escaped run of prose in monospace."""
    return IDENTIFIER.sub(r"<code>\1</code>", escaped)


def _assessment_block(assessment, resolution=None, findings=(), stability=None,
                      weights=None):
    colour = VERDICT_COLOR.get(assessment.verdict, INERT)
    # Declared once on the block. The stripe, the verdict word and every meter
    # fill below all read --vc, so a product cannot end up half one state and
    # half another the way six separate inline colours eventually would.
    parts = [f'<section class="block" style="--vc:{colour}">'
             f'<h2>{_esc(assessment.product)}</h2>']

    if assessment.score is None:
        # Two very different states share "no score": a product we could not
        # assess, and one a gate disqualified outright. Saying "not enough data"
        # for the second is wrong -- the tool decided, and the reason is the
        # gate shown below.
        reason = ("disqualified below" if assessment.gates
                  else "not enough data to assess")
        summary = f'<span class="s">no score</span><span class="n">{reason}</span>'
    else:
        detail = f'{assessment.findings_count} CVE(s) in scope'
        if assessment.undecided_count:
            detail += f' &middot; {assessment.undecided_count} need review'
        detail += f' &middot; evidence confidence {assessment.confidence:.0%}'
        summary = (f'<span class="s">{assessment.score}/100</span>'
                   f'<span class="n">{detail}</span>')

    parts.append(f'<div class="verdict"><span class="v">'
                 f'{_esc(assessment.verdict)}</span>{summary}</div>')

    if stability is not None:
        klass = "robust" if (stability.gated or stability.robust) else "fragile"
        parts.append(
            f'<p class="stability {klass}"><b>Weight robustness.</b> '
            f'{_esc(stability.summary())}.'
            + ('' if stability.gated else
               f' Score ranged {stability.score_min}&ndash;{stability.score_max} '
               f'across {stability.samples} random weightings.')
            + '</p>')

    if resolution is not None:
        if resolution.resolved:
            parts.append(
                f'<p class="meta">matched by {_esc(resolution.method)} '
                f'&middot; confidence {resolution.confidence:.2f} '
                f'&middot; {len(resolution.matches)} advisory product(s)</p>')
        elif not assessment.gates:
            parts.append(f'<div class="note"><b>Not assessed.</b> '
                         f'{_esc(resolution.reason)}</div>')

    for gate in assessment.gates:
        parts.append(
            f'<div class="gate"><b>Hard gate &mdash; {_esc(gate["gate"])}</b><br>'
            f'{_ids(_esc(gate["detail"]))}'
            f'<span class="src">Source: {_esc(gate["source"])}</span></div>')

    if assessment.pillars:
        parts.append(_pillar_table(assessment, weights))

    for note in assessment.notes:
        parts.append(f'<div class="note">{_ids(_esc(note))}</div>')

    top = sorted(findings, key=lambda f: (-(f.epss or 0), -(f.cvss or 0)))[:10]
    if top:
        parts.append(_cve_table(top))

    parts.append('</section>')
    return "".join(parts)


def _pillar_table(assessment, weights):
    parts = ['<div class="tw" tabindex="0" role="region" aria-label="Pillar evidence, scroll horizontally for more columns">'
             '<p class="table-scroll-hint">Scroll sideways to see all evidence →</p>'
             '<table><thead><tr><th>Pillar</th><th>Score</th>'
             '<th style="width:18%">&nbsp;</th><th>Weight</th><th>Coverage</th>'
             '<th>Evidence</th></tr></thead><tbody>']
    for pillar in assessment.pillars:
        evidence = "".join(f"<li>{_esc(e)}</li>" for e in pillar.evidence)
        share = _weight_share(pillar.name, weights)
        weight = None if share is None else f"{share:.2f}"
        # Evidence quality is reported but not scored, and must look different
        # from the pillars that move the number.
        unscored = weight is None
        parts.append(
            f'<tr{" class=unscored" if unscored else ""}>'
            f'<td><b>{_esc(pillar.name)}</b></td>'
            f'<td class="n">{pillar.score:.0f}</td>'
            f'<td><span class="bar"><i style="width:{max(0, min(100, pillar.score)):.0f}%"></i></span></td>'
            + (f'<td class="n">{weight}</td>' if weight
               else '<td class="n na">not scored</td>')
            + f'<td class="n">{pillar.coverage * 100:.0f}%</td>'
            f'<td><ul class="ev">{evidence}</ul></td></tr>')
    parts.append('</tbody></table></div>')
    return "".join(parts)


def _cve_table(findings):
    """The most significant CVEs, worst exploitation probability first.

    The affected range is shown because it is what a reader has to check by
    hand on the rows marked "needs review": saying a range could not be parsed
    without saying which range leaves them nowhere to start.
    """
    parts = ['<div class="tw" tabindex="0" role="region" aria-label="CVE evidence, scroll horizontally for more columns">'
             '<p class="table-scroll-hint">Scroll sideways to see all evidence →</p>'
             '<table><thead><tr><th>Most significant CVEs</th>'
             '<th>CVSS</th><th>EPSS</th><th>KEV</th><th>Advisory</th>'
             '<th>Affected range</th></tr></thead><tbody>']
    for f in findings:
        parts.append(
            f'<tr><td><code>{_esc(f.cve)}</code>'
            + ('' if f.decided else ' <span class="meta">needs review</span>')
            + f'</td><td class="n">{"" if f.cvss is None else f"{f.cvss:.1f}"}</td>'
            f'<td class="n">{"" if f.epss is None else f"{f.epss:.3f}"}</td>'
            f'<td class="n">{"yes" if f.in_kev else ""}</td>'
            f'<td><code>{_esc(f.advisory_id)}</code></td>'
            f'<td class="id rng">{_esc(f.version_range)}</td></tr>')
    parts.append('</tbody></table></div>')
    return "".join(parts)


def _summary_table(blocks, stabilities):
    """Side-by-side ranking, so the decision is visible without scrolling."""
    rows = []
    for assessment, resolution, _ in blocks:
        colour = VERDICT_COLOR.get(assessment.verdict, INERT)
        st = stabilities.get(assessment.product)
        robust = "&mdash;" if st is None else (
            "gated" if st.gated else f"{st.agreement:.0%}")
        note = (assessment.gates[0]["gate"] if assessment.gates
                else "" if resolution.resolved else resolution.reason)
        rows.append(
            f'<tr class="cand" style="--vc:{colour}">'
            f'<td><b>{_esc(assessment.product)}</b></td>'
            f'<td class="v">{_esc(assessment.verdict)}</td>'
            f'<td class="n">{"&mdash;" if assessment.score is None else assessment.score}</td>'
            f'<td class="n">{"&mdash;" if assessment.score is None else assessment.findings_count}</td>'
            f'<td class="n">{robust}</td>'
            f'<td>{_esc(note)}</td></tr>')
    return ('<div class="tw" tabindex="0" role="region" aria-label="Candidate comparison, scroll horizontally for more columns">'
            '<p class="table-scroll-hint">Scroll sideways to see all candidates’ evidence →</p>'
            '<table><thead><tr><th>Candidate</th><th>Verdict</th>'
            '<th>Score</th><th>CVEs</th><th>Robust</th><th>Deciding factor</th>'
            '</tr></thead><tbody>' + "".join(rows) + '</tbody></table></div>'
            '<p class="tnote">Robust is the share of random weightings that give the '
            'most common verdict. Below 90%, that verdict is sensitive to the '
            'pillar weights. This measures each verdict, not the stability of '
            'the ranking. A dash means it was not sampled.</p>')


def body(blocks, stabilities=None, weights=None):
    """The summary table and assessment blocks, without the page around them.

    Split out so the local web server can put the same markup inside its own
    page. One renderer for both surfaces means they cannot drift into showing
    the same assessment differently.
    """
    stabilities = stabilities or {}
    summary = _summary_table(blocks, stabilities) if len(blocks) > 1 else ""
    return summary + "".join(
        _assessment_block(a, r, f, stabilities.get(a.product), weights)
        for a, r, f in blocks)


def render(blocks, title="ReTrust assessment", snapshot="", stabilities=None,
           provenance=(), weights=None, config_source=""):
    """Render one or more (assessment, resolution, findings) triples to HTML."""
    inner = body(blocks, stabilities, weights)
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>{_esc(title)}</title><style>{CSS}</style></head><body><div class=\"wrap\">"
        f"<p class=\"meta\">ReTrust &middot; generated {date.today().isoformat()}"
        + (f" &middot; data snapshot {_esc(snapshot)}" if snapshot else "")
        + f"</p><h1>{_esc(title)}</h1>{inner}"
        + _footer_sources(provenance, weights, config_source)
        + "<footer>Scores are decision support, not a certification. Every figure above "
        "comes from public CISA, FIRST and vendor sources; weights are configurable and "
        "shown so you can disagree with them. Ranges this tool could not parse are "
        "reported as needing review, never assumed safe.</footer>"
        "</div></body></html>"
    )
