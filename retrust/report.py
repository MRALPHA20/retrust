"""Render an assessment as a self-contained HTML report.

The report is the deliverable a buyer attaches to a purchase decision, so every
number shows the evidence behind it and every abstention is stated plainly. No
external assets, so it can be emailed or opened offline.
"""

import html
from datetime import date

from . import score

CSS = """
:root{--bg:#f4f6f8;--card:#fff;--sunk:#e9edf1;--rule:#ccd4dc;--ink:#16202a;
--soft:#47586a;--faint:#5c6c7d;--strong:#9aa8b5;--prefer:#1c6b4a;--cond:#8a5c00;--avoid:#9c2a24;}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#171c21;--card:#1e252c;
--sunk:#141a1f;--rule:#323c46;--ink:#e4eaf0;--soft:#a9b8c6;--faint:#8b9aa8;
--strong:#55636f;--prefer:#5fc493;--cond:#e0ab4e;--avoid:#f08d84;}}
:root[data-theme=dark]{--bg:#171c21;--card:#1e252c;--sunk:#141a1f;--rule:#323c46;
--ink:#e4eaf0;--soft:#a9b8c6;--faint:#8b9aa8;--strong:#55636f;--prefer:#5fc493;--cond:#e0ab4e;--avoid:#f08d84;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 ui-sans-serif,system-ui,sans-serif}
.wrap{max-width:58rem;margin:0 auto;padding:2.5rem 1.4rem 4rem}
h1{font-size:1.9rem;margin:0 0 .3rem;letter-spacing:-.02em}
h2{font-size:1.15rem;margin:2.2rem 0 .6rem;padding-bottom:.4rem;border-bottom:1px solid var(--rule)}
.meta{font:500 .72rem/1.5 ui-monospace,monospace;letter-spacing:.1em;text-transform:uppercase;color:var(--faint)}
.verdict{display:flex;align-items:baseline;gap:1rem;flex-wrap:wrap;
 border:1px solid var(--rule);border-left:5px solid var(--vc);background:var(--card);
 padding:1rem 1.2rem;margin:1.4rem 0}
.verdict .v{font:700 1.5rem/1 ui-sans-serif,system-ui,sans-serif;color:var(--vc)}
.verdict .s{font:600 1.1rem/1 ui-monospace,monospace;font-variant-numeric:tabular-nums}
.verdict .n{color:var(--soft);font-size:.9rem}
.gate{border:1px solid var(--avoid);background:var(--card);padding:.8rem 1rem;margin:.6rem 0}
.gate b{color:var(--avoid)}
.gate .src{display:block;margin-top:.25rem;font-size:.78rem;color:var(--faint)}
table{border-collapse:collapse;width:100%;font-size:.88rem;background:var(--card);border:1px solid var(--rule)}
th,td{text-align:left;padding:.5rem .7rem;border-bottom:1px solid var(--rule);vertical-align:top}
th{font:600 .68rem/1.4 ui-monospace,monospace;letter-spacing:.08em;text-transform:uppercase;
 color:var(--soft);background:var(--sunk)}
tbody tr:last-child td{border-bottom:none}
td.n{text-align:right;font-family:ui-monospace,monospace;font-variant-numeric:tabular-nums;white-space:nowrap}
.bar{display:block;position:relative;height:6px;background:var(--sunk);border-radius:3px;overflow:hidden;min-width:70px}
.bar i{position:absolute;inset:0 auto 0 0;background:var(--soft)}
.ev{margin:.3rem 0 0;padding-left:1.1rem;color:var(--soft);font-size:.83rem}
.note{border:1px solid var(--rule);border-left:3px solid var(--cond);background:var(--card);
 padding:.75rem 1rem;margin:.6rem 0;font-size:.9rem;color:var(--soft)}
.tw{overflow-x:auto}
footer{margin-top:3rem;padding-top:1rem;border-top:1px solid var(--rule);font-size:.8rem;color:var(--faint)}
code{font-family:ui-monospace,monospace;font-size:.86em}
.stability{font-size:.86rem;padding:.55rem .8rem;margin:.5rem 0 1rem;
 border-left:3px solid var(--strong);background:var(--card);color:var(--soft)}
.stability.fragile{border-left-color:var(--cond)}
.stability.robust{border-left-color:var(--prefer)}
.tnote{font-size:.82rem;color:var(--faint);margin:.5rem 0 1.5rem}
.sources{margin-top:2.5rem;font-size:.84rem;color:var(--soft)}
.sources h2{font-size:1rem}
.sources dl{display:grid;grid-template-columns:auto 1fr;gap:.25rem 1rem;margin:.6rem 0}
.sources dt{font-family:ui-monospace,monospace;font-size:.78rem;color:var(--faint)}
.sources dd{margin:0}
tr.unscored{background:var(--sunk)}
tr.unscored .bar i{background:var(--faint);opacity:.55}
td.na{font-size:.72rem;letter-spacing:.06em;text-transform:uppercase;color:var(--faint)}
"""

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


def _esc(text):
    return html.escape(str(text))


def _assessment_block(assessment, resolution=None, findings=(), stability=None,
                      weights=None):
    colour = VERDICT_COLOR.get(assessment.verdict, "var(--soft)")
    parts = [f'<h2>{_esc(assessment.product)}</h2>']

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

    parts.append(
        f'<div class="verdict" style="--vc:{colour}">'
        f'<span class="v">{_esc(assessment.verdict)}</span>{summary}</div>'
    )

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
            f'{_esc(gate["detail"])}<span class="src">Source: {_esc(gate["source"])}</span></div>')

    if assessment.pillars:
        parts.append(_pillar_table(assessment, weights))

    for note in assessment.notes:
        parts.append(f'<div class="note">{_esc(note)}</div>')

    top = sorted(findings, key=lambda f: (-(f.epss or 0), -(f.cvss or 0)))[:10]
    if top:
        parts.append(_cve_table(top))

    return "".join(parts)


def _pillar_table(assessment, weights):
    parts = ['<div class="tw"><table><thead><tr><th>Pillar</th><th>Score</th>'
             '<th style="width:30%">&nbsp;</th><th>Weight</th><th>Coverage</th>'
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
    """The most significant CVEs, worst exploitation probability first."""
    parts = ['<div class="tw"><table><thead><tr><th>Most significant CVEs</th>'
             '<th>CVSS</th><th>EPSS</th><th>KEV</th><th>Advisory</th>'
             '</tr></thead><tbody>']
    for f in findings:
        parts.append(
            f'<tr><td><code>{_esc(f.cve)}</code>'
            + ('' if f.decided else ' <span class="meta">needs review</span>')
            + f'</td><td class="n">{"" if f.cvss is None else f"{f.cvss:.1f}"}</td>'
            f'<td class="n">{"" if f.epss is None else f"{f.epss:.3f}"}</td>'
            f'<td class="n">{"yes" if f.in_kev else ""}</td>'
            f'<td><code>{_esc(f.advisory_id)}</code></td></tr>')
    parts.append('</tbody></table></div>')
    return "".join(parts)


def _summary_table(blocks, stabilities):
    """Side-by-side ranking, so the decision is visible without scrolling."""
    rows = []
    for assessment, resolution, _ in blocks:
        colour = VERDICT_COLOR.get(assessment.verdict, "var(--soft)")
        st = stabilities.get(assessment.product)
        robust = "&mdash;" if st is None else (
            "gated" if st.gated else f"{st.agreement:.0%}")
        note = (assessment.gates[0]["gate"] if assessment.gates
                else "" if resolution.resolved else resolution.reason)
        rows.append(
            f'<tr><td><b>{_esc(assessment.product)}</b></td>'
            f'<td style="color:{colour};font-weight:600">{_esc(assessment.verdict)}</td>'
            f'<td class="n">{"&mdash;" if assessment.score is None else assessment.score}</td>'
            f'<td class="n">{"&mdash;" if assessment.score is None else assessment.findings_count}</td>'
            f'<td class="n">{robust}</td>'
            f'<td>{_esc(note)}</td></tr>')
    return ('<div class="tw"><table><thead><tr><th>Candidate</th><th>Verdict</th>'
            '<th>Score</th><th>CVEs</th><th>Robust</th><th>Deciding factor</th>'
            '</tr></thead><tbody>' + "".join(rows) + '</tbody></table></div>'
            '<p class="tnote">Robust is the share of random weightings that give the '
            'same verdict. Below 90%, the ranking depends on how you weigh the '
            'pillars rather than on the evidence.</p>')


def render(blocks, title="ReTrust assessment", snapshot="", stabilities=None,
           provenance=(), weights=None, config_source=""):
    """Render one or more (assessment, resolution, findings) triples to HTML."""
    stabilities = stabilities or {}
    summary = _summary_table(blocks, stabilities) if len(blocks) > 1 else ""
    body = "".join(
        _assessment_block(a, r, f, stabilities.get(a.product), weights)
        for a, r, f in blocks)
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>{_esc(title)}</title><style>{CSS}</style></head><body><div class=\"wrap\">"
        f"<p class=\"meta\">ReTrust &middot; generated {date.today().isoformat()}"
        + (f" &middot; data snapshot {_esc(snapshot)}" if snapshot else "")
        + f"</p><h1>{_esc(title)}</h1>{summary}{body}"
        + _footer_sources(provenance, weights, config_source)
        + "<footer>Scores are decision support, not a certification. Every figure above "
        "comes from public CISA, FIRST and vendor sources; weights are configurable and "
        "shown so you can disagree with them. Ranges this tool could not parse are "
        "reported as needing review, never assumed safe.</footer>"
        "</div></body></html>"
    )
