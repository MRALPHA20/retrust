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
.vector code{white-space:normal;overflow-wrap:anywhere}
.evidence-details{border:0;padding:0;margin:0;background:transparent}
.evidence-details summary{font-size:.86rem;color:var(--soft);cursor:pointer}
.evidence-details[open]>summary{margin-bottom:.5rem}
/* The state stripe. This is the panel indicator lamp, and it is how a reader
   skims a comparison of six candidates. --vc is set once per block, so the
   verdict word and every meter fill below it inherit the same state colour. */
.block{border-left:4px solid var(--vc);padding-left:1.3rem;margin:2.8rem 0 0}
.verdict{display:flex;align-items:baseline;gap:1rem;flex-wrap:wrap;
 border:1px solid var(--rule);background:var(--panel);padding:1rem 1.2rem;margin:0 0 1rem}
.verdict .v{font:700 1.55rem/1 var(--sans);color:var(--vc)}
.verdict .s{font:600 1.2rem/1 var(--mono);font-variant-numeric:tabular-nums}
.verdict .n{color:var(--soft);font-size:.95rem}
.verdict .review-required{flex-basis:100%;font:600 .95rem/1.5 var(--sans);color:var(--cond)}
.score-scope{max-width:75ch;margin:.8rem 0 1.2rem}
.coverage{margin:1rem 0}.coverage summary{cursor:pointer;font-weight:600}
.coverage p{max-width:75ch}
.gate{border:1px solid var(--rule);border-left:3px solid var(--avoid);
 background:var(--panel);padding:.8rem 1rem;margin:.6rem 0}
.gate b{color:var(--avoid)}
.gate .src{display:block;margin-top:.3rem;font-size:.82rem;color:var(--faint)}
.caution{border:1px solid var(--rule);border-left:3px solid var(--cond);
 background:var(--panel);padding:.8rem 1rem;margin:.6rem 0}
.caution b{color:var(--cond)}
.caution .src{display:block;margin-top:.3rem;font-size:.82rem;color:var(--faint)}
.tw{overflow-x:auto;margin:1rem 0}
.tw:focus-visible{outline:2px solid var(--ink);outline-offset:3px}
.table-scroll-hint{display:none}
@media(max-width:700px){.tw table{min-width:760px}.table-scroll-hint{display:block;font-size:12px;color:var(--faint);padding:8px 12px;margin:0}}
table{border-collapse:collapse;width:100%;font-size:.93rem;background:var(--panel);
 border:1px solid var(--rule);font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:.55rem .75rem;border-bottom:1px solid var(--rule);vertical-align:top}
th{line-height:1.4;white-space:nowrap;color:var(--soft);background:var(--sunk)}
tbody tr:last-child td{border-bottom:none}
th.n,td.n{text-align:right;font-family:var(--mono);white-space:nowrap}
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

# Derived from the one network registry, so a new choice cannot appear here
# under a name the model does not score.
NETWORK_LABELS = {key: entry[0] for key, entry in score.NETWORK_EXPOSURES.items()}

# exposure.py writes the "Network context:" evidence line and cannot ask score
# for the label -- score imports exposure, not the other way round -- so it has
# only the stored token. "Network context: it_ot" is a database value printed
# at a buyer: the label is one import away here, so it is substituted here.
NETWORK_TOKEN = re.compile(r"(?<=Network context: )[a-z_]+")

# Derived from the one pillar registry, so a new pillar shows a weight here
# without anyone remembering to update a second list.
PILLAR_KEYS = {spec.name: spec.key for spec in score.PILLARS}


def _weight_share(pillar_name, weights, active_pillars=None):
    """The share this pillar carries, or None when it is not scored at all."""
    key = PILLAR_KEYS.get(pillar_name)
    if key is None or not weights:
        return None
    total = (sum(weights.values()) if active_pillars is None else
             sum(weights.get(PILLAR_KEYS[p.name], 0)
                 for p in active_pillars if p.name in PILLAR_KEYS and p.scored))
    total = total or 1.0
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
        shown = ", ".join(f"{k} {v / total:.1%}" for k, v in weights.items())
        parts.append(f'<p>Weights ({_esc(config_source)}): {_esc(shown)}. '
                     'Change them in the config file and re-run; the sensitivity '
                     'figures above show how much that would matter. Parts without '
                     'measurable evidence are excluded and the remaining weights are '
                     'adjusted.</p>')
    parts.append("</section>")
    return "".join(parts)


VERDICT_COLOR = {"VERIFY": "var(--cond)", "PREFER": "var(--prefer)", "CONDITIONAL": "var(--cond)",
                 "AVOID": "var(--avoid)", "NOT ASSESSED": "var(--faint)"}
VERDICT_HELP = {
    "VERIFY": "More checks are needed before deciding. Ask your technical team to confirm the network access, operational consequences and firmware status listed below. The range shows how the score could change.",
    "PREFER": "A candidate for your shortlist. Complete the checks below before approving the purchase.",
    "CONDITIONAL": "Consider this product only after your technical team reviews the listed risks and missing evidence.",
    "AVOID": "This assessment advises against the purchase because of a purchase blocker or a low score. Review the reasons below.",
    "NOT ASSESSED": "There is not enough usable information for a recommendation. Check the exact part number and ask the supplier for the firmware details.",
}
PILLAR_LABELS = {
    "Exposure": "Exposure safety", "Patch availability": "Available fixes",
    "Vendor practice": "Vendor security practices", "Certification": "Certification evidence",
    "Exploitation": "Attack activity", "Severity": "Issue severity",
    "Network exposure": "Network access", "Evidence quality": "Evidence completeness",
}
# Keyed by the caution name score.py sets, which is the coupling: a lookup miss
# falls back to the model's own wording silently, so the day somebody writes
# "CVEs" on one side of this pair and "CVE(s)" on the other, the page loses its
# plain-language title and nothing fails. _caution_key accepts either spelling.
CAUTION_HELP = {
    "KEV-listed CVEs in third-party component bundles": (
        "Known exploited weaknesses in included software",
        "CISA has confirmed attacks using weaknesses in software included with this product. "
        "Ask the supplier whether those weaknesses can be reached on this equipment and which fixes apply."),
    "Ransomware-linked CVEs in third-party component bundles": (
        "Ransomware-related weaknesses in included software",
        "Public records link weaknesses in included software to ransomware attacks. "
        "Ask the supplier to confirm whether those attack paths exist on this equipment."),
    "Critical unfixable CVEs in third-party component bundles": (
        "Serious weaknesses in included software may have no fix",
        "Included software has serious vulnerability records without an available remedy. "
        "Ask the supplier whether this product is affected and what protection is possible."),
}
# A verdict this table does not know is an unknown state, and an unknown state
# is inert -- not --soft, which is secondary text everywhere else in the sheet
# and would light a stripe in a colour that means nothing.
INERT = VERDICT_COLOR["NOT ASSESSED"]


def _esc(text):
    return html.escape(str(text))


def _probability(value):
    if value is None:
        return 'Not available'
    if 0 < value < .001:
        return 'Under 0.1%'
    return 'Over 99.9%' if .999 < value < 1 else f'{value:.1%}'


def _ids(escaped):
    """Set the identifiers inside an already-escaped run of prose in monospace."""
    return IDENTIFIER.sub(r"<code>\1</code>", escaped)


def _caution_key(name):
    """A caution name in CAUTION_HELP's spelling, whichever score.py used."""
    return name.replace("CVE(s)", "CVEs")


def _labels(escaped):
    """Read a stored enum back as the label the form offered for it."""
    return NETWORK_TOKEN.sub(
        lambda found: _esc(NETWORK_LABELS.get(found.group(), found.group())), escaped)


def plural(count, singular, many=None):
    """A counted noun that agrees with its count: "1 finding", "2 findings".

    Plain text, no markup, so the terminal and both web surfaces can share it.
    Counting is the one thing this tool does on every screen, and "1 finding(s)"
    was on all of them -- a hedge in the one place a reader is being told a
    number. The regular plural is assumed; `many` carries the irregulars
    ("advisory", "advisories").
    """
    return f"{count:,} {singular if abs(count) == 1 else many or singular + 's'}"


def verb(count, singular, many):
    """The word that agrees with a plural() count: "1 finding is", "2 are".

    Its own helper because the noun alone is not enough: "1 finding(s) are
    memory safety" was wrong twice on every score page, and a count that reads
    correctly in front of a verb that does not is no better than before.
    """
    return singular if abs(count) == 1 else many


# One dash for every score range on every surface. alternatives.py printed an
# ASCII hyphen while the report, the terminal and the comparison cards printed
# an en dash, so "6.3-99.2" and "6.3–99.2" were the same range rendered two ways
# inside a single session -- and the next surface to be added would have had to
# guess which was house style.
RANGE_DASH = '–'


def _reading(subject, key):
    """score_label takes an Assessment, an alternatives.Option, or a batch dict."""
    return (subject.get(key) if isinstance(subject, dict)
            else getattr(subject, key, None))


def score_label(subject, unit='', note=' (provisional)', missing='&mdash;', places=None):
    """Consistent score display across report, terminal and comparison views.

    Every caller formats the same three fields, so the formatting lives here and
    only what legitimately differs is a parameter:

      `unit`     follows the number on surfaces that name it ("/100").
      `note`     follows a provisional range only; the terminal says
                 "(provisional range)", the report "(provisional)", and the
                 alternatives table has room for neither.
      `missing`  stands in for an unscored product: an HTML entity in a page,
                 a plain word in a terminal.
      `places`   fixed decimals, for the column-aligned alternatives table.
    """
    def shown(value):
        return str(value) if places is None else f'{value:.{places}f}'

    if _reading(subject, 'score') is None:
        return missing
    if _reading(subject, 'provisional'):
        return (f"{shown(_reading(subject, 'score_min'))}{RANGE_DASH}"
                f"{shown(_reading(subject, 'score_max'))}{unit}{note}")
    return f"{shown(_reading(subject, 'score'))}{unit}"


def _scroll_hint(text, show=True):
    """The sideways-scroll affordance, on the surfaces somebody can swipe.

    A downloaded report is a document: emailed, printed, stapled to a purchase
    order. "Scroll sideways to see all evidence" is an instruction a reader
    holding paper cannot follow, so render() asks for the same tables without
    it rather than shipping screen chrome inside the deliverable.
    """
    return f'<p class="table-scroll-hint">{text}</p>' if show else ''


def _assessment_block(assessment, resolution=None, findings=(), stability=None,
                      weights=None, tools='', hint=True):
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
        noun = 'vulnerability' if assessment.findings_count == 1 else 'vulnerabilities'
        detail = f'{assessment.findings_count} known {noun} included'
        if assessment.undecided_count:
            detail += f' &middot; {assessment.undecided_count} need review'
        # The range only; "Provisional range" is said in the detail line below,
        # so repeating the note beside the number would say it twice.
        shown_score = score_label(assessment, note='')
        if assessment.provisional:
            detail = "Provisional range · " + detail
        summary = (f'<span class="s">{shown_score}/100</span>'
                   f'<span class="n">{detail}</span>')

    supplier_review = bool(assessment.cautions or assessment.third_party_count)
    if supplier_review:
        summary += '<span class="review-required">Supplier verification required before purchase</span>'
    parts.append(f'<div class="verdict"><span class="v">'
                 f'{_esc(assessment.verdict)}</span>{summary}</div>')
    parts.append(f'<p class="result-help">{_esc(VERDICT_HELP.get(assessment.verdict, "Review the evidence below."))}</p>')
    if assessment.score is not None:
        parts.append('<p class="tnote">Higher scores are more favourable under the chosen settings. '
                     'The score is not a percentage chance that the equipment is secure.</p>')

    if assessment.first_party_count and assessment.third_party_count:
        noun = 'vulnerability' if assessment.first_party_count == 1 else 'vulnerabilities'
        parts.append(f'<p class="score-scope"><b>What this score covers:</b> '
                     f'{assessment.first_party_count} {noun} from device-vendor advisories. '
                     f'<b>{assessment.third_party_count} additional vulnerabilities in bundled software '
                     'need separate supplier review.</b> Their reachability on this equipment '
                     'has not been confirmed.</p>')

    if assessment.verification:
        parts.append('<section class="verification"><h3>What to check next</h3>'
                     '<p>A network or operations owner can help with these checks. '
                     'Unknown answers stay unresolved; ReTrust does not test your network.</p><ul>'
                     + ''.join(f'<li>{_esc(item)}</li>' for item in assessment.verification)
                     + '</ul></section>')

    # Keep the verdict and its limits ahead of editing and download controls.
    parts.append(tools)

    if assessment.vector:
        parts.append('<details class="vector"><summary>Technical assessment settings</summary>'
                     f'<p><code>{_esc(assessment.vector)}</code></p>'
                     '<p class="tnote">Includes the scoring version, supplied firmware and '
                     'operator choices. The data token fingerprints recorded source '
                     'provenance metadata; it does not checksum the full database.</p>'
                     '</details>')

    if assessment.paths:
        rows = []
        for path in assessment.paths:
            for entry in path['inputs']:
                cells = ''.join(
                    '<td>' + _esc(f"{bounds[0]:.3g}" if bounds[0] == bounds[1]
                                  else f"{bounds[0]:.3g}–{bounds[1]:.3g}") + '</td>'
                    for bounds in entry['factors'].values())
                rows.append('<tr><td>' + _esc(entry['cve']) + '</td>' + cells
                            + '<td>' + _esc(entry['advisory']) + '</td></tr>')
        parts.append('<details><summary>How each vulnerability contributes</summary>'
                     '<p>T = threat evidence; A = attack access; H = operational harm; '
                     'U = affected and unfixed. A range means evidence is missing. '
                     'Repeated advisories for the same CVE count once. Separate CVEs '
                     'are review units; independent attack paths have not been established.</p>'
                     # .table-scroll had no rule in either stylesheet, so this
                     # one table computed overflow-x:visible and clipped its U
                     # and Advisory columns off the right of a phone with no way
                     # to reach them. .tw is the class that scrolls.
                     '<div class="tw" tabindex="0" role="region" aria-label="Factor contributions per vulnerability, scroll horizontally for more columns">'
                     + _scroll_hint('Scroll sideways to see every factor →', hint)
                     + '<table><thead><tr><th>Vulnerability</th>'
                     '<th>T</th><th>A</th><th>H</th><th>U</th><th>Advisory</th></tr></thead><tbody>'
                     + ''.join(rows) + '</tbody></table></div></details>')

    if stability is not None:
        klass = "robust" if (stability.gated or stability.robust) else "fragile"
        parts.append(
            f'<p class="stability {klass}"><b>Verdict stability.</b> '
            + ('A purchase blocker sets this verdict regardless of score weights.' if stability.gated else
               'This check was not run for this result. Resolve missing evidence before testing weight sensitivity.' if not stability.samples else
               f'{_esc(stability.dominant)} was the most common verdict, appearing in {stability.agreement:.0%} of '
               f'{stability.samples} tested weight settings. Scores ranged '
               f'{stability.score_min}&ndash;{stability.score_max}. '
               'This tests the effect of changing weights, not the accuracy of the evidence.')
            + '</p>')

    if resolution is not None:
        if resolution.resolved:
            parts.append(
                f'<p class="meta">Matched using {_esc(resolution.method.replace("_", " "))} '
                f'&middot; {plural(resolution.product_count, "product")} across '
                f'{plural(resolution.advisory_count, "advisory", "advisories")}'
                ' (security notices)</p>')
        elif not assessment.gates:
            parts.append(f'<div class="note"><b>Not assessed.</b> '
                         f'{_esc(resolution.reason)}</div>')

    for gate in assessment.gates:
        parts.append(
            f'<div class="gate"><b>Purchase blocker &mdash; {_esc(gate["gate"])}</b><br>'
            f'{_ids(_esc(gate["detail"]))}'
            f'<span class="src">Source: {_esc(gate["source"])}</span></div>')

    # A caution demands a human look without forcing the verdict: rendered in
    # the warning colour, right where a gate would sit, so it cannot be missed
    # on a page whose headline verdict reads well.
    for caution in getattr(assessment, "cautions", ()):
        title, explanation = CAUTION_HELP.get(
            _caution_key(caution['caution']), (caution['caution'], caution['detail']))
        parts.append(
            f'<div class="caution"><b>Supplier review needed &mdash; {_esc(title)}</b>'
            f'<p>{_esc(explanation)}</p><details><summary>Which vulnerabilities and sources?</summary>'
            f'<p>{_ids(_esc(caution["detail"]))}</p>'
            f'<span class="src">Source: {_esc(caution["source"])}</span></details></div>')

    if assessment.score is not None:
        scope = (' This percentage covers the scored device-vendor findings; '
                 'it does not confirm the applicability or safety of bundled software.'
                 if assessment.first_party_count and assessment.third_party_count else '')
        parts.append('<details class="coverage"><summary>What evidence was checked?</summary>'
                     f'<p>Evidence completeness for scored findings: <b>{assessment.confidence:.0%}</b>. '
                     'This describes available scoring inputs, not independent verification of every fact '
                     'or a guarantee that the equipment is secure.' + scope + '</p></details>')

    if assessment.pillars:
        parts.append(_pillar_table(assessment, weights, hint))

    for note in assessment.notes:
        parts.append(f'<div class="note">{_ids(_esc(note))}</div>')

    ranked = sorted(findings, key=lambda f: (-(f.epss or 0), -(f.cvss or 0)))
    top = ranked[:10]
    if top:
        if len(ranked) > len(top):
            # A capped table must say so: "54 need review" above a silent
            # 10-row table reads as the whole list. And the JSON export caps
            # at the same 10 and records the remainder in
            # `findings_truncated` -- claiming it "carries every finding" sent
            # a buyer to an export described as exhaustive that is not.
            parts.append(f'<p class="tnote">Showing the {len(top)} most'
                         f' significant of {len(ranked)} findings, ranked by'
                         ' exploitation probability and then severity. The'
                         ' JSON export carries the same selection and records'
                         ' how many were left out.</p>')
        parts.append(_cve_table(top, hint))

    parts.append('</section>')
    return "".join(parts)


# Threat data feeds T. CVSS severity and network topology are context; actual
# reachability and credible OT consequence are established separately in RT4.
FEEDS_EXPOSURE = {"Exploitation"}

# Recorded and shown, but deliberately NOT a term: where the equipment sits
# describes the deployment, it does not establish that an attacker can reach
# the vulnerable service. Saying "not scored" here invited the obvious
# question -- then where does reachability come from? -- so the row answers it.
CONTEXT_ONLY = {"Network exposure"}


def _pillar_table(assessment, weights, hint=True):
    active_pillars = [p for p in assessment.pillars
                      if p.name != "Evidence quality" and p.scored]
    parts = ['<div class="tw" tabindex="0" role="region" aria-label="Pillar evidence, scroll horizontally for more columns">'
             + _scroll_hint('Scroll sideways to see all evidence →', hint)
             + '<table><thead><tr><th>Assessment part</th><th class="n">Score / 100</th>'
             '<th style="width:18%">&nbsp;</th><th class="n">Influence</th><th class="n">Evidence available</th>'
             '<th>Evidence</th></tr></thead><tbody>']
    for pillar in assessment.pillars:
        evidence = "".join(f"<li>{_labels(_esc(e))}</li>" for e in pillar.evidence)
        share = (_weight_share(pillar.name, weights, active_pillars)
                 if pillar.scored else None)
        weight = None if share is None else f"{share:.1%}"
        # Evidence quality is reported but not scored, and must look different
        # from the pillars that move the number.
        unscored = weight is None
        displayed_score = f"{pillar.score:.0f}" if pillar.scored else "not scored"
        bar_width = max(0, min(100, pillar.score)) if pillar.scored else 0
        parts.append(
            f'<tr{" class=unscored" if unscored else ""}>'
            f'<td><b>{_esc(PILLAR_LABELS.get(pillar.name, pillar.name))}</b></td>'
            f'<td class="n">{_esc(displayed_score)}</td>'
            f'<td><span class="bar"><i style="width:{bar_width:.0f}%"></i></span></td>'
            + (f'<td class="n">{weight}</td>' if weight
               else '<td class="n na">within exposure</td>'
               if pillar.name in FEEDS_EXPOSURE
               else '<td class="n na">context only</td>'
               if pillar.name in CONTEXT_ONLY
               else '<td class="n na">not scored</td>')
            + f'<td class="n">{pillar.coverage * 100:.0f}%</td>'
            f'<td><details class="evidence-details"><summary>Show supporting evidence</summary>'
            f'<ul class="ev">{evidence}</ul></details></td></tr>')
    parts.append('</tbody></table></div><p class="tnote">Influence is the weight used in the '
                 'formula. Evidence available describes usable inputs, including operator statements; '
                 'it does not mean every fact has been independently verified. Rows marked '
                 '“within exposure” carry no weight of their own because they are inputs to '
                 'the exposure score rather than separate terms. “Context only” means the row '
                 'is recorded and reported but is not a term in the formula: where the equipment '
                 'sits does not by itself establish that an attacker can reach a weakness, so it '
                 'never moves the score. Attack reachability is taken from each weakness&rsquo;s own '
                 'CVSS attack vector and the conditions it demands, narrowed only by what you have '
                 '<em>verified</em> &mdash; whether the affected service is reachable, and whether its '
                 'required privileges, user interaction or attack conditions can be met. Those answers '
                 'change the result; the network row does not. Evidence completeness is reported and '
                 'never scored.</p>')
    return "".join(parts)


def _cve_table(findings, hint=True):
    """The most significant CVEs, worst exploitation probability first.

    The affected range is shown because it is what a reader has to check by
    hand on the rows marked "needs review": saying a range could not be parsed
    without saying which range leaves them nowhere to start.
    """
    parts = ['<h3>Vulnerabilities to review</h3><p class="tnote">A CVE is a reference number '
             'for a known security weakness. Severity measures possible harm; EPSS estimates '
             'exploitation in the next 30 days. Neither shows that your equipment was attacked.</p>'
             '<div class="tw" tabindex="0" role="region" aria-label="CVE evidence, scroll horizontally for more columns">'
             + _scroll_hint('Scroll sideways to see all evidence →', hint)
             + '<table><thead><tr><th>Vulnerability (CVE)</th>'
             '<th class="n">Severity / 10 (CVSS)</th><th class="n">30-day estimate (EPSS)</th>'
             '<th>Confirmed exploitation record</th><th>Security notice</th>'
             '<th>Affected firmware range</th></tr></thead><tbody>']
    for f in findings:
        parts.append(
            f'<tr><td><code>{_esc(f.cve)}</code>'
            + ('' if f.decided else ' <span class="meta">needs review</span>')
            + f'</td><td class="n">{"Not available" if f.cvss is None else f"{f.cvss:.1f}"}</td>'
            f'<td class="n">{_probability(f.epss)}</td>'
            f'<td>{"Listed in CISA KEV" if f.in_kev else "No record shown"}</td>'
            f'<td><code>{_esc(f.advisory_id)}</code></td>'
            f'<td class="id rng">{_esc(f.version_range)}</td></tr>')
    parts.append('</tbody></table></div>')
    return "".join(parts)


def _summary_table(blocks, stabilities, hint=True):
    """Side-by-side ranking, so the decision is visible without scrolling."""
    rows = []
    for assessment, resolution, _ in blocks:
        colour = VERDICT_COLOR.get(assessment.verdict, INERT)
        st = stabilities.get(id(assessment), stabilities.get(assessment.product))
        robust = "&mdash;" if st is None else (
            "Blocked" if st.gated else "Needs verification" if assessment.provisional else
            "Not tested" if not st.samples else f"{st.agreement:.0%}")
        note = (assessment.gates[0]["gate"] if assessment.gates
                else 'Supplier verification required' if assessment.cautions or assessment.third_party_count
                else (f"Needs verification: {len(assessment.verification)} open"
                      f" check(s)" if assessment.provisional and assessment.verification else "")
                if resolution.resolved else resolution.reason)
        rows.append(
            f'<tr class="cand" style="--vc:{colour}">'
            f'<td><b>{_esc(assessment.product)}</b></td>'
            f'<td class="v">{_esc(assessment.verdict)}</td>'
            f'<td class="n">{score_label(assessment)}</td>'
            f'<td class="n">{"&mdash;" if assessment.score is None else assessment.findings_count}</td>'
            f'<td class="n">{robust}</td>'
            f'<td>{_esc(note)}</td></tr>')
    return ('<div class="tw" tabindex="0" role="region" aria-label="Candidate comparison, scroll horizontally for more columns">'
            + _scroll_hint('Scroll sideways to see all candidates’ evidence →', hint)
            + '<table><thead><tr><th>Candidate</th><th>Verdict</th>'
            '<th class="n">Score</th><th class="n">Vulnerabilities</th><th class="n">Verdict stability</th><th>Main reason</th>'
            '</tr></thead><tbody>' + "".join(rows) + '</tbody></table></div>'
            '<p class="tnote">Verdict stability shows how often the most common verdict '
            'repeated when score weights were changed. Below 90%, the result depends more '
            'strongly on the chosen weights. This does not measure evidence accuracy or '
            'the stability of the ranking. A dash means this check was not run.</p>')


def body(blocks, stabilities=None, weights=None, tools=''):
    """The summary table and assessment blocks, without the page around them.

    Split out so the local web server can put the same markup inside its own
    page. One renderer for both surfaces means they cannot drift into showing
    the same assessment differently.
    """
    stabilities = stabilities or {}
    summary = _summary_table(blocks, stabilities) if len(blocks) > 1 else ""
    return summary + "".join(
        _assessment_block(a, r, f, stabilities.get(id(a), stabilities.get(a.product)), weights, tools)
        for a, r, f in blocks)


def _query_table(queries):
    """Retain the procurement inputs alongside the resolved evidence."""
    if not queries:
        return ""
    fields = ('vendor', 'product', 'version', 'order_number')
    rows = ''.join('<tr>' + ''.join(f'<td>{_esc(query.get(field) or "—")}</td>'
                                   for field in fields) + '</tr>' for query in queries)
    mixed = any(q.get('version') for q in queries) and not all(q.get('version') for q in queries)
    return ('<h2>Assessment inputs</h2><p class="tnote">Original inputs, in result order. '
            'Keep these identifiers when reassessing.</p>'
            + ('<p class="note">Some candidates have firmware specified and others do not. '
               'Add a version for each to compare on equal terms.</p>' if mixed else '')
            + '<div class="tw"><table><thead><tr><th>Vendor</th><th>Product / model</th>'
            '<th>Firmware</th><th>Order number</th></tr></thead><tbody>' + rows + '</tbody></table></div>')


def render(blocks, title="ReTrust assessment", snapshot="", stabilities=None,
           provenance=(), weights=None, config_source="", queries=()):
    """Render one or more (assessment, resolution, findings) triples to HTML."""
    inner = body(blocks, stabilities, weights)
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>{_esc(title)}</title><style>{CSS}</style></head><body><div class=\"wrap\">"
        f"<p class=\"meta\">ReTrust &middot; generated {date.today().isoformat()}"
        + (f" &middot; data snapshot {_esc(snapshot)}" if snapshot else "")
        + f"</p><h1>{_esc(title)}</h1>{inner}"
        + _query_table(queries)
        + _footer_sources(provenance, weights, config_source)
        + "<footer>Scores are decision support, not a certification. Every figure above "
        "comes from public CISA, FIRST and vendor sources; weights are configurable and "
        "shown so you can disagree with them. Ranges this tool could not parse are "
        "reported as needing review, never assumed safe.</footer>"
        "</div></body></html>"
    )
