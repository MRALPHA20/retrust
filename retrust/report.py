"""Render an assessment as a self-contained HTML report.

The report is the deliverable a buyer attaches to a purchase decision, so every
number shows the evidence behind it and every abstention is stated plainly. No
external assets, so it can be emailed or opened offline.

The look is the "Control Room" language (Design-spec-document.md): a low-chroma
field, saturated colour spent only on a verdict, a gate or a gap, and every
status carried by a glyph and a word as well as a hue. Identifiers are set in
monospace throughout -- they are part numbers, and should read like the plate
they are stamped on.

One renderer serves two surfaces. With ``web=None`` it produces the static
export (light theme, no controls, no links out); with a ``WebView`` it also
emits the action bar, section nav, edit form, supplier questions and evidence
drawers the server supplies. Nothing here needs JavaScript.
"""

import html
import inspect
import re
from dataclasses import dataclass, field as dc_field
from datetime import date
from urllib.parse import quote, quote_plus

from . import assets, components, design, evidenceview, identity, score, supplychain
from .evidenceview import EvidenceView

# Export themes. The bare :root is the light default; the dark selector exists
# only because retrust/screenshot.py stamps data-theme to shoot both themes
# deterministically. There is deliberately no prefers-color-scheme rule: a
# report is printed and emailed, and a reader's OS setting must not turn the
# document they attach to a purchase order dark (spec 5.5).
THEME = (design.theme_css(design.LIGHT, ":root")
         + design.theme_css(design.DARK, ":root[data-theme=dark]"))

# The names the pre-redesign stylesheet used. The web shell still carries rules
# written against them until it is rebuilt on the new tokens, and a rule that
# reads an undefined variable silently loses its colour.
_LEGACY_ALIASES = (":root{--field:var(--ground);--panel:var(--surface);--sunk:var(--bar);"
                   "--ink:var(--text);--soft:var(--text-2);--faint:var(--muted);"
                   "--cond:var(--conditional)}\n")

# Kept apart from RESULT_CSS so the comparison page can change without
# touching the result rules. Appended to RESULT_CSS below.
COMPARE_CSS = """
.rt-cmp-card{padding:0;overflow:hidden;margin:var(--s20) 0}
.rt-cmp-card .tw{margin:0}
.rt-cmp-card .tnote{margin:0;padding:var(--s12) var(--s16);border-top:1px solid var(--rule)}
.rt-cmp-card .table-scroll-hint{padding:var(--s8) var(--s16)}
.tw table.rt-cmp{min-width:620px;border:0;border-collapse:separate;border-spacing:0}
.rt-cmp th,.rt-cmp td{vertical-align:middle;min-width:132px}
.rt-cmp thead th{position:sticky;top:0;z-index:2;vertical-align:top}
.rt-cmp .rt-cmp__label,.rt-cmp .rt-cmp__corner{position:sticky;left:0;z-index:1;min-width:150px;background:var(--bar);border-right:1px solid var(--rule)}
.rt-cmp thead .rt-cmp__corner{z-index:3}
.rt-cmp td.n{text-align:left}
@media (max-width:700px){.rt-cmp .rt-cmp__label,.rt-cmp .rt-cmp__corner{min-width:136px;max-width:136px;white-space:normal;overflow-wrap:break-word}.rt-cmp td{min-width:150px}}
.rt-cmp .rt-cmp__head{position:relative;min-width:150px;padding-right:calc(var(--s12) + 44px);font-family:var(--font-sans);font-size:.875rem;font-weight:600;line-height:1.3;text-transform:none;letter-spacing:0;white-space:normal;color:var(--text)}
.rt-cmp__name{display:block;overflow-wrap:anywhere}
.rt-cmp__order{display:block;margin-top:var(--s2);font-family:var(--font-mono);font-size:.75rem;font-weight:400;color:var(--muted);overflow-wrap:anywhere}
.rt-cmp__gate{color:var(--avoid)}
.rt-cmp__remove{position:absolute;top:0;right:0;display:flex;align-items:center;justify-content:center;width:44px;height:44px;font-size:1.25rem;line-height:1;text-decoration:none;color:var(--muted)}
.rt-cmp__remove:hover{color:var(--text)}
.rt-cmp__remove:focus-visible{outline:2px solid var(--action);outline-offset:-2px}
.rt-cmp__key{font-family:var(--font-mono);font-weight:600;color:var(--action)}
.rt-cmp td{font-family:var(--font-mono);font-size:.8125rem;color:var(--text-2)}
.rt-cmp td.rt-cmp__reason{font-family:var(--font-sans);color:var(--text-2);overflow-wrap:anywhere}
.rt-cmp td.rt-cmp__best,.rt-cmp td.rt-cmp__best .rt-cmp__val,.rt-cmp td.rt-cmp__best .rt-cmp__score{font-weight:700;color:var(--text)}
.rt-cmp__score{font-family:var(--font-mono);font-weight:500;font-size:1.25rem;line-height:1.2;color:var(--text);font-variant-numeric:tabular-nums}
.rt-cmp__score--range{font-size:.875rem}
.rt-cmp__score--struck{text-decoration:line-through;text-decoration-thickness:1px;color:var(--muted)}
.rt-cmp__val{display:block;color:var(--text)}
.rt-cmp__val--range{font-size:.75rem}
.rt-cmp__val--neutral{color:var(--verify)}
.rt-cmp__bar{position:relative;display:block;height:4px;margin-top:var(--s4);overflow:hidden;background:var(--raised)}
.rt-cmp__bar i{position:absolute;top:0;bottom:0;left:0;background:var(--action)}
.rt-cmp__bar i.rt-cmp__hatch{background:repeating-linear-gradient(90deg,var(--verify) 0 4px,transparent 4px 8px)}
.rt-confirm{box-sizing:border-box;width:min(320px,calc(100vw - 32px));margin:auto;padding:var(--s20);color:var(--text);background:var(--surface);border:1px solid var(--rule);border-radius:var(--r-card);box-shadow:var(--overlay-shadow)}
.rt-confirm::backdrop{background:rgba(0,0,0,.5)}
.rt-confirm:not(:popover-open){display:none}
.rt-confirm p{margin:0 0 var(--s16)}
.rt-confirm__actions{display:flex;flex-wrap:wrap;gap:var(--s8)}
.rt-cmp-actions{display:flex;flex-wrap:wrap;align-items:center;gap:var(--s8);margin:var(--s16) 0}
@media print{.rt-cmp .rt-cmp__label,.rt-cmp .rt-cmp__corner,.rt-cmp thead th{position:static}.rt-cmp__remove{display:none}}
"""

RESULT_CSS = """
.block{margin:var(--s32) 0 0}
.rt-result{display:flex;flex-direction:column;gap:var(--s20)}
.rt-result>*{margin:0}
.rt-identity{display:flex;flex-direction:column;gap:var(--s8)}
.rt-identity__eyebrow{margin:0;font-family:var(--font-mono);font-size:.75rem;line-height:1.3;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.rt-identity__title{margin:0;padding:0;border:0;font-family:var(--font-sans);font-weight:600;font-size:1.625rem;line-height:1.25;color:var(--text);overflow-wrap:anywhere}
.rt-identity__meta{display:flex;flex-wrap:wrap;gap:var(--s8);margin:0;padding:0;list-style:none}
.rt-supplier-review{margin:0;font-weight:600;color:var(--conditional)}
.rt-alerts{display:flex;flex-direction:column;gap:var(--s12)}
.rt-alert__src{display:block;margin-top:var(--s4);font-size:.75rem;color:var(--muted)}
.rt-alert__actions{display:flex;flex-wrap:wrap;align-items:center;gap:var(--s8);margin-top:var(--s12)}
.rt-alert__detail summary{cursor:pointer;color:var(--action)}
.rt-grid{display:grid;grid-template-columns:minmax(0,1fr);gap:var(--s20);align-items:start}
@media (min-width:1100px){.rt-grid{grid-template-columns:minmax(380px,1fr) minmax(0,2fr)}}
.rt-col{display:flex;flex-direction:column;gap:var(--s12);min-width:0}
.rt-col>*{margin:0}
.rt-score{display:flex;flex-direction:column;gap:18px;min-width:0}
.rt-score__top{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:var(--s12)}
.rt-score__top .rt-panel-label{margin:0}
.rt-score__hero{display:flex;align-items:baseline;gap:var(--s8);margin:0}
.rt-score__num{font-family:var(--font-mono);font-weight:500;font-size:4.5rem;line-height:1;color:var(--text);font-variant-numeric:tabular-nums}
@media (max-width:480px){.rt-score__num{font-size:3.5rem}}
.rt-score__num--struck{text-decoration:line-through;text-decoration-thickness:1px;text-decoration-color:var(--muted)}
.rt-score__of{font-family:var(--font-mono);font-size:.875rem;color:var(--muted)}
.rt-score__lines{display:flex;flex-direction:column;gap:var(--s4);margin:0;padding:0;list-style:none}
.rt-score__line{margin:0;font-family:var(--font-mono);font-size:.8125rem;line-height:1.4;color:var(--text-2)}
.rt-score__line--verify{color:var(--verify)}
.rt-score__line--muted{color:var(--muted)}
.rt-score__help{margin:0;max-width:75ch;color:var(--text-2)}
.rt-score__note{margin:0;font-size:.75rem;line-height:1.4;color:var(--muted)}
.rt-band{display:flex;flex-direction:column;gap:var(--s6)}
.rt-band__bar{position:relative;height:10px}
.rt-band__segs{display:flex;height:100%;overflow:hidden;border-radius:var(--r-sm)}
.rt-band__seg{display:block;height:100%;background:var(--raised)}
.rt-band__seg--avoid{background:var(--avoid-track)}
.rt-band__seg--conditional{background:var(--conditional-track)}
.rt-band__seg--prefer{background:var(--prefer-track)}
.rt-band__marker{position:absolute;top:-6px;width:2px;height:22px;margin-left:-1px;background:var(--text);transition:left var(--t-load) ease-out;animation:rt-band-slide var(--t-load) ease-out}
.rt-band__marker--overridden{opacity:.45}
.rt-band__range{position:absolute;top:0;height:10px;min-width:2px;box-sizing:border-box;border:1px solid var(--verify);background:repeating-linear-gradient(135deg,var(--verify) 0 2px,transparent 2px 5px);transition:left var(--t-load) ease-out,width var(--t-load) ease-out;animation:rt-band-grow var(--t-load) ease-out}
@keyframes rt-band-slide{from{left:0}}
@keyframes rt-band-grow{from{width:0}}
.rt-band__axis{position:relative;height:1.3em;margin-top:var(--s4);font-family:var(--font-mono);font-size:.75rem;line-height:1.3;color:var(--muted)}
.rt-band__tick{position:absolute;top:0;transform:translateX(-50%)}
.rt-band__tick--first{transform:none}
.rt-band__tick--last{transform:translateX(-100%)}
.rt-band__legend{display:flex;flex-wrap:wrap;gap:var(--s4) var(--s16);margin:0;padding:0;list-style:none;font-family:var(--font-mono);font-size:.75rem;color:var(--muted)}
.rt-strip{margin:0;padding:var(--s10) var(--s12);background:var(--bar);border:1px solid var(--rule);border-radius:var(--r-lg);color:var(--text)}
.rt-strip__tick{font-family:var(--font-mono);font-weight:600;color:var(--prefer)}
.rt-pillars{display:flex;flex-direction:column;gap:var(--s12);margin:0;padding:0;list-style:none}
.rt-pillar{display:grid;grid-template-columns:28px minmax(0,1fr) auto;column-gap:var(--s10);align-items:start}
.rt-pillar__key{font-family:var(--font-mono);font-weight:600;font-size:.875rem;line-height:1.3;color:var(--action)}
.rt-pillar__main{min-width:0}
.rt-pillar__head{display:flex;flex-wrap:wrap;align-items:baseline;justify-content:space-between;gap:var(--s2) var(--s8);font-size:.8125rem;line-height:1.4}
.rt-pillar__name{color:var(--text)}
.rt-pillar__miss{color:var(--verify)}
.rt-pillar__w{font-family:var(--font-mono);font-size:.75rem;color:var(--muted)}
.rt-pillar__track{position:relative;display:block;height:6px;margin-top:var(--s6);background:var(--raised);border-radius:1px;overflow:hidden}
.rt-pillar__fill{position:absolute;top:0;bottom:0;left:0;transition:width var(--t-load) ease-out;animation:rt-pillar-grow var(--t-load) ease-out}
@keyframes rt-pillar-grow{from{width:0}}
.rt-pillar__fill--prefer{background:var(--prefer)}
.rt-pillar__fill--conditional{background:var(--conditional)}
.rt-pillar__fill--avoid{background:var(--avoid)}
.rt-pillar__fill--action{background:var(--action)}
.rt-pillar__fill--neutral,.rt-pillar__fill--hatch{background:repeating-linear-gradient(90deg,var(--verify) 0 4px,transparent 4px 8px)}
.rt-pillar__val{min-width:56px;font-family:var(--font-mono);font-size:.875rem;line-height:1.3;text-align:right;color:var(--text);font-variant-numeric:tabular-nums}
.rt-pillar--neutral .rt-pillar__val{color:var(--verify)}
.rt-pillar__val--range{font-size:.75rem}
.rt-pillar .evidence-details{margin-top:var(--s4)}
.rt-pillar .ev{margin:var(--s4) 0 0}
.rt-pillars__note{margin:0;font-family:var(--font-mono);font-size:.75rem;color:var(--verify)}
.rt-gaps{display:flex;flex-direction:column;gap:var(--s12)}
.rt-gaps h3,.rt-technical h3{margin:0;font-size:1.125rem;font-weight:600;line-height:1.3}
.rt-gaps__lead{margin:0;max-width:75ch;color:var(--text-2)}
.rt-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:var(--s12);align-items:start}
.rt-gap__action{margin:var(--s4) 0 0}
.rt-context__body p{margin:0}
.rt-context__body p+p,.rt-context__body ul+p,.rt-context__body p+ul{margin-top:var(--s8)}
.rt-context__body ul{margin:0;padding-left:var(--s20);list-style:disc}
.rt-context__body li+li{margin-top:var(--s4)}
.rt-context .stability.fragile{color:var(--text)}
.rt-static__title{margin:var(--s8) 0 var(--s4);font-weight:600}
.assessment-more-info{border:1px solid var(--rule);border-radius:var(--r-card);background:var(--surface);padding:0 var(--s20)}
.assessment-more-info>summary{cursor:pointer;font-weight:600}
.assessment-more-info[open]>summary{margin-bottom:var(--s8)}
.rt-technical{display:flex;flex-direction:column;gap:var(--s16);padding-bottom:var(--s20)}
.block summary{min-height:44px;padding:var(--s10) 0;line-height:1.6}
.block summary:focus-visible{outline:2px solid var(--action);outline-offset:2px}
.meta{font-family:var(--font-mono);font-size:.75rem;line-height:1.4;color:var(--muted)}
code,.id{font-family:var(--font-mono);font-variant-numeric:tabular-nums}
code{white-space:nowrap}
.vector code{white-space:normal;overflow-wrap:anywhere}
.evidence-details{border:0;padding:0;margin:0;background:transparent}
.evidence-details summary{min-height:0;padding:var(--s2) 0;font-size:.75rem;color:var(--action);cursor:pointer}
.evidence-details[open]>summary{margin-bottom:var(--s4)}
.ev{margin:var(--s4) 0 0;padding-left:var(--s16);list-style:disc;color:var(--text-2);font-size:.8125rem}
.tw{overflow-x:auto;margin:var(--s12) 0}
.table-scroll-hint{display:none}
@media (max-width:700px){.tw table{min-width:760px}.table-scroll-hint{display:block;font-size:.75rem;color:var(--muted);padding:var(--s8) var(--s12);margin:0}}
.block table,.tw table{width:100%;font-size:.8125rem;background:var(--surface);border:1px solid var(--rule);font-variant-numeric:tabular-nums}
.block th,.block td,.tw th,.tw td{text-align:left;padding:var(--s8) var(--s12);border-bottom:1px solid var(--rule-row);vertical-align:top}
.block th,.tw th{font-family:var(--font-mono);font-size:.75rem;font-weight:500;line-height:1.4;text-transform:uppercase;letter-spacing:.06em;white-space:nowrap;color:var(--muted);background:var(--bar)}
.block tbody tr:last-child td,.tw tbody tr:last-child td{border-bottom:none}
.block th.n,.block td.n,.tw th.n,.tw td.n{text-align:right}
td.na{color:var(--muted)}
td.rng{max-width:15rem;overflow-wrap:anywhere;color:var(--text-2)}
tr.cand td:first-child{border-left:4px solid var(--vc)}
td.v{color:var(--vc);font-weight:700}
.bar{display:block;position:relative;height:6px;min-width:5rem;overflow:hidden;background:var(--raised)}
.bar i{position:absolute;inset:0 auto 0 0;background:var(--vc,var(--muted))}
tr.unscored{background:var(--bar)}
tr.unscored .bar i{background:var(--muted)}
.note{border:1px solid var(--rule);border-left:3px solid var(--conditional);background:var(--surface);border-radius:var(--r-lg);padding:var(--s12) var(--s16);margin:var(--s8) 0;color:var(--text-2)}
.tnote{font-size:.8125rem;color:var(--muted);margin:0 0 var(--s12)}
""" + COMPARE_CSS

# Everything that exists only because the export is a document: the page frame,
# the glossary that replaces tooltips, and print behaviour.
EXPORT_CSS = """
.wrap{padding-top:var(--s32);padding-bottom:var(--s48)}
.rt-export-title{margin:var(--s8) 0 0;padding:0;border:0;font-family:var(--font-sans);font-weight:600;font-size:1.625rem;line-height:1.25;color:var(--text)}
.sources{margin-top:var(--s48);color:var(--text-2)}
.sources h2,.rt-glossary h2{margin:0 0 var(--s12);font-family:var(--font-mono);font-weight:500;font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.sources dl{display:grid;grid-template-columns:auto 1fr;gap:var(--s4) var(--s20);margin:var(--s12) 0}
.sources dt{font-family:var(--font-mono);font-size:.8125rem;color:var(--muted)}
.sources dd{margin:0}
.rt-glossary{margin-top:var(--s32);color:var(--text-2)}
.rt-glossary dl{display:grid;grid-template-columns:minmax(8rem,max-content) 1fr;gap:var(--s6) var(--s20);margin:0}
.rt-glossary dt{font-family:var(--font-mono);font-size:.8125rem;font-weight:600;color:var(--text)}
.rt-glossary dd{margin:0}
footer{margin-top:var(--s32);padding-top:var(--s16);border-top:1px solid var(--rule);font-size:.75rem;color:var(--muted)}
@media print{
.wrap{max-width:none;padding:0}
.rt-grid{display:block}
.rt-grid>*+*{margin-top:var(--s20)}
.rt-card,.rt-alert,.rt-gap,.rt-context{break-inside:avoid}
.block{break-inside:auto}
.assessment-more-info::details-content{content-visibility:visible;display:block}
.tw{overflow:visible}
}
"""

# The legacy stylesheet name, now the web-facing result CSS: tokens (dark, as
# the web shell is), faces, base, components and the result rules. The web
# page assembles its own stack in webui.py; this exists so importers and the
# interim shell keep working.
CSS = (design.theme_css(design.DARK, ":root") + _LEGACY_ALIASES
       + assets.font_face_css(served=True) + design.BASE_CSS
       + components.CSS + evidenceview.CSS + RESULT_CSS)


def export_css():
    """The stylesheet of the self-contained export, in the order spec 5.5 needs.

    Order is load-bearing: tokens before anything that reads them, base before
    components, and EXPORT_CSS last so its print rules win.
    """
    return (THEME + assets.font_face_css(served=False) + design.BASE_CSS
            + components.CSS + evidenceview.CSS + RESULT_CSS + EXPORT_CSS)


@dataclass
class WebView:
    """Web-only context for the result renderer; None means export/static mode.

    The server builds one per result page and the composites read it. Every
    field is optional: an empty WebView renders the web variant with nothing
    extra in it.
    """

    actions_html: str = ""      # export menu / action buttons (components output)
    tabs_html: str = ""         # in-page section nav
    inputs_html: str = ""       # "what was assessed" editable inputs panel
    questions_html: str = ""    # supplier questions block
    evidence: EvidenceView = dc_field(default_factory=EvidenceView)
    # advisory id -> (title, released date string)
    advisories: dict = dc_field(default_factory=dict)
    # {"kev_loaded": bool, "screening_loaded": bool}: which lists actually ran.
    # A missing key means "not known", which is not the same as "not loaded".
    checks: dict = dc_field(default_factory=dict)
    order_number: str = ""
    version: str = ""
    # logical gap name -> DOM id of the input a gap card should link to
    field_ids: dict = dc_field(default_factory=dict)

# Identifiers turn up in prose too -- a KEV gate names the CVEs it fired on --
# and they should read as part numbers there as well. Substituted after
# escaping, and matching bare id shapes only, so it cannot introduce markup.
IDENTIFIER = re.compile(r"\b((?:CVE|ICSA|ICSMA|SSA|VDE)-[0-9][0-9A-Z-]*[0-9A-Z])")
_CVE_ID = re.compile(r"\bCVE-[0-9]{4}-[0-9]{4,}\b")
_URL_SCHEME = re.compile(r"https?://", re.I)

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

# The single letters the spec uses on the meters. Falls back to the first
# letter of the config key for a pillar added later.
PILLAR_LETTERS = {"exposure": "E", "patchability": "P", "vendor_practice": "V",
                  "certification": "C"}


def _weight_share(pillar_name, weights, active_pillars=None):
    """The exponent this pillar carries in the composite, or None if unknown.

    score._composite raises every pillar to weight / (sum of ALL the pillar
    weights): a pillar with no evidence is not dropped, it enters at
    MISSING_PILLAR with its full weight. So the share is normalised over the
    whole set. The old code renormalised over the pillars that happened to be
    scored, which showed a larger share than the model applies the moment one
    pillar was missing. `active_pillars` is accepted and ignored so existing
    callers keep working; it must not change the answer.
    """
    key = PILLAR_KEYS.get(pillar_name)
    if key is None or not weights:
        return None
    total = sum(weights.get(spec.key, 0) for spec in score.PILLARS) or 1.0
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
                     'figures above show how much that would matter. A part with no '
                     'measurable evidence is not dropped: it enters the formula as a neutral '
                     f'{score.MISSING_PILLAR:.0f} at its full weight, and the other weights '
                     'are not adjusted.</p>')
    parts.append("</section>")
    return "".join(parts)


VERDICT_COLOR = {"VERIFY": "var(--verify)", "PREFER": "var(--prefer)",
                 "CONDITIONAL": "var(--conditional)", "AVOID": "var(--avoid)",
                 "NOT ASSESSED": "var(--muted)"}
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
# is inert -- not a verdict hue, which would light a stripe in a colour that
# means something else.
INERT = VERDICT_COLOR["NOT ASSESSED"]

# Which gate labels are supplier restrictions rather than facts about the
# product. The labels belong to supplychain.gates_for; equality on the shared
# constants is the whole link between the two files.
RESTRICTION_GATES = frozenset({supplychain.COVERED_LIST_GATE, supplychain.SANCTIONS_GATE})

# Phrases in an assessment's verification list, and the form field that closes
# each. The checklist words some questions differently from the form. Moved
# here from serve.py (where it is OPEN_QUESTIONS) so the page that draws the
# gap cards and the code that decides which form fields are still open read
# one table. Same shape and order as the original, so serve can alias it.
GAP_RULES = (
    ('"Network exposure"', 'network_exposure'),
    ('"Attack reachability (A)"', 'interface'),
    ('"Exploitation prerequisites"', 'prerequisites'),
    ('"Credible operational impact (H)"', 'consequence'),
    ('"Is the firmware you are getting already fixed?"', 'remediation'),
    ('exact firmware version', 'version'),
    ('Re-check the version', 'version'),
    ('Resolve the conflict', 'version'),
)
# Checklist items no form field can close: the evidence itself is missing.
# Same phrases as serve.DATA_GAPS.
DATA_GAP_RULES = (
    ('Exploitation data is missing', 'T', 'Exploitation data missing'),
    ('CVSS base score is missing', 'I', 'CVSS score missing'),
    ('Review the attack requirements', 'A', 'Attack requirements unsettled'),
)
# Tag and title per form field. The tag is the model term the answer feeds, so
# the card says which factor of Z stays a range until it is closed.
GAP_TAGS = {'network_exposure': 'ZONE', 'interface': 'A', 'prerequisites': 'A',
            'consequence': 'H', 'remediation': 'U', 'version': 'FW'}
GAP_TITLES = {
    'network_exposure': 'Network exposure not given',
    'interface': 'Attack reachability not verified',
    'prerequisites': 'Exploitation prerequisites not verified',
    'consequence': 'Operational impact not given',
    'remediation': 'Firmware fix status not given',
    'version': 'Firmware version needs checking',
}


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


def _plain(text, static):
    """Source text as shown: the export carries identifiers, not URLs.

    A downloaded report is self-contained and is checked for any scheme
    prefix, so a gate source that is a web address loses only its "https://".
    The host and path -- what a reader would type -- stay.
    """
    text = str(text)
    return _URL_SCHEME.sub("", text) if static else text


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


def _calculation_summary(assessment):
    """Show the values applied and common reasons for an unchanged score."""
    if assessment.score is None or assessment.exposure_min is None:
        return ''
    def number(low, high, places=1):
        return f"{low:.{places}f}" if abs(high-low) < 1e-10 else f"{low:.{places}f}–{high:.{places}f}"
    e = number(assessment.exposure_min, assessment.exposure_max)
    risk = number(1-assessment.exposure_max/100, 1-assessment.exposure_min/100, 3)
    network = NETWORK_LABELS.get(assessment.network_exposure, 'Unknown')
    factors = [entry['factors'] for path in assessment.paths for entry in path['inputs']]
    def factor(name):
        values = {tuple(item[name]) for item in factors}
        if not values:
            return 'Not available'
        if len(values) > 1:
            return 'Varies by vulnerability'
        low, high = next(iter(values))
        return number(low, high, 2)
    parts = ['<section class="calculation-summary"><h3>Applied scoring inputs</h3>',
             '<p class="tnote"><b>Network exposure:</b> ' + _esc(network)
             + '. Connectivity is context; verified attack paths determine A.</p>',
             '<p class="tnote"><b>Threat T:</b> ' + _esc(factor('T'))
             + ' · <b>Severity I:</b> ' + _esc(factor('I'))
             + ' · <b>Effective attack factor A:</b> ' + _esc(factor('A'))
             + ' · <b>Operational impact H:</b> ' + _esc(factor('H'))
             + ' · <b>Unresolved applicability U:</b> ' + _esc(factor('U')) + '.</p>',
             '<p class="tnote"><b>Combined risk R:</b> ' + risk
             + ' · <b>Exposure safety E:</b> ' + e + '/100. E = 100 × (1 − R).</p>']
    if factors and all(item['A'][1] == 0 for item in factors):
        parts.append('<p class="tnote"><b>Why some changes do not move this score:</b> '
                     'All assessed attack paths are recorded as blocked (A = 0). Their contributions are zero, so changing impact or network context does not change exposure. Reassess reachability if access changes.</p>')
    elif factors and all(item['H'][1] == 0 for item in factors):
        parts.append('<p class="tnote">No material operational impact is recorded (H = 0), so these paths contribute no operational risk.</p>')
    elif factors and all(item['U'][1] == 0 for item in factors):
        parts.append('<p class="tnote">The assessed vulnerabilities are recorded as fixed or not applicable (U = 0), so these paths contribute zero.</p>')
    elif assessment.exposure_min == 0 and not getattr(assessment, 'evidence_free', False):
        # An evidence-free range starts at 0 because nothing was measured, not
        # because the risk index saturated.
        parts.append('<p class="tnote">The conservative risk index has reached its maximum (R = 1). Further increases cannot reduce exposure safety below zero.</p>')
    if any(note.startswith('Capped below PREFER:') for note in assessment.notes):
        parts.append('<p class="tnote"><b>Policy cap applies:</b> The final score cannot enter PREFER while the stated unfixable credential issue remains. Exposure can change while the capped score remains the same.</p>')
    if assessment.gates:
        parts.append('<p class="tnote">A mandatory purchase blocker determines AVOID regardless of the numerical score.</p>')
    parts.append('</section>')
    return ''.join(parts)


# ---------------------------------------------------------------------------
# Result composites
# ---------------------------------------------------------------------------

def _score_text(value):
    return components.fmt_score(value)


def _range_text(low, high):
    """A score range at one decimal on both ends: "41.3–78.2".

    components.fmt_range prints whole numbers bare ("41–78"), which suits a
    badge; beside a headline numeral the two ends must read at the same
    precision as the numeral itself.
    """
    return f"{_score_text(low)}{RANGE_DASH}{_score_text(high)}"


def _bounds(assessment):
    """(low, high) of the score; both None when there is no score."""
    if assessment.score is None:
        return None, None
    low = assessment.score_min if assessment.score_min is not None else assessment.score
    high = assessment.score_max if assessment.score_max is not None else low
    return low, high


def _is_unidentified(assessment, resolution):
    return (resolution is not None and not resolution.resolved) or not assessment.resolved


def _firmware(assessment, web):
    """The firmware version this result was scored for, or "".

    The web page passes it; the export recovers it from the assessment's own
    vector (FW:<version> | FW:unset), the record of what was actually scored.
    """
    if web is not None and web.version:
        return web.version
    found = re.search(r"/FW:([^/]+)", assessment.vector or "")
    return "" if not found or found.group(1) == "unset" else found.group(1)


def _vendor(resolution):
    """The vendor of the matched product when every match agrees, else ""."""
    if resolution is None or not resolution.resolved:
        return ""
    vendors = {m.vendor for m in resolution.matches if getattr(m, "vendor", "")}
    return next(iter(vendors)) if len(vendors) == 1 else ""


def _identity(assessment, resolution, findings, web):
    """Eyebrow, title and meta chips.

    Category ("CONTROLLER") and service life are in the spec but not in the
    data, so they are omitted rather than invented. A chip is dashed when the
    value behind it is not confirmed: a firmware whose ranges could not be
    decided, a firmware not given, a zone not given.
    """
    vendor = _vendor(resolution)
    eyebrow = "Assessment" + (" · " + vendor if vendor else "")
    chips = []
    order = web.order_number if web is not None else ""
    if order:
        chips.append(components.meta_chip(
            "Order no. " + order,
            unverified=_is_unidentified(assessment, resolution)))
    version = _firmware(assessment, web)
    if version:
        undecided = any(not f.decided for f in findings)
        chips.append(components.meta_chip("FW " + version, unverified=undecided))
    else:
        chips.append(components.meta_chip("FW not given", unverified=True))
    zone = NETWORK_LABELS.get(assessment.network_exposure)
    if zone:
        chips.append(components.meta_chip("Zone: " + zone))
    else:
        chips.append(components.meta_chip("Zone: not given", unverified=True))
    parts = ['<header class="rt-identity">',
             f'<p class="rt-identity__eyebrow">{_esc(eyebrow)}</p>',
             f'<h2 class="rt-identity__title">{_esc(assessment.product)}</h2>',
             '<ul class="rt-identity__meta">'
             + "".join(f"<li>{chip}</li>" for chip in chips) + "</ul>"]
    # In the header, not the score card: it is the first thing said about the
    # product, and a reader who stops after the title must still see it.
    if assessment.cautions or assessment.third_party_count:
        parts.append('<p class="rt-supplier-review"><span aria-hidden="true">'
                     f'{components.GLYPH[components.CONDITIONAL]}</span> '
                     'Supplier verification required before purchase</p>')
    parts.append("</header>")
    return "".join(parts)


def _segments(bands):
    """[(start, end, verdict)] from the configured thresholds, lowest first."""
    ordered = sorted(((float(t), str(v)) for t, v in (bands or score.BANDS)),
                     key=lambda band: band[0])
    segments = []
    for index, (threshold, verdict) in enumerate(ordered):
        end = ordered[index + 1][0] if index + 1 < len(ordered) else 100.0
        segments.append((0.0 if index == 0 else threshold, end, verdict))
    return segments


def _verdict_of(value, bands):
    """The band a displayed (one-decimal) value falls in, as score.assess bands it."""
    for threshold, verdict in sorted(bands or score.BANDS, key=lambda band: -band[0]):
        if round(value, 1) >= threshold:
            return verdict
    return "AVOID"


def _tone(verdict):
    key = str(verdict).lower()
    return key if key in ("prefer", "conditional", "avoid") else "other"


def _pct(value):
    return f"{max(0.0, min(100.0, float(value))):.2f}".rstrip("0").rstrip(".")


def _band_bar(assessment, bands):
    """The three-band track with a marker, or a hatched range when provisional."""
    segments = _segments(bands)
    low, high = _bounds(assessment)
    spans = "".join(
        f'<span class="rt-band__seg rt-band__seg--{_tone(verdict)}" '
        f'style="width:{_pct(end - start)}%"></span>'
        for start, end, verdict in segments)
    names = ", ".join(f"{verdict} {start:g} to {end:g}" for start, end, verdict in segments)
    marker = ""
    if low is None:
        state = "No numeric score."
    elif assessment.provisional:
        marker = (f'<span class="rt-band__range" style="left:{_pct(low)}%;'
                  f'width:{_pct(high - low)}%"></span>')
        state = f"Provisional range {low:.1f} to {high:.1f}."
    else:
        overridden = " rt-band__marker--overridden" if assessment.gates else ""
        marker = (f'<span class="rt-band__marker{overridden}" '
                  f'style="left:{_pct(low)}%"></span>')
        state = (f"Score {low:.1f}, overridden by a purchase blocker."
                 if assessment.gates else f"Score {low:.1f}.")
    label = f"Score bands: {names}. {state}"
    ticks = [f'<span class="rt-band__tick rt-band__tick--first">{segments[0][0]:g}</span>']
    for start, _end, _verdict in segments[1:]:
        ticks.append(f'<span class="rt-band__tick" style="left:{_pct(start)}%">{start:g}</span>')
    ticks.append(f'<span class="rt-band__tick rt-band__tick--last" style="left:100%">'
                 f'{segments[-1][1]:g}</span>')
    legend = "".join(
        f'<li>{_esc(components.GLYPH.get(str(verdict).upper(), "–"))} {_esc(verdict)} '
        f'{start:g}{RANGE_DASH}{end:g}</li>'
        for start, end, verdict in segments)
    return ('<div class="rt-band"><div class="rt-band__bar" role="img" '
            f'aria-label="{_esc(label)}"><span class="rt-band__segs">{spans}</span>{marker}</div>'
            f'<div class="rt-band__axis" aria-hidden="true">{"".join(ticks)}</div>'
            f'<ul class="rt-band__legend">{legend}</ul></div>')


def _hero(assessment, resolution):
    """The numeral and the lines beneath it, per state."""
    low, high = _bounds(assessment)
    lines = []
    if low is None:
        # Two very different states share "no score": a product we could not
        # assess, and one a gate disqualified outright. Saying "not enough data"
        # for the second is wrong -- the tool decided, and the reason is the
        # gate shown above.
        reason = ("disqualified below" if assessment.gates
                  else "product not identified" if resolution is not None and not resolution.resolved
                  else "no applicable risk evidence" if resolution is not None and resolution.resolved
                  else "not enough data to assess")
        hero = ('<p class="rt-score__hero"><span class="rt-score__num" '
                'aria-label="No numeric score">&mdash;</span></p>')
        lines.append(("", reason))
        return hero, lines
    struck = " rt-score__num--struck" if assessment.gates else ""
    hero = ('<p class="rt-score__hero">'
            f'<span class="rt-score__num{struck}">{_esc(_score_text(low))}</span>'
            '<span class="rt-score__of">/ 100</span></p>')
    if assessment.gates:
        lines.append(("muted", "numeric score, overridden"))
    if assessment.provisional:
        lines.append(("verify", "Provisional range " + _range_text(low, high)))
    if getattr(assessment, "evidence_free", False):
        detail = ("product not identified" if not assessment.resolved
                  else "no applicable vulnerability recorded")
    elif getattr(assessment, "cleared_count", 0):
        detail = ("firmware outside the affected range of all "
                  f"{assessment.cleared_count} recorded CVE(s)")
    else:
        noun = 'vulnerability' if assessment.findings_count == 1 else 'vulnerabilities'
        detail = f'{assessment.findings_count} known {noun} included'
        if assessment.undecided_count:
            detail += f' · {assessment.undecided_count} need review'
    lines.append(("muted", detail))
    return hero, lines


def _explanation(assessment, resolution):
    text = VERDICT_HELP.get(assessment.verdict, "Review the evidence below.")
    if getattr(assessment, "evidence_free", False) and resolution is not None:
        text = (
            "The product was identified, but no advisory records an affected vulnerability "
            "for it, so the range spans everything the missing evidence allows and its low "
            "end is the headline. Your answers are recorded. This is often the vendor's "
            "fixed release: confirm the delivered firmware and ask the supplier for its "
            "advisory history."
            if resolution.resolved else
            # No "choose one below": this block is also the downloaded report and
            # the CLI output, where there is no form and no suggestion list. The
            # web page adds its own invitation where matches actually exist.
            "Your answers are recorded, but the product has not been identified in the advisory "
            "data, so nothing about it is measured and the range spans everything that allows. "
            "Check the manufacturer order number, vendor and model against the equipment "
            "nameplate, then assess it again.")
    return text


def _pillar_fill_class(pillar_key, value, bands):
    if pillar_key == "exposure":
        return _tone(_verdict_of(value, bands))
    # Spec 4.9 gives P and V the action hue for ordinary values; certification
    # is not mentioned and is drawn the same so the three read as one family.
    return "action"


def _evidence_list(pillar, static):
    items = "".join(f"<li>{_labels(_esc(e))}</li>" for e in pillar.evidence)
    if not items:
        return ""
    if static:
        return f'<ul class="ev">{items}</ul>'
    return ('<details class="evidence-details"><summary>Show supporting evidence'
            f'</summary><ul class="ev">{items}</ul></details>')


def _neutral_pillars(assessment):
    """Main pillars that entered the composite as the neutral placeholder.

    Only when a composite exists: a gated product with no score never ran the
    formula, so claiming "neutral 50 applied" there would describe a
    calculation that did not happen.
    """
    if assessment.score is None:
        return []
    by_name = {p.name: p for p in assessment.pillars}
    neutral = []
    for spec in score.PILLARS:
        pillar = by_name.get(spec.name)
        if pillar is None or pillar.scored:
            continue
        if (spec.key == "exposure" and assessment.provisional
                and assessment.exposure_min is not None):
            continue            # drawn as a range, not as the placeholder
        neutral.append(spec)
    return neutral


def _letter(spec):
    return PILLAR_LETTERS.get(spec.key, spec.key[:1].upper())


def _weight_text(spec, weights):
    share = _weight_share(spec.name, weights)
    return None if share is None else components.fmt_weight(share)


def _pillar_meters(assessment, weights, bands, static):
    """Four rows, E P V C: name, weight, track and fill, value.

    The weight is the exponent score._composite applies (weight over the sum of
    all four), including for a pillar that had no evidence: that pillar enters
    at the neutral placeholder with its full weight, and is drawn as exactly
    that -- a dashed violet half-bar and "50*" -- never as an absence.
    """
    if not assessment.pillars:
        return ""
    by_name = {p.name: p for p in assessment.pillars}
    neutral = {spec.key for spec in _neutral_pillars(assessment)}
    rows, notes = [], []
    for spec in score.PILLARS:
        pillar = by_name.get(spec.name)
        if pillar is None:
            continue
        label = PILLAR_LABELS.get(spec.name, spec.name)
        weight = _weight_text(spec, weights)
        weight_html = f'<span class="rt-pillar__w">w {weight}</span>' if weight else ""
        suffix = ""
        modifier = ""
        value_class = "rt-pillar__val"
        if (spec.key == "exposure" and assessment.provisional
                and assessment.exposure_min is not None
                and assessment.exposure_max is not None):
            low, high = assessment.exposure_min, assessment.exposure_max
            tone = _pillar_fill_class(spec.key, low, bands)
            fill = (f'<span class="rt-pillar__fill rt-pillar__fill--{tone}" '
                    f'style="width:{_pct(low)}%"></span>'
                    '<span class="rt-pillar__fill rt-pillar__fill--hatch" '
                    f'style="left:{_pct(low)}%;width:{_pct(high - low)}%"></span>')
            value = _range_text(low, high)
            value_class += " rt-pillar__val--range"
        elif spec.key in neutral:
            modifier = " rt-pillar--neutral"
            fill = ('<span class="rt-pillar__fill rt-pillar__fill--neutral" '
                    'style="width:50%"></span>')
            value = f"{score.MISSING_PILLAR:.0f}*"
            suffix = '<span class="rt-pillar__miss"> · missing → neutral</span>'
            notes.append((_letter(spec), weight))
        elif not pillar.scored:
            modifier = " rt-pillar--unmeasured"
            fill = ""
            value = "&mdash;"
            suffix = '<span class="rt-pillar__miss"> · not measured</span>'
        else:
            tone = _pillar_fill_class(spec.key, pillar.score, bands)
            fill = (f'<span class="rt-pillar__fill rt-pillar__fill--{tone}" '
                    f'style="width:{_pct(pillar.score)}%"></span>')
            value = _esc(_score_text(pillar.score))
        rows.append(
            f'<li class="rt-pillar{modifier}">'
            f'<span class="rt-pillar__key">{_esc(_letter(spec))}</span>'
            '<div class="rt-pillar__main"><p class="rt-pillar__head">'
            f'<span class="rt-pillar__name">{_esc(label)}{suffix}</span>{weight_html}</p>'
            f'<span class="rt-pillar__track" aria-hidden="true">{fill}</span>'
            f'{_evidence_list(pillar, static)}</div>'
            f'<span class="{value_class}">{value}</span></li>')
    if not rows:
        return ""
    foot = ""
    if notes:
        known = [(letter, w) for letter, w in notes if w]
        if len(notes) == 1 and known:
            said = f"*neutral {score.MISSING_PILLAR:.0f} applied at weight {known[0][1]}"
        elif known and len(known) == len(notes):
            listed = ", ".join(f"{w} ({letter})" for letter, w in known)
            said = f"*neutral {score.MISSING_PILLAR:.0f} applied at weight {listed}"
        else:
            said = f"*neutral {score.MISSING_PILLAR:.0f} applied at the pillar's full weight"
        foot = f'<p class="rt-pillars__note">{_esc(said)}</p>'
    return f'<ul class="rt-pillars">{"".join(rows)}</ul>{foot}'


def _list_card(title, body_html):
    return components.context_card(title, body_html)


def _checks_for(web, checks):
    if web is not None:
        return web.checks or {}
    return checks or {}


def _blocker_free(assessment, checks):
    """The "no blockers" strip, or the cards that say a check did not run.

    Honesty rule: a tick claims only what ran. KEV status needs the KEV list
    loaded (without it nothing can be marked known-exploited, so "no KEV
    blocker" would be vacuously true), and a supplier restriction needs the
    screening list. A list reported as not loaded produces a context card
    instead of a tick; a list whose state is unknown (key absent) produces
    neither a claim nor a card.
    """
    if assessment.gates or assessment.score is None or assessment.evidence_free:
        return ""
    kev, screening = checks.get("kev_loaded"), checks.get("screening_loaded")
    claims = []
    if kev is True:
        claims.append("No applicable KEV.")
    if screening is True:
        claims.append("No supplier restriction configured.")
    cards = []
    if kev is False:
        cards.append(components.context_card(
            "KEV list not loaded",
            "<p>Known-exploited status was not checked. No CVE could be marked as "
            "known exploited, so the absence of a KEV blocker here proves nothing. "
            "Load the CISA KEV snapshot and assess again.</p>"))
    if screening is False:
        cards.append(components.context_card(
            "Supplier screening list not loaded",
            "<p>Covered-list and sanctions screening did not run, so the absence of "
            "a supplier restriction here proves nothing. Load the screening lists "
            "and assess again.</p>"))
    strip = ""
    if claims:
        lead = ("No mandatory blockers." if not cards
                else "No mandatory blockers in the checks that ran.")
        strip = ('<p class="rt-strip"><span class="rt-strip__tick" aria-hidden="true">'
                 f'{components.GLYPH[components.OK]}</span> '
                 f'<span>{_esc(lead)} {_esc(" ".join(claims))}</span></p>')
    return strip + "".join(cards)


def _no_evidence_card(assessment, resolution, static):
    """The way forward when nothing about the product could be weighed."""
    gated = bool(assessment.gates)
    if gated or not (getattr(assessment, "evidence_free", False)
                     or _is_unidentified(assessment, resolution)):
        return ""
    unidentified = _is_unidentified(assessment, resolution)
    lead = ""
    if unidentified and resolution is not None and resolution.reason:
        lead = (f'<p><b>Not identified.</b> '
                f'{_esc(_plain(resolution.reason, static))}</p>')
    elif unidentified:
        lead = "<p><b>Not identified.</b></p>"
    if unidentified:
        ways = ("<li>Enter the manufacturer order number from the nameplate.</li>"
                "<li>Enter the vendor and the exact model name.</li>")
    else:
        ways = ("<li>Confirm that the delivered firmware is the vendor's fixed release.</li>"
                "<li>Ask the supplier for the advisory history of this product.</li>")
    return components.context_card("No usable evidence for this product",
                                   f"{lead}<p>Ways forward:</p><ul>{ways}</ul>")


def _score_card(assessment, resolution, weights, bands, checks, static):
    hero, lines = _hero(assessment, resolution)
    low, high = _bounds(assessment)
    badge = components.verdict_badge(
        assessment.verdict, "l",
        low if assessment.provisional else None,
        high if assessment.provisional else None)
    line_html = "".join(
        f'<li class="rt-score__line{" rt-score__line--" + tone if tone else ""}">'
        f'{_esc(text)}</li>' for tone, text in lines)
    parts = ['<section class="rt-card rt-score" aria-label="Procurement score">',
             '<div class="rt-score__top">',
             components.panel_label("Procurement score · S"), badge, "</div>",
             hero, f'<ul class="rt-score__lines">{line_html}</ul>',
             _band_bar(assessment, bands),
             f'<p class="rt-score__help result-help">{_esc(_explanation(assessment, resolution))}</p>']
    if assessment.score is not None:
        parts.append('<p class="rt-score__note">Higher scores are more favourable under the '
                     'chosen settings. The score supports a procurement review; it is not '
                     'a probability of compromise or a certification.</p>')
    parts.append(_no_evidence_card(assessment, resolution, static))
    parts.append(_blocker_free(assessment, checks))
    parts.append(_pillar_meters(assessment, weights, bands, static))
    parts.append("</section>")
    return "".join(parts)


def _drawer_id(cve):
    """The id the evidence drawer for `cve` carries.

    evidenceview owns the drawers; if it publishes drawer_id() this follows it,
    otherwise it assumes the same slug rule components uses for ids.
    """
    named = getattr(evidenceview, "drawer_id", None)
    if callable(named):
        return named(cve)
    return "ev-d-" + (re.sub(r"[^A-Za-z0-9_-]+", "-", str(cve)).strip("-") or "x")


def _gate_alert(assessment, gate, web, drawers_html):
    kind = "restriction" if gate.get("gate") in RESTRICTION_GATES else "blocker"
    static = web is None
    low, high = _bounds(assessment)
    if low is None:
        shown = "none computed"
    elif assessment.provisional:
        shown = _range_text(low, high)
    else:
        shown = _score_text(low)
    detail = _ids(_esc(_plain(gate.get("detail", ""), static)))
    body = (f'<p class="rt-alert__text">Verdict forced to AVOID regardless of numeric '
            f'score ({_esc(shown)}).</p>'
            f'<p class="rt-alert__text">{detail}</p>'
            f'<span class="rt-alert__src">Source: '
            f'{_esc(_plain(gate.get("source", ""), static))}</span>')
    if web is not None and kind == "blocker":
        actions = []
        first = _CVE_ID.search(str(gate.get("detail", "")))
        if first:
            target = _drawer_id(first.group())
            if f'id="{target}"' in drawers_html:
                actions.append(components.button(
                    "View advisory", kind="ghost", attrs={"popovertarget": target}))
            else:
                actions.append(components.link_button(
                    "View advisory", "#evidence", kind="ghost"))
        version_id = (web.field_ids or {}).get("version", "field-version")
        actions.append(components.link_button(
            "Re-assess with another version",
            "#" + quote(str(version_id), safe="-_:."), kind="secondary"))
        body += f'<div class="rt-alert__actions">{"".join(actions)}</div>'
    return components.alert(kind, "Purchase blocker — " + str(gate.get("gate", "")),
                            body_html=body)


def _gap_for(item):
    """(field, tag, title) for one checklist item."""
    for phrase, field in GAP_RULES:
        if phrase in item:
            return field, GAP_TAGS.get(field, ""), GAP_TITLES.get(field, "Open check")
    for phrase, tag, title in DATA_GAP_RULES:
        if phrase in item:
            return "", tag, title
    if item.startswith("Identify the product"):
        return "", "ID", "Product not identified"
    return "", "", "Open check"


def _gap_link(card_html, href, label):
    """Append a ghost link row to a gap card (spec 4.11's optional action row)."""
    action = ('<p class="rt-gap__action">'
              + components.link_button(label, href, kind="ghost") + "</p>")
    return card_html[:-len("</div>")] + action + "</div>"


def _gap_cards(assessment, resolution, findings, weights, web):
    static = web is None
    ids = {} if web is None else (web.field_ids or {})
    cards, seen, fields = [], set(), set()
    for item in assessment.verification:
        field, tag, title = _gap_for(item)
        if item in seen:
            continue
        seen.add(item)
        if field:
            fields.add(field)
        link = ""
        if field and not static:
            link = ids.get(field) or "field-" + field.replace("_", "-")
        cards.append(components.gap_card(title, _plain(item, static), link, tag))
    vendor = _vendor(resolution)
    for spec in _neutral_pillars(assessment):
        label = PILLAR_LABELS.get(spec.name, spec.name)
        weight = _weight_text(spec, weights)
        applied = (f"Neutral {score.MISSING_PILLAR:.0f} applied at weight {weight}."
                   if weight else
                   f"Neutral {score.MISSING_PILLAR:.0f} applied at the pillar's full weight.")
        card = components.gap_card(f"{label}: no usable evidence",
                                   "Nothing was found to measure this part. " + applied,
                                   "", _letter(spec))
        if not static:
            href = "/vendor" + ("?name=" + quote_plus(vendor) if vendor else "")
            card = _gap_link(card, href, "Look up vendor evidence")
        cards.append(card)
    # A firmware that was never given is a material gap even when no checklist
    # line happened to name it.
    if (assessment.score is not None and not assessment.evidence_free
            and assessment.resolved and "version" not in fields
            and not _firmware(assessment, web)):
        link = "" if static else (ids.get("version") or "field-version")
        cards.append(components.gap_card(
            "Firmware version not given",
            "The published affected ranges were not checked against your unit, so "
            "every recorded CVE stays in scope with applicability unresolved.",
            link, "FW"))
    return cards


def _disclose(summary, inner_html, static):
    """A collapsible on the web, plain visible rows in the export."""
    if static:
        return f'<p class="rt-static__title">{_esc(summary)}</p>{inner_html}'
    return f'<details><summary>{_esc(summary)}</summary>{inner_html}</details>'


def _caution_alerts(assessment, static):
    # A caution demands a human look without forcing the verdict: a REVIEW
    # alert, which is amber but not role=alert, because nothing here is an
    # emergency and an assertive announcement would outrank the real blockers.
    alerts = []
    for caution in getattr(assessment, "cautions", ()):
        title, explanation = CAUTION_HELP.get(
            _caution_key(caution['caution']), (caution['caution'], caution['detail']))
        inner = (f'<p>{_ids(_esc(_plain(caution["detail"], static)))}</p>'
                 f'<span class="rt-alert__src">Source: '
                 f'{_esc(_plain(caution["source"], static))}</span>')
        body = ('<div class="rt-alert__detail">'
                + _disclose("Which vulnerabilities and sources?", inner, static) + '</div>')
        alerts.append(components.alert(
            "review", "Supplier review needed — " + title,
            body=_plain(explanation, static), body_html=body))
    return alerts


def _stability_text(stability):
    if stability.gated:
        return 'A purchase blocker sets this verdict regardless of score weights.'
    if not stability.samples:
        return ('This check was not run for this result. Resolve missing evidence '
                'before testing weight sensitivity.')
    return (f'{_esc(stability.dominant)} was the most common verdict, appearing in '
            f'{stability.agreement:.0%} of {stability.samples} tested weight settings. '
            f'Scores ranged {stability.score_min}&ndash;{stability.score_max}. '
            'This tests the effect of changing weights, not the accuracy of the evidence.')


def _context_cards(assessment, stability, static):
    cards = []
    if assessment.first_party_count and assessment.third_party_count:
        noun = 'vulnerability' if assessment.first_party_count == 1 else 'vulnerabilities'
        cards.append(components.context_card(
            "What this score covers",
            f'<p class="score-scope">{assessment.first_party_count} {noun} from '
            'device-vendor advisories. '
            f'<b>{assessment.third_party_count} additional vulnerabilities in bundled software '
            'need separate supplier review.</b> Their reachability on this equipment '
            'has not been confirmed.</p>'))
    if assessment.notes:
        items = "".join(f'<li class="note-item">{_ids(_esc(_plain(n, static)))}</li>'
                        for n in assessment.notes)
        cards.append(components.context_card("Assessment notes", f"<ul>{items}</ul>"))
    if stability is not None:
        klass = "robust" if (stability.gated or stability.robust) else "fragile"
        cards.append(components.context_card(
            "Weight sensitivity",
            f'<p class="stability {klass}"><b>Verdict stability.</b> '
            f'{_stability_text(stability)}</p>'))
    if assessment.score is not None:
        scope = (' This percentage covers the scored device-vendor findings; '
                 'it does not confirm the applicability or safety of bundled software.'
                 if assessment.first_party_count and assessment.third_party_count else '')
        inner = (f'<p>Evidence completeness for scored findings: <b>{assessment.confidence:.0%}</b>. '
                 'This describes available scoring inputs, not independent verification of every fact '
                 'or a statement that the equipment has no unrecorded vulnerabilities.'
                 + scope + '</p>')
        cards.append(components.context_card(
            "Evidence checked",
            _disclose("What evidence was checked?", inner, static)
            if not static else inner))
    return cards


def _legacy_evidence(findings, hint):
    """The pre-redesign findings table, used only while evidenceview is a stub."""
    ranked = sorted(findings, key=lambda f: (-(f.epss or 0), -(f.cvss or 0)))
    top = ranked[:10]
    if not top:
        return ""
    note = ""
    if len(ranked) > len(top):
        # A capped table must say so: "54 need review" above a silent
        # 10-row table reads as the whole list. And the JSON export caps
        # at the same 10 and records the remainder in
        # `findings_truncated` -- claiming it "carries every finding" sent
        # a buyer to an export described as exhaustive that is not.
        note = (f'<p class="tnote">Showing the {len(top)} most'
                f' significant of {len(ranked)} findings, ranked by'
                ' exploitation probability and then severity. The'
                ' JSON export carries the same selection and records'
                ' how many were left out.</p>')
    return note + _cve_table(top, hint)


def _call_view(function, *args, **kwargs):
    """Call an evidenceview function; None while it is not yet the contract.

    Two shapes mean "not built yet": it raises NotImplementedError, or its
    signature cannot take the contract's arguments (the original stubs took
    different ones). Anything else -- including a TypeError raised from inside
    a real implementation -- is a bug and propagates.
    """
    try:
        inspect.signature(function).bind(*args, **kwargs)
    except TypeError:
        return None
    try:
        return function(*args, **kwargs)
    except NotImplementedError:
        return None


def _evidence_views(assessment, findings, web, hint):
    """The one place the result page calls evidenceview.

    Returns (exposure_html, evidence_html, drawers_html). Each call is made
    through the module so a replacement is picked up. While evidenceview is
    still a stub the page degrades to the previous table rather than failing;
    once it is complete the fallbacks are dead code and can go.
    """
    static = web is None
    view = EvidenceView() if web is None else web.evidence
    advisories = None if web is None else web.advisories
    firmware = _firmware(assessment, web)
    exposure = _call_view(evidenceview.exposure_card, assessment, static=static,
                          findings=findings, view=view)
    if exposure is None:
        summary = _calculation_summary(assessment)
        exposure = components.card(summary, "Exposure") if summary else ""
    evidence = _call_view(evidenceview.evidence_card, findings, assessment, view,
                          firmware=firmware, advisories=advisories, static=static)
    if evidence is None:
        evidence = _legacy_evidence(findings, hint)
    drawers = ""
    if not static:
        drawers = _call_view(evidenceview.drawers, findings, assessment, view,
                             advisories, firmware=firmware) or ""
    # The evidence module cannot import this one (circular), so the applied
    # inputs and the "why this answer did not move the score" notes sit next to
    # its card from here. Skipped when the card already carries them.
    summary = _calculation_summary(assessment)
    if summary and "calculation-summary" not in exposure:
        exposure += ('<details class="rt-calc"><summary>Applied scoring inputs</summary>'
                     + summary + '</details>')
    return exposure, evidence, drawers


def _contributions(assessment, hint):
    rows = []
    for path in assessment.paths:
        for entry in path['inputs']:
            cells = ''.join(
                '<td>' + _esc(f"{bounds[0]:.3g}" if bounds[0] == bounds[1]
                              else f"{bounds[0]:.3g}–{bounds[1]:.3g}") + '</td>'
                for bounds in entry['factors'].values())
            rows.append('<tr><td>' + _esc(entry['cve']) + '</td>' + cells
                        + '<td>' + _esc(entry['advisory']) + '</td></tr>')
    if not rows:
        return ""
    return ('<section><h3>How each vulnerability contributes</h3>'
            '<p>T = threat evidence, floored for service life; I = CVSS severity; '
            'A = attack access; H = operational harm; '
            'U = affected and unfixed. A range means evidence is missing. '
            'Repeated advisories for the same CVE count once. Separate CVEs '
            'are review units; independent attack paths have not been established.</p>'
            # .table-scroll had no rule in either stylesheet, so this
            # one table computed overflow-x:visible and clipped its U
            # and Advisory columns off the right of a phone with no way
            # to reach them. .tw is the class that scrolls.
            '<div class="tw" tabindex="0" role="region" aria-label="Factor contributions per vulnerability, scroll horizontally for more columns">'
            + _scroll_hint('Scroll sideways to see every factor →', hint)
            + '<table><thead><tr><th scope="col">Vulnerability</th>'
            '<th scope="col">T</th><th scope="col">I</th><th scope="col">A</th>'
            '<th scope="col">H</th><th scope="col">U</th><th scope="col">Advisory</th>'
            '</tr></thead><tbody>'
            + ''.join(rows) + '</tbody></table></div></section>')


def _technical(assessment, resolution, hint, static):
    """Settings, contributions, diagnostic pillars and match metadata.

    Collapsed on purpose: none of it changes a decision, all of it lets a
    reviewer reproduce one.
    """
    inner = []
    if assessment.vector:
        inner.append('<section class="vector"><h3>Technical assessment settings</h3>'
                     f'<p><code>{_esc(assessment.vector)}</code></p>'
                     '<p class="tnote">Includes the scoring version, supplied firmware and '
                     'operator choices. The data token identifies '
                     'the recorded data inputs. Current CLI and web assessments fingerprint the database and supplementary lists; older results may identify provenance metadata only.</p>'
                     '</section>')
    inner.append(_contributions(assessment, hint))
    if assessment.pillars:
        inner.append(_pillar_table(assessment, None, hint, section="additional"))
    if resolution is not None and resolution.resolved:
        inner.append(
            f'<p class="meta">Matched using {_esc(resolution.method.replace("_", " "))} '
            f'&middot; {plural(resolution.product_count, "product")} across '
            f'{plural(resolution.advisory_count, "advisory", "advisories")}'
            ' (security notices)</p>')
    inner = [piece for piece in inner if piece]
    if not inner:
        return ""
    ident = "" if static else ' id="technical"'
    return (f'<details class="assessment-more-info"{ident}>'
            '<summary>Show more info</summary><div class="rt-technical">'
            + "".join(inner) + '</div></details>')


def _assessment_block(assessment, resolution=None, findings=(), stability=None,
                      weights=None, tools='', hint=True, web=None, bands=None,
                      checks=None):
    """One product's result, top to bottom in reading order (spec 3).

    identity -> actions and section nav (web) -> blockers -> [score | exposure]
    -> gaps and context -> `tools` -> evidence -> questions and inputs (web)
    -> technical -> drawers (web). `tools` stays after the score's scope note
    because the verdict and its limits must come before any editing or
    download control. Blockers sit directly above the grid at every width: a
    hard disqualification is read before the number it overrides.
    """
    static = web is None
    findings = list(findings)
    colour = VERDICT_COLOR.get(assessment.verdict, INERT)
    # Declared once on the block so the comparison table's rows and anything
    # else keyed on the verdict read one value.
    parts = [f'<section class="block rt-result" style="--vc:{colour}">',
             _identity(assessment, resolution, findings, web)]
    if web is not None:
        parts.append(web.actions_html)
        parts.append(web.tabs_html)

    exposure_html, evidence_html, drawers_html = _evidence_views(
        assessment, findings, web, hint)

    if assessment.gates:
        parts.append('<div class="rt-alerts">'
                     + "".join(_gate_alert(assessment, g, web, drawers_html)
                               for g in assessment.gates) + '</div>')

    ident = "" if static else ' id="overview"'
    parts.append(f'<div class="rt-grid"{ident}>'
                 + _score_card(assessment, resolution, weights, bands,
                               _checks_for(web, checks), static)
                 + '<div class="rt-col">' + exposure_html + '</div></div>')

    gap_cards = _gap_cards(assessment, resolution, findings, weights, web)
    if gap_cards:
        ident = "" if static else ' id="gaps"'
        parts.append(f'<section class="verification rt-gaps"{ident}>'
                     '<h3>What to check next</h3>'
                     '<p class="rt-gaps__lead">A network or operations owner can help with '
                     'these checks. Unknown answers stay unresolved; ReTrust does not test '
                     'your network.</p>'
                     f'<div class="rt-cards">{"".join(gap_cards)}</div></section>')

    context = _caution_alerts(assessment, static)
    cards = _context_cards(assessment, stability, static)
    if context:
        parts.append(f'<div class="rt-alerts">{"".join(context)}</div>')
    if cards:
        parts.append(f'<div class="rt-cards">{"".join(cards)}</div>')

    # Keep the verdict and its limits ahead of editing and download controls.
    parts.append(tools)
    parts.append(evidence_html)
    if web is not None:
        parts.append(web.questions_html)
        parts.append(web.inputs_html)
    parts.append(_technical(assessment, resolution, hint, static))
    if web is not None:
        parts.append(drawers_html)
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


def _pillar_table(assessment, weights, hint=True, section=None):
    """The full pillar table: the diagnostic detail behind the meters."""
    parts = ['<div class="tw" tabindex="0" role="region" aria-label="Pillar evidence, scroll horizontally for more columns">'
             + _scroll_hint('Scroll sideways to see all evidence →', hint)
             + '<table><thead><tr><th scope="col">Assessment part</th><th scope="col" class="n">Score / 100</th>'
             '<th scope="col" style="width:18%"><span class="sr-only">Meter</span></th>'
             '<th scope="col" class="n">Influence</th><th scope="col" class="n">Evidence available</th>'
             '<th scope="col">Evidence</th></tr></thead><tbody>']
    neutral = {spec.name for spec in _neutral_pillars(assessment)}
    for pillar in assessment.pillars:
        is_main = pillar.name in PILLAR_KEYS
        if section == "scored" and not is_main:
            continue
        if section == "additional" and is_main:
            continue
        evidence = "".join(f"<li>{_labels(_esc(e))}</li>" for e in pillar.evidence)
        # A pillar with no evidence is not excluded from the weights: it keeps
        # its full exponent at the neutral placeholder (score._composite).
        is_neutral = pillar.name in neutral
        share = (_weight_share(pillar.name, weights)
                 if pillar.scored or is_neutral else None)
        weight = None if share is None else f"{share:.1%}"
        # Evidence quality is reported but not scored, and must look different
        # from the pillars that move the number.
        unscored = weight is None
        displayed_score = (f"{score.MISSING_PILLAR:.0f} (neutral)" if is_neutral
                           else f"{pillar.score:.0f}" if pillar.scored else "not scored")
        bar_width = (score.MISSING_PILLAR if is_neutral
                     else max(0, min(100, pillar.score)) if pillar.scored else 0)
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
    parts.append('</tbody></table></div>')
    if section == 'scored':
        return ''.join(parts)
    parts.append('<p class="tnote">Influence is the weight used in the '
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
             + '<table><thead><tr><th scope="col">Vulnerability (CVE)</th>'
             '<th scope="col" class="n">Severity / 10 (CVSS)</th><th scope="col" class="n">30-day estimate (EPSS)</th>'
             '<th scope="col">Confirmed exploitation record</th><th scope="col">Security notice</th>'
             '<th scope="col">Affected firmware range</th></tr></thead><tbody>']
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
            f'<td class="n">{"&mdash;" if assessment.score is None or not assessment.resolved else assessment.findings_count}</td>'
            f'<td class="n">{robust}</td>'
            f'<td>{_esc(note)}</td></tr>')
    return ('<div class="tw" tabindex="0" role="region" aria-label="Candidate comparison, scroll horizontally for more columns">'
            + _scroll_hint('Scroll sideways to see all candidates’ evidence →', hint)
            + '<table><thead><tr><th scope="col">Candidate</th><th scope="col">Verdict</th>'
            '<th scope="col" class="n">Score</th><th scope="col" class="n">Vulnerabilities</th>'
            '<th scope="col" class="n">Verdict stability</th><th scope="col">Main reason</th>'
            '</tr></thead><tbody>' + "".join(rows) + '</tbody></table></div>'
            '<p class="tnote">Verdict stability shows how often the most common verdict '
            'repeated when score weights were changed. Below 90%, the result depends more '
            'strongly on the chosen weights. This does not measure evidence accuracy or '
            'the stability of the ranking. A dash means this check was not run.</p>')


def _cmp_robust(assessment, st):
    """(text, agreement-or-None) for the verdict stability row."""
    if st is None:
        return "&mdash;", None
    if st.gated:
        return "Blocked", None
    if assessment.provisional:
        return "Needs verification", None
    if not st.samples:
        return "Not tested", None
    return f"{st.agreement:.0%}", st.agreement


def _cmp_note(assessment, resolution):
    if not resolution.resolved:
        return resolution.reason
    if assessment.gates:
        return assessment.gates[0]["gate"]
    if assessment.cautions or assessment.third_party_count:
        return "Supplier verification required"
    if assessment.provisional and assessment.verification:
        return f"Needs verification: {len(assessment.verification)} open check(s)"
    return ""


def _cmp_pillar(assessment, spec, neutral, bands):
    """(value for ranking or None, cell html) for one E/P/V/C cell."""
    pillar = {p.name: p for p in assessment.pillars}.get(spec.name)
    if pillar is None or assessment.score is None:
        return None, "&mdash;"
    if (spec.key == "exposure" and assessment.provisional
            and assessment.exposure_min is not None
            and assessment.exposure_max is not None):
        low, high = assessment.exposure_min, assessment.exposure_max
        return None, (f'<span class="rt-cmp__val rt-cmp__val--range">{_esc(_range_text(low, high))}</span>'
                      '<span class="rt-cmp__bar" aria-hidden="true">'
                      f'<i style="width:{_pct(low)}%"></i>'
                      f'<i class="rt-cmp__hatch" style="left:{_pct(low)}%;width:{_pct(high - low)}%"></i></span>')
    if spec.key in neutral:
        return None, (f'<span class="rt-cmp__val rt-cmp__val--neutral">{score.MISSING_PILLAR:.0f}*</span>'
                      '<span class="rt-cmp__bar rt-cmp__bar--neutral" aria-hidden="true">'
                      f'<i class="rt-cmp__hatch" style="width:{_pct(score.MISSING_PILLAR)}%"></i></span>')
    if not pillar.scored:
        return None, "&mdash;"
    return pillar.score, (f'<span class="rt-cmp__val">{_esc(_score_text(pillar.score))}</span>'
                          '<span class="rt-cmp__bar" aria-hidden="true">'
                          f'<i style="width:{_pct(pillar.score)}%"></i></span>')


def _cmp_best(values, high):
    """Indexes holding the best value of a row, or none at all.

    Bold marks the winner; when everyone ties, or only one candidate has a
    number, there is no winner and bolding would only be noise.
    """
    numbers = [(i, v) for i, v in enumerate(values) if v is not None]
    if len(numbers) < 2:
        return set()
    best = (max if high else min)(v for _, v in numbers)
    winners = {i for i, v in numbers if v == best}
    return set() if len(winners) == len(numbers) else winners


def comparison_table(blocks, stabilities=None, hint=True, remove=None,
                     queries=None, bands=None, weights=None):
    """The transposed shortlist (spec 4.18): candidates are columns.

    `blocks` are (assessment, resolution, findings) in ranked order and keep
    that order. `remove(index)` returns the href that drops that candidate, or
    None for the static export, which has nowhere to link. `queries` is a
    parallel list of input dicts, used only to show the order number. The best
    value in a row is bold; there is no hue for "best".
    """
    stabilities = stabilities or {}
    cols = []
    for index, (assessment, resolution, findings) in enumerate(blocks):
        findings = list(findings or ())
        known = bool(resolution.resolved) and assessment.score is not None
        st = stabilities.get(id(assessment), stabilities.get(assessment.product))
        robust_text, agreement = _cmp_robust(assessment, st)
        neutral = {s.key for s in _neutral_pillars(assessment)}
        low, high = _bounds(assessment)
        gates = len(assessment.gates)
        unpatched = sum(1 for f in findings if not f.fixed)
        cols.append({
            "a": assessment, "known": known, "gated": bool(assessment.gates),
            "low": low, "high": high, "robust": robust_text, "agreement": agreement,
            "pillars": [_cmp_pillar(assessment, spec, neutral, bands) for spec in score.PILLARS],
            "blockers": gates if resolution.resolved else None,
            "gaps": (len(_gap_cards(assessment, resolution, findings, weights, None))
                     if resolution.resolved else None),
            "unpatched": unpatched if known else None,
            "kev": sum(1 for f in findings if f.in_kev) if known else None,
            "note": _cmp_note(assessment, resolution),
            "order": ((queries[index] or {}).get("order_number", "")
                      if queries and index < len(queries) else ""),
            "href": remove(index) if remove else None,
        })

    def number(value):
        return "&mdash;" if value is None else str(value)

    def cells(values, best):
        return "".join(f'<td class="n{" rt-cmp__best" if i in best else ""}">{number(v)}</td>'
                       for i, v in enumerate(values))

    def row(label, inner, key):
        return (f'<tr class="rt-cmp__row rt-cmp__row--{key}">'
                f'<th scope="row" class="rt-cmp__label">{label}</th>{inner}</tr>')

    head = ['<th scope="col" class="rt-cmp__corner">Measure</th>']
    for col in cols:
        a = col["a"]
        gate = ('<span class="rt-cmp__gate" role="img" aria-label="Has a purchase blocker">■</span> '
                if col["gated"] else "")
        order = f'<span class="rt-cmp__order">{_esc(col["order"])}</span>' if col["order"] else ""
        x = (f'<a class="rt-cmp__remove" href="{_esc(col["href"])}" '
             f'aria-label="Remove {_esc(a.product)} from the shortlist"><span aria-hidden="true">×</span></a>'
             if col["href"] else "")
        head.append(f'<th scope="col" class="rt-cmp__head"><span class="rt-cmp__name">{gate}{_esc(a.product)}</span>'
                    f'{order}{x}</th>')

    rows = []
    verdicts = "".join(
        '<td>' + components.verdict_badge(
            c["a"].verdict, "s",
            c["low"] if c["a"].provisional else None,
            c["high"] if c["a"].provisional else None) + '</td>' for c in cols)
    rows.append(row("Verdict", verdicts, "verdict"))

    # A gated candidate's number is overridden by its blocker, so it cannot be
    # the best score even when it is the highest.
    scores = [c["a"].score if c["a"].score is not None and not c["gated"] else None for c in cols]
    best = _cmp_best(scores, True)
    cell = []
    for i, c in enumerate(cols):
        a = c["a"]
        if c["low"] is None:
            text, klass = "&mdash;", ""
        elif a.provisional:
            text, klass = _esc(_range_text(c["low"], c["high"])), " rt-cmp__score--range"
        else:
            text, klass = _esc(_score_text(c["low"])), ""
        if c["gated"] and c["low"] is not None:
            klass += " rt-cmp__score--struck"
        bold = " rt-cmp__best" if i in best else ""
        cell.append(f'<td class="n{bold}"><span class="rt-cmp__score{klass}">{text}</span></td>')
    rows.append(row("Score", "".join(cell), "score"))

    for k, spec in enumerate(score.PILLARS):
        values = [c["pillars"][k][0] for c in cols]
        best = _cmp_best(values, True)
        inner = "".join(
            f'<td class="rt-cmp__pillar{" rt-cmp__best" if i in best else ""}">{c["pillars"][k][1]}</td>'
            for i, c in enumerate(cols))
        label = f'<span class="rt-cmp__key">{_esc(_letter(spec))}</span> {_esc(PILLAR_LABELS.get(spec.name, spec.name))}'
        rows.append(row(label, inner, "pillar-" + spec.key))

    for key, label in (("blockers", "Blockers"), ("gaps", "Open gaps"),
                       ("unpatched", "Unpatched CVEs"), ("kev", "In CISA KEV")):
        values = [c[key] for c in cols]
        rows.append(row(label, cells(values, _cmp_best(values, False)), key))

    values = [c["agreement"] for c in cols]
    best = _cmp_best(values, True)
    inner = "".join(f'<td class="n{" rt-cmp__best" if i in best else ""}">{c["robust"]}</td>'
                    for i, c in enumerate(cols))
    rows.append(row("Verdict stability", inner, "stability"))
    rows.append(row("Main reason", "".join(
        f'<td class="rt-cmp__reason">{_esc(c["note"]) or "&mdash;"}</td>' for c in cols), "reason"))

    return ('<section class="rt-card rt-cmp-card" aria-label="Shortlist comparison">'
            '<div class="tw" tabindex="0" role="region" '
            'aria-label="Candidate comparison, scroll horizontally for more columns">'
            + _scroll_hint('Scroll sideways to see all candidates’ evidence →', hint)
            + '<table class="rt-cmp"><thead><tr>' + "".join(head) + '</tr></thead><tbody>'
            + "".join(rows) + '</tbody></table></div>'
            '<p class="tnote">Verdict stability shows how often the most common verdict '
            'repeated when score weights were changed. Below 90%, the result depends more '
            'strongly on the chosen weights. This does not measure evidence accuracy or '
            'the stability of the ranking. A dash means this check was not run. Bold marks '
            'the best value in a row; a score overridden by a blocker is never marked best.</p>'
            '</section>')


def body(blocks, stabilities=None, weights=None, tools='', web=None, bands=None,
         checks=None, compare=None):
    """The summary table and assessment blocks, without the page around them.

    Split out so the local web server can put the same markup inside its own
    page. One renderer for both surfaces means they cannot drift into showing
    the same assessment differently. `web` is the server's context (actions,
    inputs, drawers); None is the static export. `bands` is the configured
    [(threshold, verdict), ...] list and `checks` the {kev_loaded,
    screening_loaded} facts for a caller with no WebView.
    """
    stabilities = stabilities or {}
    summary = (comparison_table(blocks, stabilities, bands=bands, weights=weights,
                                **(compare or {})) if len(blocks) > 1 else "")
    return summary + "".join(
        _assessment_block(a, r, f, stabilities.get(id(a), stabilities.get(a.product)),
                          weights, tools, web=web, bands=bands, checks=checks)
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
            + '<div class="tw"><table><thead><tr><th scope="col">Vendor</th><th scope="col">Product / model</th>'
            '<th scope="col">Firmware</th><th scope="col">Order number</th></tr></thead><tbody>' + rows + '</tbody></table></div>')


def _glossary(bands):
    """Visible definitions for what the web page offers as tooltips.

    A printed page has no hover, so each term the result uses is defined in
    the document. Every line states what the model computes (exposure.py,
    score._composite); none of them describes a probability.
    """
    segments = _segments(bands)
    band_text = "; ".join(
        f"{verdict} {start:g}{RANGE_DASH}{end:g}" for start, end, verdict in segments)
    pillar_names = ", ".join(
        f"{_letter(spec)} {PILLAR_LABELS.get(spec.name, spec.name).lower()}"
        for spec in score.PILLARS)
    terms = (
        ("Score", "The weighted geometric mean of the four pillars, from 0 to 100. Higher is "
                  "more favourable. It supports a procurement review; it is not a probability "
                  "of compromise or a certification."),
        ("Bands", band_text + ". The band is taken from the displayed one-decimal score."),
        ("Pillars", pillar_names + "."),
        ("w", "A pillar's weight divided by the sum of all four weights. It is the exponent "
              "the pillar's value is raised to in the score."),
        ("50*", f"No usable evidence for the pillar. A neutral {score.MISSING_PILLAR:.0f} enters "
                "the score at the pillar's full weight. It is a placeholder, not a measurement."),
        ("Provisional range", "Shown when material inputs are unknown. The low end assumes the "
                              "conservative case for every unanswered input and is the headline; "
                              "the hatched part of a bar is the span the open inputs allow."),
        ("T I A H U", "Per-vulnerability factors. T threat evidence (strongest of KEV, LEV and "
                      "EPSS, floored by how the flaw is reached), I CVSS severity, A attack "
                      "access, H operational harm, U whether this firmware is affected and unfixed."),
        ("Z", "T × I × A × H × U for one review unit (a CVE)."),
        ("R and E", "R = min(1, Z1 + 0.20·Z2 + 0.10·Z3) over the three highest Z values; "
                    "E = 100 × (1 − R)."),
        ("KEV", "Listed in the CISA Known Exploited Vulnerabilities catalogue."),
        ("EPSS", "FIRST's estimate of exploitation in the next 30 days. It does not show "
                 "that your equipment was attacked."),
    )
    rows = "".join(f"<dt>{_esc(t)}</dt><dd>{_esc(d)}</dd>" for t, d in terms)
    return ('<section class="rt-glossary"><h2>Terms used in this report</h2>'
            f'<dl>{rows}</dl></section>')


def render(blocks, title="ReTrust assessment", snapshot="", stabilities=None,
           provenance=(), weights=None, config_source="", queries=(), bands=None,
           checks=None):
    """Render one or more (assessment, resolution, findings) triples to HTML.

    The self-contained export: light theme, no controls, no scripts, no
    external references. `provenance` (rows from index.provenance) is also the
    only evidence an export has of which lists were loaded, so a KEV row there
    lets the blocker-free strip say "No applicable KEV"; a caller that passes
    no provenance gets no claim about KEV at all.
    """
    if checks is None and provenance:
        checks = {"kev_loaded": any(p.get("source") == "CISA KEV" for p in provenance)}
    inner = body(blocks, stabilities, weights, bands=bands, checks=checks)
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>{_esc(title)}</title><style>{export_css()}</style></head><body><div class=\"wrap\">"
        f"<p class=\"meta\">ReTrust &middot; generated {date.today().isoformat()}"
        + (f" &middot; data snapshot {_esc(snapshot)}" if snapshot else "")
        + f"</p><h1 class=\"rt-export-title\">{_esc(title)}</h1>{inner}"
        + _query_table(queries)
        + _footer_sources(provenance, weights, config_source)
        + _glossary(bands)
        + f'<p class="tnote">Model {_esc(score.SCORING_VERSION)} · Tool build {_esc(identity.build_fingerprint())}. Keep this report with its data snapshot when reassessing.</p>'
        + "<footer>Scores are decision support, not a certification. Every figure above "
        "comes from public CISA, FIRST and vendor sources; weights are configurable and "
        "shown so you can disagree with them. Ranges this tool could not parse are "
        "reported as needing review, never treated as cleared.</footer>"
        "</div></body></html>"
    )
