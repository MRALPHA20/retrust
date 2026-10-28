"""Shared presentation for the local browser. No scripts or remote assets."""

import contextvars
import html
import os
from datetime import date

from . import assets, components, design, doctor, evidenceview, report, score


def esc(value):
    return html.escape(str(value or ""), quote=True)


# The repository is private. Linking it from the hosted site advertised the
# exact private path and handed every visitor a 404 -- which made the
# keep-private decision read as a broken link rather than a choice. A hosted
# deployment says where the source stands; a local one, where the operator
# already has a clone, keeps the link.
SOURCE_URL = "https://github.com/MRALPHA20/retrust"


def source_note(hosted=None):
    """Either a link to the source or an honest sentence about its absence."""
    if os.environ.get("RETRUST_HOSTED") == "1" if hosted is None else hosted:
        return "Source code is not public yet."
    return f'<a href="{SOURCE_URL}">Source code on GitHub</a>'



# Request-scoped: the handler sets the index provenance before dispatch and
# resets it afterwards, so page() (called from ~15 sites that know nothing
# about provenance) can still show the snapshot status. A ContextVar rather
# than a global because the concurrent server renders on worker threads.
CURRENT_SNAPSHOT = contextvars.ContextVar("retrust_snapshot", default=None)

# Exactly four primary destinations (D5). Every other page is reached through
# related_links() and the footer.
PRIMARY_NAV = (("/score", "Assess"), ("/compare", "Compare"),
               ("/", "Search"), ("/about", "Methodology"))

CONTEXTUAL_PAGES = (("/vendor", "Vendor profile"), ("/timeline", "Advisory timeline"),
                    ("/alternatives", "Find alternatives"), ("/annex", "Supplier questions"),
                    ("/ssvc", "Response priority"), ("/lev", "Exploitation estimate"),
                    ("/demo", "Guided demo"))

# Which primary item a route lights up.
NAV_FOR_ROUTE = {"/": "/", "/score": "/score", "/annex": "/score",
                 "/alternatives": "/score", "/ssvc": "/score", "/lev": "/score",
                 "/vendor": "/", "/timeline": "/", "/demo": "/",
                 "/compare": "/compare", "/about": "/about"}

_TITLE_ROUTES = (("Score", "/score"), ("Procurement comparison", "/compare"),
                 ("Alternatives", "/alternatives"), ("Timeline", "/timeline"),
                 ("Annex", "/annex"), ("RFQ", "/annex"), ("SSVC", "/ssvc"),
                 ("LEV", "/lev"), ("Vendor", "/vendor"), ("About", "/about"),
                 ("Demo", "/demo"), ("Search", "/"))


def _active_route(title, active):
    if active is None:
        if title == "ReTrust":
            return "/"
        active = next((route for prefix, route in _TITLE_ROUTES
                       if title.startswith(prefix)), None)
    return NAV_FOR_ROUTE.get(active)


def related_links(active=None):
    """Links to the contextual pages, minus `active` (a route such as "/ssvc").

    Rendered under page titles by the page functions and repeated in the
    footer. A plain list, not a <nav>: the primary navigation is the only
    navigation landmark with page-level destinations.
    """
    items = "".join(f'<li><a href="{route}">{label}</a></li>'
                    for route, label in CONTEXTUAL_PAGES if route != active)
    return f'<ul class="rt-related" aria-label="Related pages">{items}</ul>'


def _captured(provenance, source):
    for row in provenance:
        if row.get("source") == source:
            try:
                return date.fromisoformat(str(row.get("captured") or "")[:10])
            except ValueError:
                return None
    return None


def snapshot_status(provenance, today, hosted):
    """Header chip: glyph + word, never colour alone, never role=alert.

    The date shown is the oldest of the KEV and EPSS captures, because the
    snapshot is only as fresh as its stalest exploitation signal. A missing
    feed means the KEV gate cannot fire, which is worse than a stale one.
    """
    mode = "hosted" if hosted else "offline"
    if provenance is None:
        return ('<span class="rt-snap rt-snap--unknown"><span aria-hidden="true">●</span> '
                'Snapshot · unknown</span>')
    feeds = (("KEV", _captured(provenance, "CISA KEV"), doctor.AGE_LIMITS["kev"]),
             ("EPSS", _captured(provenance, "FIRST EPSS"), doctor.AGE_LIMITS["epss"]))
    missing = [name for name, captured, _ in feeds if captured is None]
    known = [captured for _, captured, _ in feeds if captured is not None]
    oldest = f" · {min(known).isoformat()}" if known else ""
    if missing:
        state, word = "missing", " · " + " and ".join(missing) + " missing"
    elif any((today - captured).days > limit for _, captured, limit in feeds):
        state, word = "stale", " · stale"
    else:
        state, word = "current", ""
    sr = '<span class="rt-sr"> (current)</span>' if state == "current" else ""
    return (f'<span class="rt-snap rt-snap--{state}"><span aria-hidden="true">●</span> '
            f'Snapshot · {mode}{oldest}{word}{sr}</span>')


def page(title, body, subtitle="", active=None):
    hosted = os.environ.get('RETRUST_HOSTED') == '1'
    workspace_label = 'Hosted workspace' if hosted else 'Local workspace'
    workspace_detail = 'Queries are processed on this server.' if hosted else 'Public evidence. Private decisions.'
    assessment_label = 'Hosted assessment' if hosted else 'Offline assessment'
    current = _active_route(title, active)
    links = "".join(
        f'<li><a href="{route}"' + (' aria-current="page"' if route == current else '')
        + f'>{label}</a></li>' for route, label in PRIMARY_NAV)
    status = snapshot_status(CURRENT_SNAPSHOT.get(), date.today(), hosted)
    footer_links = "".join(
        f'<li><a href="{route}">{label}</a></li>' for route, label in (
            ("/about", "Methodology"), ("/about#sources", "Source coverage")))
    return (
        '<!doctype html><html lang="en" data-theme="dark"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>{esc(title if title == "ReTrust" else title + " · ReTrust")}</title>'
        f'<style>{STYLESHEET}</style></head>'
        '<body class="app"><a class="skip-link" href="#main">Skip to content</a>'
        '<header class="rt-header">'
        '<a class="rt-brand" href="/" aria-label="ReTrust home">'
        f'{components.icon("shield-check", 22)}<span class="rt-wordmark">ReTrust</span>'
        f'<span class="rt-model">{esc(score.SCORING_VERSION)}</span></a>'
        f'<nav class="rt-nav" aria-label="Primary"><ul>{links}</ul></nav>'
        '<form class="rt-search" role="search" action="/" method="get">'
        '<label class="rt-sr" for="rt-global-q">Search by order number, vendor or model</label>'
        '<input id="rt-global-q" type="search" name="q" maxlength="200" autocomplete="off" '
        'placeholder="Order no. or vendor / model"></form>'
        f'{status}</header>'
        '<main id="main" class="wrap">'
        + (f'<p class="rt-page-sub">{esc(subtitle)}</p>' if subtitle else '')
        + body + '</main>'
        '<footer class="rt-footer"><div class="rt-footer__in">'
        '<p class="rt-footer__claim">ReTrust supports procurement review. It is not a '
        'probability of compromise or a certification.</p>'
        f'<ul class="rt-footer__links">{footer_links}<li>{source_note()}</li></ul>'
        f'{related_links(None)}'
        f'<p class="rt-footer__mode">{assessment_label} · {workspace_label} · {workspace_detail}</p>'
        '</div></footer></body></html>')


def error_page(title, heading, message, actions_html=""):
    """An error inside the shell: ERROR alert (role=alert) plus a way onward."""
    return page(title, f'<h1>{esc(heading)}</h1>'
                + components.alert("error", heading, message, body_html=actions_html))


SHELL_CSS = """
:root{--ink:var(--text);--soft:var(--text-2);--faint:var(--muted);--panel:var(--surface);--field:var(--ground);--sunk:var(--bar);--cond:var(--conditional);--sans:var(--font-sans);--mono:var(--font-mono)}
body.app{background:var(--ground);color:var(--text);font-size:.875rem;line-height:1.5}
.rt-header{display:flex;flex-wrap:wrap;align-items:center;gap:var(--s8) var(--s24);padding:var(--s12) var(--s24);background:var(--bar);border-bottom:1px solid var(--rule)}
.rt-brand{display:inline-flex;align-items:center;gap:var(--s8);color:var(--text);text-decoration:none}
.rt-brand:hover{color:var(--text)}
.rt-brand .rt-icon{color:var(--action)}
.rt-wordmark{font-family:var(--font-sans);font-weight:700;font-size:1rem;letter-spacing:.02em}
.rt-model{font-family:var(--font-mono);font-size:.75rem;line-height:1;color:var(--muted);border:1px solid var(--rule);border-radius:3px;padding:var(--s2) var(--s6)}
.rt-nav ul{display:flex;gap:var(--s4)}
.rt-nav a{display:inline-flex;align-items:center;min-height:36px;padding:0 var(--s12);color:var(--text-2);text-decoration:none;font-weight:500;border-bottom:2px solid transparent}
.rt-nav a:hover{color:var(--text)}
.rt-nav a[aria-current=page]{color:var(--text);border-bottom-color:var(--action)}
.rt-search{flex:1 1 260px;max-width:520px;margin:0}
.rt-search input{display:block;width:100%;height:36px;padding:0 var(--s12);background:var(--ground);color:var(--text);border:1px solid var(--control-border);border-radius:3px;font-family:var(--font-mono);font-size:.8125rem}
.rt-search input::placeholder{color:var(--muted);opacity:1}
.rt-snap{margin-left:auto;display:inline-flex;align-items:center;gap:var(--s6);font-family:var(--font-mono);font-size:.75rem;color:var(--muted);white-space:nowrap}
.rt-snap--current [aria-hidden]{color:var(--prefer)}
.rt-snap--stale{color:var(--text-2)}
.rt-snap--stale [aria-hidden]{color:var(--conditional)}
.rt-snap--missing{color:var(--text-2)}
.rt-snap--missing [aria-hidden]{color:var(--avoid)}
main.wrap{max-width:1360px;margin:0 auto;padding:var(--s24) var(--s24) var(--s48)}
.rt-page-sub{font-family:var(--font-mono);font-size:.75rem;color:var(--muted);margin:0 0 var(--s12)}
.rt-related{display:flex;flex-wrap:wrap;gap:var(--s4) var(--s16)}
.rt-footer{border-top:1px solid var(--rule);background:var(--bar);color:var(--muted);font-size:.8125rem}
.rt-footer__in{max-width:1360px;margin:0 auto;padding:var(--s20) var(--s24);display:grid;gap:var(--s8)}
.rt-footer p{margin:0}
.rt-footer__claim{color:var(--text-2)}
.rt-footer__links{display:flex;flex-wrap:wrap;gap:var(--s4) var(--s16)}
.rt-footer__mode{font-family:var(--font-mono);font-size:.75rem}
@media(max-width:1099px){
.rt-header{gap:var(--s8) var(--s16)}
.rt-brand{order:1}
.rt-snap{order:2}
.rt-nav{order:3}
.rt-search{order:4;flex:1 1 100%;max-width:none}
}
@media(max-width:639px){
.rt-header{padding:var(--s12) var(--s16)}
.rt-snap{margin-left:0;white-space:normal}
.rt-nav{flex:1 1 100%;overflow-x:auto;-webkit-overflow-scrolling:touch}
.rt-nav ul{width:max-content}
.rt-nav a{white-space:nowrap}
main.wrap{padding:var(--s16) var(--s16) var(--s32)}
.rt-footer__in{padding:var(--s16)}
.actions .button,.actions button:not(.rt-btn),.actions .rt-btn{flex:1 1 100%;width:100%}
}
@media(pointer:coarse){.rt-search input{font-size:1rem;height:44px}.rt-nav a{min-height:44px}}
"""

PAGE_CSS = """
main h1{font-family:var(--font-sans);font-weight:600;font-size:1.625rem;line-height:1.25;border:0;padding:0;margin:0 0 var(--s12);max-width:60rem}
main h2{font-size:1.125rem;font-weight:600;line-height:1.3;border:0;padding:0;margin:0 0 var(--s8)}
main h3{font-size:1rem;font-weight:600;margin:0 0 var(--s8)}
.lead{color:var(--text-2);max-width:42rem;font-size:1rem;line-height:1.6;margin:0 0 var(--s20)}
.eyebrow{font-family:var(--font-mono);font-weight:500;font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:0 0 var(--s8)}
.helper{font-size:.8125rem;color:var(--muted);margin:var(--s8) 0 0}
.muted{color:var(--muted)}
.empty{color:var(--text-2);font-size:.875rem}
.panel{border:1px solid var(--rule);border-radius:var(--r-card);background:var(--surface);padding:var(--s20);margin:0 0 var(--s16)}
.panel-heading{display:flex;justify-content:space-between;gap:var(--s12);align-items:baseline;margin-bottom:var(--s12)}
.panel-heading span{font-family:var(--font-mono);font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.notice{padding:var(--s12) var(--s16);border:1px solid var(--rule);border-left:3px solid var(--control-border);border-radius:var(--r-lg);background:var(--surface);color:var(--text-2);font-size:.875rem;margin:var(--s12) 0}
.section-title{display:flex;align-items:baseline;justify-content:space-between;margin:var(--s24) 0 var(--s12)}
.section-title span{font-family:var(--font-mono);font-size:.8125rem;color:var(--muted)}
.hero{margin:0 0 var(--s20)}
.hero h1{font-size:2rem}
.hero-mark{display:none}
.metrics{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:var(--s12);margin:var(--s20) 0}
.metric{padding:var(--s16);background:var(--surface);border:1px solid var(--rule);border-radius:var(--r-card)}
.metric strong{display:block;font-family:var(--font-mono);font-weight:500;font-size:1.5rem;line-height:1.2;margin-bottom:var(--s4);font-variant-numeric:tabular-nums}
.metric span{color:var(--text-2);font-size:.8125rem}
.metric small{display:block;color:var(--muted);font-family:var(--font-mono);font-size:.75rem;margin-top:var(--s6)}
main form{margin:var(--s16) 0 var(--s20)}
main label{display:block;color:var(--text-2);font-size:.8125rem;font-weight:500;margin:0 0 var(--s4)}
main input[type=text],main select{width:100%;max-width:42rem;min-height:40px;padding:var(--s8) var(--s12);font-family:var(--font-sans);font-size:.875rem;color:var(--text);background:var(--ground);border:1px solid var(--control-border);border-radius:var(--r-lg)}
main input::placeholder{color:var(--muted);opacity:1}
main input:focus,main select:focus{outline:2px solid var(--action);outline-offset:2px}
main button:not(.rt-btn),main .button{display:inline-flex;align-items:center;justify-content:center;min-height:40px;padding:0 var(--s16);background:var(--action);color:var(--on-action);border:1px solid var(--action);border-radius:var(--r-lg);font-family:var(--font-sans);font-weight:600;font-size:.875rem;cursor:pointer;text-decoration:none;white-space:nowrap;margin-top:var(--s12)}
main button:not(.rt-btn):hover,main .button:hover{background:var(--action-hover);border-color:var(--action-hover);color:var(--on-action)}
main .button.secondary{background:transparent;border-color:var(--control-border);color:var(--text)}
main .button.secondary:hover{background:var(--raised);color:var(--text);border-color:var(--text)}
.search-form{margin:0}
.search-line{display:flex;gap:var(--s8)}
.search-line input{max-width:none}
.search-line button{margin:0;min-width:128px}
.chips{display:flex;gap:var(--s8);flex-wrap:wrap;margin-top:var(--s12);align-items:center}
.chips>span{color:var(--muted);font-size:.8125rem}
.chip{border:1px solid var(--rule);background:var(--raised);border-radius:var(--r-md);padding:var(--s2) var(--s8);font-family:var(--font-mono);font-size:.8125rem;color:var(--text-2);text-decoration:none}
.chip:hover{border-color:var(--action);color:var(--text)}
.split{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(0,1fr);gap:var(--s16)}
.split .panel{margin:0}
.steps{list-style:none;padding:0;margin:var(--s16) 0 0;display:grid;gap:var(--s16)}
.steps li{display:flex;gap:var(--s12)}
.step-number{font-family:var(--font-mono);font-size:.8125rem;color:var(--action);border:1px solid var(--rule);background:var(--raised);border-radius:var(--r-md);min-width:28px;height:28px;display:grid;place-items:center}
.steps b{font-weight:600}
.steps p{font-size:.8125rem;color:var(--muted);margin:var(--s2) 0 0}
.example{display:flex;align-items:center;justify-content:space-between;padding:var(--s12) 0;text-decoration:none;border-bottom:1px solid var(--rule-row);color:var(--text)}
.example:last-child{border:0;padding-bottom:0}
.example small{display:block;color:var(--muted);font-size:.8125rem;margin-top:var(--s2)}
.example .arrow{color:var(--action);margin-left:var(--s8)}
.rows{display:grid;gap:var(--s8)}
.hit{display:block;border:1px solid var(--rule);border-radius:var(--r-card);background:var(--surface);padding:var(--s12) var(--s16);text-decoration:none;color:var(--text)}
.hit:hover{border-color:var(--action);background:var(--raised);color:var(--text)}
.hit .w{display:block;font-family:var(--font-mono);font-size:.8125rem;line-height:1.6;color:var(--muted);margin-top:var(--s4)}
.form-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:var(--s12)}
.form-grid input,.candidate-grid input,.lookup-grid input,.order-field input{max-width:none}
.form-grid>div:last-child{grid-column:1/-1}
.candidate-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:var(--s12)}
.order-field{margin-bottom:var(--s16);max-width:100%}
.form-panel{background:var(--surface);border:1px solid var(--rule);padding:var(--s20);border-radius:var(--r-card)}
.form-panel>p:first-child{margin-top:0}
.form-panel .helper{max-width:none}
.form-divider{font-size:.8125rem;color:var(--muted);margin:var(--s16) 0}
.site-context{margin-top:var(--s20)}
.site-context h3{margin-bottom:var(--s12)}
.site-context .form-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:var(--s16)}
.site-context .form-grid>div:last-child{grid-column:auto}
.site-context label{min-height:2.8em}
.form-options{padding:var(--s12) 0;border-width:1px 0 0;border-radius:0;background:transparent;margin:var(--s16) 0}
.form-options .helper{margin-bottom:var(--s12)}
.form-options .candidate-grid,.form-options .form-grid{margin-top:var(--s12)}
.form-options summary{font-weight:600}
.lookup-form{max-width:58rem}
.lookup-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:var(--s16)}
.lookup-edit{margin:var(--s16) 0}
.lookup-edit form{margin-bottom:0}
.supplier-questions{max-width:75ch;padding-left:var(--s24);list-style:decimal}
.supplier-questions>li{padding:var(--s12) 0;border-bottom:1px solid var(--rule-row)}
.supplier-questions>li>p{margin:0 0 var(--s8);line-height:1.6}
.supplier-questions details{background:transparent;border:0;padding:0;margin:var(--s8) 0}
.supplier-questions details p,.supplier-questions details li{color:var(--text-2)}
.assumption-summary{max-width:75ch;line-height:1.6;margin:var(--s16) 0;color:var(--text-2)}
.assumption-summary b{color:var(--text)}
.assessment-edit,.assessment-downloads{margin:var(--s12) 0}
.assessment-edit .form-panel{border:0;padding:0}
.edit-effects{color:var(--text-2)}
.block .coverage{border:0;border-block:1px solid var(--rule);border-radius:0;background:transparent}
fieldset{border:1px solid var(--rule);border-radius:var(--r-card);padding:var(--s16);margin:0 0 var(--s12);min-width:0}
legend{font-family:var(--font-mono);font-size:.8125rem;color:var(--text-2);padding:0 var(--s8)}
.actions{display:flex;gap:var(--s8);flex-wrap:wrap;align-items:center;margin:var(--s16) 0}
.actions .button{margin:0}
details{border:1px solid var(--rule);border-radius:var(--r-card);padding:var(--s12) var(--s16);background:var(--surface);margin:var(--s16) 0}
summary{cursor:pointer;color:var(--text-2);min-height:36px;padding:var(--s8) 0;line-height:1.5}
summary:hover{color:var(--text)}
details[open]>summary{margin-bottom:var(--s12)}
.evidence-details,.assessment-more-info{background:transparent}
.block{padding-left:var(--s16)}
.block h2{font-size:1.25rem;overflow-wrap:anywhere}
.verdict{border-radius:var(--r-card);background:var(--surface)}
.gate,.caution,.note,.stability{border-radius:var(--r-lg)}
.bar{border:0;border-radius:var(--r-md)}
.bar i{border-radius:var(--r-md)}
table{border-radius:var(--r-card);background:var(--surface)}
.tw{border-radius:var(--r-card)}
th,td{padding:var(--s8) var(--s12);font-size:.8125rem;border-color:var(--rule-row)}
th{font-family:var(--font-mono);font-size:.75rem;font-weight:500;letter-spacing:.06em;color:var(--muted);background:var(--bar)}
caption{text-align:left;padding:var(--s8) var(--s12);color:var(--text-2);font-size:.8125rem}
th.n,td.n{text-align:right;font-family:var(--font-mono);font-variant-numeric:tabular-nums;white-space:nowrap}
.tnote{font-size:.8125rem;color:var(--muted)}
.meta{font-size:.75rem}
.src,.sources{overflow-wrap:anywhere}
pre{font-size:.8125rem;line-height:1.5;overflow-wrap:anywhere;padding:var(--s16);background:var(--bar);border:1px solid var(--rule);border-radius:var(--r-lg)}
.reading-summary{max-width:75ch;margin:var(--s20) 0}
.reading-summary p{line-height:1.6}
.subject{overflow-wrap:anywhere;margin-top:var(--s24)}
.reading-facts{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:var(--s16) var(--s24);margin:var(--s20) 0;padding:var(--s16) 0;border-block:1px solid var(--rule)}
.reading-facts dt{font-size:.8125rem;color:var(--muted)}
.reading-facts dd{margin:var(--s4) 0 0;font-size:1.125rem;font-weight:600;overflow-wrap:anywhere}
.priority-list dt,.term-list dt{font-weight:600;margin-top:var(--s16)}
.priority-list dd,.term-list dd{margin:var(--s4) 0 var(--s12);max-width:75ch;color:var(--text-2);line-height:1.6}
.score-scope{line-height:1.6}
.result-help{max-width:75ch;line-height:1.6}
.demo-cards{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:var(--s16)}
.demo-cards .panel{margin:0}
.demo-cards .step-number{margin-bottom:var(--s12);width:32px}
.demo-cards p{color:var(--text-2)}
@media(max-width:1099px){.split{grid-template-columns:1fr}.form-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.form-grid>div:last-child{grid-column:1/-1}}
@media(max-width:639px){
.helper a,footer a,.empty a,.tnote a{display:inline-block;min-height:24px;line-height:24px}
.metrics{gap:var(--s8)}
.metric{padding:var(--s12) var(--s8)}
.metric strong{font-size:1.25rem}
.metric small{display:none}
.panel{padding:var(--s16)}
.search-line{flex-direction:column}
.search-line button{width:100%}
.form-grid,.candidate-grid,.lookup-grid,.site-context .form-grid,.reading-facts,.demo-cards{grid-template-columns:1fr}
.site-context label{min-height:0}
.form-panel{padding:var(--s12)}
.lookup-form button{width:100%}
.block{padding-left:var(--s8)}
.panel-heading{flex-wrap:wrap;gap:var(--s2)}
main h1{font-size:1.375rem}
}
"""

# One stylesheet, one order (Redesign-plan A2): later layers win ties, and
# report.RESULT_CSS's legacy rules must come before the shell that overrides them.
STYLESHEET = (design.theme_css(design.DARK, ":root") + assets.font_face_css(served=True)
              + design.BASE_CSS + components.CSS + evidenceview.CSS + report.RESULT_CSS
              + SHELL_CSS + PAGE_CSS + design.PRINT_CSS)

# Kept so callers that took the old name still get the page-level rules.
CSS = SHELL_CSS + PAGE_CSS
