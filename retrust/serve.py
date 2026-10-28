"""A local web interface, for the people who actually sign purchase orders.

The terminal suits an engineer and a pipeline. It does not suit the person in
procurement who has a shortlist to settle and no reason to learn a shell, and
that person is the one the tool exists for. This serves the same assessments as
pages, in the same control-room language as the printed report.

It is deliberately small and deliberately local. One standard-library HTTP
server, bound to the loopback address unless somebody insists otherwise, GET
requests only, without sessions. A bounded memory cache shares public alternatives
and history pages; assessments are never cached. Nothing is written to disk and
nothing is executed: every request turns into the same function call the command
line would have made, and the result is rendered with report.py.

The security posture is the point rather than an afterthought, because a tool
that screens sanctions lists has no business opening an unauthenticated port on
a plant network by accident. See SAFETY below for what is enforced.
"""

import html
import http.server
import json
from pathlib import Path
import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import urllib.parse
from datetime import date

from . import alternatives, batch, lev, questions, report, score, search, sensitivity, ssvc, timeline, webviews
from . import webui, supplychain, identity, webcache, assets
from .webui import page as _page
from . import index as index_module
from .index import normalize_name
from .match import _vendor_key

# Bound to loopback by default. Serving to anything else is opt-in, announced,
# and still read-only -- but it is the user's decision, not a default.
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765

# Caps on what one request may ask for, so a hand-written URL cannot turn into a
# scoring run over the whole corpus.
# The editable-inputs panel is named in prose as well as on the control, and a
# notice that quotes a label the page does not carry sends the reader looking
# for something that is not there. One constant, so they cannot drift.
EDIT_PANEL = "Inputs: product, firmware and network exposure"


from .identity import build_fingerprint


BUILD = build_fingerprint()
CONTEXT_FIELDS = ('network_exposure', 'assessment_type', 'consequence', 'interface',
                  'prerequisites', 'remediation')
COMPARISON_FIELDS = batch.QUERY_FIELDS + CONTEXT_FIELDS

MAX_CANDIDATES = 12
MAX_QUERY = 200
MAX_RESULTS = 25

SAFETY = """\
GET only; no request body is ever read.
No path is used as a filename, so no file outside the index can be reached.
Nothing is written and no subprocess is run.
Every value reaching a page goes through html.escape.
Bound to 127.0.0.1 unless --host says otherwise, and that is printed when it is.
On a loopback bind, the Host header must name this machine to prevent
  DNS-rebinding pages from reading the local index.
No page or download is cached (Cache-Control: no-store) and none may be framed.
Only the bundled font files are cacheable, found by exact name and never by path.
A connection that stalls is dropped after 10 seconds and releases its worker.
Request workers own independent read-only advisory and screening connections.
Active and queued work is bounded; excess requests receive 503 with a retry hint.
"""

# The names a loopback-bound server may be addressed by. Anything else in the
# Host header is a browser that resolved somebody else's domain to this
# machine -- the DNS-rebinding trick -- and it is refused.
LOOPBACK_NAMES = {"127.0.0.1", "localhost", "::1"}


def _esc(text):
    return html.escape(str(text or ""), quote=True)


def _search_hits(connection, query):
    """Prefer complete matches and actually search the order-number index."""
    numbers = search.order_numbers(connection, query, limit=MAX_RESULTS)
    products = search.products(connection, query, limit=MAX_RESULTS)
    # Buyers often type the manufacturer and model in the same box. Vendor
    # identity has its own normalization; it need not occur in the model name.
    words = query.split()
    for end in range(min(4, len(words) - 1), 0, -1):
        vendor_key = _vendor_key(connection, ' '.join(words[:end]))
        if vendor_key:
            products = search.products(connection, ' '.join(words[end:]),
                                       vendor=vendor_key, limit=MAX_RESULTS)
            break
    found = numbers + products
    strong = [hit for hit in found if hit.method in ('exact', 'prefix', 'tokens')]
    # Partial token matches are a fallback, not filler beside an exact result.
    found = strong or found
    unique = {}
    for hit in found:
        unique.setdefault((hit.vendor, hit.name), hit)
    return list(unique.values())[:MAX_RESULTS]


from . import components  # noqa: E402  (kept here so the import block stays untouched)


SAMPLE_QUERIES = ('S7-1500', '6ES7518-4AX00-1AB0', 'Moxa EDS-405A')


def _secondary_head(title, lead, route=None):
    """h1, lead and (when a route is given) the links to the other lookups."""
    return (f'<h1>{_esc(title)}</h1><p class="lead">{_esc(lead)}</p>'
            + (webui.related_links(route) if route else ''))


def _search_page(connection, stats, query):
    """A starting point for a buyer, backed by the actual local index."""
    form = (
        '<form class="search-form rt-searchbox" method="get" action="/"><div class="search-line">'
        + components.text_field(
            'q', 'Product, vendor or order number', query, input_id='q', mono=True,
            help_text='Use the name on your requisition. An order number gives the most precise match.',
            attrs={'maxlength': MAX_QUERY, 'required': True, 'autocomplete': 'off',
                   'placeholder': 'e.g. 6ES7518-4AX00-1AB0'})
        + components.button('Search', 'primary', type='submit')
        + '</div></form>')
    # Links, not fill-the-field buttons: without scripts a sample has to run the search.
    chips = ('<div class="chips"><span>Try</span>' + ''.join(
        f'<a class="chip" href="/?q={urllib.parse.quote(q)}">{_esc(q)}</a>'
        for q in SAMPLE_QUERIES) + '</div>')
    counts = (f'<p class="rt-counts">{stats["products"]:,} product entries · '
              f'{stats["vendors"]:,} vendor spellings · {stats["advisories"]:,} advisories · '
              f'{stats["cves"]:,} distinct vulnerabilities</p>')
    heading = ('<h1>Search products</h1><p class="lead">Find a product by manufacturer order number, '
               'product name or vendor, then open its assessment.</p>')
    if not query:
        examples = (
            '<p class="helper">Examples: '
            '<a href="/score?vendor=Siemens&amp;product=SIMATIC%20IPC477E%20Pro">Siemens SIMATIC IPC477E Pro</a> · '
            '<a href="/score?vendor=Siemens&amp;product=SIMATIC%20S7-1500&amp;version=3.1.6">Siemens SIMATIC S7-1500, firmware 3.1.6</a> · '
            '<a href="/demo">Guided demo</a>. Results depend on the loaded public evidence.</p>')
        return _page("ReTrust", heading + form + chips + counts + examples)

    hits = _search_hits(connection, query)

    def assessment_link(hit):
        fields = dict(vendor=hit.vendor, product=hit.name)
        if any(index_module.normalize_order_number(number) == index_module.normalize_order_number(query)
               for number in hit.order_numbers):
            fields['order_number'] = query
        return '/score?' + urllib.parse.urlencode(fields)

    def order_shown(hit):
        wanted = index_module.normalize_order_number(query)
        for number in hit.order_numbers:
            if index_module.normalize_order_number(number) == wanted:
                return number
        return hit.order_numbers[0] if hit.order_numbers else ''

    meta = '{:,} advisory record(s) · Open assessment →'
    if hits:
        rows = "".join(
            webviews.search_row(assessment_link(h), order_shown(h) or h.name,
                                h.name if order_shown(h) else '', h.vendor,
                                meta.format(h.advisories), query) for h in hits)
        results = ('<div class="section-title"><h2>Results</h2>'
                   f'<span>{len(hits)} product result(s)'
                   + (' · first 25 shown' if len(hits) == MAX_RESULTS else '')
                   + f'</span></div><div class="rows">{rows}</div>')
    else:
        vendors = search.vendors(connection, query, limit=8)
        rows = "".join(
            webviews.search_row('/vendor?name=' + urllib.parse.quote(v.vendor), v.vendor, '', '',
                                f'{v.products:,} product entries · View vendor profile →', query)
            for v in vendors)
        results = (f'<p class="empty">No product matches "{_esc(query)}". '
                   'Try the manufacturer order number.</p>'
                   + (f'<div class="section-title"><h2>Matching vendors</h2></div><div class="rows">{rows}</div>'
                      if rows else '')
                   + '<p class="helper"><a href="/score">Enter product details manually →</a></p>')
    return _page(f"Search: {query}", heading + form + chips + counts + results)


def _demo_page():
    stages = (
        ('Identify the exact hardware', 'Search by the order number from a requisition. '
         'Check the matched model before assessing its firmware.', '/?q=6ES7518-4AX00-1AB0', 'Find a Siemens controller'),
        ('Explain a verdict', 'See why the product received its recommendation. '
         'Review the four parts of the score, missing information and assumptions about your network.', '/score?vendor=Siemens&product=SIMATIC%20IPC477E%20Pro',
         'Assess Siemens SIMATIC IPC477E Pro'),
        ('Compare a shortlist', 'Review three examples together. These are different equipment classes '
         'to demonstrate the workflow, not interchangeable engineering alternatives.',
         '/compare?c=ABB%7CAC%20800M&c=Moxa%7CEDS-405A&c=Siemens%7CSIMATIC%20S7-1500%7C3.1.6', 'Open example comparison'),
        ('Ask better supplier questions', 'Prepare security questions to copy into your quotation request. '
         'Ask the supplier for written answers and evidence.', '/annex?vendor=Moxa&product=EDS-405A', 'Prepare supplier questions'),
    )
    # All four steps are equals, so none is primary: the demo has no single next action.
    cards = ''.join(
        components.card(f'<h2>{_esc(title)}</h2><p>{_esc(description)}</p>'
                        f'<div class="actions">{components.link_button(action, url, "secondary")}</div>',
                        label=f'Step {i}')
        for i, (title, description, url, action) in enumerate(stages, 1))
    return _page('Demo', _secondary_head(
        'Guided demo', 'A four-step walkthrough of one purchase decision. Every example uses this '
        'workspace’s public evidence, so results change with the data.', '/demo')
        + '<div class="demo-cards">' + cards + '</div>'
        '<p class="helper">A verdict is decision support. Product fit, plant context, '
        'and the supplier’s answer still belong in the purchasing decision.</p>', active='/demo')


# What each owner-supplied fact means when nobody answered it. Only answers
# that differ from these are forwarded, so a caller that never asks about plant
# context keeps the simpler call it always had.
UNDECLARED = {"consequence": None, "interface": "unknown",
              "assessment_type": "purchase", "remediation": "unknown",
              "prerequisites": "unknown"}


def _run_assessment(assess, vendor, product, version=None, order_number=None,
                    network_exposure=None, owner=None):
    options = {key: value for key, value in (owner or {}).items()
               if key in UNDECLARED and value != UNDECLARED[key]}
    if network_exposure:
        options["network_exposure"] = network_exposure
    if order_number:
        return assess(vendor, product, version or None, order_number=order_number,
                      **options)
    return assess(vendor, product, version or None, **options)


def _owner_from(params_first):
    """The owner-supplied facts in a request, each validated against its table."""
    def pick(name, table, default):
        value = params_first(name)
        return value if value in table else default
    return dict(
        consequence=pick("consequence", score.CONSEQUENCES, None),
        interface=pick("interface", score.INTERFACES, "unknown"),
        assessment_type=pick("assessment_type", score.ASSESSMENT_TYPES, "purchase"),
        remediation=pick("remediation", score.REMEDIATIONS, "unknown"),
        prerequisites=pick("prerequisites", score.PREREQUISITES, "unknown"),
    )


# The form's labels, one definition for the form and for the panel that reports
# what each answer did, so the two can never name the same field differently.
FIELD_LABELS = {
    'version': 'Firmware version',
    'network_exposure': 'Network exposure',
    'interface': 'Attack reachability (A)',
    'prerequisites': 'Exploitation prerequisites',
    'consequence': 'Credible operational impact (H)',
    'remediation': 'Firmware applicability and remediation (U)',
    'assessment_type': 'Assessment purpose',
}
ANSWER_TABLES = {
    'network_exposure': score.NETWORK_EXPOSURES, 'interface': score.INTERFACES,
    'prerequisites': score.PREREQUISITES, 'consequence': score.CONSEQUENCES,
    'remediation': score.REMEDIATIONS, 'assessment_type': score.ASSESSMENT_TYPES,
}
IDENTITY_FIELDS = ('vendor', 'product', 'order_number')

# The answer that equals what the conservative end of the range already
# assumes. Giving it cannot lower the low end, and the high end only comes
# down once every other open factor is answered too -- which is why a buyer
# could make four edits in a row and see nothing move.
CONSERVATIVE = {'consequence': ('safety',), 'interface': ('exposed',),
                'prerequisites': ('satisfiable',),
                'remediation': ('affected', 'available')}

# Phrases in an assessment's verification list, and the form field that
# closes each. One table, owned by report.py, because the gap cards on the page
# and the "still open" sentence here must name the same fields; this name stays
# as an alias for callers that already import it.
OPEN_QUESTIONS = report.GAP_RULES
DATA_GAPS = tuple(phrase for phrase, _, _ in report.DATA_GAP_RULES)

# Component helpers, reached through report so this module needs no new import
# line (several pages are edited in parallel and import lines conflict).
components = report.components


def _previous_from(params_first):
    """The answers the last page was showing, carried in the edit form."""
    if params_first('was') != '1':
        return None
    network = params_first('was_network_exposure')
    return dict(
        {key: params_first('was_' + key) for key in IDENTITY_FIELDS},
        version=params_first('was_version'),
        network_exposure=network if network in score.NETWORK_EXPOSURES else None,
        **_owner_from(lambda name: params_first('was_' + name)))


def _answer_text(field, value):
    if field == 'version':
        return value or 'not specified'
    entry = ANSWER_TABLES[field].get(value)
    if entry is None:
        return 'Unknown'
    return entry[0] if isinstance(entry, tuple) else entry


def _shown(assessment):
    """The headline a reader compares between two updates."""
    label = report.score_label(assessment, unit='/100', note='', missing='')
    return f'{assessment.verdict} {label}'.strip()


def _assess_state(assess, state):
    owner = {key: state[key] for key in UNDECLARED}
    return _run_assessment(assess, state['vendor'], state['product'], state['version'],
                           state['order_number'], state['network_exposure'], owner)[0]


def _why_unmoved(field, value, state, result):
    """Why one answer, applied on its own, left the headline where it was."""
    if field == 'assessment_type':
        return 'Recorded for traceability only; it never changes the calculation.'
    if field == 'network_exposure':
        return ('Deployment context: recorded with the result but not scored, because a'
                ' network route alone does not establish an attack path. Attack'
                ' reachability (A) is the answer the score uses.')
    if getattr(result, 'cleared_count', 0):
        # Ahead of every per-answer reason: the published ranges, not any
        # answer, already rule out each recorded flaw for this firmware.
        return ('The firmware you gave is outside every published affected range, so'
                ' none of the recorded flaws applies and exposure is already 100/100.'
                ' No answer has anything left to change.')
    if field == 'remediation' and value in ('applied', 'not_affected'):
        if not state['version']:
            return ('A fixed or not-affected claim counts only for a named firmware. Add'
                    ' the firmware version so the claim can be checked against the'
                    ' published affected ranges.')
        return ('The firmware you gave is inside a published affected range, which'
                ' contradicts this answer. See what to check next.')
    if field == 'remediation' and value in ('mitigated', 'planned', 'unknown'):
        return ('Treated as Unknown: an unverified mitigation or a planned fix does not'
                ' settle whether the firmware is affected.')
    # Ahead of the per-answer reasons: with exposure already at 100 there is no
    # range left to narrow, so "the high end comes down later" would be false.
    if result.exposure_min is not None and result.exposure_min >= 100 - 1e-9:
        return ('Exposure is already at its best (100/100): another answer, such as'
                ' verified-blocked reachability, already rules these flaws out, so this'
                ' one has nothing left to change.')
    if value in CONSERVATIVE.get(field, ()):
        return ('Confirms the worst case for this factor, which the low end already'
                ' assumed, so it cannot go lower. The high end comes down once the other'
                ' open answers are given.')
    if field == 'prerequisites' and value == 'unsatisfiable':
        return ('Did not apply: these weaknesses need no extra conditions, or their'
                ' requirements are unknown, so ruling conditions out removes nothing.'
                ' See the assessment notes.')
    # Below FLOOR every exposure enters the composite as FLOOR, so a change down
    # there is real but cannot show.
    if result.exposure_min is not None and result.exposure_min < score.FLOOR:
        return ('Exposure stays at its floor: enough severe flaws remain applicable that'
                ' this answer alone cannot lift it.')
    if any(note.startswith('Capped below PREFER') for note in result.notes):
        return ('Exposure did change, but the score is capped just below PREFER by a'
                ' hardcoded-credential flaw with no vendor fix, and no answer can lift'
                ' that cap. See the assessment notes.')
    return 'Other open answers still set both ends of the range.'


def _still_open(assessment):
    """Form fields still holding a provisional range open, and any data gaps."""
    fields, gaps = [], False
    for item in assessment.verification:
        gaps = gaps or any(phrase in item for phrase in DATA_GAPS)
        for phrase, field in OPEN_QUESTIONS:
            if phrase in item and field not in fields:
                fields.append(field)
    return [f for f in FIELD_LABELS if f in fields], gaps


def _edit_effects(assess, previous, state, current):
    """Say what the last update changed, and why an answer moved nothing.

    The range is an interval over every unanswered factor, so most single
    answers leave the headline exactly where it was until the last open factor
    closes. Without this, an unchanged number reads as a form that ignored the
    edit. Each changed answer is re-scored on its own against the previous
    answers, so the panel reports what that answer did, not what it might do.
    """
    if previous is None or any(previous[k] != state[k] for k in IDENTITY_FIELDS):
        return ''
    changed = [field for field in FIELD_LABELS if previous[field] != state[field]]
    if not changed:
        return ''
    before = _assess_state(assess, previous)
    moved_overall = _shown(before) != _shown(current)
    lead = (f'Result: {_esc(_shown(before))} &rarr; <b>{_esc(_shown(current))}</b>.'
            if moved_overall else
            f'The result is unchanged at <b>{_esc(_shown(current))}</b>.')
    frozen = None
    if not current.resolved:
        frozen = ('The product was not identified, so no answer has anything to act on.'
                  ' Identify it by order number or exact model name.')
    elif current.evidence_free:
        frozen = ('No recorded vulnerability applies to this product, so no answer has'
                  ' anything to act on and the range stays the full range.')
    elif current.score is None:
        frozen = 'A purchase blocker decides this outright, whatever is answered.'
    items = ''
    for field in changed:
        old, new = previous[field], state[field]
        if frozen:
            effect = ''
        else:
            trial = current if len(changed) == 1 else _assess_state(
                assess, dict(previous, **{field: new}))
            if _shown(trial) != _shown(before):
                effect = ('Moved the result.' if len(changed) == 1 else
                          f'On its own, moves the result to {_esc(_shown(trial))}.')
            else:
                effect = 'No visible effect. ' + _why_unmoved(field, new, state, trial)
        items += (f'<li><b>{FIELD_LABELS[field]}</b>: {_esc(_answer_text(field, old))}'
                  f' &rarr; {_esc(_answer_text(field, new))}. {effect}</li>')
    tail = ''
    if current.gates and not frozen:
        # A high number beside AVOID reads as a contradiction unless the page
        # says, where the edit is reported, that the verdict is not the score's.
        # A scored blocker is always a firmware one (screening blockers are
        # never scored), and check_gates honours the firmware answers -- so
        # those two answers can lift it, and saying "no answer can" was false.
        tail += ('<p class="notice">AVOID here comes from a purchase blocker, not from'
                 ' the score: ' + _esc('; '.join(g['detail'] for g in current.gates))
                 + '. Reachability and impact answers move the number but not the'
                 ' blocker. Only a firmware answer can lift it: a firmware version'
                 ' outside the published affected range, or a fix verified installed on'
                 ' a named firmware.</p>')
    if frozen:
        tail = f'<p class="helper">{frozen}</p>'
    elif current.provisional:
        fields, gaps = _still_open(current)
        if fields:
            tail += ('<p class="helper">The range stays open until these are answered: '
                     + ', '.join(FIELD_LABELS[f] for f in fields) + '.'
                     + (' Some checks are data gaps that no answer can close; see what'
                        ' to check next.' if gaps else '') + '</p>')
        elif gaps:
            tail += ('<p class="helper">Only data gaps hold the range open, and no answer'
                     ' can close them; see what to check next.</p>')
    card = components.context_card('Since your last update',
                                   f'<p>{lead}</p><ul>{items}</ul>{tail}')
    # context_card has one fixed tag; this one reports an update, not context.
    card = card.replace('>CONTEXT</p>', '>UPDATE</p>', 1)
    return f'<div class="edit-effects" aria-live="polite">{card}</div>'



# What the evidence table may be asked for in a URL. Anything else is dropped
# silently: the values are presentation only, so a hand-edited one has nothing
# to protest about and nothing of it is ever echoed back.
def _evidence_state(view, base_params):
    from .evidenceview import DIRS, FILTERS, SORTS, EvidenceView
    view = view or {}
    ev = view.get("ev") if view.get("ev") in FILTERS else "all"
    sort = view.get("sort") if view.get("sort") in SORTS else ""
    direction = view.get("dir") if view.get("dir") in DIRS else ""
    return EvidenceView(ev=ev, sort=sort, dir=direction,
                        show_all=view.get("show") == "all",
                        base_params=base_params, anchor="evidence")


def _advisory_titles(connection, assessment, findings, evidence):
    """{advisory id: (title, released)} for the CVEs the table actually shows.

    One parameterised query for the shown rows only, so a product with
    thousands of findings does not pay for titles nobody opens.
    """
    import sqlite3
    from . import evidenceview
    shown = evidenceview.shown(findings, assessment, evidence)
    ids = sorted({f.advisory_id for f in shown if f.advisory_id})
    if not ids:
        return {}
    marks = ",".join("?" * len(ids))
    try:
        rows = connection.execute(
            "SELECT id,title,released FROM advisory WHERE id IN (" + marks + ")",
            ids).fetchall()
    except sqlite3.Error:
        return {}
    return {row[0]: (row[1] or "", row[2] or "") for row in rows}


FIELD_IDS = {
    'order_number': 'field-order-number', 'vendor': 'field-vendor',
    'product': 'field-product', 'version': 'field-version',
    'network_exposure': 'field-network-exposure', 'interface': 'field-interface',
    'prerequisites': 'field-prerequisites', 'consequence': 'field-consequence',
    'remediation': 'field-remediation', 'assessment_type': 'field-assessment-type',
}


def _gap_target(gap, vendor):
    """Where a supplier question's GAP tag leads, or "" when nowhere honest.

    Only fragments that exist on this page, or the vendor page for the two
    pillars (V, C) that have no input here.
    """
    if gap == 'ID':
        return '#' + FIELD_IDS['order_number']
    if gap == 'E':
        return '#exposure'
    if gap == 'P':
        return '#evidence'
    if gap in ('V', 'C') and vendor:
        return '/vendor?name=' + urllib.parse.quote(vendor)
    return ''


def _questions_section(items, vendor, text_query):
    label = components.panel_label(f'QUESTIONS · {len(items)} FOR THE SUPPLIER')
    if not items:
        body = ('<p class="helper">No open questions. Every material input is '
                'verified.</p>')
    else:
        rows = []
        for number, question in enumerate(items, 1):
            evidence = ''.join(f'<li>{_esc(item)}</li>' for item in question.evidence)
            why = (f'<details class="rt-q__why"><summary>Why ask this</summary>'
                   f'<p>{_esc(question.why)}</p>'
                   + (f'<ul>{evidence}</ul>' if evidence else '') + '</details>')
            tag = ''
            if question.gap:
                text = f'GAP · {_esc(question.gap)}'
                target = _gap_target(question.gap, vendor)
                tag = (f'<a class="rt-q__gap" href="{_esc(target)}">{text}</a>' if target
                       else f'<span class="rt-q__gap">{text}</span>')
            rows.append(f'<li class="rt-q"><span class="rt-q__n">{number:02d}</span>'
                        f'<div><p class="rt-q__text">{_esc(question.text)}</p>{why}</div>'
                        f'{tag}</li>')
        body = '<ol class="rt-questions">' + ''.join(rows) + '</ol>'
    foot = ''
    if text_query:
        foot = ('<p class="rt-q__foot">'
                + components.link_button('Export as .txt', '/annex.txt?' + text_query)
                + '</p>')
    return components.card(label + body + foot, id='questions')


def _inputs_section(form):
    return ('<section class="rt-card rt-assess-section" id="inputs" '
            'aria-labelledby="inputs-title">'
            f'<h2 id="inputs-title">{_esc(EDIT_PANEL)}</h2>' + form + '</section>')


def _export_menu(parameters, resolved):
    return components.menu('Export evidence', (
        ('HTML report', f'/export.html?{parameters}', '.html', ''),
        ('JSON', f'/export.json?{parameters}', '.json', ''),
        ('CSV', f'/export.csv?{parameters}', '.csv', ''),
        ('VEX', f'/export.vex.json?{parameters}', 'CycloneDX',
         '' if resolved else 'Needs an identified product.'),
    ), 'export-menu', kind='primary')


def _score_page(connection, assess, context, vendor, product, version, order_number="",
                submitted=False, network_exposure=None, owner=None, previous=None,
                view=None, dossier=None):
    """A verdict first, with editable inputs and the evidence below it."""
    if network_exposure not in score.NETWORK_EXPOSURES:
        network_exposure = None
    owner = owner or {}
    recognised = None
    # A full title copied from Explore is a product identifier, not a part
    # number. Recognise an exact title or an explicitly named vendor/model;
    # suggestions never become matches. Never override conflicting fields.
    if order_number and not (vendor or product):
        recognised = search.product_query(connection, order_number)
        if recognised:
            vendor, product, order_number = recognised.vendor, recognised.name, ""
    # Everything the page was assessed with, defaults filled in, so the next
    # update can be compared against exactly this.
    state = dict(vendor=vendor, product=product, order_number=order_number,
                 version=version, network_exposure=network_exposure,
                 **{key: owner.get(key, default) for key, default in UNDECLARED.items()})
    answers = (network_exposure, owner.get("consequence"), owner.get("interface", "unknown"),
               owner.get("assessment_type", "purchase"), owner.get("remediation", "unknown"))
    asked = bool(vendor or product or order_number)
    if not asked:
        form = _score_form(vendor, product, version, order_number, *answers,
                           prerequisites=owner.get("prerequisites", "unknown"))
        notice = components.alert(
            'error', 'Nothing to assess yet',
            'Enter a manufacturer order number, or a vendor and product, '
            'before assessing.') if submitted else ''
        return _page('Score', _empty_assess(form, notice))
    assessment, resolution, findings = _run_assessment(
        assess, vendor, product, version, order_number, network_exposure, owner)
    parameters = urllib.parse.urlencode(dict(
        vendor=vendor, product=product, version=version,
        order_number=order_number, network_exposure=network_exposure or "",
        **{key: value or "" for key, value in owner.items()}))
    # The answers, minus anything empty, are what every generated link carries
    # forward. was_* never belongs here: it would re-submit the previous page.
    base = {key: value for key, value in urllib.parse.parse_qsl(parameters) if value}
    evidence = _evidence_state(view, base)
    # A version that was submitted counts as confirmed unless its ranges could
    # not be decided (Redesign-plan.md item 24).
    undecided = any(not f.decided for f in findings)
    firmware_state = 'unverified' if (not version or undecided) else 'verified'
    form = _score_form(vendor, product, version, order_number, *answers,
                       prerequisites=owner.get("prerequisites", "unknown"),
                       update=True, carried=state, firmware_state=firmware_state)

    named = resolution.matches[0] if resolution.resolved else None
    query = candidate_query = text_query = ''
    if named:
        query = urllib.parse.urlencode(dict(vendor=named.vendor, product=named.name, version=version))
        text_query = query
        candidate_fields = dict(
            vendor_0=vendor or ('' if order_number else named.vendor),
            product_0=product or ('' if order_number else named.name),
            version_0=version or '', order_number_0=order_number or '',
            network_exposure_0=network_exposure or '')
        candidate_fields.update({f'{key}_0': owner.get(key) or default or ''
                                 for key, default in UNDECLARED.items()})
        candidate_query = urllib.parse.urlencode(candidate_fields)

    # Add to comparison must stay the first /compare? link on the page.
    actions = []
    if named:
        actions.append(components.link_button('Supplier questions', f'/annex?{query}'))
        actions.append(components.link_button('Add to comparison', f'/compare?{candidate_query}'))
    actions.append(_export_menu(parameters, resolution.resolved))

    profile = None
    if dossier is not None and resolution.matches:
        profile = dossier.build(connection, resolution.matches[0].vendor,
                                screening=context.get('screening', {}),
                                certificates=context.get('certificates', {}))
    items = questions.build(assessment, findings, profile)

    sections = (('overview', 'Overview'), ('exposure', 'Exposure'),
                ('evidence', 'Evidence'), ('questions', 'Questions'),
                ('inputs', 'Inputs'))
    web = report.WebView(
        actions_html='<div class="rt-assess-actions">' + ''.join(actions) + '</div>',
        tabs_html=components.tabs(sections, current='overview', label='Sections of this assessment'),
        inputs_html=_inputs_section(form),
        questions_html=_questions_section(items, named.vendor if named else '', text_query),
        evidence=evidence,
        advisories=_advisory_titles(connection, assessment, findings, evidence),
        checks={'kev_loaded': any(p['source'] == 'CISA KEV'
                                  for p in index_module.provenance(connection)),
                'screening_loaded': bool(len(context.get('screening') or ()))},
        order_number=order_number, version=version, field_ids=dict(FIELD_IDS))

    body = '<h1>Product assessment</h1>'
    if recognised:
        body += ('<p class="notice">Product name recognised. Assessing '
                 + _esc(recognised.vendor) + ' / ' + _esc(recognised.name) + '.</p>')
    body += _edit_effects(assess, previous, state, assessment)
    tools = ''
    if not version and resolution.resolved:
        tools += ('<p class="notice"><b>Firmware not specified.</b> All known affected versions '
                  'are in scope. Add the firmware you plan to buy under '
                  f'“{_esc(EDIT_PANEL)}” below.</p>')
    if named:
        tools += _next_steps(named, query, version)
    body += report.body([(assessment, resolution, findings)], weights=context['weights'],
                        tools=tools, web=web, bands=context.get('bands'))
    if not resolution.resolved:
        body += _recovery(connection, vendor, product, version, order_number,
                          network_exposure, owner)
    return _page(f'Score: {assessment.product}', body)


def _empty_assess(form, notice):
    samples = (('S7-1500', urllib.parse.urlencode(dict(vendor='Siemens', product='SIMATIC S7-1500'))),
               ('6ES7518-4AX00-1AB0', urllib.parse.urlencode(dict(order_number='6ES7518-4AX00-1AB0'))))
    chips = ('<p class="rt-sample"><span>Try</span>'
             + ''.join(f'<a class="chip" href="/score?{_esc(q)}">{_esc(t)}</a>'
                       for t, q in samples) + '</p>')
    return ('<h1>Assess a product</h1>'
            + webui.related_links('/score') + notice
            + '<div class="rt-assess-empty">'
            + components.empty_state(
                'Check the equipment before you buy it',
                'Start with its order number or model. Leave technical details '
                'unknown if you are unsure; the result will say what still needs checking.',
                form + chips)
            + '</div>')


def _next_steps(named, query, version):
    """Product-specific onward links, the contextual pages with this product filled in."""
    links = (f'<li><a href="/alternatives?{_esc(query)}">Find alternatives</a></li>'
             f'<li><a href="/vendor?name={urllib.parse.quote(named.vendor)}">Vendor profile</a></li>'
             f'<li><a href="/timeline?{_esc(query)}">Advisory timeline</a></li>'
             f'<li><a href="/lev?{_esc(query)}">Check past exploitation estimates</a></li>'
             f'<li><a href="/ssvc?{_esc(query)}">Plan response priorities</a></li>')
    return ('<div class="rt-assess-next rt-assess-section">'
            + components.context_card(
                'Take the next step',
                f'<ul class="rt-related" aria-label="This product">{links}</ul>')
            + '</div>')


def _recovery(connection, vendor, product, version, order_number, network_exposure, owner):
    """Recovery for every way a lookup can fail, not just a bad model name.

    An order number is matched exactly, so one that found nothing used to end
    here with no suggestions at all -- and a product name pasted into that box
    is the commonest way to get here.
    """
    body = ''
    suggestions = search.suggest(connection, vendor=vendor, product=product,
                                 order_number=order_number)
    if suggestions['mistyped_order_number']:
        # Only invite a choice when there is something to choose. A name the
        # corpus does not know reaches here too, and "choose one below"
        # followed by "nothing close was found" contradicts itself.
        body += ('<p class="notice" role="alert">That product name could not '
                 'be identified. '
                 + ('Choose a matching product below, or refine it'
                    if suggestions['products'] else 'Refine it')
                 + ' under &ldquo;Use vendor and model instead&rdquo;.</p>')
    elif order_number and not (vendor or product):
        body += ('<p class="notice" role="alert">No advisory in this corpus '
                 'names that order number. Check the digits, or search by '
                 'vendor and model instead.</p>')

    def recovery_link(hit):
        # Correct only the failed identity. Keep the owner's firmware and
        # network answers so choosing a suggestion cannot reset the risk.
        query = urllib.parse.urlencode(dict(
            vendor=hit.vendor, product=hit.name, version=version or '',
            network_exposure=network_exposure or '',
            **{key: value or '' for key, value in owner.items()}))
        return (f'<a class="hit" href="/score?{_esc(query)}">'
                f'{_esc(hit.vendor)} / {_esc(hit.name)}</a>')
    rows = ''.join(recovery_link(h) for h in suggestions['products'][:8])
    if rows:
        body += f'<h2>Did you mean</h2><div class="rows">{rows}</div>'
    # A misspelled manufacturer never had a route back either.
    vendor_rows = ''.join(
        f'<a class="hit" href="/?q={urllib.parse.quote(h.vendor)}">'
        f'{_esc(h.vendor)} <span class="meta">{h.products:,} product entries</span></a>'
        for h in suggestions['vendors'][:5])
    if vendor_rows:
        body += (f'<h2>Did you mean this manufacturer?</h2>'
                 f'<div class="rows">{vendor_rows}</div>')
    if not rows and not vendor_rows:
        body += ('<p class="helper">Nothing close was found. Try a shorter '
                 'model name, the manufacturer on its own, or '
                 '<a href="/">search the corpus</a>.</p>')
    return body


def _field(id_, name, label, value='', placeholder='', required=False):
    return (f'<div><label for="{id_}">{label}</label><input type="text" id="{id_}" '
            f'name="{name}" value="{_esc(value)}" placeholder="{_esc(placeholder)}" '
            f'maxlength="{MAX_QUERY}"' + (' required' if required else '') + '></div>')


def _lookup_form(route, action, vendor, product, version=None, product_optional=False, extra=''):
    """A consistent entry point for the evidence pages. Its submit is the page's one primary."""
    def text(name, label, value, placeholder, input_id, required=False, mono=False):
        attrs = {'maxlength': MAX_QUERY, 'placeholder': placeholder}
        if required:
            attrs['required'] = True
        return components.text_field(name, label, value, input_id=input_id, mono=mono, attrs=attrs)

    fields = (text('vendor', 'Manufacturer (vendor)', vendor, 'e.g. ABB', 'v', required=True)
              + text('product', 'Product / model' + (' (optional)' if product_optional else ''),
                     product, 'e.g. SIMATIC IPC477E Pro', 'p', required=not product_optional, mono=True))
    if version is not None:
        fields += text('version', 'Firmware version (optional)', version, 'e.g. 3.1.6', 'f', mono=True)
    helper = ('Leave the product blank to see the manufacturer’s full history.' if product_optional else
              'Use the model on the quotation or equipment label. Firmware is the software running on the equipment; leave its version blank if unknown.'
              if version is not None else 'Use the model on the quotation or equipment label.')
    return (f'<form class="lookup-form" method="get" action="{_esc(route)}">'
            f'<div class="lookup-grid">{fields}</div><p class="helper">{helper} '
            '<a href="/">Find the exact product with search</a>.</p>' + extra
            + components.button(action, 'primary', type='submit') + '</form>')


def _lookup_controls(form, populated, label='Change product'):
    return (f'<details class="lookup-edit"><summary>{label}</summary>{form}</details>'
            if populated else form)


def _lookup_example(route, vendor='Siemens', product='SIMATIC IPC477E Pro'):
    query = urllib.parse.urlencode(dict(vendor=vendor, product=product))
    return (f'<p class="helper">Try an example: <a href="{route}?{_esc(query)}">'
            f'{_esc(vendor)} · {_esc(product)}</a>. Examples use the loaded public evidence.</p>')


def _lookup_error():
    return components.alert(
        'error', 'Enter both the manufacturer and product/model',
        body_html='<p class="rt-alert__text">If you are unsure, '
                  '<a href="/">find the product in Explore</a> first.</p>')


def _product_next_steps(vendor, product, version=''):
    query = urllib.parse.urlencode(dict(vendor=vendor, product=product, version=version))
    return ('<div class="actions">'
            + components.link_button('Assess this product', f'/score?{query}', 'secondary')
            + components.link_button('Prepare supplier questions', f'/annex?{query}', 'secondary')
            + '</div>')


def _choice(name, label, table, chosen, blank=None, helper='', input_id=''):
    """One labelled dropdown over an exposure table.

    Options and their wording come from the table that scores them, so the form
    can never offer a choice the model does not know, or describe it differently.
    Unknown is always a choice, and is drawn VERIFY-style while selected: an
    unanswered fact is a gap, not a neutral default.
    """
    import re
    options = [('', blank)] if blank else []
    options +=[(key, entry[0] if isinstance(entry, tuple) else entry)
                for key, entry in table.items()]
    markup = components.select_field(
        name, label, options, selected=chosen or '',
        unknown_value='unknown' if 'unknown' in table else '',
        input_id=input_id or name, help_text=helper)
    if blank:
        # The blank option is the Unknown choice, but select_field can only mark
        # an option with a non-empty value, so it is marked here.
        markup = re.sub(r'<option value=""( selected)?>',
                        lambda found: '<option value="" class="rt-option--unknown"'
                        + (found.group(1) or '') + '>? ', markup, count=1)
        if not chosen:
            markup = markup.replace('rt-field rt-field--select"',
                                    'rt-field rt-field--select rt-field--unknown"', 1)
    return markup


def _owner_fields(network_exposure=None, consequence=None, interface='unknown',
                  assessment_type='purchase', remediation='unknown', suffix='',
                  prerequisites='unknown', ids=False):
    """The facts only the asset owner has, each optional and each explained.

    ReTrust supplies the vulnerability intelligence; these describe the plant.
    Nothing here is verified, so every one is labelled operator-reported, and
    leaving one unanswered keeps it unresolved rather than guessing either way.
    `ids` gives each control the stable id the result page's gap cards link to;
    the compare page keeps name-plus-suffix ids so several rows stay unique.
    """
    def field(name):
        return FIELD_IDS[name] if ids else name + suffix
    return ('<div class="form-grid">'
            + _choice('assessment_type' + suffix, FIELD_LABELS['assessment_type'],
                      score.ASSESSMENT_TYPES, assessment_type,
                      helper='Recorded for traceability; does not change the calculation.',
                      input_id=field('assessment_type'))
            + _choice('network_exposure' + suffix, FIELD_LABELS['network_exposure'],
                      score.NETWORK_EXPOSURES, network_exposure, blank='Unknown',
                      helper='Deployment context; selection alone does not change the score. Internet isolation alone does not establish a blocked attack path. Reachability below determines A.',
                      input_id=field('network_exposure'))
            + _choice('interface' + suffix, FIELD_LABELS['interface'],
                      score.INTERFACES, interface,
                      helper='Can a credible attacker reach the vulnerable interface? Select verified blocked only when all relevant network, local and physical paths have been assessed.',
                      input_id=field('interface'))
            + _choice('prerequisites' + suffix, FIELD_LABELS['prerequisites'],
                      score.PREREQUISITES, prerequisites,
                      helper='Confirm whether required privileges, user interaction, local or physical access, and other attack conditions can be satisfied.',
                      input_id=field('prerequisites'))
            + _choice('consequence' + suffix, FIELD_LABELS['consequence'],
                      score.CONSEQUENCES, consequence, blank='Unknown',
                      helper='Highest credible consequence of exploiting the assessed vulnerabilities. H: safety 1.0; process control 0.8; recoverable disruption 0.5; minor disruption 0.2; no material impact 0.',
                      input_id=field('consequence'))
            + _choice('remediation' + suffix, FIELD_LABELS['remediation'],
                      score.REMEDIATIONS, remediation,
                      helper='Status of the selected firmware across the listed vulnerabilities. Fix availability alone does not establish that a fix is installed. Fix verified installed and Verified not affected count only when the firmware version is given.',
                      input_id=field('remediation'))
            + '</div>')


def _conditions_summary(network_exposure, consequence, interface, prerequisites, remediation):
    """What the plant-context answers currently say, with gaps drawn as gaps."""
    def shown(field, value):
        if value in (None, '', 'unknown'):
            return 'Unknown'
        return _answer_text(field, value)
    return components.conditions_row((
        ('Network', shown('network_exposure', network_exposure)),
        ('Reachability', shown('interface', interface)),
        ('Prerequisites', shown('prerequisites', prerequisites)),
        ('Impact', shown('consequence', consequence)),
        ('Fix status', shown('remediation', remediation))))


def _score_form(vendor, product, version, order_number='', network_exposure=None,
                consequence=None, interface='unknown',
                assessment_type='purchase', remediation='unknown',
                prerequisites='unknown', update=False, carried=None,
                firmware_state=None):
    using_model = ' open' if (vendor or product) and not order_number else ''
    # The answers this page was assessed with ride along unseen, so the update
    # can report what changed without the server keeping any session.
    hidden = '' if not carried else (
        '<input type="hidden" name="was" value="1">'
        + ''.join(f'<input type="hidden" name="was_{key}" value="{_esc(value or "")}">'
                  for key, value in carried.items()))
    # Firmware is a material input: it is drawn as unverified until the page
    # has something to confirm it against (Redesign-plan.md item 24).
    if firmware_state is None:
        firmware_state = '' if version else 'unverified'
    firmware_help = ('Firmware is the software running on the equipment. Leave blank if '
                     'unknown; without it the result stays VERIFY with a range.'
                     if firmware_state == 'unverified' and not version else
                     'Some affected ranges could not be checked against this version.'
                     if firmware_state == 'unverified' else
                     'Checked against the published affected ranges.')
    button = components.button('Update assessment' if update else 'Assess product',
                               kind='secondary' if update else 'primary', type='submit')
    return ('<form class="form-panel" method="get" action="/score">' + hidden
            + '<div class="order-field">'
            + components.text_field(
                'order_number', 'Manufacturer order number or full product name', order_number,
                help_text='Printed on the label or the quotation.', mono=True,
                input_id=FIELD_IDS['order_number'],
                attrs={'placeholder': 'e.g. 6ES7518-4AX00-1AB0', 'maxlength': MAX_QUERY,
                       'autocomplete': 'off', 'spellcheck': 'false'})
            + '</div>'
            f'<details class="form-options"{using_model}><summary>Use vendor and model instead</summary>'
            '<p class="helper">Use these if you do not have an order number. If both are entered, they must agree.</p>'
            '<div class="candidate-grid">'
            + components.text_field('vendor', 'Vendor', vendor, input_id=FIELD_IDS['vendor'],
                                    attrs={'placeholder': 'e.g. Siemens', 'maxlength': MAX_QUERY})
            + components.text_field('product', 'Product / model', product,
                                    input_id=FIELD_IDS['product'],
                                    attrs={'placeholder': 'e.g. SIMATIC S7-1500',
                                           'maxlength': MAX_QUERY})
            + '</div></details>'
            + components.text_field('version', 'Firmware version (optional)', version,
                                    state=firmware_state, help_text=firmware_help, mono=True,
                                    input_id=FIELD_IDS['version'],
                                    attrs={'placeholder': 'e.g. 3.1.6', 'maxlength': MAX_QUERY})
            + '<fieldset class="rt-conditions-card">'
            '<legend>Network access and operating conditions</legend>'
            + _conditions_summary(network_exposure, consequence, interface,
                                  prerequisites, remediation)
            + '<p class="helper">These answers are central to the assessment. '
            'Use Unknown for unverified inputs. ReTrust uses operator-reported evidence; it does not inspect the network.</p>'
            + _owner_fields(network_exposure, consequence, interface,
                            assessment_type, remediation,
                            prerequisites=prerequisites, ids=True)
            + '</fieldset>'
            + ('<p class="helper">Select Update assessment to recalculate after changing any input.</p>' if update else '')
            + button + '</form>')


def _candidate_rows(params):
    """Accept structured form fields and retain existing shareable ?c= links."""
    if any(key.startswith(tuple(f'{field}_' for field in COMPARISON_FIELDS)) for key in params):
        rows = []
        for i in range(MAX_CANDIDATES):
            parts = [(params.get(f'{field}_{i}') or [''])[0][:MAX_QUERY].strip()
                     for field in COMPARISON_FIELDS]
            if any(parts[:4]):
                rows.append(parts)
        return rows
    return [[p[:MAX_QUERY].strip() for p in value[:MAX_QUERY * 4 + 3].split('|', 3)]
            for value in params.get('c', [])[:MAX_CANDIDATES] if value.strip()]


def _comparison_rows(candidates):
    return [(list(c) + [''] * len(COMPARISON_FIELDS))[:len(COMPARISON_FIELDS)]
            for c in candidates][:MAX_CANDIDATES]


def _candidate_context(row):
    fields = dict(zip(COMPARISON_FIELDS, row))
    network = fields.get('network_exposure')
    network = network if network in score.NETWORK_EXPOSURES else None
    owner = _owner_from(lambda key: fields.get(key))
    return network, owner


def _valid_comparison(rows):
    return bool(rows) and all(row[0] or row[1] or row[3] for row in rows)


def _comparison_parameters(rows):
    return urllib.parse.urlencode({f'{field}_{i}': value
                                   for i, row in enumerate(rows)
                                   for field, value in zip(COMPARISON_FIELDS, row)})


def _comparison_results(assess, context, rows):
    """Keep the exact input and robustness attached to each ranked assessment."""
    entries = []
    for row in rows:
        vendor, product, version, order_number = row[:4]
        network, owner = _candidate_context(row)
        block = _run_assessment(assess, vendor, product, version, order_number, network, owner)
        query = dict(zip(batch.QUERY_FIELDS, (vendor, product, version, order_number)))
        assessment = block[0]
        stability = (sensitivity.stability(*assessment.inputs, samples=300,
                     bands=context.get('bands'), network_exposure=network, **owner)
                     if assessment.inputs else None)
        entries.append((block, query, stability))
    # The same ranking the CLI uses, from the same map. This was a seventh copy.
    entries.sort(key=lambda entry: (
        score.VERDICT_RANK.get(entry[0][0].verdict, len(score.VERDICT_RANK)),
        -(entry[0][0].score or 0)))
    return entries


def _comparison_warning(rows):
    if not (any(row[2] for row in rows) and not all(row[2] for row in rows)):
        return ''
    # "review" is the amber alert and carries no role=alert: this is advice
    # about the comparison, not an error.
    return report.components.alert(
        'review', 'Firmware is not given for every candidate',
        'Some candidates have firmware specified and others do not. '
        'Add a version for each to compare on equal terms.')


def _remove_hrefs(entries, rows):
    """For each ranked entry, the shortlist URL without that one candidate.

    Ranking reorders the rows, so an entry is matched back to its input row by
    the four identifying fields, each row used once. Two rows identical in all
    four fields (differing only in site details) are interchangeable here.
    """
    pool = list(range(len(rows)))
    hrefs = []
    for _, query, _ in entries:
        key = [query.get(name, '') for name in batch.QUERY_FIELDS]
        match = next((i for i in pool if list(rows[i][:4]) == key), None)
        if match is None:
            hrefs.append(None)
            continue
        pool.remove(match)
        rest = [row for i, row in enumerate(rows) if i != match]
        hrefs.append('/compare?' + _comparison_parameters(rest) if rest else '/compare')
    return hrefs


def _clear_shortlist():
    """Destructive control that always confirms, with a native popover (no JS)."""
    components = report.components
    return (components.button('Clear shortlist', 'destructive',
                              attrs={'popovertarget': 'clear-shortlist'})
            + '<div class="rt-confirm" id="clear-shortlist" popover role="alertdialog" '
              'aria-labelledby="clear-shortlist-text">'
              '<p id="clear-shortlist-text">Clear the whole shortlist? Every candidate is '
              'removed from this page. Nothing is saved.</p>'
              '<div class="rt-confirm__actions">'
            + components.link_button('Clear shortlist', '/compare', 'destructive')
            + components.button('Keep shortlist', 'secondary',
                                attrs={'popovertarget': 'clear-shortlist',
                                       'popovertargetaction': 'hide'})
            + '</div></div>')


def _compare_page(assess, context, candidates, submitted=False):
    """A shortlist with separate input fields and ranked, explainable results."""
    components = report.components
    filled = _comparison_rows(candidates)
    boxes = ''
    for i in range(min(MAX_CANDIDATES, max(2, len(filled) + 1))):
        row = filled[i] if i < len(filled) else [''] * len(COMPARISON_FIELDS)
        vendor, product, version, order_number = row[:4]
        network, owner = _candidate_context(row)
        boxes += (f'<fieldset><legend>Candidate {i + 1}</legend><div class="candidate-grid">'
                  + _field(f'co{i}', f'order_number_{i}', 'Manufacturer order number', order_number,
                           'e.g. 6ES7518-4AX00-1AB0')
                  + _field(f'cv{i}', f'vendor_{i}', 'Vendor', vendor, 'e.g. Moxa')
                  + _field(f'cp{i}', f'product_{i}', 'Product / model', product, 'e.g. EDS-405A')
                  + _field(f'cf{i}', f'version_{i}', 'Firmware (optional)', version, 'e.g. 3.0')
                  + '</div><h3>Network access and operating conditions</h3>'
                  + _owner_fields(network, suffix=f'_{i}', **owner) + '</fieldset>')
    # Compare is secondary: the one primary control on this page is the export menu.
    form = ('<form method="get" action="/compare">' + boxes
            + '<p class="helper">Use an order number, or a vendor and model. If you enter both, '
            'they must agree. Leave unused candidates blank. Another row appears after comparing, '
            'up to 12 candidates. Each candidate keeps its own site details and fixes.</p>'
            + components.button('Compare', 'secondary', 'submit') + '</form>')
    heading = ('<h1>Compare your candidates</h1><p class="lead">Review products side by side before '
               'choosing what to buy. Higher scores are more favourable; purchase blockers override the score. '
               'An engineer still needs to confirm that each product can do the required job.</p>')
    if not _valid_comparison(filled):
        notice = (components.alert(
            'error', 'Name a product in each candidate row',
            'Enter an order number, vendor or product in each used candidate row before '
            'comparing. Firmware alone does not identify a product.')
            if submitted else '')
        example = ('<p class="helper"><a href="/compare?c=ABB%7CAC%20800M&amp;c=Moxa%7CEDS-405A">'
                   'Open an example comparison</a>. These examples demonstrate the tool; they are '
                   'different equipment types, not interchangeable products.</p>')
        return _page('Procurement comparison', heading + notice + form + example)
    entries = _comparison_results(assess, context, filled)
    blocks = [block for block, _, _ in entries]
    stabilities = {id(block[0]): stability for block, _, stability in entries if stability}
    parameters = _comparison_parameters(filled)
    export = components.menu('Export comparison', [
        (label, f'/compare.{extension}?{parameters}', tag, '')
        for extension, label, tag in (('html', 'HTML report', 'HTML'),
                                      ('json', 'JSON', 'JSON'),
                                      ('csv', 'CSV', 'CSV'))], 'export-comparison')
    actions = f'<div class="rt-cmp-actions">{export}{_clear_shortlist()}</div>'
    hrefs = _remove_hrefs(entries, filled)
    queries = [query for _, query, _ in entries]
    warning = _comparison_warning(filled)
    return _page('Procurement comparison', heading + warning + actions
                 + '<details><summary>Edit candidates or add another</summary>' + form + '</details>'
                 + report.body(blocks, stabilities=stabilities, weights=context['weights'],
                               compare={'remove': lambda i: hrefs[i], 'queries': queries}),
                 f'{len(blocks)} candidate(s)')


def _alternatives_page(connection, assess, vendor, product, version, candidate_pages=None, data_dir="data"):
    """Same-family candidates, with the same caveat the terminal prints."""
    form = _lookup_form('/alternatives', 'Find alternatives', vendor, product, version)
    heading = _secondary_head(
        'Find other products to review',
        'Explore related products from the same manufacturer. Ask an engineer to confirm '
        'they can do the same job; this is not a recommendation to substitute.', '/alternatives')
    if not (vendor and product):
        return _page('Alternatives', heading + (_lookup_error() if vendor or product else '')
                     + form + _lookup_example('/alternatives', 'Siemens', 'SIMATIC S7-1500'))

    subject, resolution, _ = assess(vendor, product, version or None)
    named = resolution.matches[0] if resolution.matches else None
    family_vendor = named.vendor if named else vendor
    family_name = named.name if named else product
    if not resolution.resolved:
        return _page('Alternatives', heading + form + components.alert(
            'review', 'Product not identified', body_html=(
                f'<p class="rt-alert__text">{_esc(resolution.reason)}. '
                '<a href="/">Search for the exact model</a> and try again.</p>')))
    body = heading + _lookup_controls(form, True)
    shown = "no score" if subject.score is None else report.score_label(subject, unit='/100')
    body += (f'<div class="actions"><b>{_esc(subject.product)}</b> {components.verdict_badge(subject.verdict, "s")} '
             f'<span class="rt-formula">{shown}</span></div>')

    excluded = {normalize_name(m.name) for m in resolution.matches}
    def candidate_list():
        return alternatives.find(
            connection, family_vendor, family_name,
            lambda v, p: assess(v, p), limit=8, exclude=excluded)
    if candidate_pages is None:
        options, skipped = candidate_list()
    else:
        # Candidate assessments deliberately have no selected firmware or
        # owner assertions. Share their public snapshot across firmware-specific
        # pages; the subject assessment above always uses this request's version.
        snapshot = identity.data_fingerprint(connection, data_dir)
        key = (snapshot, date.today().isoformat(), 'alternative-candidates',
               family_vendor, family_name, tuple(sorted(excluded)))
        def encoded_candidates():
            from dataclasses import asdict
            options, skipped = candidate_list()
            return json.dumps({'options': [asdict(option) for option in options],
                               'skipped': skipped})
        data = json.loads(candidate_pages.get(key, encoded_candidates))
        options = [alternatives.Option(**option) for option in data['options']]
        skipped = data['skipped']
    body += '<p>Open a product name to check its exact model and firmware with your engineer.</p>'
    if version:
        body += components.alert(
            'review', 'Firmware is not carried over',
            f'Your original product uses firmware {version}. '
            'Alternatives have no firmware specified. Check each version before comparing scores.')

    if options:
        if any(o.provisional for o in options):
            body += components.alert(
                'review', 'Provisional candidates',
                'VERIFY candidates need technical checks. Their score ranges are provisional; '
                'they are not recommendations or proof of a better outcome.')
        rows = "".join(
            f'<tr><td><a href="/score?vendor='
            f'{urllib.parse.quote(family_vendor)}&amp;product='
            f'{urllib.parse.quote(o.name)}">'
            f'{_esc(o.product)}</a></td>'
            f'<td>{components.verdict_badge(o.verdict, "s")}</td>'
            f'<td class="n">{report.score_label(o)}</td><td class="n">{o.cves}</td></tr>'
            for o in options)
        body += ('<div class="tw" tabindex="0" role="region" aria-label="Alternative products; scroll sideways for more columns">'
                 '<p class="table-scroll-hint">Scroll sideways to see all columns →</p>'
                 '<table><thead><tr><th>Product — open for an assessment</th>'
                 '<th>Verdict</th><th class="n">Score / 100</th><th class="n">Known vulnerabilities</th></tr></thead>'
                 f'<tbody>{rows}</tbody></table></div>')
        if subject.score is not None and not subject.provisional and not any(o.provisional for o in options):
            better = sum(1 for o in options if o.score > subject.score)
            body += (f'<p>{better} of {len(options)} scored above '
                     f'{_esc(subject.product)} ({subject.score}/100).</p>')
    else:
        body += ('<p class="empty">No related product met the requirements for this list. '
                 'Ask your supplier for other candidates and assess them individually.</p>')
    for reason, count in (skipped or {}).items():
        if count:
            label = {'gated': 'have purchase blockers', 'unassessable': 'need further verification or could not receive a favourable assessment',
                     'no evidence': 'have no published vulnerability evidence to compare'}.get(reason, 'could not be included')
            body += f'<p class="helper">{count} related product(s) are not shown because they {label}.</p>'
    body += ('<details><summary>What this list can and cannot compare</summary>'
             f'<p>{_esc(alternatives.CAVEAT)}</p></details>')
    body += _product_next_steps(vendor, product, version)
    return _page(f"Alternatives: {subject.product}", body,
                 f"{len(options)} candidate(s)")


def _timeline_page(connection, vendor, product):
    """The advisory record drawn as a shape, exactly as the terminal draws it."""
    form = _lookup_form('/timeline', 'Show advisory history', vendor, product, product_optional=True)
    heading = _secondary_head(
        'Advisory timeline',
        'See when security notices were published and whether they offered a fix. '
        'More notices can reflect better reporting; a quiet year says nothing '
        'about whether the equipment is exposed.', '/timeline')
    if not vendor:
        return _page('Timeline', heading + (components.alert(
            'error', 'Enter the manufacturer to show its history') if product else '')
            + form + _lookup_example('/timeline'))

    from . import match
    if product:
        resolution = match.resolve(connection, vendor=vendor, product=product)
        if not resolution.resolved:
            return _page('Timeline', heading + form +
                         f'<p class="empty">{_esc(resolution.reason)}. <a href="/">Find the exact model with search</a>.</p>')
        subject = f'{vendor} {product}'.strip()
        line = timeline.build(connection, [(m.advisory_id, m.product_id)
                                           for m in resolution.matches])
    else:
        key = _vendor_key(connection, vendor)
        if key is None:
            return _page("Timeline", heading + form +
                         f'<p class="empty">vendor {_esc(vendor)} does not '
                         'appear in the available data. Check the spelling or use search.</p>')
        subject, line = vendor, timeline.for_vendor(connection, key)
    body = heading + _lookup_controls(form, True, 'Change manufacturer or product')
    if product:
        body += (f'<p class="helper">History combines {resolution.product_count} matched product name(s). '
                 'Use the exact model to narrow the selection.</p>')
    body += webviews.advisory_history(subject, line)
    if product:
        body += _product_next_steps(vendor, product)
    return _page(f"Timeline: {subject}", body)


def _annex_data(connection, assess, dossier, context, vendor, product, version):
    assessment, resolution, findings = assess(vendor, product, version or None)
    profile = None
    if resolution.matches:
        profile = dossier.build(connection, resolution.matches[0].vendor,
                                screening=context['screening'], certificates=context['certificates'])
    return assessment, resolution, questions.build(assessment, findings, profile)


def _annex_text(connection, assess, dossier, context, vendor, product, version, download=False):
    """The annex as bare text: what actually gets pasted into an RFQ.

    Returned as text/plain so "select all, copy" needs no care about markup,
    and a procurement template can curl it straight into a document. With
    download=True the same bytes come back as an attachment.
    """
    if not (vendor or product):
        return PlainText("Give vendor and product: /annex.txt?vendor=...&product=...")
    assessment, _, items = _annex_data(connection, assess, dossier, context, vendor, product, version)
    text = questions.format_report(assessment.product, items)
    if not download:
        return PlainText(text)
    # The filename reaches a response header, so it is rebuilt from ASCII
    # letters and digits only: no quote, separator or control character survives.
    slug = ''.join(c if c.isascii() and c.isalnum() else '-' for c in assessment.product)
    slug = '-'.join(part for part in slug.split('-') if part)[:60].strip('-') or 'product'
    return Download(text, f'retrust-rfq-annex-{slug}.txt', 'text/plain')


def _annex_page(connection, assess, dossier, context, vendor, product, version):
    """The RFQ security annex, as text a buyer pastes into a request."""
    form = _lookup_form('/annex', 'Prepare supplier questions', vendor, product, version)
    heading = _secondary_head(
        'Questions to send your supplier',
        'Prepare questions for your email or quotation request. Ask for written answers '
        'and evidence, then have your technical team review the replies.', '/annex')
    if not (vendor and product):
        return _page('RFQ annex', heading + (_lookup_error() if vendor or product else '')
                     + form + _lookup_example('/annex', 'Moxa', 'EDS-405A'))

    assessment, resolution, items = _annex_data(connection, assess, dossier, context, vendor, product, version)
    annex = questions.format_report(assessment.product, items)
    text_query = urllib.parse.urlencode(
        dict(vendor=vendor, product=product, **({'version': version} if version else {})))
    body = heading + _lookup_controls(form, True)
    if not resolution.resolved:
        body += components.alert(
            'review', 'Product not matched',
            'These are starting questions to confirm its identity and security information. '
            'They are not findings about this product.')
    body += (webviews.supplier_questions(assessment.product, items,
                                         export_href=f'/annex.txt?{text_query}&download=1',
                                         text_href=f'/annex.txt?{text_query}')
             + '<p class="helper">In the plain text version, select all and copy into your email '
               'or quotation request. ReTrust does not send anything to the supplier.</p>'
             + '<details><summary>Complete text and technical reasons</summary>'
             f'<pre class="tw" style="white-space:pre-wrap">{_esc(annex)}</pre></details>')
    return _page(f'Annex: {assessment.product}', body)


def _select(name, label, options, chosen):
    """One labelled dropdown, in the shared select style."""
    pairs = list(options.items()) if isinstance(options, dict) else [(o, o) for o in options]
    return components.select_field(name, label, pairs, chosen, input_id=name)


def _ssvc_page(connection, assess, vendor, product, version,
               exposure, automatable, impact):
    """CERT/CC's deployer tree, with the three plant facts asked out loud."""
    settings = ('<details class="form-options"><summary>Review the technical team’s settings</summary>'
        '<div class="candidate-grid">'
        + _select("exposure", "How accessible is the system? (describes your plant)",
                  webviews.ACCESS_LABELS, exposure)
        + _select("automatable", "Could an attacker carry out the attack automatically?",
                  {"yes": "Yes", "no": "No"}, automatable)
        + _select("impact", "Potential effect on people and operations", webviews.IMPACT_LABELS, impact)
        + '</div><p class="helper">Ask your technical and operations teams to confirm these settings. '
          'The choices apply to every vulnerability in this assessment.</p>'
        + '</details><p class="helper">The selected access, automation and impact settings are assumptions. '
          'Review them with your technical team before using the suggested timing.</p>')
    form = _lookup_form('/ssvc', 'Show response priorities', vendor, product, version, extra=settings)
    heading = _secondary_head(
        'What should be fixed first?',
        'Get suggested timing for reviewing and fixing known security weaknesses. Your technical '
        'and operations teams should confirm the settings and agree on maintenance steps.', '/ssvc')
    if exposure not in ssvc.EXPOSURE or automatable not in ssvc.AUTOMATABLE or impact not in ssvc.HUMAN_IMPACT:
        return _page("SSVC", heading + components.alert(
            'error', 'Choose one of the listed options',
            'Pick an access, automation and impact option from the lists, then try again.') + form)
    if not (vendor and product):
        return _page('SSVC', heading + (_lookup_error() if vendor or product else '')
                     + form + _lookup_example('/ssvc'))
    assessment, resolution, findings = assess(vendor, product, version or None)
    if not resolution.resolved:
        return _page("SSVC", heading + form +
                     f'<p class="empty">{_esc(resolution.reason)}</p>')
    decisions = ssvc.assess(findings, exposure, automatable, impact)
    return _page(f"SSVC: {assessment.product}",
                 heading + _lookup_controls(form, True, 'Change product or response settings') + webviews.response_priority(
                     assessment.product, decisions, exposure, automatable, impact,
                     undecided=sum(1 for f in findings if not f.decided),
                     kev_loaded=any(p['source'] == 'CISA KEV' for p in index_module.provenance(connection)))
                 + _product_next_steps(vendor, product, version))


def _lev_page(connection, assess, vendor, product):
    """NIST CSWP 41 estimates, or the honest abstention when history is absent."""
    form = _lookup_form('/lev', 'Check exploitation history', vendor, product)
    heading = _secondary_head(
        'Past exploitation estimate',
        'Could these known security weaknesses have been used in attacks already? Compare a '
        'historical model estimate with confirmed public records.', '/lev')
    if not (vendor and product):
        return _page('LEV', heading + (_lookup_error() if vendor or product else '')
                     + form + _lookup_example('/lev', 'Schneider Electric', 'Modicon M340 PLC modules'))
    if not index_module.has_epss_history(connection):
        return _page("LEV", heading + form +
                     '<p class="empty">Historical attack estimates are not available in this workspace. '
                     'Ask the workspace owner to refresh the historical data. This is missing data, not a zero estimate.</p>')
    assessment, resolution, findings = assess(vendor, product)
    if not resolution.resolved:
        return _page("LEV", heading + form +
                     f'<p class="empty">{_esc(resolution.reason)}. Check the name or '
                     '<a href="/">find the product with search</a>.</p>')
    cves = sorted({f.cve for f in findings})
    history = index_module.epss_history(connection, cves)
    signals = {f.cve: f for f in findings}
    corpus_share = index_module.lev_corpus_share(connection, lev.WORTH_LOOKING)
    estimates = [lev.estimate(c, history.get(c, []), in_kev=signals[c].in_kev,
                              current_epss=signals[c].epss) for c in cves]
    return _page(f"LEV: {assessment.product}",
                 heading + _lookup_controls(form, True) + webviews.exploitation(
                     assessment.product, estimates,
                     corpus_share=corpus_share,
                     kev_loaded=any(p['source'] == 'CISA KEV' for p in index_module.provenance(connection)))
                 + _product_next_steps(vendor, product))


def _vendor_page(connection, dossier, context, name):
    form = ('<form class="lookup-form" method="get" action="/vendor">'
            + components.text_field('name', 'Manufacturer', name, input_id='n', attrs={
                'maxlength': MAX_QUERY, 'required': True, 'placeholder': 'e.g. ABB, Siemens or Moxa'})
            + components.button('View manufacturer profile', 'primary', type='submit') + '</form>')
    heading = _secondary_head(
        'Vendor profile',
        'Check a manufacturer’s published security notices, supplier restrictions and '
        'certification records. Use this to prepare questions; the notice count is not a ranking.',
        '/vendor')
    if not name:
        return _page('Vendor', heading + form
                     + '<p class="helper">Try an example: <a href="/vendor?name=ABB">ABB</a>, '
                     '<a href="/vendor?name=Siemens">Siemens</a> or <a href="/vendor?name=Moxa">Moxa</a>.</p>')
    profile = dossier.build(connection, name, screening=context["screening"],
                            certificates=context["certificates"])
    body = heading + _lookup_controls(form, True, 'Change manufacturer') + webviews.vendor_profile(profile)
    if not profile.known:
        body += '<p><a href="/">Check the manufacturer spelling with search</a>, or ask the supplier for its published security notices.</p>'
    if profile.known:
        body += ('<div class="actions">'
                 + components.link_button("Search this vendor's products",
                                          f'/?q={urllib.parse.quote(name)}', 'secondary')
                 + components.link_button('Advisory timeline',
                                          f'/timeline?vendor={urllib.parse.quote(name)}', 'secondary')
                 + '</div>')
    return _page(f"Vendor: {name}", body)


PILLAR_LABELS = {'exposure': 'exposure safety', 'patchability': 'available fixes',
                 'vendor_practice': 'vendor security practices',
                 'certification': 'certification evidence'}


def _pillar_weights():
    """(letter, label, share) per scored pillar, from the weights score.py applies."""
    total = sum(spec.weight for spec in score.PILLARS) or 1.0
    return [(report.PILLAR_LETTERS.get(spec.key, spec.key[:1].upper()),
             PILLAR_LABELS.get(spec.key, spec.name.lower()), spec.weight / total)
            for spec in score.PILLARS]


def _about_page(stats, provenance, host, port):
    deployment = ('This is a hosted workspace. Queries are processed on this server and '
                  'requests pass through the hosting provider. For confidential procurement '
                  'inputs, run ReTrust locally with <code>retrust serve</code>.'
                  if os.environ.get('RETRUST_HOSTED') == '1' else
                  f'Serving on {_esc(host)}:{port}. Stop it with Ctrl-C.')
    stat_names = {'advisories': 'Published security notices', 'products': 'Product entries in advisories',
                  'vendors': 'Manufacturers', 'cves': 'Distinct vulnerability IDs',
                  'order_numbers': 'Manufacturer part numbers', 'cves_in_kev': 'Vulnerabilities here with confirmed CISA exploitation records',
                  'kev_catalogue': 'Entries in the full CISA exploitation catalogue', 'epss_scores': '30-day attack estimates available'}
    weights = _pillar_weights()
    weight_sentence = ', '.join(f'{label} ({share:.0%})' for _, label, share in weights[:-1])
    weight_sentence += f' and {weights[-1][1]} ({weights[-1][2]:.0%})'
    pillar_table = webviews.table(
        ('Pillar', 'Symbol', 'Default weight'),
        [(label.capitalize(), letter, components.fmt_weight(share)) for letter, label, share in weights],
        'Default pillar weights', numeric=(2,))
    verdicts = webviews.table(
        ('Verdict', 'Meaning'),
        [(verdict, meaning) for verdict, meaning in (
            ('PREFER', 'Consider for your shortlist. Complete the supplier checks and confirm that the product is suitable before approving a purchase.'),
            ('CONDITIONAL', 'Review before deciding. Ask your technical team to review the risks and missing information.'),
            ('AVOID', 'Advised against purchase. A purchase blocker or a low score makes this an unfavourable assessment. Read the stated reasons.'),
            ('VERIFY', 'Technical checks needed. Resolve missing network, consequence or firmware evidence before choosing. A provisional range shows what remains uncertain; a product with no evidence at all gets the full range, with its low end as the headline.'))],
        'What each verdict asks of you', badges=(0,))
    facts = webviews.table(
        ('Holds', 'Count'), [(stat_names.get(k, k.replace('_', ' ')), f'{v:,}') for k, v in stats.items()],
        'Data available in this workspace', numeric=(1,))
    origins = webviews.table(
        ('Source', 'What was loaded', 'Recorded on'),
        [(p['source'], p['detail'], p['captured']) for p in provenance],
        'Where the loaded data came from', numeric=(2,))
    steps = ('<ol class="steps">'
             '<li><span class="step-number">1</span><div><b>Identify the exact product</b>'
             '<p>Use the order number from the supplier’s quotation and add the firmware version. '
             'If ReTrust cannot match the product, it reports VERIFY across the full range. Unconfirmed firmware '
             'ranges remain visible for review.</p></div></li>'
             '<li><span class="step-number">2</span><div><b>Check for purchase blockers</b>'
             '<p>Confirmed exploitation affecting the device firmware and supplier restrictions can '
             'trigger AVOID. A blocker overrides the numerical score. Issues reported only in '
             'bundled software are flagged separately for technical review.</p></div></li>'
             '<li><span class="step-number">3</span><div><b>Combine four kinds of evidence</b>'
             f'<p>The default score weighs {weight_sentence}. Where the equipment sits on '
             'the network is recorded as context and never moves the score: a network zone does not '
             'establish that an attacker can reach a particular weakness. Reachability is read from '
             'each weakness&rsquo;s own CVSS attack vector and the conditions it demands, narrowed only by '
             'what you have verified. Missing evidence and operator assumptions are shown with the '
             'result.</p></div></li></ol>')
    return _page("About", f"""<h1>Methodology</h1>
<p class="lead">How a verdict is reached, which data it rests on, and what ReTrust does not do.</p>
<details><summary>Which page should I use?</summary>
<dl class="term-list">
<dt><a href="/">Search</a></dt><dd>Find the exact manufacturer and model from an order number or product name.</dd>
<dt><a href="/score">Assess a product</a></dt><dd>Get a procurement recommendation and see the evidence and supplier checks behind it.</dd>
<dt><a href="/compare">Compare candidates</a></dt><dd>Review a shortlist side by side using the firmware and site details for each product.</dd>
<dt><a href="/vendor">Vendor profile</a></dt><dd>Review a manufacturer’s published security notices, restrictions and certificates.</dd>
<dt><a href="/timeline">Advisory timeline</a></dt><dd>See when security notices appeared and whether they offered fixes.</dd>
<dt><a href="/alternatives">Find alternatives</a></dt><dd>Find related products for an engineer to evaluate for suitability.</dd>
<dt><a href="/annex">Supplier questions</a></dt><dd>Prepare questions to copy into an email or quotation request.</dd>
<dt><a href="/ssvc">Response priority</a></dt><dd>Discuss suggested fix timings with your security and operations teams.</dd>
<dt><a href="/lev">Exploitation estimate</a></dt><dd>Compare estimated past attacks on known weaknesses with confirmed public records.</dd>
<dt><a href="/demo">Guided demo</a></dt><dd>Walk through an example purchase decision.</dd>
</dl></details>
<section class="rt-section"><h2>What the recommendation means</h2>{verdicts}</section>
<section class="rt-section"><h2>How a verdict is reached</h2>{components.card(steps)}</section>
<section class="rt-section"><h2>Scoring formula and its limits</h2>
{pillar_table}
<details class="vector"><summary>Formula and inputs</summary>
<p><code>S = E^0.60 × P^0.20 × V^0.15 × C^0.05</code>, using scores from 1 to 100.
E is exposure safety, P is available fixes, V is vendor practices, and C is certification evidence.
These are the default weights; individual reports show the weights actually used.</p>
<p><code>Z = T × I × A × H × U; R = min(1, Z1 + 0.20Z2 + 0.10Z3); E = 100(1 − R)</code>.
The highest-risk review unit counts fully; only the next two add weight. T uses the maximum of KEV, LEV and EPSS,
floored for the equipment's service life by how the flaw is reached (wormable .50, other network .30, local .15,
physical .05). I is the CVSS base score divided by 10.
A is 1 for a feasible attack path, 0 for a verified block, or an unresolved range.
H is the credible operational consequence; U records whether the selected firmware remains affected.
Network topology is context, not a fractional discount. Missing inputs produce VERIFY and a provisional range.
Repeated advisories for a CVE count once; distinct CVEs are not proof of independent paths.</p>
<p>A pillar with no measurable evidence is not dropped. It enters the weighted product at a neutral 50
with its full weight, and the report lists it as a gap. Each measured pillar enters at its measured value.
Purchase blockers still override the score. A score is not a probability: 80/100 does not predict the chance of a compromise.</p></details>
<p><a href="/formula-check.json">Download the all-product deployment formula check</a>.
It records the checked product count, input scenarios, code build and data fingerprint.
A failed check blocks deployment; missing or outdated checks are identified in the download.</p></section>
<section class="rt-section"><h2>Common terms in plain language</h2>
<dl class="term-list"><dt>Vulnerability / CVE</dt><dd>A known security weakness. A CVE number is its reference ID.</dd>
<dt>Severity / CVSS</dt><dd>How serious the weakness could be, rated out of 10. It does not say how likely an attack is.</dd>
<dt>EPSS</dt><dd>A model estimate of exploitation in the next 30 days, shown as a percentage.</dd>
<dt>CISA KEV</dt><dd>A public list of vulnerabilities confirmed to have been exploited. A missing entry does not prove no attack happened.</dd>
<dt>LEV</dt><dd>A model estimate of earlier exploitation, built from historical EPSS scores. It does not show whether your own equipment was attacked.</dd>
<dt>Firmware</dt><dd>The software running inside the equipment. Its version helps determine which vulnerabilities apply.</dd></dl></section>
<section class="rt-section" id="sources"><h2>Data sources</h2>
<h3 class="rt-h3">Data available in this workspace</h3>{facts}
<h3 class="rt-h3">Where the data came from</h3>{origins}
<p class="empty">Certification evidence comes from the ISASecure certified-component,
-process and -system directories, the Common Criteria certified-products list, and a
small curated layer for IEC 62443 certificates issued outside those directories
(each curated entry names its source and says to verify with the certifying body).
Supplier screening uses the trade.gov Consolidated Screening List and the FCC
Covered List. {webui.source_note()}.</p></section>
<section class="rt-section"><h2>What this server does and does not do</h2>
<p>The website displays assessments and downloads. It does not scan devices,
apply patches or change equipment.</p>
<details><summary>Technical server details</summary><pre style="white-space:pre-wrap">{_esc(SAFETY)}</pre></details>
<p class="empty">{deployment}</p></section>""")


class PlainText(str):
    """A page that is text, not markup. _send switches the content type on it."""


class Download(str):
    """Generated in memory with a fixed filename; no server-side file writes."""

    def __new__(cls, text, filename, content_type):
        value = super().__new__(cls, text)
        value.filename, value.content_type = filename, content_type
        return value


class InvalidComparison(ValueError):
    """A comparison download needs at least one identifiable candidate."""


def _export_comparison(assess, context, provenance, path, candidates):
    rows = _comparison_rows(candidates)
    if not _valid_comparison(rows):
        raise InvalidComparison('Enter an order number, vendor or product for each used candidate. '
                                'Return to Compare candidates to complete the shortlist.')
    entries = _comparison_results(assess, context, rows)
    blocks = [block for block, _, _ in entries]
    stabilities = {id(block[0]): stability for block, _, stability in entries if stability}
    queries = [query for _, query, _ in entries]
    if path.endswith('.html'):
        return Download(report.render(blocks, title='ReTrust procurement comparison',
                        stabilities=stabilities, provenance=provenance, weights=context['weights'],
                        config_source=context.get('config_source', ''), queries=queries),
                        'retrust-comparison.html', 'text/html')
    if path.endswith('.csv'):
        records = [batch.to_record(block[0], block[1], stability, query)
                   for block, query, stability in entries]
        return Download(batch.dumps_csv(records, include_queries=True),
                        'retrust-comparison.csv', 'text/csv')
    records = [batch.to_detail(*block, stability=stability, query=query)
               for block, query, stability in entries]
    payload = batch.envelope(records, {
        'provenance': provenance, 'weights': context['weights'],
        'bands': context.get('bands'), 'config_source': context.get('config_source', ''),
        'generated': date.today().isoformat(), 'requested_stability_samples': 300,
        'warnings': (['Some candidates have firmware specified and others do not. '
                      'Add a version for each to compare on equal terms.']
                     if _comparison_warning(rows) else [])})
    return Download(batch.dumps(payload), 'retrust-comparison.json', 'application/json')


class ExportUnavailable(Exception):
    """A download that cannot honestly be produced.

    Raised instead of returning an empty file: a blank CSV or a VEX with no
    statements still reads as an answer ("nothing affects this"), which is the
    one thing neither may say by accident. The handler turns it into an error
    page with `status`.
    """

    def __init__(self, heading, message, status=404):
        super().__init__(message)
        self.heading, self.status = heading, status


def _export(assess, context, provenance, path, vendor, product, version, order_number,
            network_exposure=None, owner=None):
    if network_exposure not in score.NETWORK_EXPOSURES:
        network_exposure = None
    if path.endswith('.csv'):
        return _export_csv(assess, vendor, product, version, order_number,
                           network_exposure, owner)
    block = _run_assessment(assess, vendor, product, version, order_number,
                            network_exposure, owner)
    if path.endswith('.json'):
        query = dict(vendor=vendor, product=product, version=version,
                     order_number=order_number, network_exposure=network_exposure)
        payload = batch.envelope([batch.to_detail(*block, query=query)], {
            'provenance': provenance, 'weights': context['weights'],
            'config_source': context.get('config_source', ''),
            'generated': date.today().isoformat()})
        return Download(batch.dumps(payload), 'retrust-assessment.json', 'application/json')
    return Download(report.render([block], title='ReTrust procurement assessment',
                    provenance=provenance, weights=context['weights'],
                    config_source=context.get('config_source', '')),
                    'retrust-assessment.html', 'text/html')


def _export_csv(assess, vendor, product, version, order_number,
                network_exposure=None, owner=None):
    """One assessment as a spreadsheet row, with the query that produced it.

    dumps_csv neutralises formula-leading cells, so a hostile product name
    cannot become a formula when this is opened in a spreadsheet.
    """
    if not (vendor or product or order_number):
        raise ExportUnavailable(
            'Nothing to export',
            'Give an order number, or a vendor and product, to export a CSV row.', 400)
    assessment, resolution, _ = _run_assessment(assess, vendor, product, version,
                                                order_number, network_exposure, owner)
    query = dict(vendor=vendor, product=product, version=version,
                 order_number=order_number)
    record = batch.to_record(assessment, resolution, None, query)
    return Download(batch.dumps_csv([record], include_queries=True),
                    'retrust-assessment.csv', 'text/csv')


def _export_vex(connection, assess, provenance, vendor, product, version, order_number,
                network_exposure=None, owner=None):
    """The assessment as a CycloneDX VEX document (the CLI's `vex` command).

    A product that did not resolve, or one whose records name no CVE, has
    nothing to state; that is an error page, never an empty document.
    """
    from . import vex
    if not (vendor or product or order_number):
        raise ExportUnavailable(
            'Nothing to export',
            'Give an order number, or a vendor and product, to export a VEX.', 400)
    assessment, resolution, _ = _run_assessment(assess, vendor, product, version,
                                                order_number, network_exposure, owner)
    if not resolution.resolved:
        raise ExportUnavailable(
            'VEX unavailable',
            'No VEX was written: the product was not identified, so there is nothing to '
            'make a claim about. Identify it by order number or exact model name.')
    statements = vex.statements(connection, resolution, version or None)
    if not statements:
        raise ExportUnavailable(
            'VEX unavailable',
            'No VEX was written: the records for this product name no CVE to make a claim about.')
    named = resolution.matches[0]
    subject = f'{named.vendor} {named.name}'.strip()
    document = vex.document(subject, version or None, statements, provenance)
    return Download(json.dumps(document, indent=2) + '\n',
                    'retrust-assessment.vex.json', 'application/json')


def build_concurrent_handler(database, assessor, context, dossier, stats, provenance, host, port):
    """Create request-owned readers inside the worker that uses them.

    Shared settings and certificate records are read-only. Both advisory and
    screening SQLite connections are opened and closed by their request thread.
    """
    public_pages = webcache.PublicPages()

    def handle(request, address, server):
        reader = index_module.connect_readonly(database)
        screening = supplychain.load(context.get('data_dir', 'data'), read_only=True)
        request_context = dict(context, screening=screening)
        try:
            def assess(vendor, product, version=None, order_number=None, **options):
                return assessor(reader, vendor, product, version, order_number,
                                context=request_context, **options)
            handler = build_handler(reader, assess, request_context, dossier,
                                    stats, provenance, host, port, public_pages)
            handler(request, address, server)
        finally:
            screening.close()
            reader.close()
    handle.concurrent_safe = True
    return handle


LINGER_SECONDS = .1
# Refused sockets drained at once. Beyond this, a flood of refusals is closed
# straight away as it was before: losing some 503s beats stalling the accepts.
LINGERING = 16


def _linger(request):
    """Half-close and read what the client sent before the socket is closed.

    Closing with unread request bytes makes TCP answer with a reset, and the
    client then reports "connection aborted" instead of reading the 503 and
    its Retry-After (Windows did so on most overloaded requests). A client
    that closes promptly costs nothing, a silent one at most LINGER_SECONDS.
    Socket timeouts rather than select(), which refuses descriptors >= 1024.
    """
    request.shutdown(socket.SHUT_WR)
    deadline = time.monotonic() + LINGER_SECONDS
    drained = 0
    while drained < 65536:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        request.settimeout(remaining)
        chunk = request.recv(4096)          # socket.timeout is an OSError
        if not chunk:
            return
        drained += len(chunk)


class ConcurrentHTTPServer(http.server.HTTPServer):
    """A fixed worker pool and a bounded queue, including stalled clients."""
    request_queue_size = 64
    allow_reuse_address = True

    def __init__(self, address, handler, workers=8):
        if not 1 <= workers <= 32:
            raise ValueError('Web workers must be between 1 and 32')
        super().__init__(address, handler)
        self.workers = workers
        # Two request handlers remain available for health probes and prompt
        # busy responses while all calculation slots are occupied.
        self._pool = ThreadPoolExecutor(max_workers=workers + 2, thread_name_prefix='retrust-web')
        self._calculations = threading.BoundedSemaphore(workers)
        self._slots = threading.BoundedSemaphore(workers * 2)
        self._lingering = threading.BoundedSemaphore(LINGERING)

    def process_request(self, request, address):
        if not self._slots.acquire(blocking=False):
            # Refuse excess work explicitly instead of growing the queue until
            # the proxy times out or the process runs out of memory.
            body = b'The server is busy. Please try again shortly.\n'
            headers = ('HTTP/1.0 503 Service Unavailable\r\n'
                       'Content-Type: text/plain; charset=utf-8\r\n'
                       f'Content-Length: {len(body)}\r\n'
                       'Retry-After: 2\r\nCache-Control: no-store\r\n'
                       'X-Content-Type-Options: nosniff\r\n'
                       'Connection: close\r\n\r\n').encode('ascii')
            try:
                request.settimeout(1)
                request.sendall(headers + body)
            except OSError:
                self.shutdown_request(request)
                return
            # Drained off the accepting thread, which must never wait on a
            # client: 40 silent refusals held a health probe for 4.3 s.
            if self._lingering.acquire(blocking=False):
                threading.Thread(target=self._linger_and_close, args=(request,),
                                 name='retrust-linger', daemon=True).start()
            else:
                self.shutdown_request(request)
            return
        try:
            self._pool.submit(self._run_request, request, address)
        except BaseException:
            self._slots.release()
            self.shutdown_request(request)
            raise

    def _linger_and_close(self, request):
        try:
            _linger(request)
        except OSError:
            pass
        finally:
            self.shutdown_request(request)
            self._lingering.release()

    def _run_request(self, request, address):
        try:
            self.finish_request(request, address)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass  # a client leaving is not an application failure
        except Exception:
            self.handle_error(request, address)
        finally:
            self.shutdown_request(request)
            self._slots.release()

    def server_close(self):
        super().server_close()
        pool = getattr(self, '_pool', None)
        if pool is not None:
            pool.shutdown(wait=True)


def build_handler(connection, assess, context, dossier, stats, provenance,
                  host, port, public_pages=None):
    """The request handler, closed over everything a page needs.

    Routing is an explicit dict rather than anything derived from the path, so a
    request can only ever reach a function named here. A path is never joined to
    a filename, which is the whole class of traversal bug this avoids by not
    having the code that would contain it.
    """
    # Enforced only on a loopback bind: served wider, the names clients use
    # cannot be known here, and that exposure was the user's explicit choice.
    guard_host = host in LOOPBACK_NAMES or host.strip("[]") in LOOPBACK_NAMES

    def host_allowed(header):
        if not guard_host or not (header or "").strip():
            return True               # an absent Host cannot carry a rebind
        try:
            name = urllib.parse.urlsplit(f"//{header.strip()}").hostname or ""
        except ValueError:
            return False
        return name in LOOPBACK_NAMES

    def page_for(path, params):
        """Dispatch one request. The table below is the entire routing surface.

        A dict keyed on the exact path, looked up once, so a request can only
        ever reach a function named here and an unknown path is a plain miss
        (None, which the caller turns into a 404). This used to be a 57-line
        if-chain under a comment claiming it was a dict -- same behaviour, but
        the claim a reader was relying on, that the routes are enumerable in one
        place, could only be checked by reading all 57 lines.

        Values are thunks rather than calls, so only the matched route runs; the
        arguments of the other seventeen are never evaluated.
        """
        def first(key):
            return (params.get(key) or [""])[0][:MAX_QUERY].strip()

        def health():
            connection.execute("SELECT 1 FROM advisory LIMIT 1").fetchone()
            return PlainText("ok\n")

        def export():
            return _export(assess, context, provenance, path,
                           first("vendor"), first("product"), first("version"),
                           first("order_number"), first("network_exposure"),
                           _owner_from(first))

        def export_vex():
            return _export_vex(connection, assess, provenance,
                               first("vendor"), first("product"), first("version"),
                               first("order_number"),
                               first("network_exposure") if first("network_exposure")
                               in score.NETWORK_EXPOSURES else None,
                               _owner_from(first))

        def export_comparison():
            return _export_comparison(assess, context, provenance, path,
                                      _candidate_rows(params))

        def score_page():
            return _score_page(connection, assess, context, first("vendor"),
                               first("product"), first("version"), first("order_number"),
                               submitted=any(key in params for key in
                                             ("vendor", "product", "version", "order_number")),
                               network_exposure=first("network_exposure"),
                               owner=_owner_from(first), previous=_previous_from(first),
                               view=dict(ev=first("ev"), sort=first("sort"),
                                         dir=first("dir"), show=first("show")),
                               dossier=dossier)

        def compare_page():
            return _compare_page(assess, context, _candidate_rows(params),
                                 submitted=any(key == "c" or key.startswith(
                                     ("vendor_", "product_", "version_", "order_number_"))
                                     for key in params))

        def public_page(route, fields, render):
            if public_pages is None:
                return render()
            # Only public product lookups are shared. Owner answers never
            # enter this cache, and a data or calendar change gets a new key.
            snapshot = identity.data_fingerprint(connection, context.get('data_dir', 'data'))
            return public_pages.get((snapshot, date.today().isoformat(), route, *fields), render)

        def formula_validation():
            target = Path(context.get('data_dir', 'data')) / 'formula-validation.json'
            if not target.exists():
                result = {'passed': False, 'available': False, 'reason': 'No deployment formula check is available for this snapshot.'}
            else:
                result = json.loads(target.read_text())
                current = (result.get('source_build') == BUILD
                           and result.get('data_fingerprint') == identity.data_fingerprint(
                               connection, context.get('data_dir', 'data')))
                result = dict(result, current=current, passed=bool(result.get('passed') and current))
            return Download(json.dumps(result, indent=2), 'retrust-formula-validation.json', 'application/json')

        routes = {
            "/": lambda: _search_page(connection, stats, first("q")),
            "/healthz": health,
            "/formula-check.json": formula_validation,
            "/robots.txt": lambda: PlainText("User-agent: *\nDisallow: /\n"),
            "/demo": _demo_page,
            "/about": lambda: _about_page(stats, provenance, host, port),
            "/score": score_page,
            "/export.html": export,
            "/export.json": export,
            "/export.csv": export,
            "/export.vex.json": export_vex,
            "/compare": compare_page,
            "/compare.html": export_comparison,
            "/compare.json": export_comparison,
            "/compare.csv": export_comparison,
            "/alternatives": lambda: public_page(
                "/alternatives", (first("vendor"), first("product"), first("version")),
                lambda: _alternatives_page(
                    connection, assess, first("vendor"), first("product"), first("version"),
                    candidate_pages=public_pages, data_dir=context.get('data_dir', 'data'))),
            "/timeline": lambda: _timeline_page(
                connection, first("vendor"), first("product")),
            "/annex": lambda: _annex_page(
                connection, assess, dossier, context,
                first("vendor"), first("product"), first("version")),
            "/annex.txt": lambda: _annex_text(
                connection, assess, dossier, context,
                first("vendor"), first("product"), first("version"),
                download=first("download") == "1"),
            "/ssvc": lambda: _ssvc_page(
                connection, assess, first("vendor"), first("product"), first("version"),
                first("exposure") or "controlled", first("automatable") or "yes",
                first("impact") or "medium"),
            "/lev": lambda: public_page(
                "/lev", (first("vendor"), first("product")),
                lambda: _lev_page(connection, assess, first("vendor"), first("product"))),
            "/vendor": lambda: _vendor_page(connection, dossier, context, first("name")),
        }
        if assets.is_static_path(path):
            return assets.static_asset(path)      # None if the file is missing
        route = routes.get(path)
        return route() if route else None

    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "ReTrust"
        sys_version = ""                  # the Python version is nobody's business

        # Drop incomplete requests so stalled clients release their worker.
        timeout = 10

        def do_GET(self):
            if not host_allowed(self.headers.get("Host")):
                self._send(403, webui.error_page(
                    "Refused", "Wrong name for this server",
                    "The request addressed this server by a name that is "
                    "not local. That is what a DNS-rebinding page looks like, "
                    "so it was refused.", '<p><a href="/">Open the home page</a></p>'))
                return
            parsed = urllib.parse.urlparse(self.path)
            capacity = getattr(self.server, '_calculations', None)
            if (parsed.path == '/healthz' or assets.is_static_path(parsed.path)
                    or capacity is None):
                self._dispatch_get(parsed)
                return
            if not capacity.acquire(timeout=.05):
                self._send(503, PlainText("The server is busy. Please try again shortly.\n"))
                return
            try:
                self._dispatch_get(parsed)
            finally:
                capacity.release()

        def _dispatch_get(self, parsed):
            # The snapshot status in the page header reads the index provenance
            # through a ContextVar, so the ~15 page functions need not carry it.
            # Reset in finally: a worker thread is reused for the next request.
            token = webui.CURRENT_SNAPSHOT.set(provenance)
            try:
                self._dispatch_get_scoped(parsed)
            finally:
                webui.CURRENT_SNAPSHOT.reset(token)

        def _dispatch_get_scoped(self, parsed):
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            try:
                page = page_for(parsed.path, params)
            except InvalidComparison as error:
                self._send(400, webui.error_page(
                    "Procurement comparison", "Complete the shortlist", str(error),
                    '<p><a href="/compare">Edit candidates →</a></p>'))
                return
            except ExportUnavailable as error:
                self._send(error.status, webui.error_page(
                    "Export unavailable", error.heading, str(error),
                    '<p><a href="/score">Back to the assessment</a></p>'))
                return
            except Exception as error:
                # A malformed query is the user's typo, not a crash. The message
                # is escaped like everything else and the server stays up.
                self._send(500, webui.error_page(
                    "Error", "That did not work", str(error),
                    '<p><a href="">Try again</a> or <a href="/">return to search</a>.</p>'))
                return
            if page is None:
                self._send(404, webui.error_page(
                    "Not found", "No such page",
                    "Nothing in this workspace answers that address.",
                    '<p><a href="/">Start again</a></p>'))
                return
            self._send(200, page)

        def _send(self, status, markup):
            if isinstance(markup, assets.Asset):
                payload, content_type = markup.body, markup.content_type
                cache_control = markup.cache_control
            else:
                payload = markup.encode("utf-8")
                kind = (markup.content_type if isinstance(markup, Download) else
                        "text/plain" if isinstance(markup, PlainText) else "text/html")
                content_type, cache_control = f"{kind}; charset=utf-8", "no-store"
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            revision = os.environ.get('RENDER_GIT_COMMIT', '')
            if 7 <= len(revision) <= 40 and all(char in '0123456789abcdef' for char in revision):
                self.send_header('X-ReTrust-Revision', revision)
            if isinstance(markup, Download):
                self.send_header("Content-Disposition", f'attachment; filename="{markup.filename}"')
            # The pages are self-contained, so the strictest policy that still
            # works is the correct one: nothing may be fetched or executed.
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; style-src 'unsafe-inline'; "
                             "font-src 'self'; form-action 'self'; "
                             "base-uri 'none'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            # Behind the hosting proxy only: HSTS on a plain-HTTP localhost
            # response would poison the developer's browser for localhost.
            if self.headers.get("X-Forwarded-Proto", "").lower() == "https":
                self.send_header("Strict-Transport-Security",
                                 "max-age=31536000; includeSubDomains")
            # Verdicts and sanctions screening have no business sitting in a
            # browser cache after the tab closes.
            self.send_header("Cache-Control", cache_control)
            if status == 503:
                self.send_header("Retry-After", "2")
            # Which code is serving this, independent of the data it serves.
            self.send_header("X-ReTrust-Build", BUILD)
            self.send_header("X-ReTrust-Workers", str(getattr(self.server, 'workers', 1)))
            self.end_headers()
            if not getattr(self, "_head_only", False):
                self.wfile.write(payload)

        def do_HEAD(self):
            """Answer HEAD the way GET would, minus the body.

            Browsers and link checkers send it, and a 501 from a tool whose whole
            point is not surprising you is a poor first impression.
            """
            self._head_only = True
            try:
                self.do_GET()
            finally:
                self._head_only = False

        def log_message(self, fmt, *args):
            pass                          # a request log on stdout helps nobody here

    return Handler


def serve(handler, host=DEFAULT_HOST, port=DEFAULT_PORT, forever=True, workers=8):
    """Use concurrent readers for the application; retain injected serial handlers.

    Existing callers that close over their own SQLite connection stay on its
    owner thread. The CLI uses build_concurrent_handler, which owns no shared
    database connection and is safe for the bounded worker pool.
    """
    httpd = (ConcurrentHTTPServer((host, port), handler, workers)
             if getattr(handler, 'concurrent_safe', False)
             else http.server.HTTPServer((host, port), handler))
    if not forever:
        return httpd
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return httpd
