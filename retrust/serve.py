"""A local web interface, for the people who actually sign purchase orders.

The terminal suits an engineer and a pipeline. It does not suit the person in
procurement who has a shortlist to settle and no reason to learn a shell, and
that person is the one the tool exists for. This serves the same assessments as
pages, in the same control-room language as the printed report.

It is deliberately small and deliberately local. One standard-library HTTP
server, bound to the loopback address unless somebody insists otherwise, GET
requests only, and no state kept between them. Nothing is written to disk and
nothing is executed: every request turns into the same function call the command
line would have made, and the result is rendered with report.py.

The security posture is the point rather than an afterthought, because a tool
that screens sanctions lists has no business opening an unauthenticated port on
a plant network by accident. See SAFETY below for what is enforced.
"""

import hashlib
import html
import http.server
import os
import pathlib
import urllib.parse
from datetime import date

from . import alternatives, batch, lev, questions, report, score, search, sensitivity, ssvc, timeline, webviews
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
EDIT_PANEL = "Edit product, firmware, or network exposure"


def build_fingerprint():
    """A short hash of the package's own source, served as a header.

    "Is the deployed code the code I have?" turned out to be the hardest
    question to answer about this service, and the expensive way to learn that
    was a silent deploy: the build ran, the data refreshed, and the index hash
    moved while three commits of fixes stayed behind. Nothing user-visible had
    to change for the site to be stale, so nothing user-visible could prove it
    current. Comparing the scoring version did not help either -- it is the same
    string across every one of those builds.

    This hashes the source instead, so any code difference shows up, and it is
    computed once per process rather than per request.
    """
    digest = hashlib.sha256()
    for path in sorted(pathlib.Path(__file__).parent.glob("*.py")):
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()[:12]


BUILD = build_fingerprint()
CONTEXT_FIELDS = ('network_exposure', 'assessment_type', 'consequence', 'interface', 'remediation')
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
No response is cached (Cache-Control: no-store) and none may be framed.
A connection that stalls is dropped after 10 seconds, so one stuck client
  cannot hold the single-threaded server.
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


def _search_page(connection, stats, query):
    """A starting point for a buyer, backed by the actual local index."""
    form = (
        '<form class="search-form" method="get" action="/">'
        '<label for="q">Product, vendor or order number</label><div class="search-line">'
        f'<input type="text" id="q" name="q" value="{_esc(query)}" '
        'placeholder="Try SIMATIC S7-1500, Moxa or a manufacturer part number" '
        f'maxlength="{MAX_QUERY}" required>'
        '<button type="submit">Find a product <span aria-hidden="true">&nbsp; →</span></button></div>'
        '<p class="helper">Use the name on your requisition. An order number gives the most precise match.</p></form>')
    chips = ('<div class="chips"><span>Try a search</span>' + ''.join(
        f'<a class="chip" href="/?q={urllib.parse.quote(q)}">{_esc(q)}</a>'
        for q in ('S7-1500', 'Moxa EDS-405A', 'Modicon M340')) + '</div>')
    if not query:
        metrics = '<div class="metrics">' + ''.join(
            f'<div class="metric" aria-label="{stats[key]:,} {label}"><strong>{stats[key]:,}</strong><span>{label}</span>'
            f'<small>{detail}</small></div>' for key, label, detail in (
                ('products', 'product entries', 'SEARCHABLE HARDWARE'),
                ('advisories', 'security advisories', 'PUBLIC VENDOR EVIDENCE'),
                ('cves', 'distinct vulnerabilities', 'TRACEABLE FINDINGS'))) + '</div>'
        body = (
            '<section class="hero"><div><p class="eyebrow">Know what you are buying</p>'
            '<h1>Better hardware decisions.<br><em>Evidence first.</em></h1>'
            '<p class="lead">Understand the cyber risk of industrial equipment before '
            'it reaches your plant. Find a product, check the evidence, and compare your options.</p>'
            '</div><div class="hero-mark" aria-hidden="true"><span>R↗</span></div></section>'
            + metrics + '<section class="panel"><div class="panel-heading">'
            '<h2>Start with a product</h2></div>' + form + chips + '</section>'
            '<div class="split"><section class="panel"><div class="panel-heading">'
            '<h2>From requisition to decision</h2><span>The workflow</span></div>'
            '<ol class="steps"><li><span class="step-number">1</span><div><b>Identify the hardware</b>'
            '<p>Match a product name or manufacturer order number.</p></div></li>'
            '<li><span class="step-number">2</span><div><b>Understand the verdict</b>'
            '<p>Review how exposed it is, what fixes exist, and how complete the evidence is.</p></div></li>'
            '<li><span class="step-number">3</span><div><b>Bring evidence to the purchase order</b>'
            '<p>Compare candidates and prepare questions for the supplier.</p></div></li></ol></section>'
            '<section class="panel"><div class="panel-heading"><h2>Explore an example</h2>'
            '<span>Live assessments</span></div>'
            '<a class="example" href="/score?vendor=ABB&amp;product=AC%20800M">'
            '<span><strong>ABB · AC 800M</strong><small>Inspect the evidence and network exposure</small></span><span class="arrow">↗</span></a>'
            '<a class="example" href="/score?vendor=Siemens&amp;product=SIMATIC%20S7-1500&amp;version=3.1.6">'
            '<span><strong>Siemens · SIMATIC S7-1500</strong><small>See how firmware changes the assessment</small></span><span class="arrow">↗</span></a>'
            '<a class="example" href="/demo"><span><strong>Take the guided demo</strong>'
            '<small>Walk through a complete procurement decision</small></span><span class="arrow">↗</span></a>'
            '</section></div>'
            f'<p class="helper">Search covers {stats["vendors"]:,} vendor spellings. '
            'Examples use this workspace’s public evidence; results can change with the data.</p>')
        return _page("ReTrust", body)

    hits = _search_hits(connection, query)
    def assessment_link(hit):
        fields = dict(vendor=hit.vendor, product=hit.name)
        if any(index_module.normalize_order_number(number) == index_module.normalize_order_number(query)
               for number in hit.order_numbers):
            fields['order_number'] = query
        return _esc('/score?' + urllib.parse.urlencode(fields))

    rows = "".join(
        f'<a class="hit" href="{assessment_link(h)}"><strong>{_esc(h.vendor)}</strong> / '
        f'{_esc(h.name)}<span class="w">{h.advisories:,} advisory record(s)'
        + (f' · {_esc(h.order_numbers[0])}' if h.order_numbers else '')
        + ' · Open assessment →</span></a>' for h in hits)
    if not hits:
        vendors = search.vendors(connection, query, limit=8)
        rows = "".join(
            f'<a class="hit" href="/vendor?name={urllib.parse.quote(v.vendor)}">'
            f'{_esc(v.vendor)}<span class="w">{v.products:,} product entries · View vendor profile →</span></a>'
            for v in vendors)
        rows = (rows and '<h2>Matching vendors</h2>' + rows) or (
            '<div class="panel"><h2>No matching product yet</h2><p class="empty">'
            'Try a shorter model name, the manufacturer, or the order number on the requisition. '
            'Missing evidence does not mean the equipment is safe.</p>'
            '<a href="/score">Enter product details manually →</a></div>')
    heading = ('<h1>Find your hardware</h1><p class="lead">Select a result to inspect its risk '
               'and add the firmware version you plan to buy.</p>')
    return _page(f"Search: {query}", heading + '<section class="panel">' + form + chips + '</section>'
                 f'<div class="section-title"><h2>Results for “{_esc(query)}”</h2>'
                 f'<span>{len(hits)} product result(s)' + (' · first 25 shown' if len(hits) == MAX_RESULTS else '')
                 + f'</span></div><div class="rows">{rows}</div>')


def _demo_page():
    stages = (
        ('Identify the exact hardware', 'Search by the order number from a requisition. '
         'Check the matched model before assessing its firmware.', '/?q=6ES7518-4AX00-1AB0', 'Find a Siemens controller'),
        ('Explain a verdict', 'See why the product received its recommendation. '
         'Review the four parts of the score, missing information and assumptions about your network.', '/score?vendor=ABB&product=AC%20800M', 'Assess ABB AC 800M'),
        ('Compare a shortlist', 'Review three examples together. These are different equipment classes '
         'to demonstrate the workflow, not interchangeable engineering alternatives.',
         '/compare?c=ABB%7CAC%20800M&c=Moxa%7CEDS-405A&c=Siemens%7CSIMATIC%20S7-1500%7C3.1.6', 'Open example comparison'),
        ('Ask better supplier questions', 'Prepare security questions to copy into your quotation request. '
         'Ask the supplier for written answers and evidence.', '/annex?vendor=Moxa&product=EDS-405A', 'Prepare supplier questions'),
    )
    cards = ''.join(
        f'<section class="panel"><span class="step-number">{i}</span><h2>{title}</h2><p>{description}</p>'
        f'<a class="button secondary" href="{_esc(url)}">{action} →</a></section>'
        for i, (title, description, url, action) in enumerate(stages, 1))
    return _page('Demo', '<p class="eyebrow">A four-step walkthrough</p>'
                 '<h1>Show the decision.<br>Then show the evidence.</h1>'
                 '<p class="lead">A guided tour for a first look or a live presentation. '
                 'Every example uses this workspace’s public evidence. Start with the first step and return here for the next one.</p>'
                 '<div class="demo-cards">' + cards + '</div>'
                 '<p class="helper">A verdict is decision support. Product fit, plant context, '
                 'and the supplier’s answer still belong in the purchasing decision.</p>', active='/demo')


# What each owner-supplied fact means when nobody answered it. Only answers
# that differ from these are forwarded, so a caller that never asks about plant
# context keeps the simpler call it always had.
UNDECLARED = {"consequence": None, "interface": "unknown",
              "assessment_type": "purchase", "remediation": "unknown"}


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
    )


def _score_page(connection, assess, context, vendor, product, version, order_number="",
                submitted=False, network_exposure=None, owner=None):
    """A verdict first, with editable inputs and the evidence below it."""
    if network_exposure not in score.NETWORK_EXPOSURES:
        network_exposure = None
    owner = owner or {}
    form = _score_form(vendor, product, version, order_number, network_exposure,
                       owner.get("consequence"), owner.get("interface", "unknown"),
                       owner.get("assessment_type", "purchase"),
                       owner.get("remediation", "unknown"))
    if not (vendor or product or order_number):
        notice = ('<p class="notice" role="alert">Enter a manufacturer order number, '
                  'or a vendor and product, before assessing.</p>' if submitted else '')
        return _page('Score', '<h1>Assess a product</h1><p class="lead">'
                     'Check the equipment before you buy it. Start with its order number '
                     'or model; leave technical details unknown if you are unsure.</p>'
                     + notice + form)
    assessment, resolution, findings = _run_assessment(
        assess, vendor, product, version, order_number, network_exposure, owner)
    parameters = urllib.parse.urlencode(dict(
        vendor=vendor, product=product, version=version,
        order_number=order_number, network_exposure=network_exposure or "",
        **{key: value or "" for key, value in owner.items()}))
    body = '<h1>Product assessment</h1>'
    tools = (f'<details class="assessment-edit"><summary>{EDIT_PANEL}</summary>' + form + '</details>'
             '<details class="assessment-downloads"><summary>Save or share this assessment</summary>'
             '<p class="helper">Download a report to discuss with your supplier or purchasing team.</p>'
             '<div class="actions">'
             f'<a class="button secondary" href="/export.html?{_esc(parameters)}">Download report ↓</a>'
             f'<a class="button secondary" href="/export.json?{_esc(parameters)}">Technical data (JSON) ↓</a>'
             '<a class="button secondary" href="/">Find another product</a></div></details>')
    if not version and resolution.resolved:
        tools = ('<p class="notice"><b>Firmware not specified.</b> All known affected versions '
                 'are in scope. Add the firmware you plan to buy using '
                 f'\u201c{EDIT_PANEL}\u201d below.</p>') + tools
    body += report.body([(assessment, resolution, findings)], weights=context['weights'], tools=tools)
    if resolution.resolved:
        named = resolution.matches[0]
        query = urllib.parse.urlencode(dict(vendor=named.vendor, product=named.name, version=version))
        candidate_fields = dict(
            vendor_0=vendor or ('' if order_number else named.vendor),
            product_0=product or ('' if order_number else named.name),
            version_0=version or '', order_number_0=order_number or '',
            network_exposure_0=network_exposure or '')
        candidate_fields.update({f'{key}_0': owner.get(key) or default or ''
                                 for key, default in UNDECLARED.items()})
        candidate_query = urllib.parse.urlencode(candidate_fields)
        body += ('<section class="panel" style="margin-top:24px"><h2>Take the next step</h2><div class="actions">'
                 f'<a class="button secondary" href="/compare?{_esc(candidate_query)}">Compare this product →</a>'
                 f'<a class="button secondary" href="/annex?{_esc(query)}">Prepare supplier questions →</a>'
                 f'<a class="button secondary" href="/alternatives?{_esc(query)}">Find alternatives →</a></div>'
                 f'<p class="helper"><a href="/vendor?name={urllib.parse.quote(named.vendor)}">Vendor profile</a>'
                 f' · <a href="/timeline?{_esc(query)}">Advisory timeline</a>'
                 f' · <a href="/lev?{_esc(query)}">Check past exploitation estimates</a>'
                 f' · <a href="/ssvc?{_esc(query)}">Plan response priorities</a></p></section>')
    else:
        suggestions = search.suggest(connection, vendor=vendor, product=product)
        rows = ''.join(
            f'<a class="hit" href="/score?vendor={urllib.parse.quote(h.vendor)}'
            f'&amp;product={urllib.parse.quote(h.name)}">{_esc(h.vendor)} / {_esc(h.name)}</a>'
            for h in suggestions['products'][:8])
        if rows:
            body += f'<h2>Did you mean</h2><div class="rows">{rows}</div>'
    return _page(f'Score: {assessment.product}', body)


def _field(id_, name, label, value='', placeholder='', required=False):
    return (f'<div><label for="{id_}">{label}</label><input type="text" id="{id_}" '
            f'name="{name}" value="{_esc(value)}" placeholder="{_esc(placeholder)}" '
            f'maxlength="{MAX_QUERY}"' + (' required' if required else '') + '></div>')


def _lookup_form(route, action, vendor, product, version=None, product_optional=False, extra=''):
    """A consistent entry point for the evidence pages."""
    fields = (_field('v', 'vendor', 'Manufacturer (vendor)', vendor, 'e.g. ABB', required=True)
              + _field('p', 'product', 'Product / model' + (' (optional)' if product_optional else ''),
                       product, 'e.g. AC 800M', required=not product_optional))
    if version is not None:
        fields += _field('f', 'version', 'Firmware version (optional)', version, 'e.g. 3.1.6')
    helper = ('Leave the product blank to see the manufacturer’s full history.' if product_optional else
              'Use the model on the quotation or equipment label. Firmware is the software running on the equipment; leave its version blank if unknown.'
              if version is not None else 'Use the model on the quotation or equipment label.')
    return (f'<form class="lookup-form" method="get" action="{route}">'
            f'<div class="lookup-grid">{fields}</div><p class="helper">{helper} '
            '<a href="/">Find the exact product in Explore</a>.</p>' + extra
            + f'<button type="submit">{action}</button></form>')


def _lookup_controls(form, populated, label='Change product'):
    return (f'<details class="lookup-edit"><summary>{label}</summary>{form}</details>'
            if populated else form)


def _lookup_example(route, vendor='ABB', product='AC 800M'):
    query = urllib.parse.urlencode(dict(vendor=vendor, product=product))
    return (f'<p class="helper">Try an example: <a href="{route}?{_esc(query)}">'
            f'{_esc(vendor)} · {_esc(product)}</a>. Examples use the loaded public evidence.</p>')


def _lookup_error():
    return ('<p class="notice" role="alert">Enter both the manufacturer and product/model. '
            'If you are unsure, <a href="/">find the product in Explore</a> first.</p>')


def _product_next_steps(vendor, product, version=''):
    query = _esc(urllib.parse.urlencode(dict(vendor=vendor, product=product, version=version)))
    return ('<div class="actions">'
            f'<a class="button secondary" href="/score?{query}">Assess this product</a>'
            f'<a class="button secondary" href="/annex?{query}">Prepare supplier questions</a></div>')


def _choice(name, label, table, chosen, blank=None, helper=''):
    """One labelled dropdown over an exposure table.

    Options and their wording come from the table that scores them, so the form
    can never offer a choice the model does not know, or describe it differently.
    """
    options = ''
    if blank:
        options += f'<option value="">{blank}</option>'
    for key, entry in table.items():
        text = entry[0] if isinstance(entry, tuple) else entry
        selected = ' selected' if key == chosen else ''
        options += f'<option value="{key}"{selected}>{_esc(text)}</option>'
    return (f'<div><label for="{name}">{label}</label>'
            f'<select id="{name}" name="{name}">{options}</select>'
            + (f'<p class="helper">{helper}</p>' if helper else '') + '</div>')


def _owner_fields(network_exposure=None, consequence=None, interface='unknown',
                  assessment_type='purchase', remediation='unknown', suffix=''):
    """The facts only the asset owner has, each optional and each explained.

    ReTrust supplies the vulnerability intelligence; these describe the plant.
    Nothing here is verified, so every one is labelled operator-reported, and
    leaving one unanswered keeps it unresolved rather than guessing either way.
    """
    return ('<div class="form-grid">'
            + _choice('assessment_type' + suffix, 'Are you buying or reviewing installed equipment?',
                      score.ASSESSMENT_TYPES, assessment_type,
                      helper='Buying it, or assessing one already installed.')
            + _choice('network_exposure' + suffix, 'What is the equipment connected to?',
                      score.NETWORK_EXPOSURES, network_exposure,
                      blank='Unknown — ask your technical team',
                      helper='Operator-reported, not verified. IT–OT means a connection to business IT; Internet–OT means internet access. These choices do not prove every weakness can be reached.')
            + _choice('consequence' + suffix, 'If the equipment were attacked, what could happen?',
                      score.CONSEQUENCES, consequence, blank='Unknown — needs engineering review',
                      helper='Ask your operations or safety team. Unknown consequences receive no reduction in impact.')
            + _choice('interface' + suffix, 'Can an attacker reach the affected service?',
                      score.INTERFACES, interface,
                      helper='Choose “Not established” if unsure. A technical owner must verify a block for all in-scope findings before you select it.')
            + _choice('remediation' + suffix, 'Have the fixes or protective measures been verified?',
                      score.REMEDIATIONS, remediation,
                      helper='“Applied” or “verified” must cover all in-scope findings. A plan or an available download does not mean the equipment is fixed.')
            + '</div>')


def _score_form(vendor, product, version, order_number='', network_exposure=None,
                consequence=None, interface='unknown',
                assessment_type='purchase', remediation='unknown'):
    using_model = ' open' if (vendor or product) and not order_number else ''
    return ('<form class="form-panel" method="get" action="/score">'
            '<div class="order-field">' + _field('o', 'order_number', 'Manufacturer order number', order_number,
                                                 'e.g. 6ES7518-4AX00-1AB0') + '</div>'
            f'<details class="form-options"{using_model}><summary>Use vendor and model instead</summary>'
            '<p class="helper">Use these if you do not have an order number. If both are entered, they must agree.</p>'
            '<div class="candidate-grid">' + _field('v', 'vendor', 'Vendor', vendor, 'e.g. Siemens')
            + _field('p', 'product', 'Product / model', product, 'e.g. SIMATIC S7-1500')
            + '</div></details>'
            + _field('f', 'version', 'Firmware version (optional)', version, 'e.g. 3.1.6')
            + '<p class="helper">Firmware is the software running on the equipment. Leave blank if unknown; the result will show what still needs checking.</p>'
            '<details class="form-options"><summary>Site details and fixes (optional)</summary>'
            '<p class="helper">You can get a first assessment without these answers. '
            'Leave them unknown if unsure, then ask your technical team. '
            'ReTrust uses your answers; it does not inspect your network.</p>'
            + _owner_fields(network_exposure, consequence, interface,
                            assessment_type, remediation)
            + '</details>'
            + '<button type="submit">Assess product →</button></form>')


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
                     bands=context.get('bands')) if assessment.inputs else None)
        entries.append((block, query, stability))
    rank = {'PREFER': 0, 'CONDITIONAL': 1, 'AVOID': 2, 'NOT ASSESSED': 3}
    entries.sort(key=lambda entry: (rank.get(entry[0][0].verdict, 4),
                                   -(entry[0][0].score or 0)))
    return entries


def _comparison_warning(rows):
    return ('<p class="notice">Some candidates have firmware specified and others do not. '
            'Add a version for each to compare on equal terms.</p>'
            if any(row[2] for row in rows) and not all(row[2] for row in rows) else '')


def _compare_page(assess, context, candidates, submitted=False):
    """A shortlist with separate input fields and ranked, explainable results."""
    filled = _comparison_rows(candidates)
    boxes = ''
    for i in range(min(MAX_CANDIDATES, max(2, len(filled) + 1))):
        row = filled[i] if i < len(filled) else [''] * len(COMPARISON_FIELDS)
        vendor, product, version, order_number = row[:4]
        network, owner = _candidate_context(row)
        saved = network or any(owner[key] != default for key, default in UNDECLARED.items())
        boxes += (f'<fieldset><legend>Candidate {i + 1}</legend><div class="candidate-grid">'
                  + _field(f'co{i}', f'order_number_{i}', 'Manufacturer order number', order_number,
                           'e.g. 6ES7518-4AX00-1AB0')
                  + _field(f'cv{i}', f'vendor_{i}', 'Vendor', vendor, 'e.g. Moxa')
                  + _field(f'cp{i}', f'product_{i}', 'Product / model', product, 'e.g. EDS-405A')
                  + _field(f'cf{i}', f'version_{i}', 'Firmware (optional)', version, 'e.g. 3.0')
                  + '</div><details class="form-options"><summary>Site details and fixes'
                  + (' (saved)' if saved else ' (optional)') + '</summary>'
                  + _owner_fields(network, suffix=f'_{i}', **owner) + '</details></fieldset>')
    form = ('<form method="get" action="/compare">' + boxes
            + '<p class="helper">Use an order number, or a vendor and model. If you enter both, '
            'they must agree. Leave unused candidates blank. Another row appears after comparing, '
            'up to 12 candidates. Each candidate keeps its own site details and fixes.</p>'
            '<button type="submit">Compare candidates →</button></form>')
    heading = ('<h1>Compare your candidates</h1><p class="lead">Review products side by side before '
               'choosing what to buy. Higher scores are more favourable; purchase blockers override the score. '
               'An engineer still needs to confirm that each product can do the required job.</p>')
    if not _valid_comparison(filled):
        notice = ('<p class="notice" role="alert">Enter an order number, vendor or product in each '
                  'used candidate row before comparing. Firmware alone does not identify '
                  'a product.</p>' if submitted else '')
        example = ('<p class="helper"><a href="/compare?c=ABB%7CAC%20800M&amp;c=Moxa%7CEDS-405A">'
                   'Open an example comparison</a>. These examples demonstrate the tool; they are '
                   'different equipment types, not interchangeable products.</p>')
        return _page('Procurement comparison', heading + notice + form + example)
    entries = _comparison_results(assess, context, filled)
    blocks = [block for block, _, _ in entries]
    stabilities = {id(block[0]): stability for block, _, stability in entries if stability}
    parameters = _comparison_parameters(filled)
    downloads = '<details><summary>Save or share this comparison</summary><div class="actions">' + ''.join(
        f'<a class="button secondary" href="/compare.{extension}?{_esc(parameters)}">'
        f'Download {label} ↓</a>' for extension, label in
        (('html', 'comparison report'), ('json', 'comparison JSON'), ('csv', 'comparison CSV'))) + '</div></details>'
    warning = _comparison_warning(filled)
    return _page('Procurement comparison', heading + warning
                 + '<details><summary>Edit candidates or add another</summary>' + form + '</details>'
                 + downloads
                 + report.body(blocks, stabilities=stabilities, weights=context['weights']),
                 f'{len(blocks)} candidate(s)')


def _alternatives_page(connection, assess, vendor, product, version):
    """Same-family candidates, with the same caveat the terminal prints."""
    form = _lookup_form('/alternatives', 'Find alternatives', vendor, product, version)
    heading = ('<h1>Find other products to review</h1><p class="lead">Explore related products '
               'from the same manufacturer. Ask an engineer to confirm they can do the same job; '
               'this is not a recommendation to substitute.</p>')
    if not (vendor and product):
        return _page('Alternatives', heading + (_lookup_error() if vendor or product else '')
                     + form + _lookup_example('/alternatives', 'Siemens', 'SIMATIC S7-1500'))

    subject, resolution, _ = assess(vendor, product, version or None)
    named = resolution.matches[0] if resolution.matches else None
    family_vendor = named.vendor if named else vendor
    family_name = named.name if named else product
    if not resolution.resolved:
        return _page('Alternatives', heading + form
                     + f'<p class="notice">{_esc(resolution.reason)}. '
                     '<a href="/">Search for the exact model</a> and try again.</p>')
    body = heading + _lookup_controls(form, True)
    shown = "no score" if subject.score is None else f"{subject.score}/100"
    body += (f'<div class="tw"><p><b>{_esc(subject.product)}</b> &mdash; '
             f'{_esc(subject.verdict)}, {shown}.</p></div>')

    options, skipped = alternatives.find(
        connection, family_vendor, family_name,
        lambda v, p: assess(v, p), limit=8,
        exclude={normalize_name(m.name) for m in resolution.matches})
    body += '<p>Open a product name to check its exact model and firmware with your engineer.</p>'
    if version:
        body += (f'<p class="notice">Your original product uses firmware {_esc(version)}. '
                 'Alternatives have no firmware specified. Check each version before comparing scores.</p>')

    if options:
        rows = "".join(
            f'<tr><td><a href="/score?vendor='
            f'{urllib.parse.quote(family_vendor)}&amp;product='
            f'{urllib.parse.quote(o.name)}">'
            f'{_esc(o.product)}</a></td>'
            f'<td style="color:{report.VERDICT_COLOR.get(o.verdict, report.INERT)};'
            f'font-weight:700">{_esc(o.verdict)}</td>'
            f'<td class="n">{o.score:.1f}</td><td class="n">{o.cves}</td></tr>'
            for o in options)
        body += ('<div class="tw" tabindex="0" role="region" aria-label="Alternative products; scroll sideways for more columns">'
                 '<p class="table-scroll-hint">Scroll sideways to see all columns →</p>'
                 '<table><thead><tr><th>Product — open for an assessment</th>'
                 '<th>Verdict</th><th class="n">Score / 100</th><th class="n">Known vulnerabilities</th></tr></thead>'
                 f'<tbody>{rows}</tbody></table></div>')
        if subject.score is not None:
            better = sum(1 for o in options if o.score > subject.score)
            body += (f'<p>{better} of {len(options)} scored above '
                     f'{_esc(subject.product)} ({subject.score}/100).</p>')
    else:
        body += ('<p class="empty">No related product met the requirements for this list. '
                 'Ask your supplier for other candidates and assess them individually.</p>')
    for reason, count in (skipped or {}).items():
        if count:
            label = {'gated': 'have purchase blockers', 'unassessable': 'could not receive a favourable assessment',
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
    heading = ('<h1>Advisory timeline</h1><p class="lead">See when security notices were published '
               'and whether they offered a fix. More notices can reflect better reporting; '
               'a quiet year does not prove that equipment is secure.</p>')
    if not vendor:
        return _page('Timeline', heading + ('<p class="notice" role="alert">Enter the manufacturer to show its history.</p>' if product else '')
                     + form + _lookup_example('/timeline'))

    from . import match
    if product:
        resolution = match.resolve(connection, vendor=vendor, product=product)
        if not resolution.resolved:
            return _page('Timeline', heading + form +
                         f'<p class="empty">{_esc(resolution.reason)}. <a href="/">Find the exact model in Explore</a>.</p>')
        subject = f'{vendor} {product}'.strip()
        line = timeline.build(connection, [(m.advisory_id, m.product_id)
                                           for m in resolution.matches])
    else:
        key = _vendor_key(connection, vendor)
        if key is None:
            return _page("Timeline", heading + form +
                         f'<p class="empty">vendor {_esc(vendor)} does not '
                         'appear in the available data. Check the spelling or search in Explore.</p>')
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


def _annex_text(connection, assess, dossier, context, vendor, product, version):
    """The annex as bare text: what actually gets pasted into an RFQ.

    Returned as text/plain so "select all, copy" needs no care about markup,
    and a procurement template can curl it straight into a document.
    """
    if not (vendor or product):
        return "Give vendor and product: /annex.txt?vendor=...&product=..."
    assessment, _, items = _annex_data(connection, assess, dossier, context, vendor, product, version)
    return questions.format_report(assessment.product, items)


def _annex_page(connection, assess, dossier, context, vendor, product, version):
    """The RFQ security annex, as text a buyer pastes into a request."""
    form = _lookup_form('/annex', 'Prepare supplier questions', vendor, product, version)
    heading = ('<h1>Questions to send your supplier</h1><p class="lead">Prepare questions '
               'for your email or quotation request. Ask for written answers and evidence, '
               'then have your technical team review the replies.</p>')
    if not (vendor and product):
        return _page('RFQ annex', heading + (_lookup_error() if vendor or product else '')
                     + form + _lookup_example('/annex', 'Moxa', 'EDS-405A'))

    assessment, resolution, items = _annex_data(connection, assess, dossier, context, vendor, product, version)
    annex = questions.format_report(assessment.product, items)
    text_query = (f"vendor={urllib.parse.quote(vendor)}"
                  f"&amp;product={urllib.parse.quote(product)}"
                  + (f"&amp;version={urllib.parse.quote(version)}" if version
                     else ""))
    body = heading + _lookup_controls(form, True)
    if not resolution.resolved:
        body += ('<p class="notice"><b>Product not matched.</b> These are starting questions '
                 'to confirm its identity and security information. They are not findings about this product.</p>')
    body += (f'<div class="actions"><a class="button" href="/annex.txt?{text_query}">Open text to copy</a></div>'
             '<p class="helper">In the text version, select all and copy into your email or quotation request. '
             'ReTrust does not send anything to the supplier.</p>'
             + webviews.supplier_questions(assessment.product, items)
             + '<details><summary>Complete text and technical reasons</summary>'
             f'<pre class="tw" style="white-space:pre-wrap">{_esc(annex)}</pre></details>')
    return _page(f'Annex: {assessment.product}', body)


def _select(name, label, options, chosen):
    """One labelled dropdown, in the same legend style as the text inputs."""
    rendered = "".join(
        f'<option value="{_esc(option)}"'
        + (" selected" if option == chosen else "")
        + f">{_esc(options[option] if isinstance(options, dict) else option)}</option>"
        for option in options)
    return (f'<label for="{name}" style="margin-top:.8rem">{_esc(label)}</label>'
            f'<select id="{name}" name="{name}">{rendered}</select>')


def _ssvc_page(connection, assess, vendor, product, version,
               exposure, automatable, impact):
    """CERT/CC's deployer tree, with the three plant facts asked out loud."""
    settings = ('<details class="form-options"><summary>Review the technical team’s settings</summary>'
        + _select("exposure", "How accessible is the system? (describes your plant)",
                  webviews.ACCESS_LABELS, exposure)
        + _select("automatable", "Could an attacker carry out the attack automatically?",
                  {"yes": "Yes", "no": "No"}, automatable)
        + _select("impact", "Potential effect on people and operations", webviews.IMPACT_LABELS, impact)
        + '<p class="helper">Ask your technical and operations teams to confirm these settings. '
          'The choices apply to every vulnerability in this assessment.</p>'
        + '</details><p class="helper">The selected access, automation and impact settings are assumptions. '
          'Review them with your technical team before using the suggested timing.</p>')
    form = _lookup_form('/ssvc', 'Show response priorities', vendor, product, version, extra=settings)
    heading = ('<h1>What should be fixed first?</h1><p class="lead">Get suggested timing '
               'for reviewing and fixing known security weaknesses. Your technical and operations '
               'teams should confirm the settings and agree on safe maintenance steps.</p>')
    if exposure not in ssvc.EXPOSURE or automatable not in ssvc.AUTOMATABLE or impact not in ssvc.HUMAN_IMPACT:
        return _page("SSVC", heading + '<p class="notice" role="alert">Choose one of the listed '
                     'access, automation and impact options, then try again.</p>' + form)
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
    heading = ('<h1>Past exploitation estimate</h1><p class="lead">Could these known security '
               'weaknesses have been used in attacks already? Compare a historical model estimate '
               'with confirmed public records.</p>')
    if not (vendor and product):
        return _page('LEV', heading + (_lookup_error() if vendor or product else '')
                     + form + _lookup_example('/lev', 'Schneider Electric', 'Modicon M340 PLC modules'))
    if not index_module.has_epss_history(connection):
        return _page("LEV", heading + form +
                     '<p class="empty">Historical attack estimates are not available in this workspace. '
                     'Ask the workspace owner to refresh the historical data. This is missing data, not a zero risk result.</p>')
    assessment, resolution, findings = assess(vendor, product)
    if not resolution.resolved:
        return _page("LEV", heading + form +
                     f'<p class="empty">{_esc(resolution.reason)}. Check the name or '
                     '<a href="/">find the product in Explore</a>.</p>')
    cves = sorted({f.cve for f in findings})
    history = index_module.epss_history(connection, cves)
    signals = {f.cve: f for f in findings}
    cached = index_module.lev_estimates(connection)
    estimates = [lev.estimate(c, history.get(c, []), in_kev=signals[c].in_kev,
                              current_epss=signals[c].epss) for c in cves]
    return _page(f"LEV: {assessment.product}",
                 heading + _lookup_controls(form, True) + webviews.exploitation(
                     assessment.product, estimates,
                     corpus_share=lev.baseline(cached)["share"] if cached else None,
                     kev_loaded=any(p['source'] == 'CISA KEV' for p in index_module.provenance(connection)))
                 + _product_next_steps(vendor, product))


def _vendor_page(connection, dossier, context, name):
    form = ('<form class="lookup-form" method="get" action="/vendor">'
            + _field('n', 'name', 'Manufacturer', name, 'e.g. ABB, Siemens or Moxa', required=True)
            + '<button type="submit">View manufacturer profile</button></form>')
    heading = ('<h1>Vendor profile</h1><p class="lead">Check a manufacturer’s published '
               'security notices, supplier restrictions and certification records. '
               'Use this to prepare questions; the notice count is not a safety ranking.</p>')
    if not name:
        return _page('Vendor', heading + form
                     + '<p class="helper">Try an example: <a href="/vendor?name=ABB">ABB</a>, '
                     '<a href="/vendor?name=Siemens">Siemens</a> or <a href="/vendor?name=Moxa">Moxa</a>.</p>')
    profile = dossier.build(connection, name, screening=context["screening"],
                            certificates=context["certificates"])
    body = heading + _lookup_controls(form, True, 'Change manufacturer') + webviews.vendor_profile(profile)
    if not profile.known:
        body += '<p><a href="/">Check the manufacturer spelling in Explore</a>, or ask the supplier for its published security notices.</p>'
    if profile.known:
        body += (f'<p class="empty"><a href="/?q={urllib.parse.quote(name)}">'
                 "Search this vendor's products</a> &middot; "
                 f'<a href="/timeline?vendor={urllib.parse.quote(name)}">'
                 "Advisory timeline</a></p>")
    return _page(f"Vendor: {name}", body)


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
    rows = "".join(f"<tr><td>{_esc(stat_names.get(k, k.replace('_', ' ')))}</td>"
                   f"<td class=\"n\">{v:,}</td></tr>"
                   for k, v in stats.items())
    sources = "".join(
        f"<tr><td>{_esc(p['source'])}</td><td>{_esc(p['detail'])}</td>"
        f"<td class=\"n\">{_esc(p['captured'])}</td></tr>" for p in provenance)
    return _page("About", f"""<h1>Data &amp; methodology</h1>
<p class="lead">Understand the recommendation, check the evidence, and see
which information is still missing.</p>
<details><summary>Which page should I use?</summary>
<dl class="term-list">
<dt><a href="/">Explore</a></dt><dd>Find the exact manufacturer and model from an order number or product name.</dd>
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
<h2>What the recommendation means</h2>
<dl class="term-list">
<dt>PREFER — consider for your shortlist</dt><dd>Complete the supplier checks and confirm that the product is suitable before approving a purchase.</dd>
<dt>CONDITIONAL — review before deciding</dt><dd>Ask your technical team to review the risks and missing information.</dd>
<dt>AVOID — advised against purchase</dt><dd>A purchase blocker or a low score makes this an unfavourable assessment. Read the stated reasons.</dd>
<dt>NOT ASSESSED — more information needed</dt><dd>Confirm the exact product and firmware, then ask for missing evidence.</dd>
</dl>
<section class="panel"><h2>How a verdict is reached</h2>
<ol class="steps">
<li><span class="step-number">1</span><div><b>Identify the exact product</b>
<p>Use the order number from the supplier’s quotation and add the firmware version.
If ReTrust cannot match the product, it reports NOT ASSESSED. Unconfirmed firmware
ranges remain visible for review.</p></div></li>
<li><span class="step-number">2</span><div><b>Check for purchase blockers</b>
<p>Confirmed exploitation affecting the device firmware and supplier restrictions can
trigger AVOID. A blocker overrides the numerical score. Issues reported only in
bundled software are flagged separately for technical review.</p></div></li>
<li><span class="step-number">3</span><div><b>Combine four kinds of evidence</b>
<p>The default score weighs exposure safety (60%), available fixes (20%), vendor
security practices (15%) and certification evidence (5%). Network access contributes
to exposure safety; it does not add a separate score. Missing evidence and operator
assumptions are shown with the result.</p></div></li>
</ol></section>
<details class="vector"><summary>Scoring formula and its limits</summary>
<p><code>S = E^0.60 × P^0.20 × V^0.15 × C^0.05</code>, using scores from 1 to 100.
E is exposure safety, P is available fixes, V is vendor practices, and C is certification evidence.
These are the default weights; individual reports show the weights actually used.</p>
<p>A part with no measurable evidence is excluded and the remaining weights are adjusted.
Certification can improve the result but cannot lower it. Purchase blockers still override the score.
An 80/100 score does not mean the product is 80% secure or predict the chance of a compromise.</p></details>
<h2>Common terms in plain language</h2>
<dl class="term-list"><dt>Vulnerability / CVE</dt><dd>A known security weakness. A CVE number is its reference ID.</dd>
<dt>Severity / CVSS</dt><dd>How serious the weakness could be, rated out of 10. It does not say how likely an attack is.</dd>
<dt>EPSS</dt><dd>A model estimate of exploitation in the next 30 days, shown as a percentage.</dd>
<dt>CISA KEV</dt><dd>A public list of vulnerabilities confirmed to have been exploited. A missing entry does not prove no attack happened.</dd>
<dt>LEV</dt><dd>A model estimate of earlier exploitation, built from historical EPSS scores. It does not show whether your own equipment was attacked.</dd>
<dt>Firmware</dt><dd>The software running inside the equipment. Its version helps determine which vulnerabilities apply.</dd></dl>
<h2>Data available in this workspace</h2>
<div class="tw"><table><thead><tr><th>Holds</th><th class="n">Count</th></tr></thead>
<tbody>{rows}</tbody></table></div>
<h2>Where the data came from</h2>
<div class="tw"><table><thead><tr><th>Source</th><th>What was loaded</th><th class="n">Recorded on</th>
</tr></thead><tbody>{sources}</tbody></table></div>
<p class="empty">Certification evidence comes from the ISASecure certified-component,
-process and -system directories, the Common Criteria certified-products list, and a
small curated layer for IEC 62443 certificates issued outside those directories
(each curated entry names its source and says to verify with the certifying body).
Supplier screening uses the trade.gov Consolidated Screening List and the FCC
Covered List. <a href="https://github.com/MRALPHA20/retrust">Source code on
GitHub</a>.</p>
<h2>What this server does and does not do</h2>
<p>The website displays assessments and downloads. It does not scan devices,
apply patches or change equipment.</p>
<details><summary>Technical server safety details</summary><pre style="white-space:pre-wrap">{_esc(SAFETY)}</pre></details>
<p class="empty">{deployment}</p>""")


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
        'generated': date.today().isoformat(), 'stability_samples': 300,
        'warnings': (['Some candidates have firmware specified and others do not. '
                      'Add a version for each to compare on equal terms.']
                     if _comparison_warning(rows) else [])})
    return Download(batch.dumps(payload), 'retrust-comparison.json', 'application/json')


def _export(assess, context, provenance, path, vendor, product, version, order_number,
            network_exposure=None, owner=None):
    if network_exposure not in score.NETWORK_EXPOSURES:
        network_exposure = None
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


def build_handler(connection, assess, context, dossier, stats, provenance,
                  host, port):
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
        first = lambda key: (params.get(key) or [""])[0][:MAX_QUERY].strip()
        if path == "/healthz":
            connection.execute("SELECT 1 FROM advisory LIMIT 1").fetchone()
            return PlainText("ok\n")
        if path == "/robots.txt":
            return PlainText("User-agent: *\nDisallow: /\n")
        if path == "/demo":
            return _demo_page()
        if path in ("/export.html", "/export.json"):
            return _export(assess, context, provenance, path,
                           first("vendor"), first("product"), first("version"),
                           first("order_number"), first("network_exposure"),
                           _owner_from(first))
        if path in ("/compare.html", "/compare.json", "/compare.csv"):
            return _export_comparison(assess, context, provenance, path, _candidate_rows(params))
        if path == "/":
            return _search_page(connection, stats, first("q"))
        if path == "/score":
            return _score_page(connection, assess, context, first("vendor"),
                               first("product"), first("version"), first("order_number"),
                               submitted=any(key in params for key in
                                             ("vendor", "product", "version", "order_number")),
                               network_exposure=first("network_exposure"),
                               owner=_owner_from(first))
        if path == "/compare":
            return _compare_page(assess, context,
                                 _candidate_rows(params),
                                 submitted=any(key == "c" or key.startswith(
                                     ("vendor_", "product_", "version_", "order_number_")) for key in params))
        if path == "/alternatives":
            return _alternatives_page(connection, assess, first("vendor"),
                                      first("product"), first("version"))
        if path == "/timeline":
            return _timeline_page(connection, first("vendor"), first("product"))
        if path == "/annex":
            return _annex_page(connection, assess, dossier, context,
                               first("vendor"), first("product"),
                               first("version"))
        if path == "/annex.txt":
            return PlainText(_annex_text(connection, assess, dossier, context,
                                         first("vendor"), first("product"),
                                         first("version")))
        if path == "/ssvc":
            return _ssvc_page(connection, assess, first("vendor"),
                              first("product"), first("version"),
                              first("exposure") or "controlled",
                              first("automatable") or "yes",
                              first("impact") or "medium")
        if path == "/lev":
            return _lev_page(connection, assess, first("vendor"),
                             first("product"))
        if path == "/vendor":
            return _vendor_page(connection, dossier, context, first("name"))
        if path == "/about":
            return _about_page(stats, provenance, host, port)
        return None

    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "ReTrust"
        sys_version = ""                  # the Python version is nobody's business

        # A client that connects and never finishes its request would hold
        # the single thread forever. Ten seconds is generous for a loopback.
        timeout = 10

        def do_GET(self):
            if not host_allowed(self.headers.get("Host")):
                self._send(403, _page(
                    "Refused", "<h1>Wrong name for this server</h1>"
                    "<p>The request addressed this server by a name that is "
                    "not local. That is what a DNS-rebinding page looks like, "
                    "so it was refused.</p>"))
                return
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            try:
                page = page_for(parsed.path, params)
            except InvalidComparison as error:
                self._send(400, _page("Procurement comparison", '<h1>Complete the shortlist</h1>'
                                      f'<p role="alert">{_esc(error)}</p>'
                                      '<a href="/compare">Edit candidates →</a>'))
                return
            except Exception as error:
                # A malformed query is the user's typo, not a crash. The message
                # is escaped like everything else and the server stays up.
                self._send(500, _page("Error", "<h1>That did not work</h1>"
                                      f"<p>{_esc(error)}</p>"))
                return
            if page is None:
                self._send(404, _page("Not found", "<h1>No such page</h1>"
                                      '<p><a href="/">Start again</a>.</p>'))
                return
            self._send(200, page)

        def _send(self, status, markup):
            payload = markup.encode("utf-8")
            kind = (markup.content_type if isinstance(markup, Download) else
                    "text/plain" if isinstance(markup, PlainText) else "text/html")
            self.send_response(status)
            self.send_header("Content-Type", f"{kind}; charset=utf-8")
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
                             "form-action 'self'; base-uri 'none'; "
                             "frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            # Verdicts and sanctions screening have no business sitting in a
            # browser cache after the tab closes.
            self.send_header("Cache-Control", "no-store")
            # Which code is serving this, independent of the data it serves.
            self.send_header("X-ReTrust-Build", BUILD)
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


def serve(handler, host=DEFAULT_HOST, port=DEFAULT_PORT, forever=True):
    """Run the server. Returns it unstarted when `forever` is false, for tests.

    Single-threaded on purpose. A SQLite connection belongs to the thread that
    opened it, and this is one person looking at their own index: threading would
    buy nothing and cost either a per-thread connection pool or the
    check_same_thread escape hatch, which is how corruption gets in. Responses
    are milliseconds, and HTTP/1.0 without keep-alive means no request can hold
    the queue.
    """
    httpd = http.server.HTTPServer((host, port), handler)
    if not forever:
        return httpd
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return httpd
