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

import html
import http.server
import urllib.parse
from datetime import date

from . import alternatives, batch, lev, questions, report, search, sensitivity, ssvc, timeline
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
MAX_CANDIDATES = 12
MAX_QUERY = 200
MAX_RESULTS = 25

SAFETY = """\
GET only; no request body is ever read.
No path is used as a filename, so no file outside the index can be reached.
Nothing is written and no subprocess is run.
Every value reaching a page goes through html.escape.
Bound to 127.0.0.1 unless --host says otherwise, and that is printed when it is.
The Host header must name this machine, so a DNS-rebinding page in a browser
  cannot read the index through it.
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
            '<h2>Start with a product</h2><span>01 / Explore</span></div>' + form + chips + '</section>'
            '<div class="split"><section class="panel"><div class="panel-heading">'
            '<h2>From requisition to decision</h2><span>The workflow</span></div>'
            '<ol class="steps"><li><span class="step-number">1</span><div><b>Identify the hardware</b>'
            '<p>Match a product name or manufacturer order number.</p></div></li>'
            '<li><span class="step-number">2</span><div><b>Understand the verdict</b>'
            '<p>Review exploitation, severity, available fixes, and the quality of the evidence.</p></div></li>'
            '<li><span class="step-number">3</span><div><b>Bring evidence to the purchase order</b>'
            '<p>Compare candidates and prepare questions for the supplier.</p></div></li></ol></section>'
            '<section class="panel"><div class="panel-heading"><h2>Explore an example</h2>'
            '<span>Live assessments</span></div>'
            '<a class="example" href="/score?vendor=ABB&amp;product=AC%20800M">'
            '<span><strong>ABB · AC 800M</strong><small>Inspect the five scoring pillars</small></span><span class="arrow">↗</span></a>'
            '<a class="example" href="/score?vendor=Siemens&amp;product=SIMATIC%20S7-1500&amp;version=3.1.6">'
            '<span><strong>Siemens · SIMATIC S7-1500</strong><small>See how firmware changes the assessment</small></span><span class="arrow">↗</span></a>'
            '<a class="example" href="/demo"><span><strong>Take the guided demo</strong>'
            '<small>Walk through a complete procurement decision</small></span><span class="arrow">↗</span></a>'
            '</section></div>'
            f'<p class="helper">Search covers {stats["vendors"]:,} vendor spellings. '
            'Examples use your local evidence; results can change with the data.</p>')
        return _page("ReTrust", body)

    hits = _search_hits(connection, query)
    rows = "".join(
        f'<a class="hit" href="/score?vendor={urllib.parse.quote(h.vendor)}'
        f'&amp;product={urllib.parse.quote(h.name)}"><strong>{_esc(h.vendor)}</strong> / '
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
        ('Explain a verdict', 'Open an assessment and follow the score back to its five pillars. '
         'Check evidence coverage as well as the headline number.', '/score?vendor=ABB&product=AC%20800M', 'Assess ABB AC 800M'),
        ('Compare a shortlist', 'Review three examples together. These are different equipment classes '
         'to demonstrate the workflow, not interchangeable engineering alternatives.',
         '/compare?c=ABB%7CAC%20800M&c=Moxa%7CEDS-405A&c=Siemens%7CSIMATIC%20S7-1500%7C3.1.6', 'Open example comparison'),
        ('Ask better supplier questions', 'Turn the findings into an RFQ security annex. '
         'Take the plain text back to your procurement team.', '/annex?vendor=Moxa&product=EDS-405A', 'Prepare supplier questions'),
    )
    cards = ''.join(
        f'<section class="panel"><span class="step-number">{i}</span><h2>{title}</h2><p>{description}</p>'
        f'<a class="button secondary" href="{_esc(url)}">{action} →</a></section>'
        for i, (title, description, url, action) in enumerate(stages, 1))
    return _page('Demo', '<p class="eyebrow">A four-step walkthrough</p>'
                 '<h1>Show the decision.<br>Then show the evidence.</h1>'
                 '<p class="lead">A guided tour for a first look or a live presentation. '
                 'Every example runs against this machine’s index.</p>'
                 '<div class="demo-cards">' + cards + '</div>'
                 '<p class="helper">A verdict is decision support. Product fit, plant context, '
                 'and the supplier’s answer still belong in the purchasing decision.</p>', active='/demo')


def _run_assessment(assess, vendor, product, version=None, order_number=None):
    if order_number:
        return assess(vendor, product, version or None, order_number=order_number)
    return assess(vendor, product, version or None)


def _score_page(connection, assess, context, vendor, product, version, order_number=""):
    """A verdict first, with editable inputs and the evidence below it."""
    form = _score_form(vendor, product, version, order_number)
    if not (vendor or product or order_number):
        return _page('Score', '<h1>Assess a product</h1><p class="lead">'
                     'Start with a manufacturer order number, or enter the vendor and model. '
                     'Add the firmware version to narrow the affected vulnerabilities.</p>' + form)
    assessment, resolution, findings = _run_assessment(assess, vendor, product, version, order_number)
    parameters = urllib.parse.urlencode(dict(vendor=vendor, product=product,
                                             version=version, order_number=order_number))
    body = ('<h1>Product assessment</h1><p class="lead">A procurement verdict, '
            'with the evidence behind every number.</p>'
            '<details><summary>Edit product details and firmware</summary>' + form + '</details>'
            '<div class="actions">'
            f'<a class="button secondary" href="/export.html?{_esc(parameters)}">Download report ↓</a>'
            f'<a class="button secondary" href="/export.json?{_esc(parameters)}">Download JSON ↓</a>'
            '<a class="button secondary" href="/">Find another product</a></div>')
    if not version and resolution.resolved:
        body += ('<p class="notice"><b>Firmware not specified.</b> All known affected versions '
                 'are in scope. Add the firmware you plan to buy using “Edit product details” above.</p>')
    body += report.body([(assessment, resolution, findings)], weights=context['weights'])
    if resolution.resolved:
        named = resolution.matches[0]
        query = urllib.parse.urlencode(dict(vendor=named.vendor, product=named.name, version=version))
        candidate = '|'.join([named.vendor, named.name, version or ''])
        body += ('<section class="panel" style="margin-top:24px"><h2>Take the next step</h2><div class="actions">'
                 f'<a class="button secondary" href="/compare?c={urllib.parse.quote(candidate)}">Compare this product →</a>'
                 f'<a class="button secondary" href="/annex?{_esc(query)}">Prepare supplier questions →</a>'
                 f'<a class="button secondary" href="/alternatives?{_esc(query)}">Find alternatives →</a></div>'
                 f'<p class="helper"><a href="/vendor?name={urllib.parse.quote(named.vendor)}">Vendor profile</a>'
                 f' · <a href="/timeline?{_esc(query)}">Advisory timeline</a></p></section>')
    else:
        suggestions = search.suggest(connection, vendor=vendor, product=product)
        rows = ''.join(
            f'<a class="hit" href="/score?vendor={urllib.parse.quote(h.vendor)}'
            f'&amp;product={urllib.parse.quote(h.name)}">{_esc(h.vendor)} / {_esc(h.name)}</a>'
            for h in suggestions['products'][:8])
        if rows:
            body += f'<h2>Did you mean</h2><div class="rows">{rows}</div>'
    return _page(f'Score: {assessment.product}', body)


def _field(id_, name, label, value='', placeholder=''):
    return (f'<div><label for="{id_}">{label}</label><input type="text" id="{id_}" '
            f'name="{name}" value="{_esc(value)}" placeholder="{_esc(placeholder)}" '
            f'maxlength="{MAX_QUERY}"></div>')


def _score_form(vendor, product, version, order_number=''):
    return ('<form class="form-panel" method="get" action="/score">'
            '<div class="order-field">' + _field('o', 'order_number', 'Manufacturer order number', order_number,
                                                 'e.g. 6ES7518-4AX00-1AB0') + '</div>'
            '<p class="form-divider">Or identify it by vendor and product. If you enter both, they must agree.</p>'
            '<div class="form-grid">' + _field('v', 'vendor', 'Vendor', vendor, 'e.g. Siemens')
            + _field('p', 'product', 'Product / model', product, 'e.g. SIMATIC S7-1500')
            + _field('f', 'version', 'Firmware version (optional)', version, 'e.g. 3.1.6') + '</div>'
            '<p class="helper">Unsure of the model name? <a href="/">Search the advisory index first.</a></p>'
            '<button type="submit">Assess product →</button></form>')


def _candidate_rows(params):
    """Accept structured form fields and retain existing shareable ?c= links."""
    if any(key.startswith('vendor_') for key in params):
        rows = []
        for i in range(MAX_CANDIDATES):
            parts = [(params.get(f'{field}_{i}') or [''])[0][:MAX_QUERY].strip()
                     for field in ('vendor', 'product', 'version')]
            if any(parts):
                rows.append(parts)
        return rows
    return [[p.strip() for p in value[:MAX_QUERY].split('|', 2)]
            for value in params.get('c', [])[:MAX_CANDIDATES] if value.strip()]


def _compare_page(assess, context, candidates):
    """A shortlist with separate input fields and ranked, explainable results."""
    filled = [(list(c) + ['', '', ''])[:3] for c in candidates][:MAX_CANDIDATES]
    boxes = ''
    for i in range(min(MAX_CANDIDATES, max(3, len(filled) + 1))):
        vendor, product, version = filled[i] if i < len(filled) else ('', '', '')
        boxes += (f'<fieldset><legend>Candidate {i + 1}</legend><div class="form-grid">'
                  + _field(f'cv{i}', f'vendor_{i}', 'Vendor', vendor, 'e.g. Moxa')
                  + _field(f'cp{i}', f'product_{i}', 'Product / model', product, 'e.g. EDS-405A')
                  + _field(f'cf{i}', f'version_{i}', 'Firmware (optional)', version, 'e.g. 3.0')
                  + '</div></fieldset>')
    form = ('<form method="get" action="/compare">' + boxes
            + '<p class="helper">Leave unused candidates blank. Another row appears after comparing, '
            'up to 12 candidates.</p><button type="submit">Compare candidates →</button></form>')
    heading = ('<h1>Compare your candidates</h1><p class="lead">Put the shortlist on equal terms. '
               'Scores compare the evidence; an engineer still needs to confirm functional suitability.</p>')
    if not filled:
        return _page('Procurement comparison', heading + form)
    blocks = [assess(v, p, f or None) for v, p, f in filled]
    rank = {'PREFER': 0, 'CONDITIONAL': 1, 'AVOID': 2, 'NOT ASSESSED': 3}
    blocks.sort(key=lambda b: (rank.get(b[0].verdict, 4), -(b[0].score or 0)))
    stabilities = {a.product: sensitivity.stability(*a.inputs, samples=300,
                    bands=context.get('bands')) for a, _, _ in blocks if a.inputs}
    warning = ('<p class="notice">Some candidates have firmware specified and others do not. '
               'Add a version for each to compare on equal terms.</p>'
               if any(f for _, _, f in filled) and not all(f for _, _, f in filled) else '')
    return _page('Procurement comparison', heading + warning
                 + '<details><summary>Edit candidates or add another</summary>' + form + '</details>'
                 + report.body(blocks, stabilities=stabilities, weights=context['weights']),
                 f'{len(blocks)} candidate(s)')


def _alternatives_page(connection, assess, vendor, product, version):
    """Same-family candidates, with the same caveat the terminal prints."""
    form = (
        '<form method="get" action="/alternatives">'
        f'<label for="v">Vendor</label><input type="text" id="v" name="vendor" value="{_esc(vendor)}">'
        f'<label for="p" style="margin-top:.8rem">Product</label>'
        f'<input type="text" id="p" name="product" value="{_esc(product)}">'
        f'<label for="f" style="margin-top:.8rem">Firmware version (optional, '
        f'scores the subject only)</label>'
        f'<input type="text" id="f" name="version" value="{_esc(version)}">'
        '<button type="submit">Find alternatives</button></form>')
    if not (vendor and product):
        return _page("Alternatives", "<h1>Alternatives in the family</h1>" + form +
                     '<p class="empty">Other products from the same vendor '
                     "family, scored the same way. Candidates for an engineer "
                     "to evaluate, never a recommendation to substitute.</p>")

    subject, resolution, _ = assess(vendor, product, version or None)
    named = resolution.matches[0] if resolution.matches else None
    family_vendor = named.vendor if named else vendor
    family_name = named.name if named else product
    body = "<h1>Alternatives in the family</h1>" + form
    shown = "no score" if subject.score is None else f"{subject.score}/100"
    body += (f'<div class="tw"><p><b>{_esc(subject.product)}</b> &mdash; '
             f'{_esc(subject.verdict)}, {shown}.</p></div>')

    options, skipped = alternatives.find(
        connection, family_vendor, family_name,
        lambda v, p: assess(v, p), limit=8,
        exclude={normalize_name(m.name) for m in resolution.matches})
    body += f'<p class="empty">{_esc(alternatives.CAVEAT)}</p>'
    if version:
        body += ('<p class="empty">These are scored without a firmware '
                 f'version, while the product above was scored at '
                 f'{_esc(version)}. The two columns are not on equal terms: '
                 'check each candidate again once you know which firmware '
                 'you would buy.</p>')

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
        body += ('<div class="tw"><table><thead><tr><th>Candidate</th>'
                 '<th>Verdict</th><th>Score</th><th>CVEs</th></tr></thead>'
                 f'<tbody>{rows}</tbody></table></div>')
        if subject.score is not None:
            better = sum(1 for o in options if o.score > subject.score)
            body += (f'<p>{better} of {len(options)} scored above '
                     f'{_esc(subject.product)} ({subject.score}/100).</p>')
    else:
        body += ('<p class="empty">No product in this family scored better '
                 'and could also be assessed.</p>')
    for reason, count in (skipped or {}).items():
        if count:
            body += (f'<p class="empty">{count} family member(s) skipped: '
                     f'{_esc(reason)}. '
                     + ("Disqualified by a hard gate, so not offered as safer."
                        if reason == "gated" else
                        "Absence of advisories is not evidence of safety, so "
                        "not offered.") + '</p>')
    return _page(f"Alternatives: {subject.product}", body,
                 f"{len(options)} candidate(s)")


def _timeline_page(connection, vendor, product):
    """The advisory record drawn as a shape, exactly as the terminal draws it."""
    form = (
        '<form method="get" action="/timeline">'
        f'<label for="v">Vendor</label><input type="text" id="v" name="vendor" value="{_esc(vendor)}">'
        f'<label for="p" style="margin-top:.8rem">Product (optional: blank for the whole vendor)</label>'
        f'<input type="text" id="p" name="product" value="{_esc(product)}">'
        '<button type="submit">Draw</button></form>')
    if not vendor:
        return _page("Timeline", "<h1>Advisory timeline</h1>" + form +
                     '<p class="empty">When advisories land, how the remediation '
                     "mix has moved, and how long the record has been quiet. "
                     "Cadence measures disclosure activity, not safety.</p>")

    from . import match
    if product:
        resolution = match.resolve(connection, vendor=vendor, product=product)
        if not resolution.resolved:
            return _page("Timeline", "<h1>Advisory timeline</h1>" + form +
                         f'<p class="empty">{_esc(resolution.reason)}</p>')
        named = resolution.matches[0]
        subject = f"{named.vendor} {named.name}".strip()
        line = timeline.build(connection, [(m.advisory_id, m.product_id)
                                           for m in resolution.matches])
    else:
        key = _vendor_key(connection, vendor)
        if key is None:
            return _page("Timeline", "<h1>Advisory timeline</h1>" + form +
                         f'<p class="empty">vendor {_esc(vendor)} does not '
                         "appear in the advisory corpus</p>")
        subject, line = vendor, timeline.for_vendor(connection, key)
    body = (f"<h1>Advisory timeline</h1>{form}"
            '<pre class="tw" style="white-space:pre-wrap">'
            f"{_esc(timeline.format_report(subject, line))}</pre>")
    return _page(f"Timeline: {subject}", body)


def _annex_text(connection, assess, dossier, context, vendor, product, version):
    """The annex as bare text: what actually gets pasted into an RFQ.

    Returned as text/plain so "select all, copy" needs no care about markup,
    and a procurement template can curl it straight into a document.
    """
    if not (vendor or product):
        return "Give vendor and product: /annex.txt?vendor=...&product=..."
    assessment, resolution, findings = assess(vendor, product, version or None)
    profile = None
    if resolution.matches:
        profile = dossier.build(connection, resolution.matches[0].vendor,
                                screening=context["screening"],
                                certificates=context["certificates"])
    return questions.format_report(
        assessment.product, questions.build(assessment, findings, profile))


def _annex_page(connection, assess, dossier, context, vendor, product, version):
    """The RFQ security annex, as text a buyer pastes into a request."""
    form = (
        '<form method="get" action="/annex">'
        f'<label for="v">Vendor</label><input type="text" id="v" name="vendor" value="{_esc(vendor)}">'
        f'<label for="p" style="margin-top:.8rem">Product</label>'
        f'<input type="text" id="p" name="product" value="{_esc(product)}">'
        f'<label for="f" style="margin-top:.8rem">Firmware version (optional)</label>'
        f'<input type="text" id="f" name="version" value="{_esc(version)}">'
        '<button type="submit">Write the annex</button></form>')
    if not (vendor or product):
        return _page("RFQ annex", "<h1>RFQ security annex</h1>" + form +
                     '<p class="empty">The questions the evidence supports, '
                     "written to be pasted into a request for quotation. A "
                     "vendor asked which firmware version fixes a named CVE "
                     "must answer with a fact or a visible refusal.</p>")

    annex = _annex_text(connection, assess, dossier, context,
                        vendor, product, version)
    text_query = (f"vendor={urllib.parse.quote(vendor)}"
                  f"&amp;product={urllib.parse.quote(product)}"
                  + (f"&amp;version={urllib.parse.quote(version)}" if version
                     else ""))
    body = (f"<h1>RFQ security annex</h1>{form}"
            '<pre class="tw" style="white-space:pre-wrap">'
            f"{_esc(annex)}</pre>"
            f'<p class="empty"><a href="/annex.txt?{text_query}">Plain text,'
            " for pasting into the request</a></p>")
    subject = annex.splitlines()[0].replace("RFQ SECURITY ANNEX", "").strip()
    return _page(f"Annex: {subject or 'RFQ'}", body)


def _select(name, label, options, chosen):
    """One labelled dropdown, in the same legend style as the text inputs."""
    rendered = "".join(
        f'<option value="{_esc(option)}"'
        + (" selected" if option == chosen else "") + f">{_esc(option)}</option>"
        for option in options)
    return (f'<label for="{name}" style="margin-top:.8rem">{_esc(label)}</label>'
            f'<select id="{name}" name="{name}">{rendered}</select>')


def _ssvc_page(connection, assess, vendor, product, version,
               exposure, automatable, impact):
    """CERT/CC's deployer tree, with the three plant facts asked out loud."""
    form = (
        '<form method="get" action="/ssvc">'
        f'<label for="v">Vendor</label><input type="text" id="v" name="vendor" value="{_esc(vendor)}">'
        f'<label for="p" style="margin-top:.8rem">Product</label>'
        f'<input type="text" id="p" name="product" value="{_esc(product)}">'
        f'<label for="f" style="margin-top:.8rem">Firmware version (optional)</label>'
        f'<input type="text" id="f" name="version" value="{_esc(version)}">'
        + _select("exposure", "System exposure (describes your plant)",
                  ssvc.EXPOSURE, exposure)
        + _select("automatable", "Can an attacker automate it?",
                  ("yes", "no"), automatable)
        + _select("impact", "Human impact", ssvc.HUMAN_IMPACT, impact)
        + '<button type="submit">Decide</button></form>')
    if not (vendor and product):
        return _page("SSVC", "<h1>SSVC decisions</h1>" + form +
                     "<p class=\"empty\">Every finding placed on CERT/CC's "
                     "deployer tree. Three of the four decision points describe "
                     "your plant, not the product, so they are asked rather "
                     "than assumed.</p>")
    assessment, resolution, findings = assess(vendor, product, version or None)
    if not resolution.resolved:
        return _page("SSVC", "<h1>SSVC decisions</h1>" + form +
                     f'<p class="empty">{_esc(resolution.reason)}</p>')
    decisions = ssvc.assess(findings, exposure, automatable, impact)
    text = ssvc.format_report(assessment.product, decisions, exposure,
                              automatable, impact,
                              undecided=sum(1 for f in findings if not f.decided))
    return _page(f"SSVC: {assessment.product}",
                 "<h1>SSVC decisions</h1>" + form +
                 '<pre class="tw" style="white-space:pre-wrap">'
                 f"{_esc(text)}</pre>")


def _lev_page(connection, assess, vendor, product):
    """NIST CSWP 41 estimates, or the honest abstention when history is absent."""
    form = (
        '<form method="get" action="/lev">'
        f'<label for="v">Vendor</label><input type="text" id="v" name="vendor" value="{_esc(vendor)}">'
        f'<label for="p" style="margin-top:.8rem">Product</label>'
        f'<input type="text" id="p" name="product" value="{_esc(product)}">'
        '<button type="submit">Estimate</button></form>')
    if not (vendor and product):
        return _page("LEV", "<h1>Likely exploited</h1>" + form +
                     '<p class="empty">NIST CSWP 41: from the EPSS history, '
                     "how likely each finding has already been exploited. A "
                     "lower bound from a model -- a prompt to go and look, "
                     "never a finding that it happened.</p>")
    if not index_module.has_epss_history(connection):
        return _page("LEV", "<h1>Likely exploited</h1>" + form +
                     '<p class="empty">No EPSS history loaded, so LEV cannot '
                     "be estimated. `retrust lev --update` fetches it "
                     "(67 daily snapshots, about four minutes).</p>")
    assessment, resolution, findings = assess(vendor, product)
    if not resolution.resolved:
        return _page("LEV", "<h1>Likely exploited</h1>" + form +
                     f'<p class="empty">{_esc(resolution.reason)}</p>')
    cves = sorted({f.cve for f in findings})
    history = index_module.epss_history(connection, cves)
    signals = {f.cve: f for f in findings}
    cached = index_module.lev_estimates(connection)
    estimates = [lev.estimate(c, history.get(c, []), in_kev=signals[c].in_kev,
                              current_epss=signals[c].epss) for c in cves]
    text = lev.format_report(
        assessment.product, estimates,
        corpus_share=lev.baseline(cached)["share"] if cached else None)
    return _page(f"LEV: {assessment.product}",
                 "<h1>Likely exploited</h1>" + form +
                 '<pre class="tw" style="white-space:pre-wrap">'
                 f"{_esc(text)}</pre>")


def _vendor_page(connection, dossier, context, name):
    form = ('<form method="get" action="/vendor"><label for="n">Manufacturer</label>'
            f'<input type="text" id="n" name="name" value="{_esc(name)}">'
            "<button type=\"submit\">Look up</button></form>")
    if not name:
        return _page("Vendor", "<h1>Vendor profile</h1>" + form)
    profile = dossier.build(connection, name, screening=context["screening"],
                            certificates=context["certificates"])
    # The dossier is built for a terminal, so it is shown as preformatted text
    # rather than restyled. One renderer, two surfaces, nothing to drift.
    body = (f"<h1>Vendor profile</h1>{form}<pre class=\"tw\" style=\"white-space:pre-wrap\">"
            f"{_esc(dossier.format_report(profile))}</pre>")
    if profile.known:
        body += (f'<p class="empty"><a href="/?q={urllib.parse.quote(name)}">'
                 "Search this vendor's products</a> &middot; "
                 f'<a href="/timeline?vendor={urllib.parse.quote(name)}">'
                 "Advisory timeline</a></p>")
    return _page(f"Vendor: {name}", body)


def _about_page(stats, provenance, host, port):
    rows = "".join(f"<tr><td>{_esc(k.replace('_', ' '))}</td>"
                   f"<td class=\"n\">{v:,}</td></tr>"
                   for k, v in stats.items())
    sources = "".join(
        f"<tr><td>{_esc(p['source'])}</td><td>{_esc(p['detail'])}</td>"
        f"<td class=\"n\">{_esc(p['captured'])}</td></tr>" for p in provenance)
    return _page("About", f"""<h1>Data &amp; methodology</h1>
<p class="lead">Follow the decision back to its inputs. These are the sources
loaded into this workspace and the rules that turn them into an assessment.</p>
<section class="panel"><h2>How a verdict is reached</h2>
<ol class="steps">
<li><span class="step-number">1</span><div><b>Resolve the hardware</b>
<p>Use the manufacturer order number or vendor and product name. Unresolved
products receive NOT ASSESSED. Unknown version ranges stay in scope.</p></div></li>
<li><span class="step-number">2</span><div><b>Apply disqualifying evidence</b>
<p>Known exploitation and supplier screening can trigger an AVOID gate,
regardless of the weighted score.</p></div></li>
<li><span class="step-number">3</span><div><b>Weigh five pillars</b>
<p>Exploitation, severity, patch availability, vendor practice, and certification
contribute to the score. Higher is better. Evidence quality is reported separately.</p></div></li>
</ol></section>
<h2>What the index contains</h2>
<div class="tw"><table><thead><tr><th>Holds</th><th>Count</th></tr></thead>
<tbody>{rows}</tbody></table></div>
<h2>Where the data came from</h2>
<div class="tw"><table><thead><tr><th>Source</th><th>Detail</th><th>Captured</th>
</tr></thead><tbody>{sources}</tbody></table></div>
<h2>What this server does and does not do</h2>
<pre style="white-space:pre-wrap">{_esc(SAFETY)}</pre>
<p class="empty">Serving on {_esc(host)}:{port}. Stop it with Ctrl-C.</p>""")


class PlainText(str):
    """A page that is text, not markup. _send switches the content type on it."""


class Download(str):
    """Generated in memory with a fixed filename; no server-side file writes."""

    def __new__(cls, text, filename, content_type):
        value = super().__new__(cls, text)
        value.filename, value.content_type = filename, content_type
        return value


def _export(assess, context, provenance, path, vendor, product, version, order_number):
    block = _run_assessment(assess, vendor, product, version, order_number)
    if path.endswith('.json'):
        query = dict(vendor=vendor, product=product, version=version, order_number=order_number)
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
        first = lambda key: (params.get(key) or [""])[0][:MAX_QUERY]
        if path == "/demo":
            return _demo_page()
        if path in ("/export.html", "/export.json"):
            return _export(assess, context, provenance, path,
                           first("vendor"), first("product"), first("version"), first("order_number"))
        if path == "/":
            return _search_page(connection, stats, first("q"))
        if path == "/score":
            return _score_page(connection, assess, context, first("vendor"),
                               first("product"), first("version"), first("order_number"))
        if path == "/compare":
            return _compare_page(assess, context,
                                 _candidate_rows(params))
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
