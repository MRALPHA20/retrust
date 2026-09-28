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

from . import alternatives, report, search
from .index import normalize_name

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
"""


def _esc(text):
    return html.escape(str(text or ""), quote=True)


def _page(title, body, subtitle=""):
    """One page, in the report's own stylesheet so both surfaces match."""
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{_esc(title)}</title><style>{report.CSS}{EXTRA}</style></head>"
        '<body><div class="wrap">'
        f'<p class="meta">ReTrust &middot; {date.today().isoformat()}'
        + (f" &middot; {_esc(subtitle)}" if subtitle else "")
        + "</p>" + NAV + body +
        "<footer>Decision support, not a certification. Served locally from your "
        "own index; nothing leaves this machine.</footer>"
        "</div></body></html>")


EXTRA = """
.nav{display:flex;gap:1.2rem;margin:0 0 1.6rem;padding-bottom:.6rem;
     border-bottom:1px solid var(--rule);font-size:.82rem;letter-spacing:.08em;
     text-transform:uppercase;font-family:var(--mono)}
.nav a{color:var(--faint);text-decoration:none}
.nav a:hover,.nav a:focus{color:var(--ink)}
form{margin:0 0 1.6rem}
label{display:block;font-family:var(--mono);font-size:.72rem;letter-spacing:.12em;
      text-transform:uppercase;color:var(--faint);margin:0 0 .3rem}
input[type=text]{width:100%;max-width:34rem;padding:.55rem .7rem;font:inherit;
     background:var(--panel);color:var(--ink);border:1px solid var(--rule)}
input[type=text]:focus{outline:2px solid var(--ink);outline-offset:-2px}
button{margin-top:.8rem;padding:.5rem 1.4rem;font:inherit;cursor:pointer;
       background:var(--ink);color:var(--field);border:1px solid var(--ink)}
.rows{display:grid;gap:.5rem;max-width:34rem}
.hit{display:block;padding:.5rem .7rem;border:1px solid var(--rule);
     background:var(--panel);text-decoration:none;color:var(--ink)}
.hit:hover{border-color:var(--ink)}
.hit .w{display:block;font-family:var(--mono);font-size:.74rem;color:var(--faint);
        letter-spacing:.06em;margin-top:.15rem}
.empty{color:var(--soft);font-size:.92rem}
"""

NAV = ('<nav class="nav"><a href="/">Search</a><a href="/score">Score</a>'
       '<a href="/compare">Compare</a><a href="/alternatives">Alternatives</a>'
       '<a href="/vendor">Vendor</a><a href="/about">About</a></nav>')


def _search_page(connection, stats, query):
    """The landing page: a box, and what the corpus holds that matches it."""
    form = (
        '<form method="get" action="/"><label for="q">Product, vendor or order '
        f'number</label><input type="text" id="q" name="q" value="{_esc(query)}" '
        'autofocus><button type="submit">Search</button></form>')
    if not query:
        # The counts are the index's own, so this page cannot go stale the way
        # a number typed in once already did.
        return _page("ReTrust", "<h1>Search the corpus</h1>" + form +
                     f'<p class="empty">{stats["products"]:,} product entries '
                     f'under {stats["vendors"]:,} vendor spellings. Scoring '
                     "needs the spelling the advisory used, so start here.</p>")

    hits = search.products(connection, query, limit=MAX_RESULTS)
    rows = "".join(
        f'<a class="hit" href="/score?vendor={urllib.parse.quote(h.vendor)}'
        f'&amp;product={urllib.parse.quote(h.name)}">{_esc(h.vendor)} / '
        f'{_esc(h.name)}<span class="w">matched by {_esc(h.method)} &middot; '
        f'{h.advisories:,} advisor{"y" if h.advisories == 1 else "ies"}'
        + (f' &middot; {_esc(h.order_numbers[0])}' if h.order_numbers else "")
        + "</span></a>" for h in hits)
    if not hits:
        vendors = search.vendors(connection, query, limit=8)
        rows = "".join(
            f'<a class="hit" href="/vendor?name={urllib.parse.quote(v.vendor)}">'
            f'{_esc(v.vendor)}<span class="w">{v.products:,} product entries '
            f"&middot; matched by {_esc(v.method)}</span></a>" for v in vendors)
        rows = (rows and "<h2>Vendors matching that</h2>" + rows) or \
            '<p class="empty">Nothing in the corpus matches that.</p>'
    return _page(f"Search: {query}", "<h1>Search the corpus</h1>" + form +
                 f'<div class="rows">{rows}</div>', f"{len(hits)} result(s)")


def _score_page(connection, assess, context, vendor, product, version):
    """One product, rendered by the same function that writes the PDF report."""
    if not (vendor or product):
        return _page("Score", "<h1>Score a product</h1>" + _score_form("", "", ""))
    assessment, resolution, findings = assess(vendor, product, version)
    body = ("<h1>Score a product</h1>" + _score_form(vendor, product, version)
            + report.body(
                [(assessment, resolution, findings)], weights=context["weights"]))
    if resolution.resolved:
        # The next two questions a buyer asks, one click away rather than a
        # form to refill: who makes this, and what else is in the family.
        named = resolution.matches[0]
        query = (f"vendor={urllib.parse.quote(named.vendor)}"
                 f"&amp;product={urllib.parse.quote(named.name)}")
        candidate = "|".join(filter(None, [named.vendor, named.name, version]))
        body += (f'<p class="empty"><a href="/vendor?name='
                 f'{urllib.parse.quote(named.vendor)}">Vendor profile: '
                 f'{_esc(named.vendor)}</a> &middot; '
                 f'<a href="/alternatives?{query}'
                 + (f"&amp;version={urllib.parse.quote(version)}" if version else "")
                 + '">Alternatives in this family</a> &middot; '
                 f'<a href="/compare?c={urllib.parse.quote(candidate)}">'
                 'Start a comparison with this</a></p>')
    if not resolution.resolved:
        suggestions = search.suggest(connection, vendor=vendor, product=product)
        rows = "".join(
            f'<a class="hit" href="/score?vendor={urllib.parse.quote(h.vendor)}'
            f'&amp;product={urllib.parse.quote(h.name)}">{_esc(h.vendor)} / '
            f'{_esc(h.name)}<span class="w">matched by {_esc(h.method)}</span></a>'
            for h in suggestions["products"][:8])
        if rows:
            body += f'<h2>Did you mean</h2><div class="rows">{rows}</div>'
    return _page(f"Score: {assessment.product}", body)


def _score_form(vendor, product, version):
    return (
        '<form method="get" action="/score">'
        f'<label for="v">Vendor</label><input type="text" id="v" name="vendor" value="{_esc(vendor)}">'
        f'<label for="p" style="margin-top:.8rem">Product</label><input type="text" id="p" name="product" value="{_esc(product)}">'
        f'<label for="f" style="margin-top:.8rem">Firmware version (optional)</label>'
        f'<input type="text" id="f" name="version" value="{_esc(version)}">'
        "<button type=\"submit\">Score</button></form>")


def _compare_page(assess, context, candidates):
    """Several products ranked for one decision, as the terminal does it."""
    filled = [c for c in candidates if c.strip()][:MAX_CANDIDATES]
    boxes = "".join(
        f'<label for="c{i}">Candidate {i + 1} &mdash; Vendor|Product|Version</label>'
        f'<input type="text" id="c{i}" name="c" value="{_esc(filled[i] if i < len(filled) else "")}" '
        'style="margin-bottom:.6rem">' for i in range(max(3, len(filled) + 1)))
    form = f'<form method="get" action="/compare">{boxes}<button type="submit">Compare</button></form>'
    if not filled:
        return _page("Compare", "<h1>Compare candidates</h1>" + form +
                     '<p class="empty">One per box, pipe-separated. Everything '
                     "after the vendor is optional.</p>")

    blocks = []
    for raw in filled:
        parts = [p.strip() for p in raw.split("|")]
        blocks.append(assess(parts[0], parts[1] if len(parts) > 1 else None,
                             parts[2] if len(parts) > 2 else None))
    rank = {"PREFER": 0, "CONDITIONAL": 1, "AVOID": 2, "NOT ASSESSED": 3}
    blocks.sort(key=lambda b: (rank.get(b[0].verdict, 4), -(b[0].score or 0)))
    return _page("Procurement comparison",
                 "<h1>Compare candidates</h1>" + form
                 + report.body(blocks, weights=context["weights"]),
                 f"{len(blocks)} candidate(s)")


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
            f'<tr><td><a class="plain" href="/score?vendor='
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
                 "Search this vendor's products</a></p>")
    return _page(f"Vendor: {name}", body)


def _about_page(stats, provenance, host, port):
    rows = "".join(f"<tr><td>{_esc(k.replace('_', ' '))}</td>"
                   f"<td class=\"n\">{v:,}</td></tr>"
                   for k, v in stats.items())
    sources = "".join(
        f"<tr><td>{_esc(p['source'])}</td><td>{_esc(p['detail'])}</td>"
        f"<td class=\"n\">{_esc(p['captured'])}</td></tr>" for p in provenance)
    return _page("About", f"""<h1>About this index</h1>
<div class="tw"><table><thead><tr><th>Holds</th><th>Count</th></tr></thead>
<tbody>{rows}</tbody></table></div>
<h2>Where the data came from</h2>
<div class="tw"><table><thead><tr><th>Source</th><th>Detail</th><th>Captured</th>
</tr></thead><tbody>{sources}</tbody></table></div>
<h2>What this server does and does not do</h2>
<pre style="white-space:pre-wrap">{_esc(SAFETY)}</pre>
<p class="empty">Serving on {_esc(host)}:{port}. Stop it with Ctrl-C.</p>""")


def build_handler(connection, assess, context, dossier, stats, provenance,
                  host, port):
    """The request handler, closed over everything a page needs.

    Routing is an explicit dict rather than anything derived from the path, so a
    request can only ever reach a function named here. A path is never joined to
    a filename, which is the whole class of traversal bug this avoids by not
    having the code that would contain it.
    """
    def page_for(path, params):
        first = lambda key: (params.get(key) or [""])[0][:MAX_QUERY]
        if path == "/":
            return _search_page(connection, stats, first("q"))
        if path == "/score":
            return _score_page(connection, assess, context, first("vendor"),
                               first("product"), first("version"))
        if path == "/compare":
            return _compare_page(assess, context,
                                 [c[:MAX_QUERY] for c in params.get("c", [])])
        if path == "/alternatives":
            return _alternatives_page(connection, assess, first("vendor"),
                                      first("product"), first("version"))
        if path == "/vendor":
            return _vendor_page(connection, dossier, context, first("name"))
        if path == "/about":
            return _about_page(stats, provenance, host, port)
        return None

    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "ReTrust"
        sys_version = ""                  # the Python version is nobody's business

        def do_GET(self):
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
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            # The pages are self-contained, so the strictest policy that still
            # works is the correct one: nothing may be fetched or executed.
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; style-src 'unsafe-inline'; "
                             "form-action 'self'; base-uri 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
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
