"""Tests for the local web interface.

A tool that screens sanctions lists has no business opening a port carelessly,
so most of this file is about what the server refuses to do: reach a file, run
anything, emit an unescaped value, or answer a path that is not in its routing
table. The rendering is report.py's and is tested there.
"""

import json
import threading
import urllib.error
import urllib.request

import pytest

from retrust import index, report, serve

ADVISORY = {
    "document": {"title": "T", "tracking": {
        "id": "ICSA-26-001-01", "initial_release_date": "2026-01-01T00:00:00Z"}},
    "product_tree": {"branches": [{
        "category": "vendor", "name": "Testco Electric", "branches": [{
            "category": "product_name", "name": "TestPLC 9000 (TC-9000-A1)",
            "branches": [{"category": "product_version_range",
                          "name": "vers:intdot/<2.0",
                          "product": {"product_id": "P1", "name": "TestPLC 9000"}}]}]}]},
    "vulnerabilities": [{"cve": "CVE-2026-0001",
                         "product_status": {"known_affected": ["P1"]},
                         "scores": [{"cvss_v3": {"baseScore": 7.5},
                                     "products": ["P1"]}]}],
}


@pytest.fixture
def db(tmp_path):
    directory = tmp_path / "csaf"
    directory.mkdir()
    (directory / "a.json").write_text(json.dumps(ADVISORY))
    connection, _ = index.build(str(tmp_path / "t.db"), str(directory))
    return connection


@pytest.fixture
def handler(db):
    """The real handler over a real index, with a stub scorer."""
    from retrust import dossier, score
    from retrust.match import Resolution

    def assess(vendor, product, version=None, order_number=None, **owner):
        # Mirrors what serve actually calls, including the order number and the
        # site answers. The narrower signature this replaced raised TypeError
        # -- a 500 -- for any order-number lookup, so no test here had ever
        # exercised that path.
        label = " ".join(filter(None, [vendor, product])) or (order_number or "")
        assessment = score.not_assessed(label.strip(), "stub")
        return assessment, Resolution(query="q", abstained=True, reason="stub"), []

    return serve.build_handler(
        db, assess, {"weights": {"exploitation": 1.0}, "screening": {},
                     "certificates": {}, "config_source": "test"},
        dossier, index.stats(db), index.provenance(db), "127.0.0.1", 0)


def _get(handler, path):
    """One real request against a real socket on an ephemeral port.

    The server runs in the main thread and the client in a background one, the
    same way round as production. Serving from a spawned thread would fail on
    SQLite's thread affinity -- which is exactly why serve() is single-threaded,
    so a test that did it the other way would be testing a server nobody runs.
    """
    httpd = serve.serve(handler, "127.0.0.1", 0, forever=False)
    port = httpd.server_address[1]
    caught = {}

    def fetch():
        try:
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}{path}", timeout=10) as response:
                caught["ok"] = (response.status, dict(response.headers),
                                response.read().decode("utf-8"))
        except Exception as error:
            caught["error"] = error

    client = threading.Thread(target=fetch, daemon=True)
    client.start()
    httpd.handle_request()
    client.join(timeout=10)
    httpd.server_close()
    if "error" in caught:
        raise caught["error"]
    return caught["ok"]


def test_json_download_keeps_the_real_assessment_context(db, tmp_path):
    from retrust import cli, dossier
    context = cli._context(data_dir=str(tmp_path))

    def assess(vendor, product, version=None, order_number=None, **owner):
        return cli._assess(db, vendor, product, version, order_number,
                           context=context, **owner)

    handler = serve.build_handler(
        db, assess, context, dossier, index.stats(db), index.provenance(db), "127.0.0.1", 0)
    status, _, output = _get(
        handler, '/export.json?order_number=TC-9000-A1&version=1.0'
        '&assessment_type=installed&network_exposure=it_ot&consequence=minor'
        '&interface=blocked&remediation=planned')
    assert status == 200
    result = json.loads(output)["results"][0]
    assert result["assessment_type"] == "installed"
    assert result["network_exposure"] == "it_ot"
    assert result["consequence"] == "minor"
    assert result["interface"] == "blocked"
    assert result["remediation"] == "planned"
    for part in ("FW:1.0", "AT:installed", "NX:it_ot", "OC:minor", "IF:blocked", "RS:planned"):
        assert part in result["vector"]


def test_comparison_round_trip_retains_each_candidates_site_context(db, tmp_path):
    import csv
    import html
    import io
    import re
    from retrust import cli, dossier
    context = cli._context(data_dir=str(tmp_path))

    def assess(vendor, product, version=None, order_number=None, **owner):
        return cli._assess(db, vendor, product, version, order_number,
                           context=context, **owner)

    handler = serve.build_handler(db, assess, context, dossier, index.stats(db),
                                  index.provenance(db), '127.0.0.1', 0)
    query = ('order_number=TC-9000-A1&version=1.0&assessment_type=installed'
             '&network_exposure=isolated&consequence=minor&interface=blocked&remediation=planned')
    _, _, original_json = _get(handler, '/export.json?' + query)
    original = json.loads(original_json)['results'][0]
    _, _, page = _get(handler, '/score?' + query)
    handoff = html.unescape(re.search(r'href="(/compare\?[^\"]+)"', page).group(1))
    # A second candidate must retain its own defaults, rather than inherit
    # assertions about the first candidate's installation.
    comparison_query = handoff.partition('?')[2] + '&order_number_1=TC-9000-A1&version_1=1.0'
    _, _, result = _get(handler, '/compare.json?' + comparison_query)
    results = json.loads(result)['results']
    saved = next(r for r in results if r['assessment_type'] == 'installed')
    other = next(r for r in results if r['assessment_type'] == 'purchase')
    assert saved['score'] == original['score'] and saved['vector'] == original['vector']
    for field in serve.CONTEXT_FIELDS:
        assert saved[field] == original[field]
    assert other['network_exposure'] is None and other['interface'] == 'unknown'
    _, _, html_report = _get(handler, '/compare.html?' + comparison_query)
    assert original['vector'] in html_report
    _, _, csv_report = _get(handler, '/compare.csv?' + comparison_query)
    rows = list(csv.DictReader(io.StringIO(csv_report)))
    assert next(r for r in rows if r['assessment_type'] == 'installed')['network_exposure'] == 'isolated'
    # Read the browser form as a browser would and submit it unchanged.
    from html.parser import HTMLParser

    class FormValues(HTMLParser):
        def __init__(self):
            super().__init__()
            self.values = {}
            self.select = None

        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if tag == 'input' and attrs.get('name'):
                self.values[attrs['name']] = attrs.get('value', '')
            elif tag == 'select':
                self.select = attrs['name']
            elif tag == 'option' and self.select:
                if self.select not in self.values or 'selected' in attrs:
                    self.values[self.select] = attrs.get('value', '')

        def handle_endtag(self, tag):
            if tag == 'select':
                self.select = None

    _, _, comparison_page = _get(handler, '/compare?' + comparison_query)
    form = FormValues()
    form.feed(comparison_page)
    assert form.values['network_exposure_0'] == 'isolated'
    _, _, resubmitted = _get(handler, '/compare.json?' + urllib.parse.urlencode(form.values))
    repeated = json.loads(resubmitted)['results']
    assert len(repeated) == 2  # blank candidate rows carry default selects
    assert sorted(r['vector'] for r in repeated) == sorted(r['vector'] for r in results)


def test_comparison_rejects_invalid_context_values_without_trusting_them():
    rows = serve._comparison_rows([['V', 'P', '', '', 'private', 'invalid', '<script>', 'invalid', 'invalid']])
    network, owner = serve._candidate_context(rows[0])
    assert network is None
    assert owner == serve.UNDECLARED


# --- routing ---------------------------------------------------------------

def test_health_check_reads_index(handler):
    status, headers, body = _get(handler, "/healthz")
    assert status == 200
    assert headers["Content-Type"] == "text/plain; charset=utf-8"
    assert headers["Cache-Control"] == "no-store"
    assert body == "ok\n"


def test_deployed_revision_is_identifiable_without_changing_health_response(handler, monkeypatch):
    monkeypatch.setenv('RENDER_GIT_COMMIT', 'a' * 40)
    _, headers, body = _get(handler, '/healthz')
    assert headers['X-ReTrust-Revision'] == 'a' * 40
    assert body == 'ok\n'
    monkeypatch.setenv('RENDER_GIT_COMMIT', 'bad\r\nInjected: true')
    _, headers, _ = _get(handler, '/healthz')
    assert 'X-ReTrust-Revision' not in headers


def test_health_check_fails_for_unusable_index(handler, db):
    db.execute("DROP TABLE advisory")
    with pytest.raises(urllib.error.HTTPError) as error:
        _get(handler, "/healthz")
    assert error.value.code == 500


def test_robots_discourages_crawling_assessment_queries(handler):
    status, headers, body = _get(handler, "/robots.txt")
    assert status == 200
    assert headers["Content-Type"].startswith("text/plain")
    assert body == "User-agent: *\nDisallow: /\n"


def test_hosted_workspace_explains_processing_location(handler, monkeypatch):
    monkeypatch.setenv("RETRUST_HOSTED", "1")
    _, _, body = _get(handler, "/about")
    assert "Hosted assessment" in body
    assert "Queries are processed on this server" in body
    assert "requests pass through the hosting provider" in body
    assert "Offline assessment" not in body
    assert "Private decisions" not in body


def test_local_workspace_keeps_offline_label(handler, monkeypatch):
    monkeypatch.delenv("RETRUST_HOSTED", raising=False)
    _, _, body = _get(handler, "/")
    assert "Offline assessment" in body
    assert "Local workspace" in body
    assert "Hosted assessment" not in body

@pytest.mark.parametrize("path", [
    "/", "/?q=test", "/score?vendor=Testco&product=TestPLC",
    "/compare?c=Testco%7CTestPLC", "/vendor?name=Testco", "/about",
    "/alternatives", "/alternatives?vendor=Testco&product=TestPLC",
    "/timeline", "/timeline?vendor=Testco",
    "/timeline?vendor=Testco&product=TestPLC",
    "/annex", "/annex?vendor=Testco&product=TestPLC",
    "/ssvc", "/ssvc?vendor=Testco&product=TestPLC&exposure=open"
    "&automatable=yes&impact=high",
    "/lev", "/lev?vendor=Testco&product=TestPLC"])
def test_every_route_answers(handler, path):
    status, _, body = _get(handler, path)
    assert status == 200
    assert body.startswith("<!doctype html>")


def test_the_landing_counts_come_from_the_index(handler, db):
    """The corpus size on the landing page is measured, not typed in once."""
    stats = index.stats(db)
    _, _, body = _get(handler, "/")
    assert f'{stats["products"]:,} product entries' in body
    assert f'{stats["vendors"]:,} vendor spellings' in body


@pytest.mark.parametrize("path, message", [
    ("/score?vendor=&product=&version=3.1.6&order_number=",
     "Enter a manufacturer order number"),
    ("/score?vendor=%20%20&product=%09", "Enter a manufacturer order number"),
    ("/compare?vendor_0=&product_0=&version_0=3.1.6",
     "Enter an order number, vendor or product in each"),
])
def test_empty_submissions_explain_how_to_continue(handler, path, message):
    status, _, body = _get(handler, path)
    assert status == 200
    assert 'role="alert"' in body
    assert message in body
    assert "stub" not in body  # No assessment was attempted.
    if "3.1.6" in path:
        assert 'value="3.1.6"' in body


@pytest.mark.parametrize("path", ["/score", "/compare"])
def test_initial_forms_do_not_show_submission_errors(handler, path):
    _, _, body = _get(handler, path)
    assert 'role="alert"' not in body


def test_the_timeline_page_keeps_its_caveat(handler):
    _, _, body = _get(handler, "/timeline?vendor=Testco")
    assert "not safety" in body


def test_the_annex_page_is_pasteable_text(handler):
    _, _, body = _get(handler, "/annex?vendor=Testco&product=TestPLC")
    assert "RFQ SECURITY ANNEX" in body
    assert "<pre" in body                    # the annex is a document, not a widget


@pytest.mark.parametrize('path', ['/annex', '/lev', '/ssvc', '/alternatives'])
def test_incomplete_evidence_lookup_explains_required_identity(handler, path):
    _, _, page = _get(handler, path + '?vendor=Testco')
    assert 'role="alert"' in page
    assert 'Enter both the manufacturer and product/model' in page
    assert 'find the product in Explore' in page


def test_timeline_names_the_combined_query_not_the_first_matched_variant(handler):
    _, _, page = _get(handler, '/timeline?vendor=Testco&product=TestPLC')
    assert '<h2 class="subject">Testco TestPLC</h2>' in page
    assert 'matched product name(s)' in page


def test_alternatives_do_not_search_from_an_unresolved_product(handler, monkeypatch):
    from retrust import alternatives

    def unexpected_search(*args, **kwargs):
        raise AssertionError('must identify the subject before searching its family')

    monkeypatch.setattr(alternatives, 'find', unexpected_search)
    _, _, page = _get(handler, '/alternatives?vendor=UnknownVendor&product=UnknownModel')
    assert 'Search for the exact model' in page
    assert 'No product in this family scored better' not in page


def test_the_lev_page_abstains_without_history(handler):
    """The fixture index has no EPSS history; the page must say so, not zero."""
    _, _, body = _get(handler, "/lev?vendor=Testco&product=TestPLC")
    assert "Historical attack estimates are not available" in body


def test_the_ssvc_form_carries_the_plant_questions(handler):
    _, _, body = _get(handler, "/ssvc")
    assert "describes your plant" in body
    assert "<select" in body


def test_invalid_response_setting_explains_how_to_recover(handler):
    status, _, body = _get(handler, '/ssvc?vendor=Testco&product=TestPLC&exposure=unknown')
    assert status == 200
    assert 'role="alert"' in body
    assert 'Choose one of the listed' in body


def test_methodology_describes_current_network_and_scoring_rules(handler):
    """The /about page must not claim network topology feeds the score.

    It said "Network access contributes to exposure safety" while, five lines
    below, the formula block correctly called topology context -- the page
    contradicted itself, and the claim was false: isolated, IT-OT and direct
    Internet all produce an identical range.
    """
    _, _, body = _get(handler, '/about')
    assert 'exposure safety (60%)' in body
    assert 'available fixes (20%)' in body
    assert 'recorded as context and never moves the score' in body
    assert 'CVSS attack vector' in body
    assert 'Network access contributes' not in body
    assert 'Five evidence pillars' not in body


def test_the_annex_text_endpoint_is_plain_text(handler):
    """What gets pasted into an RFQ must arrive without markup around it."""
    status, headers, body = _get(handler, "/annex.txt?vendor=Testco&product=TestPLC")
    assert status == 200
    assert headers["Content-Type"].startswith("text/plain")
    assert "RFQ SECURITY ANNEX" in body
    assert "<" not in body.split("ANNEX")[1][:200]   # no markup leaks into the text


def test_the_alternatives_page_keeps_the_caveat(handler):
    """The one paragraph that must survive any restyling."""
    for path in ("/alternatives", "/alternatives?vendor=Testco&product=TestPLC"):
        _, _, body = _get(handler, path)
        assert "recommendation to substitute" in body


def test_an_unknown_path_is_a_clean_404(handler):
    with pytest.raises(urllib.error.HTTPError) as error:
        _get(handler, "/nope")
    assert error.value.code == 404


@pytest.mark.parametrize("attempt", [
    "/static/../../../etc/shadow", "/etc/passwd", "/..%2f..%2fetc%2fpasswd"])
def test_a_path_is_never_used_as_a_filename(handler, attempt):
    """The traversal bug avoided by having no code that could contain it.

    Routing is an explicit dict, so a request can only reach a function named
    there. Nothing joins a request path to a directory.
    """
    with pytest.raises(urllib.error.HTTPError) as error:
        _get(handler, attempt)
    assert error.value.code == 404


# --- what reaches the page -------------------------------------------------

def test_a_hostile_query_comes_back_escaped(handler):
    _, _, body = _get(handler, "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
    assert "<script>alert(1)" not in body
    assert "&lt;script&gt;" in body


def test_a_hostile_vendor_comes_back_escaped(handler):
    """The angle brackets are what matter.

    "onerror=alert" survives escaping as inert text, because html.escape has no
    reason to touch an equals sign. What must never appear is an unescaped tag.
    """
    _, _, body = _get(
        handler, "/score?vendor=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E&product=P")
    assert "<img" not in body
    assert "&lt;img" in body


@pytest.mark.parametrize("path", ["/", "/?q=test", "/about", "/compare?c=A%7CB"])
def test_no_page_ever_emits_a_script(handler, path):
    _, _, body = _get(handler, path)
    assert "<script" not in body.lower()


# --- caps ------------------------------------------------------------------

def test_a_long_query_is_truncated_not_run(handler):
    """A hand-written URL must not turn into a scan of the whole corpus."""
    _, _, body = _get(handler, "/?q=" + "a" * 5000)
    assert "a" * (serve.MAX_QUERY + 1) not in body


def test_more_candidates_than_the_cap_are_dropped(handler):
    query = "&".join(f"c=V{i}%7CP{i}" for i in range(serve.MAX_CANDIDATES + 20))
    _, _, body = _get(handler, f"/compare?{query}")
    assert f"V{serve.MAX_CANDIDATES + 10}" not in body


# --- headers ---------------------------------------------------------------

def test_a_rebound_host_header_is_refused(handler):
    """DNS rebinding: attacker.com resolving to 127.0.0.1 must not read pages."""
    import http.client
    httpd = serve.serve(handler, "127.0.0.1", 0, forever=False)
    port = httpd.server_address[1]
    caught = {}

    def fetch():
        try:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            connection.request("GET", "/", headers={"Host": "attacker.example"})
            response = connection.getresponse()
            caught["status"] = response.status
            caught["body"] = response.read().decode("utf-8")
        except Exception as error:
            caught["error"] = error

    client = threading.Thread(target=fetch, daemon=True)
    client.start()
    httpd.handle_request()
    client.join(timeout=10)
    httpd.server_close()
    assert caught.get("status") == 403
    assert "DNS-rebinding" in caught["body"]


def test_a_local_host_header_is_answered(handler):
    """The check refuses foreign names, not the names this machine goes by."""
    status, _, _ = _get(handler, "/")           # urllib sends Host: 127.0.0.1
    assert status == 200


def test_responses_are_not_cacheable_or_frameable(handler):
    _, headers, _ = _get(handler, "/")
    assert headers["Cache-Control"] == "no-store"
    assert headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]


def test_the_policy_forbids_fetching_and_executing(handler):
    _, headers, _ = _get(handler, "/")
    policy = headers["Content-Security-Policy"]
    assert "default-src 'none'" in policy
    assert "form-action 'self'" in policy
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Referrer-Policy"] == "no-referrer"


def test_the_python_version_is_not_advertised(handler):
    _, headers, _ = _get(handler, "/")
    assert "Python" not in headers.get("Server", "")


# --- the promises the about page makes -------------------------------------

def test_the_about_page_states_what_the_server_will_not_do(handler):
    _, _, body = _get(handler, "/about")
    for promise in ("GET only", "No path is used as a filename",
                    "Nothing is written", "html.escape", "127.0.0.1"):
        assert promise in body


def test_the_default_host_is_loopback():
    """Anything else has to be asked for, and the CLI announces it."""
    assert serve.DEFAULT_HOST == "127.0.0.1"


# --- one renderer, two surfaces --------------------------------------------

def test_the_page_uses_the_report_stylesheet(handler):
    _, _, body = _get(handler, "/")
    assert report.CSS[:80] in body


def test_report_body_is_what_render_puts_in_its_page(db):
    """The server and the printed report must show an assessment identically."""
    from retrust import score
    from retrust.match import Resolution
    assessment = score.not_assessed("X", "reason")
    blocks = [(assessment, Resolution(query="x", abstained=True, reason="r"), [])]
    inner = report.body(blocks, weights={"exploitation": 1.0})
    assert inner and inner in report.render(blocks, weights={"exploitation": 1.0})


@pytest.mark.parametrize('path', ['/demo', '/export.html?vendor=Testco&product=TestPLC',
                                  '/export.json?vendor=Testco&product=TestPLC'])
def test_demo_and_download_routes_answer(handler, path):
    status, headers, body = _get(handler, path)
    assert status == 200
    if path.startswith('/export'):
        assert 'attachment; filename="retrust-assessment.' in headers['Content-Disposition']
        if '.json' in path:
            assert headers['Content-Type'].startswith('application/json')
            assert json.loads(body)['results'][0]['query']['vendor'] == 'Testco'
        else:
            assert 'ReTrust procurement assessment' in body
            assert 'How this was produced' in body
    else:
        assert 'four-step walkthrough' in body


def test_structured_comparison_fields_reach_the_scorer(db):
    from retrust import dossier, score
    from retrust.match import Resolution
    calls = []

    def assess(vendor, product, version=None):
        calls.append((vendor, product, version))
        return score.not_assessed(product, 'test'), Resolution(query=product), []

    handler = serve.build_handler(db, assess, {'weights': {}}, dossier,
                                  index.stats(db), [], '127.0.0.1', 0)
    _, _, body = _get(handler, '/compare?vendor_0=Testco&product_0=TestPLC&version_0=2.5'
                     '&vendor_1=&product_1=&version_1=')
    assert calls == [('Testco', 'TestPLC', '2.5')]
    assert 'name="vendor_0"' in body
    assert 'Vendor|Product|Version' not in body


def test_order_number_reaches_assessment_and_export(db):
    from retrust import dossier, score
    from retrust.match import Resolution
    calls = []

    def assess(vendor, product, version=None, order_number=None):
        calls.append((vendor, product, version, order_number))
        return score.not_assessed(order_number, 'test'), Resolution(query=order_number), []

    handler = serve.build_handler(db, assess, {'weights': {}}, dossier,
                                  index.stats(db), [], '127.0.0.1', 0)
    _get(handler, '/score?order_number=TC-9000-A1&version=2.5')
    _, _, output = _get(handler, '/export.json?order_number=TC-9000-A1&version=2.5')
    assert calls == [('', '', '2.5', 'TC-9000-A1')] * 2
    assert json.loads(output)['results'][0]['query']['order_number'] == 'TC-9000-A1'


def test_web_download_cannot_inject_html(handler):
    _, _, output = _get(handler, '/export.html?vendor=%3Cscript%3Ealert(1)%3C%2Fscript%3E&product=P')
    assert '<script>' not in output
    assert '&lt;script&gt;' in output


def test_web_search_finds_an_order_number_held_only_in_helpers(db):
    with db:
        row = db.execute('SELECT rowid_ FROM product LIMIT 1').fetchone()[0]
        db.execute('INSERT INTO order_number VALUES (?,?,?)', ('UNIQUE42PART', 'UNIQUE-42-PART', row))
    hits = serve._search_hits(db, 'UNIQUE-42-PART')
    assert len(hits) == 1
    assert hits[0].vendor == 'Testco Electric'


def test_web_search_understands_vendor_and_model(db):
    hits = serve._search_hits(db, 'Testco TestPLC 9000')
    assert hits and hits[0].vendor == 'Testco Electric'


@pytest.fixture
def comparison_handler(db, monkeypatch):
    from retrust import dossier, score, sensitivity
    from retrust.match import Resolution
    calls = []

    def assess(vendor, product, version=None, order_number=None):
        calls.append((vendor, product, version, order_number))
        # Deliberately identical labels: stability and queries must follow rows,
        # not a dictionary keyed only by the displayed product name.
        value = 80 if order_number == 'BEST' else 50
        result = score.Assessment(product or order_number or vendor,
                                  'PREFER' if value == 80 else 'CONDITIONAL', value,
                                  inputs=(value,))
        return result, Resolution(query=product or order_number or vendor), []

    monkeypatch.setattr(sensitivity, 'stability', lambda value, **kwargs:
                        sensitivity.Stability(300, {'PREFER': 270, 'AVOID': 30}
                                              if value == 80 else {'CONDITIONAL': 180, 'AVOID': 120}))
    handler = serve.build_handler(db, assess, {'weights': {'severity': 1}, 'bands': (40, 70),
                                  'config_source': 'test'}, dossier, index.stats(db),
                                  [{'source': 'fixture', 'captured': '2026-09-29', 'detail': 'test data'}], '127.0.0.1', 0)
    return handler, calls


def test_order_only_comparison_and_legacy_links(comparison_handler):
    handler, calls = comparison_handler
    _, _, page = _get(handler, '/compare?order_number_0=BEST&version_0=2.5')
    assert calls == [('', '', '2.5', 'BEST')]
    assert 'name="order_number_0" value="BEST"' in page
    assert '/compare.csv?' in page
    _get(handler, '/compare?c=Testco%7CTestPLC%7C2.5%7CBEST')
    assert calls[-1] == ('Testco', 'TestPLC', '2.5', 'BEST')


def test_comparison_download_preserves_ranked_queries_and_stability(comparison_handler):
    handler, _ = comparison_handler
    query = '?product_0=Same&order_number_0=SECOND&product_1=Same&order_number_1=BEST&version_1=2.5'
    _, headers, body = _get(handler, '/compare.json' + query)
    payload = json.loads(body)
    best, second = payload['results']
    assert best['query']['order_number'] == 'BEST' and best['query']['version'] == '2.5'
    assert best['score'] == 80 and best['robust'] == .9
    assert second['query']['order_number'] == 'SECOND' and second['robust'] == .6
    assert payload['weights'] == {'severity': 1} and payload['provenance']
    assert payload['warnings'] and payload['requested_stability_samples'] == 300
    assert 'retrust-comparison.json' in headers['Content-Disposition']
    _, _, page = _get(handler, '/compare' + query)
    assert '90%' in page and '60%' in page
    assert page.count('PREFER was the most common verdict, appearing in 90%') == 1
    _, _, report_html = _get(handler, '/compare.html' + query)
    assert 'Assessment inputs' in report_html and 'BEST' in report_html
    assert 'Some candidates have firmware specified' in report_html
    assert '90%' in report_html and '60%' in report_html


def test_comparison_csv_neutralizes_formula_inputs(comparison_handler):
    import csv
    import io
    handler, _ = comparison_handler
    _, headers, body = _get(handler, '/compare.csv?product_0=%3Dformula&order_number_0=%40part')
    row = next(csv.DictReader(io.StringIO(body)))
    assert row['product'] == "'=formula"
    assert row['query_product'] == "'=formula"
    assert row['query_order_number'] == "'@part"
    assert headers['Content-Type'].startswith('text/csv')
    assert 'retrust-comparison.csv' in headers['Content-Disposition']


@pytest.mark.parametrize('extension', ['html', 'json', 'csv'])
def test_invalid_comparison_downloads_return_400(handler, extension):
    with pytest.raises(urllib.error.HTTPError) as error:
        _get(handler, f'/compare.{extension}?version_0=2.5')
    assert error.value.code == 400
    assert b'Complete the shortlist' in error.value.read()


def test_comparison_exports_keep_the_candidate_cap(comparison_handler):
    handler, calls = comparison_handler
    query = '&'.join(f'order_number_{i}=P{i}' for i in range(serve.MAX_CANDIDATES + 5))
    _, _, body = _get(handler, '/compare.json?' + query)
    assert len(calls) == len(json.loads(body)['results']) == serve.MAX_CANDIDATES


def test_search_and_comparison_handoff_retain_order_number(db):
    import html
    import re
    from retrust import dossier, match, score
    calls = []

    def assess(vendor, product, version=None, order_number=None):
        calls.append((vendor, product, version, order_number))
        resolution = match.resolve(db, vendor=vendor, product=product, order_number=order_number)
        return score.not_assessed('TestPLC', 'test'), resolution, []

    handler = serve.build_handler(db, assess, {'weights': {}}, dossier, index.stats(db),
                                  [], '127.0.0.1', 0)
    _, _, search_page = _get(handler, '/?q=TC-9000-A1')
    assert 'order_number=TC-9000-A1' in search_page
    _, _, page = _get(handler, '/score?order_number=TC-9000-A1&version=1.2')
    link = html.unescape(re.search(r'href="(/compare\?[^\"]+)"', page).group(1))
    _get(handler, link)
    assert calls == [('', '', '1.2', 'TC-9000-A1')] * 2


def test_comparison_report_escapes_original_inputs(comparison_handler):
    handler, _ = comparison_handler
    _, _, body = _get(handler, '/compare.html?product_0=%3Cscript%3Eevil%3C%2Fscript%3E')
    assert '<script>' not in body
    assert '&lt;script&gt;evil&lt;/script&gt;' in body
    assert 'Assessment inputs' in body


def test_the_notice_names_the_control_the_page_actually_carries():
    """A notice that quotes a label the page does not have sends the reader
    hunting for a control that is not there. The live site said "Edit product
    details" while the control read "Edit product, firmware, or network
    exposure"; both now come from one constant."""
    from retrust import serve
    source = (serve.__file__)
    text = open(source, encoding="utf-8").read()
    # The old, drifted wording must not come back as a literal.
    assert "Edit product details" not in text
    assert serve.EDIT_PANEL in text


def test_inline_links_meet_the_touch_target_floor_on_small_screens():
    """Measured on the live site: the "Vendor profile", "Advisory timeline" and
    footer links rendered 12-15px tall on a 375px viewport, under the 24px WCAG
    2.5.8 floor and awkward for anyone holding a tablet in a plant. Buttons and
    form controls already carry their own 44px, so only the inline prose and
    footer links needed raising."""
    from retrust import webui
    rule = ".helper a,footer a,.empty a,.tnote a"
    assert rule in webui.CSS
    # and it must live inside the small-screen query, not change the desktop line
    small = webui.CSS.split("@media(max-width:700px){")
    assert any(rule in part and "min-height:24px" in part for part in small[1:])


def test_the_build_header_identifies_the_deployed_code():
    """The question that cost the most time on this project was "is the deployed
    code the code I have?". Neither the data snapshot nor the scoring version
    could answer it -- both were identical across builds three commits apart --
    so a stale deploy looked healthy from the outside. The fingerprint hashes
    the package source, so any code difference is visible."""
    from retrust import serve
    assert len(serve.BUILD) == 12 and serve.BUILD.isalnum()
    # Stable for identical source, and actually derived from it.
    assert serve.build_fingerprint() == serve.BUILD


# --- a failed lookup must never be a dead end --------------------------------

def test_a_product_name_in_the_order_number_box_offers_a_way_out(handler):
    """Reported by a user: a product title pasted into the part-number field.

    An order number is matched exactly and never by name, so the page answered
    "not enough data to assess" with no suggestions and nowhere to go. It now
    names the mistake and lists the product the text actually describes.
    """
    _, _, body = _get(handler, '/score?order_number=Testco+Electric+TestPLC+9000+Alpha')
    assert 'NOT ASSESSED' in body
    flat = " ".join(body.split())
    assert 'That product name could not be identified' in flat
    assert 'Did you mean' in body
    assert 'product=' in body, 'the suggestions must be clickable into a real lookup'


def test_an_absent_order_number_explains_exact_matching(handler):
    _, _, body = _get(handler, '/score?order_number=6ES7999-9ZZ99-9ZZ9')
    flat = " ".join(body.split())
    assert 'No advisory in this corpus names that order number' in flat
    assert 'product name rather than' not in flat, 'a short code is not a name'


def test_a_failed_lookup_always_says_something(handler):
    """Whatever was typed, the page offers a next step rather than stopping."""
    for query in ('order_number=Testco+Electric+TestPLC+9000+Alpha',
                  'order_number=6ES7999-9ZZ99-9ZZ9',
                  'vendor=Nope&product=Nothing',
                  'vendor=Testco+Electric&product=Nonesuch+1'):
        _, _, body = _get(handler, '/score?' + query)
        flat = " ".join(body.split())
        assert ('Did you mean' in flat or 'Nothing close was found' in flat
                or 'No advisory in this corpus' in flat), query


@pytest.mark.parametrize('vendor,name,title', [
    ('Moxa', 'Moxa EDS-405A/EDS-408A series managed Ethernet switches',
     'Moxa Moxa EDS-405A/EDS-408A series managed Ethernet switches'),
    ('ABB', 'AC500', 'ABB AC500'),
    ('Siemens', 'SIMATIC S7-1500', 'Siemens SIMATIC S7-1500'),
    ('Schneider Electric', 'Modicon M340', 'Schneider Electric Modicon M340'),
])
def test_full_title_in_order_field_retains_all_assessment_answers(db, tmp_path, vendor, name, title):
    import html
    import re
    from urllib.parse import parse_qs, urlencode, urlsplit
    from retrust import cli, dossier
    db.execute('UPDATE product SET vendor=?,vendor_key=?,name=?,name_key=?',
               (vendor, index.normalize_vendor(vendor), name, index.normalize_name(name)))
    context = cli._context(data_dir=str(tmp_path))
    calls = []
    def assess(vendor, product, version=None, order_number=None, **owner):
        calls.append((vendor, product, version, order_number, owner))
        return cli._assess(db, vendor, product, version, order_number, context=context, **owner)
    handler = serve.build_handler(db, assess, context, dossier, index.stats(db),
                                  index.provenance(db), '127.0.0.1', 0)
    answers = dict(network_exposure='internet_ot', assessment_type='installed',
                   interface='exposed', prerequisites='unknown', consequence='safety',
                   remediation='not_affected')
    _, _, output = _get(handler, '/score?' + urlencode(dict(order_number=title, **answers)))
    assert 'Product name recognised' in output and 'NOT ASSESSED' not in output
    assert calls[0][:4] == (vendor, name, None, None)
    for key, value in answers.items():
        assert calls[0][4].get(key, 'unknown') == value
    link = html.unescape(re.search(r'href="(/export.json[^" ]+)"', output)[1])
    query = parse_qs(urlsplit(link).query)
    assert query['vendor'] == [vendor] and query['product'] == [name]
    assert not query.get('order_number')
    for key, value in answers.items():
        assert query[key] == [value]
    assert 'not sure' not in output.lower()


def test_lookup_suggestions_keep_firmware_and_network_answers(handler):
    import html
    import re
    from urllib.parse import parse_qs, urlsplit
    _, _, output = _get(handler, '/score?order_number=Testco+Electric+TestPLC+9000+Alpha'
                        '&version=1.2&network_exposure=it_ot&interface=blocked'
                        '&consequence=minor&assessment_type=installed&remediation=applied'
                        '&prerequisites=unsatisfiable')
    links = re.findall(r'<a class="hit" href="([^" ]+)"', output)
    queries = [parse_qs(urlsplit(html.unescape(link)).query) for link in links]
    products = [query for query in queries if 'product' in query]
    assert products
    for query in products:
        for key, value in dict(version='1.2',network_exposure='it_ot',interface='blocked',
                              consequence='minor',assessment_type='installed',
                              remediation='applied',prerequisites='unsatisfiable').items():
            assert query[key] == [value]
        assert not query.get('order_number')


def test_known_product_without_applicable_findings_explains_the_difference(db, tmp_path):
    from retrust import cli, dossier
    context = cli._context(data_dir=str(tmp_path))
    def assess(vendor, product, version=None, order_number=None, **owner):
        return cli._assess(db, vendor, product, version, order_number, context=context, **owner)
    handler = serve.build_handler(db, assess, context, dossier, index.stats(db),
                                  index.provenance(db), '127.0.0.1', 0)
    _, _, output = _get(handler, '/score?vendor=Testco&product=TestPLC+9000&version=9.0'
                        '&network_exposure=it_ot&interface=exposed&consequence=safety'
                        '&prerequisites=satisfiable&remediation=not_affected')
    assert 'NOT ASSESSED' in output and 'no applicable risk evidence' in output
    assert 'The product was identified' in output and 'Your answers are recorded' in output
    assert 'not enough data to assess' not in output
