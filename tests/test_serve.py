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

    def assess(vendor, product, version=None):
        assessment = score.not_assessed(f"{vendor} {product}".strip(), "stub")
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


# --- routing ---------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/", "/?q=test", "/score?vendor=Testco&product=TestPLC",
    "/compare?c=Testco%7CTestPLC", "/vendor?name=Testco", "/about",
    "/alternatives", "/alternatives?vendor=Testco&product=TestPLC",
    "/timeline", "/timeline?vendor=Testco",
    "/timeline?vendor=Testco&product=TestPLC",
    "/annex", "/annex?vendor=Testco&product=TestPLC"])
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


def test_the_timeline_page_keeps_its_caveat(handler):
    _, _, body = _get(handler, "/timeline?vendor=Testco")
    assert "not safety" in body


def test_the_annex_page_is_pasteable_text(handler):
    _, _, body = _get(handler, "/annex?vendor=Testco&product=TestPLC")
    assert "RFQ SECURITY ANNEX" in body
    assert "<pre" in body                    # the annex is a document, not a widget


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
