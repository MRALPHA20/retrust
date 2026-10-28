"""The same-origin enhancement script, its route, its policy and /search.json.

The browser behaviour is in tests/e2e/test_enhance_browser.py; this file holds
what can be checked without one: the bytes served, the headers and policy they
travel with, the JSON contract, and the properties that keep the script from
ever turning data into markup or reaching another origin.
"""
import hashlib
import http.client
import json
import re
import threading
import urllib.parse

import pytest

from retrust import assets, cli, dossier, enhance, identity, index, report, serve, webui

WIDGETS = 12


def _advisory():
    branches = [{"category": "product_name", "name": f"Widget {100 + n} (WID-{100 + n}-A)",
                 "branches": [{"category": "product_version_range", "name": "vers:intdot/<2.0",
                               "product": {"product_id": f"P{n}", "name": f"Widget {100 + n}"}}]}
                for n in range(WIDGETS)]
    return {
        "document": {"title": "T", "tracking": {
            "id": "ICSA-26-001-01", "initial_release_date": "2026-01-01T00:00:00Z"}},
        "product_tree": {"branches": [{"category": "vendor", "name": 'Testco </script> "Electric"',
                                       "branches": branches}]},
        "vulnerabilities": [{"cve": "CVE-2026-0001",
                             "product_status": {"known_affected": [f"P{n}" for n in range(WIDGETS)]},
                             "scores": [{"cvss_v3": {"baseScore": 7.5},
                                         "products": [f"P{n}" for n in range(WIDGETS)]}]}],
    }


@pytest.fixture
def handler(tmp_path):
    directory = tmp_path / "csaf"
    directory.mkdir()
    (directory / "a.json").write_text(json.dumps(_advisory()))
    path = tmp_path / "t.db"
    connection, _ = index.build(str(path), str(directory))
    context = cli._context(str(tmp_path))
    stats, provenance = index.stats(connection), index.provenance(connection)
    connection.close()
    context["screening"].close()
    return serve.build_concurrent_handler(path, cli._assess, context, dossier,
                                          stats, provenance, "127.0.0.1", 0)


@pytest.fixture
def server(handler):
    httpd = serve.ConcurrentHTTPServer(("127.0.0.1", 0), handler, 2)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()
    thread.join(timeout=5)
    httpd.server_close()


def request(server, path, method="GET"):
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=10)
    try:
        connection.request(method, path)
        response = connection.getresponse()
        return response.status, {k: v for k, v in response.getheaders()}, response.read()
    finally:
        connection.close()


# --- the script itself ------------------------------------------------------

@pytest.mark.parametrize("forbidden", [
    "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(",
    "new Function", "http://", "https://", "importScripts", "XMLHttpRequest",
    "WebSocket", "sendBeacon", "localStorage", "document.cookie"])
def test_the_script_never_builds_markup_or_reaches_out(forbidden):
    assert forbidden not in enhance.SCRIPT


def test_the_only_requests_are_a_same_origin_search_and_a_head_check_of_an_export_link():
    assert re.findall(r"fetch\(([^,]+),", enhance.SCRIPT) == [
        "'/search.json?q=' + encodeURIComponent(typed)", "href"]
    # The second is a HEAD, only after the same-origin path guard, and it never
    # reads the answer's body (no response.text/json on it).
    export = enhance.SCRIPT[enhance.SCRIPT.index("function initExportMenu"):
                            enhance.SCRIPT.index("// ---------------------------------------------------------- loading")]
    assert "!safePath(href)" in export and "method: 'HEAD'" in export
    assert ".text()" not in export and ".json()" not in export


def test_a_resubmit_is_not_swallowed_and_loading_has_a_safety_reset():
    loading = enhance.SCRIPT[enhance.SCRIPT.index("// ---------------------------------------------------------- loading"):
                             enhance.SCRIPT.index("// ------------------------------------------------------ supplier")]
    assert "preventDefault" not in loading
    assert "var SAFETY_MS = 90000;" in loading and "setTimeout(stopLoading, SAFETY_MS)" in loading
    assert "'pageshow', stopLoading" in loading and "visibilitychange" in loading


def test_the_script_is_plain_ascii_and_strict():
    assert all(ord(char) < 128 for char in enhance.SCRIPT)
    assert enhance.SCRIPT.lstrip().startswith("'use strict';")


def test_every_navigation_target_is_checked_as_a_local_path():
    # window.location is only ever assigned through the safePath guard.
    assert enhance.SCRIPT.count("location.assign(") == 1
    assert "safePath(href)) { window.location.assign(href)" in enhance.SCRIPT


# --- the route --------------------------------------------------------------

def test_the_script_is_served_with_the_page_policy_headers(server):
    status, headers, body = request(server, f"{assets.SCRIPT_PATH}?v={assets.script_version()}")
    assert status == 200
    assert headers["Content-Type"] == "text/javascript; charset=utf-8"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Cache-Control"] == "public, max-age=31536000, immutable"
    policy = headers["Content-Security-Policy"]
    assert "script-src 'self'" in policy and "connect-src 'self'" in policy
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert body == enhance.SCRIPT.encode("utf-8")
    assert int(headers["Content-Length"]) == len(body)


def test_the_version_in_the_page_is_the_hash_of_the_bytes(server):
    _, _, page = request(server, "/")
    named = re.search(rb'<script src="/static/retrust\.js\?v=([0-9a-f]{8})" defer></script>', page)
    assert named
    assert named.group(1).decode() == hashlib.sha256(enhance.SCRIPT.encode()).hexdigest()[:8]


def test_head_has_headers_and_no_body(server):
    status, headers, body = request(server, assets.SCRIPT_PATH, "HEAD")
    assert status == 200 and body == b""
    assert headers["Content-Type"] == "text/javascript; charset=utf-8"
    assert int(headers["Content-Length"]) == len(enhance.SCRIPT.encode("utf-8"))


def test_the_script_is_served_while_every_calculation_slot_is_taken(server):
    taken = 0
    while server._calculations.acquire(blocking=False):
        taken += 1
    try:
        assert request(server, "/search.json?q=Widget")[0] == 503      # a calculation
        status, headers, _ = request(server, assets.SCRIPT_PATH)
        assert status == 200 and headers["Content-Type"].startswith("text/javascript")
    finally:
        for _ in range(taken):
            server._calculations.release()


@pytest.mark.parametrize("path", [
    "/static/retrust.js/", "/static/retrust.jsx", "/static/../retrust/enhance.py",
    "/static/%2e%2e/retrust/enhance.py", "/static/retrust.js/../x", "/static/..%5cretrust.js",
    "/static/RETRUST.JS", "/static/enhance.py", "/static//retrust.js", "/retrust.js"])
def test_traversal_and_lookalikes_are_404(server, path):
    status, _, body = request(server, path)
    assert status == 404
    assert b"use strict" not in body


def test_pages_remain_uncached(server):
    for path in ("/", "/about", "/search.json?q=Widget"):
        assert request(server, path)[1]["Cache-Control"] == "no-store", path


def test_the_exported_report_is_still_script_free():
    markup = report.render([], title="ReTrust export")
    assert "<script" not in markup.lower()
    assert "src=" not in markup and "https://" not in markup


def test_the_shell_names_the_script_once_and_marks_hosted_mode(monkeypatch):
    monkeypatch.delenv("RETRUST_HOSTED", raising=False)
    local = webui.page("About", "<p>x</p>")
    assert local.count("<script") == 1 and "data-hosted" not in local
    assert local.rstrip().endswith(assets.script_tag() + "</body></html>")
    monkeypatch.setenv("RETRUST_HOSTED", "1")
    hosted = webui.page("About", "<p>x</p>")
    assert hosted.count("<script") == 1
    assert '<html lang="en" data-theme="dark" data-hosted="1">' in hosted


# --- the fingerprint --------------------------------------------------------

def test_the_fingerprint_changes_when_the_script_changes(tmp_path, monkeypatch):
    package = tmp_path / "retrust"
    package.mkdir()
    source = package / "enhance.py"
    source.write_text('SCRIPT = "a"\n')
    monkeypatch.setattr(identity, "__file__", str(package / "identity.py"))
    compute = identity.build_fingerprint.__wrapped__
    before = compute()
    source.write_text('SCRIPT = "b"\n')
    assert compute() != before
    # And the real module sits where the real fingerprint looks.
    assert (identity.Path(identity.__file__).parent / "enhance.py").exists()


def test_the_script_version_follows_the_content(monkeypatch):
    before = assets.script_version()
    monkeypatch.setattr(enhance, "SCRIPT", enhance.SCRIPT + "\n// changed")
    assets.script_version.cache_clear()
    try:
        assert assets.script_version() != before
    finally:
        monkeypatch.undo()
        assets.script_version.cache_clear()
        assets._cached.cache_clear()
    assert assets.script_version() == before


# --- /search.json -----------------------------------------------------------

def _json(server, path, method="GET"):
    status, headers, body = request(server, path, method)
    return status, headers, (json.loads(body) if body else None)


def test_the_contract_shape_and_headers(server):
    status, headers, data = _json(server, "/search.json?q=Widget+105")
    assert status == 200
    assert headers["Content-Type"] == "application/json; charset=utf-8"
    assert headers["Cache-Control"] == "no-store"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert "Content-Disposition" not in headers
    assert set(data) == {"query", "results", "empty"}
    assert data["query"] == "Widget 105" and data["empty"] is False
    assert data["results"]
    for row in data["results"]:
        assert set(row) == {"order_number", "name", "vendor", "href"}
        assert all(isinstance(value, str) for value in row.values())
        assert row["href"].startswith("/score?")


def test_it_returns_the_same_hits_as_the_search_page(server):
    _, _, data = _json(server, "/search.json?q=WID-103-A")
    assert [row["name"] for row in data["results"]] == ["Widget 103 (WID-103-A)"]
    assert data["results"][0]["order_number"] == "WID-103-A"
    _, _, page = request(server, "/?q=WID-103-A")
    assert data["results"][0]["href"].replace("&", "&amp;").encode() in page


def test_results_are_capped_at_eight(server):
    _, _, data = _json(server, "/search.json?q=Widget")
    assert len(data["results"]) == serve.SUGGESTIONS == 8
    # The page lists more: the cap belongs to the popover, not to the search.
    _, _, page = request(server, "/?q=Widget")
    assert page.count(b"/score?vendor=") > 8


def test_a_nonsense_query_is_empty_true(server):
    _, _, data = _json(server, "/search.json?q=zzqqxx")
    assert data["results"] == [] and data["empty"] is True


@pytest.mark.parametrize("path", ["/search.json", "/search.json?q=", "/search.json?q=W",
                                  "/search.json?q=%20%20"])
def test_a_short_or_missing_query_has_no_results_and_is_not_empty(server, path):
    status, _, data = _json(server, path)
    assert status == 200 and data["results"] == [] and data["empty"] is False


def test_the_query_is_limited_to_200_characters(server):
    _, _, data = _json(server, "/search.json?q=" + "a" * 500)
    assert len(data["query"]) == 200


def test_hostile_text_round_trips_as_data_not_markup(server):
    payload = '</script><img src=x onerror=alert(1)>"\'\\u0000'
    status, headers, body = request(server, "/search.json?q=" + urllib.parse.quote(payload))
    assert status == 200
    assert headers["Content-Type"].startswith("application/json")
    assert json.loads(body)["query"] == payload[:200]
    # JSON.parse on the client gets the string back untouched; nothing is HTML.
    assert "text/html" not in headers["Content-Type"]


def test_vendor_names_with_markup_characters_come_back_as_plain_strings(server):
    _, _, data = _json(server, "/search.json?q=Widget+101")
    assert data["results"][0]["vendor"] == 'Testco </script> "Electric"'


def test_head_works(server):
    status, headers, body = request(server, "/search.json?q=Widget", "HEAD")
    assert status == 200 and body == b""
    assert headers["Content-Type"] == "application/json; charset=utf-8"


def test_other_methods_are_not_implemented(server):
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=10)
    try:
        connection.request("POST", "/search.json?q=Widget", body=b"x")
        assert connection.getresponse().status == 501
    finally:
        connection.close()
