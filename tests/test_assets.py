"""Bundled fonts: the loader, the CSS, the routes and the packaging."""
import hashlib
import http.client
import re
import threading
from pathlib import Path

import pytest

from retrust import assets, cli, dossier, identity, index, serve

ROOT = Path(__file__).resolve().parent.parent
FONT_DIR = ROOT / "retrust" / "static" / "fonts"

# Change together with retrust/static/fonts/README.md when a font is replaced.
FONT_SHA256 = {
    "IBMPlexSans-Regular.woff2": "b5ad7bd39f996144915f0ad9849a90183b27d8c28ad97ed98af5b1bebc51f6b1",
    "IBMPlexSans-Medium.woff2": "b5610af04d0d4b5a14a621d96d974b993e945a065db1a8861918f69ef9321934",
    "IBMPlexSans-SemiBold.woff2": "fff0ab3a88b0b4aa0b693e4f0201359a15183b08e3fa5696d1918d8f0ade8ad5",
    "IBMPlexSans-Bold.woff2": "914f1400f363e636b6f9cc7965aa807ff01e93586e1437617525cba0a62aa78d",
    "IBMPlexMono-Regular.woff2": "e8993d946649b9d01abb1ed06d574b19d8ea3e66b5c3948602db335c44c18e56",
    "IBMPlexMono-Medium.woff2": "41201b658a328b9d00368215c2f1102770f80b15952ab82631e4006255e6365d",
    "IBMPlexMono-SemiBold.woff2": "b7acd05041ab65f3b7039e218ddd893065e11a07e85ea85019473152a51b6b7d",
}


@pytest.fixture
def handler(tmp_path):
    """The production handler: each request opens its own read-only reader."""
    path = tmp_path / "t.db"
    connection = index.connect(path)
    with connection:
        connection.execute("INSERT INTO advisory VALUES(?,?,?,?,?)",
                           ("A", "Notice", "2026-01-01", "fixture", 0))
    index.record_provenance(connection, "CISA KEV", "Fixture data")
    context = cli._context(str(tmp_path))
    stats, provenance = index.stats(connection), index.provenance(connection)
    connection.close()
    context["screening"].close()
    return serve.build_concurrent_handler(path, cli._assess, context, dossier,
                                          stats, provenance, "127.0.0.1", 0)


@pytest.fixture
def server(handler):
    """A real threaded server, so several requests can be made to one."""
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


# --- files and packaging ----------------------------------------------------

def test_font_hashes_are_pinned():
    assert sorted(p.name for p in FONT_DIR.glob("*.woff2")) == sorted(FONT_SHA256)
    for name, expected in FONT_SHA256.items():
        assert hashlib.sha256((FONT_DIR / name).read_bytes()).hexdigest() == expected
    assert (FONT_DIR / "OFL.txt").is_file() and (FONT_DIR / "README.md").is_file()


def test_the_fonts_are_listed_as_package_data():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "[tool.setuptools.package-data]" in text
    assert re.search(r'retrust\s*=\s*\[[^\]]*"static/fonts/\*\.woff2"[^\]]*"static/fonts/OFL\.txt"', text)
    assert "*.woff2 binary" in (ROOT / ".gitattributes").read_text(encoding="utf-8")


# --- the CSS ----------------------------------------------------------------

def test_served_css_points_at_versioned_font_routes():
    css = assets.font_face_css(True)
    assert css.count("@font-face") == 7
    assert css.count("font-display:swap") == 7
    for name, digest in FONT_SHA256.items():
        assert f"url(/static/fonts/{name}?v={digest[:8]}) format(\"woff2\")" in css
    assert "http" not in css
    for family, weights in (("IBM Plex Sans", (400, 500, 600, 700)),
                            ("IBM Plex Mono", (400, 500, 600))):
        for weight in weights:
            assert f'font-family:"{family}";font-style:normal;font-weight:{weight};' in css


def test_the_self_contained_css_names_only_installed_fonts():
    css = assets.font_face_css(False)
    assert css.count("@font-face") == 7
    assert "url(" not in css and "http" not in css
    assert 'local("IBM Plex Sans")' in css and 'local("IBM Plex Mono SemiBold")' in css


# --- the loader -------------------------------------------------------------

def test_lookup_is_exact_and_returns_bytes():
    asset = assets.static_asset("/static/fonts/IBMPlexSans-Regular.woff2")
    assert asset.content_type == "font/woff2"
    assert hashlib.sha256(asset.body).hexdigest() == FONT_SHA256["IBMPlexSans-Regular.woff2"]
    assert asset.cache_control == "public, max-age=31536000, immutable"


@pytest.mark.parametrize("path", [
    "/static/fonts/../x", "/static/fonts/..\\x", "/static/fonts/a/b.woff2",
    "/static/fonts/unknown.woff2", "/static/fonts/OFL.txt", "/static/fonts/",
    "/static/fonts/%2e%2e/x", "/static/fonts/IBMPlexSans-Regular.woff2/",
    "/static/fonts/ibmplexsans-regular.woff2", "static/fonts/IBMPlexSans-Regular.woff2", ""])
def test_lookup_rejects_everything_else(path):
    assert assets.static_asset(path) is None


def test_a_missing_file_is_none_not_a_crash(monkeypatch):
    assets._cached.cache_clear()
    monkeypatch.setattr(assets, "_read", lambda parts, name: None)
    try:
        assert assets.static_asset("/static/fonts/IBMPlexSans-Regular.woff2") is None
    finally:
        assets._cached.cache_clear()


# --- the routes -------------------------------------------------------------

@pytest.mark.parametrize("name", sorted(FONT_SHA256))
def test_each_font_route_serves_the_file(server, name):
    status, headers, body = request(server, f"/static/fonts/{name}?v=whatever")
    assert status == 200
    assert headers["Content-Type"] == "font/woff2"
    assert headers["Cache-Control"] == "public, max-age=31536000, immutable"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'none'" in headers["Content-Security-Policy"]
    assert "font-src 'self'" in headers["Content-Security-Policy"]
    assert int(headers["Content-Length"]) == len(body)
    assert hashlib.sha256(body).hexdigest() == FONT_SHA256[name]


def test_pages_are_still_not_cacheable(server):
    for path in ("/", "/about", "/healthz", "/static/fonts/nope.woff2"):
        _, headers, _ = request(server, path)
        assert headers["Cache-Control"] == "no-store", path


@pytest.mark.parametrize("path", [
    "/static/fonts/../x", "/static/fonts/%2e%2e/x", "/static/fonts/..%2fx",
    "/static/fonts/%2e%2e%2fretrust/serve.py", "/static/fonts/..%5cx",
    "/static/fonts/nope.woff2", "/static/fonts/OFL.txt", "/static/", "/static"])
def test_traversal_and_unknown_files_are_404(server, path):
    status, _, body = request(server, path)
    assert status == 404
    assert b"woff2" not in body[:4]          # not a font


def test_head_has_headers_and_no_body(server):
    status, headers, body = request(server, "/static/fonts/IBMPlexMono-Regular.woff2", "HEAD")
    assert status == 200 and body == b""
    assert headers["Content-Type"] == "font/woff2"
    assert int(headers["Content-Length"]) == (FONT_DIR / "IBMPlexMono-Regular.woff2").stat().st_size


def test_fonts_are_served_while_every_calculation_slot_is_taken(server):
    taken = 0
    while server._calculations.acquire(blocking=False):
        taken += 1
    try:
        assert taken == 2
        assert request(server, "/about")[0] == 503
        status, headers, _ = request(server, "/static/fonts/IBMPlexSans-Bold.woff2")
        assert status == 200 and headers["Content-Type"] == "font/woff2"
    finally:
        for _ in range(taken):
            server._calculations.release()


def test_the_safety_text_describes_the_cache_policy():
    assert "No page or download is cached" in serve.SAFETY
    assert "Only the bundled font files and the enhancement script are cacheable" in serve.SAFETY


# --- the build fingerprint --------------------------------------------------

def test_the_fingerprint_covers_static_files(tmp_path, monkeypatch):
    package = tmp_path / "retrust"
    (package / "static" / "fonts").mkdir(parents=True)
    (package / "a.py").write_text("x = 1\n")
    font = package / "static" / "fonts" / "f.woff2"
    font.write_bytes(b"one")
    monkeypatch.setattr(identity, "__file__", str(package / "identity.py"))
    compute = identity.build_fingerprint.__wrapped__
    before = compute()
    assert compute() == before
    font.write_bytes(b"two")
    changed = compute()
    assert changed != before
    (package / "static" / "fonts" / "g.woff2").write_bytes(b"new")
    assert compute() not in (before, changed)
    (package / "a.py").write_text("x = 2\n")
    assert compute() != before
