"""Control Room shell (WP4): header, navigation, snapshot status, error pages."""

from script_policy import without_enhancement
import re
import threading
import urllib.error
import urllib.request
from datetime import date

import pytest

from design_lint import css_lint
from retrust import components, design, report, score, serve, webui
from test_serve import db, handler  # noqa: F401  (fixtures)

TODAY = date(2026, 10, 28)


def _fetch(handler, path, headers=None):
    """Like test_serve._get but returns error responses instead of raising."""
    httpd = serve.serve(handler, "127.0.0.1", 0, forever=False)
    port = httpd.server_address[1]
    caught = {}

    def fetch():
        request = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
                                         headers=headers or {})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                caught["r"] = (response.status, response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            caught["r"] = (error.code, error.read().decode("utf-8"))
        except Exception as error:
            caught["e"] = error

    client = threading.Thread(target=fetch, daemon=True)
    client.start()
    httpd.handle_request()
    client.join(timeout=10)
    httpd.server_close()
    if "e" in caught:
        raise caught["e"]
    return caught["r"]


def _header(body):
    return body[body.index('<header class="rt-header">'):body.index("</header>")]


ROUTES = [
    ("/", "/"), ("/?q=test", "/"),
    ("/score?vendor=Testco&product=TestPLC", "/score"),
    ("/compare?c=Testco%7CTestPLC", "/compare"),
    ("/vendor?name=Testco", "/"), ("/about", "/about"), ("/demo", "/"),
    ("/alternatives", "/score"),
    ("/alternatives?vendor=Testco&product=TestPLC", "/score"),
    ("/timeline", "/"), ("/timeline?vendor=Testco", "/"),
    ("/timeline?vendor=Testco&product=TestPLC", "/"),
    ("/annex", "/score"), ("/annex?vendor=Testco&product=TestPLC", "/score"),
    ("/ssvc", "/score"),
    ("/ssvc?vendor=Testco&product=TestPLC&exposure=open&automatable=yes&impact=high",
     "/score"),
    ("/lev", "/score"), ("/lev?vendor=Testco&product=TestPLC", "/score"),
    ("/vendor", "/"), ("/compare", "/compare"),
]


@pytest.mark.parametrize("path, expected", ROUTES)
def test_four_nav_links_and_aria_current_per_route(handler, path, expected):
    status, body = _fetch(handler, path)
    assert status == 200
    nav = re.search(r'<nav class="rt-nav" aria-label="Primary">(.*?)</nav>', body, re.S).group(1)
    links = re.findall(r'<a href="([^"]+)"([^>]*)>([^<]+)</a>', nav)
    assert [(h, t) for h, _, t in links] == [
        ("/score", "Assess"), ("/compare", "Compare"), ("/", "Search"),
        ("/about", "Methodology")]
    current = [h for h, attrs, _ in links if 'aria-current="page"' in attrs]
    assert current == [expected]


def test_old_sidebar_and_mobile_menu_are_gone(handler):
    _, body = _fetch(handler, "/")
    for gone in ('class="sidebar"', "mobile-menu", "desktop-nav", "topbar"):
        assert gone not in body


def test_header_structure(handler):
    _, body = _fetch(handler, "/")
    assert body.index('class="skip-link"') < body.index("<header")
    assert body.index("<body") < body.index('class="skip-link"') < body.index("<header")
    header = _header(body)
    assert 'class="rt-wordmark">ReTrust<' in header
    assert f'class="rt-model">{score.SCORING_VERSION}<' in header
    assert 'viewBox="0 0 24 24"' in header and 'width="22"' in header
    assert '<main id="main"' in body


def test_global_search_form(handler):
    _, body = _fetch(handler, "/")
    form = re.search(r"<form class=\"rt-search\".*?</form>", _header(body), re.S).group(0)
    assert 'action="/"' in form and 'method="get"' in form
    assert 'name="q"' in form and 'maxlength="200"' in form
    assert 'placeholder="Order no. or vendor / model"' in form
    assert re.search(r'<label[^>]* for="rt-global-q"', form)
    assert 'id="rt-global-q"' in form


def test_footer_carries_disclaimer_and_links(handler):
    _, body = _fetch(handler, "/")
    footer = body[body.index("<footer"):]
    assert ("ReTrust supports procurement review. It is not a probability of "
            "compromise or a certification.") in footer
    assert 'href="/about"' in footer and 'href="/about#sources"' in footer
    for route, _ in webui.CONTEXTUAL_PAGES:
        assert f'href="{route}"' in footer


def test_no_script_anywhere(handler):
    for path in ("/", "/about", "/score?vendor=Testco&product=TestPLC", "/nope"):
        _, body = _fetch(handler, path)
        assert "<script" not in without_enhancement(body)


def test_hosted_and_local_strings(handler, monkeypatch):
    monkeypatch.setenv("RETRUST_HOSTED", "1")
    _, body = _fetch(handler, "/")
    assert "Hosted assessment" in body and "Queries are processed on this server" in body
    assert "Offline assessment" not in body and "Private decisions" not in body
    assert "Snapshot · hosted" in body
    monkeypatch.delenv("RETRUST_HOSTED")
    _, body = _fetch(handler, "/")
    assert "Offline assessment" in body and "Local workspace" in body
    assert "Hosted assessment" not in body and "Snapshot · offline" in body


# --- snapshot status ---------------------------------------------------------

def _prov(kev, epss):
    rows = []
    if kev:
        rows.append({"source": "CISA KEV", "detail": "1 entries", "captured": kev})
    if epss:
        rows.append({"source": "FIRST EPSS", "detail": "1 scores", "captured": epss})
    return rows


def test_snapshot_current():
    html = webui.snapshot_status(_prov("2026-10-27", "2026-10-28"), TODAY, False)
    assert "rt-snap--current" in html and "●" in html
    assert "Snapshot · offline · 2026-10-27" in html
    assert "stale" not in html and "missing" not in html
    assert 'role="alert"' not in html


def test_snapshot_exactly_at_the_limit_is_current_and_over_it_is_stale():
    assert "rt-snap--current" in webui.snapshot_status(
        _prov("2026-10-14", "2026-10-28"), TODAY, False)
    html = webui.snapshot_status(_prov("2026-10-13", "2026-10-28"), TODAY, True)
    assert "rt-snap--stale" in html and "stale" in html and "◆" in html
    assert "Snapshot · hosted · 2026-10-13" in html
    assert 'role="alert"' not in html


@pytest.mark.parametrize("kev, epss, word", [
    (None, "2026-10-28", "KEV missing"), ("2026-10-28", None, "EPSS missing"),
    (None, None, "KEV and EPSS missing")])
def test_snapshot_missing(kev, epss, word):
    html = webui.snapshot_status(_prov(kev, epss), TODAY, False)
    assert "rt-snap--missing" in html and word in html and "■" in html
    assert 'role="alert"' not in html


def test_snapshot_unknown_without_request_context():
    assert webui.CURRENT_SNAPSHOT.get() is None
    assert "Snapshot · unknown" in webui.page("ReTrust", "")


def test_page_reads_the_request_scoped_snapshot_and_it_resets(handler):
    _, body = _fetch(handler, "/")
    assert "rt-snap--missing" in body       # the fixture index has no KEV
    assert 'role="alert"' not in _header(body)
    assert webui.CURRENT_SNAPSHOT.get() is None


# --- error pages -------------------------------------------------------------

def test_error_pages_render_in_the_shell_with_role_alert(handler):
    status, body = _fetch(handler, "/nope")
    assert status == 404
    assert '<header class="rt-header">' in body and '<main id="main"' in body
    assert 'role="alert"' in body and "ERROR" in body and "No such page" in body
    assert 'href="/"' in body
    status, body = _fetch(handler, "/compare.html?version_0=2.5")
    assert status == 400 and 'role="alert"' in body and "Complete the shortlist" in body
    assert 'href="/compare"' in body
    status, body = _fetch(handler, "/", headers={"Host": "evil.example"})
    assert status == 403 and 'role="alert"' in body and "<header" in body


def test_error_page_escapes_the_message():
    markup = webui.error_page("Error", "That did not work", "<b>x</b>")
    assert "&lt;b&gt;x&lt;/b&gt;" in markup and "<b>x</b>" not in markup
    assert 'role="alert"' in markup


# --- stylesheet ----------------------------------------------------------------

def test_assembled_css_order_and_lint():
    css = webui.STYLESHEET
    parts = [design.theme_css(design.DARK, ":root"), design.BASE_CSS, components.CSS,
             report.RESULT_CSS, webui.SHELL_CSS, webui.PAGE_CSS, design.PRINT_CSS]
    positions = [css.index(part[:60]) for part in parts]
    assert positions == sorted(positions)
    assert css_lint(css) == []
    assert "@import" not in css and "url(data:" not in css


def test_page_is_one_style_block_with_dark_theme(handler):
    _, body = _fetch(handler, "/")
    assert body.count("<style>") == 1
    assert '<html lang="en" data-theme="dark">' in body


def test_every_custom_property_in_result_and_page_css_is_defined():
    theme = design.theme_css(design.DARK, ":root") + webui.SHELL_CSS
    defined = set(re.findall(r"(--[\w-]+)\s*:", theme))
    # --vc is set inline per verdict block by report.py, with a fallback.
    used = set(re.findall(r"var\((--[\w-]+)", report.RESULT_CSS + webui.PAGE_CSS
                          + webui.SHELL_CSS)) - {"--vc"}
    assert used - defined == set()
    for alias in ("--ink", "--soft", "--faint", "--panel", "--field", "--sunk", "--cond"):
        assert alias in defined


def test_small_screen_rules():
    assert "@media(max-width:639px)" in webui.SHELL_CSS
    assert "overflow-x:auto" in webui.SHELL_CSS
    assert "@media(max-width:1099px)" in webui.SHELL_CSS
    assert "main.wrap{max-width:1360px" in webui.SHELL_CSS


def test_related_links_exclude_the_active_page():
    html = webui.related_links("/ssvc")
    assert 'href="/ssvc"' not in html and 'href="/lev"' in html
    assert "<nav" not in html
