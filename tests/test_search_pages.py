"""WP8: Search, Methodology and the secondary pages (spec 4.3, 4.19, 4.23, 5.3)."""

from script_policy import without_enhancement
import html
import re
import urllib.parse

import pytest

from retrust import dossier, index, questions, serve, webviews
from test_serve import ADVISORY, _get, db, handler  # noqa: F401  (fixtures)

from design_lint import css_lint

PAGES = ["/", "/?q=TestPLC", "/?q=zzzzqqq", "/about", "/demo", "/vendor?name=Testco",
         "/vendor", "/timeline", "/timeline?vendor=Testco&product=TestPLC",
         "/annex", "/annex?vendor=Testco&product=TestPLC", "/ssvc", "/lev",
         "/alternatives", "/alternatives?vendor=Testco&product=TestPLC"]


# --- search -----------------------------------------------------------------

def test_result_rows_follow_the_popover_anatomy(handler):
    _, _, body = _get(handler, "/?q=TC-9000-A1")
    row = re.search(r'<a class="hit hit--product" href="([^"]+)">(.*?)</a>', body, re.S)
    assert row, "a result is an <a class=hit>"
    assert "order_number=TC-9000-A1" in html.unescape(row[1])
    assert '<span class="hit__id">' in row[2]            # order number, Mono cyan slot
    assert '<span class="hit__name">' in row[2]          # product name, Sans
    assert '<span class="hit__vendor">' in row[2]        # vendor, Mono muted, right
    assert '<strong class="hit__m">TC-9000-A1</strong>' in row[2]


def test_highlight_escapes_text_and_matches_on_raw_text():
    assert webviews.highlight("A <b> & C", "b") == (
        'A &lt;<strong class="hit__m">b</strong>&gt; &amp; C')
    # "amp" must not match inside the escaped ampersand.
    assert "<strong" not in webviews.highlight("A & C", "amp")
    assert webviews.highlight("x", "") == "x"
    assert webviews.highlight("Moxa EDS", "moxa eds").count("<strong") == 1


def test_no_results_copy_and_query_is_escaped(handler):
    _, _, body = _get(handler, "/?q=" + urllib.parse.quote('<i>"zzzqq'))
    assert ('No product matches "&lt;i&gt;&quot;zzzqq". '
            'Try the manufacturer order number.') in body
    assert "<i>" not in body


def test_vendor_fallback_row_is_a_link_with_escaped_text():
    row = webviews.search_row("/vendor?name=A%26B", "A&B <Co>", "", "", "3 product entries", "co")
    assert row.startswith('<a class="hit hit--product" href="/vendor?name=A%26B">')
    assert "A&amp;B &lt;" in row and "<Co>" not in row and "hit__m" in row


def test_sample_chips_are_links_that_run_the_search(handler):
    _, _, body = _get(handler, "/")
    chips = re.findall(r'<a class="chip" href="(/\?q=[^"]+)">([^<]+)</a>', body)
    assert [text for _, text in chips] == ["S7-1500", "6ES7518-4AX00-1AB0", "Moxa EDS-405A"]
    assert all(urllib.parse.unquote(href[4:]) == text for href, text in chips)


def test_landing_has_counts_and_no_marketing_copy(handler, db):
    stats = index.stats(db)
    _, _, body = _get(handler, "/")
    assert f'{stats["products"]:,} product entries' in body
    assert f'{stats["vendors"]:,} vendor spellings' in body
    for gone in ("Better hardware decisions", "Evidence first", "Know what you are buying",
                 "class=\"hero\"", "From requisition to decision"):
        assert gone not in body
    assert 'id="q"' in body and "rt-input--mono" in body


# --- methodology ------------------------------------------------------------

def test_about_states_the_real_missing_pillar_rule(handler):
    _, _, body = _get(handler, "/about")
    assert "neutral 50" in body and "full weight" in body
    assert "excluded and the remaining weights are adjusted" not in body
    assert "80% secure" not in body
    assert 'id="sources"' in body
    assert body.count('id="sources"') == 1


def test_about_weights_come_from_the_scoring_module(handler):
    _, _, body = _get(handler, "/about")
    for text in ("exposure safety (60%)", "available fixes (20%)",
                 "vendor security practices (15%)", "certification evidence (5%)"):
        assert text in body


# --- supplier questions -----------------------------------------------------

def test_questions_render_numbered_with_gap_tags_and_export_link():
    items = [questions.Question(text="Confirm <fw>", why="w", evidence=["CVE-1"], gap="E"),
             questions.Question(text="Standing ask", why="w")]
    out = webviews.supplier_questions("P", items, export_href="/annex.txt?a=1&download=1",
                                      text_href="/annex.txt?a=1")
    assert out.count("<li><div") == 2 and "<ol" in out
    assert 'GAP · E' in out and out.count('class="rt-q__tag"') == 1
    assert "Confirm &lt;fw&gt;" in out
    assert 'href="/annex.txt?a=1&amp;download=1"' in out and "Export as .txt" in out
    assert "<script" not in out and "checkbox" not in out


def test_no_questions_shows_the_empty_state():
    assert "No open questions. Every material input is verified." in (
        webviews.supplier_questions("P", []))


def test_annex_page_keeps_pre_and_offers_the_download(handler):
    _, _, body = _get(handler, "/annex?vendor=Testco&product=TestPLC")
    assert "<pre" in body and "RFQ SECURITY ANNEX" in body
    assert "download=1" in body and "Export as .txt" in body


def test_annex_download_headers_and_identical_text(handler):
    status, headers, text = _get(handler, "/annex.txt?vendor=Testco&product=TestPLC")
    assert headers["Content-Type"].startswith("text/plain")
    assert "Content-Disposition" not in headers
    status, headers, download = _get(handler, "/annex.txt?vendor=Testco&product=TestPLC&download=1")
    assert status == 200 and download == text
    assert headers["Content-Type"].startswith("text/plain")
    assert re.fullmatch(r'attachment; filename="retrust-rfq-annex-[A-Za-z0-9-]+\.txt"',
                        headers["Content-Disposition"])


def test_annex_download_filename_cannot_carry_header_injection(handler):
    _, headers, _ = _get(handler, "/annex.txt?vendor=a&product=b%22%0d%0aX-Evil%3a%201&download=1")
    assert "X-Evil" not in headers and '"' not in headers["Content-Disposition"].split("=", 1)[1][1:-1]


# --- alternatives, vendor ---------------------------------------------------

def test_alternatives_use_verdict_badges_and_no_inline_colour(db, tmp_path):
    from retrust import cli
    context = cli._context(data_dir=str(tmp_path))

    def assess(vendor, product, version=None, order_number=None, **owner):
        return cli._assess(db, vendor, product, version, order_number, context=context, **owner)

    page = serve._alternatives_page(db, assess, "Testco", "TestPLC", "")
    main = page[page.index("<main"):page.index("</main>")]
    assert "rt-badge--s" in main
    assert "style=\"color" not in main and "font-weight:700" not in main


def test_vendor_screening_hits_are_restriction_alerts():
    blocked = dossier.Dossier("V <x>", "v", screening_gates=[
        {"gate": "Restriction", "detail": "Match <on> list", "source": "src"}],
        sanctions_checked=True, certificates=[])
    out = webviews.vendor_profile(blocked)
    assert 'class="rt-alert rt-alert--restriction"' in out and 'role="alert"' in out
    assert "Match &lt;on&gt; list" in out and "<on>" not in out


# --- every page -------------------------------------------------------------

@pytest.mark.parametrize("path", PAGES)
def test_page_hygiene(handler, path):
    status, _, body = _get(handler, path)
    assert status == 200
    main = body[body.index("<main"):body.index("</main>")]
    assert main.count("<h1") == 1
    assert "<script" not in without_enhancement(body)
    assert main.count("rt-btn--primary") <= 1
    ids = re.findall(r'\sid="([^"]+)"', body)
    assert len(ids) == len(set(ids)), [i for i in ids if ids.count(i) > 1]
    assert "http://" not in main and "https://" not in main.replace("https://github.com", "")
    for word in ("risk-free",):
        assert word not in main


def test_page_css_passes_the_design_lint():
    assert css_lint(webviews.CSS) == []
