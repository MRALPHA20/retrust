"""Print media shows the content of every closed <details> (Chromium).

A closed <details> does not render its content, in print as on screen, so an
exported or printed report silently dropped the "evidence" and "why" text
inside nested disclosures. The fix is CSS only (`details::details-content`
made visible under @media print); this proves it in a real browser, not by
matching the rule text.
"""
import pathlib
import urllib.request

import pytest

pytest.importorskip("playwright")

ROOT = pathlib.Path(__file__).resolve().parents[2]
DB = ROOT / "data" / "retrust.db"

pytestmark = pytest.mark.skipif(not DB.exists(), reason="data/retrust.db is absent")

S7 = "vendor=Siemens&product=SIMATIC+S7-1500&version=3.1.6"

# Per closed <details>: how many of its non-summary children are rendered.
# Forms, popovers and dialogs are chrome that print hides on purpose, so a
# disclosure that only wraps one (the compare page's edit form) is not counted.
PROBE = """() => [...document.querySelectorAll('details:not([open])')]
  .filter(d => !d.closest('form, [popover], dialog'))
  .map(d => {
    const kids = [...d.children].filter(c => c.tagName !== 'SUMMARY'
                                           && !c.matches('form, [popover], dialog'));
    return {name: (d.className || d.querySelector('summary')?.textContent || '').trim().slice(0, 40),
            kids: kids.length,
            shown: kids.filter(k => k.checkVisibility() && k.getBoundingClientRect().height > 0).length};
  }).filter(d => d.kids > 0)"""


@pytest.fixture(scope="module")
def chromium(browser):
    if browser.browser_type.name != "chromium":
        pytest.skip("::details-content printing is asserted on Chromium")
    return browser


def _closed_details(page, media):
    page.emulate_media(media=media)
    return page.evaluate(PROBE)


def _assert_print_shows_everything(page):
    on_screen = _closed_details(page, "screen")
    assert len(on_screen) >= 4, "the page lost its disclosures; the probe proves nothing"
    # Control: on screen the closed content really is hidden, so print is what changed.
    assert any(d["shown"] < d["kids"] for d in on_screen)
    printed = _closed_details(page, "print")
    assert [d for d in printed if d["shown"] < d["kids"]] == []


def test_web_result_prints_the_content_of_closed_details(chromium, base_url):
    page = chromium.new_page()
    try:
        page.goto(base_url + "/score?" + S7, wait_until="load")
        _assert_print_shows_everything(page)
    finally:
        page.close()


def test_html_export_prints_the_content_of_closed_details(chromium, base_url, tmp_path):
    with urllib.request.urlopen(base_url + "/export.html?" + S7, timeout=60) as response:
        exported = tmp_path / "s7.html"
        exported.write_bytes(response.read())
    page = chromium.new_page()
    try:
        page.goto(exported.as_uri(), wait_until="load")
        _assert_print_shows_everything(page)
    finally:
        page.close()


def test_comparison_page_prints_the_content_of_closed_details(chromium, base_url):
    page = chromium.new_page()
    try:
        page.goto(base_url + "/compare?c=ABB%7CAC%20800M&c=Moxa%7CEDS-405A", wait_until="load")
        _assert_print_shows_everything(page)
    finally:
        page.close()


def test_print_media_rule_is_shipped_in_both_stylesheets():
    from retrust import report, webui
    rule = "details::details-content{content-visibility:visible!important"
    assert rule in webui.STYLESHEET and rule in report.export_css()
