"""Regression tests for the findings of the third UI review round.

The numbers in the test names match the review.
"""

import collections
import os
import pathlib
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import date
from html.parser import HTMLParser

import pytest

from retrust import components, report, score, serve, supplychain, webui
from test_result_view import block, clean, resolved

ROOT = pathlib.Path(__file__).resolve().parents[1]
DB = ROOT / "data" / "retrust.db"
needs_data = pytest.mark.skipif(not DB.exists(), reason="data/retrust.db is absent")

S7 = "/score?order_number=6ES7518-4AX00-1AB0"
COMPARE = "?c=ABB%7CAC%20800M&c=Moxa%7CEDS-405A"


@pytest.fixture(scope="module")
def site():
    """`retrust serve` over the real index, fetched with a tolerant client."""
    if not DB.exists():
        pytest.skip("data/retrust.db is absent")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    env = {k: v for k, v in os.environ.items() if k != "RETRUST_HOSTED"}
    server = subprocess.Popen([sys.executable, "-m", "retrust.cli", "serve", "--port", str(port)],
                              cwd=ROOT, env=env, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 90
        while True:
            if server.poll() is not None:
                pytest.skip("retrust serve exited")
            try:
                with urllib.request.urlopen(base + "/healthz", timeout=2):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    pytest.skip("retrust serve did not become healthy")
                time.sleep(.5)

        def fetch(path):
            try:
                with urllib.request.urlopen(base + path, timeout=60) as response:
                    return response.status, response.read().decode("utf-8")
            except urllib.error.HTTPError as error:
                return error.code, error.read().decode("utf-8")
        yield fetch
    finally:
        server.terminate()
        server.wait(timeout=10)


class _Ids(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = collections.Counter()
        self.bare_th = 0

    def handle_starttag(self, tag, attrs):
        names = dict(attrs)
        if "id" in names:
            self.ids[names["id"]] += 1
        if tag == "th" and "scope" not in names:
            self.bare_th += 1


def _scan(markup):
    parser = _Ids()
    parser.feed(markup)
    return parser


# 1 ---------------------------------------------------------------------------

def test_covered_list_alone_is_not_a_loaded_screening_list(tmp_path):
    index = supplychain.load(str(tmp_path), read_only=True)
    assert len(index) > 0 and bool(index)            # the trap in the review
    assert serve._screening_loaded({"screening": index}) is False
    assert serve._screening_loaded({}) is False


def test_covered_list_only_says_so_and_claims_no_supplier_result():
    markup = block(clean(), web=report.WebView(
        checks={"kev_loaded": True, "screening_loaded": False}))
    assert "Covered list only; sanctions list not loaded" in markup
    assert "No supplier restriction configured" not in markup
    assert "No supplier screening match" not in markup


# 2 ---------------------------------------------------------------------------

def _chip_before(page, text):
    return page.split(text)[0][-200:]


@needs_data
@pytest.mark.parametrize("path, chip", [
    ("/score?vendor=Nope&product=Nothing&version=1.0", "FW 1.0"),
    ("/score?order_number=XYZ-NOT-REAL&version=2.0", "FW 2.0")])
def test_firmware_of_an_unidentified_product_is_not_verified(site, path, chip):
    _, page = site(path)
    assert "Checked against the published affected ranges" not in page
    assert "· not verified" in page
    assert "rt-meta--unverified" in _chip_before(page, chip)


@needs_data
def test_firmware_checked_against_ranges_is_verified(site):
    _, page = site("/score?order_number=6ES7518-4AX00-1AB0&version=2.9.2")
    assert "Checked against the published affected ranges" in page
    assert "rt-meta--unverified" not in _chip_before(page, "FW 2.9.2")


def test_firmware_verified_needs_something_to_have_been_checked():
    assessment = score.not_assessed("P", "stub")
    assert report.firmware_verified(assessment, resolved(), [], "1.0") is False
    assessment.cleared_count = 2
    assert report.firmware_verified(assessment, resolved(), [], "1.0") is True
    assert report.firmware_verified(assessment, resolved(), [], "") is False


# 3 ---------------------------------------------------------------------------

def test_legacy_button_rule_cannot_restyle_cve_openers_or_close_buttons():
    selectors = re.findall(r"main button:not\(\.rt-btn\)[^{,]*", webui.STYLESHEET)
    assert selectors
    for selector in selectors:
        assert ":not(.ev-open):not(.ev-close)" in selector, selector


# 4 + 6 -----------------------------------------------------------------------

@needs_data
def test_strip_does_not_say_no_kev_beside_kev_evidence(site):
    _, page = site(S7)
    assert "No applicable KEV" not in page
    _, export = site("/export.html?order_number=6ES7518-4AX00-1AB0")
    assert "No applicable KEV" not in export


def test_export_lead_is_qualified_when_a_check_state_is_unknown():
    blocks = [(clean(), resolved(), [])]
    html = report.render(blocks, provenance=[
        {"source": "CISA KEV", "detail": "d", "captured": "2026-10-01"}])
    assert "No mandatory blockers in the checks that ran." in html
    assert "No mandatory blockers. " not in html


# 5 + 12 ----------------------------------------------------------------------

@needs_data
@pytest.mark.parametrize("path", ["/compare" + COMPARE, "/compare.html" + COMPARE])
def test_comparison_pages_have_no_duplicate_ids(site, path):
    status, page = site(path)
    assert status == 200
    duplicates = {k: v for k, v in _scan(page).ids.items() if v > 1}
    assert not duplicates, duplicates


@needs_data
def test_single_product_page_keeps_its_plain_ids(site):
    _, page = site(S7)
    ids = _scan(page).ids
    assert ids["evidence-table"] == 1 and ids["exposure"] == 1 and ids["evidence"] == 1
    assert not {k: v for k, v in ids.items() if v > 1}


@needs_data
@pytest.mark.parametrize("path", [
    "/", "/score", S7, "/score?vendor=ABB&product=AC+800M",
    "/compare" + COMPARE, "/compare.html" + COMPARE, "/about",
    "/annex?vendor=Moxa&product=EDS-405A",
    "/vendor?name=Siemens", "/timeline?vendor=Siemens&product=SIMATIC+S7-1500",
    "/lev?vendor=Siemens&product=SIMATIC+S7-1500",
    "/ssvc?vendor=Siemens&product=SIMATIC+S7-1500&version=3.1.6",
    "/alternatives?vendor=Siemens&product=SIMATIC+S7-1500",
    "/?q=siemens", "/demo", "/ssvc", "/lev", "/vendor", "/export.html?vendor=ABB&product=AC+800M"])
def test_every_table_header_has_a_scope(site, path):
    status, page = site(path)
    if status == 404:
        pytest.skip("no such route")
    assert _scan(page).bare_th == 0


# 7 ---------------------------------------------------------------------------

def _prov(kev, epss):
    return [{"source": "CISA KEV", "detail": "d", "captured": kev},
            {"source": "FIRST EPSS", "detail": "d", "captured": epss}]


TODAY = date(2026, 10, 28)


def test_snapshot_with_a_future_capture_date_is_not_current():
    html = webui.snapshot_status(_prov("2026-11-30", "2026-10-28"), TODAY, False)
    assert "rt-snap--current" not in html and "(current)" not in html
    assert "in the future" in html and "◆" in html


def test_snapshot_with_an_unreadable_kev_date_is_amber_not_missing():
    html = webui.snapshot_status(_prov("not-a-date", "2026-10-28"), TODAY, False)
    assert "KEV date unreadable" in html and "KEV missing" not in html
    assert "rt-snap--stale" in html and "◆" in html


def test_snapshot_glyphs_follow_the_state():
    assert "●" in webui.snapshot_status(_prov("2026-10-28", "2026-10-28"), TODAY, False)
    assert "■" in webui.snapshot_status([], TODAY, False)


# 8 ---------------------------------------------------------------------------

@needs_data
def test_about_page_describes_epss_the_way_the_tables_show_it(site):
    _, page = site("/about")
    assert "shown as a percentage" not in page
    assert "two decimals" in page


# 9 ---------------------------------------------------------------------------

def test_default_evidence_order_is_announced_on_the_signals_header():
    from test_evidence_view import many, assessed, view
    from retrust import evidenceview as ev
    fs = many(4)
    card = ev.evidence_card(fs, assessed(fs), view())
    assert card.count("aria-sort=") == 1 and 'aria-sort="descending"><a' in card
    other = ev.evidence_card(fs, assessed(fs), view(sort="cvss", dir="asc"))
    assert other.count("aria-sort=") == 1 and 'aria-sort="descending"' not in other


# 10 --------------------------------------------------------------------------

@needs_data
def test_export_unavailable_page_keeps_the_assessment_inputs(site):
    status, page = site("/export.vex.json?vendor=Nope&product=Nothing&version=1.0&x=%22%3E%3Cb%3E")
    assert status in (400, 404)
    assert 'href="/score?vendor=Nope&amp;product=Nothing&amp;version=1.0"' in page
    assert "<b>" not in page


def test_back_link_whitelists_and_escapes():
    link = serve._back_to_assessment({"vendor": ['A"B'], "evil": ["1"], "version": [""]})
    assert link == "/score?vendor=A%22B"
    assert serve._back_to_assessment({}) == "/score"


def test_vex_row_is_disabled_when_there_would_be_no_statements():
    off = serve._export_menu("vendor=A", True, False)
    assert "No CVE statements for this product." in off
    on = serve._export_menu("vendor=A", True, True)
    assert "No CVE statements" not in on and "/export.vex.json?vendor=A" in on
    assert "Needs an identified product." in serve._export_menu("vendor=A", False, False)


def test_disabled_menu_row_is_keyboard_reachable_but_not_a_link():
    markup = components.menu("Export", (("VEX", "/x", "tag", "Because."),), "m")
    row = markup[markup.index('<a class="rt-menu__row rt-menu__row--disabled"'):]
    row = row[:row.index(">")]
    assert 'tabindex="0"' in row and 'aria-disabled="true"' in row
    assert "aria-describedby=" in row and "href" not in row


# 11 --------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["href", "action", "formaction", "src", "poster", "xlink:href"])
def test_url_attributes_go_through_the_scheme_check(name):
    assert components._attrs([], {name: "javascript:alert(1)"}) == f' {name}="#"'
    assert components._attrs([], {name: " JaVa\tScript:x"}) == f' {name}="#"'
    assert components._attrs([], {name: "data:text/html,x"}) == f' {name}="#"'
    assert components._attrs([], {name: "/ok?a=1"}) == f' {name}="/ok?a=1"'


def test_non_url_attributes_are_left_alone():
    assert components._attrs([], {"title": "javascript:x"}) == ' title="javascript:x"'
