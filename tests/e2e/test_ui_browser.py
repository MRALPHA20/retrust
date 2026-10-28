"""Browser checks for the web UI (Design-spec 5.4, Redesign-plan section 5 item 6).

Optional: needs Playwright, an installed browser and a built index at
data/retrust.db. Anything missing skips the module, so CI without a browser
stays green.

    python -m pip install -e '.[docs]' && python -m playwright install chromium
    python -m pytest tests/e2e -q -p no:cacheprovider
    RETRUST_E2E_BROWSERS=chromium,firefox,webkit python -m pytest tests/e2e -q

The checks that need markup owned by later work packages (export menu popover,
evidence drawer, aria-sort) look for the feature first and xfail with a reason
while it is absent; they start asserting as soon as it lands.
"""

import os
import pathlib
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

pytest.importorskip("playwright")
from playwright.sync_api import sync_playwright  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
DB = ROOT / "data" / "retrust.db"

pytestmark = pytest.mark.skipif(not DB.exists(), reason="data/retrust.db is absent")

BROWSERS = [name.strip() for name in
            os.environ.get("RETRUST_E2E_BROWSERS", "chromium").split(",") if name.strip()]
WIDTHS = [375, 640, 1024, 1100, 1440]
S7 = "/score?vendor=Siemens&product=SIMATIC+S7-1500&version=3.1.6"
PAGES = {
    "home": "/",
    "score-empty": "/score",
    "result-verify": "/score?vendor=ABB&product=AC+800M",
    "result-avoid": S7,
    "compare": "/compare?c=ABB%7CAC%20800M&c=Moxa%7CEDS-405A",
    "about": "/about",
    "annex": "/annex?vendor=Moxa&product=EDS-405A",
    "vendor": "/vendor?name=Siemens",
    "timeline": "/timeline?vendor=Siemens&product=SIMATIC+S7-1500",
    "lev": "/lev?vendor=Siemens&product=SIMATIC+S7-1500",
    "ssvc": "/ssvc?vendor=Siemens&product=SIMATIC+S7-1500&version=3.1.6",
    "alternatives": "/alternatives?vendor=Siemens&product=SIMATIC+S7-1500",
}
CSP_MARKERS = ("content security policy", "content-security-policy", "violates the following")


@pytest.fixture(scope="session")
def base_url():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    env = {k: v for k, v in os.environ.items() if k != "RETRUST_HOSTED"}
    server = subprocess.Popen([sys.executable, "-m", "retrust.cli", "serve", "--port", str(port)],
                              cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 90
        while True:
            if server.poll() is not None:
                pytest.skip(f"retrust serve exited with status {server.returncode}")
            try:
                with urllib.request.urlopen(base + "/healthz", timeout=2):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    pytest.skip("retrust serve did not become healthy")
                time.sleep(.5)
        yield base
    finally:
        server.terminate()
        server.wait(timeout=10)


@pytest.fixture(scope="session", params=BROWSERS)
def browser(request):
    with sync_playwright() as playwright:
        try:
            launched = getattr(playwright, request.param).launch()
        except Exception as error:  # browser binaries not installed
            pytest.skip(f"{request.param} is not installed: {str(error).splitlines()[0]}")
        yield launched
        launched.close()


def _open(browser, base, path, width=1280, height=900, **options):
    # bypass_csp only affects what we evaluate; the CSP test uses its own context.
    options.setdefault("bypass_csp", True)
    context = browser.new_context(viewport={"width": width, "height": height}, **options)
    page = context.new_page()
    page.goto(base + path, wait_until="networkidle")
    return context, page


@pytest.mark.parametrize("width", WIDTHS)
@pytest.mark.parametrize("name", PAGES)
def test_no_page_level_horizontal_scroll(browser, base_url, name, width):
    # Wide tables must scroll inside .tw, never the page.
    context, page = _open(browser, base_url, PAGES[name], width=width)
    try:
        sizes = page.evaluate("({s: document.documentElement.scrollWidth,"
                              " c: document.documentElement.clientWidth})")
        assert sizes["s"] <= sizes["c"], f"{name} at {width}px scrolls the page: {sizes}"
    finally:
        context.close()


@pytest.mark.parametrize("name", PAGES)
def test_no_csp_violations_in_console(browser, base_url, name):
    context = browser.new_context(viewport={"width": 1280, "height": 900})  # CSP enforced
    page = context.new_page()
    messages = []
    page.on("console", lambda m: messages.append(m.text))
    page.on("pageerror", lambda e: messages.append(str(e)))
    try:
        page.goto(base_url + PAGES[name], wait_until="networkidle")
        bad = [m for m in messages if any(k in m.lower() for k in CSP_MARKERS)]
        assert not bad, bad
    finally:
        context.close()


@pytest.mark.parametrize("name", PAGES)
def test_single_h1(browser, base_url, name):
    context, page = _open(browser, base_url, PAGES[name])
    try:
        assert page.locator("h1").count() == 1
    finally:
        context.close()


@pytest.mark.parametrize("name", ["home", "result-avoid", "compare"])
def test_skip_link_is_first_focusable(browser, base_url, name):
    context, page = _open(browser, base_url, PAGES[name])
    try:
        page.keyboard.press("Tab")
        first = page.evaluate("""() => { const e = document.activeElement;
            return {tag: e.tagName, href: e.getAttribute('href') || '', text: e.textContent.trim().toLowerCase()}; }""")
        assert first["tag"] == "A" and first["href"].startswith("#") and "skip" in first["text"], first
        page.keyboard.press("Enter")
        target = page.evaluate("location.hash")
        assert target and page.locator(target).count() == 1, "skip link target must exist"
    finally:
        context.close()


@pytest.mark.parametrize("name", ["home", "result-avoid"])
def test_focus_ring_visible_while_tabbing(browser, base_url, name):
    context, page = _open(browser, base_url, PAGES[name])
    try:
        seen = []
        for _ in range(8):
            page.keyboard.press("Tab")
            seen.append(page.evaluate("""() => { const e = document.activeElement;
                const s = getComputedStyle(e);
                return {el: e.tagName + ' ' + (e.textContent || '').trim().slice(0, 30),
                        style: s.outlineStyle, width: parseFloat(s.outlineWidth),
                        shadow: s.boxShadow}; }"""))
        flat = [f for f in seen if not (f["style"] not in ("none", "hidden") and f["width"] >= 2)
                and f["shadow"] in ("none", "")]
        assert not flat, f"focused elements without a visible ring: {flat}"
    finally:
        context.close()


@pytest.mark.parametrize("name", ["home", "result-avoid", "compare"])
def test_reduced_motion_zeroes_transitions(browser, base_url, name):
    context, page = _open(browser, base_url, PAGES[name], reduced_motion="reduce")
    try:
        offenders = page.evaluate("""() => {
            const bad = [];
            for (const e of document.querySelectorAll('body, body *')) {
              const s = getComputedStyle(e);
              const parts = s.transitionDuration.split(',').concat(s.animationDuration.split(','));
              if (parts.some(p => parseFloat(p) > 0)) bad.push(e.tagName + '.' + e.className + ' ' + s.transitionDuration);
            }
            return bad.slice(0, 10); }""")
        assert not offenders, offenders
    finally:
        context.close()


@pytest.mark.parametrize("name", ["home", "score-empty", "result-avoid", "compare"])
def test_primary_controls_are_44px_under_coarse_pointer(browser, base_url, name):
    context, page = _open(browser, base_url, PAGES[name], width=390, has_touch=True, is_mobile=True)
    try:
        small = page.evaluate("""() => {
            const out = [];
            const sel = 'button, a.button, input[type=submit], input[type=text], input[type=search], select';
            for (const e of document.querySelectorAll(sel)) {
              const r = e.getBoundingClientRect();
              if (r.width === 0 || r.height === 0) continue;   // not rendered
              if (r.height < 44) out.push(e.tagName + ' ' + (e.textContent || e.name || '').trim().slice(0, 30)
                                          + ' ' + Math.round(r.height) + 'px');
            }
            return out; }""")
        assert not small, small
    finally:
        context.close()


@pytest.mark.parametrize("name", ["home", "result-avoid", "compare", "about"])
def test_640px_viewport_loses_no_content(browser, base_url, name):
    # 640px is 200% zoom of 1280: every heading and column header present and
    # rendered at 1280 must still be rendered at 640.
    probe = """() => {
        const out = [];
        for (const e of document.querySelectorAll('main h1, main h2, main h3, main th')) {
          const s = getComputedStyle(e);
          if (e.getClientRects().length && s.visibility !== 'hidden') out.push(e.textContent.trim());
        }
        return out; }"""
    wide_context, wide = _open(browser, base_url, PAGES[name], width=1280)
    narrow_context, narrow = _open(browser, base_url, PAGES[name], width=640)
    try:
        wide_seen, narrow_seen = wide.evaluate(probe), narrow.evaluate(probe)
        missing = [t for t in wide_seen if t not in narrow_seen]
        assert wide_seen and not missing, missing
    finally:
        wide_context.close()
        narrow_context.close()


# ---- features owned by later work packages: xfail until present ----------

def test_export_menu_closes_on_escape_and_returns_focus(browser, base_url):
    context, page = _open(browser, base_url, S7)
    try:
        invoker = page.locator("[popovertarget]").first
        if not page.locator("[popovertarget]").count():
            pytest.xfail("export menu popover lands in WP5b/WP6")
        invoker.focus()
        page.keyboard.press("Enter")
        target = invoker.get_attribute("popovertarget")
        assert page.locator(f"#{target}:popover-open").count() == 1
        page.keyboard.press("Escape")
        assert page.locator(f"#{target}:popover-open").count() == 0
        assert page.evaluate("document.activeElement.getAttribute('popovertarget')") == target
    finally:
        context.close()


def test_evidence_drawer_closes_on_escape_and_returns_focus(browser, base_url):
    context, page = _open(browser, base_url, S7)
    try:
        invoker = page.locator("[data-drawer], summary.drawer, a[href^='#drawer-']").first
        if not page.locator("[data-drawer], summary.drawer, a[href^='#drawer-']").count():
            pytest.xfail("evidence drawer lands in WP5b/WP6")
        invoker.focus()
        page.keyboard.press("Enter")
        page.keyboard.press("Escape")
        assert page.evaluate("document.activeElement === arguments[0]", invoker.element_handle())
    finally:
        context.close()


def test_aria_sort_follows_sort_navigation(browser, base_url):
    context, page = _open(browser, base_url, S7)
    try:
        sortable = page.locator("th a[href*='sort=']")
        if not page.locator("th[aria-sort]").count() or not sortable.count():
            pytest.xfail("sortable headers with aria-sort land in WP6")
        before = page.locator("th[aria-sort]:not([aria-sort=none])").count()
        assert before == 1, "exactly one column carries the active sort"
        sortable.last.click()
        page.wait_for_load_state("networkidle")
        assert page.locator("th[aria-sort]:not([aria-sort=none])").count() == 1
    finally:
        context.close()


# Gate R3: a legacy `main button:not(.rt-btn)` rule once out-specified .ev-open
# and .ev-close, so every CVE-ID opener rendered as a primary button.
_PRIMARY_PROBE = """() => {
    const probe = document.createElement('i');
    probe.style.background = 'var(--action)';
    document.body.appendChild(probe);
    const action = getComputedStyle(probe).backgroundColor;
    probe.remove();
    const out = [];
    for (const e of document.querySelectorAll('button, a, input[type=submit]')) {
      const r = e.getBoundingClientRect();
      if (r.width === 0 || r.height === 0) continue;
      if (e.classList.contains('skip-link')) continue;   // primary by design, off-screen until focused
      if (getComputedStyle(e).backgroundColor === action
          && !e.classList.contains('rt-btn--primary'))
        out.push(e.tagName + '.' + e.className + ' ' + (e.textContent || '').trim().slice(0, 24));
    }
    return {primary: document.querySelectorAll('.rt-btn--primary').length, offenders: out}; }"""


@pytest.mark.parametrize("name", ["result-avoid", "result-verify", "compare", "score-empty", "home"])
def test_nothing_is_visibly_primary_unless_it_is_the_primary_button(browser, base_url, name):
    context, page = _open(browser, base_url, PAGES[name])
    try:
        found = page.evaluate(_PRIMARY_PROBE)
        assert not found["offenders"], found["offenders"]
        assert found["primary"] <= 1
    finally:
        context.close()


def test_cve_openers_are_links_and_drawer_close_is_not_primary(browser, base_url):
    context, page = _open(browser, base_url, S7)
    try:
        openers = page.evaluate("""() => [...document.querySelectorAll('.ev-open')].map(e => {
            const s = getComputedStyle(e);
            return [s.backgroundColor, s.marginTop, s.minHeight, s.paddingLeft, s.textDecorationLine]; })""")
        assert openers, "the evidence table has CVE openers"
        for background, margin, min_height, padding, decoration in openers:
            assert background == "rgba(0, 0, 0, 0)"
            assert margin == "0px" and padding == "0px" and decoration == "underline"
        closers = page.evaluate("""() => [...document.querySelectorAll('.ev-close')].map(
            e => getComputedStyle(e).backgroundColor)""")
        assert closers and all(c == "rgba(0, 0, 0, 0)" for c in closers)
    finally:
        context.close()
