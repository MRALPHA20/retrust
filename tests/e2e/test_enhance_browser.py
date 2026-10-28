"""Browser checks for the enhancement script and for its absence.

Every behaviour here runs with the real Content-Security-Policy enforced (no
bypass), and a violation or page error in the console fails the test. The last
group runs every page of the matrix with JavaScript disabled: that is the
contract, the script only adds to it.

    python -m pytest tests/e2e/test_enhance_browser.py -q -p no:cacheprovider
"""

import contextlib

import pytest

pytest.importorskip("playwright")

from test_ui_browser import DB, PAGES, S7, csp_problems  # noqa: E402

pytestmark = pytest.mark.skipif(not DB.exists(), reason="data/retrust.db is absent")

OPTIONS = dict(viewport={"width": 1280, "height": 900})
ORDER = "6ES7518-4AX00-1AB0"
ANNEX = "/annex?vendor=Moxa&product=EDS-405A"
HIDDEN = "[role=listbox]"


@contextlib.contextmanager
def session(browser, base, path, **options):
    """A page with CSP enforced; console CSP messages and page errors fail the test."""
    context = browser.new_context(**{**OPTIONS, **options})
    page = context.new_page()
    problems = []
    page.on("console", lambda m: problems.extend(csp_problems([m.text])))
    page.on("pageerror", lambda e: problems.append("pageerror: %s" % e))
    try:
        page.goto(base + path, wait_until="networkidle")
        yield page
        assert not problems, problems
    finally:
        context.close()


def _type(page, text, selector="#rt-global-q"):
    page.locator(selector).click()
    page.locator(selector).press_sequentially(text, delay=15)


def _popover_open(page, ident):
    return page.locator("#%s:popover-open" % ident).count() == 1


# ---- global search ------------------------------------------------------------

def test_search_popover_keyboard_flow(browser, base_url):
    with session(browser, base_url, "/about") as page:
        _type(page, ORDER)
        options = page.locator("[role=option]")
        options.first.wait_for()
        search = page.locator("#rt-global-q")
        assert search.get_attribute("role") == "combobox"
        assert search.get_attribute("aria-expanded") == "true"
        assert search.get_attribute("aria-controls") == page.locator(HIDDEN).get_attribute("id")
        assert page.locator(".rt-suggest__no").first.text_content().strip() == ORDER
        page.keyboard.press("ArrowDown")
        first = options.first
        assert first.get_attribute("aria-selected") == "true"
        assert search.get_attribute("aria-activedescendant") == first.get_attribute("id")
        page.keyboard.press("ArrowUp")                       # wraps to the last row
        last = options.last
        assert last.get_attribute("aria-selected") == "true"
        page.keyboard.press("ArrowDown")                     # and back to the first
        assert first.get_attribute("aria-selected") == "true"
        page.keyboard.press("Enter")
        page.wait_for_url("**/score?*")
        assert "order_number=" in page.url or "product=" in page.url


def test_at_most_eight_rows_with_the_anatomy_of_spec_4_3(browser, base_url):
    with session(browser, base_url, "/about") as page:
        _type(page, "SIMATIC")
        page.locator("[role=option]").first.wait_for()
        assert 1 <= page.locator("[role=option]").count() <= 8
        row = page.locator(".rt-suggest__row").first
        families = row.evaluate("""r => [...r.children].map(c => getComputedStyle(c).fontFamily)""")
        assert "Plex Mono" in families[0] or "mono" in families[0].lower()
        assert row.locator(".rt-suggest__vendor").count() == 1


def test_escape_closes_the_popover_and_keeps_the_text(browser, base_url):
    with session(browser, base_url, "/about") as page:
        _type(page, ORDER)
        page.locator("[role=option]").first.wait_for()
        page.keyboard.press("Escape")
        assert page.locator(".rt-suggest").is_hidden()
        assert page.locator("#rt-global-q").get_attribute("aria-expanded") == "false"
        assert page.locator("#rt-global-q").input_value() == ORDER


def test_no_results_line_is_the_spec_copy(browser, base_url):
    with session(browser, base_url, "/about") as page:
        _type(page, "zzqqxxnomatch")
        page.locator(".rt-suggest__empty").wait_for(state="visible")
        assert page.locator(".rt-suggest__empty").text_content() == \
            'No product matches "zzqqxxnomatch". Try the manufacturer order number.'
        assert page.locator("[role=option]").count() == 0


def test_enter_without_a_highlighted_row_submits_the_form_normally(browser, base_url):
    with session(browser, base_url, "/about") as page:
        _type(page, ORDER)
        page.locator("[role=option]").first.wait_for()
        page.keyboard.press("Enter")
        page.wait_for_url("**/?q=*")
        assert page.locator("h1").inner_text().startswith("Search")


def _hint(browser, base_url, platform):
    """The placeholder the script writes when the browser reports `platform`."""
    init = ("Object.defineProperty(navigator, 'platform', {get: () => %r});"
            "Object.defineProperty(navigator, 'userAgentData', {get: () => undefined});"
            % platform)
    context = browser.new_context(**OPTIONS)
    context.add_init_script(init)
    page = context.new_page()
    try:
        page.goto(base_url + "/about", wait_until="networkidle")
        return page.locator("#rt-global-q").get_attribute("placeholder")
    finally:
        context.close()


@pytest.mark.parametrize("platform, hint", [
    ("MacIntel", "⌘K"), ("iPad", "⌘K"), ("Win32", "Ctrl K"), ("Linux x86_64", "Ctrl K")])
def test_the_shortcut_hint_names_the_platform_modifier(browser, base_url, platform, hint):
    placeholder = _hint(browser, base_url, platform)
    assert placeholder.endswith(" " + hint)
    assert ("⌘" in placeholder) == (hint == "⌘K")


def test_ctrl_k_and_cmd_k_both_focus_the_field_and_the_hint_is_script_only(browser, base_url):
    with session(browser, base_url, "/about") as page:
        assert page.locator("#rt-global-q").get_attribute("placeholder").endswith(("⌘K", "Ctrl K"))
        for chord in ("Control+k", "Meta+k"):
            page.locator("h1").click()
            page.keyboard.press(chord)
            assert page.evaluate("document.activeElement.id") == "rt-global-q"


def test_a_slow_stale_answer_never_replaces_a_newer_one(browser, base_url):
    with session(browser, base_url, "/about") as page:
        held = []

        def slow_first(route):
            if "q=SIMATIC" in route.request.url and not held:
                held.append(route)                       # held until the second query is shown
            else:
                route.continue_()
        page.route("**/search.json*", slow_first)
        _type(page, "SIMATIC")
        page.wait_for_timeout(400)
        page.locator("#rt-global-q").fill("")
        _type(page, "zzqqxxnomatch")
        page.locator(".rt-suggest__empty").wait_for(state="visible")
        if held:
            held[0].continue_()
        page.wait_for_timeout(300)
        assert page.locator(".rt-suggest__empty").is_visible()
        assert page.locator("[role=option]").count() == 0


# ---- drawers ------------------------------------------------------------------

def test_drawer_traps_focus_and_returns_it_to_the_opener(browser, base_url):
    with session(browser, base_url, S7) as page:
        opener = page.locator(".ev-open").first
        target = opener.get_attribute("popovertarget")
        # Safari does not focus a button on click, so the popover has no
        # previously focused element to return to. A keyboard user focuses the
        # opener first, which is the case this test is about.
        opener.focus()
        opener.click()
        assert _popover_open(page, target)
        drawer = "#%s" % target
        inside = "(d => d.contains(document.activeElement))(document.querySelector('%s'))" % drawer
        page.wait_for_function("document.activeElement.classList.contains('ev-close')")
        for _ in range(12):
            page.keyboard.press("Tab")
            assert page.evaluate(inside), "Tab left the drawer"
        for _ in range(12):
            page.keyboard.press("Shift+Tab")
            assert page.evaluate(inside), "Shift+Tab left the drawer"
        page.keyboard.press("Escape")
        assert not _popover_open(page, target)
        assert page.evaluate("el => document.activeElement === el", opener.element_handle())


# ---- export menu and toasts ---------------------------------------------------

def test_export_choice_shows_a_toast_closes_the_menu_and_downloads(browser, base_url):
    with session(browser, base_url, S7, accept_downloads=True) as page:
        button = page.locator(".rt-menu > [popovertarget]").first
        menu = button.get_attribute("popovertarget")
        button.click()
        assert _popover_open(page, menu)
        with page.expect_download() as download:
            page.locator("#%s a[href^='/export.json']" % menu).click()
        assert download.value.suggested_filename == "retrust-assessment.json"
        toast = page.locator(".rt-toasts[role=status] .rt-toast")
        toast.wait_for()
        assert toast.text_content().strip().endswith("Exported retrust-assessment.json")
        assert not _popover_open(page, menu)
        assert page.url.endswith(S7.split("?", 1)[1]) or "/score" in page.url   # stayed on the page
        # Success toasts go away by themselves after about five seconds.
        toast.wait_for(state="detached", timeout=8000)


_ADD_LINK = """([menu, href, label]) => { const a = document.createElement('a');
    a.className = 'rt-menu__row'; a.href = href; a.textContent = label;
    document.getElementById(menu).appendChild(a); }"""


def test_unavailable_export_shows_an_error_toast_and_never_claims_success(browser, base_url):
    """/export.vex.json answers 404 for a product it cannot make a claim about;
    the menu link is real, so the script must look before it announces."""
    with session(browser, base_url, S7, accept_downloads=True) as page:
        button = page.locator(".rt-menu > [popovertarget]").first
        menu = button.get_attribute("popovertarget")
        page.evaluate(_ADD_LINK, [menu, "/export.vex.json?vendor=Nobody&product=Nothing", "VEX (test)"])
        start = page.url
        downloads = []
        page.on("download", lambda download: downloads.append(download))
        button.click()
        page.get_by_role("link", name="VEX (test)").click()
        toast = page.locator(".rt-toast[role=alert]")
        toast.wait_for()
        assert "Export unavailable" in toast.text_content()
        assert "nothing to export" in toast.text_content()
        page.wait_for_timeout(5600)
        assert toast.is_visible(), "an error toast persists"
        assert page.locator(".rt-toast--prefer").count() == 0, "no success toast"
        assert page.url == start and not downloads
        assert not _popover_open(page, menu)


def test_export_check_that_cannot_run_falls_back_to_the_plain_link(browser, base_url):
    with session(browser, base_url, S7, accept_downloads=True) as page:
        page.route("**/export.csv*", lambda route: route.abort() if route.request.method == "HEAD"
                   else route.continue_())
        button = page.locator(".rt-menu > [popovertarget]").first
        menu = button.get_attribute("popovertarget")
        button.click()
        with page.expect_download() as download:
            page.locator("#%s a[href^='/export.csv']" % menu).click()
        assert download.value.suggested_filename == "retrust-assessment.csv"
        page.wait_for_timeout(300)
        assert page.locator(".rt-toast").count() == 0, "no success claimed without an answer"


# ---- loading state ------------------------------------------------------------

# The page's own listener is added after the script's, so the script sees every
# submit first; this one then cancels the navigation, which leaves the loading
# state on screen to be inspected (a held network request would crash the page).
_HOLD = """() => { window.__submits = [];
    document.addEventListener('submit', e => { window.__submits.push(e.defaultPrevented); e.preventDefault(); }); }"""
_BUTTON = "document.querySelector('form button[type=submit]')"


def _submit_and_hold(page):
    page.locator("#field-order-number").fill(ORDER)
    page.evaluate(_HOLD)
    page.locator("form button[type=submit]").first.click()


def test_submit_switches_to_the_loading_look_and_lets_a_second_submit_through(browser, base_url):
    with session(browser, base_url, "/score") as page:
        width = page.evaluate("%s.getBoundingClientRect().width" % _BUTTON)
        _submit_and_hold(page)
        page.wait_for_function("() => document.querySelector('.rt-loadnote').textContent.includes('Scoring')")
        state = page.evaluate("""() => { const b = %s;
            return {busy: b.getAttribute('aria-busy'), cls: b.className, text: b.textContent,
                    width: b.getBoundingClientRect().width,
                    note: document.querySelector('.rt-loadnote').textContent,
                    role: document.querySelector('.rt-loadnote').getAttribute('role')}; }""" % _BUTTON)
        assert state["busy"] == "true" and "rt-btn--loading" in state["cls"]
        assert abs(state["width"] - width) < 1.5, "the button changed width"
        assert "Assessing…" in state["text"]
        assert state["role"] == "status"
        assert state["note"] == "Resolving product… · Matching firmware… · Scoring…"
        assert "waking up" not in state["note"]                 # not hosted
        page.locator("form button[type=submit]").first.click(force=True)  # a second attempt
        # a GET re-submit is idempotent: neither was stopped by the script
        assert page.evaluate("window.__submits") == [False, False]
        assert page.locator(".rt-btn--loading").count() == 1      # still one spinner, not two


def test_hosted_demo_adds_the_waking_up_sentence_after_four_seconds(browser, base_url):
    with session(browser, base_url, "/score") as page:
        page.evaluate("document.documentElement.setAttribute('data-hosted', '1')")
        _submit_and_hold(page)
        page.wait_for_function("() => document.querySelector('.rt-loadnote').textContent.includes('Scoring')")
        assert "waking up" not in page.evaluate("document.querySelector('.rt-loadnote').textContent")
        page.wait_for_function(
            "() => document.querySelector('.rt-loadnote').textContent.includes('waking up')",
            timeout=6000)
        assert page.evaluate("document.querySelector('.rt-loadnote').textContent").endswith(
            "The hosted demo is waking up on the free plan; this can take a minute.")


def test_pageshow_restores_the_form_from_the_back_forward_cache(browser, base_url):
    with session(browser, base_url, "/score") as page:
        before = page.evaluate("%s.outerHTML" % _BUTTON)
        _submit_and_hold(page)
        page.wait_for_function("() => document.querySelector('.rt-btn--loading')")
        page.evaluate("window.dispatchEvent(new PageTransitionEvent('pageshow', {persisted: true}))")
        assert page.locator(".rt-btn--loading").count() == 0
        assert page.locator(".rt-loadnote").count() == 0
        assert page.evaluate("%s.outerHTML" % _BUTTON) == before
        page.locator("form button[type=submit]").first.click()   # usable again
        assert page.evaluate("window.__submits")[-1] is False


def test_a_cancelled_navigation_does_not_leave_the_form_blocked(browser, base_url):
    """Esc/Stop/network error: the page stays, so nothing resets the spinner by
    navigation. The form must still submit, and one submit must not stack a
    second spinner. (A real held request cannot be used: with a navigation in
    flight Playwright cannot evaluate in the page, so the submit is cancelled
    by a listener instead, exactly as the other loading tests do.)"""
    with session(browser, base_url, "/score") as page:
        _submit_and_hold(page)
        assert page.locator(".rt-btn--loading").count() == 1
        for _ in range(2):
            page.locator("form button[type=submit]").first.click(force=True)
        assert page.evaluate("window.__submits") == [False, False, False]
        assert page.locator(".rt-btn--loading").count() == 1
        assert page.locator(".rt-loadnote").count() == 1
        # The user gives up and edits the form: it still works after the Stop.
        page.locator("#field-order-number").fill(ORDER + "X")
        page.locator("#field-order-number").press("Enter")
        assert page.evaluate("window.__submits")[-1] is False


def test_busy_state_clears_on_a_safety_timer_and_when_the_tab_returns(browser, base_url):
    with session(browser, base_url, "/score") as page:
        page.clock.install()
        page.goto(base_url + "/score", wait_until="networkidle")
        _submit_and_hold(page)
        assert page.locator(".rt-btn--loading").count() == 1     # set synchronously by the submit
        page.clock.run_for(60000)
        assert page.locator(".rt-btn--loading").count() == 1, "still within the cold-start allowance"
        page.clock.run_for(31000)
        assert page.locator(".rt-btn--loading").count() == 0
        assert page.locator("form[data-rt-busy]").count() == 0
        page.locator("form button[type=submit]").first.click()
        assert page.locator(".rt-btn--loading").count() == 1     # set synchronously by the submit
        page.evaluate("""() => { const set = v => { Object.defineProperty(document, 'visibilityState',
            {get: () => v, configurable: true}); document.dispatchEvent(new Event('visibilitychange')); };
            set('hidden'); set('visible'); }""")
        assert page.locator(".rt-btn--loading").count() == 0
        assert page.locator("form[data-rt-busy]").count() == 0


def test_a_real_submit_navigates_and_leaves_no_loading_state_behind(browser, base_url):
    with session(browser, base_url, "/score") as page:
        page.locator("#field-order-number").fill(ORDER)
        page.locator("form button[type=submit]").first.click()
        page.wait_for_url("**/score?*")
        page.wait_for_load_state("networkidle")
        assert page.locator(".rt-btn--loading").count() == 0
        page.go_back()
        page.wait_for_load_state("networkidle")
        assert page.locator(".rt-btn--loading").count() == 0
        assert page.locator(".rt-loadnote").count() == 0


# ---- supplier questions -------------------------------------------------------

def test_copy_all_puts_numbered_questions_on_the_clipboard(browser, base_url):
    # Only Chromium has the clipboard permission names; elsewhere the text
    # handed to navigator.clipboard.writeText is captured instead.
    chromium = browser.browser_type.name == "chromium"
    options = {"permissions": ["clipboard-read", "clipboard-write"]} if chromium else {}
    with session(browser, base_url, ANNEX, **options) as page:
        if not chromium:
            page.evaluate("""() => { window.__clip = '';
                Object.defineProperty(navigator, 'clipboard', {value: {
                  writeText: t => { window.__clip = t; return Promise.resolve(); }}}); }""")
        count = page.locator("ol > li .rt-q__text").count()
        assert count > 1
        page.get_by_role("button", name="Copy all").click()
        toast = page.locator(".rt-toast").first
        toast.wait_for()
        assert "Copied %d questions" % count in toast.text_content()
        clip = page.evaluate("navigator.clipboard.readText()" if chromium else "window.__clip")
        assert clip.startswith("1. ") and ("\n%d. " % count) in clip


def test_copy_failure_is_an_error_toast_that_stays(browser, base_url):
    with session(browser, base_url, ANNEX) as page:
        page.evaluate("""() => {
            Object.defineProperty(navigator, 'clipboard', {value: {writeText: () => Promise.reject(new Error('no'))}});
            document.execCommand = () => false; }""")
        page.get_by_role("button", name="Copy all").click()
        toast = page.locator(".rt-toast[role=alert]")
        toast.wait_for()
        page.wait_for_timeout(5600)
        assert toast.is_visible(), "an error toast persists"
        toast.get_by_role("button", name="Dismiss").click()
        assert page.locator(".rt-toast").count() == 0


def test_mark_as_sent_survives_a_reload_in_the_same_session(browser, base_url):
    with session(browser, base_url, ANNEX) as page:
        boxes = page.get_by_role("checkbox", name="Mark as sent")
        assert boxes.count() > 1
        boxes.nth(1).check()
        assert page.locator("li[data-sent]").count() == 1
        page.reload(wait_until="networkidle")
        boxes = page.get_by_role("checkbox", name="Mark as sent")
        assert [boxes.nth(i).is_checked() for i in range(boxes.count())][:2] == [False, True]
        boxes.nth(1).uncheck()
        page.reload(wait_until="networkidle")
        assert page.get_by_role("checkbox", name="Mark as sent").nth(1).is_checked() is False


def test_the_page_works_when_session_storage_is_unavailable(browser, base_url):
    with session(browser, base_url, ANNEX) as page:
        page.add_init_script("Object.defineProperty(window, 'sessionStorage', {get() { throw new Error('denied'); }})")
        page.reload(wait_until="networkidle")
        page.get_by_role("checkbox", name="Mark as sent").first.check()
        assert page.get_by_role("button", name="Copy all").count() == 1


# ---- gap cards and tooltips ---------------------------------------------------

def test_a_gap_card_link_focuses_its_field(browser, base_url):
    with session(browser, base_url, "/score?vendor=ABB&product=AC+800M") as page:
        link = page.locator("a.rt-gap__link[href^='#field-']").first
        assert link.count() == 1, "the VERIFY result has a gap card that targets a field"
        target = link.get_attribute("href")[1:]
        link.click()
        page.wait_for_function("id => document.activeElement && document.activeElement.id === id", arg=target)
        assert page.evaluate("location.hash") == "#" + target


def test_escape_dismisses_a_visible_tooltip(browser, base_url):
    with session(browser, base_url, S7) as page:
        tip = page.locator(".rt-tip").first
        assert tip.count() == 1
        bubble = tip.locator(".rt-tip__bubble")
        tip.focus()
        page.wait_for_function(
            "() => getComputedStyle(document.querySelector('.rt-tip .rt-tip__bubble')).visibility === 'visible'")
        page.keyboard.press("Escape")
        assert bubble.evaluate("b => getComputedStyle(b).visibility") == "hidden"


# ---- the script's own hygiene on every page ----------------------------------

@pytest.mark.parametrize("name", PAGES)
def test_one_external_script_no_inline_script_no_handlers(browser, base_url, name):
    with session(browser, base_url, PAGES[name]) as page:
        scripts = page.evaluate("""() => [...document.scripts].map(s => [s.getAttribute('src'), s.defer, s.text.length])""")
        assert len(scripts) == 1
        src, deferred, inline = scripts[0]
        assert src.startswith("/static/retrust.js?v=") and deferred and inline == 0
        handlers = page.evaluate("""() => [...document.querySelectorAll('*')].flatMap(
            e => e.getAttributeNames().filter(n => n.startsWith('on')).map(n => e.tagName + '@' + n))""")
        assert handlers == []


@pytest.mark.parametrize("name", PAGES)
def test_no_csp_violation_on_load_or_a_search(browser, base_url, name):
    with session(browser, base_url, PAGES[name]) as page:
        _type(page, "SIMATIC")
        page.wait_for_timeout(500)


# ---- JavaScript disabled: the baseline is the contract --------------------------

@pytest.mark.parametrize("name", PAGES)
def test_every_page_renders_without_javascript(browser, base_url, name):
    context = browser.new_context(java_script_enabled=False, **OPTIONS)
    page = context.new_page()
    try:
        response = page.goto(base_url + PAGES[name], wait_until="load")
        assert response.status == 200
        assert page.locator("h1").count() == 1
        assert page.locator(".rt-suggest, .rt-toasts, .rt-loadnote").count() == 0
        # Nothing that needs the script is shown as a dead control.
        assert page.get_by_role("button", name="Copy all").count() == 0
        assert page.get_by_role("checkbox", name="Mark as sent").count() == 0
        placeholder = page.locator("#rt-global-q").get_attribute("placeholder") or ""
        assert "⌘K" not in placeholder and "Ctrl K" not in placeholder
    finally:
        context.close()


def test_the_search_form_submits_without_javascript(browser, base_url):
    context = browser.new_context(java_script_enabled=False, **OPTIONS)
    page = context.new_page()
    try:
        page.goto(base_url + "/about", wait_until="load")
        page.locator("#rt-global-q").fill(ORDER)
        page.locator("#rt-global-q").press("Enter")
        page.wait_for_url("**/?q=*")
        assert page.locator(".hit, .rt-search-row, [href^='/score?']").count() >= 1
        # And the page's own big search form, with its button.
        page.locator("#q").fill("SIMATIC S7-1500")
        page.get_by_role("button", name="Search").click()
        page.wait_for_url("**/?q=SIMATIC*")
    finally:
        context.close()


def test_drawers_and_export_menu_work_natively_without_javascript(browser, base_url):
    context = browser.new_context(java_script_enabled=False, accept_downloads=True, **OPTIONS)
    page = context.new_page()
    try:
        page.goto(base_url + S7, wait_until="load")
        opener = page.locator(".ev-open").first
        target = opener.get_attribute("popovertarget")
        opener.click()
        assert _popover_open(page, target)
        page.keyboard.press("Escape")
        assert not _popover_open(page, target)
        button = page.locator(".rt-menu > [popovertarget]").first
        menu = button.get_attribute("popovertarget")
        button.click()
        assert _popover_open(page, menu)
        with page.expect_download() as download:
            page.locator("#%s a[href^='/export.csv']" % menu).click()
        assert download.value.suggested_filename == "retrust-assessment.csv"
    finally:
        context.close()


def test_forms_submit_without_javascript(browser, base_url):
    context = browser.new_context(java_script_enabled=False, **OPTIONS)
    page = context.new_page()
    try:
        page.goto(base_url + "/score", wait_until="load")
        page.locator("#field-order-number").fill(ORDER)
        page.locator("form button[type=submit]").first.click()
        page.wait_for_url("**/score?*")
        assert page.locator("main .rt-verdict, main h2").count() >= 1
    finally:
        context.close()
