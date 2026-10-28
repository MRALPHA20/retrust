"""CSS-level guards for defects the full browser matrix found (WP10b).

The behaviour itself is proved in tests/e2e/test_ui_browser.py; these keep the
rules from being edited away on machines without a browser.
"""

import re

from retrust import components, design, report, webui


def _rule(css, selector):
    match = re.search(re.escape(selector) + r"\{([^}]*)\}", css)
    assert match, selector
    return match.group(1)


def test_export_menu_is_anchored_to_its_button():
    # A popover is in the top layer; without an anchor it opened at the
    # viewport corner. The unsupported-browser fallback is a centred sheet.
    css = components.CSS
    assert "anchor-name:--rt-menu" in css and "anchor-scope:--rt-menu" in css
    assert "top:anchor(bottom)" in css and "position-anchor:--rt-menu" in css
    base = _rule(css, ".rt-menu__list")
    assert "position:fixed" in base and "left:50%" in base


def test_print_lets_tables_shrink_and_hides_action_chrome():
    for css in (design.PRINT_CSS, report.EXPORT_CSS):
        assert ".tw table,.tw table.rt-cmp,.ev-table{min-width:0!important" in css
        assert ".rt-assess-actions" in css and "display:none!important" in css
    assert design.PRINT_CSS in webui.STYLESHEET


def test_header_search_keeps_its_shortcut_hint_visible_at_1100():
    assert "@media(min-width:1100px) and (max-width:1279px)" in webui.SHELL_CSS
    assert "text-overflow:ellipsis" in webui.SHELL_CSS
