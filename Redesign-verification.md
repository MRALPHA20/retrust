# Redesign verification (WP10b)

Full verification matrix of the "Control Room" redesign, run on branch `redesign`.

## Browsers

| Engine | Version | Result |
|---|---|---|
| Chromium | Playwright 1.64.1 bundled | whole `tests/e2e` suite green |
| Firefox | 157.0 (playwright firefox-1555) | whole suite green after the fixes below |
| WebKit | 27.2 (playwright webkit-2370) | whole suite green after the fixes below |

The Firefox and WebKit builds that were installed (1490, 2203) did not match
Playwright 1.64.1, so `python -m playwright install firefox webkit` was run once.
JavaScript-disabled flows pass on all three engines. `tests/e2e/test_print_browser.py`
asserts `::details-content` printing on Chromium only (by design; other engines skip).

## Matrix coverage

- `tools/capture_screenshots.py --set review`: 18 pages x 5 widths (375, 640, 1024,
  1100, 1440) x 5 modes (default, reduced-motion, grayscale, print, coarse) = 450
  screenshots, no 5xx, no CSP violation (the one console line is the intended 404 of
  the not-found page).
- `--hosted`: home, score-empty, avoid-kev-s7-1500, about at 375 and 1440, default = 8.
- A DOM audit over every page at 375, 640, 1024, 1100, 1440 and coarse 375/768: no
  page-level horizontal overflow, no visible text under 12px, no table outside `.tw`.
- Interactive states captured and inspected at 1440 and 375: export menu, evidence
  drawer, tooltip, search suggestions, toast, compare with a blocked candidate
  (Hikvision IP Camera), clear-shortlist popover, loading state.
- Keyboard walk of `/score` result (111 tab stops): skip link first, 2px outline on
  every stop except text inputs and selects, which use the spec's `--action` border
  plus 1px ring (spec 4.x "Focus: border --action").
- Viewport 320 and CSS zoom 2: no horizontal overflow.
- axe-core: not run (no installed copy; nothing downloaded).

## Defects found and fixed

- Export menu opened at the top-left corner of the viewport (top-layer static position); now anchored under its button with CSS anchor positioning, centred fixed sheet where unsupported (e2e on 3 engines, `tests/test_wp10b_css.py`).
- Header search placeholder clipped to "Ct" at 1100px; tighter gap and wider field in 1100-1279, ellipsis otherwise (e2e at 1100/1180/1279/1440).
- Print: action buttons were printed, tables kept their screen `min-width` and ran off the page, tooltip bubbles widened the page; print now hides them and lets tables wrap and shrink (web and export stylesheets; e2e at 640 and 794 on 3 engines).
- WebKit: focus after closing a drawer with Esc landed on the table scroller instead of the opener; the script now returns focus to the opener after Esc (e2e).
- Tooltip bubble inherited `white-space:nowrap` from table headers; now `normal`.
- Test fixes: Firefox logs its own favicon request against `default-src 'none'` (`FaviconLoader`) which is ignored by the CSP console checks; clipboard permission names exist only on Chromium (other engines capture `writeText`); WebKit/Safari do not Tab to links, so the skip-link test focuses it first there and the ring test ignores focus leaving the page.

## Known limitations

- Safari/WebKit does not put links in the Tab order unless the user enables it, so the skip link is not the first Tab stop there.
- A tooltip inside a scrolling table card can be clipped by the card on a narrow screen. Anchoring it to the top layer was tried and dropped: it made the bubble intermittently stay hidden in Firefox. The legend under the table repeats every definition.
- Firefox logs one CSP console line per page for its favicon request (no `img-src`); no page resource is affected.
- In print emulation at a 375px viewport (not a real paper width) the tables still exceed the page by up to 170px; 640px and wider fit.
- Inline text links and the 18px checkbox boxes are under 44px on touch (24px links, 44px label hit area for checkboxes); spec 4 requires 44px for primary controls only.
- The clear-shortlist confirm popover is not anchored; it appears near the page top rather than under its button.

## Needs user decision

- Add `img-src 'self'` plus a tiny `/favicon.ico` (or `data:` icon) to remove the Firefox favicon console line? It changes the CSP.

## Resolved after this report

- The result section navigation (OVERVIEW ... INPUTS) is now a single horizontally scrolling row below 640px.
