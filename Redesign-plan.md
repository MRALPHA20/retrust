# ReTrust "Control Room" redesign: implementation plan

Repo root: `D:\karthik\retrust`, branch `redesign`. Baseline today: 1,102 tests collect (`python -m pytest -p no:cacheprovider --collect-only -q`). Local Python is 3.13; CI runs 3.10 and 3.13. Local tooling is in place for verification: `data/retrust.db` (44 MB real index), Playwright, ReportLab 5.1 and Chrome 156.

---

## 1. Current state and gap analysis

### 1.1 How the UI is produced today
- **No templates, no JS, no build step.** Pages are Python f-strings, and every dynamic value is escaped with `html.escape` (`webui.esc`, `serve._esc`, `report._esc`, `webviews._esc`).
- **CSS lives in Python string constants, inlined in a `<style>` on every response:**
  - `report.CSS = THEME + rules`. THEME is a light `:root`, plus `@media(prefers-color-scheme:dark)`, plus `:root[data-theme=dark]`. Tokens are named `--field/--panel/--sunk/--rule/--ink/--soft/--faint/--prefer/--cond/--avoid`.
  - `webui.CSS` holds the sidebar shell and the page classes, with type scale `--t-xs:13px … --t-lg:18px`.
  - `webui.page(title, body, subtitle="", active=None)` emits `report.CSS + webui.CSS` with `<html data-theme="dark">`. The export `report.render(...)` emits `report.CSS` only.
- **Fonts are system stacks only, on purpose.** `report.FACES` carries the comment "A webfont would be a network fetch".
- **Server:** stdlib `http.server`. `serve.build_handler.page_for` is an exact-path dict of 20 routes:
  - `/`, `/healthz`, `/formula-check.json`, `/robots.txt`, `/demo`, `/about`, `/score`
  - `/export.html|.json`, `/compare`, `/compare.html|.json|.csv`
  - `/alternatives`, `/timeline`, `/annex`, `/annex.txt`, `/ssvc`, `/lev`, `/vendor`
  - GET/HEAD only. `Handler._send` only handles `str` (it calls `.encode`); responses are `PlainText` or `Download` (str subclasses).
- **Headers on every response:**
  - CSP `default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`
  - `Cache-Control: no-store`, XFO DENY, nosniff, `Referrer-Policy: no-referrer`
  - `do_GET` sends every path except `/healthz` through the calculation semaphore.
- **No server state.** Everything rides in GET URLs. The edit form carries `was_*` hidden fields so that `_edit_effects` can diff old and new answers.
- **Packaging:**
  - Zero runtime dependencies. `packages.find include=["retrust*"]`, and no package-data is declared.
  - Render runs `pip install .` (non-editable) via `scripts/render-build.sh`, so any non-.py asset must be declared.
  - `identity.build_fingerprint()` hashes only top-level `retrust/*.py`. New modules must stay flat (CONTRIBUTING.md says the same). The `X-ReTrust-Build` header and `formula-validation.json` depend on this fingerprint.
- **Security tests that shape the design:**
  - `test_no_page_ever_emits_a_script` checks for no `<script`.
  - `test_report_is_self_contained` forbids `<script`, `http://`, `https://fonts`, `<img` and `@import` in the export.
  - `test_the_policy_forbids_fetching_and_executing` checks for `default-src 'none'`.
- **Terminal:** `console.py` has its own ANSI palette. VERIFY is amber there, and a test pins only the key set against `report.VERDICT_COLOR`.
- **Screenshot tooling:**
  - `retrust/screenshot.py` drives system Chrome on export HTML and themes it by stamping `data-theme`.
  - `tools/capture_screenshots.py` uses Playwright and takes a single shot, `workspace-comparison.png`. `tools/build_overview.py` embeds that image in `docs/ReTrust-Guide.pdf`.
- **Docs pages:**
  - `docs/user-guide.html` is a print guide with system fonts.
  - `docs/explainers/*.html` are standalone, not served by the app. They already load Plex from Google Fonts and include a small theme-toggle `<script>`.
  - `test_documented_figures` scans these files for score text.

### 1.2 Pages today

| Route | Function | Current UI |
|---|---|---|
| `/` | `serve._search_page` | Marketing hero, 3 metric tiles, workflow and example panels; results as `.hit` cards; vendor fallback |
| `/score` (empty) | `_score_page` → `_score_form` | Full form: order number, vendor/model in `<details>`, firmware, 6 owner selects |
| `/score` (result) | `_score_page` → `report.body(tools=…)` | "Product assessment" h1, edit-effects panel, verdict strip, help, calculation summary, "What to check next" list, edit/download `<details>`, contributions table, gates, cautions, pillar table + "Show more info", notes, top-10 CVE table, "Take the next step" links |
| `/score` (unresolved) | same | VERIFY block + "Did you mean" `.hit` rows |
| `/compare` | `_compare_page` | Candidate fieldsets, summary table (Candidate/Verdict/Score/…/Main reason) + full block per candidate |
| `/about` | `_about_page` | Methodology prose, formula, data/provenance tables, SAFETY |
| `/vendor`, `/timeline`, `/alternatives`, `/annex`, `/ssvc`, `/lev`, `/demo` | `_vendor_page` … `_demo_page` + `webviews.*` | Lookup forms, `.reading-facts`, `_table`, `.notice`, `<details>`; alternatives uses an inline verdict `style="color:…"` |
| 400/403/404/500 | `Handler._dispatch_get`/`do_GET` | Bare page with h1 + p |
| Export | `report.render` (also CLI `--html`) | Light/dark auto theme, same block markup |

### 1.3 What data exists versus what the spec draws
- **Per-unit T/I/A/H/U/Z is available.** It sits in `assessment.paths[]` as `{path_id, cves, advisories, z_min, z_max, inputs[{cve, advisory, factors{T,I,A,H,U:[lo,hi]}, missing, kev, lev, epss, cvss_vector, cvss_severity, firmware_range, version_checked}]}`, sorted by −z_max. R and E come from `exposure.CONCENTRATION`/`concentrate` and `exposure_min/max`.
- **A "floored T" flag is not stored but can be derived.** Compare `exposure.threat(f)` (or `max(kev, lev, epss)` from the inputs) against `exposure.THREAT_FLOORS[exposure.access_profile(f)][1]`.
- **Weights:** `context["weights"]`. The composite exponent is w/Σ(all) (`score._composite`).
- **Neutral-substituted pillar:** a `PILLAR_KEYS` pillar with `Pillar.scored is False`. It enters the composite at `score.MISSING_PILLAR` (50) with its full weight.
- **Gates:** `{gate, detail, source}`. Screening gates are labelled "Named on a covered list" or "Sanctioned or export-restricted entity" (`supplychain.gates_for`).
- **Snapshot freshness:**
  - `index.provenance()` gives `{source, detail, captured(ISO)}` rows with sources "CISA KEV", "FIRST EPSS", "FIRST EPSS history" and the CSAF root label.
  - Thresholds: `doctor.AGE_LIMITS` (KEV/EPSS 14 days).
  - Load checks: `any(p["source"]=="CISA KEV" …)` for KEV (already used in `/ssvc` and `/lev`); `len(context["screening"])` for the screening list.
- **LEV:** `Finding.lev` is set only after `retrust lev --update`.
- **Fix status:** only `Finding.remediation` (a category) plus `fix_text`. **There is no fixed-in version.**
- **Advisory:** only `advisory(id, title, released)`. There is no per-CVE summary.
- **Order number:** from the query only (`Match` has none).
- **Questions:** `questions.Question(text, why, evidence)` carries no gap tag.
- **Not in the data at all:** product category (the "CONTROLLER" eyebrow), service-life years, plant zone names beyond `NETWORK_EXPOSURES` labels.

### 1.4 Component inventory (spec §7) mapped to existing code

| Spec component | Exists today | Status |
|---|---|---|
| Header | `.topbar` + sidebar `.brand`/`.local-status` | New (replace) |
| Nav | `NAVIGATION` (3 groups, 10 links), sidebar + mobile `<details>` | New: 4 items |
| GlobalSearch | Search form only on `/` | New (GET form; popover needs JS, see A5) |
| Button ×5 | `button,.button`, `.button.secondary`; primary is teal `#73e0b7` | Rework (cyan; 5 kinds; states) |
| TextField | `serve._field` | Rework (verified/unverified/error/disabled) |
| Select | `serve._choice`, `serve._select` | Rework (styling; Unknown drawn VERIFY) |
| Checkbox/Radio/Toggle | none | New (CSS only; Radio/Toggle currently have no use) |
| OperatingConditionsForm | `serve._owner_fields` in `.site-context` | Rework (fieldset card rows) |
| VerdictBadge S/M/L | `.verdict .v` coloured word; inline colour in alternatives | New |
| ScoreCard, BandBar | `.verdict` strip | New |
| PillarMeter | `_pillar_table` rows + `.bar` | New (table kept for diagnostics) |
| ExposureTable | Contributions table in `<details>` + `_calculation_summary` | New (top-3 units + formula) |
| GapCard / ContextCard | "What to check next" `<ul>`, `.notice`, `.note`, `.caution` | New / Rework |
| SignalChip | none (text "Listed in CISA KEV") | New |
| BlockerAlert | `.gate` (no role) | Rework (`role=alert`, BLOCKER/RESTRICTION tag) |
| EvidenceTable | `report._cve_table` (top 10 by EPSS, no sort or filter) | Rework |
| EvidenceDrawer | none | New |
| PageIdentity | `<h1>Product assessment</h1>` + block `<h2>` | New |
| ExportMenu | "Save or share" `<details>` (HTML, JSON) | New (+CSV, +VEX routes) |
| ComparisonTable | `report._summary_table` (one row per candidate) | Rework (transposed, sticky) |
| SupplierQuestions | `webviews.supplier_questions` | Rework (gap tags, copy/export) |
| Tabs | none | New (section nav) |
| Tooltip | none | New (CSS) |
| Toast, Skeleton | none | New (CSS; only useful with JS) |
| EmptyState | blank `/score` form, `.empty` | Rework |
| ErrorAlert | bare 4xx/5xx pages, `.notice role=alert` | New |
| Footer | footer flex row | Rework |

### 1.5 Pages after the redesign
- `/` becomes **Search**: no marketing hero, a large search box, sample chips, the corpus counts on a mono line, and result rows with popover anatomy.
- `/score` gets:
  - an EmptyState when no product is selected;
  - the full result layout: identity → actions → tabs → blockers → [Score | Exposure] → gaps/context → evidence → questions → inputs → technical → disclaimer;
  - a not-identified variant.
- `/compare` becomes a transposed shortlist table with an export menu.
- `/about` becomes **Methodology**, with the stale copy fixed (see 1.6).
- The seven secondary pages are restyled with the new components, with their content unchanged.
- Error pages show an ErrorAlert inside the shell.
- The export becomes the light variant with the same anatomy and no controls.

### 1.6 Existing inconsistencies found (fix during the redesign)
1. **Pillar weight display contradicts the maths.**
   - `report._weight_share(..., active_pillars)` renormalises over scored pillars, and `_pillar_table` shows "not scored" for a neutral-substituted pillar.
   - `score._composite` actually uses full-set exponents, with MISSING_PILLAR=50 at full weight.
   - The copy in `report._footer_sources` and `/about` ("Parts without measurable evidence are excluded and the remaining weights are adjusted") contradicts score.py's own comment.
   - Spec 4.9 (`50*`, "neutral 50 applied at weight .05") matches the code. Fix the display and the copy.
2. VERIFY is drawn amber (`VERDICT_COLOR["VERIFY"]="var(--cond)"`). The spec makes it violet.
3. Links, focus, primary buttons and active nav all use teal accent `#73e0b7`. The spec reserves teal for PREFER; interactive elements must be cyan.
4. Radii of 7–10px and a 20px pill (`.offline`) break the "≤6px, no pills" rule.
5. The landing hero copy is marketing voice, which breaks spec 5.3.

---

## 2. Architecture decisions

**A1. Module layout: flat modules only.**
- `retrust/design.py`: tokens, base CSS, print CSS, colour maths.
- `retrust/components.py`: primitives and formatters.
- `retrust/evidenceview.py`: exposure table, evidence table, drawer, ranking, filters.
- `retrust/assets.py`: fonts and the `Asset` response type.
- Binary fonts go in `retrust/static/fonts/`.
- Shell stays in `webui.py`, result composites and export in `report.py`, page composition in `serve.py`.
- Rationale: build fingerprint, the CONTRIBUTING rule, and existing tests that import `serve._*`/`report._*`.

**A2. CSS stays as plain Python string constants (never f-strings).**
- Why: it is fingerprinted automatically, needs no package-data, can be unit-tested, and matches the current pattern.
- Fixed assembly order:
  - **Web page:** `design.theme_css(DARK)` + `assets.font_face_css(served=True)` + `design.BASE_CSS` + `components.CSS` + `evidenceview.CSS` + `report.RESULT_CSS` + `webui.SHELL_CSS` + `webui.PAGE_CSS` + `design.PRINT_CSS`.
  - **Export:** `design.theme_css(LIGHT, ":root")` + `design.theme_css(DARK, ":root[data-theme=dark]")` + `font_face_css(served=False)` + `BASE_CSS` + `components.CSS` + `evidenceview.CSS` + `report.RESULT_CSS` + `report.EXPORT_CSS`.
  - The dark selector stays only for `screenshot.capture_both_themes`. Remove the `prefers-color-scheme` auto-dark (spec 5.5).
- Token contract:
  - Spec §2.6 names verbatim.
  - Derived, precomputed 8-digit hex (no `color-mix`): `--{prefer,conditional,avoid,verify}-fill` (14%), `-edge` (50%), `-track` (35%), and `--avoid-alert` (10%).
  - Also `--overlay-shadow`, spacing `--s2 … --s48`, radii `--r-sm/md/lg/card`, `--t-fast:120ms`, `--t-load:200ms`.
- Class contract:
  - New components use an `rt-` prefixed BEM scheme (`rt-badge rt-badge--verify rt-badge--l`).
  - Legacy hook classes that tests or regexes depend on keep their names: `hit`, `tw`, `table-scroll-hint`, `subject`, `n`, `meta`, `tnote`, `note`, `helper`, `empty`, `assessment-more-info`, `edit-effects`.
- CSP gotcha for implementers: `url(data:…)` in CSS is blocked by `default-src 'none'` (img-src). Inline `<svg>` and `style=""` attributes are allowed, and gradients are fine (hatching).

**A3. Component model.**
- Components are pure functions: data in, escaped HTML string out, no I/O.
- Every text parameter is escaped inside the function. `*_html` parameters accept only markup produced by other components.
- Composites take domain objects plus `web: WebView | None`. `None` means export/static mode.
- One renderer serves both the web page and the export (spec 5.5; the existing `test_report_body_is_what_render_puts_in_its_page` invariant is kept).

**A4. Fonts: self-host IBM Plex (decision D2).**
- Spec text says Google Fonts. That conflicts with:
  - the CSP (`default-src 'none'`);
  - the air-gapped claim (pyproject comment);
  - hosted-mode privacy (a visitor IP leaks to Google);
  - `test_report_is_self_contained`.
- Recommendation:
  - Ship OFL-1.1 woff2 for Sans 400/500/600/700 and Mono 400/500/600 (Latin-1 split files from the official IBM Plex release, version pinned, `OFL.txt` included).
  - Serve them from exact routes `/static/fonts/<file>.woff2?v=<sha8>` with `Cache-Control: public, max-age=31536000, immutable` (fonts only; pages stay `no-store`).
  - Add `font-src 'self'` to the CSP.
  - The export uses `@font-face{src:local(...)}` only, falling back to the system stack: no network, small file, same anatomy.

**A5. Interactivity: platform-native, no-JS baseline (decision D1).** Optional same-origin script in WP9 only if approved.

| Spec behaviour | No-JS baseline | Added by WP9 (if approved) |
|---|---|---|
| Global search popover 4.3 | GET form → `/?q=` page whose rows use the popover anatomy; spec no-results copy | Live listbox from `/search.json`; ↑↓/Enter/Esc |
| ⌘K | Removed from placeholder | Ctrl/⌘K |
| Export menu 4.17 | `popover="auto"` list + `popovertarget` button. Items are `<a href>` downloads. Esc, light-dismiss and focus return are native. Anchor-positioned where supported, centred sheet otherwise | Toast |
| Drawer 4.15 | `popover="auto"` right panel (`role=dialog`, `aria-labelledby`), `::backdrop` scrim. Esc and focus return are native. If e2e passes on Chromium, Firefox and WebKit, use modal `<dialog>` + invoker commands (`commandfor`/`command="show-modal"`) to get a real focus trap | Focus trap polyfill |
| Sort/filter 4.14 | Server-side GET links (`ev`, `sort`, `dir`, `show`), `aria-sort`, `aria-current` | (unchanged) |
| Tabs 4.20 | In-page section nav (`<nav aria-label="Result sections">` anchors); active via `aria-current` + `:target`/`:has()` | Scroll-spy |
| Tooltip 4.21 | CSS hover/focus-within, `role=tooltip` + `aria-describedby`, 150ms delay; definitions repeated in a visible legend | Esc dismiss |
| Toast 4.22, loading/skeleton 4.23, "demo waking" note | Not possible with synchronous GET; CSS shipped, unused | Yes |
| Gap card → field 4.11 | Link to `#field-x` (scroll + `:target` highlight; the next Tab enters the field) | Focus the field |
| Copy all / mark as sent 4.19 | Link to `/annex.txt`; checkbox omitted | Clipboard; sessionStorage |
| Sample chips 4.23 | Links that run the search or assessment | Fill the field |

**A6. Request-scoped shell data.**
- `webui.CURRENT_SNAPSHOT = contextvars.ContextVar(...)`, set and reset in `Handler._dispatch_get` from `provenance` captured in `build_handler`.
- This avoids threading provenance through roughly 40 `_page()` calls.
- The webcache-cached pages (`/alternatives`, `/lev`) stay correct because their cache keys already include the snapshot and date.

**A7. Evidence view state lives in the URL.**
- Parameters: `ev ∈ {all, unpatched, network, kev}`, `sort ∈ {z, id, weakness, cvss, epss, vector, fix}`, `dir ∈ {asc, desc}`, `show=all`.
- All are whitelisted, presentation-only and never passed to the scorer.
- Links are built from `_score_page`'s existing `parameters` plus `#evidence`, and never include `was_*`.

**A8. No scoring changes.**
- `score.py`, `exposure.py` and `match.py` must show no diff against `main`.
- The only behaviour change outside the UI is `batch.to_detail` ranking, and only if D4 is approved.

---

## 3. Phases and work packages
Each work package gets its own branch off `redesign` (git worktree), is rebased before merge, and merges in the stated order. **The full suite must be green at every merge.** Visual coherence is guaranteed only at phase gates.

### Phase 0: contracts (lead, serial, small)
**WP0 Contracts and stubs**
- **Files:**
  - `D:\karthik\retrust\retrust\design.py` (token dicts, `alpha()`, `theme_css()` signatures)
  - `D:\karthik\retrust\retrust\components.py` (signatures and docstrings)
  - `D:\karthik\retrust\retrust\evidenceview.py` (`EvidenceView` dataclass and stub functions)
  - `D:\karthik\retrust\retrust\report.py`: split the current CSS into `THEME` + `RESULT_CSS`, with `CSS = THEME + RESULT_CSS` producing byte-identical output; add the `WebView` dataclass
- `WebView` fields: `actions_html`, `tabs_html`, `inputs_html`, `questions_html`, `evidence: EvidenceView`, `advisories: dict[id, (title, released)]`, `checks: dict(kev_loaded, screening_loaded)`, `order_number`, `version`, `field_ids: dict`.
- The decisions D1–D6 get recorded in the `design.py` docstring.
- **Acceptance:** the suite is unchanged and green, and nothing calls the stubs.

### Phase 1: foundations (all four in parallel; no shared files)

**WP1 Tokens and base CSS.** Spec 2.1–2.3, 2.5, 2.6, 5.4 (contrast, focus, motion), 5.5.
- **Files:** `D:\karthik\retrust\retrust\design.py`, new `D:\karthik\retrust\tests\test_design.py`.
- **DARK** uses the exact spec 2.1 values.
- **LIGHT** uses spec 5.5 plus proposals for the tokens the spec leaves undefined:

  | Token | Value |
  |---|---|
  | `--ground` | `#FFFFFF` |
  | `--bar` | `#EEF1F4` |
  | `--surface` | `#F6F8FA` |
  | `--raised` | `#E5E9EF` |
  | `--rule` | `#D5DBE3` |
  | `--rule-row` | `#E3E7ED` |
  | `--control-border` | `#6B7686` |
  | `--text` | `#111827` |
  | `--text-2` | `#374151` |
  | `--muted` | `#5B6472` |
  | `--action` | `#0B6E8E` |
  | `--action-hover` | `#095A74` |
  | `--on-action` | `#FFFFFF` |
  | `--prefer` | `#0F7A64` |
  | `--conditional` | `#8A5A00` |
  | `--avoid` | `#B42318` |
  | `--verify` | `#5B3FC4` |
  | `--on-avoid` | `#FFFFFF` |

  My hand calculation puts every proposed pair above threshold; the test is the arbiter.
- **BASE_CSS:** reset; body 14/1.45 sans (sizes in rem); type-role classes; `.num` with tabular figures; `:focus-visible` 2px action ring, 2px offset (inset inside tables); `.sr-only`; skip link; links; code wells on `--bar`; `.tw` scroller with focus ring; `th.n`/`td.n`; content max width 1360 with 24px gutter.
- **Touch and motion rules:**
  - `@media(pointer:coarse)`: 44px minimum targets, and inputs at 16px (prevents iOS zoom-on-focus).
  - `@media(prefers-reduced-motion:reduce)`: no transitions or animation.
- **PRINT_CSS:** `@media print` switches to LIGHT tokens, hides header, nav, search, actions, forms and popovers, and adds `break-inside:avoid` on cards and `thead{display:table-header-group}`.
- **Tests:**
  - Tokens equal the spec hexes.
  - WCAG ratios for every spec 2.1 claim, plus every LIGHT pair (text ≥4.5, control-border ≥3).
  - Composited fills: badge text on 14% fill over surface ≥4.5; `--text-2` on avoid 10% over ground ≥4.5.
  - The reduced-motion and focus rules are present.
  - Provide a reusable CSS-lint helper for WP12.

**WP2 Fonts and static assets.** Spec 2.2.
- **Files:**
  - `D:\karthik\retrust\retrust\assets.py`
  - `D:\karthik\retrust\retrust\static\fonts\*` (7 woff2 + `OFL.txt` + README with source URL, version and sha256)
  - `D:\karthik\retrust\pyproject.toml`: `[tool.setuptools.package-data] retrust = ["static/fonts/*.woff2","static/fonts/OFL.txt"]`
  - `D:\karthik\retrust\.gitattributes`: `*.woff2 binary`
  - `D:\karthik\retrust\retrust\identity.py`: `build_fingerprint` also hashes `retrust/static/**`
  - `D:\karthik\retrust\retrust\serve.py`, only these parts:
    - the font routes in the dict;
    - `_send` handling for `assets.Asset(bytes)` (no encode, `font/woff2`, immutable cache);
    - `do_GET` bypassing the calculation semaphore for font routes, like `/healthz`;
    - `font-src 'self'` in the CSP;
    - SAFETY text changed to "No page or download is cached; only bundled font files are cacheable" (all tested phrases kept).
  - New `D:\karthik\retrust\tests\test_assets.py`.
- Load fonts through `importlib.resources.files("retrust").joinpath(...)` (works on 3.10 and in wheels). Missing files mean a 404 and system-font fallback, never a crash.
- Needs network access to fetch the fonts. Check that ● ◆ ■ ✓ ▲ ▼ ↑ – · ≥ × are covered; any missing glyph falls back to the system font.
- **Tests:**
  - Each font route returns 200, `font/woff2`, immutable cache, nosniff and the CSP.
  - Pages still send `no-store`.
  - `/static/fonts/../x` returns 404.
  - The package-data line exists in pyproject.
  - Font hashes are pinned.
  - Fonts are served while calculation slots are full (copy the `test_web_concurrency` pattern).
  - Extend `test_the_policy_forbids_fetching_and_executing` with the `font-src` assertion.
- **Acceptance:** `python -m pip wheel . --no-deps -w <scratch>` produces a wheel containing the fonts.

**WP3 Component primitives.** Spec 2.4, 4.4–4.7, 4.11–4.13 (shell), 4.17 (menu shell), 4.20–4.23, 5.1–5.3.
- **Files:** `D:\karthik\retrust\retrust\components.py`, new `D:\karthik\retrust\tests\test_components.py`.
- **Formatters (spec 5.2):**
  - `fmt_score` 1 decimal; `fmt_range` with en dash; `fmt_z` 3 decimals; `fmt_cvss` 1 decimal.
  - `fmt_prob` gives `.04`, never `.00`: values <0.005 render `<.01`, values ≥0.995 and <1 render `>.99`.
  - `fmt_weight` gives `.60`.
- **Glyphs and icons:** `GLYPH = {PREFER:'●', CONDITIONAL:'◆', AVOID:'■', VERIFY:'?', OK:'✓'}`. `icon()` returns inline SVG (shield-check 22, chevron, close, spinner).
- **Components:**
  - `verdict_badge(verdict, size, low, high)`: VERIFY is dashed and carries its range; NOT ASSESSED gets a neutral fallback; a badge is never a button.
  - `signal_chip(kind, text, status)`: KEV solid; neutral; vector (with `wormable` in amber); fix status.
  - `button`/`link_button`: five kinds. Disabled uses `aria-disabled` plus a visible reason with `aria-describedby`. A loading-state variant is included.
  - `text_field`: states verified / unverified (`· not verified` suffix, dashed violet) / error (`■` text) / disabled.
  - `select_field`: inline SVG chevron; Unknown drawn VERIFY via `:has(option[value=…]:checked)`.
  - `checkbox`, `radio`, `toggle` (`role=switch` plus a Yes/No word).
  - `conditions_row`, `gap_card`, `context_card`.
  - `alert(kind: blocker|restriction|review|error)`: `role=alert` except for review.
  - `panel_label`, `card`, `tabs`, `tooltip`, `menu` (popover rows: label + format tag; disabled rows show a reason), `meta_chip`, `skeleton`, `empty_state`, `toast` (markup only).
  - `CSS` for all of the above.
- **Tests:**
  - Every text parameter is escaped.
  - Every verdict carries both glyph and word.
  - Ranges use the en dash.
  - Labels pair with ids; the disabled reason is present.
  - Formatter edge cases.

**WPQ Gap tags on supplier questions.** Spec 4.19.
- **Files:** `D:\karthik\retrust\retrust\questions.py`, `D:\karthik\retrust\tests\test_questions.py`.
- Add `gap: str = ""` as the last field of `Question`. Set it per generator: `_kev`→E, `_unfixed`→P, `_mitigated`→P, `_undecided`→E, `_wormable`→E, `_certification`→C, `_feed`→V, unresolved product→ID, `_always`→"".
- **Test:** `format_report` output is byte-identical before and after on a fixture.

**WPC (optional, tiny) Terminal VERIFY in violet.**
- **Files:** `D:\karthik\retrust\retrust\console.py`, `tests\test_console.py`.
- Add style `"verify": "38;5;141"`, map VERIFY to it, and pin it in the test.

**Gate R1 (review):** tokens and contrast, CSP, packaging, font licence.

### Phase 2: shell and result renderer (four in parallel; merge order WP5b → WP5a → WP4 → WP10a, then integration screenshots)

**WP4 Shell and page chrome.** Spec 3, 4.1–4.3, 4.23 (error), 4.24, 5.4.
- **Files:**
  - `D:\karthik\retrust\retrust\webui.py`
  - `D:\karthik\retrust\retrust\serve.py`, only `Handler.do_GET`/`_dispatch_get`: ContextVar set and reset, plus the 400/403/404/500 bodies
  - `D:\karthik\retrust\tests\test_serve.py`
- **`page()` keeps its signature. Structure:**
  - Skip link.
  - `<header class="rt-header">` containing: logo SVG, wordmark, `RT8` tag from `score.SCORING_VERSION`, 4-item nav (D5), GET search form (`action="/"`, `name="q"`, maxlength 200, label), and snapshot status.
  - `<main id="main">`.
  - Footer: disclaimer and links to `/about`, `/about#sources` and `source_note()`.
- **Snapshot status:** `snapshot_status(provenance, today, hosted)`.
  - Uses the oldest KEV/EPSS captured date: within the age limit means current, over 14 days means stale, either source absent means missing.
  - Renders `● Snapshot · offline|hosted · YYYY-MM-DD`, with the word "stale" or "missing" visible when not current (never colour alone).
  - **No `role=alert`.** `test_initial_forms_do_not_show_submission_errors` would fail, and the fixture index has no KEV.
- **Footer** must keep the tested strings "Offline assessment" / "Local workspace", and in hosted mode "Hosted assessment" / "Queries are processed on this server", never "Private decisions".
- **PAGE_CSS** restyles every legacy class still emitted (`.panel` `.notice` `.hit` `.chip` `.rows` `.lead` `.eyebrow` `.helper` `.empty` `.reading-facts` `.priority-list` `.term-list` `.lookup-*` `.form-grid` `.candidate-grid` fieldset/legend, details/summary, `.actions` `.steps` `.demo-cards` `.metrics`, pre). Add aliases (`--ink:var(--text)`, `--soft:var(--text-2)`, `--faint:var(--muted)`, `--panel:var(--surface)`, `--field:var(--ground)`, `--sunk:var(--bar)`, `--cond:var(--conditional)`) so `report.RESULT_CSS` legacy rules still render if WP5a lands later.
- **Breakpoints:** ≥1100; 640–1099; <640 (header wraps, nav becomes a horizontal scroll row, actions go full width).
- **Error pages:** ErrorAlert with tag ERROR, neutral border and a retry link; status codes unchanged.
- **Tests:**
  - Change `test_the_page_uses_the_report_stylesheet` to assert that `components.CSS[:80]` and `report.RESULT_CSS[:80]` appear in both the page and the export.
  - Change `test_inline_links_meet_the_touch_target_floor_on_small_screens` to the new breakpoint literal, keeping the 24px property.
  - New: exactly 4 nav links and the correct `aria-current` per route (parametrise all routes); search form attributes; three snapshot states; skip link first; error pages carry `role=alert` with codes unchanged; still no `<script`.

**WP5a Result composites and export variant.** Spec 3 (grid and order), 4.7–4.9, 4.11, 4.13, 4.16, 4.23 (not identified), 5.1, 5.2, 5.5, 6.
- **Files:** `D:\karthik\retrust\retrust\report.py`; `D:\karthik\retrust\retrust\supplychain.py` (only add `COVERED_LIST_GATE`/`SANCTIONS_GATE` constants used by `gates_for`, output unchanged); new `D:\karthik\retrust\tests\test_result_view.py`; listed test updates.
- **Keep these names:** `CSS`, `VERDICT_COLOR` (keys unchanged; values become the new vars), `VERDICT_HELP`, `PILLAR_LABELS`, `PILLAR_KEYS`, `FEEDS_EXPOSURE`, `CONTEXT_ONLY`, `INERT`, `score_label`, `plural`, `verb`, `RANGE_DASH`, `_probability`, `_calculation_summary`, `_pillar_table` (diagnostics), `_summary_table` (until WP7).
- **Signature changes:**
  - `_weight_share`: same signature, full-set normalisation (1.6 item 1).
  - `_assessment_block(..., tools='', hint=True, web=None)`.
  - `body(blocks, stabilities=None, weights=None, tools='', web=None)`.
  - `render(...)`: light variant.
- **DOM order:**
  1. Identity (eyebrow `ASSESSMENT · VENDOR`, title, meta chips MLFB/FW/Zone; unverified chips dashed).
  2. Web actions and tabs.
  3. Full-width BLOCKER/RESTRICTION alerts.
  4. Grid: `≥1100: minmax(380px,1fr) minmax(0,2fr)`, otherwise one column, Score → Exposure.
  5. Gaps (heading "What to check next" kept) and context cards (notes, cautions as REVIEW, stability, coverage).
  6. `tools`, placed after "What this score covers" (test).
  7. Evidence card, then questions, then inputs (web only).
  8. Technical section: vector, contributions, `_pillar_table` inside `<details class="assessment-more-info">` "Show more info", match meta.
  9. Drawers (web only).
- **Score card states:**
  - PREFER / CONDITIONAL: the numeral.
  - VERIFY: the low end, plus "Provisional range 41.3–78.2" (sentence case, keeps the tested "Provisional range") and a hatched range on the band bar.
  - AVOID with gates and a score: numeral struck through, plus "numeric score, overridden".
  - AVOID with no score: "—" plus "disqualified below" (tested).
  - Not identified / evidence-free: the computed range, plus a ContextCard "No usable evidence for this product" listing the two ways forward. Keep "product not identified", "Not identified." and "Check the manufacturer order number, vendor and model".
- **Band bar:** segments from the configured `bands` (default 60/20/20 at 35% alpha), a 2×22 marker, an axis built from the bands, and `role=img` with an `aria-label`.
- **Pillar meters:** E/P/V/C; `w .60` = w/Σ(all); the E fill takes its own verdict hue; a neutral pillar is drawn as a dashed violet bar at 50% width with `50*`, `· missing → neutral` and the footnote `*neutral 50 applied at weight .05`; a provisional E is solid up to low and hatched from low to high; 200ms transition.
- **Blocker alerts:**
  - Tag RESTRICTION when the gate label matches the supplychain constants, BLOCKER otherwise.
  - Body: "Verdict forced to AVOID regardless of numeric score (x)". Keep the text "Purchase blocker".
  - Web actions: "View advisory" (drawer for the first CVE) and "Re-assess with another version" (`#field-version`).
- **Blocker-free strip:** only shown with no gates. The wording comes from `checks`; an unchecked list produces a ContextCard, never a ✓.
- **Gap cards:**
  - Move the phrase→field mapping into `report.GAP_RULES` (serve imports it in WP6).
  - Neutral P/V/C pillars get a gap card with no form field; on the web it links to `/vendor`.
  - Missing firmware gets `GAP · FW`.
- **Export:** LIGHT default; no `<form>`, `popovertarget`, `<dialog>` or filter links; tooltip definitions as a visible `<dl>`; static detail rows; IDs only, no `https://`.
- **Tests:**
  - Update `test_cli.py::test_report_defines_both_themes`: light `:root`, `[data-theme=dark]` override, no auto-dark.
  - Update `test_webviews.py::test_assessment_only_collapses_the_four_additional_rows`: main labels visible outside `.assessment-more-info`, diagnostics inside.
  - New tests for every state above, for alert roles and tags, and for the export having no controls and no https.

**WP5b Exposure and evidence views.** Spec 4.10, 4.12, 4.14, 4.15, 4.21, 5.2.
- **Files:** `D:\karthik\retrust\retrust\evidenceview.py`; new `D:\karthik\retrust\tests\test_evidence_view.py`; update `tests\test_webviews.py` (`_reviewed` hook moves to `id="evidence-table"`; probability-format test). If D4=Z, also `D:\karthik\retrust\retrust\batch.py` and `tests\test_batch.py::test_detail_ranks_and_truncates_findings`.
- **Exposure card:**
  - Panel label `EXPOSURE · TOP 3 REVIEW UNITS`.
  - Readout `R = min(1, Z1 + 0.20·Z2 + 0.10·Z3) = 0.417 → E = 58.3`; ranges when provisional.
  - Unit rows use the input with the highest z; ranges render as `? 0–1` in violet; floored T gets `↑` with tooltip "floored by service-life vector".
  - Header tooltips plus a visible legend; `_calculation_summary` inside `<details>`.
  - Rows open the drawer.
- **Ranking:** `rank(findings, assessment)` sorts by Z (unit z_max) descending, then CVSS, then EPSS, then CVE id.
- **Counts and filters:** `unpatched` means `not f.fixed`; `network` means CVSS AV in N/A; `kev` means `in_kev`.
- **Evidence card:**
  - Panel label `EVIDENCE · N CVEs IN SCOPE FOR FW x`, or `· ALL AFFECTED VERSIONS` when no firmware is given.
  - Segment filter links with counts and `aria-current`.
  - Columns ID · WEAKNESS (CWE + `weakness` class) · CVSS · SIGNALS · VECTOR · FIX · Z.
  - Sortable `th` links; `aria-sort` on the active column only; `▲`/`▼`; sticky thead; inset focus ring.
  - Default cap is 10 (keep the "most significant of N findings" and "records how many were left out" disclosures); `show=all` caps at 200 and says so.
  - Separate empty states for cleared firmware, no CVEs, and an empty filter; footer caption.
- **Drawer:** one per **shown** CVE, as described in A5. Sections: Summary (advisory id, title, released), Affected versions (selected FW highlighted), Fix, Signals, How it enters the score (unit, Z, weight 1 / .20 / .10 or "outside top 3"). 480px wide, full width below 640px.
- **Export mode:** static rows, no links or popovers.
- **Tests:** ranking; counts; sort and `aria-sort`; cap; formats (`.04`, `<.01`); chips; fix mapping; floored marker; readout equal to `exposure_min/max`; drawer count equal to shown rows; unique escaped ids.

**WP10a Browser harness** (can start here; finalised in Phase 5).
- **Files:** `D:\karthik\retrust\tools\capture_screenshots.py`, new `D:\karthik\retrust\tests\e2e\test_ui_browser.py`.
- **Capture tool:** `--set docs` keeps today's single published shot as the default. `--set review` captures the matrix in §5. Add `--out`.
- **e2e tests:** `pytest.importorskip("playwright")`, and skip when `data/retrust.db` or the browsers are absent, so CI stays green.

**Gate R2:** merge all four; run the full suite; capture the review screenshot set; visual and a11y review of the result page and the export.

### Phase 3: pages (three in parallel; disjoint `serve.py` functions; merge order WP6 → WP7 → WP8, each rebasing first)

**WP6 Assess page.** Spec 3, 4.4–4.6, 4.16, 4.17, 4.19, 4.20, 4.23.
- **Files:** `D:\karthik\retrust\retrust\serve.py`, limited to: `_score_page`, `_score_form`, `_owner_fields`, `_choice`, `_field`, `_edit_effects` (markup only), `_still_open` (using `report.GAP_RULES`; keep `OPEN_QUESTIONS` as an alias), `_export`, new `_export_csv` and `_export_vex`, and **all routes-dict edits**: `/export.csv`, `/export.vex.json`, and a `download` parameter passed through to `/annex.txt`. Plus `tests\test_serve.py`.
- **Empty state:**
  - Large Mono order-number field.
  - Vendor/model fields may stay inside `<details>`; network/interface/prereq selects must stay outside (`test_network_exposure`).
  - Firmware field in the unverified style.
  - Operating-conditions card.
  - The only primary button is "Assess product".
  - Sample-chip links.
- **Result page:**
  - Build a `WebView`.
  - Actions: secondary "Supplier questions"; secondary "Add to comparison", which must remain the **first** `href="/compare?` on the page; primary "Export evidence ▾" menu with HTML, JSON (`href="/export.json?…"` is regex-tested), CSV and VEX (VEX disabled with a reason when the product is unresolved).
  - Tabs.
  - Inputs section open under heading `EDIT_PANEL`. Redefine the constant's value, but the literal "Edit product details" must stay absent. "Update assessment" becomes secondary.
  - Questions use `questions.build(assessment, findings, dossier.build(...))`.
  - Advisory titles: one parameterised `SELECT id,title,released FROM advisory WHERE id IN (...)` for the shown CVEs.
  - Checks, evidence view parameters, and filter links.
- **Keep:** `<a class="hit" href=` recovery rows; the exact `<input type="hidden" name="was" value="1">`; `name="…" value="…"` adjacency; `value="x" selected`; edit-effects copy (now a ContextCard tagged UPDATE, `aria-live=polite`).
- **New exports:**
  - CSV: `batch.dumps_csv([batch.to_record(...)], include_queries=True)`.
  - VEX: `vex.statements(connection, resolution, version)` → `vex.document(...)`. An empty result gives an ErrorAlert page with a 4xx status.
- **Tests:** export menu items and hrefs; CSV/VEX headers, filenames and formula neutralisation; VEX unavailable; hostile or invalid `ev`/`sort`/`dir` values are ignored and escaped; filter links carry the answers and never `was_*`; gap links point at existing ids; exactly one `rt-btn--primary` on the result page.

**WP7 Compare page.** Spec 4.18, 4.4 (destructive), 4.17.
- **Files:** `serve.py` (`_compare_page`, `_comparison_warning` markup), `report.py` (new `comparison_table`, replacing `_summary_table` inside `body` when there are 2+ blocks), tests.
- **Table layout:**
  - Transposed: candidate column headers show name + order number, a coral `■` when gated, and a `×` remove link (`aria-label`).
  - The sticky first column holds the metric labels; the header row is sticky too.
- **Rows:** Verdict (badge S), Score (Mono 500 20), E/P/V/C with mini bars, Blockers, Gaps, Unpatched CVEs, KEV, Verdict stability, Main reason. The best value per row is set in bold `--text`.
- **Kept behaviour:**
  - Ranked order is unchanged; no drag reorder (D6).
  - The region `aria-label` keeps "scroll horizontally for more columns".
  - The primary button is "Export comparison ▾" (keep `/compare.csv?` on the page).
  - "Clear shortlist" uses a popover confirm.
  - Per-candidate blocks stay; the stability sentence appears once per block.
- **Tests:** all existing compare tests unchanged; remove links; bolding; gated `■`.

**WP8 Search, Methodology and secondary pages.** Spec 4.3, 4.19, 4.23, 5.3.
- **Files:** `serve.py` (`_search_page`, `_demo_page`, `_about_page`, `_alternatives_page`, `_timeline_page`, `_annex_page`, `_annex_text(download=False)` returning a `Download` when true, `_ssvc_page`, `_lev_page`, `_vendor_page`, `_lookup_*`, `_product_next_steps`, `_select`); `D:\karthik\retrust\retrust\webviews.py`; tests.
- **`/`:** voice-compliant (no hero); keep "`{n:,} product entries`" and "`{n:,} vendor spellings`"; result rows as `<a class="hit">`; spec no-results copy.
- **`/about`:** fix the missing-pillar copy; add `id="sources"`; keep all tested strings.
- **`/annex`:** the SupplierQuestions component; keep `<pre` and "RFQ SECURITY ANNEX".
- **`/alternatives`:** S badges, no inline colour.
- **`/vendor`:** screening hits as RESTRICTION alerts.
- **Others:** stat tiles and shared tables; keep `<h2 class="subject">`.

**Gate R3:** run the `security-review` skill on the serve.py diff (new params, routes, escaping, CSP). Also check one primary per view, copy voice, and that the scoring modules have no diff.

### Phase 4 (only if D1 = allow script)
**WP9 Same-origin enhancement.**
- **Files:** new `retrust/enhance.py` (a vanilla JS string, no dependencies), `assets.py` (an `Asset` for `/static/retrust.js`), serve.py (route; CSP `script-src 'self'; connect-src 'self'`; new `/search.json?q=` reusing `_search_hits`, 8 results), and the `webui.page` script tag (`defer`).
- **Features:** the "With WP9" column of the A5 table. Everything must still work with JS disabled.
- **Tests:**
  - `test_no_page_ever_emits_a_script` becomes: exactly one same-origin external script, no inline scripts or `on*=` handlers.
  - `/search.json` escaping and caps.
  - Update the SAFETY text.

### Phase 5: verification, docs and cleanup
- **WP10b:** run the full matrix (§5) and file defects back to the owning work package.
- **WP11 Docs:**
  - Update `docs\manual.md` and `docs\demo-runbook.md` (labels: EDIT_PANEL, "Download report" → "Export evidence", "Explore" → "Search").
  - `make screenshots` → `docs\assets\workspace-comparison.png`; `make guide` (PDFs).
  - Optionally retheme the explainers; their figure text must not change (`test_documented_figures`).
- **WP12 Cleanup:**
  - Delete the legacy token aliases and old `.block/.verdict/.gate` rules.
  - Global CSS lint test over the assembled web and export CSS:
    - radius ≤6px, except `50%` on dots and radios;
    - `box-shadow` only on overlays;
    - reserved hues only in whitelisted selectors;
    - no `url(data:`, `@import` or `http`.
  - `git diff --check`.
- **R4:** final `code-review` (high).

### Conflict matrix (who edits what)
- **`serve.py`:**
  - Phase 1: WP2 (`_send`, `do_GET`, routes, CSP, SAFETY).
  - Phase 2: WP4 (`do_GET`/`_dispatch_get` bodies).
  - Phase 3: WP6 (score functions, exports, **routes dict**), WP7 (compare functions), WP8 (other page functions).
  - Phase 4: WP9.
- **`report.py`:** WP0, then WP5a, then WP7, then WP12 (strictly serial).
- **`webui.py`:** WP4, then WP9, then WP12.
- **`evidenceview.py`:** WP5b only (`batch.py` too, if D4).
- **Single owners:** `components.py` WP3; `design.py` WP1; `assets.py` WP2/WP9; `questions.py` WPQ; `webviews.py` WP8; `supplychain.py` WP5a; `identity.py`, `pyproject.toml`, `.gitattributes` WP2; `tools/` and `tests/e2e/` WP10; `docs/` WP11.

### Test change register (only these existing tests may change, and each must keep its property)

| Test | Owner | Property to preserve |
|---|---|---|
| `test_serve.py::test_the_page_uses_the_report_stylesheet` | WP4 | One shared result stylesheet across page and export |
| `test_serve.py::test_inline_links_meet_the_touch_target_floor_on_small_screens` | WP4 | Inline/footer links ≥24px in the small-screen query |
| `test_serve.py::test_the_policy_forbids_fetching_and_executing` | WP2 (adds an assertion only) | `default-src 'none'` stays |
| `test_cli.py::test_report_defines_both_themes` | WP5a | Light default plus an explicit dark override |
| `test_webviews.py::test_assessment_only_collapses_the_four_additional_rows` | WP5a | Main pillars visible; diagnostics collapsed |
| `test_webviews.py::test_assessment_table_displays_probabilities_as_percentages`, `_reviewed` | WP5b | Small probabilities never shown as zero; cap of 10 worst |
| `test_batch.py::test_detail_ranks_and_truncates_findings` | WP5b, only if D4=Z | Deterministic ranking, cap, truncation count |
| `test_console.py::test_verdicts_take_the_same_colours_as_the_html_report` | WPC | Key sets match; codes pinned |
| `test_serve.py::test_no_page_ever_emits_a_script` | WP9, only if D1=yes | No inline script |

Every other test must pass unchanged.

---

## 4. Spec ambiguities and conflicts

| # | Spec says | Reality | Resolution |
|---|---|---|---|
| 1 | Google Fonts | CSP, offline use, privacy, export test | Self-host (D2) |
| 2 | Popover search, drawer focus trap, toasts, loading | No JS, `<script` banned by tests | Native mechanisms (A5); optional WP9 (D1) |
| 3 | 11–12px chips, labels, axis | Commit b75c245 set a 13px floor | D3 |
| 4 | Inputs at Mono 13 / Sans 14 | iOS zooms on focus below 16px | 16px on `pointer:coarse` |
| 5 | BLOCKER tag in Mono 700 | Mono 700 is not in the loaded weights | Use 600 |
| 6 | Per-unit T/I/A/H/U/Z | Present as `[lo,hi]` ranges | Range cells in violet with `?`; Z to 3 decimals |
| 7 | "Floored" T `↑` | Not stored | Derive in presentation (1.3) |
| 8 | Weight `w .60`, neutral `50*` | Existing display renormalises (bug 1.6.1) | Use full-set exponent; fix the copy |
| 9 | Snapshot dot states | Provenance dates + `AGE_LIMITS` | Oldest KEV/EPSS date, 14 days; visible word when not current |
| 10 | LEV chip | Only with EPSS history | Omit the chip when None; existing evidence note explains |
| 11 | RESTRICTION alerts | Screening gates by label | supplychain constants |
| 12 | "no supplier restriction configured" | Screening may not be loaded | Shown only when loaded; otherwise a ContextCard |
| 13 | "Fixed in 3.1.6", "Update ≥3.1.7" | No fixed-version data | Fixed (verified, U=0) teal · Fix available amber · Mitigation only / No fix coral · Unknown violet dashed |
| 14 | Eyebrow "CONTROLLER", "Service life 15 y", "Zone: Cell/L1" | Not in data | Omit category and service life; Zone uses the `NETWORK_EXPOSURES` label |
| 15 | Advisory summary in row/drawer | Only advisory title and date | Show id, title, released |
| 16 | Not identified shows `0–100` | Computed range is e.g. ~5–76 | Show the real range; hatch over it |
| 17 | Grid `auto-fit minmax(380)` with span 2, plus "two-up ≥1100" | These contradict at 2 columns | Explicit 1fr/2fr at ≥1100; single column below |
| 18 | Blockers after score in reading order, but "above score card on narrow" | Contradictory | Full-width, directly above the grid at all widths |
| 19 | Tabs | No JS, plus printing | Section-anchor nav, not `role=tablist` |
| 20 | Default sort is Z, but Z is not a column | — | Add a Z column |
| 21 | "Unpatched", "Network" filters undefined | — | Unpatched = no vendor fix; Network = AV:N/A |
| 22 | EPSS `.04` | Current `%` and "Under 0.1%" logic | `.04`, with `<.01` / `>.99`; the LEV page keeps prose percentages |
| 23 | Gap card always paired with a field | P/V/C have no form field | Card without a field, linking to `/vendor` |
| 24 | Firmware "unverified until confirmed" | No confirm step | A submitted version counts as confirmed unless its ranges are undecided |
| 25 | Light variant lists 6 tokens | Others undefined | Proposed values (WP1), checked by the contrast test |
| 26 | Expanded row and drawer carry the same content | Duplicate markup | Web: drawer only. Export: static detail rows |
| 27 | Comparison "first column sticky (product name)" plus "one column per candidate" | Contradictory | Sticky metric-label column; products are the header row |
| 28 | Drag reorder | Table is ranked by `VERDICT_RANK` by design | No reorder (D6) |
| 29 | Cautions (bundled KEV) | No matching spec component | Amber REVIEW alert, not `role=alert` |
| 30 | One primary per view | "Update assessment" is also a submit | Secondary on the result page |
| 31 | Export source links | Export test bans `https://` | Links on the web only; IDs in the export |

### Decisions that need the user (short list)
- **D1, needs an answer. JavaScript.**
  - Recommended: ship the no-JS baseline now and defer WP9.
  - Cost of no-JS: no live search popover, no toasts, no loading state, no clipboard copy, and no strict focus trap unless invoker commands pass on all engines.
  - Cost of approving WP9: `script-src 'self'`, and the About-page/CSP promise changes.
- **D2, recommended, confirm. Fonts:** self-host Plex rather than use Google Fonts; the export uses `local()` with system fallback.
- **D3, needs an answer. Minimum type size.**
  - Recommended: follow the spec but use 12px as the absolute minimum (spec 11px → 12px).
  - Alternative: keep the 13px floor from b75c245 and scale the spec's small sizes up.
- **D4, needs an answer. Evidence ranking and JSON order.**
  - Recommended: Z-desc ranking in both the HTML and `batch.to_detail` `findings`, so "the JSON export carries the same selection" stays true.
  - Alternative: keep EPSS order for the selection and the JSON.
- **D5, recommended, confirm. Navigation.**
  - 4 items: Assess, Compare, Search, Methodology.
  - Vendor, Timeline, Alternatives, SSVC, LEV and Demo become contextual "Related evidence" links, plus the Methodology index and the footer.
  - Active mapping: product pages → Assess; vendor/timeline → Search.
- **D6, recommended, confirm. Shortlist:** URL-only, no persistence, no nav count chip, no reorder.
- **FYI:** fixing bug 1.6.1 (weight display and copy) is included unless the user objects.

---

## 5. Verification plan
1. **Suite:** `python -m pytest -q` must be green at every merge (1,102 plus new tests), plus `git diff --check` (CI also runs `git show --check`).
   - Python 3.10 rule: no reuse of the enclosing quote inside f-string expressions, no backslashes in f-string expressions.
2. **New markup a11y lint, no browser** (`tests/test_a11y_markup.py`, WP12). Render every route plus the export and parse them with `html.parser`, checking:
   - ids are unique;
   - every `input`, `select` and `textarea` has a `label for` or an `aria-label`;
   - every `a` and `button` has text or an `aria-label`;
   - every `th` has `scope`;
   - at most one valid `aria-sort` per table;
   - blockers and errors carry `role=alert`;
   - every `popovertarget` exists;
   - no nested interactive elements, no inline `on*=` handlers;
   - a single `h1`.
3. **Contrast:** `tests/test_design.py` checks WCAG ratios for DARK, LIGHT and the tinted composites.
4. **Run the app:**
   - Local: `python -m retrust.cli serve --port 8765`.
   - Hosted mode: set `RETRUST_HOSTED=1` first.
5. **Screenshots:** `python tools/capture_screenshots.py --set review --out <scratch>`.
   - Widths: 375, 640, 1024, 1100, 1440.
   - Modes:
     - default;
     - `reduced-motion` (`emulate_media`);
     - grayscale (`add_style_tag("html{filter:grayscale(1)}")`, allowed by the CSP);
     - print (`emulate_media(media="print")`);
     - coarse (context `has_touch/is_mobile`).
   - Pages:
     - `/` and `/?q=S7-1500`;
     - `/score` empty;
     - VERIFY (ABB AC 800M);
     - AVOID + KEV (Siemens SIMATIC S7-1500 fw 3.1.6, 1,227 CVEs, also the performance case);
     - AVOID restriction with no score (Hikvision IP Camera);
     - an answered result: `/score?vendor=Siemens&product=SIMATIC+IPC477E+Pro&network_exposure=ot_only&interface=blocked&prerequisites=satisfiable&consequence=control&remediation=affected`, answers from `examples\approved-bom.csv`;
     - not identified (`vendor=Nobody&product=Nothing+123`);
     - cleared firmware;
     - `/compare` (the manual's example);
     - `/about`, `/annex?vendor=Moxa&product=EDS-405A`, `/vendor?name=Siemens`, timeline, lev, ssvc, alternatives, 404.
   - Export: `python -m retrust.cli score --vendor Siemens --product "SIMATIC S7-1500" --version 3.1.6 --html <scratch>\s7.html`, then `python -m retrust.cli screenshot <scratch>\s7.html --both-themes --out-dir <scratch>`.
   - Published shot: `make screenshots`.
6. **Spec 5.4 checks in e2e** (Playwright on Chromium, Firefox and WebKit; context `bypass_csp=True` for evaluation):
   - a visible focus ring (computed outline) while tabbing the header;
   - Esc closes the export menu and the drawer, and focus returns to the invoker;
   - `aria-sort` follows sort navigation;
   - the reduced-motion computed `transition-duration` is 0s;
   - primary controls are ≥44px under coarse pointer;
   - no page-level horizontal scroll at any width (`scrollWidth <= clientWidth`); tables scroll inside `.tw`;
   - a 640px viewport (equivalent to 200% zoom of 1280) loses no content;
   - no CSP violation messages in the console.
   - Optional: `axe-playwright-python` as a docs-only extra.
7. **Grayscale:** in the review grayscale set, every verdict, status, chip, gap and the snapshot state must read by glyph and word.
8. **Print and export:** export is light by default with no controls; the web result printed under print media uses light tokens with chrome hidden; check a grayscale export shot.
9. **Packaging:** the wheel build from WP2 contains `retrust/static/fonts/*.woff2`.
10. **Performance:** the S7-1500 3.1.6 result page stays under an agreed size (suggest <400 KB), and the number of drawers equals the number of shown rows.
11. **No scoring change:** `git diff main -- retrust/score.py retrust/exposure.py retrust/match.py` is empty. Optional: `make formula-check`, and `PYTHON=python bash smoke.sh`.

---

## 6. Risks and sub-agent breakdown

### Risks
- **`serve.py` contention in Phase 3.** Mitigated by function-level ownership, one owner for the routes dict (WP6), and rebase-then-merge in a fixed order.
- **Tests weakened to make them pass.** Only the register above may change; each change must cite the property it keeps; a reviewer diffs `tests/`.
- **CSP regressions.** `data:` URLs in CSS, external fonts and inline handlers will fail silently in the browser. The CSS lint and the e2e console check catch these.
- **Fonts missing from the Render wheel.** The fallback would hide the problem silently. Covered by the package-data test and the wheel check.
- **Large pages** (1,227 CVEs). Server-side cap; drawers only for shown rows.
- **Browser support** for popover anchoring, invoker commands and `:has`. Choose per e2e results; fallbacks are specified.
- **Copy that misstates the model.** Every new sentence must match RT8 behaviour (the old "weights adjusted" copy is a live example) and spec 5.3 (no "secure/safe", never a probability). Opus review of WP5a, WP5b and WP8 copy.
- **BUILD fingerprint changes.** `/formula-check.json` will read `current:false` and `make live` will differ until the next Render build. Expected; mention in the PR.
- **Python 3.10 syntax and CRLF/trailing whitespace.** CI matrix plus `--check`.
- **Visual defects that unit tests cannot see.** R2, R3 and R4 screenshot reviews.

### Sub-agent breakdown (Sonnet 5.5 implementers; Opus lead for WP0, merges and reviews)

| Agent | Work packages | Notes |
|---|---|---|
| S1 | WP1 | Mechanical and test-driven |
| S2 | WP2 | Needs network access and a binary commit; R1 checks the licence and the hashes |
| S3 | WP3 | Give it the exact signatures from WP0 |
| S4 | WPQ (+ WPC) | Tiny |
| S5 | WP4 | Must preserve the hosted/local strings and use no `role=alert` in the shell |
| S6 | WP5a | Highest copy and semantic risk; Opus review required |
| S7 | WP5b | Ranking and exposure maths must equal `exposure.*` output |
| S8 | WP10a/b | Tools and e2e only |
| S9 | WP6 | Security review required |
| S10 | WP7 | |
| S11 | WP8 | |
| S12 | WP9 | Only if D1 is approved |
| S13 | WP11 + WP12 | |

### What every implementer brief must contain
1. The spec sections for the package, plus §2 (A1–A8) and the WP0 contracts: token and class names, the `WebView`/`EvidenceView` fields, and the CSS assembly order.
2. The exact file allow-list and test allow-list, taken from the conflict matrix and the test register.
3. The constraint checklist:
   - No JS (unless WP9).
   - No external URLs or assets.
   - No `url(data:)` in CSS; inline SVG and style attributes are fine.
   - Escape everything through `components.esc`.
   - Plain-string CSS, never f-strings.
   - Python 3.10 syntax.
   - Flat modules.
   - No scoring changes.
   - Keep the legacy hook classes and the tested strings and markup fragments (listed per package above).
   - One primary per view.
   - Never colour alone.
   - LF endings, no trailing whitespace.
4. The commands:
   - `python -m pytest -q` and the package's targeted test files;
   - `git diff --check`;
   - running the server (`python -m retrust.cli serve --port 8765`);
   - capturing screenshots (`python tools/capture_screenshots.py --set review --out <scratch>`).
5. The definition of done:
   - the acceptance criteria are met;
   - new tests are added;
   - the suite is green;
   - UI packages attach desktop and mobile screenshots (CONTRIBUTING/PR template);
   - a summary of every test change with its justification;
   - no edits outside the allow-list.

**Review passes:**
- **R1 (after Phase 1):** contrast, CSP and packaging.
- **R2 (after Phase 2 integration):** visual and a11y on the result page and the export.
- **R3 (after Phase 3):** `security-review` on serve.py params, routes and escaping; one-primary rule; copy voice.
- **R4 (final):** `code-review` at high effort.

### Critical files for implementation
- D:\karthik\retrust\retrust\serve.py
- D:\karthik\retrust\retrust\report.py
- D:\karthik\retrust\retrust\webui.py
- D:\karthik\retrust\tests\test_serve.py
- D:\karthik\retrust\Design-spec-document.md

New modules: D:\karthik\retrust\retrust\design.py, D:\karthik\retrust\retrust\components.py, D:\karthik\retrust\retrust\evidenceview.py, D:\karthik\retrust\retrust\assets.py.

---

## 7. Decisions (confirmed by the user)

- **D1 JavaScript: ADD IT (WP9 is in scope)** unless a genuine blocker appears. Constraints: one same-origin external script `/static/retrust.js`, CSP `script-src 'self'; connect-src 'self'`, no inline scripts, no `on*=` handlers, no external URLs, and every page must still work with JS disabled (the no-JS baseline in A5 stays). Update `test_no_page_ever_emits_a_script`, the SAFETY copy and the About copy accordingly. If an implementer finds a real blocker, stop and report it instead of working around it.
- **D2 Fonts:** self-host IBM Plex (as in A4). Export uses `local()` + system fallback.
- **D3 Type floor:** 12px absolute minimum (spec 11px sizes become 12px).
- **D4 Ranking:** keep the application's existing evidence selection and ordering (top 10 by EPSS, as today). Do NOT change `batch.to_detail` or `tests/test_batch.py`. Z is shown as a sortable column; an explicit `sort=` applies to the full in-scope list before the cap, while the default (no `sort`) keeps today's selection and order. Spec 4.14 "default sort is Z" is overridden by this decision.
- **D5 Nav:** 4 items (Assess, Compare, Search, Methodology); other pages are contextual "Related evidence" links.
- **D6 Shortlist:** URL-only, no persistence, no count chip, no drag reorder. (With WP9 the "mark as sent" checkbox may use sessionStorage.)
- **FYI:** fix the pillar-weight display/copy inconsistency (1.6 item 1) as planned.
