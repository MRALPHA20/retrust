# Web review — 29 September 2026

> Historical record. Scores and checks describe the dated review, not the
> current release. See the [documentation index](../README.md) for current guides.

## Result

Restored the stopped local web server and checked the current interface against the installed dataset. Fixed silent empty submissions on assessment and comparison forms. Firmware-only comparison rows now ask for a product identity before assessment. Entered firmware is retained, whitespace-only identity fields are treated as empty, and validation messages expose an alert role.

- Complete regression suite: **787 passed in 6.39 seconds**.
- Focused web suite: **58 passed**.
- Live HTTP checks: **19 passed**, including HTML and JSON exports, missing-page handling, search, scoring, comparison, vendor profile, timeline, alternatives, supplier questions, SSVC, LEV, methodology and demo.
- `git diff --check`: passed.

## Reviewed flow

### 1. Homepage — healthy after restarting the server

The page initially could not connect because the server had stopped. After restarting, the homepage loaded with current corpus totals, a labeled search field, examples and clear navigation. Navigation labels have no decorative number prefixes.

Homepage (local evidence: `reports/web-check-2026-09-29/01-home.png`)

### 2. Product search — healthy within the current result limit

S7-1500 returns advisory products with vendor, model and order-number context. Long names wrap within the page. The screen displays the first 25 results; narrower terms or an order number help refine larger searches. A no-match query was also checked at the HTTP layer.

Search (local evidence: `reports/web-check-2026-09-29/02-search.png`)

### 3. Assessment and exports — healthy

Submitted order number `6ES7518-4AX00-1AB0` and firmware `3.1.6` through the form using keyboard controls. The response shows 40.2, AVOID, 477 distinct CVEs, and a hard gate listing four KEV CVEs. Both export endpoints return downloadable content; JSON parses and the HTML contains the matching score.

The long product title wraps cleanly. Labels, verdict and gate text convey meaning without relying on color alone. Dense evidence tables still require careful reading.

Assessment (local evidence: `reports/web-check-2026-09-29/03-assessment.png`)

### 4. Candidate comparison — healthy

Submitted ABB AC 800M and Moxa EDS-405A through the structured form. The summary shows 82.2/PREFER/93% robustness and 56.1/CONDITIONAL/77%. The explanatory text distinguishes verdict robustness from ranking stability. Repeated the flow after the validation change and captured the accepted result.

Comparison (local evidence: `reports/web-check-2026-09-29/04-comparison.png`)

### 5. Validation and recovery — fixed

Previously, blank submissions silently redisplayed a form. A comparison containing firmware without a vendor or product also proceeded without a useful identity. The forms now explain what to enter and retain firmware for correction. New regression cases cover blank input, whitespace-only input, firmware-only input, preservation of entered firmware and clean initial forms.

Validation (local evidence: `reports/web-check-2026-09-29/05-validation.png`)

### 6. Mobile layout and keyboard navigation — healthy in the tested view

Requested a 390 × 844 viewport. The expanded mobile menu is keyboard operable and displays a visible focus outline. The form and warning wrap without horizontal page overflow (reported scroll width 375px, viewport width 390px). Restored the normal viewport afterward.

Mobile form and menu (local evidence: `reports/web-check-2026-09-29/06-mobile.png`)

## Evidence and limits

All accepted screenshots were captured in this review and inspected after saving. One comparison capture showed a different page and was rejected and replaced. Pointer automation produced inconsistent navigation in the in-app browser, so form and menu interaction checks used keyboard activation; pointer behavior is not fully validated by this pass.

The six pictured states were visually reviewed. Other routes were checked through live HTTP responses and automated regression tests, not exhaustively through every visual state. No formal screen-reader, contrast-compliance, cross-browser or load test was performed. Data sources were not refreshed. The local service runs in a terminal session; it is not installed as an operating-system service.

Evidence: HTTP results (local evidence: `reports/web-check-2026-09-29/http-checks.json`), test log (local evidence: `reports/web-check-2026-09-29/tests.txt`), and screenshots in `reports/web-check-2026-09-29/`.
