# Terminal polish and verification — 28 September 2026

ReTrust now has named interactive commands, cyan headings, semantic verdict
colors, aligned pillar bars, and wrapped assessment evidence. Numeric menu
inputs remain compatible. Terminal background and fonts remain controlled by
the user's terminal settings.

## Verification results

- Full automated suite: **775 passed in 9.06s**.
- Real-index smoke suite: **89 passed, 0 failed**.
- `doctor`: all installation checks passed.
- Fatal Python lint checks (`E9,F63,F7,F82`) and `git diff --check`: passed.
- A broader Ruff run reports existing style conventions, including import
  ordering and intentionally broad exceptions at command boundaries. This was
  not a repository-wide formatting pass.

The smoke suite exercises overview, menu actions, search, vendor dossiers,
order-number and product scoring, comparison, batch/SBOM input, LEV, SSVC,
alternatives, saved-result diff, JSON output, evaluation, sensitivity,
backtesting, configuration, shell completion, advisory integrity, supplier
questions, timelines, VEX, CVE lookup, and error exit codes against the local
corpus. The automated suite also covers the HTTP routes and exports.

Logs: [tests](../reports/qa/tests.txt), [smoke checks](../reports/qa/smoke.txt).

## Visual and interaction review

### 1. Terminal — passed

Exercised a real PTY session: named `score`, prompts, result, `save`, JSON file,
and `quit`. Captured ANSI output and rendered it with a monospace font for
inspection. These images show actual command output on a dark preview
background, not a native terminal-window screenshot. Verified no-color output
and 52-column wrapping through automated tests.

![Terminal menu](../reports/qa/terminal-menu.png)
![Assessment output](../reports/qa/terminal-score.png)

### 2. Assessment form and result — passed

Submitted order number `6ES7518-4AX00-1AB0`, firmware `3.1.6`, through the browser.
The labels, input layout, action and result were visible and keyboard operable.
The corrected result reports four distinct KEV CVEs, matching the four listed
identifiers. It remains AVOID; deduplicating exploitation counts changes its
composite score from 39.3 to 40.2. Hard gates override the numeric band.

![Assessment form](../reports/qa/01-assessment-form.png)
![Corrected assessment](../reports/qa/02-assessment-result.png)

### 3. Comparison — passed

Submitted ABB AC 800M and Moxa EDS-405A through the structured form. The ranked
summary is readable above the detailed evidence. Fixed the previously empty
robustness column: the web now runs 300 seeded weight samples, showing 93% and
77% for these candidates. Clarified that robustness measures each product's
most common verdict, not the stability of the overall ranking.

![Comparison](../reports/qa/03-comparison.png)

### 4. Mobile assessment and navigation — passed for the tested viewport

Checked at a requested 390 × 844 viewport. An initial browser capture problem
was resolved by using a fresh in-app tab and a full-page capture. Rejected
captures are not used as evidence here.

Fixed excessively tall table rows caused by narrow evidence columns. Tables
now preserve a readable minimum width inside scrollable regions with a visible
hint. The page width and scroll width are both 390px; overflow is confined to
the tables. Confirmed keyboard focus and ArrowRight scrolling on a named table
region. The mobile navigation opens with Enter. Restored the normal viewport
after testing.

![Mobile assessment](../reports/qa/04-mobile-assessment.png)

## Functional fixes from this pass

- Count repeated exploitation CVEs once across advisories, including hard gates.
- Label advisory-level proportions as findings and explain their relationship
  to distinct CVEs.
- Avoid claiming firmware was omitted merely because all ranges were undecided.
- Preserve the assessment query in interactive JSON saves for later `diff`.
- Keep the interactive session alive after invalid file input and handle
  Ctrl-C at the main menu cleanly.
- Reject malformed JSON candidate-list shapes with an actionable error.
- Add an interactive `order` assessment command and order-number discovery.
- Write requested HTML even for a NOT ASSESSED result.
- Preserve full candidate names and gate explanations in terminal comparisons.

## Limits

This pass validates the installed local dataset. It did not refresh every live
upstream feed, reinstall from scratch on other operating systems, or conduct a
formal screen-reader or WCAG audit. Native terminal-window automation is not
available, so visual terminal inspection used the recorded output rendering.
Screenshots and passing tests do not prove that every possible input is correct.

## Documentation and benchmark snapshot

The [PDF overview](ReTrust-Guide.pdf), [benchmark report](benchmark-report.md) and
[tool comparison](tool-comparison.md) were refreshed on 28 September 2026.
Benchmark JSON/text is retained in `docs/benchmarks/`. The nine-page PDF was
rendered and every page inspected for layout, readability and overflow.
