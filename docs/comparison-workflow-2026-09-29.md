# Comparison workflow update — 29 September 2026

A record of one change, kept as it was written. The behaviour below still holds;
the numbers do not. Scores move with the scoring version, the weights and the
loaded snapshot, so treat every figure here as evidence that the export path
worked on the day and re-run the commands for current ones.

## What changed

- Browser comparison accepts manufacturer order numbers and optional firmware.
- Exact order-number searches and the assessment-to-comparison link retain the identifier.
- HTML, JSON and CSV exports retain the complete ranked shortlist and original inputs.
- HTML and JSON include source provenance and configured weights. JSON also retains bands and robustness details.
- Candidates with the same display name retain their own robustness result.
- The form uses two columns on desktop and one on mobile. The results table scrolls within its own region on narrow screens.

Downloads use the current local index. Save the file to retain that decision
record; opening the comparison URL later may produce different results after
an index update. JSON exports retain queries for subsequent `retrust diff`
use. CSV cells are protected against spreadsheet formula interpretation.

## Verification, as recorded on 29 September 2026

- Full suite: **796 passed in 6.58 seconds**.
- Live localhost HTML, JSON and CSV responses matched the web comparison and retained original queries, attachment names and `no-store` headers.
- Example, measured that day: ABB AC 800M scored 82.2 with 93% weight robustness. Siemens order number 6ES7518-4AX00-1AB0, firmware 3.1.6, scored 40.2 with an AVOID gate and 477 CVEs in scope. These were local snapshot results, not independent accuracy measurements.
- Regression coverage includes duplicate display names, escaped HTML inputs, spreadsheet formula protection, malformed exports, the 12-candidate limit and order-number handoff.
- Visually checked desktop and 390-by-844 mobile layouts. Inputs and download buttons fit; neither layout overflowed the document horizontally.
- Browser download automation stalled. The generated files and HTTP download responses were verified directly; the browser save flow remains unverified.

Local evidence is under `reports/comparison-upgrade/`: screenshots, example
exports, `export-checks.json` and `tests.txt`.

**Those example figures no longer reproduce.** Under RT4 on the 20 October 2026
snapshot, `retrust compare --candidate "ABB|AC 800M"` reads `VERIFY ·
68.0–87.7/100 (provisional range)` with `ROBUST not sampled`, and the Siemens
order number at firmware 3.1.6 reads `VERIFY · 79.4–82.6/100 (provisional
range)` — still 477 CVEs in scope, but a `CAUTION: KEV-listed CVE(s) in
third-party component bundles` rather than a hard gate, because gates run on
first-party findings only and every KEV-listed CVE left in scope here arrives
via a component bundle advisory. A single number with a robustness percentage is
also no longer the normal output: with no deployment context declared the result
is a range, and weight robustness is not sampled for a range. Nothing in *What
changed* above depends on these values; re-run the commands rather than quoting
them.

## Recommended next work

1. Build an independently labelled product and firmware benchmark that counts extra incorrect advisory matches as well as missed matches.
2. Make stale or incomplete source coverage clearer at the point of assessment.
3. Add search pagination and vendor filters for large result sets.

These remain priorities, not completed features. The current change focuses
on carrying a shortlist from identification through a retained decision record.
