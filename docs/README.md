# ReTrust documentation

Start with the [project quick start](../README.md#quick-start). For contributing
code, use [CONTRIBUTING.md](../CONTRIBUTING.md); to report a vulnerability, use
[SECURITY.md](../SECURITY.md).

## Use ReTrust

- [User guide](user-guide.html) — browser and terminal workflows; open in a browser.
- [Commands and workflows](commands.md) — installation, CLI reference and exports.
- [Demo runbook](demo-runbook.md) — a presentation walkthrough.
- [Example inputs](../examples/) — candidate lists and bill-of-materials files.

## Understand an assessment

- [Scoring methodology](explainers/scoring.html) — current formula, worked examples and decision rules.
- [Technical manual](manual.md) — matching, evidence handling, architecture and security details.
- [Overview explainer](explainers/overview.html) — what the tool does and why.
- [Command explainer](explainers/commands.html) — commands grouped by task.
- [Scoring PDF](ReTrust-Scoring-Explained.pdf) — printable scoring reference.

The manual and scoring methodology describe current behavior. Printable PDFs
are retained generated documents; check their model/date before quoting a
worked result. Rebuild them with `make guide` after changing their sources.

## Evaluate the evidence

- [Benchmark report](benchmark-report.md) — methods, dates and limitations.
- [Retained measurements](benchmarks/) — raw evaluation, backtest and latency data.
- [Tool comparison](tool-comparison.md) — scope alongside other security tools.
- [PDF overview](ReTrust-Guide.pdf) — printable overview and retained measurements.

Historical benchmark results do not establish current predictive accuracy.
The deployed `/formula-check.json` checks arithmetic consistency against its
loaded data; it does not validate the model's ability to predict compromise.

## Deploy and present

- [Render deployment](render-deployment.md) — build, runtime, concurrency and release verification.
- [Presentation submission](arsenal-submission.md) — project description and demo material.

## Interface design

- [Design language](design/design-language.md) — principles, tokens, components and page rules of the Control Room interface.
- [Implementation plan](design/implementation-plan.md) — architecture decisions, work packages and the record of what was built.
- [Verification report](design/verification-report.md) — cross-browser, accessibility and print matrix results.

## Documentation sources

`tools/build_overview.py` and `tools/build_scoring_sheet.py` generate the PDFs.
`assets/` contains committed documentation images. `benchmarks/` contains
retained measurements. Generated screenshots, local audit reports and private
assessment exports stay outside the tracked files.
