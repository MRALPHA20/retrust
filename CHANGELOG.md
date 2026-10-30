# Changelog

Notable changes to the ReTrust software are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Scoring-model versions (RT6, RT8 and so on) are versioned separately and
described in the [scoring methodology](docs/explainers/scoring.html). A score
carries its model version, so results stay comparable across software releases.
This file records the software.

## [Unreleased]

### Added

- An issue-template config so GitHub offers private vulnerability reporting
  before a blank issue, as `SECURITY.md` asks, plus a link to the
  documentation index.

### Changed

- Package metadata names the authors as the LICENSE copyright line does,
  rather than publishing contributors' personal addresses, and declares the
  Python versions, environments and audiences the project supports.

## [0.1.0] - 2026-10-30

First tagged release. The software is feature-complete for procurement review
and is not yet published; the repository remains private pending the owner's
decision. Version 0 signals that the command-line surface, the HTTP routes and
the export schemas may still change without a major-version bump.

### Added

- Product assessment from public advisory evidence, resolving a candidate by
  manufacturer order number or vendor and model, narrowing scope by firmware,
  and producing a verdict with the inputs and gaps behind it.
- The RT8 scoring model: concentrated exposure over the top three review units,
  combined with patch capability, vendor practice and certification evidence.
  Mandatory blockers override the numeric band and unresolved material evidence
  produces VERIFY rather than a lower score.
- Three interfaces over one scoring engine: a read-only local web workspace, a
  command line, and an interactive terminal menu.
- Evidence exports in HTML, JSON, CSV and VEX, plus generated supplier
  questions and a reproducible assessment vector recording the scoring version,
  declared context and data snapshot.
- Shortlist comparison, alternatives, advisory timeline, vendor profile,
  response priority and exploitation-estimate views.
- Data acquisition from CISA OT CSAF advisories, KEV and EPSS, with digest and
  signature verification as a separate explicit step that reports origin and
  content independently.
- An independent all-product formula validator that Render runs on every build
  against freshly fetched data, refusing the deployment if any product fails.
- Reproducible evaluation and backtest commands, with retained measurements and
  their limits in the benchmark report.
- `SECURITY.md` with the private reporting channel, scope and the server's
  design assumptions. `CODE_OF_CONDUCT.md` and this changelog.

### Security

- The server answers GET and HEAD only, reads no request body, writes nothing,
  runs no subprocess and never uses a request path as a filename. Every value
  reaching a page is HTML-escaped.
- Pages carry no JavaScript and load nothing from any origin, under a
  `default-src 'none'` content security policy, with no caching and no framing.
- On a loopback bind the `Host` header must name the machine, which refuses
  DNS-rebinding attempts to read the local index.
- Regression tests cover injection, server-side request forgery and
  decompression-bomb inputs.

### Notes on the history

A "Control Room" interface redesign was built on a branch, merged and then
reverted before this release. The commits remain in the history, so a reader
browsing the log will find an interface that is deliberately not in the tree.
The shipped interface is the one documented here and shown in the README.

Earlier development history predates this changelog and is recorded in the Git
log.

[Unreleased]: https://github.com/MRALPHA20/retrust/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/MRALPHA20/retrust/releases/tag/v0.1.0
