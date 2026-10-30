# Changelog

Notable changes to the ReTrust software are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Scoring-model
versions (RT6, RT8 and so on) are described in the
[scoring methodology](docs/explainers/scoring.html); this file records the
software, not the model.

## [Unreleased]

### Added

- "Control Room" browser interface: a dark, dense operator-console layout with
  four navigation places (Assess, Compare, Search, Methodology), verdict-first
  result pages, exposure and evidence views, a comparison table and a
  self-contained light stylesheet for exported reports.
- Self-hosted IBM Plex fonts served from `/static/fonts/`, with pinned hashes
  and licence.
- One same-origin enhancement script (`/static/retrust.js`) for search
  suggestions, focus handling, toasts, copy buttons and the `Ctrl K` / `⌘K`
  search shortcut. Every page works with it disabled.
- Gap tags on supplier questions and a distinct VERIFY colour in the terminal.
- Global CSS lint, markup accessibility checks and cross-browser end-to-end
  tests on Chromium, Firefox and WebKit, including print and no-JavaScript
  flows.
- `SECURITY.md`, `CODE_OF_CONDUCT.md` and this changelog.

### Changed

- The content security policy now allows `script-src 'self'` and
  `connect-src 'self'` for the single enhancement script. Inline scripts and
  event-handler attributes remain forbidden and are tested for.
- Design documents live in `docs/design/`; the real-data smoke script lives in
  `scripts/smoke.sh`.
- Documentation, screenshots and PDF guides regenerated for the new interface.

### Removed

- Pre-redesign stylesheet aliases, the legacy findings and summary tables in
  the export renderer and the compatibility shims used during the redesign.

Earlier history is recorded in the Git log.
