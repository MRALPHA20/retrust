# Contributing to ReTrust

## Development setup

Requires Git and Python 3.10+. Run commands from the repository root.

```bash
git clone https://github.com/MRALPHA20/retrust.git
cd retrust
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e '.[dev]'
python3 -m pytest -q
```

Most tests use temporary fixtures. Checks that require a local advisory index
skip when it is absent. Installing the application does not fetch live sources.

For real-data work, run `python3 -m retrust.cli setup`, then start the browser
with `python3 -m retrust.cli serve`. Setup requires network access. Later
assessments use the downloaded snapshot.

## Where changes belong

| Location | Responsibility |
| --- | --- |
| `retrust/match.py`, `identity.py`, `version.py` | Product resolution and firmware scope |
| `retrust/exposure.py`, `score.py` | Exposure factors, scoring and decision policy |
| `retrust/cli.py`, `shell.py`, `console.py` | Command and terminal interfaces |
| `retrust/serve.py`, `webui.py`, `webviews.py` | HTTP routes, browser layout and result views |
| `retrust/enhance.py`, `retrust/static/` | The one same-origin script and the bundled fonts; pages must keep working without the script |
| `retrust/bootstrap.py`, `csaf.py`, `index.py` | Public source fetching, parsing and indexing |
| `retrust/formula_check.py` | Independent all-product formula validation |
| `tests/test_*.py` | Automated regression cases |
| `docs/` | Current guides, design documents and retained benchmark evidence |
| `examples/` | Small sample inputs without confidential information |
| `scripts/` | Deployment build and real-data smoke checks |
| `tools/` | Documentation generation and benchmark utilities |

Pages must work with JavaScript off, load nothing from another origin and add
no inline scripts or event-handler attributes; the Content Security Policy
enforces this and `tests/test_enhance.py` checks it. After a UI change, run
`make guide` to regenerate `docs/assets/workspace-comparison.png` and the PDF
guides (needs `.[docs]` and `python3 -m playwright install chromium`). Keep
the review screenshots (`make screenshots-review`) out of the repository.

Keep the existing Python package layout. Avoid moving application modules just
to group them visually: imports, CLI entry points and deployment fingerprints
rely on it. Keep runtime dependencies in the standard library unless a change
has an explicit reason to introduce one.

## Checks

```bash
make test                   # Automated suite; does not fetch live sources.
git diff --check            # Whitespace and patch checks.
make smoke                  # Real-data CLI checks; requires setup first.
make formula-check          # Every indexed product; requires setup first.
```

The smoke script (`scripts/smoke.sh`) performs broad CLI work and writes local
reports. Some checks
reflect its retained corpus and require review when source data changes.
The all-product validator can take several minutes. Its output is ignored by
Git; Render runs this validator against newly fetched data during every build.

For an interface change, follow the
[design language](docs/design/design-language.md) and check the relevant
interaction and desktop/mobile layout. For a scoring change, cover the numeric result, unknown inputs,
firmware applicability and any gate that can override the score. Update the
current methodology when behavior changes. A passing formula check establishes
arithmetic consistency, not predictive accuracy.

## Security issues

Do not report vulnerabilities in public issues or pull requests. Use the
private channel described in [SECURITY.md](SECURITY.md).

## Working with GitHub

1. Update `main` with `git pull --ff-only` before starting.
2. Create a branch such as `fix/assessment-inputs` or `docs/quick-start`.
3. Keep the change focused and run the relevant checks.
4. Open a pull request against `main`; explain the problem, change and checks.

GitHub Actions runs the automated suite on Python 3.10 and 3.13 for pushes and
pull requests to `main`. It uses fixtures instead of downloading live sources.
Data-dependent checks still need local or Render build verification.

## Local files and privacy

Do not commit credentials, `.env` files, personal configuration, downloaded
source feeds, SQLite databases, private procurement inputs, chat transcripts or
user exports. Existing ignore rules cover generated data, caches and reports.
Ignored local files are not deleted as part of repository housekeeping.

Retained public measurements in `docs/benchmarks/` and published documentation
PDFs are intentional tracked artifacts. Keep their dates and limitations.

## Deployment

See [Render deployment](docs/render-deployment.md). `make deploy` tests and
pushes both `main` and the existing Render tracking branch; use it only when
publishing a release. `make live` compares the deployed source fingerprint with
the local one. Pushing a commit alone does not establish that a deployment is
healthy or serving that commit.

## Documentation generation

Install `python3 -m pip install -e '.[docs]'`, then run `make guide`. PDF builder
sources are under `tools/`; retained measurements are under `docs/benchmarks/`.
Inspect regenerated documents before committing them.
