# Deploy ReTrust on Render

The repository includes a `render.yaml` Blueprint for a free Python web service
in Singapore. The repository can stay private. Render needs permission to read
it; the deployed application is reachable at its assigned HTTPS URL.

## Create the service

1. Sign in to Render and choose **New > Blueprint**.
2. Select the ReTrust repository and the branch containing `render.yaml`.
3. Review the free service and deploy it.
4. Wait for the build and `/healthz` check to pass, then open the service URL.

For a manually configured web service, use:

| Setting | Value |
| --- | --- |
| Runtime | Python 3.13 |
| Build command | `bash scripts/render-build.sh` |
| Start command | `python -u -m retrust.cli serve --host 0.0.0.0 --port "$PORT"` |
| Health check | `/healthz` |
| Instance | Free |
| Environment | `RETRUST_HOSTED=1`, `RETRUST_BUILD_LEV_HISTORY=1`, `PYTHONUNBUFFERED=1` |

## Data and updates

The build downloads public advisory and supporting sources, builds SQLite,
and loads historical EPSS for the exploitation-estimate page. Initial builds
can take several minutes. Set `RETRUST_BUILD_LEV_HISTORY=0` to skip the history;
that page will then explain that its required data is missing.

Data is part of the deployment artifact. Runtime requests read it and generate
downloads in memory, so a restart requires no persistent disk. **Which branch Render tracks is the thing to get right.** This service was
originally created against another branch, not `main`, and a Blueprint deploys
the branch it was created from. Pushing to `main` therefore changed nothing
live, and pressing **Manual Deploy** twice simply rebuilt the same old commit
with fresh data -- the index hash moved while the code did not. That is fixed:
on 2026-10-30 a push of `main` alone rebuilt the service and the live
`X-ReTrust-Build` header moved to `main`'s fingerprint, so one push is enough.

```bash
make deploy      # runs the tests, then pushes main
make live        # prints the live build string against the local one
```

`make live` reads the `X-ReTrust-Build` header off `/healthz` and prints
`serve.BUILD` beside it; equal means the deployed code is exactly what you have.
It compares the source of the deployed code rather than the data *or* the
scoring version, which is the check that actually catches this — `Makefile:86-88`
records why: both the index counts and the scoring-version string stayed
identical across builds three commits apart, so neither could detect a stale
deploy. `render.yaml` declares `branch: main`, so the intent is config-as-code rather
than a dashboard setting somebody has to remember. A Blueprint property change
is only picked up when Render re-reads the file, and the dashboard value wins
over the YAML if the two ever disagree, so the setting is worth a glance under
**Settings > Build & Deploy > Branch**. It reads `main`: on 2026-10-30 a push
of `main` alone rebuilt the service and the live build header moved to that
commit's fingerprint. `make deploy` is therefore a single push, and the old
deploy branch has been retired. To check what is actually live rather than what
you pushed, compare a string you changed, not the data counts:

```bash
curl -s https://<your-app>.onrender.com/score?vendor=ABB\&product=AC%20800M | grep -c "a phrase you just changed"
```

Each new build
refreshes the main sources. Automatic deployment is enabled
(`autoDeployTrigger: commit`), so every push to the tracked branch rebuilds and
redeploys; **Manual Deploy > Deploy latest commit** still forces one on demand.

Because the build runs `setup --force` and `lev --update`, it refetches the
whole advisory corpus and 68 EPSS snapshots — tens of minutes on the free plan,
and a slow deploy is expected rather than a hang. It also means the live index
is rebuilt from current sources on every deploy, so hosted figures can differ
from the ones in these docs. Inspect source dates on **Data & methodology**
after deploying. Before a presentation, prefer a local snapshot: same numbers,
no cold start.

New deployments return the deployed Git commit in the `X-ReTrust-Revision`
HTTP response header (from Render's `RENDER_GIT_COMMIT`). Compare that header
on `/healthz` with `git rev-parse HEAD` to verify the exact code revision;
the scoring-version string alone cannot distinguish interface fixes within RT4.

The app has no accounts or saved procurement projects. Hosted assessments are
processed on Render, and requests pass through Render's infrastructure. Run
the local version for confidential procurement inputs. The hosted UI labels
its processing location explicitly.

## Limits and checks

The free service sleeps after 15 idle minutes and can take about a minute to
wake. Open it before a presentation. The server uses eight concurrent request
workers by default. Each request opens its own read-only advisory and screening
database connections and closes them in the same worker. It admits at most
16 active or queued requests at that setting; excess requests receive HTTP 503
with `Retry-After: 2`. Two extra request handlers serve health checks and prompt busy responses while all eight calculation slots are occupied. The TCP listen backlog is 64. `--workers` accepts 1–32;
worker count alone does not increase the instance's CPU or memory allocation.

Identical alternatives and exploitation-history page requests share one computation
and immutable HTML in memory. The cache holds at most 16 entries and 2 MiB,
keyed by complete input snapshot, date, page and product/firmware arguments.
Assessment results, comparison exports and operator answers are not cached.
The history page computes its corpus fraction with SQL rather than loading
all estimates for each visitor. Browsers still receive Cache-Control: no-store.

Weight sensitivity measures the evidence once and varies only the exponents,
so comparison reports do not rerun the complete vulnerability analysis 300
times per candidate. Concurrent-load verification should include scoring,
comparison downloads and health requests together, with no retries concealing
5xx failures. Record the tested user count and latency; free-instance capacity
is finite even though independent readers prevent requests from blocking each
other behind one shared SQLite connection.

The hosted surface is strictly read-only: the server answers GET requests only
and routes each one through an explicit table of read pages -- search, scoring,
comparison, the advisory views and `/healthz`. None of the commands that fetch
from the network or change state (`provider`, `setup`, `refresh`, `snapshot`,
`ingest`) is wired into it; that work runs only on the command line, so the
public URL cannot be driven to fetch a URL or alter the index.

After deployment check search, an order-number assessment, comparison, all
three comparison downloads, the advisory timeline and exploitation estimates.
`/healthz` must return `ok`. No project data directory, local scoring override,
credentials, generated reports or chat transcript is included in Git commits.

References: [Render web services](https://render.com/docs/web-services),
[Blueprint configuration](https://render.com/docs/blueprint-spec),
[free instance limits](https://render.com/docs/free).

## Preparation verified on 2026-09-29

- Full regression suite: 801 tests passed.
- Clean build in an isolated Python 3.13 environment completed from downloaded sources.
- Loaded 3,937 advisories, 67 EPSS history snapshots and 12,003 exploitation estimates.
- Fifteen live HTTP checks passed, covering the main workflows, health endpoint and all comparison export formats.
- Hosted UI labels were checked in the browser.

## Live deployment verified on 2026-09-29

- Public app: **https://retrust-q2tr.onrender.com/**
- Service: `srv-dattpanavr4c73eu5kp0`, free Python instance in Singapore.
- Blueprint: `exs-dattp3g93c1s73c021ug`.
- Source branch at that time: the original deploy branch, fast-forwarded to `main` on 2026-10-17. The service has tracked `main` directly since, confirmed 2026-10-30.
- Initial deployment completed successfully in 4 minutes 18 seconds.
- All 67 EPSS history snapshots loaded, with 12,003 exploitation estimates.
- Twenty-two public HTTPS checks passed: main workflows, HTML/JSON/CSV downloads, health GET/HEAD, missing routes and invalid comparison inputs.
- Browser checks confirmed order-number search and opening the corresponding assessment. The hosted labels and homepage were visually inspected.

Both sections above are records of what was true on their date, not current
figures. The feed counts in particular keep moving — 67 snapshots and 12,003
estimates then, 68 and 12,045 locally on 20 October 2026 — so read them as the
evidence that the deploy worked, and take live numbers from `retrust doctor`
or **Data & methodology** instead.

The deployment uses the private GitHub repository; publishing the app did not
change the repository visibility. Detailed live-check results and the homepage
screenshot are saved locally in `reports/render-live-checks.json` and
`reports/render-live-home.png`.

[Manage the service](https://dashboard.render.com/web/srv-dattpanavr4c73eu5kp0)
or [view its deployment](https://dashboard.render.com/web/srv-dattpanavr4c73eu5kp0/deploys/dep-dattpbfavr4c73eu5nu0).


## Formula verification on every deployment

After loading current advisory and exploitation data, the build runs
python -m retrust.formula_check. It recalculates every indexed vendor/model
under five scenarios: reachable, minor impact, verified blocked, unknown inputs,
and an unverified fix claim. Expected factor products, top-three concentration,
exposure safety, geometric score, caps and verdict precedence are checked
independently. Any arithmetic mismatch stops deployment.

The result is available at /formula-check.json and is tied to the source build
and complete input fingerprint. An unresolved product remains unscored and is
counted explicitly; passing the check does not establish predictive accuracy.
Assessment and comparison requests always recalculate their results from the
submitted inputs. The public-page cache covers only alternatives and history.


Firmware-specific alternatives pages recalculate their subject assessment but
share the same public candidate-list computation when the canonical family,
exclusions, scoring configuration and source snapshot agree. Candidate lists
contain no operator assertions or selected firmware. They use the same bounded
cache; each page receives separate decoded records.


Repeated firmware-range comparisons reuse at most 2,048 deterministic tri-state
results, keyed by both the exact advisory range and supplied firmware. True,
False and Unknown remain distinct. This avoids reparsing the same range across
hundreds of model variants; changed inputs are evaluated separately. It does
not cache assessment scores or operator answers.
The immutable parsed firmware and range representations also have independent
2,048-entry limits. Their keys include the exact source text, so changing a
version or advisory range cannot reuse a decision made for different inputs.
