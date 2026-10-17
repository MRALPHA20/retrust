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
created against `codex/render-deployment`, not `main`, and a Blueprint deploys
the branch it was created from. Pushing to `main` therefore changed nothing
live, and pressing **Manual Deploy** twice simply rebuilt the same old commit
with fresh data -- the index hash moved while the code did not. If the two
branches drift again, fast-forward the deploy branch:

```bash
make deploy      # runs the tests, then pushes main AND the deploy branch
make live        # prints the live scoring version against the local one
```

`make live` compares the deployed code rather than the data, which is the check
that actually catches this: index counts move on every build whether or not the
code changed. The raw equivalent, if you prefer it:

```bash
git push origin main:refs/heads/codex/render-deployment
```

Better, point the service at `main` in **Settings > Build & Deploy > Branch**
and keep one branch. To check what is actually live rather than what you
pushed, compare a string you changed, not the data counts:

```bash
curl -s https://<your-app>.onrender.com/score?vendor=ABB\&product=AC%20800M | grep -c "a phrase you just changed"
```

Each new build
refreshes the main sources. Automatic deployment is enabled
(`autoDeployTrigger: commit`), so every push to the tracked branch rebuilds and
redeploys; **Manual Deploy > Deploy latest commit** still forces one on demand.

Because the build runs `setup --force` and `lev --update`, it refetches the
whole advisory corpus and 67 EPSS snapshots — tens of minutes on the free plan,
and a slow deploy is expected rather than a hang. It also means the live index
is rebuilt from current sources on every deploy, so hosted figures can differ
from the ones in these docs. Inspect source dates on **Data & methodology**
after deploying. Before a presentation, prefer a local snapshot: same numbers,
no cold start.

The app has no accounts or saved procurement projects. Hosted assessments are
processed on Render, and requests pass through Render's infrastructure. Run
the local version for confidential procurement inputs. The hosted UI labels
its processing location explicitly.

## Limits and checks

The free service sleeps after 15 idle minutes and can take about a minute to
wake. Open it before a presentation. This deployment uses the existing serial,
read-only HTTP server behind Render's HTTPS proxy; it is intended for a demo
or light use. A service designed for substantial concurrent traffic needs a
separate production-serving change and load testing.

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
- Source branch: `codex/render-deployment` (fast-forwarded to `main` on 2026-10-17); deployed application commit: `3162308` at the time of that check.
- Initial deployment completed successfully in 4 minutes 18 seconds.
- All 67 EPSS history snapshots loaded, with 12,003 exploitation estimates.
- Twenty-two public HTTPS checks passed: main workflows, HTML/JSON/CSV downloads, health GET/HEAD, missing routes and invalid comparison inputs.
- Browser checks confirmed order-number search and opening the corresponding assessment. The hosted labels and homepage were visually inspected.

The deployment uses the private GitHub repository; publishing the app did not
change the repository visibility. Detailed live-check results and the homepage
screenshot are saved locally in `reports/render-live-checks.json` and
`reports/render-live-home.png`.

[Manage the service](https://dashboard.render.com/web/srv-dattpanavr4c73eu5kp0)
or [view its deployment](https://dashboard.render.com/web/srv-dattpanavr4c73eu5kp0/deploys/dep-dattpbfavr4c73eu5nu0).
