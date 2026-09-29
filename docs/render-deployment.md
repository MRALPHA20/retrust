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
| Environment | `RETRUST_HOSTED=1`, `RETRUST_BUILD_LEV_HISTORY=1` |

## Data and updates

The build downloads public advisory and supporting sources, builds SQLite,
and loads historical EPSS for the exploitation-estimate page. Initial builds
can take several minutes. Set `RETRUST_BUILD_LEV_HISTORY=0` to skip the history;
that page will then explain that its required data is missing.

Data is part of the deployment artifact. Runtime requests read it and generate
downloads in memory, so a restart requires no persistent disk. Each new build
refreshes the main sources. Automatic deployment is disabled; use **Manual
Deploy > Deploy latest commit** when an update is ready. Inspect source dates
on **Data & methodology** after deploying.

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

After deployment check search, an order-number assessment, comparison, all
three comparison downloads, the advisory timeline and exploitation estimates.
`/healthz` must return `ok`. No project data directory, local scoring override,
credentials, generated reports or chat transcript is included in Git commits.

References: [Render web services](https://render.com/docs/web-services),
[Blueprint configuration](https://render.com/docs/blueprint-spec),
[free instance limits](https://render.com/docs/free).
