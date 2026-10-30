# Bootstrap everything from nothing. Requires git, curl and python3.
DATA ?= data

.PHONY: all data ingest refresh test eval backtest demo docs guide screenshots batch snapshot ci deploy live clean smoke formula-check

all: ingest refresh test

data:
	@mkdir -p $(DATA)
	@test -d $(DATA)/CSAF || (echo "Fetching CISA OT advisories..." && \
	  git clone -c core.autocrlf=false --depth 1 --filter=blob:none --no-checkout -q \
	    https://github.com/cisagov/CSAF.git $(DATA)/CSAF && \
	  cd $(DATA)/CSAF && git sparse-checkout set --cone csaf_files/OT && \
	  git checkout -q)
	@test -f $(DATA)/kev.json || (echo "Fetching CISA KEV..." && \
	  curl -sLo $(DATA)/kev.json \
	    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
	@test -f $(DATA)/epss.csv || (echo "Fetching EPSS..." && \
	  curl -sL https://epss.empiricalsecurity.com/epss_scores-current.csv.gz \
	    | gunzip > $(DATA)/epss.csv)

ingest: data
	python3 -m retrust.cli ingest --csaf $(DATA)/CSAF/csaf_files/OT \
	  --kev $(DATA)/kev.json --epss $(DATA)/epss.csv

refresh:
	python3 -m retrust.cli refresh --data $(DATA)

test:
	python3 -m pytest tests/ -q

# Broad CLI checks against the downloaded local data.
smoke:
	bash scripts/smoke.sh

# Validate scoring across all indexed products without fetching new sources.
formula-check:
	python3 -m retrust.formula_check --db $(DATA)/retrust.db --data $(DATA) --output $(DATA)/formula-validation.json

eval:
	python3 -m retrust.cli eval --sample 4000

backtest:
	python3 -m retrust.cli backtest --cutoff 2022-01-01

snapshot:
	python3 -m retrust.cli snapshot --note "offline demo bundle"

# Everything end to end: score, check robustness, report, screenshot, re-measure.
demo:
	python3 -m retrust.cli demo

# Recapture the documentation screenshots from the running app with Playwright's
# own Chromium. Install .[docs], then `python3 -m playwright install chromium`.
screenshots:
	python3 tools/capture_screenshots.py

# Build the illustrated overview from retained measurements. Install .[docs].
guide: screenshots
	python3 tools/build_overview.py
	python3 tools/build_scoring_sheet.py

# Regenerate the screenshots used in the documentation, so they cannot drift.
docs: demo
	@echo "Screenshots in docs/screenshots/"

# Score the example bill of materials. This one deliberately contains a gated
# vendor and an unresolvable part, so it exits non-zero -- that is the point.
batch:
	python3 -m retrust.cli batch examples/candidates.csv \
	  --json reports/batch.json --csv reports/batch.csv || true

# Pipeline gate on a BOM that should pass: tests green and nothing disqualified.
# The BOM carries a completed site review (OT-only network, reachability
# verified blocked, process-control impact, firmware confirmed affected):
# without those answers every row is VERIFY by design and the gate fails.
ci: test
	python3 -m retrust.cli batch examples/approved-bom.csv --fail-on unassessed

# Render tracks main. Confirmed on 2026-10-30: a push of main alone rebuilt
# the service and the live X-ReTrust-Build header moved to main's fingerprint.
# The service was originally created against another branch, which made pushes
# to main silent; that is fixed, so one push is enough.
deploy: test
	git push origin main
	@echo
	@echo "Pushed main. Render builds in a few minutes."
	@echo "Check what is actually LIVE with:  make live"

# Verify the deployed code, not the data. Index counts move on every build
# whether or not the code did, so they prove nothing -- grep a string instead.
LIVE_URL ?= https://retrust-q2tr.onrender.com

# Compares the SOURCE of the deployed code, not the data and not the scoring
# version. Both of those stayed identical across builds that were three commits
# apart, so neither could detect a stale deploy -- this can.
live:
	@printf 'live  build: '
	@curl -s -m 90 -D - -o /dev/null "$(LIVE_URL)/healthz" \
	  | awk 'tolower($$1)=="x-retrust-build:"{print $$2}' \
	  | tr -d '\r' | grep . || echo "(no build header -- the deployed code predates it)"
	@printf 'local build: '
	@python3 -c "from retrust import serve; print(serve.BUILD)"
	@echo "Equal means the deployed code is exactly what you have."
	@echo "Different means the live site is stale: run make deploy, or Manual Deploy."

clean:
	rm -rf $(DATA)/retrust.db $(DATA)/screening.json $(DATA)/certifications.json \
	  reports retrust-snapshot.zip __pycache__ */__pycache__ .pytest_cache
