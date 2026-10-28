# Bootstrap everything from nothing. Requires git, curl and python3.
DATA ?= data

.PHONY: all data ingest refresh test eval backtest demo docs guide batch snapshot ci deploy live clean smoke formula-check

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
	bash smoke.sh

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

# Build the illustrated overview from retained measurements. Install .[docs].
guide:
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

# Render's Blueprint deploys the branch the service was created from, which is
# codex/render-deployment rather than main. Pushing only main is silent: the
# build runs, the data refreshes, the code does not change. This pushes both,
# so the live site cannot drift behind again.
DEPLOY_BRANCH ?= codex/render-deployment

# render.yaml declares branch: main, but the deploy branch is still pushed
# until the dashboard confirms the switch -- a belt-and-braces push costs
# nothing and a silently-stale live site costs an afternoon.
deploy: test
	git push origin main
	git push origin main:refs/heads/$(DEPLOY_BRANCH)
	@echo
	@echo "Pushed main and $(DEPLOY_BRANCH). Render builds in a few minutes."
	@echo "Once Settings > Build & Deploy > Branch reads 'main', the second"
	@echo "push is redundant and DEPLOY_BRANCH can be dropped from this target."
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
