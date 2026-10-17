# Bootstrap everything from nothing. Requires git, curl and python3.
DATA ?= data

.PHONY: all data ingest refresh test eval backtest demo docs guide batch snapshot ci deploy live clean

all: ingest refresh test

data:
	@mkdir -p $(DATA)
	@test -d $(DATA)/CSAF || (echo "Fetching CISA OT advisories..." && \
	  git clone --depth 1 --filter=blob:none --no-checkout -q \
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

# Regenerate the screenshots used in the documentation, so they cannot drift.
docs: demo
	@echo "Screenshots in docs/screenshots/"

# Score the example bill of materials. This one deliberately contains a gated
# vendor and an unresolvable part, so it exits non-zero -- that is the point.
batch:
	python3 -m retrust.cli batch examples/candidates.csv \
	  --json reports/batch.json --csv reports/batch.csv || true

# Pipeline gate on a BOM that should pass: tests green and nothing disqualified.
ci: test
	python3 -m retrust.cli batch examples/approved-bom.csv --fail-on unassessed

# Render's Blueprint deploys the branch the service was created from, which is
# codex/render-deployment rather than main. Pushing only main is silent: the
# build runs, the data refreshes, the code does not change. This pushes both,
# so the live site cannot drift behind again.
DEPLOY_BRANCH ?= codex/render-deployment

deploy: test
	git push origin main
	git push origin main:refs/heads/$(DEPLOY_BRANCH)
	@echo
	@echo "Pushed main and $(DEPLOY_BRANCH). Render builds in a few minutes."
	@echo "Check what is actually LIVE with:  make live"

# Verify the deployed code, not the data. Index counts move on every build
# whether or not the code did, so they prove nothing -- grep a string instead.
LIVE_URL ?= https://retrust-q2tr.onrender.com

live:
	@printf 'live scoring version: '
	@curl -s -m 90 "$(LIVE_URL)/export.json?vendor=ABB&product=AC%%20800M" \
	  | python3 -c "import json,sys; print(json.load(sys.stdin)['results'][0].get('vector','?').split('/')[0])" \
	  || echo "(could not reach $(LIVE_URL))"
	@printf 'local scoring version:  '
	@python3 -c "from retrust import score; print(score.SCORING_VERSION)"
	@echo "A mismatch means the deploy branch is behind; run make deploy."

clean:
	rm -rf $(DATA)/retrust.db $(DATA)/screening.json $(DATA)/certifications.json \
	  reports retrust-snapshot.zip __pycache__ */__pycache__ .pytest_cache
