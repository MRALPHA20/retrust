# Bootstrap everything from nothing. Requires git, curl and python3.
DATA ?= data

.PHONY: all data ingest refresh test eval demo docs batch snapshot ci clean

all: ingest refresh test

data:
	@mkdir -p $(DATA)
	@test -d $(DATA)/CSAF || (echo "Fetching CISA OT advisories..." && \
	  git clone --depth 1 --filter=blob:none --no-checkout -q \
	    https://github.com/cisagov/CSAF.git $(DATA)/CSAF && \
	  cd $(DATA)/CSAF && git sparse-checkout init --cone -q && \
	  git sparse-checkout set csaf_files/OT -q && git checkout -q)
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

snapshot:
	python3 -m retrust.cli snapshot --note "offline demo bundle"

# Everything end to end: score, check robustness, report, screenshot, re-measure.
demo:
	python3 -m retrust.cli demo

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

clean:
	rm -rf $(DATA)/retrust.db $(DATA)/screening.json $(DATA)/certifications.json \
	  reports retrust-snapshot.zip __pycache__ */__pycache__ .pytest_cache
