# ReTrust

**Score OT hardware for cyber risk before you buy it.**

Existing tools tell you about equipment you already own. ReTrust answers the
question a procurement team actually asks: *of these candidate PLCs, which one
should we put on the purchase order?* It works from public advisory data, keys
on the manufacturer order number a purchase requisition already contains, and
shows the evidence behind every number.

```
$ retrust compare \
    --candidate "ABB|AC 800M" \
    --candidate "Schneider Electric|Modicon M340" \
    --candidate "Rockwell Automation|ControlLogix" \
    --candidate "Moxa|EDS-405A" \
    --candidate "Siemens|SIMATIC S7-1500|3.1.6" \
    --candidate "Hikvision|IP Camera"

CANDIDATE                                 VERDICT       SCORE  CVES  ROBUST  NOTES
ABB AC 800M                               PREFER         81.5    10    96%
Schneider Electric Modicon M340           PREFER         77.2    21    84%
Rockwell Automation ControlLogix          CONDITIONAL    56.4    35   100%
Moxa EDS-405A                             CONDITIONAL    55.9    10    89%
Siemens SIMATIC S7-1500 (firmware 3.1.6)  AVOID          39.1  1011   gated  Known exploited vulnerability
Hikvision IP Camera                       AVOID           --      -     -     Named on a covered list
```

---

## Why order numbers, not CPE

Every conventional vulnerability tool joins products to CVEs through CPE
strings. Measured across all 27,234 product entries in CISA's OT advisory
corpus:

| Identifier available on the product entry | Entries | Share |
|---|---:|---:|
| **CPE** — what conventional scanners join on | 26 | **0.10%** |
| Order number the advisory declares (`model_numbers` / `skus`) | 8,204 | 30.12% |
| Order number ReTrust recovers from the product name | 1,384 | 5.08% |
| **Order number, either** — what ReTrust keys on | **9,588** | **35.21%** |
| Vendor name | 27,231 | 99.99% |
| Product name | 27,234 | 100.00% |

CPE is effectively absent from ICS advisory data, which is why general-purpose
tooling performs so poorly on OT gear. Declared order numbers are **316×** more
available, and the ones ReTrust recovers from product names bring that to 369× —
and `6ES7518-4AX00-1AB0` is exactly what a buyer types onto a requisition.
ReTrust keys on those instead.

`retrust eval` recomputes that whole table from your own index, so it is a
measurement you can check rather than a claim you have to accept. The declared
and recovered rows are counted apart because they are different claims: one is
what the vendor published, the other is what this tool inferred. An index built
before this was recorded says so instead of reporting zero CPEs — zero measured
and zero stored would otherwise print identically.

## Accuracy, and how to check it yourself

Run `retrust eval`. It recomputes every figure below from your own index, so you
never have to take these numbers on trust.

| Measurement | Result |
|---|---|
| Version ranges decided deterministically | **93.1%** of 26,958 |
| ...of ranges that *can* be decided from a version string | **94.7%** |
| Product resolution precision (n = 4,000) | **99.9%** |
| Product resolution recall (n = 4,000) | **99.9%** |
| Resolution by order number | **100%** (1,428 / 1,428) |

Two things that keep these honest:

- **The round-trip test does not feed the corpus string back verbatim.** It
  strips the parenthetical order number, drops punctuation and case, and keeps
  only the first four words — roughly what a buyer types. Testing exact strings
  against themselves reports a meaningless 100%.
- **Ranges that cannot be decided are counted separately, not hidden.** A range
  pinned to a serial number or a board revision (`<= first 5 digits of serial
  number 26061`) is undecidable for any version-based tool. ReTrust abstains and
  says why.

**What this does not claim.** These figures measure resolving a *named* product
to its advisories. They are not device-fingerprinting accuracy — identifying
equipment from passive network traffic is a much harder problem where the
commercial state of the art is around 83%. Different question, different number.

## Install

Python 3.10+ and no third-party runtime dependencies, so there is nothing to
resolve and nothing to pin.

```bash
git clone https://github.com/<you>/retrust.git && cd retrust
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

The virtualenv is not optional on Debian, Ubuntu or Kali: those ship Python as
an externally managed environment, and `pip install -e .` outside a venv fails
with a PEP 668 error.

**Or skip installing entirely.** Every command works straight from a clone:

```bash
python3 -m retrust.cli --help
```

Both forms are equivalent — `retrust <command>` below is the same as
`python3 -m retrust.cli <command>`. If you did not install the package, use the
longer form.

## Build the index

ReTrust works offline against a local SQLite index, so results are reproducible
and a demo never depends on the network.

```bash
# 1. CISA's OT advisories in CSAF format (~134 MB, 3,937 advisories)
git clone --depth 1 --filter=blob:none --sparse https://github.com/cisagov/CSAF.git
cd CSAF && git sparse-checkout set csaf_files/OT && cd ..

# 2. Exploitation signals
curl -sLo kev.json  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
curl -sL https://epss.empiricalsecurity.com/epss_scores-current.csv.gz | gunzip > epss.csv

# 3. Build (takes about two seconds)
retrust ingest --csaf CSAF/csaf_files/OT --kev kev.json --epss epss.csv

# 4. Certification (ISASecure, Common Criteria) and sanctions screening
retrust refresh
```

## Use

Not installed? Replace `retrust` with `python3 -m retrust.cli` throughout.

```bash
# Assess one product by its manufacturer order number
retrust score --order-number 6ES7518-4AX00-1AB0 --version 3.1.6

# Or by vendor and name
retrust score --vendor Siemens --product "SIMATIC S7-1500" --version 3.1.6

# Compare candidates and write a report to send with the requisition
retrust compare --candidate "Siemens|SIMATIC S7-1500|3.1.6" \
                --candidate "Schneider Electric|Modicon M340" \
                --html decision.html

# Reproduce the accuracy figures
retrust eval --sample 4000

# How much does a verdict actually depend on the weights?
retrust sensitivity --vendor "Moxa" --product "EDS-405A"

# Edit the weights to match your own risk appetite
retrust config --init

# Pin all the data into one file for an offline demo or a reproducible result
retrust snapshot --note "Q4 procurement review"
retrust snapshot --restore retrust-snapshot.zip
```

## Automation

**Score a whole bill of materials.** Point it at a CSV or JSON export from your
procurement system — column names are matched loosely, so `Manufacturer`,
`Part Number` and `Firmware Version` all work without reshaping.

```bash
retrust batch candidates.csv --json results.json --csv results.csv --html review.html
```

```
CANDIDATE                                     VERDICT      SCORE  NOTES
ABB AC 800M                                   PREFER        81.5
Schneider Electric Modicon M340               PREFER        77.2
Rockwell Automation ControlLogix              CONDITIONAL   56.4
Moxa EDS-405A                                 CONDITIONAL   55.9
Siemens SIMATIC S7-1500 CPU 1518-4 PN/DP MFP  AVOID         44.6  Known exploited vulnerability
Siemens SIMATIC S7-1500 (firmware 3.1.6)      AVOID         39.1  Known exploited vulnerability
Hikvision IP Camera                           AVOID          --   Named on a covered list
Acme Widgets Nonexistent 9000                 NOT ASSESSED   --   vendor not in the advisory corpus

  AVOID: 3, CONDITIONAL: 2, NOT ASSESSED: 1, PREFER: 2
  exit 1: a candidate is disqualified
```

**The exit code is the point.** It makes this a gate rather than a report
somebody has to read:

| `--fail-on` | Non-zero when |
|---|---|
| `avoid` (default) | a candidate is disqualified |
| `unassessed` | also when a candidate could not be assessed at all |
| `never` | never — just report |

```yaml
# In CI, block a merge that introduces a disqualified component
- run: retrust batch bom.csv --fail-on unassessed --json results.json
```

**Run everything end to end.** One command that scores, checks robustness,
writes the report, captures screenshots and re-measures accuracy — so a station
demo cannot half-fail in front of an audience:

```bash
retrust demo
```

**JSON from any command.** `score`, `compare` and `batch` all take `--json`.
Pass a filename, or `-` to write to stdout — the human table is suppressed then,
so the output pipes cleanly:

```bash
retrust score --vendor Moxa --product EDS-405A --json - | jq '.results[0].verdict'
retrust compare --candidate "ABB|AC 800M" --candidate "Siemens|SIMATIC S7-1500|3.1.6" --json -
```

All three share one envelope and one record shape, so a single parser reads any
of them:

```json
{
  "generated_by": "retrust",
  "schema": 1,
  "weights":    { "exploitation": 0.3, "severity": 0.2, ... },
  "provenance": [ { "source": "CISA KEV", "detail": "1,726 entries",
                    "captured": "2026-09-27" } ],
  "results": [ { "product": "Moxa EDS-405A", "verdict": "CONDITIONAL",
                 "score": 55.9, "robust": 0.897, "gates": [], ... } ]
}
```

`score --json` returns a superset of the same record: the evidence line behind
every pillar, the citation behind every gate, and the most significant CVEs with
their EPSS, KEV and remediation status. Anything trimmed is counted rather than
silently dropped (`findings_truncated`). The envelope carries the weights and
the data provenance, so a stored result stays interpretable months later.

`score` and `compare` also take `--fail-on`, defaulting to `never` because they
are interactive; `batch` defaults to `avoid` because it is a gate.

**Screenshots.** Uses whatever Chrome or Chromium is already on the machine; it
is not a dependency, and its absence costs you screenshots and nothing else.

```bash
retrust screenshot reports/comparison.html --both-themes
```

Documentation screenshots are regenerated by `make docs`, so they are always
produced by the current code rather than hand-updated and left to drift.

## How the score is built

Three layers, evaluated in this order.

**1. Hard gates.** A disqualifying fact ends the assessment. A vulnerability in
CISA's Known Exploited Vulnerabilities catalogue forces `AVOID` regardless of
everything else. Gates are not weighted terms, because a weighted disqualifier
can be averaged away by good scores elsewhere.

**1. Hard gates** also cover supply chain. A vendor on the FCC Covered List, the
BIS Entity List or an OFAC sanctions list is `AVOID` outright. Screening runs on
the vendor name alone, so it fires even for a vendor absent from the advisory
corpus — otherwise the gate would only protect you from suppliers you were
already going to hear about.

**2. Five risk pillars**, each 0–100 where higher is better:

| Pillar | Weight | What it reads |
|---|---:|---|
| Exploitation | 0.30 | CISA KEV, ransomware linkage, peak EPSS |
| Severity | 0.20 | worst CVSS, count of 9.0+ |
| Patch availability | 0.20 | CSAF remediation status: a fix, a workaround, or nothing |
| Vendor practice | 0.15 | whether advisories carry CVSS and CWE |
| Certification | 0.15 | IEC 62443 (ISASecure) and Common Criteria certificates |

**3. A weighted composite**, reported as a band: `PREFER` (≥70),
`CONDITIONAL` (≥40), `AVOID`. Weights and thresholds live in an editable config
file — run `retrust config --init`.

### Do the weights actually matter?

The usual objection to any composite score is that its weights were invented.
That is fair, and the honest answer is to measure it rather than argue about it.
`retrust sensitivity` samples hundreds of weightings from across the whole
simplex and reports how often the verdict survives:

```
$ retrust sensitivity --vendor "Rockwell Automation" --product ControlLogix

CONDITIONAL under 100% of weightings -- the verdict does not hinge on the weights
  score across 500 random weightings: 39.4 to 74.1 (median 56.4)
```

A verdict that holds under 96% of weightings is not a matter of opinion. One
that holds under 72% is a judgement call, and the tool says so instead of
handing you a false precision. `compare` prints this as a **ROBUST** column and
flags anything below 90%.

Reported alongside, but deliberately **not** part of the score: **evidence
confidence**, the share of findings whose version range parsed cleanly and which
carry CVSS and EPSS data. Folding it into the composite would mean "we have good
data about how bad this is" *raises* the score, which is backwards. It tells you
how much to trust the verdict, not how safe the product is.

### Rules that keep this defensible

- **Raw CVE counts are never scored.** A vendor that discloses diligently would
  rank below one that stays quiet — exactly backwards.
- **Weights are configurable and printed.** Disagree with them without having to
  distrust the whole result.
- **Every figure cites its source.** The tool reports what CISA and the vendors
  themselves published.
- **Unparseable version ranges stay in scope and are flagged**, never assumed
  safe.
- **A product we cannot resolve gets no score at all.** Every pillar reads "no
  CVEs found" as good news, so an unresolvable product would otherwise score
  near 100 and rank top of a comparison. `NOT ASSESSED` sorts below `AVOID`.
- **Missing certification is never a penalty.** Most OT products are never
  submitted, so absence says nothing; a certificate can only add.
- **A pillar that cannot discriminate is a bug, not a feature.** Sensitivity
  analysis caught two: severity scored ~0 for every OT product (nearly all have
  a 9.8+, so `100 - peak × 10` saturated), and vendor practice scored ~100 for
  everyone (CISA normalises the advisories it republishes, so advisory quality
  is near-constant). Both were silently adding fixed offsets rather than
  ranking anything. Severity now also weighs how *many* flaws are critical, and
  vendor practice reads whether the vendor runs its own CSAF feed.
- **Some facts cannot be outvoted.** A critical, likely-exploited flaw with no
  vendor fix is a gate. Weighted scoring alone could not reach AVOID for one —
  pillars the vendor did well on offset the one that made the product
  unbuyable.
- **Screening is tiered, because a false accusation is the worst error here.**
  Only a distinctive legal name on a blocking list stops a purchase. A
  single-word name or an alias is reported for review instead: screened against
  all 883 vendors in the corpus, matching on those produced four false
  positives, including a medical-device maker colliding with a *vessel* named
  BAXTER on the SDN list. Individuals, vessels and aircraft are excluded
  outright — a hardware manufacturer is none of them.
- **Sanctions screening never fuzzy-matches.** Wrongly flagging a real
  manufacturer is the worst error this tool could make, so screening matches
  exact identity-preserving names only. Using the looser vendor normaliser here
  matched *Schneider Electric* against *Schneider GMBH* on the BIS Entity List —
  the test suite now pins that case.

### A note on convergent validity

CISA KEV records exploitation confirmed in the wild; FIRST's EPSS is an
independent statistical model. On this corpus they agree sharply — OT CVEs
listed in KEV have a median EPSS of **0.70** against **0.0073** for OT CVEs
overall, roughly a 97× separation. Two independently built sources pointing the
same way is the empirical footing for the exploitation pillar.

## Resolution ladder

Four strategies, strongest first. Each rung reports its own confidence, and
below the floor ReTrust returns nothing rather than a weak guess.

| Rung | Method | Confidence | Round-trip accuracy |
|---|---|---:|---:|
| 1 | Manufacturer order number | 0.98 | 100% |
| 2 | Vendor + product name, including longer family variants | 0.90 | 99.8% |
| 3 | Vendor + all query words present in the name | 0.70 | 100% |
| 4 | Abstain, with a typed reason | — | — |

A wrong answer about whether a PLC is vulnerable costs more than "needs review",
so abstention is a feature rather than a failure.

## Data sources

| Source | What it provides | Access |
|---|---|---|
| CISA ICS advisories (CSAF 2.0) | authoritative product→CVE mappings | `cisagov/CSAF` on GitHub |
| CISA KEV | confirmed exploitation, ransomware linkage | JSON feed |
| FIRST EPSS | exploitation probability, covers 99.7% of OT CVEs | daily CSV |
| ISASecure | IEC 62443-4-1/4-2/3-3 certificates | scraped listings |
| Common Criteria | 2,122 certified products | official CSV |
| Consolidated Screening List | 26,144 sanctioned/restricted entities | trade.gov CSV |
| FCC Covered List / NDAA §889 | named covered entities | curated, cited in-repo |

Vendors that run their own CSAF feed (Siemens, Schneider, ABB, Hitachi Energy
and others, verified via the BSI CSAF aggregator) are used as a *signal* in the
vendor-practice pillar. ReTrust does not yet ingest those feeds directly —
CISA's repository already mirrors most of their advisories.

## Development

```bash
python3 -m pytest tests/ -q      # 259 tests, no network needed
```

Layout:

```
retrust/
  version.py    version-range parsing   (the accuracy-critical component)
  csaf.py       reads CSAF advisories
  index.py      SQLite build and normalisation
  match.py      the resolution ladder
  score.py      gates, pillars, verdict
  report.py     self-contained HTML output
  supplychain.py   sanctions and covered-list screening
  certification.py IEC 62443 and Common Criteria evidence
  config.py        editable weights and band thresholds
  sensitivity.py   how much the verdict depends on the weights
  snapshot.py      portable, checksummed data bundles
  batch.py         bulk scoring, the shared JSON/CSV schema, CI exit codes
  screenshot.py    headless-Chrome report capture
  backtest.py      does the score predict later disclosure?
  evaluate.py   the reproducible accuracy harness
  cli.py        command line interface
```

## Reproducibility

Every report footer records which data snapshot produced it — the advisory
count, the KEV and EPSS capture dates, and the weights used. `retrust snapshot`
bundles the index and both auxiliary lists into one checksummed zip, so a
result can be regenerated months later and shown to be the same result. Restore
verifies every SHA-256 and refuses a modified bundle.

## Does the score predict anything?

`retrust backtest` scores every product using only advisories published before a
cutoff date, then measures against what was disclosed afterwards. Run it and you
get this, on CISA's own corpus:

```
BACK-TEST AT 2022-01-01
  products scored on pre-cutoff data only     5,839

  correlation                                rho
  score vs CVEs after the cutoff          +0.432   p=0.001 (1,000 shuffles)
  score vs CVEs before the cutoff         -0.049   (is the score just re-reading history?)
  CVEs before vs CVEs after               +0.183   (how much does volume persist?)
```

**That positive number is the interesting part, and it is not a validation.** A
higher score went with *more* later CVEs — the opposite of what a risk score
should do, if CVE count were the right yardstick.

It is not the right yardstick. The score rewards vendors who run a real
disclosure programme, and those vendors publish more CVEs. The extreme case here
is a Siemens CPU with 2 CVEs before the cutoff and **1,029 after**, because one
advisory bundled hundreds of upstream Linux CVEs. Counting CVEs measures how much
a vendor discloses — precisely what the scoring rules refuse to penalise.

The decomposition is printed for exactly this reason. The score barely tracks
*past* CVE count (−0.049), so it is not simply re-reading history; it tracks
*future* count (+0.432) because it tracks disclosure maturity. The sign is stable
across every cutoff from 2019 to 2024, so it is a property of the outcome
variable rather than of one date.

The sound outcome would be confirmed exploitation — a product later appearing in
CISA's KEV catalogue unambiguously went badly, whatever its vendor's disclosure
habits. On this corpus only **29 products across 2 vendors** qualify, so the tool
reports that sparsity rather than computing a rate from it.

### Matched cohort: holding the vendor constant

If the pooled correlation is a vendor effect, comparing each product only
against *others from the same manufacturer* should dissolve it. It does:

```
MATCHED COHORT AT 2022-01-01  (each product compared only with others from the same vendor)
  vendors with enough products                   21
  products inside those vendors               3,814
  pooled within-vendor rho                   +0.106   p=0.003 (within-vendor shuffles)
  same, excluding Siemens                    -0.187   (leave-one-out)
  vendors pointing each way               9 negative / 10 positive
```

Three readings, in order:

| Design | rho | What it means |
|---|---:|---|
| Pooled across all vendors | **+0.432** | confounded — disclosure practice varies by vendor |
| Within vendor | **+0.106** | most of the effect *was* the vendor |
| Within vendor, excluding Siemens | **−0.187** | one stratum carried the sign |

Siemens is half the matched sample and bundles hundreds of upstream Linux CVEs
into single advisories, so it dominates any count-based outcome. Dropping it
reverses the sign — which is why the tool reports leave-one-out rather than a
single number.

The honest conclusion is not "the score predicts" or "the score fails". It is
that **once the vendor is held constant the effect largely dissolves**, its
residual is small, and its sign is not consistent between manufacturers (9 to
10) or across cutoffs. With 3,814 products a small p-value means "not zero", not
"large enough to act on", and the report says so.

Strata where every product scored alike, or none had a later CVE, are dropped
rather than averaged in — they would inflate the apparent sample without adding
information.

This is what a back-test is for: not to award the score a pass mark, but to show
which outcome variables are usable and which are confounded. Nothing leaks across
the cutoff — a test asserts that adding post-cutoff advisories cannot move a
pre-cutoff score, and the permutation null shuffles *within* each vendor so it
preserves the stratification.

```bash
retrust backtest --cutoff 2022-01-01 --json results.json
```

## Extending it

Adding a scoring pillar is one entry in `score.PILLARS`:

```python
PillarSpec("supply_chain", "Supply chain", 0.10,
           lambda findings, advisories, certificates, vendor_key:
               Pillar("Supply chain", score, coverage, ["evidence line"]))
```

The default weights, the config file's accepted keys, the report's weight column
and the sensitivity sampler all derive from that list, so nothing else needs
editing. A test asserts they stay in step.

Adding a data source means a loader that writes into `data/`, a `load()` that
reads it, and wiring it into the pillar that uses it — `certification.py` is the
smallest complete example to copy.

## Limitations

- **Common Criteria barely covers OT.** Of nine major OT vendors checked against
  its 2,122 certified products, only two appear; the list is dominated by smart
  cards. ISASecure is the OT-relevant scheme and is small (155 certificates).
- Country-of-origin screening is not implemented. No authoritative public
  product-level source exists, and corporate domicile is a weak proxy that would
  need labelling as such.
- Vendor normalisation covers the common cases; the long tail of 814 vendor
  spellings will need community contributions.
- Firmware binary analysis is out of scope by design. ReTrust is the decision
  layer above tools like EMBA and FACT, not a replacement for them.
- **No advisories for a product is not evidence it is secure.** It may simply
  mean nobody has published. ReTrust says so rather than scoring it clean.

## Data sources and attribution

ReTrust redistributes no vendor data. It reads public sources at build time and
cites each one in every report footer:

- CISA ICS advisories, from the [cisagov/CSAF](https://github.com/cisagov/CSAF)
  repository (US Government work).
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
- [FIRST EPSS](https://www.first.org/epss/), used under FIRST's terms.
- [ISASecure](https://isasecure.org/) certified product listings.
- [Common Criteria](https://www.commoncriteriaportal.org/) certified products.
- [trade.gov Consolidated Screening List](https://www.trade.gov/consolidated-screening-list)
  and the [FCC Covered List](https://www.fcc.gov/supplychain/coveredlist).

Screening and certification results are reproductions of what those sources
publish. They are decision support for a buyer, not a legal determination —
verify any gate against the cited source before acting on it.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
