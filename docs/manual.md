# The ReTrust manual

Everything about how ReTrust works and why: the scoring maths, the resolution
ladder, the back-test design, the hardening, and the standards it implements.
For the short version, start at the [README](../README.md).

**Score OT hardware for cyber risk before you buy it.**

ReTrust supports shortlist review before deployment. It answers a procurement
question: *of these candidate PLCs, which one
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

  CANDIDATE COMPARISON ───────────────────────────────────────────────────────

  Moxa EDS-405A
  PREFER  ·  87.6/100
  CVEs 10  ·  ROBUST 100%

  ABB AC 800M
  PREFER  ·  78.0/100
  CVEs 10  ·  ROBUST 85%

  Schneider Electric Modicon M340
  CONDITIONAL  ·  69.9/100
  CVEs 48  ·  ROBUST 100%

  Rockwell ControlLogix
  CONDITIONAL  ·  67.0/100
  CVEs 35  ·  ROBUST 87%

  Siemens SIMATIC S7-1500 (firmware 3.1.6)
  AVOID  ·  51.3/100
  CVEs 942  ·  ROBUST gated
  Known exploited vulnerability

  Hikvision IP Camera
  AVOID  ·  no score
  ROBUST not sampled
  Named on a covered list

  AVOID: 2  ·  CONDITIONAL: 1  ·  PREFER: 3
```

---

## Why order numbers, not CPE

Measured across 28,951 product entries in the local CISA OT corpus:

| Identifier available on the product entry | Entries | Share |
|---|---:|---:|
| **CPE** | 60 | **0.21%** |
| Order number the advisory declares (`model_numbers` / `skus`) | 8,211 | 28.36% |
| Order number ReTrust recovers from the product name | 1,364 | 4.71% |
| **Order number, either** (what ReTrust keys on) | **9,575** | **33.07%** |
| Vendor name | 28,947 | 99.99% |
| Product name | 28,951 | 100.00% |

Declared order numbers occur on about 137 times as many entries as CPE in this
corpus; recovered numbers raise that to about 160 times. This motivates the
input strategy, but does not establish how other tools perform on OT equipment.

`retrust eval` recomputes that whole table from your own index, so it is a
measurement you can check, not a claim you have to accept. The declared
and recovered rows are counted apart because they are different claims: one is
what the vendor published, the other is what this tool inferred. An index built
before this was recorded says so instead of reporting zero CPEs, since zero
measured and zero stored would otherwise print identically.

## Accuracy, and how to check it yourself

Run `retrust eval`. It recomputes every figure below from your own index, so you
never have to take these numbers on trust.

| Measurement | Result |
|---|---|
| Version ranges decided deterministically | **94.91%** of 28,651 |
| ...of ranges that *can* be decided from a version string | **96.80%** |
| Source-advisory recovery precision (n = 4,000) | **99.85%** |
| Source-advisory recovery recall (n = 4,000) | **99.70%** |
| Hand-written buyer-query set (misspellings, shorthand, wrong-field entries) | **20/21** |

The round-trip test shortens names, but also supplies an order number when
available. Success means the source advisory appears among matches; extra
incorrect matches are not penalized. The 21 buyer queries are an authored set,
not independent validation. Range coverage is not affected-version accuracy.
See the [benchmark report](benchmark-report.md) for denominators and limitations.

The [printable overview](ReTrust-Guide.pdf) includes an official-source
[tool comparison](tool-comparison.md). Rebuild with `make guide` after installing
`pip install -e '.[docs]'` from the repository root.

## Install

ReTrust needs Python 3.10+ and nothing else. No third-party packages, so there
is nothing to resolve, nothing to pin, and no virtualenv to create.

**Two commands from nothing to a working tool:**

```bash
git clone https://github.com/MRALPHA20/retrust.git && cd retrust
python3 -m retrust.cli setup
```

`setup` fetches CISA's OT advisory corpus, the KEV and EPSS exploitation feeds,
and the certification and sanctions lists, then builds the local index. That is
about 165 MB, and a couple of minutes on a normal connection. It prints what it
is doing at each step, and finishes by telling you what to run next.

Then score something:

```bash
python3 -m retrust.cli score --order-number 6ES7518-4AX00-1AB0 --version 3.1.6
```

That is the whole installation. Everything after this point is optional.

**If it is interrupted, run it again.** Each step is skipped when its output is
already there, so a dropped connection costs you only the step it dropped on.
Downloads go to a temporary file and are moved into place once complete, so a
half-fetched feed is never mistaken for a whole one.

| Flag | |
|---|---|
| `--offline` | Build from data already downloaded; fetch nothing |
| `--force` | Re-fetch sources even if they are present |
| `--skip-refresh` | Skip the certification and sanctions lists |
| `--data DIR` | Keep the data somewhere other than `data/` |

`setup` stops instead of finishing on an index it knows is incomplete. If KEV
or EPSS is missing, the exploitation gate cannot fire, and a product with a
known exploited vulnerability would score as merely mediocre, so it says so
instead of handing you a plausible-looking index.

### Installing the `retrust` command (optional)

The steps above run the tool straight from the clone. To get `retrust` on your
PATH instead of typing `python3 -m retrust.cli`:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

The virtualenv is not optional on Debian, Ubuntu or Kali: those ship Python as
an externally managed environment, and `pip install -e .` outside a venv fails
with a PEP 668 error. Both forms are equivalent: `retrust <command>` below is
the same as `python3 -m retrust.cli <command>`.

### Doing it by hand (optional)

`setup` is these four steps. Run them individually if you want the corpus
somewhere specific, or if you are scripting a build:

```bash
# 1. CISA's OT advisories in CSAF format (~148 MB, 3,937 advisories)
git clone --depth 1 --filter=blob:none --no-checkout \
  https://github.com/cisagov/CSAF.git data/CSAF
cd data/CSAF && git sparse-checkout set --cone csaf_files/OT && git checkout && cd ../..

# 2. Exploitation signals
curl -sLo data/kev.json https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
curl -sL https://epss.empiricalsecurity.com/epss_scores-current.csv.gz | gunzip > data/epss.csv

# 3. Build (takes about two seconds)
retrust ingest --csaf data/CSAF/csaf_files/OT --kev data/kev.json --epss data/epss.csv

# 4. Certification (ISASecure, Common Criteria) and sanctions screening
retrust refresh
```

`make all` does the same thing through the Makefile.

## Three ways to drive it

Commands with flags suit a script or a pipeline. `retrust shell` asks instead.
And `retrust serve` puts the same assessments in a browser, which is what the
person actually signing the purchase order would rather use.

```bash
retrust serve                  # http://127.0.0.1:8765
```

Search, score, compare, alternatives and vendor profiles as pages, rendered by
the same function that writes the report, so the browser and the printed PDF
cannot drift into showing one assessment two ways. A scored product links
onward -- its vendor's profile, its family's alternatives, a comparison started
with it -- so the next question is a click rather than a form refilled.

**Compare and retain a shortlist.** Each browser candidate accepts an order
number, or a vendor and model, plus optional firmware. Exact order-number
searches retain that identifier through assessment and comparison. Download
the complete comparison as HTML, JSON or CSV. All three formats retain the
original inputs; HTML and JSON also include source provenance and weights.
The JSON can be kept for a later `retrust diff`. Downloads assess against the
current local index, so retain the downloaded file as the decision record.
If only some candidates have firmware specified, a warning prompts you to
make their scope comparable.

**It is deliberately small and deliberately local.** One standard-library HTTP
server, no dependencies, and the security posture is the point rather than an
afterthought: a tool that screens sanctions lists has no business opening an
unauthenticated port on a plant network by accident. `/about` states the
contract, and tests hold it:

| | |
|---|---|
| Bound to `127.0.0.1` | anything else is opt-in and printed as a warning |
| GET only | no request body is ever read |
| No path becomes a filename | routing is an explicit table, so traversal has no code to live in |
| Nothing written, nothing executed | every request is the same function call the CLI makes |
| Everything escaped | and a CSP of `default-src 'none'` on every response |
| Host header checked | a DNS-rebinding page in a browser cannot read the index through it |
| Nothing cached, nothing framed | `Cache-Control: no-store`, `frame-ancestors 'none'` |
| Stalled connections dropped | one stuck client cannot hold the single-threaded server |

Single-threaded on purpose: a SQLite connection belongs to the thread that
opened it, and this is one person looking at their own index. Threading would
buy nothing and cost either a connection pool or `check_same_thread=False`,
which is how corruption gets in.

The same posture runs through the rest of the tool. Feeds are fetched over
https only -- a redirect that lands on plain http is refused -- and reads are
capped, so a hostile mirror can fill neither memory nor disk, gzip bombs
included. When `retrust provider` follows a vendor's own CSAF feed, the feed,
each advisory, and the digest and signature beside them are all addresses that
document hands the tool, so every one is vetted before the request, and each
redirect is vetted before it is followed -- urllib would otherwise open the
connection to a redirect target before anything could object: https only, and
never a private, loopback or link-local host, so a crafted feed cannot turn a
fetch into a read of a local file or a request to a cloud metadata endpoint. That feed is capped at 50,000 advisories
and 30 MB apiece. All of this fetching lives in the CLI; the web server fetches
nothing, so none of it is reachable over HTTP. PGP key material is refused over
anything but https and size-capped too. A snapshot's manifest travels inside
the archive, so its file names are validated before anything is unpacked:
`../` cannot escape the data directory, and the unpack aborts at a size ceiling
counted on the bytes actually decompressed -- not the size the archive
declares -- so a zip bomb cannot fill the disk either.
And CSV cells are neutralised against spreadsheet formula injection, because
this tool's output is opened in Excel by procurement -- a hostile advisory must
not be able to put `=HYPERLINK(...)` in front of a buyer.


```text
$ retrust shell
  ReTrust  /  interactive session
  Evidence before commitment.
  ────────────────────────────────────────────────────────────────────────────
  HOLDS  3,937 advisories, 28,951 product entries, 814 vendors

  CHOOSE A COMMAND ───────────────────────────────────────────────────────────
  search         Search the corpus
                 find a vendor, product or order number
  score          Score one product
                 verdict, pillars and the evidence
  order          Assess by order number
                 use the part number from the nameplate
  compare        Compare candidates
                 rank several for one decision
  alternatives   Alternatives
                 others in the family, scored the same way
  vendor         Vendor profile
                 what the index holds on a manufacturer
  batch          Score a BOM file
                 a CSV or JSON list of candidates
  lev            Likely exploited
                 NIST LEV, has it probably happened already
  ssvc           SSVC decisions
                 what buying this commits you to
  diff           What changed
                 re-score a saved result against today
  timeline       Advisory timeline
                 the record drawn as a shape, per year
  questions      RFQ annex
                 what to ask the vendor, from the evidence
  save           Save the last result
                 HTML, JSON or CSV
  quit / Leave the workspace
  Type a command. Blank answers go back; optional fields can be skipped.
```

**It prints the command it just ran.** The menu is not meant to hide the flags
forever: anyone running the same comparison a third time should be able to paste
that line into a script, and they can only do that having seen it.

**Saving is a separate choice from producing.** The last result is held, so `save`
offers HTML, JSON or CSV after you have seen the answer. Nobody has to decide in
advance which format they wanted.

Blank skips optional fields. Two blank responses at a required prompt cancel the
action. Ctrl-C returns from an action to the menu; at the menu it exits.

## Find what you are looking for

The corpus names 28,951 product entries under 814 vendor spellings, and scoring
needs the spelling the advisory used. `retrust search` is how you get it.

```
$ retrust search S7-1500

4 products matching 'S7-1500', strongest match first:

  Siemens / S7-1500 (when HTTPS active)
    prefix        --                      1 advisory
  Siemens / SIMATIC S7-1500 Software Controller
    tokens        --                      20 advisories
  Siemens / SIMATIC S7-1500 CPU 1518-4 PN/DP MFP (6ES75...
    tokens        6ES7518-4AX00-1AB0      16 advisories
```

Every hit says which test matched it: `exact`, `prefix`, `tokens` (every word of
your query appears), `substring`, or `similar 0.86` for an edit-distance match.
A ranked list nobody can explain is only a score in different clothes.

```bash
retrust search modicon                      # products, the common case
retrust search --vendors schneider          # vendors, with their corpus weight
retrust search --order-number 6ES7518       # order numbers, whole or partial
retrust search --vendor Moxa EDS            # products from one vendor only
```

**A lookup that fails suggests what to try instead.** This is the part that
saves the most time: `score` and `vendor` both fall back to it, so a misspelling
ends in a shortlist instead of `NOT ASSESSED`.

```
$ retrust vendor Siemems

Vendors in the corpus with a similar name:

VENDOR                                  PRODUCTS  ADVISORIES  MATCHED BY
Siemens                                   15,015       1,041  similar 0.86
Simens                                         1           1  similar 0.77
```

`Simens` is not a typo in this README. It is a misspelling in CISA's own corpus,
which is the kind of thing keying on exact names quietly loses.

## Vendor profiles

Procurement shortlists suppliers before it shortlists products. `retrust vendor`
reports what the index holds on one manufacturer.

```
$ retrust vendor Moxa

VENDOR DOSSIER   Moxa
  vendor key "moxa" -- 2 spellings in the corpus

WHAT THE INDEX HOLDS
  advisories                                  51
  product entries                            152
  distinct CVEs                              151
  first advisory                      2013-05-08
  most recent advisory                2024-09-24
  CVEs listed in CISA KEV                      0
  highest CVSS                              10.0
  median CVSS                                7.6

  These are counts of what has been published, not a verdict. A vendor that
  discloses diligently shows more advisories than one that stays quiet, so
  ReTrust does not score or rank vendors.

REMEDIATION   (advisories by the best remedy they offer)
  a vendor fix                                 7
  mitigation or workaround only               44
```

It also lists every spelling of the vendor's name in the corpus (any of them
works as `--vendor`), whether they run their own CSAF feed, their certificates,
and their screening status.

**It will not grade a vendor, and says so in its own output.** The rule that
keeps raw CVE counts out of the product score applies here too, and a
vendor-level view is where it would be easiest to break by accident. A figure
that was not measured prints as `not checked`, never as `0`.

## Use

Not installed? Replace `retrust` with `python3 -m retrust.cli` throughout.

Run `retrust` on its own to see what the index holds and what to try next.

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

### Every command

| Command | |
|---|---|
| `retrust` | what the index holds, and what to try next |
| `shell` | interactive menu; no flags to remember |
| `serve` | a local web interface on 127.0.0.1 |
| `verify` | are the advisories the ones CISA published? |
| `setup` | fetch every source and build the index |
| `search QUERY` | find vendors, products or order numbers |
| `vendor NAME` | what the index holds on one manufacturer |
| `diff FILE` | re-score a stored result; what changed since |
| `alternatives` | other products in the same vendor family |
| `questions` | the RFQ security annex: what to ask the vendor, from the evidence |
| `timeline` | advisory history drawn as a shape: cadence, fix share, quiet time |
| `ssvc` | place findings on CERT/CC's SSVC deployer tree |
| `lev` | has this probably been exploited already? (NIST CSWP 41) |
| `score` | assess one product |
| `compare` | rank candidates for one decision |
| `batch FILE` | score a bill of materials or a CycloneDX SBOM, with a CI exit code |
| `vex` | write the assessment as a CycloneDX VEX document: SBOM in, VEX out |
| `cve CVE-...` | one CVE, everything the index knows about it |
| `sensitivity` | how much a verdict depends on the weights |
| `eval` | reproduce the accuracy figures, buyer-query set included |
| `backtest` | did the score predict later disclosure? |
| `doctor` | is the installation current enough to be trusted right now? |
| `stats` | counts from the index |
| `config` | show or create the scoring weights; `--appetites` lists shipped risk appetites |
| `snapshot` | pin the data into one portable file |
| `ingest` | build the index from one or several CSAF directories |
| `provider URL` | fetch a vendor's own CSAF feed beside the CISA corpus |
| `refresh` | update the certification and sanctions lists |
| `screenshot` | render an HTML report to PNG |
| `demo` | run everything end to end |
| `completion bash\|zsh` | print a shell completion script |

Two flags work everywhere: `--db PATH` to use an index somewhere other than
`data/retrust.db`, and `--no-color` to strip the colour. Colour already turns
itself off when output is not a terminal, when `NO_COLOR` is set, and under
`TERM=dumb`, so you rarely need the flag.

### Tab completion

```bash
eval "$(retrust completion bash)"     # or: retrust completion zsh
```

The script is generated from the live argument parser, so it cannot go on
advertising a flag that was renamed. Add the line to `~/.bashrc` or `~/.zshrc`
to keep it.

## What changed since we approved this?

A procurement decision is made once and lived with for years, but the advisories
keep coming. `retrust diff` re-scores a stored result against today's index.

```bash
retrust batch bom.csv --json approved.json     # in January
retrust diff approved.json                     # in April
```

```
NEWLY GATED   a disqualifying fact has appeared
  Siemens SIMATIC S7-1500 (firmware 3.1.6)      PREFER -> AVOID  (-45.9)  Known exploited vulnerability
  Hikvision IP Camera                           CONDITIONAL -> AVOID  Named on a covered list

WORSE         the verdict fell
  Rockwell Automation ControlLogix              PREFER -> CONDITIONAL  (-14.6)

SCORE MOVED   same verdict, different score
  Moxa EDS-405A                                 CONDITIONAL  -5.5

8 product(s) compared, 4 unchanged.
```

It exits non-zero when anything was newly gated or fell, so a quarterly
re-review can run unattended and only raise a flag when there is something to
read.

Three details that stop it misleading you:

- **Rows pair on the original query, not the printed label.** A stored result
  records the four fields the buyer supplied, because the label is what we
  *resolved to* and that can change upstream. Pairing on labels would report a
  renamed product as one disappearing and an unrelated one arriving.
- **A new gate outranks a fallen verdict.** A gate is categorical, a KEV listing
  or a sanctions entry, and says what to do. A score that drifted down says only
  to look again.
- **Editing the weights between runs is reported before any finding.** Otherwise
  a change you made to the config reads as evidence about the corpus. Losing the
  ability to resolve a product is also kept apart from that product getting
  worse: we have not learned it is riskier, only that we can no longer say.

## Then what should we buy?

`score` ends a conversation. A buyer told their chosen PLC is AVOID still has to
buy something. `retrust alternatives` answers the part of that question ReTrust
can answer: which neighbouring products in the same vendor's family have a
better advisory record.

```
$ retrust alternatives --vendor Siemens --product "SIMATIC S7-1500" --version 3.1.6

ALTERNATIVES TO  Siemens SIMATIC S7-1500 (firmware 3.1.6)
  AVOID  51.3   Known exploited vulnerability

ReTrust does not know whether any of these will do the same job. It holds
advisory history, not specifications: no I/O counts, no form factors, no
safety integrity levels, nothing about fitness for purpose. These are
candidates for an engineer to evaluate, not a recommendation to substitute.

CANDIDATE                                     VERDICT      SCORE  CVES  SHARED NAME
Siemens SIMATIC S7-1500 CPU family (incl. re  PREFER        72.1    24  SIMATIC S7-1500 CPU family
Siemens SIMATIC S7-1500 CPU 1516T-3 PN/DP (6  PREFER        70.5    18  SIMATIC S7-1500 CPU

2 further family member(s) could not be assessed and are not listed. Absence
of advisories is not evidence of safety.
```

**A product ReTrust could not assess is never suggested.** This is the inversion
the command exists not to make: every pillar reads "no CVEs found" as good news,
so ranking on score alone would put the products nobody has published about at
the very top. They are counted and reported, never offered as safer.

**Suggestions stay inside one vendor's family.** Crossing vendors would need
equivalence data this tool does not have. The `SHARED NAME` column shows exactly
how much of the catalogue name a candidate has in common, so you can judge the
claim rather than trust it.

**A supplied firmware version is flagged as an unequal comparison.** The version
you gave belongs to the product you asked about and means nothing on another, so
candidates are scored without one. That makes the two columns answer slightly
different questions, and the report says so instead of letting the gap read as
the alternatives being cleaner.

## SSVC: what buying this commits you to

A score ranks candidates. It does not say what the purchase will cost in
operational work, which is the question the week after the order is signed.
`retrust ssvc` places each of a product's findings on CERT/CC's SSVC deployer
tree: defer, scheduled, out-of-cycle, or immediate.

```bash
retrust ssvc --vendor Siemens --product "SIMATIC S7-1500" --version 3.1.6 \
             --exposure controlled --automatable yes --human-impact high
```

```
WHAT BUYING THIS COMMITS YOU TO
  out-of-cycle      5   act sooner than the next maintenance window
  scheduled       937   fix during regular scheduled maintenance

CVE                OUTCOME        EXPLOITATION    EPSS  CVSS
CVE-2023-44487     out-of-cycle   active         1.000   7.5
CVE-2023-4911      out-of-cycle   active         0.814   7.8
CVE-2024-6387      scheduled      none           0.995   8.1
```

**Three of the four decision points are yours, and the tool will not guess
them.** System exposure, whether an attacker can automate the attack, and what a
compromise does to people and mission all describe your plant, not the product.
They have no defaults: SSVC is stakeholder-specific by design, and a tool that
filled them in would be misrepresenting the method rather than applying it.

**ReTrust supplies exploitation, and its "none" is an understatement.** A finding
in CISA KEV is `active`. Everything else is `none`, because ReTrust has no feed
of public proof-of-concept code and so can never reach SSVC's middle value. The
report says so, and names the findings where it matters most: in the run above,
eight sit at `none` with an EPSS above 0.5, topping out at 0.995. EPSS is a
model, not evidence of a public exploit, so it cannot move the tree, and those
need checking by hand.

**One decision per CVE, not per finding.** A CVE reaches the tool once for each
product entry an advisory names, and the same vulnerability listed eight times
would read as eight things to fix.

The decision table is CERT/CC's published deployer tree v1.0.0, reproduced from
their repository rather than rewritten, and a test checks all 72 rows still
agree with it. `--json` emits the decisions for a pipeline, and the exit code is
non-zero when anything demands action before the next maintenance window.

## Has this probably been exploited already?

KEV records exploitation somebody observed. EPSS estimates the chance over the
next thirty days. Neither answers the question a buyer has about a flaw that has
sat in a product for four years. `retrust lev` implements NIST's Likely Exploited
Vulnerabilities metric (CSWP 41), which composes a CVE's EPSS scores across its
whole life.

```bash
retrust lev --update                                       # once: fetch the history
retrust lev --vendor "Schneider Electric" --product "Modicon M340"
```

```
  CVEs estimated                         20
  expected already exploited            6.9   (sum of the probabilities)
  listed in CISA KEV                      0   (observed, not estimated)

CVE                   LEV  EPSS NOW   PEAK  KEV  DAYS  FIRST SCORED
CVE-2015-7937       0.975     0.074  0.163    -    57  2022-02-08
CVE-2013-0663       0.725     0.060  0.070    -    57  2022-02-08
CVE-2018-7240       0.526     0.033  0.033    -    67  2021-04-14
```

That gap is the whole point. This product has **nothing in KEV**, and its worst
EPSS today is 0.074, which no threshold would catch. CVE-2015-7937 has been
sitting at roughly that score every month since 2022, and a flaw that is 7%
likely every month for five years is very likely by now: LEV puts it at 0.975.

**`--update` fetches about 107 MB**, one EPSS snapshot per thirty days back to
2021-04-14, when FIRST published the first scores. Thirty days is not a tuning
choice: EPSS scores the following thirty days, so sampling more often would
multiply overlapping windows and inflate the result. Only CVEs this corpus names
are stored, which is what makes five years of history a 40 MB table.

**Without that history the command abstains.** Today's scores cannot produce a
LEV, and printing one from them would be arithmetic on data that is not there.

**LEV is not in the score, deliberately.** It is a model-derived lower bound, and
folding it into the composite would change every figure published above and
invalidate the back-test that checks them. It is reported alongside, like
evidence confidence, for a reader to weigh.

**Check whether the threshold discriminates before leaning on it.** Run
`retrust lev --audit`:

```
  median LEV                       0.167
  share reaching 0.1                56.9%

BY HOW LONG EPSS HAS SCORED THEM
  band                      CVEs   median   >= 0.1
  under a year             1,365    0.008     2.6%
  one to three years       3,348    0.025    12.6%
  three years or more      7,290    0.307    87.5%

AGAINST KEV   (the paper's own check: LEV should score KEV high)
  median LEV, in KEV       1.000   (113 CVEs)
  median LEV, not in KEV   0.162
```

Two things fall out, and the tool prints both rather than only the flattering
one. **LEV works**: CVEs in KEV have a median LEV of 1.000 against 0.162 for the
rest, a 6× separation, which is the paper's own validation and means LEV is not
merely measuring age. **But it is cumulative**, so exposure dominates: 2.6% of
CVEs under a year old clear 0.1, against 87.5% of those over three. A high LEV on
an old CVE is the expected case, not a finding.

That is why a per-product count is printed with the corpus base rate beside it.
The Modicon M340 above reads "18 of these (90%) ... across the whole corpus 57%
do, so this is more than usual", and Siemens TeleControl Server Basic reads "8 of
these (10%) ... fewer than usual". A count nobody can compare is not a finding.

Three rules taken from the paper itself:

- **The expected count is an expectation over a set**, not a claim about any one
  CVE. "6.9 of these 20" does not name which.
- **LEV never overrides KEV.** The composite probability takes the highest of
  KEV, LEV and current EPSS rather than averaging them: KEV is an observation
  and LEV is a model, and an average would let the model talk down something
  somebody watched happen.
- **It augments KEV rather than replacing it.** A high LEV on a CVE absent from
  KEV is a prompt to go and look, never a finding that it was exploited.

## Automation

**Score a whole bill of materials.** Point it at a CSV or JSON export from your
procurement system. Column names are matched loosely, so `Manufacturer`,
`Part Number` and `Firmware Version` all work without reshaping. A **CycloneDX
SBOM** works directly too -- the component list an integrator ships is exactly
a candidate list, with `supplier` as the vendor and `mpn` as the order number
([examples/system-bom.json](examples/system-bom.json) shows the shape).

```bash
retrust batch candidates.csv --json results.json --csv results.csv --html review.html
retrust batch system-bom.json                  # a CycloneDX SBOM, as exported
```

```
CANDIDATE COMPARISON ───────────────────────────────────────────────────────

Siemens SIMATIC S7-1500 CPU 1518-4 PN/DP MFP (6ES7518-4AX00-1AB0)
PREFER  ·  89.3/100
CVEs 1034  ·  ROBUST 100%
Caution — KEV-listed CVE(s) in third-party component bundles

Moxa EDS-405A
PREFER  ·  87.6/100
CVEs 10  ·  ROBUST 100%

ABB AC 800M
PREFER  ·  78.0/100
CVEs 10  ·  ROBUST 85%

Schneider Electric Modicon M340
CONDITIONAL  ·  69.9/100
CVEs 48  ·  ROBUST 100%

Rockwell ControlLogix
CONDITIONAL  ·  67.0/100
CVEs 35  ·  ROBUST 87%

Siemens SIMATIC S7-1500 (firmware 3.1.6)
AVOID  ·  51.3/100
CVEs 942
Known exploited vulnerability

Hikvision IP Camera
AVOID  ·  no score
Named on a covered list

Acme Widgets Nonexistent 9000
NOT ASSESSED  ·  no score
vendor 'Acme Widgets' does not appear in the advisory corpus

AVOID: 2  ·  CONDITIONAL: 1  ·  NOT ASSESSED: 1  ·  PREFER: 4
  exit 1: a candidate is disqualified
```

**Read the caution on the top row.** The MFP carries 1,034 CVEs and still leads
this ranking, which looks wrong until you see why: all but a handful arrive in
third-party component-bundle advisories — the Linux and OpenSSL stack the device
ships — and a bundle establishes that a component is present, not that each of
its CVEs is reachable on the controller. Exposure therefore measures the
vendor's own firmware, and the bundled KEV is raised as a caution instead of a
gate, because gating on it would punish exactly the vendors who publish their
component stacks. The caution is the output here, not a footnote: it names the
CVEs and hands the buyer the question that decides them. Ask it before the
order, which is what the RFQ annex is for.

**The exit code is the point.** It makes this a gate, not a report
somebody has to read:

| `--fail-on` | Non-zero when |
|---|---|
| `avoid` (default) | a candidate is disqualified |
| `unassessed` | also when a candidate could not be assessed at all |
| `never` | never; just report |

```yaml
# In CI, block a merge that introduces a disqualified component
- run: retrust batch bom.csv --fail-on unassessed --json results.json
```

**Run everything end to end.** One command that scores, checks robustness,
writes the report, captures screenshots and re-measures accuracy, so a station
demo cannot half-fail in front of an audience:

```bash
retrust demo
```

**JSON from any command.** `score`, `compare` and `batch` all take `--json`.
Pass a filename, or `-` to write to stdout. The human table is suppressed then,
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
  "schema": 2,
  "weights":    { "exposure": 0.6, "patchability": 0.2, "vendor_practice": 0.15, "certification": 0.05 },
  "provenance": [ { "source": "CISA KEV", "detail": "1,726 entries",
                    "captured": "2026-09-27" } ],
  "results": [ { "product": "Moxa EDS-405A", "verdict": "CONDITIONAL",
                 "score": 55.9, "robust": 0.897, "gates": [], ... } ]
}
```

`score --json` returns a superset of the same record: the evidence line behind
every pillar, the citation behind every gate, and the most significant CVEs with
their EPSS, KEV and remediation status. Anything trimmed is counted, never
silently dropped (`findings_truncated`). The envelope carries the weights and
the data provenance, so a stored result stays interpretable months later.

JSON and CSV records include the assessment type, network exposure, consequence,
interface, remediation and reproduction vector. `retrust diff` keeps these
owner choices fixed when it re-scores a saved assessment. Firmware comparison
notes and weight-robustness calculations also hold the owner choices fixed.

`score` and `compare` also take `--fail-on`, defaulting to `never` because they
are interactive; `batch` defaults to `avoid` because it is a gate.

**Screenshots.** Uses whatever Chrome or Chromium is already on the machine; it
is not a dependency, and its absence costs you screenshots and nothing else.
Chrome's renderer sandbox stays on; it is dropped only where Chrome itself
refuses to start it (as root, the usual case in a container), and
`RETRUST_CHROME_NO_SANDBOX=1` forces it off for any other locked-down
environment that needs it.

```bash
retrust screenshot reports/comparison.html --both-themes
```

Documentation screenshots are regenerated by `make docs`, so they are always
produced by the current code instead of hand-updated and left to drift.

## How the score is built

Three layers, evaluated in this order.

**1. Hard gates.** A disqualifying fact ends the assessment. A vulnerability in
CISA's Known Exploited Vulnerabilities catalogue forces `AVOID` regardless of
everything else. Gates are not weighted terms, because a weighted disqualifier
can be averaged away by good scores elsewhere.

**1. Hard gates** also cover supply chain. A vendor on the FCC Covered List, the
BIS Entity List or an OFAC sanctions list is `AVOID` outright. Screening runs on
the vendor name alone, so it fires even for a vendor absent from the advisory
corpus. Otherwise the gate would only protect you from suppliers you were
already going to hear about.

**2. Evidence pillars**, each 0–100 where higher is better:

| Pillar | Exponent | What it reads |
|---|---:|---|
| Exposure | 0.60 | concentrated per-finding risk — see below |
| Patch availability | 0.20 | CSAF remediation status: a fix, a workaround, or nothing |
| Vendor practice | 0.15 | whether the vendor runs its own CSAF feed, and advisory completeness |
| Certification | 0.05 | IEC 62443 (ISASecure) and Common Criteria certificates |

**Exposure** is built per finding and then concentrated, because averaging is
what a purchase decision least wants: a product with one catastrophic flaw and
forty minor ones should not average out like forty-one middling ones.

```
z  = T' × A × H × U          one number per vulnerability, 0–1, higher is worse
T' = 0.40 + 0.60 T           threat amplifies; it never zeroes the rest
R  = 0.70 z₁ + 0.20 z₂ + 0.10 z₃ + 0.10 mean(the rest)
E  = 100 (1 − R)
```

| Term | Reads | From |
|---|---|---|
| `T` threat | KEV, ransomware linkage, EPSS | evidence; never asked |
| `A` reachability | the CVSS attack vector, narrowed by deployment and by a *verified* interface block | evidence + operator |
| `H` impact | the finding's own CVSS severity, scaled by the declared process consequence | evidence + operator |
| `U` applicability | does it still apply to the firmware being bought or run | CSAF + operator |

Two decisions worth stating. `T` is mapped onto `[0.40, 1]` rather than used
raw: the OT median EPSS is 0.007, so multiplying by it directly scored a
critical, reachable, unfixed vulnerability as harmless purely because nobody had
attacked it yet. And the tail term exists because the worst three alone cannot
tell three severe flaws from three hundred — bounded at a tenth, so breadth can
never outvote the worst case.

**3. A weighted product**, reported as a band:

```
S = E^0.60 × P^0.20 × V^0.15 × C^0.05
```

A product rather than a mean, so dangerous exposure cannot be bought back with
a good vendor record and a certificate — the rule the gates enforce, applied to
the weighted part. Pillars enter as 1–100: a floor at 1 keeps a catastrophic
pillar catastrophic (E = 0 lands near 5/100, deep in `AVOID`) without letting
one unmeasured term annihilate every other measurement. Bands are `PREFER`
(≥70), `CONDITIONAL` (≥40), `AVOID`. Exponents and thresholds live in an
editable config file; run `retrust config --init`.

Certification is the one asymmetric term. Most OT hardware is never submitted,
so a missing certificate is excluded rather than penalised — and because its
absence is never a penalty, its presence is never allowed to lower the score
either: the composite is computed with and without it and the better taken. A
`C^0.05` applied naively costs an uncertified product 20.6% of its score, which
would punish the majority for a vendor's paperwork decision.

### The facts only you have

Four inputs describe your plant rather than the product. ReTrust supplies the
vulnerability intelligence and never asks you to score a vendor or guess a
percentage. Every one is optional, and an unanswered question stays unresolved
rather than quietly becoming a best or worst case.

| Input | Choices | Effect |
|---|---|---|
| `--assessment-type` | `purchase` (default), `installed` | Records whether this is a procurement decision or an existing asset review |
| `--network-exposure` | `isolated`, `it_ot`, `internet_ot` | Narrows `A`. Folded into reachability rather than scored separately: "an attacker cannot route here" is the statement `A` already makes |
| `--consequence` | `safety`, `control`, `recoverable`, `minor`, `negligible` | Scales `H`. Left blank, exposure is reported at full process impact — the conservative reading, and said out loud |
| `--interface` | `exposed`, `blocked`, `unknown` | Only a *verified* block narrows `A` |
| `--remediation` | `applied`, `mitigated`, `available`, `planned`, `unknown` | Use for all in-scope findings; planned work does not reduce current risk |

Every declaration can only ever narrow the risk: saying nothing is already the
conservative reading, so a claim about your own plant never makes a flaw worse
than its own vector says.

Each assessment also carries a reproducible vector, so a result can be re-run
and disputed by somebody who was not there:

```
RT2/AT:installed/FW:3.1.6/NX:it_ot/IF:blocked/OC:control/RS:applied/DS:4f3a9c2d6b18
```

`DS` is a short fingerprint of the recorded source, count and capture-date
metadata, not a checksum of the full advisory database. The report lists those
source records below the vector.

### What the vector says, not just the score

A base score collapses eight decisions into one number, and the decisions are
what a buyer needs. CVSS 9.8 reached over the network with no credentials is a
different purchase from CVSS 9.8 that needs physical access to a device in a
locked cabinet.

Every score block in CISA's OT corpus carries its vector, so this is read rather
than assumed: **69,557 of 69,560 affected rows, 100%**. Better coverage than any
other optional field in the data.

| Reading | Share of findings |
|---|---:|
| Reachable over the network | 66.9% |
| No credentials needed | 66.2% |
| **Wormable** (network + no credentials + no user action) | **44.8%** |
| Automatable (that, and low complexity) | 35.5% |
| Physical access only | 1.8% |

The vector is what `A` reads: a flaw reachable over the network scores the full
reachability term, one needing physical access a tenth of it. A vector we could
not read is treated as neither extreme and said so, because silently weighing
reachability as zero would be a claim about the product rather than about the
data. The severity pillar still reports peak CVSS, critical share and the
wormable count as a diagnostic beside the score.

`retrust ssvc --automatable auto` derives SSVC's Automatable from the vectors and
shows its working. SSVC does not define that metric as a function of CVSS, so it
is offered as a suggestion for a human to accept, never as the answer.

### Do the weights actually matter?

The usual objection to any composite score is that its weights were invented.
That is fair, and the honest answer is to measure it instead of arguing about it.
`retrust sensitivity` samples hundreds of weightings from across the whole
simplex and reports how often the verdict survives:

```
$ retrust sensitivity --vendor "Schneider Electric" --product "Modicon M340"

CONDITIONAL under 100% of weightings -- the verdict does not hinge on the weights
  score across 500 random weightings: 65.0 to 70.0 (median 69.9)
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
  rank below one that stays quiet, which is exactly backwards.
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
  is near-constant). Both were silently adding fixed offsets instead of
  ranking anything. Severity now also weighs how *many* flaws are critical, and
  vendor practice reads whether the vendor runs its own CSAF feed.
- **Some facts cannot be outvoted.** A critical, likely-exploited flaw with no
  vendor fix is a gate. Weighted scoring alone could not reach AVOID for one:
  pillars the vendor did well on offset the one that made the product
  unbuyable.
- **Screening is tiered, because a false accusation is the worst error here.**
  Only a distinctive legal name on a blocking list stops a purchase. A
  single-word name or an alias is reported for review instead: screened against
  all 883 vendors in the corpus, matching on those produced four false
  positives, including a medical-device maker colliding with a *vessel* named
  BAXTER on the SDN list. Individuals, vessels and aircraft are excluded
  outright, since a hardware manufacturer is none of them.
- **Sanctions screening never fuzzy-matches.** Wrongly flagging a real
  manufacturer is the worst error this tool could make, so screening matches
  exact identity-preserving names only. Using the looser vendor normaliser here
  matched *Schneider Electric* against *Schneider GMBH* on the BIS Entity List.
  The test suite now pins that case.

### A note on convergent validity

CISA KEV records exploitation confirmed in the wild; FIRST's EPSS is an
independent statistical model. On this corpus they agree sharply. OT CVEs
listed in KEV have a median EPSS of **0.70** against **0.0073** for OT CVEs
overall, roughly a 97× separation. Two independently built sources pointing the
same way is the empirical footing for the exploitation pillar.

## Resolution ladder

Four strategies, strongest first. Each rung reports its own confidence, and
below the floor ReTrust returns nothing rather than a weak guess.

| Rung | Method | Confidence | Source-advisory recovery |
|---|---|---:|---:|
| 1 | Manufacturer order number | 0.98 | 100% |
| 2 | Vendor + product name, continuing at a component boundary | 0.90 | 99.8% |
| 3 | Vendor + all query words present in the name | 0.70 | 100% |
| 4 | Abstain, with a typed reason | — | — |

Confidence values are heuristics, not calibrated probabilities. The round-trip
method does not penalize extra matches; see the benchmark report.

A wrong answer about whether a PLC is vulnerable costs more than "needs review",
so abstention is a feature rather than a failure.

## Are the advisories genuine?

A tool that screens supply chains should be able to say where its own inputs
came from. CISA ships a SHA-512 and a detached PGP signature beside every
advisory, and `retrust verify` checks both, keeping them apart because they
answer different questions.

```bash
retrust verify
```

```
CONTENT   does each file still match the digest shipped beside it?
  verified                        3,937
  failed                              0

ORIGIN    who signed it?
  signature verified                  0
  not established                 3,937

  signed by:
    144A ED0A 57BE 7D4A E835 D9D8 CAC5 AC4F 7416 4B17   438 sampled
```

**The digest and the file came from the same clone**, so it catches corruption
and tampering after download and nothing else. A substituted repository would
carry a matching digest. Only the signature survives a hostile mirror, and the
report says so rather than rolling both into one reassuring number.

**One key signed all 3,937 advisories**, which is the expected shape; more than
one is what a partially substituted mirror looks like, and gets flagged.

**Fetching the key follows the standard, not a keyserver.** CSAF says a
publisher advertises its signing keys in `provider-metadata.json`, so
`--fetch-key` reads CISA's and imports the key it names, refusing it unless the
fingerprint matches the one these signatures were actually made with. Two
sources have to agree before anything is trusted: the key the publisher
advertises and the key the signatures were made with. `--key FILE` takes one you
obtained yourself.

```
ORIGIN    who signed it?
  signature verified              3,937
```

**One wrinkle worth knowing.** CISA's provider metadata is not at the
`.well-known/csaf/provider-metadata.json` path the standard suggests; it sits at
`www.cisa.gov/sites/default/files/csaf/provider-metadata.json`, which is what the
BSI CSAF aggregator points at. A verifier who looks only at the conventional
location finds a 404 and concludes the key is unpublished. It is not.

Exit code is non-zero if anything *failed* a check -- a digest that did not
match, a signature that did not verify -- so a build can refuse to score on a
corpus it could not verify. **"Not established" is not a failure.** The first
run above holds no keyring, so every signature is unestablished, and it still
exits zero: "could not check" is not "checked and wrong". A pipeline that must
not read the one as the other runs `retrust verify --strict`, which exits
non-zero unless both origin and content were positively established for every
advisory.

## Data sources

| Source | What it provides | Access |
|---|---|---|
| CISA ICS advisories (CSAF 2.0) | authoritative product→CVE mappings | `cisagov/CSAF` on GitHub |
| CISA KEV | confirmed exploitation, ransomware linkage | JSON feed |
| FIRST EPSS | exploitation probability, covers 99.70% of OT CVEs | daily CSV |
| ISASecure | IEC 62443-4-1/4-2/3-3 certificates | scraped listings |
| Common Criteria | Published certified products | official CSV |
| Consolidated Screening List | 26,144 sanctioned/restricted entities | trade.gov CSV |
| FCC Covered List / NDAA §889 | named covered entities | curated, cited in-repo |

Vendors that run their own CSAF feed (Siemens, Schneider, ABB, Hitachi Energy
and others, verified via the BSI CSAF aggregator) are used as a *signal* in the
vendor-practice pillar. ReTrust does not yet ingest those feeds directly;
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

Every report footer records which data snapshot produced it: the advisory
count, the KEV and EPSS capture dates, and the weights used. `retrust snapshot`
bundles the index and both auxiliary lists into one checksummed zip, so a
result can be regenerated months later and shown to be the same result. Restore
verifies every SHA-256 and refuses a modified bundle.

## Does the score predict anything?

The fresh 28 September 2026 backtest uses a 2022-01-01 cutoff and 1,000 seeded
permutations. It does not validate prediction of real-world compromise.

| Diagnostic | Products | Spearman rho |
|---|---:|---:|
| Score versus later CVE disclosure | 5,848 | +0.431 |
| Within vendor | 3,822 | +0.269 |
| Within vendor, excluding Siemens | See raw results | +0.044 |

Pooled and within-vendor permutation p-values are 0.001. The weakening positive
association is consistent with disclosure/exposure effects, but does not prove
a causal explanation. Only two products across two vendors qualify for the
later-KEV outcome. That is too sparse for an exploitation-rate claim.

The current snapshot covers one cutoff. Run `retrust backtest --sweep` to explore
other dates; earlier sweep figures are not current release measurements.
See [benchmark methods and raw evidence](benchmark-report.md).

```sh
retrust backtest --cutoff 2022-01-01 --permutations 1000 --json results.json
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
reads it, and wiring it into the pillar that uses it. `certification.py` is the
smallest complete example to copy.

## Limitations

- **Certification coverage is incomplete.** Confirm the exact product, certificate
  scope and validity with the cited scheme; a vendor-level match is not proof
  that a particular device is certified.
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
- [FIRST EPSS](https://www.first.org/epss/), used under FIRST's terms,
  including the dated snapshots the LEV estimate composes.
- [NIST CSWP 41](https://csrc.nist.gov/pubs/cswp/41/likely-exploited-vulnerabilities/final),
  Likely Exploited Vulnerabilities, implemented in `retrust/lev.py`.
- [ISASecure](https://isasecure.org/) certified product listings.
- [Common Criteria](https://www.commoncriteriaportal.org/) certified products.
- [CERT/CC SSVC](https://github.com/CERTCC/SSVC) deployer decision table
  v1.0.0, Copyright 2026 Carnegie Mellon University, MIT (SEI)-style
  licence. Reproduced in `retrust/ssvc.py` with its notice.
- [trade.gov Consolidated Screening List](https://www.trade.gov/consolidated-screening-list)
  and the [FCC Covered List](https://www.fcc.gov/supplychain/coveredlist).

Screening and certification results are reproductions of what those sources
publish. They are decision support for a buyer, not a legal determination.
Verify any gate against the cited source before acting on it.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
