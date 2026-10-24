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

  ABB AC 800M
  VERIFY  ·  87.2–87.7/100 (provisional range)
  CVEs 10  ·  ROBUST not sampled  ·  WORST FLAW 0.28

  Schneider Electric Modicon M340
  VERIFY  ·  69.1–79.9/100 (provisional range)
  CVEs 48  ·  ROBUST not sampled  ·  WORST FLAW 1.00

  Rockwell Automation ControlLogix
  VERIFY  ·  5.9–92.8/100 (provisional range)
  CVEs 35  ·  ROBUST not sampled  ·  WORST FLAW 1.00

  Moxa EDS-405A
  VERIFY  ·  89.5–92.8/100 (provisional range)
  CVEs 10  ·  ROBUST not sampled  ·  WORST FLAW 0.96

  Siemens SIMATIC S7-1500 (firmware 3.1.6)
  AVOID  ·  5.6–89.4/100 (provisional range)
  CVEs 942  ·  ROBUST gated  ·  WORST FLAW 1.00
  Known exploited vulnerability

  Hikvision IP Camera
  AVOID  ·  no score
  ROBUST not sampled
  Named on a covered list

  AVOID: 2  ·  VERIFY: 4
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

**Start with what you know.** The assessment form asks for product identity
and optional firmware first. Expand **Use vendor and model instead** if you
do not have an order number. **Site details and fixes (optional)** holds the
questions for your technical team; leaving them unknown keeps a conservative
first assessment. Results show the verdict and any supplier-verification
requirement before editing or download controls. **What this score covers**
separates scored device-vendor findings from bundled-software issues that still
need supplier review. Evidence completeness is explained under **What evidence
was checked?**; it is not a percentage chance that the equipment is secure.

**Compare and retain a shortlist.** Each browser candidate accepts an order
number, or a vendor and model, plus optional firmware. Exact order-number
searches retain that identifier through assessment and comparison. Download
the complete comparison as HTML, JSON or CSV. All three formats retain the
original inputs; HTML and JSON also include source provenance and weights.
The JSON can be kept for a later `retrust diff`. Downloads assess against the
current local index, so retain the downloaded file as the decision record.
If only some candidates have firmware specified, a warning prompts you to
make their scope comparable.
Each candidate also keeps its own assessment type, network exposure,
operational consequence, verified reachability and fix status through the
assessment-to-comparison link, editing and all three downloads. Expand that
candidate's **Site details and fixes** to review or change these answers.

**Use the supporting pages without learning the terminal.** Vendor profiles,
advisory history, alternatives, supplier questions, response priority and past
exploitation estimates explain their purpose and offer example lookups. Enter
the manufacturer and model shown on your quotation, or use Explore to find the
exact name. On a result page, expand **Change product** to revise the lookup.
The timeline accepts a manufacturer alone for its full history.

Supplier questions appear as numbered requests. Expand **Why ask this?** for
the evidence, or use **Open text to copy** to paste the complete text into an
email or quotation request. ReTrust does not send messages. Response priorities
display their assumed access, automation and impact settings; agree those with
your technical and operations teams before using the suggested timing. Related
products require an engineer's suitability check. **Data & methodology** includes
**Which page should I use?**, verdict definitions and a glossary.

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
| Stalled connections dropped | stalled clients release their request workers |

The web server uses eight bounded request workers by default. Each request
creates its own read-only advisory and screening SQLite connections in the
worker that uses them, then closes them there. User inputs and results are
request-specific. The SQLite thread check remains enabled. At the default
setting, at most 16 requests are active or queued; excess work receives HTTP
503 with a retry hint. `retrust serve --workers N` accepts 1–32 workers.

Identical alternatives and exploitation-history requests share one public-page
computation, bounded to 16 stored pages and 2 MiB. Cache keys include the input
snapshot, date and product/firmware arguments. Assessment results and operator
answers are not cached; browsers still receive no-store response headers.
Comparison weight trials reuse measured evidence instead of repeating the
full analysis for every sampled weighting.

The same posture runs through the rest of the tool. Feeds are fetched over
https only -- a redirect that lands on plain http is refused -- and reads are
capped, so a hostile mirror can fill neither memory nor disk, gzip bombs
included. When `retrust provider` follows a vendor's own CSAF feed, the feed,
each advisory, and the digest and signature beside them are all addresses that
document hands the tool, so every one is vetted before the request, and each
redirect is vetted before it is followed -- urllib would otherwise open the
connection to a redirect target before anything could object. The HTTPS
transport resolves the actual destination and connects directly to a vetted
public address, preserving TLS certificate and hostname checks. DNS errors and
non-global addresses, including shared address space, fail closed. Environment
proxies are ignored for these provider/download requests so they cannot resolve
a different target. Each redirect uses the same transport: https only, and
never a non-public host, so a crafted feed cannot turn a
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

20 products matching 'S7-1500', strongest match first:

  Siemens / S7-1500 (when HTTPS active)
    prefix        --                      1 advisory
  Siemens / SIMATIC S7-1500 Software Controller
    tokens        --                      20 advisories
  Siemens / SIMATIC S7-1500 CPU family (incl. related ET200 CPUs and SI...
    tokens        --                      19 advisories
  Siemens / SIMATIC S7-1500 CPU 1518-4 PN/DP MFP (6ES7518-4AX00-1AB0)
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
  Rockwell Automation ControlLogix              CONDITIONAL -> AVOID  (-14.6)

SCORE MOVED   same verdict, different score
  Moxa EDS-405A                                 AVOID  -5.5

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
  AVOID  5.6   Known exploited vulnerability

ReTrust does not know whether any of these will do the same job. It holds
advisory history, not specifications: no I/O counts, no form factors, no
safety integrity levels, nothing about fitness for purpose. These are
candidates for an engineer to evaluate, not a recommendation to substitute.

These are scored without a firmware version, while the product above was
scored at 3.1.6. A version decides which CVEs apply, so the two are not on
equal terms: check each candidate again once you know which firmware you
would buy.

VERIFY candidates need technical checks; their ranges are provisional, not recommendations or proof that they are safer.

CANDIDATE                                     VERDICT      SCORE  CVES  SHARED NAME
Siemens SIMATIC ET 200S IM 151-8 PN/DP CPU (  VERIFY       46.9-95.7    12  SIMATIC
Siemens SIMATIC ET 200S IM 151-8F PN/DP CPU   VERIFY       46.9-95.7    12  SIMATIC
Siemens SIMATIC ET 200pro IM 154-8 PN/DP CPU  VERIFY       46.9-95.7    12  SIMATIC
Siemens SIMATIC ET 200pro IM 154-8F PN/DP CP  VERIFY       46.9-95.7    12  SIMATIC
Siemens SIMATIC ET 200pro IM 154-8FX PN/DP C  VERIFY       46.9-95.7    12  SIMATIC
Siemens SIMATIC S7-300 CPU 314C-2 PN/DP (6ES  VERIFY       46.9-95.7    12  SIMATIC
Siemens SIMATIC S7-300 CPU 315-2 PN/DP (6ES7  VERIFY       46.9-95.7    12  SIMATIC
Siemens SIMATIC S7-300 CPU 315F-2 PN/DP (6ES  VERIFY       46.9-95.7    12  SIMATIC
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
CVE-2023-4911      out-of-cycle   active         0.638   7.8
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
nine sit at `none` with an EPSS above 0.5, topping out at 0.995. EPSS is a
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
  CVEs estimated                         48
  expected already exploited           20.1   (sum of the probabilities)
  listed in CISA KEV                      0   (observed, not estimated)

CVE                   LEV  EPSS NOW   PEAK  KEV SAMPLES  FIRST SCORED
CVE-2018-7846       1.000     0.296  0.441    -      68  2021-04-14
CVE-2015-7937       0.977     0.074  0.163    -      58  2022-02-08
CVE-2018-7842       0.976     0.350  0.372    -      68  2021-04-14
```

That gap is the whole point. This product has **nothing in KEV**, yet the
expectation says 20.1 of its 48 estimated CVEs have probably been exploited
already. CVE-2015-7937 scores an EPSS of 0.074 today, which no threshold
would catch. It has been sitting at roughly that score every month since
2022, and a flaw that is 7% likely every month for years on end is very
likely by now: LEV puts it at 0.977.

**`--update` fetches about 107 MB**, one EPSS snapshot per thirty days back to
2021-04-14, when FIRST published the first scores. Thirty days is not a tuning
choice: EPSS scores the following thirty days, so sampling more often would
multiply overlapping windows and inflate the result. Only CVEs this corpus names
are stored, which is what makes five years of history a 40 MB table.

**Without that history the command abstains.** Today's scores cannot produce a
LEV, and printing one from them would be arithmetic on data that is not there.

**LEV is included in RT4 threat priority.** T takes the maximum of KEV, LEV
and current EPSS. Missing sources remain unavailable and keep the assessment
provisional where they can change the result. Their time horizons differ, so
this maximum is a priority index rather than a compromise probability.
Historical backtests from earlier models do not validate this revision.

**Check whether the threshold discriminates before leaning on it.** Run
`retrust lev --audit`:

```
  median LEV                       0.172
  share reaching 0.1                57.4%

BY HOW LONG EPSS HAS SCORED THEM
  band                      CVEs   median   >= 0.1
  under a year             1,282    0.009     2.4%
  one to three years       3,363    0.027    12.8%
  three years or more      7,400    0.316    87.2%

AGAINST KEV   (the paper's own check: LEV should score KEV high)
  median LEV, in KEV       1.000   (114 CVEs)
  median LEV, not in KEV   0.168
```

Two things fall out, and the tool prints both rather than only the flattering
one. **LEV works**: CVEs in KEV have a median LEV of 1.000 against 0.168 for the
rest, a 6× separation, which is the paper's own validation and means LEV is not
merely measuring age. **But it is cumulative**, so exposure dominates: 2.4% of
CVEs under a year old clear 0.1, against 87.2% of those over three. A high LEV on
an old CVE is the expected case, not a finding.

That is why a per-product count is printed with the corpus base rate beside it.
The Modicon M340 above reads "39 of these (81%) ... across the whole corpus 57%
do, so this is more than usual", and Siemens TeleControl Server Basic reads "8 of
these (10%) ... fewer than usual". A count nobody can compare is not a finding.

Three rules taken from the paper itself:

- **The expected count is an expectation over a set**, not a claim about any one
  CVE. "20.1 of these 48" does not name which.
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
Scoring 8 candidate(s) from examples/candidates.csv ...

  CANDIDATE COMPARISON ───────────────────────────────────────────────────────

  Siemens SIMATIC IPC477E Pro
  VERIFY  ·  44.7–99.2/100 (provisional range)
  CVEs 14

  Siemens SIMATIC S7-1500 CPU 1518-4 PN/DP MFP (6ES7518-4AX00-1AB0)
  VERIFY  ·  6.2–98.5/100 (provisional range)
  CVEs 1034

  Schneider Electric Modicon M340
  VERIFY  ·  69.1–79.9/100 (provisional range)
  CVEs 48

  Rockwell Automation ControlLogix
  VERIFY  ·  5.9–92.8/100 (provisional range)
  CVEs 35

  Moxa EDS-405A
  VERIFY  ·  89.5–92.8/100 (provisional range)
  CVEs 10

  Johnson Controls iSTAR Ultra G2
  VERIFY  ·  5.5–69.9/100 (provisional range)
  CVEs 8

  Siemens SIMATIC S7-1500 (firmware 3.1.6)
  AVOID  ·  5.6–89.4/100 (provisional range)
  CVEs 942
  Known exploited vulnerability

  Hikvision IP Camera
  AVOID  ·  no score
  Named on a covered list

  AVOID: 2  ·  VERIFY: 6

  exit 1: a candidate is disqualified
```

**Read the caution, wherever the MFP lands.** It carries 1,034 CVEs and still
ranks beside candidates carrying a few dozen rather than at the bottom, which looks wrong until you see why: all but a handful arrive in
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
  "schema": 3,
  "weights":    { "exposure": 0.6, "patchability": 0.2, "vendor_practice": 0.15, "certification": 0.05 },
  "provenance": [ { "source": "CISA KEV", "detail": "1,748 entries",
                    "captured": "2026-10-20" } ],
  "results": [ { "product": "Moxa EDS-405A", "verdict": "VERIFY",
                 "score": 5.9, "score_min": 5.9, "score_max": 92.8,
                 "provisional": true, "assertions": [], "gates": [], ... } ]
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

`score` and `compare` also take `--fail-on`. `compare` defaults to `never`
because it is interactive; `batch` defaults to `avoid` because it is a gate.
`score` without the flag exits 2 on VERIFY or NOT ASSESSED when printing the
terminal table, and 0 when `--json` was asked for, because a pipeline that
asked for JSON parses the verdict itself. An explicit `--fail-on` wins
identically in both modes.

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

**Exposure in RT6 follows the ReTrust-OT V1 proposal:**

```
T = max(KEV, LEV, EPSS)
Z = T × A × H × U
R = min(1, Z1 + 0.20 Z2 + 0.10 Z3)
E = 100 × (1 − R)
S = E^0.60 × P^0.20 × V^0.15 × C^0.05
```

The assessment form uses professional terms for deployment context, attack
reachability, exploitation prerequisites, operational impact and firmware status.
After editing, select **Update assessment** to recalculate. The result shows
the applied A, H and U factors, risk index R and exposure safety E. It explains
when verified blocking, zero impact, a risk ceiling, or a policy cap keeps a
score unchanged.

The deployment formula check recalculates every indexed product in five input
scenarios. A numerical mismatch blocks deployment; /formula-check.json records
its source build, input fingerprint and product counts.

The largest contribution counts fully. The next two contribute 20% and 10%;
missing paths contribute zero. Only three units count. These are risk-priority
indices, not probabilities of a device being compromised.

| Factor | Rule | Evidence needed |
|---|---|---|
| T: threat | Maximum available KEV, LEV and EPSS; confirmed exploitation is 1 | Source values and capture dates |
| A: attack access | Read against the flaw's own CVSS attack vector: 1 for an established path; 0 for a verified block; unknown is [0,1] | That vector, plus whether the access it demands -- network, local or physical -- has actually been established |
| H: operational harm | Safety 1; control .8; recoverable .5; minor .2; negligible 0 | Credible consequence of this specific weakness |
| U: affected and unfixed | Affected/unpatched 1; verified fixed/not affected 0; unknown [0,1] | Selected firmware and fix evidence |

**A is read against the flaw's own attack vector.** Each weakness declares the
access it needs, so the same answer does not settle every finding. A verified
block -- `--interface blocked` -- is A=0 for any vector. A reachable affected
service -- `--interface exposed` -- answers a question about the network, so on
its own it settles A=1 only for a remotely reachable flaw, AV:N or AV:A. For
AV:L or AV:P that answer establishes neither the local execution nor the hands
on the cabinet the flaw additionally demands, so A stays [0,1] and a
verification item asks for it. Otherwise a physical-contact flaw would resolve
to fully reachable on a network answer alone, exactly like an unauthenticated
remote one. An explicit `--prerequisites satisfiable` -- an attacker can meet
what the weakness requires -- does cover local and physical access, so it
settles any vector.

**Network topology is recorded context only and never moves the score.** Select
isolated, OT-only, IT–OT, remote vendor access, direct Internet, or unknown: the
answer is kept with the assessment and shown in the record, and isolated, IT–OT
and direct Internet all produce an identical range. Topology is not a discount,
because an isolated PLC can still be reachable from a compromised OT
workstation; reachability comes from each weakness's own attack vector and the
conditions it demands, narrowed only by what the operator has verified. An
unanswered topology question is still raised for verification, since the network
owner is who the reachability question goes to. The website displays these
questions in the main assessment and comparison forms. ReTrust does not scan or
independently verify the plant network.

CVSS prerequisites are checked per finding. A no-privilege, no-interaction flaw
cannot be ruled out by declaring other prerequisites impossible. An unreadable
vector stays unresolved unless actual requirements are established.
CVSS severity is retained as context; H is not CVSS/10.
A firewall can change A, but does not count as a firmware patch in U.

Unknown factors are intervals. With T=.6, A=1, H=.8 and U=1, Z=.48 and E=52.
With U unknown, Z is [0,.48] and E is [52,100]. Adding contributions .20 and
.10 to the resolved .48 gives R=.53 and E=47. For P=70, V=80, C=60,
S = 47^.60 × 70^.20 × 80^.15 × 60^.05 = 55.80/100 (illustrative).

**VERIFY means the assessment is provisional.** The result lists missing
checks and shows the score range. A mandatory blocker still forces AVOID.
Missing threat sources are retained as unavailable, with conservative bounds;
a missing source is not a measured zero. Weight sensitivity is deferred until
material gaps close, so it cannot dress incomplete evidence up as stable approval.

Repeated advisories for one CVE form one review unit; all citations remain.
An explicit `Finding.path_id` can group findings into a reviewed common path;
`Finding.review` retains per-finding choices, rationale and evidence. Default
CVE groups do not establish that different CVEs are independent attack paths.
The web form applies its answers to all in-scope findings: use it only where
that scope is justified. An engineer must review findings with different effects.
The tool does not infer a verified attack graph from advisory records.

The four-pillar composite uses the stated weighted product. Pillars are floored
at 1 for that calculation. Missing P, V or C evidence keeps its full weight and
enters the product at a neutral 50, never dropped and renormalized, so absent
evidence cannot raise a score above what weak evidence would give; unknown
exposure remains in the range rather than disappearing. A measured
certification participates directly.
Existing hard gates and the cap below PREFER for unfixable hardcoded credentials
still apply. Bands are PREFER ≥80, CONDITIONAL 60–79.9, AVOID <60 (scoring version RT6).
These proposal-specific weights and consequence values require validation;
they are not a NIST standard or a measured procurement accuracy guarantee.

**A banded verdict reached through operator answers names them.** Site answers
are assertions ReTrust cannot verify, so a PREFER, CONDITIONAL or AVOID that
rests on them carries an "assertions" list and a note beside the verdict:
"This PREFER rests on operator assertions ReTrust cannot verify: ... On the
published evidence alone this product is VERIFY, 5.9-92.8/100." The
evidence-only range is computed with every assertion withdrawn, so the reader
sees exactly what the answers bought. JSON and CSV exports carry the same
`assertions` field, so a stored decision record keeps the attribution.

**`applied` and `not_affected` zero U only against a checked firmware
version.** "Fix verified present on this firmware" names a firmware. Without a
supplied version the claim resolves nothing: U stays an interval, and the U
verification item asks for the version instead. A dropdown answer alone cannot
clear applicability for every finding.

**A certificate with zero advisory findings is NOT ASSESSED, never banded.**
Certification is assurance, not risk evidence, and with no advisory record to
weigh it against it cannot carry a verdict on its own. Found live: a product
with no findings and one vendor certificate rendered PREFER 85.0, which is
absence of data reading as safety -- the exact inversion this tool exists to
prevent. The result now says so in its notes instead of banding.

**Rankings order verdicts PREFER, CONDITIONAL, VERIFY, AVOID, NOT ASSESSED.**
`compare`, `alternatives` and the web interface all sort this way. AVOID sits
below VERIFY because a disqualified product must never outrank one that merely
needs its checks finished: VERIFY is unfinished work, not a worse answer.
NOT ASSESSED stays last for the usual reason -- no evidence must not read as
safety.

**The `score` exit code depends on who is reading.** At the terminal the
default exits 2 on VERIFY or NOT ASSESSED, so an incomplete assessment cannot
pass silently through a script that never read the table. With `--json` the
default is 0, because a pipeline that asked for JSON parses the verdict
itself. An explicit `--fail-on` wins identically in both modes.

### The facts only you have

| Input | Choices | Effect |
|---|---|---|
| `--assessment-type` | `purchase`, `installed` | Records the review context |
| `--network-exposure` | `isolated`, `ot_only`, `it_ot`, `remote_vendor`, `internet_ot` | Recorded context only; never moves the score, and unknown still requires verification |
| `--interface` | `exposed`, `blocked`, `unknown` | `blocked` is a verified block for any vector; `exposed` settles only an AV:N or AV:A flaw, otherwise a range |
| `--prerequisites` | `satisfiable`, `unsatisfiable`, `unknown` | Checks conditions recorded by each CVSS vector; `satisfiable` also affirms local or physical access |
| `--consequence` | `safety`, `control`, `recoverable`, `minor`, `negligible` | Credible OT harm; unknown produces a range |
| `--remediation` | `affected`, `available`, `applied`, `not_affected`, `mitigated`, `planned`, `unknown` | Verified firmware applicability; protective controls do not patch it |

Batch CSV and JSON can supply the same six site fields per candidate:
`network_exposure`, `assessment_type`, `interface`, `prerequisites`,
`consequence`, and `remediation`. Omitted answers stay unknown; invalid values
are refused. Add verified context before using `--fail-on unassessed` to approve
a procurement list. Example files without site evidence deliberately need review.

JSON schema 3 includes `score_min`, `score_max`, `exposure_min`, `exposure_max`,
`provisional`, `verification`, and full per-unit factors under `paths` in detail
exports. CSV retains the ranges and verification actions. `--fail-on unassessed`
returns exit 2 for VERIFY, so a pipeline can reject incomplete assessments.
Scoring vectors begin `RT6`. RT4 and earlier results must be reassessed under
this decision policy. The exposure formula and weights are unchanged; the gate
now follows assessed firmware applicability, rather than vendor patch availability.
Conflicting reviewed path IDs for one CVE are rejected before scoring.

The question “Could an attacker meet the conditions needed to exploit it?” asks
whether exploitation is possible, not whether extra conditions exist. A technical
review can answer no; unknown attack requirements stay unknown.

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

The vector identifies the access type and required conditions. Actual feasible
access is 1, a verified block is 0, and unresolved access is [0,1]. The access
type also decides which answer can settle A: a reachable service resolves a
network or adjacent flaw, and nothing in the 1.8% that needs physical
contact. Physical access is not automatically a tenth of network access; it is a
different question, left open until somebody answers it. The severity diagnostic
retains peak CVSS and critical share, without multiplying CVSS into OT harm.

`retrust ssvc --automatable auto` derives SSVC's Automatable from the vectors and
shows its working. SSVC does not define that metric as a function of CVSS, so it
is offered as a suggestion for a human to accept, never as the answer.

### Do the weights actually matter?

`retrust sensitivity` samples pillar weights only after material inputs are
resolved. An incomplete assessment reports VERIFY and does not run the weight
check. With resolved inputs, it reports the most common verdict and the score
spread. A mandatory blocker decides the verdict without sampling.
Weight stability does not establish that site assertions or public records are correct.

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
  submitted, so absence says nothing. A measured certificate participates directly in the weighted product.
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
listed in KEV have a median EPSS of **0.72** against **0.0076** for OT CVEs
overall, roughly a 94× separation. Two independently built sources pointing the
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
  no digest shipped                   0

ORIGIN    who signed it?
  signature verified                  0
  signature failed                    0
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
| FIRST EPSS | exploitation probability, covers 99.75% of OT CVEs | daily CSV |
| ISASecure | IEC 62443-4-1/4-2/3-3 certificates | scraped listings |
| Common Criteria | Published certified products | official CSV |
| Consolidated Screening List | 26,159 sanctioned/restricted entities | trade.gov CSV |
| FCC Covered List / NDAA §889 | named covered entities | curated, cited in-repo |

Vendors that run their own CSAF feed (Siemens, Schneider, ABB, Hitachi Energy
and others, verified via the BSI CSAF aggregator) are used as a *signal* in the
vendor-practice pillar. ReTrust does not yet ingest those feeds directly;
CISA's repository already mirrors most of their advisories.

## Development

```bash
python3 -m pytest tests/ -q      # 943 tests, no network needed
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

Current CLI and web results record the RT6 model and a source-code fingerprint.
Their data token hashes the complete database plus the certification and screening
lists; it is distinct from the older count/date provenance token. JSON and CSV
retain these identifiers, and comparisons warn when the model or tool build differs.
Weights and detailed evidence remain in the assessment reports. Keep the code,
configuration and data snapshot together to reproduce a decision.

`retrust snapshot` bundles the index and both auxiliary lists into one checksummed
ZIP. Restore verifies every file before replacing live data. The manifest has its
own 1 MiB expanded limit and also counts against the 500 MiB archive budget.

## Does the score predict anything?

The fresh 20 October 2026 backtest uses a 2022-01-01 cutoff and 100 seeded
permutations. It does not validate prediction of real-world compromise.

| Diagnostic | Products | Spearman rho |
|---|---:|---:|
| Score versus later CVE disclosure | 5,848 | +0.484 |
| Within vendor (19 vendors) | 3,796 | +0.340 |
| Within vendor, excluding Siemens | See raw results | +0.110 |

Pooled and within-vendor permutation p-values are 0.010 at 100 shuffles. The
weakening positive association is consistent with disclosure/exposure effects,
but does not prove a causal explanation. Only two products across two vendors
qualify for the later-KEV outcome. That is too sparse for an
exploitation-rate claim.

The current snapshot covers one cutoff. Run `retrust backtest --sweep` to explore
other dates; earlier sweep figures are not current release measurements.
See [benchmark methods and raw evidence](benchmark-report.md).

```sh
retrust backtest --cutoff 2022-01-01 --permutations 100 --json results.json
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
