# ReTrust live demo

> **At a booth, run it locally.** The hosted free-tier instance cold-starts in
> about 30 seconds and serves one request at a time; conference Wi-Fi makes
> both worse. `retrust snapshot --restore` plus `retrust serve` needs no
> network at all, and the numbers are identical because the data is pinned.


## Start the local workspace

From the repository directory:

```bash
python3 -m retrust.cli doctor
python3 -m retrust.cli serve
```

Open **http://127.0.0.1:8765/demo** for the guided walkthrough, or start on the
home page at **http://127.0.0.1:8765/**. The browser uses the same scoring code
as the CLI. Its assessments need no network once the inputs are on disk.

## A five-minute presentation

### 1. The question (30 seconds)

“Which industrial device should go on this purchase order, and what evidence
would change our decision?” Show the home page. The counts come from the
loaded database, rather than a slide or a fixed example.

### 2. Identify the hardware (one minute)

Search for `6ES7518-4AX00-1AB0`. Open the result and add the firmware version
under **Edit product, firmware, or network exposure**. Explain that the order number is
a procurement identifier and the firmware narrows the affected ranges.

Alternatively, use **Assess a product** and enter the order number directly.
A conflicting product name is refused rather than silently ignored.

### 3. Explain the evidence (one minute)

Open the ABB AC 800M example. Walk through the four scored parts -- exposure
safety, available fixes, vendor security practices and certification evidence --
and point out that attack activity and issue severity are shown beside them but
feed exposure rather than scoring twice. Evidence completeness is reported
separately and never scored. Higher scores are better; low
coverage still needs review. A missing firmware version leaves all known
affected versions in scope.

On the published evidence alone the verdict stays provisional, and the open
questions are listed with it (the browser and the CLI share the scoring code):

```bash
python3 -m retrust.cli score --vendor ABB --product 'AC 800M'
```

```
  ABB AC 800M
  VERIFY  ·  68.0–87.7/100 (provisional range)

  WHAT TO CHECK NEXT ─────────────────────────────────────────────────────────
  - Ask an operations engineer what exploiting each weakness could do to the
  process (CVE-2020-8472, CVE-2020-8473, CVE-2020-8478 and 7 more)
  - Ask the network owner whether an attacker can reach the weakness and meet
  its requirements (CVE-2020-8472, CVE-2020-8473, CVE-2020-8478 and 7 more)
  - Confirm the exact firmware and whether the published fixes are installed
  (CVE-2020-8472, CVE-2020-8473, CVE-2020-8478 and 7 more)
  - Network context has not been supplied
```

Network context (isolated, IT–OT or Internet–OT) is required before a banded
verdict is possible, but it is context only and never moves the number: this
product scores 68.0–87.7 whether you declare isolated, IT–OT or Internet–OT.
Reachability is read from each weakness's own CVSS attack vector and narrowed
only by what the operator has verified. Reporting the affected service as
reachable settles a network or adjacent flaw; for a local or physical one it
does not establish the hands-on access that flaw also demands, so the question
stays open and is asked again. The prerequisites answer covers every vector.
Consequence and remediation close the rest. Answer them all and the verdict
bands:

```bash
python3 -m retrust.cli score --vendor ABB --product 'AC 800M' \
  --network-exposure it_ot --interface exposed --consequence control \
  --prerequisites satisfiable --remediation affected
```

```
  ABB AC 800M
  PREFER  ·  72.2/100
```

with this note attached:

```
  NOTE: This PREFER rests on operator assertions ReTrust cannot verify: attack
  reachability: Reachable; exploitation prerequisites: An attacker can satisfy
  them; operational consequence: Major loss of process control; firmware
  remediation: Confirmed affected, not fixed. On the published evidence alone
  this product is VERIFY, 68.0-87.7/100. Retain supporting evidence for each
  answer before procurement.
```

Presenter note: that attribution note is the feature, not an apology -- read
it aloud. The tool reaches a verdict only on the operator's answers, says
which answers, and keeps the published-evidence range in view. The same
questions appear on the score page's edit panel.

### 4. Compare candidates (one minute)

Open the guided demo's comparison. Order number, vendor, model, and firmware each have their
own field; edit the shortlist without learning command syntax. Known-exploited
vulnerabilities can trigger an AVOID gate regardless of the weighted score.
The ranking runs PREFER, CONDITIONAL, VERIFY, AVOID, NOT ASSESSED: a
disqualified product never outranks one that still needs checks.

The supplied demo includes different equipment classes to show different
assessment outcomes. It is **not a list of functionally interchangeable
products**. Use equivalent candidates for an actual procurement decision.

### 5. Take the result away (one minute)

On a comparison, use **Download comparison report**, **Download comparison JSON**,
or **Download comparison CSV** to retain the full shortlist and its original
queries. The report includes evidence and provenance; CSV is ready for spreadsheet
review. Downloads recompute against the current local index.

On an assessment, use **Download report** for a self-contained HTML document
or **Technical data (JSON)** for the structured evidence. A verdict reached through
operator answers carries them into the record: JSON and CSV exports include an
"assertions" field, so the file shows what was asserted rather than verified.
Open **Prepare supplier questions** to produce the RFQ annex, then follow the
plain-text link for copying into a requisition.

### 6. State the limits (30 seconds)

The tool evaluates public evidence. It does not certify safety, scan a plant,
or establish that a product without advisories is secure. Unresolved products
are NOT ASSESSED. Version ranges that cannot be decided stay in scope.

The product round-trip benchmark checks that the originating advisory appears
among the matches. It does not count every spurious match. The version metric
measures parsing coverage, not correctness against independent firmware labels.
Keep these distinctions in the presentation.

## Before presenting

- Run `python3 -m pytest -q` and `python3 -m retrust.cli doctor`. On the
  shipped snapshot doctor reports every feed ok -- KEV, EPSS, EPSS history,
  screening lists and certifications were all refreshed on 20 October 2026, so
  there is no staleness warning to explain away and nothing to refresh. Still
  run it: it is the one command that tells you what the next verdict rests on,
  and feeds age, so check it again on the day.
- Exercise the examples using the exact snapshot you will present; verdicts
  and counts may change after a data refresh.
- If you script the checks, know the exit codes: a plain-terminal `score`
  exits 2 on VERIFY or NOT ASSESSED, while the default with `--json` is 0. An
  explicit `--fail-on` wins identically in both modes.
- If doctor does report a stale feed by then, refresh before the event, then
  verify the corpus with `python3 -m retrust.cli verify` and review its
  signature status. On this snapshot it reports 3,937 verified, 0 failed. Add
  `--strict` to make "not established" (no keyring, no shipped digest) a
  failure rather than a silent pass, so a signer you have not actually
  confirmed cannot slip through before the event.
- Save a snapshot with `python3 -m retrust.cli snapshot` and keep a known-good
  copy separately. A snapshot holds data; preserve any custom scoring config too.
- Keep the default loopback bind. The browser server has no authentication.
- Test projector resolution and browser zoom on the presentation machine.

## What changed in this version

Enough to know if you last presented an earlier build.

- **Bounds instead of a single number (RT4).** An assessment with open
  questions reports a range and the verdict VERIFY, not a point score. The
  range is the conservative and optimistic endpoints of the unresolved inputs,
  so a presenter can say what is known and what is assumed without guessing.
- **A banded verdict names what it rests on.** PREFER, CONDITIONAL and AVOID
  are only reached once the operator has answered, and the result lists those
  assertions and restates the evidence-only range beside them. Read that note
  aloud; it is the feature.
- **Empty findings are NOT ASSESSED.** A product that resolved but carries no
  advisory findings, with only a vendor certificate behind it, used to score
  well enough to come out PREFER. Absence of evidence is no longer treated as
  evidence.
- **Ranking puts AVOID below VERIFY.** A disqualified part cannot outrank one
  that merely still needs checks: PREFER, CONDITIONAL, VERIFY, AVOID, NOT
  ASSESSED.
- **CVE tables disclose truncation.** A report showing ten of a thousand
  findings says so, says how they were ranked, and points at the JSON export
  that carries all of them.
- **Reachability reads the flaw's own attack vector.** A verified-exposed
  interface now settles reachability only for a remotely reachable flaw
  (network or adjacent). For a local or physical flaw the network answer does
  not establish the execution or physical contact it also needs, so the
  question stays open; the prerequisites answer still settles any vector, and a
  verified block still rules a flaw out. Previously a flaw needing hands on the
  cabinet resolved to fully reachable on the network answer alone.
- **Network topology is context only.** It is required before a verdict can
  band, it is recorded in the report and the exports, and it never moves the
  score. The pillar table says "context only" in the influence column.
- **Feeds refreshed 20 October 2026.** KEV 1,748 entries, EPSS 12,031 scores,
  68 history snapshots and 12,045 LEV estimates; doctor reports every feed ok.
  Corpus counts are unchanged, and the scores moved only slightly -- ABB AC
  800M went from 68.2 to 68.0 at its floor.

Earlier reliability work still stands: remediation is indexed by affected
product including CSAF product-group scopes, so a fix for another variant does
not raise this one's score; a family assessment keeps the least repairable
applicable status; and ingestion validates a temporary database before
replacing the live index, so a bad feed or an interrupted build leaves the
working index alone. Remediation scopes follow the
[OASIS CSAF 2.0 schema](https://docs.oasis-open.org/csaf/csaf/v2.0/os/schemas/csaf_json_schema.json).
An ordinary ingest clears EPSS history and LEV estimates; reload those when
using the exploitation-history demonstration.

## Documentation and benchmark snapshot

The [PDF overview](ReTrust-Guide.pdf), [benchmark report](benchmark-report.md) and
[tool comparison](tool-comparison.md) were refreshed on 28 September 2026; the
benchmark report's accuracy and coverage figures were re-checked unchanged on
20 October 2026 under the RT4 scoring model, after the feed refresh of the same
day. The historical diagnostic was re-run on the refreshed data and is also
unchanged, because it scores on a 2022-01-01 cutoff.
Benchmark JSON/text is retained in `docs/benchmarks/`. The nine-page PDF was
rendered and every page inspected for layout, readability and overflow.
