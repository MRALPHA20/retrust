# ReTrust live demo

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
under **Edit product details and firmware**. Explain that the order number is
a procurement identifier and the firmware narrows the affected ranges.

Alternatively, use **Assess a product** and enter the order number directly.
A conflicting product name is refused rather than silently ignored.

### 3. Explain the evidence (one minute)

Open the ABB AC 800M example. Walk through exploitation, severity, patch
availability, vendor practice, and certification. Evidence quality is separate
from the weighted score. Higher scores are better; low coverage still needs
review. A missing firmware version leaves all known affected versions in scope.

### 4. Compare candidates (one minute)

Open the guided demo's comparison. Order number, vendor, model, and firmware each have their
own field; edit the shortlist without learning command syntax. Known-exploited
vulnerabilities can trigger an AVOID gate regardless of the weighted score.

The supplied demo includes different equipment classes to show different
assessment outcomes. It is **not a list of functionally interchangeable
products**. Use equivalent candidates for an actual procurement decision.

### 5. Take the result away (one minute)

On a comparison, use **Download comparison report**, **Download comparison JSON**,
or **Download comparison CSV** to retain the full shortlist and its original
queries. The report includes evidence and provenance; CSV is ready for spreadsheet
review. Downloads recompute against the current local index.

On an assessment, use **Download report** for a self-contained HTML document
or **Download JSON** for the structured evidence. Open **Prepare supplier
questions** to produce the RFQ annex, then follow the plain-text link for
copying into a requisition.

### 6. State the limits (30 seconds)

The tool evaluates public evidence. It does not certify safety, scan a plant,
or establish that a product without advisories is secure. Unresolved products
are NOT ASSESSED. Version ranges that cannot be decided stay in scope.

The product round-trip benchmark checks that the originating advisory appears
among the matches. It does not count every spurious match. The version metric
measures parsing coverage, not correctness against independent firmware labels.
Keep these distinctions in the presentation.

## Before presenting

- Run `python3 -m pytest -q` and `python3 -m retrust.cli doctor`.
- Exercise the examples using the exact snapshot you will present; verdicts
  and counts may change after a data refresh.
- If refresh is needed, do it before the event, then verify the corpus with
  `python3 -m retrust.cli verify` and review its signature status.
- Save a snapshot with `python3 -m retrust.cli snapshot` and keep a known-good
  copy separately. A snapshot holds data; preserve any custom scoring config too.
- Keep the default loopback bind. The browser server has no authentication.
- Test projector resolution and browser zoom on the presentation machine.

## Reliability changes in this version

- Remediation is indexed by affected product, including CSAF product-group
  scopes. A fix for another variant no longer raises this variant's score.
- A family assessment retains the least repairable applicable status when the
  same CVE affects multiple variants in one advisory.
- Ingestion builds and validates a temporary database before replacing the
  live index. A missing directory, empty corpus, bad feed, or interrupted build
  preserves the existing index.
- Repeated roots are deduplicated. For the same advisory ID, later roots replace
  all earlier product and vulnerability rows. Root order therefore expresses
  source precedence; put the source you intend to prefer last.
- Zero can disable one scoring pillar while leaving unspecified defaults intact.
  Non-finite configuration values are rejected.

Remediation scopes follow the [OASIS CSAF 2.0 schema](https://docs.oasis-open.org/csaf/csaf/v2.0/os/schemas/csaf_json_schema.json).
After updating from the earlier parser, rebuild the index before presenting.
An ordinary ingest clears EPSS history and LEV estimates; reload those when
using the exploitation-history demonstration.

## Documentation and benchmark snapshot

The [PDF overview](ReTrust-Guide.pdf), [benchmark report](benchmark-report.md) and
[tool comparison](tool-comparison.md) were refreshed on 28 September 2026.
Benchmark JSON/text is retained in `docs/benchmarks/`. The nine-page PDF was
rendered and every page inspected for layout, readability and overflow.
