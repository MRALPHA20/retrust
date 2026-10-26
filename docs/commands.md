# Commands and workflows

[Documentation index](README.md) · [Project overview](../README.md)

Commands use the same assessment engine as the browser. Run them from the
repository root with `python3 -m retrust.cli`, or install the shorter command:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
```

The `retrust` commands below also work without installation when replaced with
`python3 -m retrust.cli`. Use `retrust --help` or `retrust COMMAND --help` for
the complete flags and accepted values.

## Three ways to drive it

| | |
|---|---|
| `retrust score ...` | commands with flags, for engineers and pipelines |
| `retrust shell` | a menu that asks instead — no flags to remember, prints the equivalent command each time |
| `retrust serve` | the same assessments, timelines and RFQ annexes as pages on `127.0.0.1`, for whoever signs the purchase order |

Start with `retrust search <anything>` if you don't know the exact spelling —
misspellings return a shortlist instead of nothing.

### Interactive terminal

Run `python3 -m retrust.cli shell`. Type `search`, `score`, `order`, `compare`,
`vendor`, `batch`, `alternatives`, `lev`, `ssvc`, `diff`, `timeline`, `questions`,
`save`, or `quit`. The old numeric choices still work.

The terminal uses cyan section headings, verdict colors and pillar bars. Full
product names and evidence wrap to the terminal width. `save` exports the last
assessment as HTML, JSON or CSV; JSON retains its query for `diff` later.
`--no-color`, `NO_COLOR`, and redirected output keep the text free of ANSI colors.
Terminal background and fonts follow your terminal's own settings.

## Take a shortlist from review to a decision record

In the browser, **Compare candidates** accepts a manufacturer order number or
vendor/model for each row, plus optional firmware. Exact order-number searches
and **Compare this product** retain that identifier in the next assessment.

Download the complete comparison as HTML, JSON or CSV. HTML includes the ranked
results, original inputs, scoring weights and source provenance. JSON preserves
each query for later `retrust diff`; CSV includes query columns for spreadsheet
review. A mixed-firmware warning flags candidates assessed on different scopes.
Downloads are generated from the current local index when requested.

## Command reference

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
| `lev` | review cumulative exploitation estimates (NIST CSWP 41); estimates do not confirm exploitation |
| `score` | assess one product |
| `compare` | rank candidates for one decision |
| `batch FILE` | score a bill of materials or a CycloneDX SBOM, with a CI exit code |
| `vex` | write the assessment as a CycloneDX VEX document: SBOM in, VEX out |
| `cve CVE-...` | one CVE, everything the index knows about it |
| `sensitivity` | how much a verdict depends on the weights |
| `eval` | reproduce the accuracy figures, buyer-query set included |
| `backtest` | did the score predict later disclosure? `--sweep` for five cutoffs |
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

## Checks and deployment

`make test` runs the automated suite without fetching live sources. After
`retrust setup`, `make smoke` exercises the real local index and `make
formula-check` validates the formula across indexed products.

See [contributing](../CONTRIBUTING.md) for development and
[Render deployment](render-deployment.md) for `make deploy` and `make live`.
