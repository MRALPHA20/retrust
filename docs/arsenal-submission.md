# ReTrust: Arsenal submission draft

Updated 20 October 2026. Target: Black Hat Arsenal. Confirm the chosen event's current submission deadline, eligibility, required fields and demonstration rules before submitting. This document does not indicate acceptance or submission.

## Title

ReTrust: OT procurement decisions from public security evidence

## Short description

Review industrial hardware before buying it. ReTrust resolves manufacturer order numbers and product names against public advisories, applies explicit gates, and exports a traceable comparison for the procurement record.

## Abstract

An OT purchase requisition commonly contains a manufacturer, model, order number and proposed firmware before a device exists on the buyer's network. Reviewing its advisories, exploitation signals, remedies and supplier evidence separately makes a shortlist difficult to assess consistently.

ReTrust brings those inputs into a local procurement workflow. It indexes CISA OT CSAF advisories, resolves a candidate by order number or normalized product name, filters affected ranges where firmware is known, and produces an evidence-backed verdict. A concentrated exposure term -- threat, reachability, process impact and applicability per finding, weighted onto the worst few -- combines multiplicatively with patch availability, vendor practice and certification, so dangerous exposure cannot be averaged away by good scores elsewhere. Hard gates surface disqualifying evidence even when the composite score would otherwise look favorable. Unresolved queries receive no numeric score, and uncertain version ranges remain visible and in scope.

A deliberate division of labour runs through the inputs: ReTrust supplies the vulnerability intelligence, and the operator supplies the facts only they have -- what a compromise would cost the process, whether a vulnerable interface has been verified unreachable, and whether a fix is actually on the device rather than merely published. Each is optional, each can only narrow the assessed risk, and an unanswered question stays unresolved rather than silently becoming a best or worst case. The tool never asks a buyer to score a vendor or estimate a percentage. Every assessment carries a reproducible vector recording the scoring version, the declared context and the data snapshot, so a result can be re-run and disputed by somebody who was not in the room.

The demonstration uses the browser workspace and interactive terminal to compare candidates, explain a known-exploitation gate, inspect uncertainty, generate supplier questions and export a record. The core assessment runs offline after data acquisition, with no third-party Python runtime dependencies. Integrity is a separate, deliberate step and not a property of acquisition: `retrust setup` clones the corpus, fetches KEV and EPSS and builds the index, and checks no digest or signature on the way through. What it does carry is the evidence to check later -- CISA ships a SHA-512 digest and a detached PGP signature beside each of the 3,937 advisories, and the clone brings both along. `retrust verify` checks them on demand and reports the two separately rather than rolling them into one number, because a digest that arrived in the same clone catches corruption and tampering after download while only the signature speaks to origin. The default is honest about absence: with no signing key in a keyring, origin reads "not established" rather than failed, and the command exits 0. `--fetch-key` reads the key CISA advertises in its CSAF provider metadata, over https only, and refuses it unless the fingerprint matches the one these signatures were actually made with; `--key FILE` takes a key obtained out of band. `retrust verify --strict` is the form for a pipeline: it exits non-zero unless origin and content were positively established for every file, so a build cannot read "not checked" as "verified".

ReTrust includes reproducible evaluation commands and publishes the limits of its measurements. On the current local corpus, a 4,000-query internal round-trip benchmark recovers the source advisory with 99.85% precision and 99.70% recall. It does not penalize extra matches, so this is not general matching-accuracy validation. A historical backtest does not establish prediction of compromise. The tool organizes current public evidence for a buyer's review; it complements operational scanners, inventory tools and firmware analysis.

Relative to prior art: CISA's advisory pages answer one advisory at a time with no scoring or firmware awareness, and commercial asset-risk platforms (Claroty, Nozomi, Dragos) score equipment already deployed, from traffic they already observe. ReTrust works at the other end of the lifecycle -- procurement time -- and its distinct contribution is order-number resolution off a requisition, firmware-aware range filtering, and a transparent, user-editable weighting a reviewer can argue with. An official-source capability comparison is included in the documentation.

## Demonstration, approximately five minutes

1. Explain the requisition: vendor, model, order number and firmware. Resolve Siemens order `6ES7518-4AX00-1AB0` to show order-number identification off a requisition.
2. Compare ABB AC 800M and Moxa EDS-405A: both carry ten CVEs, and on the published evidence alone both are VERIFY -- the tool refuses a confident verdict while the material questions are open. The provisional ranges already separate the candidates: ABB at 71.6–87.7, Moxa at 50.5–92.8, so ABB's floor sits above Moxa's. Declaring the site context on each candidate (`--network-exposure it_ot --interface exposed --consequence control --prerequisites satisfiable --remediation affected`) produces banded verdicts: CONDITIONAL 75.0 against CONDITIONAL 60.5. The instructive part is that Moxa lands 14.5 points lower while having shipped every fix -- patch availability 100 against ABB's 52 -- because the flaws themselves are worse: four CVSS 9.8s at peak EPSS 0.050 against ABB's 8.4 and 7.8s at peak EPSS 0.008. Concentrated exposure carries 60% of the result, so a complete patch record cannot buy back a dangerous one. Each banded verdict names the operator assertions it rests on and what the product would be without them. This is the clearest demonstration that the tool is not counting CVEs or counting fixes.
3. Assess `Siemens` / `SIMATIC S7-1500` at firmware `3.1.6` and explain the known-exploitation gate: with no context declared the composite is only a wide provisional range, and the gate disqualifies the part anyway -- AVOID before a single question is answered.
4. Declare a deployment context on the same product -- isolated, consequence negligible -- and show the range resolve to a single higher score while the gate still holds. A declared fact narrows risk; it cannot un-disqualify a part.
5. Show an unresolved query, a firmware-range uncertainty, and the third-party bundle caution on the 1,121-CVE MFP.
6. Export evidence and supplier questions; show the assessment vector, evaluation and provenance.

Verify every step against the loaded snapshot on the day: scores move with the data and the scoring version, and step 3 in particular depends on which variant the query resolves to. Use [the demo runbook](demo-runbook.md) for operational checks. Scores depend on the snapshot and weights; never describe them as probabilities of compromise.

## Evidence available for reviewers

- 3,937 advisories, 28,951 product entries, 12,061 distinct CVEs in the measured local index.
- Version-range coverage: 94.91%; eligible-range coverage: 96.80%.
- Authored buyer queries: 20/21. This is a small internal set.
- Latest functionality verification: 961 automated tests and 94 real-data smoke checks passed, including regression guards against injection, SSRF and decompression-bomb inputs. Two of those guards exist because the thing they cover once passed without them: a forged `BADSIG` survived the whole suite until the gpg verdict tree was tested directly, and four mutations of the rendered findings table survived until its cap, ranking, non-emptiness and disclosure were asserted.
- Median assessment time: approximately 505 ms end-to-end per CLI invocation for ABB AC 800M, of which about 2 ms is the assessment itself; the remainder is interpreter start-up and opening the index. Measured 28 September 2026 under shared-machine conditions.
- [Methods and raw measurements](benchmark-report.md), [official-source tool comparison](tool-comparison.md), [PDF overview](ReTrust-Guide.pdf).
- Three self-contained explainer pages for reviewers who want the model without the code: [what it is](explainers/overview.html), [every command](explainers/commands.html), [the scoring methodology](explainers/scoring.html) with the formula worked through on a real result.

## Boundaries

No live network scanning, traffic monitoring, identity attack-path collection or firmware binary analysis. No validated prediction of compromise. Vendor-family matches, missing evidence, screening scope and certification scope require analyst review. The browser service is intended for a local workstation and has no multi-user authentication; it is read-only, serving pages over GET under a strict content-security policy with a DNS-rebinding guard, and exposes none of the commands that fetch data or change local state (`provider`, `setup`, `refresh`, `snapshot`, `ingest`). The optional hosted deployment (`RETRUST_HOSTED=1`) carries the same read-only surface, so data acquisition — and its network egress — stays command-line only and is never reachable over HTTP.

## Information to complete before submission

Presenter names, affiliations, biographies and contact details; selected event; demo video if required; booth/network requirements; acknowledgment of the event's current terms. Verify the release can be installed from a fresh checkout and that the demo snapshot is legally distributable.

**The repository is deliberately private and must stay that way until the owner
says otherwise.** Arsenal asks for a public repository or release URL, so
publishing is a decision to take consciously and at the owner's direction --
not a checklist item for anyone, human or agent, to tick off on their behalf.
Until then, leave the URL blank in the submission draft rather than opening the
repository to fill it in.
