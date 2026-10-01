# ReTrust: Arsenal submission draft

Updated 28 September 2026. Target: Black Hat Arsenal. Confirm the chosen event's current submission deadline, eligibility, required fields and demonstration rules before submitting. This document does not indicate acceptance or submission.

## Title

ReTrust: OT procurement decisions from public security evidence

## Short description

Review industrial hardware before buying it. ReTrust resolves manufacturer order numbers and product names against public advisories, applies explicit gates, and exports a traceable comparison for the procurement record.

## Abstract

An OT purchase requisition commonly contains a manufacturer, model, order number and proposed firmware before a device exists on the buyer's network. Reviewing its advisories, exploitation signals, remedies and supplier evidence separately makes a shortlist difficult to assess consistently.

ReTrust brings those inputs into a local procurement workflow. It indexes CISA OT CSAF advisories, resolves a candidate by order number or normalized product name, filters affected ranges where firmware is known, and produces an evidence-backed verdict. Five weighted pillars cover exploitation, severity, patch availability, vendor practice and certification. Hard gates surface disqualifying evidence even when the composite score would otherwise look favorable. Unresolved queries receive no numeric score, and uncertain version ranges remain visible and in scope.

The demonstration uses the browser workspace and interactive terminal to compare candidates, explain a known-exploitation gate, inspect uncertainty, generate supplier questions and export a record. The core assessment runs offline after data acquisition, with no third-party Python runtime dependencies.

ReTrust includes reproducible evaluation commands and publishes the limits of its measurements. On the current local corpus, a 4,000-query internal round-trip benchmark recovers the source advisory with 99.85% precision and 99.70% recall. It does not penalize extra matches, so this is not general matching-accuracy validation. A historical backtest does not establish prediction of compromise. The tool organizes current public evidence for a buyer's review; it complements operational scanners, inventory tools and firmware analysis.

Relative to prior art: CISA's advisory pages answer one advisory at a time with no scoring or firmware awareness, and commercial asset-risk platforms (Claroty, Nozomi, Dragos) score equipment already deployed, from traffic they already observe. ReTrust works at the other end of the lifecycle -- procurement time -- and its distinct contribution is order-number resolution off a requisition, firmware-aware range filtering, and a transparent, user-editable weighting a reviewer can argue with. An official-source capability comparison is included in the documentation.

## Demonstration, approximately five minutes

1. Explain the requisition: vendor, model, order number and firmware.
2. Compare ABB AC 800M and Moxa EDS-405A; inspect pillars and missing evidence.
3. Assess Siemens order `6ES7518-4AX00-1AB0`, firmware `3.1.6`, and explain the known-exploitation gate.
4. Show an unresolved query and a firmware range uncertainty.
5. Export evidence and supplier questions; show evaluation and provenance.

Use [the demo runbook](demo-runbook.md) for operational checks. Scores depend on the snapshot and weights; never describe them as probabilities of compromise.

## Evidence available for reviewers

- 3,937 advisories, 28,951 product entries, 12,061 distinct CVEs in the measured local index.
- Version-range coverage: 94.91%; eligible-range coverage: 96.80%.
- Authored buyer queries: 20/21. This is a small internal set.
- Latest functionality verification: 775 automated tests and 89 real-data smoke checks passed.
- Median local assessment time: approximately 505 ms for ABB AC 800M; shared-machine conditions apply.
- [Methods and raw measurements](benchmark-report.md), [official-source tool comparison](tool-comparison.md), [PDF overview](ReTrust-Guide.pdf), [QA review](qa-review.md).

## Boundaries

No live network scanning, traffic monitoring, identity attack-path collection or firmware binary analysis. No validated prediction of compromise. Vendor-family matches, missing evidence, screening scope and certification scope require analyst review. The browser service is intended for a local workstation and has no multi-user authentication.

## Information to complete before submission

Presenter names, affiliations, biographies and contact details; selected event; current public repository/release URL; demo video if required; booth/network requirements; acknowledgment of the event's current terms. Verify the release can be installed from a fresh checkout and that the demo snapshot is legally distributable.
