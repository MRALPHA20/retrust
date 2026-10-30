# Where ReTrust fits

Official documentation reviewed 28 September 2026. This is a capability comparison, not a performance ranking. No competing tool was run against a shared dataset. Descriptions identify each tool's documented focus, not an exhaustive list of features or omissions.

| Tool | Documented focus | How it relates to ReTrust |
|---|---|---|
| ReTrust | Public advisory evidence for a named OT product, order number and firmware; shortlist scoring and exports | Supports procurement review before deployment; no live network discovery or firmware binary analysis |
| [Nessus](https://www.tenable.com/products/nessus) | Vulnerabilities, missing patches, configuration and compliance checks | Assess deployed systems; a different input and decision workflow from a named procurement shortlist |
| [Nozomi Guardian](https://www.nozominetworks.com/platform/guardian) | Passive OT/IoT traffic monitoring, asset inventory, vulnerabilities and threat/anomaly detection | Provides operational network visibility; ReTrust does not observe traffic or detect incidents |
| [runZero](https://help.runzero.com/docs/exposure-management/) | Discovery and exposure management through active scanning, passive inputs and integrations | Establishes what is present and exposed; discovered inventory can inform named-product review |
| [Trivy](https://github.com/aquasecurity/trivy) | Software vulnerabilities, misconfigurations, secrets and SBOM workflows | Inspects software artifacts; ReTrust importing a candidate/SBOM list is not equivalent inspection |
| [FACT](https://github.com/fkie-cad/FACT_core) | Firmware unpacking, analysis, search and comparison | Examines firmware samples; ReTrust does not discover weaknesses inside binaries |
| [BloodHound](https://bloodhound.specterops.io/get-started/introduction) | Identity relationships and attack paths, including AD/Entra and OpenGraph extensions | An adjacent security analysis workflow; ReTrust does not collect identity graphs |

ReTrust's practical distinction is its order-number-led procurement workflow, explicit abstention, local operation and exported rationale. This is not a claim of exclusive features or overall superiority. Its interface takes inspiration from clear security workspaces while retaining its own layout and visual identity.

## When to use it

Use ReTrust to compare a shortlist, inspect known exploitation and remedy evidence, prepare supplier questions and preserve the assessment. Pair it with operational discovery, configuration assessment or firmware analysis according to the evidence required.

## What a fair comparative benchmark needs

Agree on one shared task first. Use independently labeled products and firmware, pin source dates and configurations, report false matches and abstentions, and measure analyst time and resource use. Comparing ReTrust's source-advisory recovery with a scanner's device fingerprinting accuracy would compare different outcomes. The [current benchmark report](benchmark-report.md) describes only ReTrust measurements.
