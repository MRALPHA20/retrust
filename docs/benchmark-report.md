# ReTrust benchmark report

Measured 28 September 2026 against 3,937 advisories and 28,951 product entries. Accuracy and coverage figures were re-checked unchanged on 20 October 2026, when the historical diagnostic was re-measured under the RT4 scoring model. These are internal measurements, not independent accuracy validation or a comparison against competing tools.

## Resolution and range coverage

| Measurement | Result |
|---|---:|
| Ranges decided | 27,193 / 28,651 (94.91%) |
| Coverage after excluding 559 serial/revision/date-dependent ranges | 27,193 / 28,092 (96.80%) |
| Unhandled ranges | 899 |
| Source-advisory recovery precision | 3,988 / 3,994 answered (99.85%) |
| Source-advisory recovery recall | 3,988 / 4,000 attempted (99.70%) |
| Authored buyer queries | 20 / 21 (95.24%) |

The deterministic round-trip sample comes from the same corpus used by the resolver. Queries remove parenthetical text and punctuation, lowercase names and retain their first four words. **The original order number is also supplied when available.** Success means the originating advisory is among the returned matches. Extra incorrect matches are not separately penalized. Six answered queries missed their source and six abstained.

By method: order number 1,334/1,334; normalized name 2,617/2,623; token subset 37/37. The small authored buyer set is not an independent holdout; its known miss is “Belden RS switches,” which abstains. Range coverage measures parser decisions, not correctness against independently labeled affected firmware. Confidence values are heuristic, not calibrated probabilities.

## Identifier coverage

CPE occurs on 60 entries (0.21%). Declared order numbers occur on 8,211 (28.36%); recovered numbers add 1,364 (4.71%), totaling 9,575 (33.07%). Declared order numbers are about 137 times more available than CPE **in this corpus**. This does not measure scanners' identifier coverage, fingerprinting accuracy or performance.

## Runtime

| Local command | Median | P95 |
|---|---:|---:|
| Search S7-1500 | 158.94 ms | 182.89 ms |
| Assess ABB AC 800M | 504.63 ms | 542.52 ms |
| Assess Siemens by order number | 507.79 ms | 530.17 ms |
| Compare ABB/Moxa, 300 samples | 544.69 ms | 570.74 ms |

Twenty serial fresh CLI processes per case, after one warm-up; warm OS cache; stdout discarded; wall time includes startup. P95 uses nearest rank. Shared Linux 6.18.12 development machine, AMD Ryzen 5 5500U, 12 logical CPUs, Python 3.13.9; 43,016,192-byte database (the 28 September snapshot — latency has not been re-measured against the current 42,258,432-byte database). These are neither concurrent-load measurements nor cross-tool benchmarks. Commands and environment are retained in [latency.json](benchmarks/latency.json).

## Historical diagnostic

At the 2022-01-01 cutoff, 5,848 products were scored from pre-cutoff advisories. With 1,000 seeded permutations, score versus later CVE disclosure has Spearman rho **+0.484** (p=0.001). Within the vendor strata — 3,796 products across the 19 vendors with enough products to compare; 39 vendors with no score or outcome variation were dropped — pooled rho is **+0.340** (p=0.001); excluding Siemens leaves **+0.110**. (Figures re-measured 20 October 2026 under the RT4 scoring model. 5,823 of the 5,848 pre-cutoff assessments would need verification; the correlations use their conservative score endpoints, not completed procurement assessments.) Leaving Siemens out attenuates the correlation sharply rather than reversing it: that vendor bundles hundreds of upstream CVEs into single advisories and dominates any count-based outcome, so vendor concentration still carries much of the pooled figure, and the per-vendor direction is mixed (17 positive, 2 negative). The score is not merely re-reading past volume — its correlation with CVEs already known at the cutoff is +0.156, while past volume predicts future volume at +0.184 — but a higher score going with more later CVEs remains consistent with disclosure/exposure effects and does not establish causation. Only two products across two vendors qualify for the later-KEV outcome.

This does not validate prediction of compromise. The current run covers one cutoff; the historical multi-cutoff figures have not been rerun for this release. Current evidence support and future risk prediction are different claims.

## Reproduce

```sh
python3 -m retrust.cli eval --sample 4000 --json evaluation.json
python3 -m retrust.cli backtest --cutoff 2022-01-01 --permutations 1000 --json backtest.json
python3 tools/benchmark_latency.py --output latency.json
python3 -m pytest -q
bash smoke.sh
```

The latest functionality verification, 20 October 2026, recorded 943 passing automated tests and 94 passing real-data smoke checks, including regression guards against injection, SSRF and decompression-bomb inputs. See [QA review](qa-review.md) for an earlier dated run. Full benchmark evidence: [evaluation JSON](benchmarks/evaluation.json), [evaluation text](benchmarks/evaluation.txt), [backtest JSON](benchmarks/backtest.json), [backtest text](benchmarks/backtest.txt). The retained backtest files predate the 20 October re-measurement; the historical-diagnostic figures above come from a fresh run of the command listed.

Database SHA-256: `a78fb59eac1ef2bb1a44a77902f857120239a994e18f6db6258b7e4f0c4c86ab`.

Next validation should use independently labeled product/version pairs, count extra returned matches, evaluate abstention quality and involve procurement users. Source freshness and corpus composition can change every result.
