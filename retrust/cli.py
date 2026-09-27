"""Command line interface.

    retrust ingest  --csaf DIR [--kev F] [--epss F]   build the local index
    retrust stats                                     what is in the index
    retrust score   --vendor V --product P [--version X] [--order-number N]
    retrust compare --candidate "V|P|VER" ...         rank candidate products
    retrust refresh                                   fetch certification + sanctions data
    retrust sensitivity --vendor V --product P         does the verdict depend on weights?
    retrust config [--init]                           show or create scoring weights
    retrust snapshot [--restore F]                    pin data into one portable file
    retrust demo                                      run everything end to end
    retrust batch  candidates.csv --json out.json     score a whole BOM, CI-friendly
    retrust screenshot report.html --both-themes      render a report to PNG
    retrust eval                                      reproduce the accuracy figures

Every command works offline against the index built by `ingest`, so results are
reproducible and a demo never depends on the network.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .index import normalize_vendor
from . import (batch, certification, config, evaluate, index, match, report,
               score, screenshot, sensitivity, snapshot, supplychain)

DEFAULT_DB = "data/retrust.db"


def _open(path):
    if not Path(path).exists():
        sys.exit(f"No index at {path}. Run:  retrust ingest --csaf <dir>")
    try:
        connection = index.connect(path)
        connection.execute("SELECT COUNT(*) FROM advisory").fetchone()
    except Exception as error:
        sys.exit(f"{path} is not a usable ReTrust index ({error}). "
                 f"Rebuild it with:  retrust ingest --csaf <dir>")
    return connection


def _context(data_dir="data", config_path=None):
    """Load the supplementary sources and scoring configuration once per run."""
    weights, bands, source = config.load(config_path)
    return {"screening": supplychain.load(data_dir),
            "certificates": certification.load(data_dir),
            "weights": weights, "bands": bands, "config_source": source}


def _assess(connection, vendor, product, version, order_number, label=None, context=None):
    """Resolve, collect findings, and score. Shared by `score` and `compare`."""
    context = context or _context()
    resolution = match.resolve(
        connection, vendor=vendor, product=product, order_number=order_number)
    findings = match.findings(connection, resolution, version=version)
    advisories = {f.advisory_id for f in findings}

    # The vendor the advisory names is more reliable than what the buyer typed,
    # but fall back to the typed one so screening still runs when nothing matched.
    effective_vendor = (resolution.matches[0].vendor if resolution.matches else vendor)
    screening_gates = supplychain.gates_for(context["screening"], effective_vendor)
    screening_notes = supplychain.notes_for(context["screening"], effective_vendor)
    certificates = certification.certificates_for(
        context["certificates"], effective_vendor, product)

    if not label:
        # When only an order number was given we have no name to show, so take
        # the one the advisory uses.
        if not (vendor or product) and resolution.matches:
            first = resolution.matches[0]
            label = f"{first.vendor} {first.name}".strip()
        else:
            label = " ".join(filter(None, [vendor, product])) or (order_number or "product")
        if version:
            label += f" (firmware {version})"

    if screening_gates:
        return (score.blocked(label, screening_gates, resolution.reason
                              if not resolution.resolved else ""),
                resolution, findings)

    if not resolution.resolved:
        return score.not_assessed(label, resolution.reason), resolution, findings

    assessment = score.assess(label, findings, advisories,
                              weights=context.get("weights"),
                              bands=context.get("bands"),
                              certificates=certificates, screening_gates=screening_gates,
                              vendor_key=normalize_vendor(effective_vendor or ""))
    assessment.notes.extend(screening_notes)
    assessment.inputs = (findings, advisories, certificates, screening_gates,
                         normalize_vendor(effective_vendor or ''))
    return assessment, resolution, findings


def _emit_json(path, payload):
    """Write JSON to a file, or to stdout when the path is "-"."""
    text = batch.dumps(payload)
    if path == "-":
        print(text)
        return None
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text, encoding="utf-8")
    return destination


def _write_html(path, markup):
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(markup, encoding="utf-8")
    print(f"\nReport written to {destination}")


def cmd_ingest(args):
    print(f"Reading CSAF advisories from {args.csaf} ...")
    connection, counts = index.build(args.db, args.csaf)
    print(f"  {counts['advisories']:,} advisories, {counts['products']:,} products, "
          f"{counts['cve_links']:,} CVE links")

    if args.kev or args.epss:
        loaded = index.load_exploitation(connection, args.kev, args.epss)
        print(f"  KEV {loaded['kev']:,} entries, EPSS {loaded['epss']:,} scores")

    print(f"\nIndex written to {args.db}")
    for key, value in index.stats(connection).items():
        print(f"  {key:<15} {value:,}")


def cmd_stats(args):
    for key, value in index.stats(_open(args.db)).items():
        print(f"  {key:<15} {value:,}")


def cmd_score(args):
    connection = _open(args.db)
    context = _context(config_path=getattr(args, "config", None))
    assessment, resolution, findings = _assess(
        connection, args.vendor, args.product, args.version, args.order_number,
        context=context)

    stability = None
    if args.json and not args.no_sensitivity and getattr(assessment, "inputs", None):
        stability = sensitivity.stability(*assessment.inputs, samples=args.samples,
                                          bands=context["bands"])

    if args.json:
        detail = batch.to_detail(assessment, resolution, findings, stability)
        written = _emit_json(args.json, batch.envelope([detail], {
            "weights": context["weights"], "config": context["config_source"],
            "provenance": index.provenance(connection)}))
        # Quiet on stdout when JSON went there, so the output stays parseable.
        if written:
            print(f"JSON written to {written}")
        return batch.exit_code([detail], args.fail_on)

    exit_status = batch.exit_code(
        [batch.to_record(assessment, resolution)], args.fail_on)

    # A screening gate decides the verdict even when the product never resolved,
    # so check the assessment rather than the resolution.
    if assessment.verdict == "NOT ASSESSED":
        print(f"NOT ASSESSED  {assessment.product}  (no score -- see below)")
        print(f"  reason: {resolution.reason}")
        print("\nReTrust abstains rather than guessing. Try the manufacturer's "
              "order number, or check the vendor spelling with `retrust stats`.")
        return 2

    score_text = "no score" if assessment.score is None else f"{assessment.score}/100"
    print(f"{assessment.verdict}  {score_text}   {assessment.product}")
    if resolution.resolved:
        print(f"  matched by {resolution.method} (confidence {resolution.confidence:.2f}), "
              f"{len(resolution.matches)} advisory product(s), {len(findings)} CVE(s)")

    for gate in assessment.gates:
        print(f"\n  HARD GATE: {gate['gate']}\n    {gate['detail']}\n    source: {gate['source']}")

    print()
    for pillar in assessment.pillars:
        print(f"  {pillar.name:<18} {pillar.score:5.1f}   coverage {pillar.coverage:4.0%}")
        for line in pillar.evidence:
            print(f"      - {line}")
    for note in assessment.notes:
        print(f"\n  NOTE: {note}")

    if args.html:
        _write_html(args.html, report.render(
            [(assessment, resolution, findings)], title=assessment.product,
            weights=context["weights"], config_source=context["config_source"],
            provenance=index.provenance(connection)))
    return exit_status


def cmd_compare(args):
    connection = _open(args.db)
    context = _context()
    blocks = []
    for raw in args.candidate:
        parts = [p.strip() for p in raw.split("|")]
        vendor, product = parts[0], parts[1] if len(parts) > 1 else None
        version = parts[2] if len(parts) > 2 else None
        order_number = parts[3] if len(parts) > 3 else None
        blocks.append(_assess(connection, vendor, product, version, order_number,
                              context=context))

    # NOT ASSESSED ranks below AVOID: an unknown is not a recommendation.
    rank = {"PREFER": 0, "CONDITIONAL": 1, "AVOID": 2, "NOT ASSESSED": 3}
    blocks.sort(key=lambda b: (rank.get(b[0].verdict, 4), -(b[0].score or 0)))

    stabilities = {}
    if not args.no_sensitivity:
        for assessment, _, _ in blocks:
            if inputs := getattr(assessment, "inputs", None):
                stabilities[assessment.product] = sensitivity.stability(
                    *inputs, samples=args.samples, bands=context["bands"])

    quiet = args.json == "-"
    width = max(len(b[0].product) for b in blocks)
    if not quiet:
        print(f"{'CANDIDATE':<{width}}  VERDICT       SCORE  CVES  ROBUST  NOTES")
    for assessment, resolution, _ in blocks:
        # A gate is why the verdict is what it is, so it outranks the
        # resolution reason in the summary line.
        note = (assessment.gates[0]["gate"] if assessment.gates
                else "" if resolution.resolved else resolution.reason)
        shown = "  --  " if assessment.score is None else f"{assessment.score:>5}"
        count = "  - " if assessment.score is None else f"{assessment.findings_count:>4}"
        st = stabilities.get(assessment.product)
        robust = "  -   " if st is None else (
            " gated" if st.gated else f"{st.agreement:>5.0%} ")
        if not quiet:
            print(f"{assessment.product:<{width}}  {assessment.verdict:<12}  "
                  f"{shown}  {count}  {robust}  {note[:40]}")

    unstable = [] if quiet else [p for p, st in stabilities.items()
                                 if not st.gated and not st.robust]
    if unstable:
        print("\nROBUST is the share of random weightings giving the same verdict.")
        print("Below 90% the choice depends on how you weigh the pillars:")
        for product in unstable:
            print(f"  {product}: {stabilities[product].summary()}")

    if not quiet:
        print(f"\nWeights from {context['config_source']}. "
              f"Run `retrust config --init` to change them.")

    if args.html:
        _write_html(args.html, report.render(
            blocks, title="Procurement comparison",
            stabilities=stabilities, provenance=index.provenance(connection),
            weights=context["weights"], config_source=context["config_source"]))

    records = [batch.to_record(a, r, stabilities.get(a.product))
               for a, r, _ in blocks]
    if args.json:
        written = _emit_json(args.json, batch.envelope(records, {
            "candidates": len(records), "weights": context["weights"],
            "config": context["config_source"],
            "provenance": index.provenance(connection)}))
        if written:
            print(f"JSON written to {written}")
    return batch.exit_code(records, args.fail_on)


def cmd_config(args):
    if args.init:
        print(f"Wrote {config.write_template(args.file)}. Edit the weights and re-run.")
        return 0
    weights, bands, source = config.load(args.file)
    total = sum(weights.values())
    print(f"Scoring configuration from {source}\n")
    print(f"  {'pillar':<18} {'weight':>8} {'share':>8}")
    for key, value in weights.items():
        print(f"  {key:<18} {value:>8.3f} {value / total:>7.1%}")
    print(f"\n  bands: PREFER >= {bands[0][0]}, CONDITIONAL >= {bands[1][0]}, else AVOID")
    if source == "built-in defaults":
        print("\nNo config file found. `retrust config --init` writes an editable one.")
    return 0


def cmd_sensitivity(args):
    """How much does this verdict depend on the weights?"""
    connection = _open(args.db)
    context = _context(config_path=args.config)
    assessment, resolution, _ = _assess(
        connection, args.vendor, args.product, args.version, args.order_number,
        context=context)

    print(f"{assessment.verdict}  {assessment.product}\n")
    if not (inputs := getattr(assessment, "inputs", None)):
        print(f"  Not scored: {resolution.reason}")
        return 2

    result = sensitivity.stability(*inputs, samples=args.samples,
                                   bands=context["bands"])
    print(f"  {result.summary()}")
    if not result.gated:
        print(f"  score across {result.samples} random weightings: "
              f"{result.score_min} to {result.score_max} (median {result.score_median})")
        print("\n  verdict distribution:")
        for verdict, count in sorted(result.verdicts.items(), key=lambda kv: -kv[1]):
            bar = "#" * round(40 * count / result.samples)
            print(f"    {verdict:<12} {count / result.samples:>5.0%}  {bar}")

    print("\n  where the points went (largest loss first):")
    print(f"    {'pillar':<20} {'score':>6} {'weight':>7} {'gave':>7} {'lost':>7}")
    for row in sensitivity.contributions(assessment, context["weights"]):
        print(f"    {row['pillar']:<20} {row['score']:>6.1f} {row['weight']:>7.2f} "
              f"{row['points']:>7.1f} {row['points_lost']:>7.1f}")
    return 0


def cmd_snapshot(args):
    """Create, inspect or restore a pinned data bundle."""
    if args.restore:
        result = snapshot.restore(args.restore, args.data)
        print(f"Restored {len(result['restored'])} file(s) into {args.data}/")
        print(f"  captured {result['created']}"
              + (f" -- {result['note']}" if result["note"] else ""))
        for row in result["provenance"]:
            print(f"    {row['captured']}  {row['source']}: {row['detail']}")
        print("\nChecksums verified. Every command now runs fully offline.")
        return 0

    if args.inspect:
        manifest = snapshot.inspect(args.inspect)
        print(f"Snapshot created {manifest['created']}"
              + (f" -- {manifest['note']}" if manifest.get("note") else ""))
        for name, meta in manifest["files"].items():
            print(f"  {name:<22} {meta['bytes'] / 1e6:>7.1f} MB  {meta['sha256'][:16]}...")
        for row in manifest.get("provenance", []):
            print(f"    {row['captured']}  {row['source']}: {row['detail']}")
        return 0

    connection = _open(args.db)
    result = snapshot.create(args.data, args.out,
                             provenance=index.provenance(connection), note=args.note)
    print(f"Wrote {result['path']} ({result['bytes'] / 1e6:.1f} MB)")
    for name in result["files"]:
        print(f"  {name}")
    print("\nCopy this one file to the demo machine and run:")
    print(f"  retrust snapshot --restore {Path(result['path']).name}")
    return 0


def cmd_batch(args):
    """Score a whole candidate list and emit machine-readable results."""
    connection = _open(args.db)
    context = _context(config_path=args.config)
    candidates = batch.read_candidates(args.input)
    print(f"Scoring {len(candidates)} candidate(s) from {args.input} ...\n")

    blocks, records, stabilities = [], [], {}
    for row in candidates:
        block = _assess(connection, row["vendor"], row["product"],
                        row["version"], row["order_number"], context=context)
        assessment, resolution, _ = block
        stability = None
        if not args.no_sensitivity and getattr(assessment, "inputs", None):
            stability = sensitivity.stability(*assessment.inputs,
                                              samples=args.samples,
                                              bands=context["bands"])
            stabilities[assessment.product] = stability
        blocks.append(block)
        records.append(batch.to_record(assessment, resolution, stability))

    rank = {"PREFER": 0, "CONDITIONAL": 1, "AVOID": 2, "NOT ASSESSED": 3}
    records.sort(key=lambda r: (rank.get(r["verdict"], 4), -(r["score"] or 0)))

    width = min(46, max(len(r["product"]) for r in records))
    print(f"{'CANDIDATE':<{width}}  {'VERDICT':<12} SCORE  NOTES")
    for record in records:
        note = (record["gates"][0] if record["gates"] else record["reason"])
        shown = "  --  " if record["score"] is None else f"{record['score']:>5}"
        print(f"{record['product'][:width]:<{width}}  {record['verdict']:<12} "
              f"{shown}  {note[:40]}")

    counts = {}
    for record in records:
        counts[record["verdict"]] = counts.get(record["verdict"], 0) + 1
    print("\n  " + ", ".join(f"{v}: {c}" for v, c in sorted(counts.items())))

    meta = {"candidates": len(candidates), "weights": context["weights"],
            "config": context["config_source"],
            "provenance": index.provenance(connection)}
    if args.json:
        print(f"  JSON  {batch.write_json(records, args.json, meta)}")
    if args.csv:
        print(f"  CSV   {batch.write_csv(records, args.csv)}")
    if args.html:
        order = {record["product"]: position
                 for position, record in enumerate(records)}
        blocks.sort(key=lambda b: order.get(b[0].product, len(order)))
        _write_html(args.html, report.render(
            blocks, title="Procurement batch review",
            stabilities=stabilities,
            provenance=index.provenance(connection),
            weights=context["weights"], config_source=context["config_source"]))

    code = batch.exit_code(records, args.fail_on)
    if code:
        print(f"\n  exit {code}: "
              + ("a candidate is disqualified" if code == batch.EXIT_AVOID
                 else "a candidate could not be assessed"))
    return code


DEMO_CANDIDATES = [
    ("ABB", "AC 800M", None, None),
    ("Schneider Electric", "Modicon M340", None, None),
    ("Rockwell Automation", "ControlLogix", None, None),
    ("Moxa", "EDS-405A", None, None),
    ("Siemens", "SIMATIC S7-1500", "3.1.6", None),
    ("Hikvision", "IP Camera", None, None),
]


def cmd_demo(args):
    """Run the whole tool end to end and leave the artefacts behind.

    One command so a station demo cannot half-fail in front of an audience, and
    so the screenshots in the documentation are always regenerated from the
    code rather than hand-updated and left to drift.
    """
    connection = _open(args.db)
    context = _context()
    out = Path(args.out_dir)

    steps = []

    def step(name, fn):
        print(f"  [{len(steps) + 1}] {name} ...", end=" ", flush=True)
        try:
            detail = fn()
            print(detail or "ok")
            steps.append((name, True, detail))
        except SystemExit as error:
            print(f"SKIPPED ({error})")
            steps.append((name, False, str(error)))

    print("ReTrust demo\n")

    blocks, stabilities = [], {}

    def build_comparison():
        for vendor, product, version, order in DEMO_CANDIDATES:
            blocks.append(_assess(connection, vendor, product, version, order,
                                  context=context))
        rank = {"PREFER": 0, "CONDITIONAL": 1, "AVOID": 2, "NOT ASSESSED": 3}
        blocks.sort(key=lambda b: (rank.get(b[0].verdict, 4), -(b[0].score or 0)))
        return f"{len(blocks)} candidates scored"

    def measure_stability():
        for assessment, _, _ in blocks:
            if inputs := getattr(assessment, "inputs", None):
                stabilities[assessment.product] = sensitivity.stability(
                    *inputs, samples=args.samples, bands=context["bands"])
        fragile = sum(1 for s in stabilities.values() if not s.robust)
        return f"{len(stabilities)} assessed, {fragile} weight-sensitive"

    def write_report():
        path = out / "comparison.html"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(report.render(
            blocks, title="Procurement comparison",
            stabilities=stabilities,
            provenance=index.provenance(connection),
            weights=context["weights"], config_source=context["config_source"]),
            encoding="utf-8")
        return str(path)

    def shoot():
        shots = screenshot.capture_both_themes(
            out / "comparison.html", args.shots, stem="comparison")
        return ", ".join(Path(s["path"]).name for s in shots)

    def accuracy():
        results = evaluate.run(connection, sample=args.eval_sample)
        version, trip = results["version"], results["round_trip"]
        (out / "accuracy.txt").write_text(
            evaluate.format_report(results), encoding="utf-8")
        return (f"{version.coverage:.2%} version coverage, "
                f"{trip.precision:.2%} resolution precision")

    step("Score the candidate set", build_comparison)
    step("Check weight robustness", measure_stability)
    step("Write the HTML report", write_report)
    step("Capture screenshots", shoot)
    step("Reproduce the accuracy figures", accuracy)

    print("\nResult:")
    width = max(len(b[0].product) for b in blocks)
    for assessment, resolution, _ in blocks:
        note = (assessment.gates[0]["gate"] if assessment.gates
                else "" if resolution.resolved else resolution.reason)
        shown = "  --  " if assessment.score is None else f"{assessment.score:>5}"
        print(f"  {assessment.product:<{width}}  {assessment.verdict:<12} "
              f"{shown}  {note[:38]}")

    failed = [name for name, ok, _ in steps if not ok]
    print(f"\n{len(steps) - len(failed)}/{len(steps)} steps completed."
          + (f" Skipped: {', '.join(failed)}" if failed else ""))
    print(f"Artefacts in {out}/ and {args.shots}/")
    return 0


def cmd_screenshot(args):
    """Render an HTML report to PNG."""
    if not screenshot.find_browser():
        sys.exit("No Chrome or Chromium found. Screenshots need one; scoring does not.")

    if args.both_themes:
        shots = screenshot.capture_both_themes(
            args.input, args.out_dir, width=args.width, full_page=not args.viewport)
    else:
        target = Path(args.out_dir) / (Path(args.input).stem + ".png")
        shots = [screenshot.capture(args.input, target, width=args.width,
                                    theme=args.theme, full_page=not args.viewport)]

    for shot in shots:
        print(f"  {shot['theme']:<7} {shot['path']}  "
              f"({shot['bytes'] / 1024:.0f} KB, {shot['browser']})")
    return 0


def cmd_refresh(args):
    """Fetch the supplementary sources that are not part of the CSAF corpus."""
    print("Refreshing certification lists (ISASecure, Common Criteria) ...")
    for key, value in certification.refresh(args.data).items():
        print(f"  {key:<22} {value}")
    print("\nRefreshing the Consolidated Screening List (~17 MB) ...")
    for key, value in supplychain.refresh(args.data).items():
        print(f"  {key:<22} {value}")
    return 0


def cmd_eval(args):
    connection = _open(args.db)
    print("Measuring against the local index. This is the number ReTrust publishes;")
    print("re-run it yourself to check it.\n")
    print(evaluate.format_report(evaluate.run(connection, sample=args.sample)))
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="retrust",
        description="Score OT hardware for cyber risk before you buy it.")
    parser.add_argument("--db", default=DEFAULT_DB, help=f"index path (default {DEFAULT_DB})")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("ingest", help="build the index from CSAF advisories")
    p.add_argument("--csaf", required=True, help="directory of CSAF JSON files")
    p.add_argument("--kev", help="CISA KEV JSON file")
    p.add_argument("--epss", help="EPSS scores CSV file")
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("stats", help="show what the index contains")
    p.set_defaults(func=cmd_stats)

    p = sub.add_parser("score", help="assess one product")
    p.add_argument("--vendor")
    p.add_argument("--product")
    p.add_argument("--version", help="firmware version, e.g. 3.1.6")
    p.add_argument("--order-number", help="manufacturer order number, e.g. 6ES7518-4AX00-1AB0")
    p.add_argument("--html", help="also write an HTML report here")
    p.add_argument("--json", metavar="FILE",
                   help='write the full assessment as JSON; "-" for stdout')
    p.add_argument("--config")
    p.add_argument("--samples", type=int, default=300)
    p.add_argument("--no-sensitivity", action="store_true")
    p.add_argument("--fail-on", choices=["avoid", "unassessed", "never"],
                   default="never",
                   help="what makes the exit code non-zero (default: never)")
    p.set_defaults(func=cmd_score)

    p = sub.add_parser("compare", help="rank candidate products for one decision")
    p.add_argument("--candidate", action="append", required=True,
                   metavar="'Vendor|Product|Version|OrderNo'",
                   help="repeatable; fields after the vendor are optional")
    p.add_argument("--html", help="also write an HTML report here")
    p.add_argument("--json", metavar="FILE",
                   help='write the ranking as JSON; "-" for stdout')
    p.add_argument("--fail-on", choices=["avoid", "unassessed", "never"],
                   default="never",
                   help="what makes the exit code non-zero (default: never)")
    p.add_argument("--no-sensitivity", action="store_true",
                   help="skip the weight-robustness check (faster)")
    p.add_argument("--samples", type=int, default=300,
                   help="weightings to sample for robustness (default 300)")
    p.set_defaults(func=cmd_compare)

    p = sub.add_parser("demo", help="run the whole tool end to end")
    p.add_argument("--out-dir", default="reports")
    p.add_argument("--shots", default="docs/screenshots")
    p.add_argument("--samples", type=int, default=300)
    p.add_argument("--eval-sample", type=int, default=1000)
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("batch", help="score a CSV or JSON list of candidates")
    p.add_argument("input", help="CSV or JSON file of candidates")
    p.add_argument("--json", help="write results as JSON here")
    p.add_argument("--csv", help="write results as CSV here")
    p.add_argument("--html", help="write an HTML report here")
    p.add_argument("--config")
    p.add_argument("--samples", type=int, default=200)
    p.add_argument("--no-sensitivity", action="store_true")
    p.add_argument("--fail-on", choices=["avoid", "unassessed", "never"],
                   default="avoid",
                   help="what makes the exit code non-zero (default: avoid)")
    p.set_defaults(func=cmd_batch)

    p = sub.add_parser("screenshot", help="render an HTML report to PNG")
    p.add_argument("input", help="HTML report to capture")
    p.add_argument("--out-dir", default="docs/screenshots")
    p.add_argument("--theme", choices=["light", "dark"], help="force a theme")
    p.add_argument("--both-themes", action="store_true",
                   help="capture light and dark")
    p.add_argument("--width", type=int, default=screenshot.DEFAULT_WIDTH)
    p.add_argument("--viewport", action="store_true",
                   help="capture only the first screen instead of the full page")
    p.set_defaults(func=cmd_screenshot)

    p = sub.add_parser("snapshot", help="pin the data into one portable file")
    p.add_argument("--out", default="retrust-snapshot.zip", help="file to write")
    p.add_argument("--data", default="data", help="data directory")
    p.add_argument("--note", default="", help="free-text note stored in the manifest")
    p.add_argument("--restore", metavar="FILE", help="unpack a snapshot instead")
    p.add_argument("--inspect", metavar="FILE", help="show a snapshot's manifest")
    p.set_defaults(func=cmd_snapshot)

    p = sub.add_parser("config", help="show or create the scoring configuration")
    p.add_argument("--init", action="store_true", help="write an editable config file")
    p.add_argument("--file", help=f"config path (default {config.DEFAULT_PATH})")
    p.set_defaults(func=cmd_config)

    p = sub.add_parser("sensitivity",
                       help="how much the verdict depends on the weights")
    p.add_argument("--vendor")
    p.add_argument("--product")
    p.add_argument("--version")
    p.add_argument("--order-number")
    p.add_argument("--config")
    p.add_argument("--samples", type=int, default=500)
    p.set_defaults(func=cmd_sensitivity)

    p = sub.add_parser("refresh", help="fetch certification and sanctions sources")
    p.add_argument("--data", default="data", help="directory to cache into")
    p.set_defaults(func=cmd_refresh)

    p = sub.add_parser("eval", help="reproduce the published accuracy figures")
    p.add_argument("--sample", type=int, default=400,
                   help="products to round-trip (default 400)")
    p.set_defaults(func=cmd_eval)

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
