"""Command line interface.

    retrust shell                                     interactive menu, no flags needed
    retrust serve                                     a local web interface
    retrust verify                                    are the advisories genuine?
    retrust setup                                     fetch everything, build the index
    retrust search  QUERY                             find vendors, products, order numbers
    retrust vendor  NAME                              what the index knows about a maker
    retrust diff    previous.json                     what changed since that run
    retrust alternatives --vendor V --product P       others in the same family
    retrust ssvc    --vendor V --product P --exposure open   SSVC deployer decisions
    retrust lev     --vendor V --product P            likely already exploited?
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
    retrust backtest --cutoff 2022-01-01              did the score predict the future?
    retrust eval                                      reproduce the accuracy figures

Every command works offline against the index built by `ingest`, so results are
reproducible and a demo never depends on the network.
"""

import argparse
import json
import sys
from pathlib import Path

from .index import normalize_vendor
from . import (alternatives, appetites, backtest, batch, bootstrap,
               certification, config, console, cvelookup, diff, doctor, dossier,
               evaluate, index, integrity, lev, match, questions, report, score,
               screenshot, search, sensitivity, serve, shell, snapshot, ssvc,
               supplychain, timeline, vex)

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


def _assess(connection, vendor, product, version, order_number, label=None, context=None,
            network_exposure=None):
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
                              vendor_key=normalize_vendor(effective_vendor or ""),
                              network_exposure=network_exposure)
    assessment.notes.extend(screening_notes)

    # A firmware version narrowing the scope can lower the score -- the CVEs
    # that remain on the latest firmware are precisely the unfixed ones -- and
    # read cold that looks like "more information made it worse". Show the
    # delta and the reason instead of leaving the reader to reconstruct it.
    if version and resolution.resolved:
        broad = match.findings(connection, resolution)
        if len({f.cve for f in broad}) != assessment.findings_count:
            baseline = score.assess(
                label, broad, {f.advisory_id for f in broad},
                weights=context.get("weights"), bands=context.get("bands"),
                certificates=certificates, screening_gates=screening_gates,
                vendor_key=normalize_vendor(effective_vendor or ""),
                network_exposure=network_exposure)
            moved = ("unchanged" if baseline.score == assessment.score
                     else f"moved {baseline.score} -> {assessment.score}")
            note = (f"Firmware {version} narrowed the scope from "
                    f"{baseline.findings_count} to {assessment.findings_count}"
                    f" CVE(s), and the score {moved}.")
            if (baseline.score or 0) > (assessment.score or 0):
                note += (" A narrower scope can score worse: what remains on"
                         " current firmware is exactly the set nothing fixes"
                         " yet, and that is the honest reading of it.")
            assessment.notes.insert(0, note)

    # A family query is honest about its breadth: resolving "Modicon M340"
    # reaches the platform's modules too, which a buyer comparing CPUs may
    # not want. Say so, with the spread, rather than leaving 74 products to
    # be discovered in the small print.
    if resolution.resolved and product:
        spread = {m.name_key if hasattr(m, "name_key") else m.name
                  for m in resolution.matches}
        if len(spread) > 12:
            samples = sorted({m.name for m in resolution.matches})[:3]
            assessment.notes.append(
                f"The name matched {len(spread)} distinct products across the"
                f" family (e.g. {', '.join(samples)}). If you meant one model,"
                " its manufacturer order number narrows this to exactly that"
                " device.")

    assessment.inputs = (findings, advisories, certificates, screening_gates,
                         normalize_vendor(effective_vendor or ''))
    return assessment, resolution, findings


def _query(args):
    """The four fields a product was asked for by, for re-running it later."""
    return {field: getattr(args, field, None) for field in batch.QUERY_FIELDS}


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


def _render_one(assessment, resolution, findings, context=None):
    """One assessment as text: the verdict, its gates, and every pillar.

    Shared by `score` and the interactive menu, so the two cannot drift into
    describing the same result differently.
    """
    score_text = "no score" if assessment.score is None else f"{assessment.score}/100"
    lines = [console.heading("Product assessment"), "",
             console.prose(assessment.product, style="title"),
             console.prose(f"{assessment.verdict}  ·  {score_text}",
                           style=console.VERDICT_STYLES.get(assessment.verdict))]
    if resolution.resolved:
        lines.append(console.prose(
            f"Matched by {resolution.method} (confidence {resolution.confidence:.2f})"
            f" · {len(resolution.matches)} advisory product(s)"
            f" · {len({f.cve for f in findings})} CVE(s)", style="label"))
    elif assessment.verdict == "NOT ASSESSED":
        lines += [console.prose(f"Reason: {resolution.reason}"), "",
                  console.prose("ReTrust abstains rather than guessing. Try the "
                                "manufacturer's order number or check the vendor spelling.")]
    for gate in assessment.gates:
        lines += ["", console.prose(f"HARD GATE: {gate['gate']}", style="avoid"),
                  console.prose(gate['detail'], indent="    "),
                  console.prose(f"Source: {gate['source']}", indent="    ", style="label")]
    for caution in getattr(assessment, "cautions", ()):
        lines += ["", console.prose(f"CAUTION: {caution['caution']}", style="conditional"),
                  console.prose(caution['detail'], indent="    "),
                  console.prose(f"Source: {caution['source']}", indent="    ", style="label")]
    if assessment.pillars:
        lines += ["", console.heading("Evidence by pillar")]
    for pillar in assessment.pillars:
        lines += ["", console.pillar_line(pillar)]
        lines += [console.prose(f"- {line}", indent="    ") for line in pillar.evidence]
    if assessment.notes:
        lines += ["", console.heading("Assessment notes")]
        lines += [console.prose(f"NOTE: {note}") for note in assessment.notes]
    return "\n".join(lines)


def _print_table(records):
    """The candidate summary shared by batch and the interactive menu."""
    print(console.candidates(records))


def _write_html(path, markup):
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(markup, encoding="utf-8")
    print(f"\nReport written to {destination}")


def cmd_provider(args):
    """Fetch a vendor's own CSAF feed, per the trusted-provider standard."""
    print(f"Reading {args.metadata_url} ...")
    result = bootstrap.fetch_provider(
        args.metadata_url, data_dir=args.data, force=args.force,
        progress=lambda done, skip, total:
            print(f"  {done + skip}/{total} advisories", end="\r", flush=True))
    print(f"  {result['fetched']:,} fetched, {result['already_present']:,} "
          f"already present, {result['failed']:,} failed")
    print(f"\nAdvisories in {result['directory']}.")
    print("Index them beside the CISA corpus with:\n"
          f"  retrust ingest --csaf data/CSAF --csaf {result['directory']} "
          "--kev data/kev.json --epss data/epss.csv")
    return 1 if result["failed"] and not result["fetched"] else 0


def cmd_ingest(args):
    roots = args.csaf or ["data/CSAF"]
    print(f"Reading CSAF advisories from {', '.join(roots)} ...")
    try:
        connection, counts = index.build(args.db, roots,
                                         kev_path=args.kev, epss_path=args.epss)
    except (OSError, ValueError, KeyError) as error:
        sys.exit(f"Ingest failed; existing index preserved: {error}")
    print(f"  {counts['advisories']:,} advisories, {counts['products']:,} products, "
          f"{counts['cve_links']:,} CVE links")

    if args.kev or args.epss:
        loaded = counts["exploitation"]
        print(f"  KEV {loaded['kev']:,} entries, EPSS {loaded['epss']:,} scores")

    print(f"\nIndex written to {args.db}")
    for key, value in index.stats(connection).items():
        print(f"  {key.replace('_', ' '):<15} {value:,}")

    # ingest rebuilds the database from scratch, which takes the EPSS history
    # and the LEV estimates with it. Saying so beats a later `retrust lev`
    # abstaining for a reason nobody connects to the rebuild they just ran.
    if bootstrap.history_files(Path(args.db).parent.name or "data"):
        print("\n  The EPSS history and LEV estimates were cleared by this "
              "rebuild.\n  The snapshots are still on disk, so restoring them "
              "is quick:\n    retrust lev --update")


def cmd_doctor(args):
    """Is this installation current enough to be trusted right now?"""
    checks = doctor.run(data_dir=args.data, db_path=args.db)
    print("Checking what this installation's next verdict would rest on.\n")
    print(doctor.format_report(checks))
    # Missing pieces fail the run so a cron or CI wrapper can alert; stale
    # ones only warn, because the tool still works and says what to refresh.
    return 1 if any(c.state == "missing" for c in checks) else 0


def cmd_stats(args):
    for key, value in index.stats(_open(args.db)).items():
        print(f"  {key.replace('_', ' '):<15} {value:,}")


def cmd_score(args):
    connection = _open(args.db)
    context = _context(config_path=getattr(args, "config", None))
    assessment, resolution, findings = _assess(
        connection, args.vendor, args.product, args.version, args.order_number,
        context=context, network_exposure=getattr(args, "network_exposure", None))

    stability = None
    if args.json and not args.no_sensitivity and getattr(assessment, "inputs", None):
        stability = sensitivity.stability(*assessment.inputs, samples=args.samples,
                                          bands=context["bands"],
                                          network_exposure=assessment.network_exposure)

    if args.json:
        detail = batch.to_detail(assessment, resolution, findings, stability,
                                 query=_query(args))
        written = _emit_json(args.json, batch.envelope([detail], {
            "weights": context["weights"], "config": context["config_source"],
            "provenance": index.provenance(connection)}))
        # Quiet on stdout when JSON went there, so the output stays parseable.
        if written:
            print(f"JSON written to {written}")
        return batch.exit_code([detail], args.fail_on)

    exit_status = batch.exit_code(
        [batch.to_record(assessment, resolution, query=_query(args))], args.fail_on)

    print(_render_one(assessment, resolution, findings))

    if args.html:
        _write_html(args.html, report.render(
            [(assessment, resolution, findings)], title=assessment.product,
            weights=context["weights"], config_source=context["config_source"],
            provenance=index.provenance(connection)))
    return 2 if assessment.verdict == "NOT ASSESSED" else exit_status


def cmd_compare(args):
    connection = _open(args.db)
    context = _context(config_path=args.config)
    # The query travels with its block: the ranking below reorders these, and a
    # parallel list would quietly pair each result with somebody else's query.
    scored = []
    for raw in args.candidate:
        parts = [p.strip() for p in raw.split("|")]
        query = dict(zip(batch.QUERY_FIELDS,
                         [parts[0]] + [p or None for p in parts[1:4]]))
        scored.append((_assess(connection, query["vendor"], query.get("product"),
                               query.get("version"), query.get("order_number"),
                               context=context), query))

    # NOT ASSESSED ranks below AVOID: an unknown is not a recommendation.
    rank = {"PREFER": 0, "CONDITIONAL": 1, "AVOID": 2, "NOT ASSESSED": 3}
    scored.sort(key=lambda s: (rank.get(s[0][0].verdict, 4), -(s[0][0].score or 0)))
    blocks = [block for block, _ in scored]

    stabilities = {}
    if not args.no_sensitivity:
        for assessment, _, _ in blocks:
            if inputs := getattr(assessment, "inputs", None):
                stabilities[assessment.product] = sensitivity.stability(
                    *inputs, samples=args.samples, bands=context["bands"])

    quiet = args.json == "-"
    if not quiet:
        displayed = []
        for assessment, resolution, _ in blocks:
            st = stabilities.get(assessment.product)
            displayed.append({
                "product": assessment.product, "verdict": assessment.verdict,
                "score": assessment.score, "gates": assessment.gates,
                "reason": "" if resolution.resolved else resolution.reason,
                "cves": assessment.findings_count if assessment.score is not None else None,
                "robust": "not sampled" if st is None else
                          "gated" if st.gated else f"{st.agreement:.0%}",
            })
        print(console.candidates(displayed))

    unstable = [] if quiet else [p for p, st in stabilities.items()
                                 if not st.gated and not st.robust]
    if unstable:
        print("\nROBUST is the share of random weightings giving the most common verdict.")
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

    records = [batch.to_record(a, r, stabilities.get(a.product), query)
               for (a, r, _), query in scored]
    if args.json:
        written = _emit_json(args.json, batch.envelope(records, {
            "candidates": len(records), "weights": context["weights"],
            "config": context["config_source"],
            "provenance": index.provenance(connection)}))
        if written:
            print(f"JSON written to {written}")
    return batch.exit_code(records, args.fail_on)


def cmd_config(args):
    if args.appetites:
        print(appetites.describe())
        return 0
    if args.init:
        document = appetites.template(args.appetite) if args.appetite else None
        written = config.write_template(args.file, document=document)
        opinion = (f"the {args.appetite!r} appetite" if args.appetite
                   else "the defaults")
        print(f"Wrote {written} from {opinion}. Edit the weights and re-run.")
        return 0
    if args.appetite:
        print("--appetite only means something with --init; "
              "`retrust config --appetites` lists what ships.")
        return 2
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
        context=context, network_exposure=getattr(args, "network_exposure", None))

    print(f"{assessment.verdict}  {assessment.product}\n")
    if not (inputs := getattr(assessment, "inputs", None)):
        print(f"  Not scored: {resolution.reason}")
        return 2

    result = sensitivity.stability(*inputs, samples=args.samples,
                                   bands=context["bands"],
                                   network_exposure=getattr(args, "network_exposure", None))
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
        records.append(batch.to_record(assessment, resolution, stability, row))

    rank = {"PREFER": 0, "CONDITIONAL": 1, "AVOID": 2, "NOT ASSESSED": 3}
    records.sort(key=lambda r: (rank.get(r["verdict"], 4), -(r["score"] or 0)))

    _print_table(records)

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


def cmd_backtest(args):
    """Does the score predict what actually happened next?"""
    connection = _open(args.db)
    quiet = args.json == "-"          # stdout must stay parseable

    if args.sweep:
        if not quiet:
            print("Running the decomposition at "
                  f"{len(backtest.SWEEP_CUTOFFS)} cutoffs. This scores the "
                  "whole cohort once per cutoff, so expect it to take a "
                  "while;\neach cutoff prints as it finishes.\n")
        rows = backtest.sweep(
            connection, min_history=args.min_history, limit=args.limit,
            progress=None if quiet else lambda c: print(f"  scoring at {c} ..."))
        if not quiet:
            print()
            print(backtest.format_sweep(rows))
        if args.json:
            written = _emit_json(args.json, batch.envelope(
                [vars(r) for r in rows],
                {"sweep": {"cutoffs": list(backtest.SWEEP_CUTOFFS)},
                 "provenance": index.provenance(connection)}))
            if written and not quiet:
                print(f"\nJSON written to {written}")
        return 0

    if not quiet:
        print(f"Scoring every product on advisories published before {args.cutoff},")
        print("then measuring against what was disclosed after it.\n")

    result = backtest.run(connection, cutoff=args.cutoff,
                          min_history=args.min_history, limit=args.limit,
                          permutations=args.permutations)
    matched = None
    if not args.no_matched:
        matched = backtest.matched_cohort(result, min_stratum=args.min_stratum,
                                          permutations=args.permutations)
    if not quiet:
        print(backtest.format_report(result))
        if matched:
            print()
            print(backtest.format_matched(matched))

    if args.json:
        payload = batch.envelope(
            [vars(o) for o in result.outcomes],
            {"backtest": {
                "cutoff": result.cutoff,
                "cohort": result.cohort,
                "permutations": result.permutations,
                "rho_score_vs_future_cves": round(result.rho_future, 4),
                "rho_score_vs_past_cves": round(result.rho_past, 4),
                "rho_past_vs_future_cves": round(result.rho_persistence, 4),
                "p_value": round(result.p_value, 4),
                "kev_products": result.kev_products,
                "kev_vendors": result.kev_vendors,
                "kev_outcome_measurable": result.kev_is_measurable,
                "by_band": result.by_band,
                "interpretation": backtest.interpretation(result),
                "matched_cohort": None if not matched else {
                    "usable_strata": matched.usable_strata,
                    "products": matched.products,
                    "rho_within_vendor": round(matched.rho, 4),
                    "rho_excluding_largest_vendor": round(matched.rho_without_largest, 4),
                    "largest_vendor": matched.largest_vendor,
                    "p_value": round(matched.p_value, 4),
                    "vendors_negative": matched.negative_strata,
                    "vendors_positive": matched.positive_strata,
                    "by_vendor": [vars(st) for st in matched.strata]}}})
        if written := _emit_json(args.json, payload):
            print(f"\nJSON written to {written}")
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


def cmd_search(args):
    """Look through the corpus by vendor, product name or order number."""
    connection = _open(args.db)
    query = " ".join(args.query)

    if args.order_number:
        hits = search.order_numbers(connection, query, limit=args.limit)
        print(search.format_order_numbers(hits, query))
    elif args.vendors:
        hits = search.vendors(connection, query, limit=args.limit)
        print(search.format_vendors(hits, query))
    else:
        hits = search.products(connection, query, vendor=args.vendor,
                               limit=args.limit)
        print(search.format_products(hits, query))
        # A product search that finds nothing is usually a vendor the user
        # spelled differently, so show where to look rather than stopping.
        if not hits and not args.vendor:
            if vendors := search.vendors(connection, query, limit=5):
                print()
                print(search.format_vendors(vendors, query,
                                            lead="Vendors matching that:"))
    return 0 if hits else 1


_NO_HISTORY = (
    "No EPSS history loaded, so LEV cannot be estimated.\n"
    "LEV composes a CVE's EPSS scores across its whole life; today's\n"
    "scores alone cannot produce it. Fetch the history first:\n\n"
    "  retrust lev --update\n")


def _store_lev(connection):
    """Estimate and cache LEV for every corpus CVE with history."""
    rows = list(connection.execute(
        "SELECT DISTINCT a.cve, COALESCE(e.in_kev, 0) in_kev, e.epss"
        "  FROM affected a LEFT JOIN exploitation e ON e.cve = a.cve"))
    history = index.epss_history(connection, [r["cve"] for r in rows])
    estimates = [lev.estimate(r["cve"], history[r["cve"]],
                              in_kev=bool(r["in_kev"]), current_epss=r["epss"])
                 for r in rows if history.get(r["cve"])]
    return index.store_lev(connection, estimates)


def _shell_actions(connection, context, args):
    """The interactive menu, built over the same functions the flags call.

    Each entry echoes its command line before running, so the menu teaches the
    flags rather than replacing them.
    """
    def _ask_product(reader, need_name=True):
        """Vendor and product, with search offered when nothing resolves."""
        vendor = shell.ask("Vendor", required=True, reader=reader)
        if vendor is shell.CANCELLED:
            return None
        product = shell.ask("Product", required=need_name, reader=reader)
        if product is shell.CANCELLED:
            return None
        version = shell.ask("Firmware version (optional)", reader=reader)
        return vendor, product, (None if version is shell.CANCELLED else version)

    def do_search(result, reader):
        query = shell.ask("Search for", required=True, reader=reader)
        if query is shell.CANCELLED:
            return None
        numbers = search.order_numbers(connection, query, limit=10)
        hits = numbers or search.products(connection, query, limit=10)
        shell.echo_command(["search"] + (["--order-number"] if numbers else []) + [query])
        print(search.format_order_numbers(hits, query) if numbers else
              search.format_products(hits, query))
        if not hits and (vendors := search.vendors(connection, query, limit=5)):
            print()
            print(search.format_vendors(vendors, query, lead="Vendors matching that:"))
        return None

    def do_score(result, reader):
        if not (asked := _ask_product(reader)):
            return None
        vendor, product, version = asked
        network = shell.ask("Network exposure (optional: isolated, it_ot, internet_ot)",
                            reader=reader)
        if network is shell.CANCELLED:
            network = None
        elif network:
            network = network.strip().lower()
            if network not in score.NETWORK_EXPOSURES:
                print("Choose isolated, it_ot, or internet_ot; leaving it out of the score.")
                network = None
        return score_result(vendor, product, version, network_exposure=network)

    def do_order(result, reader):
        number = shell.ask("Manufacturer order number", required=True, reader=reader)
        if number is shell.CANCELLED:
            return None
        version = shell.ask("Firmware version (optional)", reader=reader)
        if version is shell.CANCELLED:
            return None
        network = shell.ask("Network exposure (optional: isolated, it_ot, internet_ot)",
                            reader=reader)
        if network is shell.CANCELLED:
            network = None
        elif network:
            network = network.strip().lower()
            if network not in score.NETWORK_EXPOSURES:
                print("Choose isolated, it_ot, or internet_ot; leaving it out of the score.")
                network = None
        return score_result(None, None, version, number, network)

    def score_result(vendor, product, version, order_number=None, network_exposure=None):
        parts = ["score", "--order-number", order_number] if order_number else [
            "score", "--vendor", vendor, "--product", product]
        shell.echo_command(parts + (["--version", version] if version else [])
                           + (["--network-exposure", network_exposure]
                              if network_exposure else []))
        assessment, resolution, findings = _assess(
            connection, vendor, product, version, order_number, context=context,
            network_exposure=network_exposure)
        print(_render_one(assessment, resolution, findings))
        if not resolution.resolved:
            print()
            print(search.format_suggestions(
                search.suggest(connection, vendor=vendor, product=product)))
            return None
        return shell.Result(
            kind="score", blocks=[(assessment, resolution, findings)],
            records=[batch.to_record(assessment, resolution, query={
                "vendor": vendor, "product": product, "version": version,
                "order_number": order_number})],
            title=f"ReTrust assessment: {assessment.product}",
            meta={"weights": context["weights"],
                  "provenance": index.provenance(connection)})

    def do_compare(result, reader):
        print("Add candidates one at a time. Blank vendor when you are done.")
        blocks, records, names = [], [], []
        while True:
            vendor = shell.ask(f"Candidate {len(blocks) + 1} vendor", reader=reader)
            if vendor is shell.CANCELLED:
                break
            product = shell.ask("  Product", reader=reader)
            version = shell.ask("  Firmware version (optional)", reader=reader)
            product = None if product is shell.CANCELLED else product
            version = None if version is shell.CANCELLED else version
            block = _assess(connection, vendor, product, version, None, context=context)
            blocks.append(block)
            records.append(batch.to_record(block[0], block[1], query={
                "vendor": vendor, "product": product, "version": version,
                "order_number": None}))
            names.append("|".join(filter(None, [vendor, product, version])))
        if not blocks:
            return None
        shell.echo_command(["compare"] + [a for n in names for a in ("--candidate", n)])
        rank = {"PREFER": 0, "CONDITIONAL": 1, "AVOID": 2, "NOT ASSESSED": 3}
        blocks.sort(key=lambda b: (rank.get(b[0].verdict, 4), -(b[0].score or 0)))
        records.sort(key=lambda r: (rank.get(r["verdict"], 4), -(r["score"] or 0)))
        print()
        _print_table(records)
        return shell.Result(kind="compare", blocks=blocks, records=records,
                            title="Procurement comparison",
                            meta={"candidates": len(records),
                                  "weights": context["weights"],
                                  "provenance": index.provenance(connection)})

    def do_alternatives(result, reader):
        if not (asked := _ask_product(reader)):
            return None
        vendor, product, version = asked
        shell.echo_command(["alternatives", "--vendor", vendor,
                            "--product", product]
                           + (["--version", version] if version else []))
        print("Scoring the family takes a moment ...")
        subject, resolution, options, skipped = _find_alternatives(
            connection, context, vendor, product, version)
        if options is None:
            print(f"{subject.product}: {resolution.reason or 'nothing to compare against'}")
            return None
        print(alternatives.format_report(subject, options, skipped,
                                         version=version))
        return None

    def do_vendor(result, reader):
        name = shell.ask("Manufacturer", required=True, reader=reader)
        if name is shell.CANCELLED:
            return None
        shell.echo_command(["vendor", name])
        profile = dossier.build(connection, name, screening=context["screening"],
                                certificates=context["certificates"])
        print(dossier.format_report(profile))
        if not profile.known and (hits := search.suggest(connection, vendor=name)["vendors"]):
            print()
            print(search.format_vendors(hits, name, lead="Closest names in the corpus:"))
        return None

    def do_batch(result, reader):
        path = shell.ask("CSV or JSON file of candidates", reader=reader)
        if path is shell.CANCELLED:
            return None
        shell.echo_command(["batch", path])
        rows = batch.read_candidates(str(path))
        blocks, records = [], []
        for row in rows:
            block = _assess(connection, row["vendor"], row["product"],
                            row["version"], row["order_number"], context=context)
            blocks.append(block)
            records.append(batch.to_record(block[0], block[1], query=row))
        rank = {"PREFER": 0, "CONDITIONAL": 1, "AVOID": 2, "NOT ASSESSED": 3}
        records.sort(key=lambda r: (rank.get(r["verdict"], 4), -(r["score"] or 0)))
        print()
        _print_table(records)
        return shell.Result(kind="batch", blocks=blocks, records=records,
                            title="Bill of materials review",
                            meta={"candidates": len(records),
                                  "weights": context["weights"],
                                  "provenance": index.provenance(connection)})

    def do_lev(result, reader):
        if not index.has_epss_history(connection):
            print(_NO_HISTORY)
            return None
        if not (asked := _ask_product(reader)):
            return None
        vendor, product, version = asked
        shell.echo_command(["lev", "--vendor", vendor, "--product", product])
        assessment, resolution, findings = _assess(
            connection, vendor, product, version, None, context=context)
        if not resolution.resolved:
            print(f"{assessment.product}: {resolution.reason}")
            return None
        cves = sorted({f.cve for f in findings})
        history = index.epss_history(connection, cves)
        signals = {f.cve: f for f in findings}
        cached = index.lev_estimates(connection)
        estimates = [lev.estimate(c, history.get(c, []), in_kev=signals[c].in_kev,
                                  current_epss=signals[c].epss) for c in cves]
        print(lev.format_report(assessment.product, estimates,
                                corpus_share=lev.baseline(cached)["share"] if cached else None))
        return None

    def do_ssvc(result, reader):
        if not (asked := _ask_product(reader)):
            return None
        vendor, product, version = asked
        print("\nThese three describe your plant. ReTrust cannot know them.")
        exposure = shell.ask(f"System exposure ({'/'.join(ssvc.EXPOSURE)})",
                             "controlled", reader=reader)
        automatable = shell.ask("Can an attacker automate it? (yes/no)", "yes",
                                reader=reader)
        impact = shell.ask(f"Human impact ({'/'.join(ssvc.HUMAN_IMPACT)})", "medium",
                           reader=reader)
        if shell.CANCELLED in (exposure, automatable, impact):
            return None
        shell.echo_command(["ssvc", "--vendor", vendor, "--product", product,
                            "--exposure", exposure, "--automatable", automatable,
                            "--human-impact", impact])
        assessment, resolution, findings = _assess(
            connection, vendor, product, version, None, context=context)
        if not resolution.resolved:
            print(f"{assessment.product}: {resolution.reason}")
            return None
        decisions = ssvc.assess(findings, str(exposure), str(automatable), str(impact))
        print(ssvc.format_report(assessment.product, decisions, exposure,
                                 automatable, impact,
                                 undecided=sum(1 for f in findings if not f.decided)))
        return None

    def do_diff(result, reader):
        path = shell.ask("Saved JSON result to compare against", reader=reader)
        if path is shell.CANCELLED:
            return None
        shell.echo_command(["diff", path])
        document, previous = diff.read(str(path))
        current = []
        for record in previous:
            query = record.get("query") or {}
            assessment, resolution, _ = _assess(
                connection, query.get("vendor"), query.get("product"),
                query.get("version"), query.get("order_number"), context=context)
            current.append(batch.to_record(assessment, resolution, query=query))
        print(diff.format_report(diff.compare(previous, current), document,
                                 context["weights"]))
        return None

    def do_timeline(result, reader):
        vendor = shell.ask("Vendor", required=True, reader=reader)
        if vendor is shell.CANCELLED:
            return None
        product = shell.ask("Product (blank for the whole vendor)", reader=reader)
        product = None if product is shell.CANCELLED else product
        shell.echo_command(["timeline", "--vendor", vendor]
                           + (["--product", product] if product else []))
        if product:
            resolution = match.resolve(connection, vendor=vendor, product=product)
            if not resolution.resolved:
                print(f"{vendor} {product}: {resolution.reason}")
                return None
            named = resolution.matches[0]
            print(timeline.format_report(
                f"{named.vendor} {named.name}".strip(),
                timeline.build(connection, [(m.advisory_id, m.product_id)
                                            for m in resolution.matches])))
            return None
        key = match._vendor_key(connection, vendor)
        if key is None:
            print(f"vendor {vendor!r} does not appear in the advisory corpus")
            return None
        print(timeline.format_report(vendor, timeline.for_vendor(connection, key)))
        return None

    def do_annex(result, reader):
        if not (asked := _ask_product(reader)):
            return None
        vendor, product, version = asked
        shell.echo_command(["questions", "--vendor", vendor, "--product", product]
                           + (["--version", version] if version else []))
        assessment, resolution, findings = _assess(
            connection, vendor, product, version, None, context=context)
        profile = None
        if resolution.matches:
            profile = dossier.build(connection, resolution.matches[0].vendor,
                                    screening=context["screening"],
                                    certificates=context["certificates"])
        print(questions.format_report(
            assessment.product, questions.build(assessment, findings, profile)))
        return None

    def do_save(result, reader):
        shell.save(result, _shell_writers(context), reader)
        return None

    return {
        "1": ("Search the corpus", "find a vendor, product or order number", do_search),
        "2": ("Score one product", "verdict, pillars and the evidence", do_score),
        "o": ("Assess by order number", "use the part number from the nameplate", do_order),
        "3": ("Compare candidates", "rank several for one decision", do_compare),
        "4": ("Alternatives", "others in the family, scored the same way", do_alternatives),
        "5": ("Vendor profile", "what the index holds on a manufacturer", do_vendor),
        "6": ("Score a BOM file", "a CSV or JSON list of candidates", do_batch),
        "7": ("Likely exploited", "NIST LEV, has it probably happened already", do_lev),
        "8": ("SSVC decisions", "what buying this commits you to", do_ssvc),
        "9": ("What changed", "re-score a saved result against today", do_diff),
        "10": ("Advisory timeline", "the record drawn as a shape, per year", do_timeline),
        "11": ("RFQ annex", "what to ask the vendor, from the evidence", do_annex),
        "s": ("Save the last result", "HTML, JSON or CSV", do_save),
    }


def _shell_writers(context):
    """How the interactive session saves whatever it last produced."""
    def write_html(result, path):
        # Not _write_html: that announces the file itself, and the menu already
        # reports what it saved. Two lines for one file reads like two files.
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(report.render(
            result.blocks, title=result.title, weights=context["weights"],
            provenance=result.meta.get("provenance"),
            config_source=context["config_source"]), encoding="utf-8")
        return path

    return {"html": write_html,
            "json": lambda result, path: batch.write_json(
                result.records, path, result.meta),
            "csv": lambda result, path: batch.write_csv(result.records, path)}


def cmd_verify(args):
    """Check the advisories we scored on are the ones CISA published."""
    keyring = Path(args.data) / "csaf-keyring.gpg"
    root = args.csaf or str(bootstrap.corpus_dir(args.data))
    if not Path(root).is_dir():
        sys.exit(f"No advisories at {root}. Run `retrust setup` first, or pass "
                 "--csaf.")

    # Read the signer from the corpus before anything else: --fetch-key demands
    # exactly this fingerprint from CISA's provider metadata, so neither source
    # alone gets to choose the key.
    keys = integrity.signers(root) if not args.no_signatures else {}
    if args.key:
        try:
            print(f"  imported into {integrity.import_key_file(keyring, args.key)}")
        except Exception as error:
            sys.exit(f"Could not import {args.key}: {error}")
    if args.fetch_key:
        if len(keys) != 1:
            sys.exit(f"Expected one signing key to fetch, found {len(keys)}. "
                     "Establish why before importing anything.")
        fingerprint = next(iter(keys))
        try:
            print(f"Reading {integrity.CISA_PROVIDER_METADATA} ...")
            print(f"  imported into "
                  f"{integrity.import_advertised_key(keyring, fingerprint)}")
        except Exception as error:
            sys.exit(f"Could not import the key: {error}")
    print(f"Verifying advisories under {root} ...")
    results = integrity.sweep(
        root, limit=args.limit, signatures=not args.no_signatures,
        keyring=keyring if keyring.exists() else None,
        progress=lambda n, total: print(f"  {n:,}/{total:,}", end="\r", flush=True))
    print(" " * 40, end="\r")      # wipe the progress line before the report
    print()
    print(integrity.format_report(results, root, keyring.exists(), keys))
    # Non-zero when anything failed, so a build can refuse to score on it.
    return 1 if any(not r.intact for r in results) else 0


def cmd_serve(args):
    """Serve the same assessments as pages, on this machine only by default."""
    connection = _open(args.db)
    context = _context(config_path=args.config)
    handler = serve.build_handler(
        connection,
        lambda vendor, product, version=None, order_number=None,
               network_exposure=None: _assess(
            connection, vendor, product, version, order_number, context=context,
            network_exposure=network_exposure),
        context, dossier, index.stats(connection), index.provenance(connection),
        args.host, args.port)

    print(f"ReTrust on http://{args.host}:{args.port}  (Ctrl-C to stop)")
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        # Said plainly rather than buried: this is read-only and unauthenticated,
        # and a plant network is not the place to leave it running unattended.
        print(f"\n  WARNING: {args.host} is not the loopback address, so anyone\n"
              "  who can reach this machine can read your index and run scoring\n"
              "  against it. There is no authentication. Stop it when you are done.\n")
    serve.serve(handler, args.host, args.port)
    return 0


def cmd_shell(args):
    """Menu-driven session, for people who would rather not learn the flags."""
    connection = _open(args.db)
    context = _context(config_path=args.config)
    counts = index.stats(connection)
    shell.run(_shell_actions(connection, context, args),
              _shell_writers(context),
              greet=f"{counts['advisories']:,} advisories, "
                    f"{counts['products']:,} product entries, "
                    f"{counts['vendors']:,} vendors.")
    return 0


def cmd_lev(args):
    """Estimate how likely a product's flaws are to have been exploited already."""
    connection = _open(args.db)

    if args.update:
        days = lev.sample_days(end=None)
        print(f"Fetching {len(days)} EPSS snapshots (about "
              f"{len(days) * 1.6:.0f} MB) into {args.data}/epss-history ...")
        result = bootstrap.fetch_epss_history(
            args.data, [d.isoformat() for d in days],
            progress=lambda day, f, p, m: print(f"  {day}", end="\r", flush=True))
        print(f"\n  fetched {result['fetched']}, already present "
              f"{result['already_present']}, unavailable {result['unavailable']}")
        counts = index.load_epss_history(connection, bootstrap.history_files(args.data))
        print(f"  loaded {counts['scores']:,} scores across {counts['days']:,} days")
        print("  estimating LEV for every CVE in the corpus ...")
        print(f"  cached {_store_lev(connection):,} estimates")
        return 0

    if args.audit:
        if not index.has_epss_history(connection):
            print(_NO_HISTORY)
            return 2
        rows = index.lev_estimates(connection)
        kev = {r["cve"] for r in connection.execute(
            "SELECT cve FROM exploitation WHERE in_kev = 1")}
        listed = [r["lev"] for r in rows if r["cve"] in kev]
        unlisted = [r["lev"] for r in rows if r["cve"] not in kev]
        print(lev.format_baseline(lev.baseline(rows), listed={
            "in_kev": len(listed), "in_kev_median": lev._median(listed),
            "not_in_kev_median": lev._median(unlisted)} if listed else None))
        return 0

    if not index.has_epss_history(connection):
        print(_NO_HISTORY)
        return 2

    if args.cve:
        cves, product = [c.upper() for c in args.cve], ", ".join(args.cve)
        exploitation = {row["cve"]: row for row in connection.execute(
            f"SELECT cve, epss, in_kev FROM exploitation"
            f" WHERE cve IN ({','.join('?' * len(cves))})", cves)}
    else:
        assessment, resolution, findings = _assess(
            connection, args.vendor, args.product, args.version, args.order_number,
            context=_context(config_path=args.config))
        if not resolution.resolved:
            print(f"{assessment.product}: {resolution.reason}")
            return 2
        product = assessment.product
        cves = sorted({f.cve for f in findings})
        exploitation = {f.cve: {"epss": f.epss, "in_kev": f.in_kev} for f in findings}

    # The corpus base rate, so a per-product count can be compared rather than
    # merely reported. Cheap: it reads the cached estimates, not the history.
    cached = index.lev_estimates(connection)
    corpus_share = lev.baseline(cached)["share"] if cached else None

    history = index.epss_history(connection, cves)
    estimates = [
        lev.estimate(cve, history.get(cve, []),
                     in_kev=bool((exploitation.get(cve) or {})["in_kev"]),
                     current_epss=(exploitation.get(cve) or {})["epss"])
        for cve in cves if cve in exploitation
    ]
    print(lev.format_report(product, estimates, limit=args.limit,
                            corpus_share=corpus_share))

    if args.json:
        written = _emit_json(args.json, batch.envelope(
            [{"cve": e.cve, "lev": round(e.lev, 4), "composite": round(e.composite, 4),
              "in_kev": e.in_kev, "current_epss": e.current_epss,
              "peak_epss": e.peak_epss, "observations": e.observations,
              "first_seen": e.first_seen, "last_seen": e.last_seen}
             for e in sorted(estimates, key=lambda e: -e.lev)],
            {"product": product, "cves": len(estimates),
             "method": "NIST CSWP 41 (Likely Exploited Vulnerabilities)",
             "provenance": index.provenance(connection)}))
        if written:
            print(f"\nJSON written to {written}")
    return 0


def cmd_ssvc(args):
    """Place a product's findings on CERT/CC's SSVC deployer tree."""
    connection = _open(args.db)
    context = _context(config_path=args.config)
    assessment, resolution, findings = _assess(
        connection, args.vendor, args.product, args.version, args.order_number,
        context=context)

    if not resolution.resolved:
        print(f"{assessment.product}: {resolution.reason}")
        print("SSVC needs findings to place on the tree, and there are none.")
        return 2

    automatable, why = args.automatable, ""
    if automatable == "auto":
        automatable, why = ssvc.suggest_automatable(findings)
        if automatable is None:
            sys.exit("--automatable auto needs CVSS vectors and this index has "
                     "none. Re-run `retrust ingest`, or answer yes/no yourself.")
        print(f"Automatable suggested as {automatable.upper()}: {why}.\n"
              "SSVC does not define this from CVSS, so check it before relying "
              "on the result.\n")

    decisions = ssvc.assess(findings, args.exposure, automatable,
                            args.human_impact)
    print(ssvc.format_report(assessment.product, decisions, args.exposure,
                             automatable, args.human_impact,
                             undecided=sum(1 for f in findings if not f.decided)))

    if args.json:
        written = _emit_json(args.json, batch.envelope(
            [{"cve": d.cve, "outcome": d.outcome, "exploitation": d.exploitation,
              "in_kev": d.in_kev, "epss": d.epss, "cvss": d.cvss}
             for d in decisions],
            {"product": assessment.product, "findings": len(decisions),
             "context": {"exposure": args.exposure, "automatable": automatable,
                         "automatable_source": "derived from CVSS vectors" if why else "given",
                         "human_impact": args.human_impact},
             "tree": "CERT/CC SSVC Deployer Patch Application Priority v1.0.0",
             "provenance": index.provenance(connection)}))
        if written:
            print(f"\nJSON written to {written}")

    # Non-zero when anything demands action before the next maintenance window.
    return 1 if any(d.outcome in ("immediate", "out-of-cycle")
                    for d in decisions) else 0


def _find_alternatives(connection, context, vendor, product, version=None,
                       order_number=None, limit=8):
    """Resolve a product, then score its family. One path for flag and menu.

    Returns (subject, resolution, options, skipped); options is None when the
    request resolved to nothing there is a family for.
    """
    subject, resolution, _ = _assess(
        connection, vendor, product, version, order_number, context=context)

    # Prefer the name the advisory uses: it is the one the family shares.
    named = resolution.matches[0] if resolution.matches else None
    family_vendor = named.vendor if named else vendor
    family_name = named.name if named else product
    if not (family_vendor and family_name):
        return subject, resolution, None, None

    options, skipped = alternatives.find(
        connection, family_vendor, family_name,
        lambda v, p: _assess(connection, v, p, None, None, context=context),
        limit=limit,
        # Every row the request resolved to is the product asked about, under
        # whatever spelling its advisory used. None of them is an alternative.
        exclude={index.normalize_name(m.name) for m in resolution.matches})
    return subject, resolution, options, skipped


def cmd_questions(args):
    """The RFQ security annex: what to ask the vendor, from the evidence."""
    connection = _open(args.db)
    context = _context(args.data, config_path=args.config)
    assessment, resolution, findings = _assess(
        connection, args.vendor, args.product, args.version, args.order_number,
        context=context)
    profile = None
    if resolution.matches:
        profile = dossier.build(
            connection, resolution.matches[0].vendor,
            screening=context["screening"],
            certificates=context["certificates"])
    asked = questions.build(assessment, findings, profile)
    quiet = args.json == "-"
    if not quiet:
        print(questions.format_report(assessment.product, asked))
    if args.json:
        from dataclasses import asdict
        written = _emit_json(args.json, batch.envelope(
            [asdict(q) for q in asked],
            {"product": assessment.product, "verdict": assessment.verdict,
             "provenance": index.provenance(connection)}))
        if written and not quiet:
            print(f"\nJSON written to {written}")
    # An annex is not a gate: it exists to be sent, whatever the verdict.
    return 0


def cmd_timeline(args):
    """A product's or vendor's advisory history, drawn as a shape."""
    connection = _open(args.db)
    if args.product or args.order_number:
        resolution = match.resolve(connection, vendor=args.vendor,
                                   product=args.product,
                                   order_number=args.order_number)
        if not resolution.resolved:
            print(f"{' '.join(filter(None, [args.vendor, args.product])) or args.order_number}: "
                  f"{resolution.reason}")
            return 1
        named = resolution.matches[0]
        subject = f"{named.vendor} {named.name}".strip()
        line = timeline.build(connection, [(m.advisory_id, m.product_id)
                                           for m in resolution.matches])
    elif args.vendor:
        key = match._vendor_key(connection, args.vendor)
        if key is None:
            print(f"vendor {args.vendor!r} does not appear in the advisory corpus")
            return 1
        subject = args.vendor
        line = timeline.for_vendor(connection, key)
    else:
        print("Give --vendor (optionally with --product), or --order-number.")
        return 1
    print(timeline.format_report(subject, line))
    return 0


def cmd_cve(args):
    """One CVE, everything the index knows about it: the pivot lookup."""
    connection = _open(args.db)
    view = cvelookup.lookup(connection, args.cve)
    if view is None:
        print(f"this index has never met {args.cve.upper().strip()}: it is in "
              "neither the corpus nor the KEV/EPSS tables")
        return 2
    quiet = args.json == "-"
    if not quiet:
        print(cvelookup.format_report(view))
    if args.json:
        from dataclasses import asdict
        written = _emit_json(args.json, batch.envelope(
            [asdict(view)], {"provenance": index.provenance(connection)}))
        if written and not quiet:
            print(f"\nJSON written to {written}")
    return 0


def cmd_vex(args):
    """The assessment as a CycloneDX VEX document: SBOM in, VEX out."""
    connection = _open(args.db)
    resolution = match.resolve(connection, vendor=args.vendor,
                               product=args.product,
                               order_number=args.order_number)
    statements = vex.statements(connection, resolution, version=args.version)
    if not statements:
        reason = resolution.reason if not resolution.resolved else \
            "the resolution names no CVE to make a claim about"
        print(f"No VEX written: {reason}")
        return 2
    named = resolution.matches[0]
    subject = f"{named.vendor} {named.name}".strip()
    doc = vex.document(subject, args.version, statements,
                       index.provenance(connection))
    payload = json.dumps(doc, indent=2) + "\n"
    if args.out == "-":
        print(payload, end="")
    else:
        Path(args.out).write_text(payload, encoding="utf-8")
        print(vex.format_summary(statements))
        print(f"\nVEX written to {args.out}")
    return 0


def cmd_alternatives(args):
    """Other products in the same vendor family, scored the same way."""
    connection = _open(args.db)
    context = _context(config_path=args.config)
    subject, resolution, options, skipped = _find_alternatives(
        connection, context, args.vendor, args.product, args.version,
        args.order_number, limit=args.limit)
    if options is None:
        print(f"{subject.product}: {resolution.reason or 'nothing to compare against'}")
        return 1
    quiet = args.json == "-"
    if not quiet:
        print(alternatives.format_report(subject, options, skipped,
                                         version=args.version))
    if args.json:
        written = _emit_json(args.json, batch.envelope(
            [vars(o) for o in options],
            {"subject": {"product": subject.product, "verdict": subject.verdict,
                         "score": subject.score},
             "skipped": skipped,
             "caveat": alternatives.CAVEAT,
             "provenance": index.provenance(connection)}))
        if written and not quiet:
            print(f"\nJSON written to {written}")
    return 0 if options else 1


def cmd_diff(args):
    """Re-score a stored result against today's index and report what moved."""
    document, previous = diff.read(args.previous)
    connection = _open(args.db)
    context = _context(config_path=args.config)

    print(f"Re-scoring {len(previous)} product(s) from {args.previous} ...\n")
    current = []
    for record in previous:
        query = record.get("query") or {}
        assessment, resolution, _ = _assess(
            connection, query.get("vendor"), query.get("product"),
            query.get("version"), query.get("order_number"), context=context,
            network_exposure=record.get("network_exposure"))
        current.append(batch.to_record(assessment, resolution, query=query))

    changes = diff.compare(previous, current)
    print(diff.format_report(changes, document, context["weights"]))

    if args.json:
        written = _emit_json(args.json, batch.envelope(
            [{"product": c.product, "query": c.query, "change": c.kind,
              "was": c.was, "now": c.now, "score_change": c.drift,
              "new_gates": c.new_gates} for c in changes],
            {"compared": len(changes), "source": str(args.previous),
             "weights": context["weights"],
             "provenance": index.provenance(connection)}))
        if written:
            print(f"\nJSON written to {written}")

    # Non-zero when something got worse, so a scheduled re-review can raise a
    # flag without anybody reading the output.
    return 1 if any(c.kind in ("gated", "worse") for c in changes) else 0


def cmd_vendor(args):
    """Everything the index knows about one manufacturer."""
    connection = _open(args.db)
    context = _context(args.data)
    name = " ".join(args.vendor)
    profile = dossier.build(connection, name,
                            screening=context["screening"],
                            certificates=context["certificates"])
    quiet = args.json == "-"
    if not quiet:
        print(dossier.format_report(profile))
    if args.json:
        from dataclasses import asdict
        written = _emit_json(args.json, batch.envelope(
            [asdict(profile)], {"provenance": index.provenance(connection)}))
        if written and not quiet:
            print(f"\nJSON written to {written}")

    # An unrecognised name is far more often a spelling difference than a vendor
    # the corpus has never heard of. suggest(), not vendors(): a substring search
    # cannot reach "Siemens" from "Siemems", which is exactly the typo to catch.
    if not profile.known and not quiet:
        if hits := search.suggest(connection, vendor=name)["vendors"]:
            print()
            print(search.format_vendors(hits, name,
                                        lead="Vendors in the corpus with a similar name:"))
    return 0 if profile.known else 1


def cmd_completion(args):
    """Emit a completion script listing the real parser's commands and flags.

    Read off the parser rather than written out by hand, so the completions
    cannot drift out of step with the commands that actually exist.
    """
    parser = build_parser()
    subparsers = next(action for action in parser._actions
                      if isinstance(action, argparse._SubParsersAction))
    commands = {name: [option for action in subparser._actions
                       for option in action.option_strings]
                for name, subparser in sorted(subparsers.choices.items())}
    shared = [option for action in parser._actions for option in action.option_strings]
    print(console.completion(args.shell, commands, shared))
    return 0


def cmd_setup(args):
    """Fetch everything and build the index, in one command."""
    print("Setting ReTrust up. Each step is skipped if it is already done,\n"
          "so re-running after an interruption resumes where it stopped.\n")
    results = bootstrap.run(
        data_dir=args.data, db_path=args.db, force=args.force,
        offline=args.offline, skip_refresh=args.skip_refresh, progress=print)

    if failed := [(name, r["detail"]) for name, r in results.items() if not r["ok"]]:
        name, detail = failed[0]
        sys.exit(f"\nSetup stopped at the {name} step.\n  {detail}")

    connection = _open(args.db)
    print("\nReady. The index holds:")
    for key, value in index.stats(connection).items():
        print(f"  {key.replace('_', ' '):<15} {value:,}")
    print("\nTry:\n"
          "  retrust score --order-number 6ES7518-4AX00-1AB0 --version 3.1.6\n"
          "  retrust compare --candidate 'ABB|AC 800M' --candidate 'Moxa|EDS-405A'\n"
          "  retrust eval")
    return 0


def cmd_eval(args):
    connection = _open(args.db)
    quiet = args.json == "-"
    if not quiet:
        print("Measuring against the local index. This is the number ReTrust "
              "publishes;")
        print("re-run it yourself to check it.\n")
    results = evaluate.run(connection, sample=args.sample)
    if not quiet:
        print(evaluate.format_report(results))

    # The hand-written query set rides along whenever its file is present, so
    # the shipped benchmark is part of the default measurement rather than a
    # flag nobody remembers.
    queries = args.queries or (
        "examples/buyer-queries.csv"
        if Path("examples/buyer-queries.csv").exists() else None)
    outcomes = evaluate.buyer_queries(connection, queries) if queries else []
    if outcomes and not quiet:
        print()
        print(evaluate.format_queries(outcomes))

    if args.json:
        trip, version = results["round_trip"], results["version"]
        written = _emit_json(args.json, batch.envelope(
            [vars(o) for o in outcomes],
            {"eval": {
                "identifiers": results.get("identifiers"),
                "version_coverage": round(version.coverage, 4),
                "decidable_accuracy": round(version.decidable_accuracy, 4),
                "round_trip": {"sample": trip.attempted,
                               "precision": round(trip.precision, 4),
                               "recall": round(trip.recall, 4)},
                "buyer_queries": {"passed": sum(1 for o in outcomes if o.passed),
                                  "total": len(outcomes)}},
             "provenance": index.provenance(connection)}))
        if written and not quiet:
            print(f"\nJSON written to {written}")
    return 0


def _product_args(parser):
    """The four ways a user can name one product."""
    parser.add_argument("--vendor")
    parser.add_argument("--product")
    parser.add_argument("--version", help="firmware version, e.g. 3.1.6")
    parser.add_argument("--order-number",
                        help="manufacturer order number, e.g. 6ES7518-4AX00-1AB0")


def _scoring_args(parser, samples=300, fail_on="never"):
    """Options shared by every command that scores something.

    `fail_on` defaults to "never" for the interactive commands and "avoid" for
    batch, which exists to gate a pipeline.
    """
    parser.add_argument("--config", help=f"scoring weights (default {config.DEFAULT_PATH})")
    parser.add_argument("--samples", type=int, default=samples,
                        help=f"weightings to sample for robustness (default {samples})")
    parser.add_argument("--no-sensitivity", action="store_true",
                        help="skip the weight-robustness check (faster)")
    parser.add_argument("--fail-on", choices=["avoid", "unassessed", "never"],
                        default=fail_on,
                        help=f"what makes the exit code non-zero (default: {fail_on})")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="retrust",
        description="Score OT hardware for cyber risk before you buy it.")
    parser.add_argument("--db", default=DEFAULT_DB, help=f"index path (default {DEFAULT_DB})")
    parser.add_argument("--no-color", action="store_true", help="never colour the output")
    # Not required: bare `retrust` shows what the index holds and what to run
    # next, which is a better first contact than an argparse usage error.
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("verify", help="are the advisories the ones CISA published?")
    p.add_argument("--csaf", help="directory of CSAF files (default: the one setup cloned)")
    p.add_argument("--data", default="data", help="data directory")
    p.add_argument("--limit", type=int, help="check only the first N, for a quick look")
    p.add_argument("--no-signatures", action="store_true",
                   help="digests only; skip gpg")
    p.add_argument("--fetch-key", action="store_true",
                   help="fetch the key CISA advertises in its CSAF provider "
                        "metadata, refusing a fingerprint mismatch")
    p.add_argument("--key", metavar="FILE",
                   help="import a signing key you obtained out of band")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("serve", help="a local web interface")
    p.add_argument("--port", type=int, default=serve.DEFAULT_PORT)
    p.add_argument("--host", default=serve.DEFAULT_HOST,
                   help="loopback by default; anything else is announced")
    p.add_argument("--config", help="scoring configuration file")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("shell", help="interactive menu, no flags to remember")
    p.add_argument("--config", help="scoring configuration file")
    p.set_defaults(func=cmd_shell)

    p = sub.add_parser("search", help="find vendors, products or order numbers")
    p.add_argument("query", nargs="+", help="what to look for")
    p.add_argument("--vendors", action="store_true", help="search vendor names")
    p.add_argument("--order-number", action="store_true",
                   help="search manufacturer order numbers")
    p.add_argument("--vendor", help="restrict a product search to one vendor")
    p.add_argument("--limit", type=int, default=20, help="results to show")
    p.set_defaults(func=cmd_search)

    p = sub.add_parser("lev", help="has this probably been exploited already?")
    _product_args(p)
    p.add_argument("--cve", action="append", help="estimate one CVE instead")
    p.add_argument("--update", action="store_true",
                   help="fetch and load the EPSS history LEV needs")
    p.add_argument("--audit", action="store_true",
                   help="does the threshold discriminate? base rates by CVE age")
    p.add_argument("--data", default="data", help="data directory")
    p.add_argument("--limit", type=int, default=20, help="CVEs to list")
    p.add_argument("--json", metavar="FILE", help='write as JSON; "-" for stdout')
    p.add_argument("--config", help="scoring configuration file")
    p.set_defaults(func=cmd_lev)

    p = sub.add_parser("ssvc", help="place findings on CERT/CC's SSVC tree")
    _product_args(p)
    # No defaults: these describe the buyer's plant, and guessing them would
    # invent the stakeholder context that SSVC exists to make explicit.
    p.add_argument("--exposure", required=True, choices=list(ssvc.EXPOSURE),
                   help="how reachable the system is")
    p.add_argument("--automatable", required=True,
                   choices=list(ssvc.AUTOMATABLE) + ["auto"],
                   help="can an attacker automate the attack? 'auto' suggests "
                        "one from the CVSS vectors and shows its working")
    p.add_argument("--human-impact", required=True, choices=list(ssvc.HUMAN_IMPACT),
                   help="safety and mission impact of a compromise")
    p.add_argument("--json", metavar="FILE",
                   help='write the decisions as JSON; "-" for stdout')
    p.add_argument("--config", help="scoring configuration file")
    p.set_defaults(func=cmd_ssvc)

    p = sub.add_parser("questions", help="the RFQ security annex: what to ask the vendor")
    _product_args(p)
    p.add_argument("--config", help=f"scoring weights (default {config.DEFAULT_PATH})")
    p.add_argument("--data", default="data", help="data directory (default data)")
    p.add_argument("--json", metavar="FILE",
                   help='write the annex as JSON; "-" for stdout')
    p.set_defaults(func=cmd_questions)

    p = sub.add_parser("timeline", help="advisory history drawn as a shape")
    _product_args(p)
    p.set_defaults(func=cmd_timeline)

    p = sub.add_parser("cve", help="one CVE, everything the index knows about it")
    p.add_argument("cve", help="the id, e.g. CVE-2023-44487 (case-insensitive)")
    p.add_argument("--json", metavar="FILE",
                   help='write the view as JSON; "-" for stdout')
    p.set_defaults(func=cmd_cve)

    p = sub.add_parser("vex", help="write the assessment as a CycloneDX VEX document")
    _product_args(p)
    p.add_argument("--out", default="retrust-vex.json",
                   help='output file (default retrust-vex.json; "-" for stdout)')
    p.set_defaults(func=cmd_vex)

    p = sub.add_parser("alternatives", help="other products in the same family")
    _product_args(p)
    p.add_argument("--limit", type=int, default=8, help="suggestions to show")
    p.add_argument("--config", help="scoring configuration file")
    p.add_argument("--json", metavar="FILE",
                   help='write results as JSON; "-" for stdout')
    p.set_defaults(func=cmd_alternatives)

    p = sub.add_parser("diff", help="re-score a stored result against today's index")
    p.add_argument("previous", help="JSON written by an earlier score/compare/batch")
    p.add_argument("--json", metavar="FILE",
                   help='write the changes as JSON; "-" for stdout')
    p.add_argument("--config", help="scoring configuration file")
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("vendor", help="what the index knows about a manufacturer")
    p.add_argument("vendor", nargs="+", help="manufacturer name")
    p.add_argument("--data", default="data", help="data directory")
    p.add_argument("--json", metavar="FILE",
                   help='write results as JSON; "-" for stdout')
    p.set_defaults(func=cmd_vendor)

    p = sub.add_parser("completion", help="print a shell completion script")
    p.add_argument("shell", choices=["bash", "zsh"])
    p.set_defaults(func=cmd_completion)

    p = sub.add_parser("setup", help="fetch everything and build the index")
    p.add_argument("--data", default="data", help="data directory (default data)")
    p.add_argument("--force", action="store_true",
                   help="re-fetch sources that are already present")
    p.add_argument("--offline", action="store_true",
                   help="build from data already downloaded; fetch nothing")
    p.add_argument("--skip-refresh", action="store_true",
                   help="skip the certification and sanctions lists")
    p.set_defaults(func=cmd_setup)

    p = sub.add_parser("ingest", help="build the index from CSAF advisories")
    p.add_argument("--csaf", action="append", metavar="DIR",
                   help="directory of CSAF JSON files; repeat to index vendor"
                        " feeds beside the CISA corpus (default data/CSAF)")
    p.add_argument("--kev", help="CISA KEV JSON file")
    p.add_argument("--epss", help="EPSS scores CSV file")
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("provider",
                       help="fetch a vendor's own CSAF feed (trusted provider)")
    p.add_argument("metadata_url",
                   help="the vendor's provider-metadata.json URL, e.g."
                        " https://cert-portal.siemens.com/productcert/csaf/"
                        "provider-metadata.json")
    p.add_argument("--data", default="data", help="data directory (default data)")
    p.add_argument("--force", action="store_true",
                   help="re-fetch advisories that are already present")
    p.set_defaults(func=cmd_provider)

    p = sub.add_parser("doctor", help="check the installation and its data ages")
    p.add_argument("--data", default="data", help="data directory (default data)")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("stats", help="show what the index contains")
    p.set_defaults(func=cmd_stats)

    p = sub.add_parser("score", help="assess one product")
    _product_args(p)
    p.add_argument("--network-exposure", choices=list(score.NETWORK_EXPOSURES),
                   help="operator-reported OT network context: isolated, it_ot, or internet_ot")
    p.add_argument("--html", help="also write an HTML report here")
    p.add_argument("--json", metavar="FILE",
                   help='write the full assessment as JSON; "-" for stdout')
    _scoring_args(p)
    p.set_defaults(func=cmd_score)

    p = sub.add_parser("compare", help="rank candidate products for one decision")
    p.add_argument("--candidate", action="append", required=True,
                   metavar="'Vendor|Product|Version|OrderNo'",
                   help="repeatable; fields after the vendor are optional")
    p.add_argument("--html", help="also write an HTML report here")
    p.add_argument("--json", metavar="FILE",
                   help='write the ranking as JSON; "-" for stdout')
    _scoring_args(p)
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
    _scoring_args(p, samples=200, fail_on="avoid")
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
    p.add_argument("--appetite", metavar="NAME",
                   help="start --init from a named risk appetite")
    p.add_argument("--appetites", action="store_true",
                   help="list the shipped risk appetites and their reasoning")
    p.set_defaults(func=cmd_config)

    p = sub.add_parser("sensitivity",
                       help="how much the verdict depends on the weights")
    _product_args(p)
    p.add_argument("--network-exposure", choices=list(score.NETWORK_EXPOSURES),
                   help="operator-reported OT network context")
    _scoring_args(p, samples=500)
    p.set_defaults(func=cmd_sensitivity)

    p = sub.add_parser("refresh", help="fetch certification and sanctions sources")
    p.add_argument("--data", default="data", help="directory to cache into")
    p.set_defaults(func=cmd_refresh)

    p = sub.add_parser("backtest",
                       help="did the score predict later vulnerabilities?")
    p.add_argument("--cutoff", default="2022-01-01",
                   help="score on advisories before this date (default 2022-01-01)")
    p.add_argument("--min-history", type=int, default=backtest.MIN_HISTORY,
                   help="advisories a product needs before the cutoff to qualify")
    p.add_argument("--limit", type=int, help="cap the cohort, for a quick run")
    p.add_argument("--permutations", type=int, default=1000,
                   help="shuffles for the significance control (default 1000)")
    p.add_argument("--min-stratum", type=int, default=backtest.MIN_STRATUM,
                   help="products a vendor needs to form a matched stratum")
    p.add_argument("--no-matched", action="store_true",
                   help="skip the within-vendor matched comparison")
    p.add_argument("--sweep", action="store_true",
                   help="run the whole decomposition at several cutoffs")
    p.add_argument("--json", metavar="FILE", help='write results as JSON; "-" for stdout')
    p.set_defaults(func=cmd_backtest)

    p = sub.add_parser("eval", help="reproduce the published accuracy figures")
    p.add_argument("--sample", type=int, default=400,
                   help="products to round-trip (default 400)")
    p.add_argument("--queries", metavar="CSV",
                   help="hand-written buyer-query set "
                        "(default examples/buyer-queries.csv when present)")
    p.add_argument("--json", metavar="FILE",
                   help='write results as JSON; "-" for stdout')
    p.set_defaults(func=cmd_eval)

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.no_color:
        console.disable()
    if not args.command:
        print(console.overview(args.db))
        return 0
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
