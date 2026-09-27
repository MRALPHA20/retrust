"""Score a whole list of candidates in one run.

The interactive commands answer "should we buy this?". This one answers the
question a procurement team actually arrives with: "here are the ninety items
on next quarter's bill of materials -- which ones need a human to look at?"

Input is a CSV or JSON list with whatever a requisition already holds:

    vendor,product,version,order_number
    Siemens,SIMATIC S7-1500,3.1.6,
    ,,,6ES7518-4AX00-1AB0
    Schneider Electric,Modicon M340,,

Output is machine-readable, and the exit code reflects the worst verdict found,
so this drops into CI or a procurement pipeline as a gate rather than something
somebody has to read and interpret.
"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict, is_dataclass
from pathlib import Path

# Accepted column names, so a real requisition export needs less reshaping.
COLUMN_ALIASES = {
    "vendor": {"vendor", "manufacturer", "supplier", "make", "brand"},
    "product": {"product", "model", "name", "description", "item", "part"},
    "version": {"version", "firmware", "fw", "firmware_version", "revision"},
    "order_number": {"order_number", "order no", "orderno", "mlfb", "part_number",
                     "partnumber", "part no", "catalog", "catalogue", "sku",
                     "article", "article_number"},
}

# Bumped whenever the JSON shape changes in a way a consumer would notice.
SCHEMA_VERSION = 1

# Exit codes, so a pipeline can branch without parsing output.
EXIT_OK = 0
EXIT_AVOID = 1
EXIT_UNASSESSED = 2


def _normalize_column(name):
    """Fold spaces, hyphens and underscores together so "Part Number",
    "part-number" and "part_number" all land on the same key."""
    return "_".join((name or "").strip().lower().replace("-", " ")
                    .replace("_", " ").split())


def _canonical(name):
    key = _normalize_column(name)
    for canonical, aliases in COLUMN_ALIASES.items():
        if key in {_normalize_column(a) for a in aliases}:
            return canonical
    return None


def read_candidates(path):
    """Read a candidate list from CSV or JSON. Returns a list of dicts."""
    source = Path(path)
    if not source.exists():
        raise SystemExit(f"{source} does not exist")

    text = source.read_text(encoding="utf-8-sig")
    rows = []

    if source.suffix.lower() == ".json" or text.lstrip().startswith(("[", "{")):
        document = json.loads(text)
        raw = document if isinstance(document, list) else document.get("candidates", [])
        for entry in raw:
            rows.append({k: (entry.get(k) or "").strip() or None
                         for k in COLUMN_ALIASES})
    else:
        reader = csv.DictReader(text.splitlines())
        if not reader.fieldnames:
            raise SystemExit(f"{source} has no header row")
        mapping = {name: _canonical(name) for name in reader.fieldnames}
        if not any(mapping.values()):
            raise SystemExit(
                f"{source}: no recognised columns. Expected some of: "
                + ", ".join(sorted(COLUMN_ALIASES)))
        for entry in reader:
            row = {k: None for k in COLUMN_ALIASES}
            for name, value in entry.items():
                if (key := mapping.get(name)) and value and value.strip():
                    row[key] = value.strip()
            if any(row.values()):
                rows.append(row)

    if not rows:
        raise SystemExit(f"{source} contained no candidates")
    return rows


def to_record(assessment, resolution, stability=None):
    """Flatten one assessment into a row a spreadsheet or pipeline can read."""
    record = {
        "product": assessment.product,
        "verdict": assessment.verdict,
        "score": assessment.score,
        "cves": assessment.findings_count if assessment.score is not None else None,
        "undecided": assessment.undecided_count,
        "confidence": assessment.confidence,
        "resolved_by": resolution.method if resolution.resolved else None,
        "match_confidence": resolution.confidence if resolution.resolved else None,
        "matched_products": len(resolution.matches),
        "reason": "" if resolution.resolved else resolution.reason,
        "gates": [g["gate"] for g in assessment.gates],
        "gate_detail": "; ".join(g["detail"] for g in assessment.gates),
        "pillars": {p.name: round(p.score, 1) for p in assessment.pillars},
    }
    if stability is not None:
        record["robust"] = None if stability.gated else round(stability.agreement, 3)
        record["gated"] = stability.gated
    return record


def to_detail(assessment, resolution, findings=(), stability=None,
              top_cves=10, top_matches=10):
    """One assessment with its full evidence, for `score --json`.

    A superset of to_record: every field there appears here with the same name
    and meaning, so a consumer can read either output with one parser. The
    extras are the things a single-product view can afford to carry -- the
    evidence line behind each pillar, the citation behind each gate, and the
    most significant CVEs.
    """
    record = to_record(assessment, resolution, stability)

    record["pillars"] = [
        {"name": p.name, "score": round(p.score, 1),
         "coverage": round(p.coverage, 3), "evidence": list(p.evidence),
         "scored": p.name != "Evidence quality"}
        for p in assessment.pillars
    ]
    record["gates"] = [dict(g) for g in assessment.gates]
    record["notes"] = list(assessment.notes)

    if resolution.resolved:
        record["matches"] = [
            {"advisory": m.advisory_id, "vendor": m.vendor, "product": m.name,
             "version_range": m.version_range, "method": m.method}
            for m in resolution.matches[:top_matches]
        ]
        record["matches_truncated"] = max(0, len(resolution.matches) - top_matches)

    ranked = sorted(findings, key=lambda f: (-(f.epss or 0), -(f.cvss or 0)))
    record["findings"] = [
        {"cve": f.cve, "advisory": f.advisory_id, "cvss": f.cvss, "cwe": f.cwe,
         "epss": f.epss, "in_kev": f.in_kev, "ransomware": f.ransomware,
         "remediation": f.remediation, "version_range": f.version_range,
         "version_decided": f.decided}
        for f in ranked[:top_cves]
    ]
    record["findings_truncated"] = max(0, len(ranked) - top_cves)
    return record


def envelope(results, meta=None):
    """Wrap results with the metadata every JSON output carries."""
    return {"generated_by": "retrust", "schema": SCHEMA_VERSION,
            **(meta or {}), "results": results}


def dumps(payload):
    """Serialise, handling the dataclasses and sets that findings carry."""
    return json.dumps(payload, indent=2, default=_plain)


def exit_code(records, fail_on="avoid"):
    """Worst-case exit status, so this can gate a pipeline.

    fail_on="avoid"      non-zero only when something is disqualified
    fail_on="unassessed" also non-zero when anything could not be assessed
    fail_on="never"      always zero; just report
    """
    if fail_on == "never":
        return EXIT_OK
    verdicts = {r["verdict"] for r in records}
    if "AVOID" in verdicts:
        return EXIT_AVOID
    if fail_on == "unassessed" and "NOT ASSESSED" in verdicts:
        return EXIT_UNASSESSED
    return EXIT_OK


def write_json(records, path, meta=None):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(dumps(envelope(records, meta)), encoding="utf-8")
    return path


def write_csv(records, path):
    """Flat CSV: nested pillars become one column each."""
    pillar_names = sorted({name for r in records for name in r.get("pillars", {})})
    columns = ["product", "verdict", "score", "cves", "undecided", "confidence",
               "robust", "resolved_by", "match_confidence", "gates", "reason"]
    columns += [f"pillar_{n.lower().replace(' ', '_')}" for n in pillar_names]

    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for record in records:
            row = dict(record)
            row["gates"] = "; ".join(record.get("gates") or [])
            for name in pillar_names:
                row[f"pillar_{name.lower().replace(' ', '_')}"] = \
                    record.get("pillars", {}).get(name)
            writer.writerow(row)
    return path


def _plain(value):
    """JSON fallback for dataclasses and sets."""
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    return str(value)
