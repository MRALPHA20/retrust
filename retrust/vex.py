"""The assessment written back out as machine-readable VEX.

`retrust batch` already reads a CycloneDX SBOM in; this module closes the
loop by writing the outcome back OUT as a CycloneDX 1.5 VEX document. The
human report prints what a buyer must act on, so it has no reason to list
the CVEs a version check cleared -- but the buyer's own records and their
downstream SBOM tooling need exactly those not_affected claims, in a shape
a machine can file against the component. One statement per CVE, collapsed
across every product row the resolver matched.

Two refusals. statements() on an unresolved resolution returns []: a claim
about a product nobody identified is a claim about nothing. And document()
raises on an empty statement list, because an empty VEX still LOOKS like an
assertion -- "we checked; nothing applies" -- and must not be writable by
accident.

Deterministic on purpose, like the rest of the tool: the serial number is
derived from the content and the timestamp from the corpus provenance,
never from the clock, so one index and one query produce byte-identical
documents for as long as the same ReTrust version writes them (the tool
version rides in the hashed metadata: a different tool wrote it).

The vulnerability source is named "CISA CSAF" because that is what `retrust
setup` indexes; an index built over another publisher's feed keeps the same
label, which overstates nothing about the claims but does name their usual
origin.
"""

import json
import re
import textwrap
import uuid
from dataclasses import dataclass, field
from datetime import date
from importlib import metadata as pkg_metadata

from . import cvss
from .version import affects

# Severity order of the three claims. A CVE affecting any one matched row IS
# a finding, whatever its other rows say; and "could not decide" must always
# outrank "decided safe", or an unparseable range would read as a clean bill.
_RANK = {"exploitable": 0, "in_triage": 1, "not_affected": 2}

# CycloneDX 1.5 rating.method values, keyed by cvss.parse()'s version string.
_METHOD = {"2.0": "CVSSv2", "3.0": "CVSSv3", "3.1": "CVSSv31"}

# The one component this document describes. Fixed, so every vulnerability's
# `affects` entry can point at it by reference.
_BOM_REF = "subject"

_ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


@dataclass
class Statement:
    """One CVE's collapsed claim about the subject product."""

    cve: str
    state: str          # "exploitable" | "in_triage" | "not_affected"
    detail: str
    advisory_ids: list = field(default_factory=list)
    cvss: float | None = None
    vector: str | None = None
    justification: str | None = None


def has_statements(connection, resolution):
    """Would statements() return anything, without building it.

    Same walk and same emptiness rule (a matched row naming at least one CVE),
    stopping at the first hit; for callers that only need to know whether a
    VEX can be written, such as the export menu on every assessment page.
    """
    if not resolution.resolved:
        return False
    return any(connection.execute(
        "SELECT 1 FROM affected WHERE advisory_id = ? AND product_id = ? LIMIT 1",
        (match_.advisory_id, match_.product_id)).fetchone()
        for match_ in resolution.matches)


def statements(connection, resolution, version=None):
    """One claim per CVE, across every product row the resolution matched.

    Walks resolution.matches exactly as match.findings() does, but keeps all
    three outcomes of the version test. findings() drops rows a version
    clearly escapes, because the human report has nothing to say about them;
    a VEX exists precisely to put "checked, and not affected" on the record,
    so those rows are re-derived here rather than recovered from findings.

    An unresolved resolution yields no statements at all: the abstention was
    the honest answer, and a VEX would overwrite it with a confident one.
    [] also comes back when the resolution resolved but the matched rows
    carry no CVEs at all -- csaf.py stores only known_affected ids, so a
    clean record is possible. Check resolution.resolved to tell the two
    apart; the CLI words them differently.
    """
    if not resolution.resolved:
        return []

    rows = {}          # cve -> [(state, advisory_id, range, cvss, vector)]
    for match_ in resolution.matches:
        if version and match_.version_range:
            verdict = affects(match_.version_range, version)
            state = ("exploitable" if verdict is True
                     else "not_affected" if verdict is False else "in_triage")
        else:
            # No version to test, or no range to test it against: nothing
            # was decided, and in_triage is the state that says so out loud.
            state = "in_triage"
        for row in connection.execute(
                "SELECT cve, cvss, vector FROM affected"
                " WHERE advisory_id = ? AND product_id = ?",
                (match_.advisory_id, match_.product_id)):
            rows.setdefault(row["cve"], []).append(
                (state, match_.advisory_id, match_.version_range,
                 row["cvss"], row["vector"]))

    out = []
    for cve in sorted(rows):     # sorted, so the document is reproducible
        evidence = rows[cve]
        state = min((r[0] for r in evidence), key=_RANK.__getitem__)
        # Only the rows carrying the winning state back the claim: citing a
        # range that decided otherwise would misattribute the evidence.
        winning = [r for r in evidence if r[0] == state]
        ranges = sorted({r[2] for r in winning if r[2]})
        scored = [(r[3], r[4]) for r in winning if r[3] is not None]
        if scored:
            # Keyed on the score alone: max() over bare pairs would fall
            # through to comparing vectors on a tie, and None beside a
            # string raises rather than picking either.
            score, vector = max(scored, key=lambda pair: pair[0])
        else:
            score, vector = None, None
        out.append(Statement(
            cve=cve, state=state, detail=_detail(state, version, ranges),
            advisory_ids=sorted({r[1] for r in winning}),
            cvss=score, vector=vector,
            # code_not_present is CycloneDX for "this version does not carry
            # the flawed code", which is what a version outside the affected
            # range establishes. It can only fire with a version to point
            # at: affects() returns False only when one was supplied.
            justification=("code_not_present" if state == "not_affected"
                           else None)))
    return out


def _detail(state, version, ranges):
    """The auditable sentence behind a state: which range, which version."""
    named = "; ".join(ranges)
    if state == "exploitable":
        return f"Version {version} falls inside affected range {named}."
    if state == "not_affected":
        # The range and the version that misses it, both named: a bare
        # "not_affected" with nothing to point at could not be re-checked.
        return f"Version {version} is outside affected range {named}."
    if not version:
        return ("No version was supplied, so no affected range was checked"
                " -- kept in triage rather than assumed safe.")
    if not named:
        return (f"The advisory names no affected range to test {version}"
                " against.")
    return (f"Affected range {named} could not be decided against version"
            f" {version} -- kept in triage rather than assumed safe.")


def document(subject_name, subject_version, statements, provenance):
    """The CycloneDX 1.5 VEX for a statement list. Refuses an empty one."""
    if not statements:
        raise ValueError(
            "refusing to write a VEX with no statements: an empty document"
            " still reads as an assertion that nothing affects the product")

    component = {"type": "device", "bom-ref": _BOM_REF, "name": subject_name}
    if subject_version:
        component["version"] = subject_version
    metadata = {"tools": {"components": [_tool()]}, "component": component}
    # The corpus is the clock, exactly as in timeline: a wall-clock stamp
    # would make one assessment produce a different file every day, and
    # would claim the data is fresher than the snapshot it came from. With
    # no dated provenance the field is omitted, never invented.
    if newest := _newest_capture(provenance):
        metadata["timestamp"] = f"{newest}T00:00:00Z"

    content = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
               "metadata": metadata,
               "vulnerabilities": [_vulnerability(s) for s in statements]}
    # The spec expects a serial number to mark one act of writing. This one
    # is a uuid5 over the canonical content instead, so the same inputs
    # yield the same document byte for byte: a re-run diffs clean, and a
    # VEX in a procurement file stays re-derivable from the index that
    # produced it. Reproducibility outweighs the spec's freshness here.
    canonical = json.dumps(content, sort_keys=True)
    serial = uuid.uuid5(uuid.NAMESPACE_URL, "retrust:vex:" + canonical)
    return {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{serial}", "version": 1,
            "metadata": metadata,
            "vulnerabilities": content["vulnerabilities"]}


def _vulnerability(statement):
    """One CycloneDX vulnerability entry, advisory ids carried twice on
    purpose: in `references`, where a machine cross-files them, and in the
    detail prose, where a human reads the claim whole."""
    analysis = {"state": statement.state}
    if statement.justification:
        analysis["justification"] = statement.justification
    detail = statement.detail
    if statement.advisory_ids:
        detail += " Advisories: " + ", ".join(statement.advisory_ids) + "."
    analysis["detail"] = detail
    entry = {"id": statement.cve, "source": {"name": "CISA CSAF"},
             "analysis": analysis, "affects": [{"ref": _BOM_REF}]}
    if statement.advisory_ids:
        entry["references"] = [{"id": advisory, "source": {"name": "CISA CSAF"}}
                               for advisory in statement.advisory_ids]
    if statement.cvss is not None:
        entry["ratings"] = [{"score": statement.cvss,
                             "method": _method(statement.vector)}]
    return entry


def _method(vector):
    """The rating method behind a score.

    A score with no parseable vector is still a score the advisory stated,
    so it is kept and labelled "other" rather than dropped: the number is
    real even when the generation that produced it is unknown.
    """
    parsed = cvss.parse(vector)
    if parsed is None:
        return "other"
    if parsed.version.startswith("4"):
        return "CVSSv4"
    return _METHOD.get(parsed.version, "other")


def _newest_capture(provenance):
    """The newest dated `captured` across the provenance rows, or "".

    Gated to real ISO dates, as timeline gates its clock: max() over text is
    lexicographic, and one malformed row must not become the timestamp of
    record for every document written from the index.
    """
    dates = []
    for row in provenance or []:
        captured = (row.get("captured") or "").strip()
        if not _ISO_DATE.fullmatch(captured):
            continue
        try:
            date.fromisoformat(captured)
        except ValueError:
            continue
        dates.append(captured)
    return max(dates, default="")


def _tool():
    """ReTrust, as CycloneDX 1.5 spells a tool.

    The version is read from the installed package so it cannot drift from
    pyproject; on a source checkout that was never installed it is omitted
    rather than guessed.
    """
    tool = {"type": "application", "name": "ReTrust"}
    try:
        tool["version"] = pkg_metadata.version("retrust")
    except pkg_metadata.PackageNotFoundError:
        pass
    return tool


def format_summary(statements):
    """State counts as a short table, so the CLI can say what it wrote
    without the user opening the JSON."""
    if not statements:
        return ("  No statements: the product did not resolve, so there is"
                " no VEX to describe.")
    counts = {}
    for statement in statements:
        counts[statement.state] = counts.get(statement.state, 0) + 1
    lines = [f"VEX STATEMENTS   {len(statements)} CVE(s), one statement each"]
    order = ["exploitable", "in_triage", "not_affected"]
    # Canonical states in severity order; anything a caller hand-built after
    # them, so the counts always add up to the header.
    for state in order + sorted(set(counts) - set(order)):
        lines.append(f"  {state.replace('_', ' '):<14}{counts.get(state, 0):>4}")
    lines += ["", _wrap(
        "Statements cover the CVEs this index's advisories name for the"
        " matched product rows, and only those: a CVE absent here was never"
        " assessed, which is a different fact from not affected.")]
    return "\n".join(lines)


def _wrap(text, width=78):
    return "\n".join(textwrap.wrap(text, width))
