"""Measure how well ReTrust reads the advisory corpus, and prove it.

The point of this module is that anyone can re-run it and get the number we
publish. Two things are measured, and they are deliberately kept apart:

  coverage    of every affected-version range in the corpus, how many can we
              decide without guessing? Ranges pinned to a serial number or a
              board revision are counted separately, because no version-based
              tool can decide those and pretending otherwise would inflate the
              figure.

  round-trip  take a product an advisory names, ask ReTrust to resolve it from
              its vendor, name and order number, and check we get that same
              advisory back. This tests the matcher, not the parser.
"""

import re
import sqlite3
from dataclasses import dataclass, field

from . import match
from .version import is_determinate

# Ranges that no version string can settle: they are scoped to a serial number,
# a board revision, a ship date, or a bare hardware letter code.
UNDECIDABLE_RANGE = re.compile(
    r"serial|BIOS|U-Boot|special.modification|distributed|without"
    r"|Rev\.?[_\s]*\d|^[<>=\s]*[A-Z]{1,3}$|^[<>=\s]*[A-Z]\d{5,}",
    re.I,
)


@dataclass
class Result:
    total: int = 0
    decided: int = 0
    undecidable: int = 0
    missed: int = 0
    examples: dict = field(default_factory=dict)

    @property
    def coverage(self):
        """Share of all ranges we can decide."""
        return self.decided / self.total if self.total else 0.0

    @property
    def decidable_accuracy(self):
        """Share of the ranges that *can* be decided which we do decide."""
        base = self.decided + self.missed
        return self.decided / base if base else 0.0


def version_coverage(connection, limit=None):
    """Measure version-range parsing across every product in the index."""
    result = Result()
    sql = "SELECT version_range FROM product WHERE version_range != ''"
    if limit:
        sql += f" LIMIT {int(limit)}"

    for (range_text,) in connection.execute(sql):
        result.total += 1
        if is_determinate(range_text):
            result.decided += 1
        elif UNDECIDABLE_RANGE.search(range_text.strip()):
            result.undecidable += 1
        else:
            result.missed += 1
            key = range_text.strip()[:44]
            result.examples[key] = result.examples.get(key, 0) + 1
    return result


def identifier_coverage(connection):
    """Which identifiers the corpus actually carries, per product entry.

    This is the measurement the whole design rests on: conventional tooling
    joins products to CVEs through CPE, and CPE is all but absent from OT
    advisory data. Reproduced here rather than quoted, so a reader can check
    it on their own index instead of taking the claim on trust.

    Returns None for an index built before this was recorded: reporting zero
    CPEs there would be indistinguishable from having measured none, and a
    number nobody measured is the one thing this module must not print.
    """
    try:
        return _identifier_counts(connection)
    except sqlite3.OperationalError:        # index predates the has_cpe column
        return None


def _identifier_counts(connection):
    has_order = ("EXISTS(SELECT 1 FROM order_number o"
                 " WHERE o.product_rowid = p.rowid_)")
    row = connection.execute(
        "SELECT COUNT(*) total,"
        "       SUM(has_cpe) cpe,"
        "       SUM(helper_order_number) declared_order_number,"
        f"      SUM(helper_order_number = 0 AND {has_order}) recovered_order_number,"
        f"      SUM({has_order}) order_number,"
        "       SUM(vendor != '') vendor,"
        "       SUM(name != '') name"
        "  FROM product p").fetchone()
    return {key: (row[key] or 0) for key in row.keys()}


@dataclass
class RoundTrip:
    attempted: int = 0
    correct: int = 0
    wrong: int = 0
    abstained: int = 0
    by_method: dict = field(default_factory=dict)

    @property
    def precision(self):
        """Of the cases we answered, how many were right?"""
        answered = self.correct + self.wrong
        return self.correct / answered if answered else 0.0

    @property
    def recall(self):
        """Of every case, how many did we answer correctly?"""
        return self.correct / self.attempted if self.attempted else 0.0


def as_a_buyer_would_type_it(name):
    """Rough up a catalogue name the way a purchase requisition would.

    Feeding the corpus string back verbatim would only prove that exact string
    equality works, and would report a meaningless 100%. Real requests drop the
    parenthetical order number, lose punctuation and case, and stop after the
    first few words, so the test does the same.
    """
    text = re.sub(r"\([^)]*\)", " ", name)          # drop "(6ES7518-4AX00-1AB0)"
    text = re.sub(r"[^A-Za-z0-9 ]+", " ", text)     # drop punctuation
    words = text.lower().split()
    return " ".join(words[:4])                      # a buyer types the short form


def round_trip(connection, sample=400, realistic=True):
    """Resolve known products back to their own advisory.

    Ground truth comes from the corpus itself: take a product entry, hand the
    matcher only what a buyer would plausibly type, and require the original
    advisory to come back among the matches.
    """
    rows = connection.execute(
        "SELECT p.rowid_, p.advisory_id, p.vendor, p.name,"
        "       (SELECT o.number_key FROM order_number o"
        "         WHERE o.product_rowid = p.rowid_ LIMIT 1) AS order_key"
        "  FROM product p WHERE p.vendor != '' AND p.name != ''"
        f" ORDER BY (p.rowid_ * 2654435761) % {2**31 - 1} LIMIT {int(sample)}"
    ).fetchall()

    trip = RoundTrip()
    for row in rows:
        query = as_a_buyer_would_type_it(row["name"]) if realistic else row["name"]
        if not query:
            continue
        trip.attempted += 1
        resolution = match.resolve(
            connection,
            vendor=row["vendor"],
            product=query,
            order_number=row["order_key"],
        )
        if not resolution.resolved:
            trip.abstained += 1
            continue

        found = any(m.advisory_id == row["advisory_id"] for m in resolution.matches)
        if found:
            trip.correct += 1
        else:
            trip.wrong += 1
        bucket = trip.by_method.setdefault(resolution.method, {"correct": 0, "wrong": 0})
        bucket["correct" if found else "wrong"] += 1

    return trip


@dataclass
class QueryOutcome:
    """One buyer query against its hand-written expectation."""

    query: str
    expect: str
    got: str
    passed: bool
    note: str = ""


def buyer_queries(connection, path):
    """Run the hand-written query set and compare against its expectations.

    The round-trip test above generates its queries from the corpus, which
    measures degradation the generator chose. This set is authored the other
    way round: real requisition habits -- misspellings, vendor shorthand,
    dropped hyphens, catalogue numbers typed into the wrong field -- each with
    the answer a human analyst would give. Expectations record the CORRECT
    answer, not the current behaviour, so a row this tool fails stays visible
    as a miss rather than being papered over.

    Each row expects either an advisory id that must be among the matches, or
    the word "abstain". An optional `reject` column names an advisory that
    must NOT appear -- how "RSLogix 5 must not reach RSLogix 5000" is written.
    """
    import csv

    outcomes = []
    with open(path, encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            expect = (row.get("expect") or "").strip()
            if not expect:
                continue
            resolution = match.resolve(
                connection,
                vendor=(row.get("vendor") or "").strip() or None,
                product=(row.get("product") or "").strip() or None,
                order_number=(row.get("order_number") or "").strip() or None)
            advisories = {m.advisory_id for m in resolution.matches}

            if expect == "abstain":
                passed = not resolution.resolved
                got = "abstained" if passed else                     f"resolved to {sorted(advisories)[0]} by {resolution.method}"
            else:
                passed = resolution.resolved and expect in advisories
                if reject := (row.get("reject") or "").strip():
                    passed = passed and reject not in advisories
                if not resolution.resolved:
                    got = "abstained"
                elif expect not in advisories:
                    got = f"resolved, but to {sorted(advisories)[0]}"
                elif reject and reject in advisories:
                    got = f"correct, but {reject} came with it"
                else:
                    got = f"correct by {resolution.method}"

            query = " ".join(filter(None, [
                row.get("vendor"), row.get("product"), row.get("order_number")]))
            outcomes.append(QueryOutcome(query=query.strip(), expect=expect,
                                         got=got, passed=passed,
                                         note=(row.get("note") or "").strip()))
    return outcomes


def format_queries(outcomes):
    """The pass/fail table for the buyer-query set."""
    passed = sum(1 for o in outcomes if o.passed)
    lines = [f"BUYER-QUERY SET   {passed}/{len(outcomes)} as a human would answer",
             ""]
    for o in outcomes:
        mark = "pass" if o.passed else "MISS"
        lines.append(f"  {mark}  {o.query[:44]:<44} {o.got}")
        if not o.passed and o.note:
            lines.append(f"        {o.note}")
    return "\n".join(lines)


def run(connection, sample=400):
    """Run both measurements. Returns a dict ready to print or serialise."""
    coverage = version_coverage(connection)
    trip = round_trip(connection, sample=sample)
    return {"identifiers": identifier_coverage(connection),
            "version": coverage, "round_trip": trip}


def _share(count, total):
    """Percentage helper that survives an empty index."""
    return count / total if total else 0.0


def format_report(results):
    """Human-readable summary -- this is what `retrust eval` prints."""
    version, trip = results["version"], results["round_trip"]
    if not version.total and not trip.attempted:
        return ("The index is empty, so there is nothing to measure.\n"
                "Run `retrust ingest --csaf <dir>` first.")
    lines = []
    if results.get("identifiers", False) is None:
        lines += ["IDENTIFIER COVERAGE   not recorded by the build that made this",
                  "  index -- re-run `retrust ingest` to measure it.", ""]
    elif identifiers := results.get("identifiers"):
        total = identifiers["total"]
        lines += ["IDENTIFIER COVERAGE   (what the corpus gives us to join on)",
                  f"  product entries              {total:>8,}"]
        for key, label in (("cpe", "CPE -- what scanners join on"),
                           ("declared_order_number", "order number, declared"),
                           ("recovered_order_number", "order number, recovered by us"),
                           ("order_number", "order number, either"),
                           ("vendor", "vendor name"),
                           ("name", "product name")):
            lines.append(f"  {label:<30} {identifiers[key]:>8,}   "
                         f"{_share(identifiers[key], total):6.2%}")
        if identifiers["cpe"]:
            lines.append(
                f"  declared order numbers are "
                f"{identifiers['declared_order_number'] / identifiers['cpe']:,.0f}x "
                f"more available than CPE; all of them, "
                f"{identifiers['order_number'] / identifiers['cpe']:,.0f}x")
        lines.append("")
    lines += [
        "VERSION-RANGE COVERAGE",
        f"  ranges examined              {version.total:>8,}",
        f"  decided deterministically    {version.decided:>8,}   {version.coverage:6.2%}",
        f"  undecidable by design        {version.undecidable:>8,}   "
        f"{_share(version.undecidable, version.total):6.2%}  (serial / revision / date scoped)",
        f"  missed                       {version.missed:>8,}   "
        f"{_share(version.missed, version.total):6.2%}",
        "",
        f"  accuracy on decidable ranges {version.decidable_accuracy:6.2%}",
        "",
        "PRODUCT ROUND-TRIP",
        f"  products tested              {trip.attempted:>8,}",
        f"  resolved to the right advisory {trip.correct:>6,}",
        f"  resolved to the wrong one    {trip.wrong:>8,}",
        f"  abstained                    {trip.abstained:>8,}",
        "",
        f"  precision (of those answered) {trip.precision:6.2%}",
        f"  recall (of all attempted)     {trip.recall:6.2%}",
    ]
    if trip.by_method:
        lines.append("")
        lines.append("  by method:")
        for method, counts in sorted(trip.by_method.items()):
            total = counts["correct"] + counts["wrong"]
            lines.append(f"    {method:<14} {counts['correct']:>5,}/{total:<5,} "
                         f"{_share(counts['correct'], total):6.2%}")
    if version.examples:
        lines.append("")
        lines.append("  most common unparsed ranges:")
        for text, count in sorted(version.examples.items(), key=lambda kv: -kv[1])[:8]:
            lines.append(f"    {count:>4,}  {text!r}")
    return "\n".join(lines)
