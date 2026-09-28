"""A product's advisory history drawn as a shape, not scored as a number.

A buyer choosing between two PLCs wants to see when advisories land, whether
the cadence is accelerating, how the vendor's remediation mix has moved, and
how long the record has been quiet. No single figure carries that, so this
module aggregates the record per year and draws it.

It refuses to turn the shape into a judgement. Cadence measures disclosure
activity, not safety: a discontinued product stops earning advisories and its
record goes quiet, while a vendor that discloses diligently looks noisy. The
report states that caveat itself rather than trusting a reader to know it.

It is also deterministic. "Quiet for" is measured against the newest release
date the corpus holds, never today's clock, so the same index prints the same
report forever and a figure in a slide deck stays reproducible.
"""

import re
import textwrap
from dataclasses import dataclass, field
from datetime import date

# The widest bar drawn: 8 columns of prefix and 44 of counts leave exactly
# this much of an 80-column line for the bar itself.
BAR_WIDTH = 28

# `released` as the index stores it: an ISO date or the empty string. Anything
# else counts as undated rather than crashing, so a hand-built index surfaces
# its defect as a stated figure instead of a traceback.
_DATE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})$")

CAVEAT = (
    "Cadence measures disclosure activity, not safety. A discontinued product"
    " stops earning advisories and its record goes quiet, while a vendor that"
    " discloses diligently looks noisy here. A quiet year is an absence of"
    " published data, never evidence that nothing was there to find.")


@dataclass
class YearBucket:
    """One year of the record. A year with no advisories is still a row."""

    year: int
    advisories: int = 0
    cves: int = 0                    # distinct CVEs across the year's advisories
    worst_cvss: float | None = None  # None when no finding that year carried one
    fixed: int = 0                   # advisories offering a vendor fix

@dataclass
class Timeline:
    """The aggregated record. Totals include undated advisories; bars cannot."""

    years: list = field(default_factory=list)   # contiguous, zero-filled
    advisories: int = 0
    cves: int = 0       # distinct CVEs across the whole selection
    fixed: int = 0      # advisories offering a vendor fix, undated ones included
    undated: int = 0    # advisories with no release date, outside the bars
    missing: int = 0    # pairs naming advisories this index does not hold
    first: str = ""     # oldest dated release in the selection
    last: str = ""      # newest dated release in the selection
    as_of: str = ""     # newest dated release anywhere in the corpus

    @property
    def quiet_months(self):
        """Whole months from the last advisory to the corpus's newest date.

        Measured against the corpus rather than the clock: "quiet" only means
        anything relative to a record that is still being written, and using
        today's date would make every report age on the shelf.
        """
        if not self.last or not self.as_of:
            return None
        return _whole_months(self.last, self.as_of)

    @property
    def fix_trend(self):
        """Fix share over the first half of the years drawn, then the second.

        Halves of the calendar record, not of the advisory count: the question
        is whether the vendor's remediation practice moved over time, and a
        split by count would let one busy year straddle the boundary.
        """
        if len(self.years) < 2:
            return (None, None)
        middle = _middle(self.years)
        return (_half_share(self.years[:middle]), _half_share(self.years[middle:]))


def build(connection, pairs):
    """Aggregate the advisories a match resolution names.

    `pairs` is a list of (advisory_id, product_id) rows: exactly what a
    resolution hands the scorer, so the timeline describes the same rows a
    verdict would rest on.
    """
    by_advisory = {}
    for advisory_id, product_id in pairs:
        by_advisory.setdefault(advisory_id, set()).add(product_id)

    timeline = Timeline(as_of=_newest_release(connection))
    cves, dated, buckets = set(), [], {}
    # One query per advisory, filtered in Python rather than with an IN
    # clause: a single advisory can name over a thousand product ids
    # (ICSA-24-235-03 holds 1,391), which would exceed SQLite's
    # bound-variable ceiling on older builds.
    for advisory_id in sorted(by_advisory):
        row = connection.execute(
            "SELECT released FROM advisory WHERE id = ?", (advisory_id,)).fetchone()
        if row is None:
            # A pair naming an advisory this index does not hold means the
            # caller mixed resolutions from another index. Counted and said,
            # like `undated`: an invisible skip at exactly the moment the
            # data is wrong would be false calm.
            timeline.missing += 1
            continue
        wanted = by_advisory[advisory_id]
        findings = [f for f in connection.execute(
            "SELECT product_id, cve, cvss, remediation FROM affected"
            " WHERE advisory_id = ?", (advisory_id,))
            if f["product_id"] in wanted]

        advisory_cves = {f["cve"] for f in findings if f["cve"]}
        worst = max((f["cvss"] for f in findings if f["cvss"] is not None),
                    default=None)
        # The advisory offers a fix if any of its entries for these products
        # does, mirroring how the vendor dossier reads the same column.
        fixed = any(f["remediation"] == "vendor_fix" for f in findings)

        timeline.advisories += 1
        timeline.fixed += int(fixed)
        cves |= advisory_cves
        released = (row["released"] or "").strip()
        if not (match := _DATE.match(released)) or not _real_date(released):
            timeline.undated += 1
            continue
        dated.append(released)
        bucket = buckets.setdefault(int(match.group(1)), {
            "advisories": 0, "cves": set(), "worst": None, "fixed": 0})
        bucket["advisories"] += 1
        bucket["cves"] |= advisory_cves
        bucket["fixed"] += int(fixed)
        if worst is not None:
            bucket["worst"] = (worst if bucket["worst"] is None
                               else max(bucket["worst"], worst))

    timeline.cves = len(cves)
    if dated:
        timeline.first, timeline.last = min(dated), max(dated)
        # Contiguous and zero-filled, so a gap year is a measured zero the
        # reader can see rather than a row that quietly fell out.
        for year in range(int(timeline.first[:4]), int(timeline.last[:4]) + 1):
            data = buckets.get(year)
            timeline.years.append(
                YearBucket(year=year) if data is None else
                YearBucket(year=year, advisories=data["advisories"],
                           cves=len(data["cves"]), worst_cvss=data["worst"],
                           fixed=data["fixed"]))
    return timeline


def for_vendor(connection, vendor_key):
    """The timeline of every advisory naming one manufacturer.

    Takes the normalised key, as `product.vendor_key` stores it, and does not
    re-normalise: keys are already bare lowercase alphanumerics, and running
    normalize_vendor over one again can strip a key that happens to spell a
    company suffix ("ab") down to nothing.
    """
    if not vendor_key:
        # Nameless products are not one manufacturer's history. dossier.build
        # refuses the same pile for the same reason.
        return build(connection, [])
    pairs = [(row["advisory_id"], row["product_id"]) for row in connection.execute(
        "SELECT DISTINCT advisory_id, product_id FROM product"
        " WHERE vendor_key = ? ORDER BY advisory_id, product_id", (vendor_key,))]
    return build(connection, pairs)


def _newest_release(connection):
    """The newest dated release anywhere in the corpus: the report's clock.

    Gated like the year buckets are: MAX over text is lexicographic, so one
    "TBD" or "9999-12-31" in a hand-built index would otherwise become the
    clock for every report drawn from it.
    """
    row = connection.execute(
        "SELECT MAX(released) FROM advisory WHERE released GLOB"
        " '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'").fetchone()
    return row[0] or ""


def _real_date(text):
    """A shape-valid but impossible date ("2026-13-40") counts as undated."""
    try:
        date.fromisoformat(text)
    except ValueError:
        return False
    return True


def _whole_months(earlier, later):
    """Whole calendar months between two ISO dates, floored at zero."""
    try:
        first, second = date.fromisoformat(earlier), date.fromisoformat(later)
    except ValueError:
        return None
    months = (second.year - first.year) * 12 + (second.month - first.month)
    if second.day < first.day:
        months -= 1
    return max(0, months)


def _middle(years):
    """Where the record splits in half. One place, so the printed year-span
    labels can never desync from the shares they caption."""
    return (len(years) + 1) // 2


def _half_share(buckets):
    """Fix share across one half of the record, or None when it is empty."""
    advisories = sum(b.advisories for b in buckets)
    if not advisories:
        return None
    return sum(b.fixed for b in buckets) / advisories


def _span(buckets):
    """A half's year range, as a label: "2019" or "2019-2021"."""
    first, last = buckets[0].year, buckets[-1].year
    return str(first) if first == last else f"{first}-{last}"


def _bar_length(count, scale):
    """At least one mark for any year with an advisory, however tall the peak."""
    return max(1, round(count * scale)) if count else 0


def format_report(subject, timeline):
    """The printed shape: bars first, then the record's edges, then the caveat."""
    lines = [f"ADVISORY TIMELINE   {subject}", ""]
    if not timeline.advisories:
        lines += [_wrap(
            "No advisories in this selection, so there is no history to draw."
            " Absence of advisories is not evidence of safety: nobody may have"
            " published about this product, or the corpus may spell its name"
            " differently."), "", _wrap(CAVEAT)]
        return "\n".join(lines)

    if timeline.years:
        peak = max(bucket.advisories for bucket in timeline.years)
        scale = 1.0 if peak <= BAR_WIDTH else BAR_WIDTH / peak
        width = max(_bar_length(b.advisories, scale) for b in timeline.years)
        for bucket in timeline.years:
            if not bucket.advisories:
                lines.append(f"  {bucket.year}  .")
                continue
            bar = "#" * _bar_length(bucket.advisories, scale)
            worst = ("  --" if bucket.worst_cvss is None
                     else f"{bucket.worst_cvss:4.1f}")
            lines.append(
                f"  {bucket.year}  {bar:<{width}}  {bucket.advisories:>3} adv"
                f"  {bucket.cves:>4} CVE  worst {worst}"
                f"  fix {bucket.fixed}/{bucket.advisories}")
        lines.append("")

    if timeline.first:
        lines.append(f"  first advisory   {timeline.first}")
        lines.append(f"  last advisory    {timeline.last}")
    if (quiet := timeline.quiet_months) is not None:
        lines.append(f"  quiet for        {quiet} whole month(s),"
                     f" as of {timeline.as_of}")
    if timeline.missing:
        lines.append(f"  not in index     {timeline.missing} advisory reference(s)"
                     " this index does not hold -- mixed indexes?")
    if timeline.undated:
        lines.append(f"  undated          {timeline.undated} advisory(ies) carry"
                     " no release date (not drawn)")
    first_half, second_half = timeline.fix_trend
    if first_half is not None and second_half is not None:
        middle = _middle(timeline.years)
        lines.append(f"  fix share        {first_half:.0%} of"
                     f" {_span(timeline.years[:middle])} advisories offered"
                     f" a vendor fix,")
        lines.append(f"                   {second_half:.0%} of"
                     f" {_span(timeline.years[middle:])} advisories did")
    else:
        lines.append(f"  fix share        {timeline.fixed}/{timeline.advisories}"
                     f" advisories offer a vendor fix")

    if timeline.quiet_months is not None:
        lines += ["", _wrap(
            "\"As of\" is the newest release date this corpus holds, not"
            " today's date: measured against the clock, the same index would"
            " print a different report every month it sat on a shelf.")]
    lines += ["", _wrap(CAVEAT)]
    return "\n".join(lines)


def _wrap(text, width=78):
    return "\n".join(textwrap.wrap(text, width))
