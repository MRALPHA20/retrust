"""Everything the index already knows about one manufacturer.

Procurement shortlists suppliers before it shortlists products, and every other
ReTrust command starts from a product. A buyer asking "what is Moxa like as a
supplier?" therefore has nowhere to go. This module answers that question from
the same local index, so it needs no network either.

It is deliberately a description and not a judgement. Counting a vendor's
advisories and calling the total a risk would put a manufacturer that discloses
diligently below one that stays quiet, which is exactly backwards. So nothing
here is a score, a grade or a rank: only the figures, the vendor's own
disclosure behaviour, and the certification and sanctions evidence -- each
labelled with whether it was actually checked, because a zero from a check that
never ran reads as reassurance and would be the worst thing this could print.
"""

import statistics
import textwrap
from dataclasses import dataclass, field

from . import certification, score, supplychain
from .index import normalize_vendor

TOP_PRODUCTS = 8
CERTIFICATES = 8

# The affected table carries no vendor column, so every vendor-scoped figure
# reaches it through product -- the same join match.findings uses.
_AFFECTED = ("affected a JOIN product p"
             " ON p.advisory_id = a.advisory_id AND p.product_id = a.product_id")

REMEDIES = (("vendor_fix", "a vendor fix"),
            ("mitigation_only", "mitigation or workaround only"),
            ("no_fix", "no fix available"),
            ("nothing_stated", "nothing stated"))

NOT_A_VERDICT = (
    "  These are counts of what has been published, not a verdict. A vendor that",
    "  discloses diligently shows more advisories than one that stays quiet, so",
    "  ReTrust does not score or rank vendors.",
)

NOT_IN_THE_CORPUS = (
    "  No advisory in this index names this manufacturer. Absence of advisories",
    "  is not evidence of safety: it may mean nobody has published about them,",
    "  that they disclose privately, or that CISA spells the name differently.",
    "  Check the spelling against the names the corpus does carry before reading",
    "  anything into this.",
)

NO_CERTIFICATE = (
    "  no entry in the ISASecure or Common Criteria caches. Most OT products are",
    "  never submitted for certification, so this is not a mark against them.",
)


@dataclass
class Dossier:
    """One vendor profile, in which None never means zero.

    kev_cves, peak_cvss, certificates and screening_gates are None when the
    thing was not measured or the cache was not supplied. No field holds a
    score, a grade, a band or a rank, by design -- see the module docstring.
    """

    vendor: str                       # commonest raw spelling, else what was typed
    vendor_key: str
    known: bool = False               # does any advisory name this manufacturer
    spellings: list = field(default_factory=list)
    products: int = 0                 # product entries, not distinct products
    product_names: int = 0
    advisories: int = 0
    cves: int = 0
    first_advisory: str | None = None
    last_advisory: str | None = None
    kev_cves: int | None = None       # None until a KEV is loaded into this index
    remediation: dict = field(default_factory=dict)
    peak_cvss: float | None = None
    median_cvss: float | None = None
    csaf_feed: str | None = None      # provider-metadata URL when it runs its own
    top_products: list = field(default_factory=list)
    certificates: list | None = None      # None: no certification cache supplied
    screening_gates: list | None = None   # None: no screening cache supplied
    screening_notes: list = field(default_factory=list)


def build(connection, vendor, screening=None, certificates=None):
    """Gather one vendor profile. Both caches are optional."""
    typed = (vendor or "").strip()
    vendor_key = normalize_vendor(typed)
    # Punctuation-only input normalises to "", which is also the key of every
    # product whose advisory named no vendor at all. Treat it as unknown rather
    # than profiling that pile of unrelated boxes as if it were a company.
    spellings = _spellings(connection, vendor_key) if vendor_key else []
    profile = Dossier(vendor=spellings[0][0] if spellings else typed,
                      vendor_key=vendor_key, known=bool(spellings),
                      spellings=spellings,
                      csaf_feed=score.CSAF_PUBLISHERS.get(vendor_key))
    if profile.known:
        _corpus(connection, profile)

    # Both checks run even for a manufacturer the corpus never names: someone
    # nobody has written an advisory about can still sit on a covered list, and
    # that is the most useful thing this profile can say about them.
    if screening is not None:
        profile.screening_gates = supplychain.gates_for(screening, profile.vendor)
        profile.screening_notes = supplychain.notes_for(screening, profile.vendor)
    if certificates is not None:
        profile.certificates = certification.certificates_for(
            certificates, profile.vendor)
    return profile


def _spellings(connection, vendor_key):
    """The raw vendor strings that collapse to this key, commonest first."""
    return [(row["vendor"], row["entries"]) for row in connection.execute(
        "SELECT vendor, COUNT(*) entries FROM product"
        " WHERE vendor_key = ? AND vendor != ''"
        " GROUP BY vendor ORDER BY entries DESC, vendor", (vendor_key,))]


def _corpus(connection, profile):
    """Fill in what the advisory index holds for this vendor."""
    key = profile.vendor_key
    # NULLIF keeps the empty string CSAF leaves behind when an advisory omits
    # its release date out of the first and last dates.
    row = connection.execute(
        "SELECT COUNT(*) products, COUNT(DISTINCT p.advisory_id) advisories,"
        " MIN(NULLIF(a.released,'')) first, MAX(NULLIF(a.released,'')) last"
        " FROM product p JOIN advisory a ON a.id = p.advisory_id"
        " WHERE p.vendor_key = ?", (key,)).fetchone()
    profile.products, profile.advisories = row["products"], row["advisories"]
    profile.first_advisory, profile.last_advisory = row["first"], row["last"]

    # One row per CVE: a CVE scored against one product and left unscored
    # against another would otherwise be counted twice and drag the median.
    scored = [row["cvss"] for row in connection.execute(
        f"SELECT a.cve, MAX(a.cvss) cvss FROM {_AFFECTED}"
        " WHERE p.vendor_key = ? GROUP BY a.cve", (key,))]
    profile.cves = len(scored)
    if measured := [value for value in scored if value is not None]:
        profile.peak_cvss = max(measured)
        profile.median_cvss = statistics.median(measured)

    # A bare 0 cannot be told apart from "no KEV was ever loaded", so abstain
    # until the index actually carries the catalogue.
    if connection.execute(
            "SELECT 1 FROM exploitation WHERE in_kev = 1 LIMIT 1").fetchone():
        profile.kev_cves = connection.execute(
            f"SELECT COUNT(DISTINCT a.cve) FROM {_AFFECTED}"
            " JOIN exploitation e ON e.cve = a.cve"
            " WHERE p.vendor_key = ? AND e.in_kev = 1", (key,)).fetchone()[0]

    for row in connection.execute(
        "SELECT MAX(a.remediation = 'vendor_fix') has_fix,"
        " MAX(a.remediation IN ('mitigation','workaround')) partial,"
        " MAX(a.remediation = 'none_available') no_fix"
        f" FROM {_AFFECTED} WHERE p.vendor_key = ? GROUP BY a.advisory_id", (key,)):
        best = ("vendor_fix" if row["has_fix"] else
                "mitigation_only" if row["partial"] else
                "no_fix" if row["no_fix"] else "nothing_stated")
        profile.remediation[best] = profile.remediation.get(best, 0) + 1

    # Grouped by name_key because sibling version-range leaves inherit one
    # product_name branch, so the raw name repeats once per version range.
    named = connection.execute(
        "SELECT MIN(p.name) name, COUNT(DISTINCT p.advisory_id) advisories"
        " FROM product p WHERE p.vendor_key = ? AND p.name != ''"
        " GROUP BY p.name_key ORDER BY advisories DESC, name", (key,)).fetchall()
    profile.product_names = len(named)
    profile.top_products = [(r["name"], r["advisories"]) for r in named[:TOP_PRODUCTS]]


def format_report(profile):
    """Printable text -- this is what `retrust dossier` shows."""
    count = len(profile.spellings)
    lines = [f"VENDOR DOSSIER   {profile.vendor or '(no vendor given)'}",
             f'  vendor key "{profile.vendor_key}" -- ' + (
                 f"{count} spelling{'' if count == 1 else 's'} in the corpus"
                 if profile.known else "not in the corpus"), ""]

    if profile.known:
        lines += ["WHAT THE INDEX HOLDS", *_rows((
            ("advisories", f"{profile.advisories:,}"),
            ("product entries", f"{profile.products:,}"),
            ("distinct CVEs", f"{profile.cves:,}"),
            ("first advisory", profile.first_advisory or "not recorded"),
            ("most recent advisory", profile.last_advisory or "not recorded"),
            ("CVEs listed in CISA KEV", _figure(profile.kev_cves, ",", "not checked")),
            ("highest CVSS", _figure(profile.peak_cvss)),
            ("median CVSS", _figure(profile.median_cvss)),
        )), "", *NOT_A_VERDICT, ""]
    else:
        lines += [*NOT_IN_THE_CORPUS, ""]

    if profile.remediation:
        lines += ["REMEDIATION   (advisories by the best remedy they offer)",
                  *_rows([(label, f"{profile.remediation.get(key, 0):,}")
                          for key, label in REMEDIES]), ""]

    if profile.known or profile.csaf_feed:
        lines += ["DISCLOSURE",
                  "  runs its own CSAF trusted provider feed" if profile.csaf_feed
                  else "  no CSAF feed of its own; disclosure relies on CISA"
                       " republishing"]
        lines += [f"    {profile.csaf_feed}"] if profile.csaf_feed else []
        lines.append("")

    if profile.spellings:
        lines += ["VENDOR NAMES IN THE CORPUS   (product entries under each)",
                  "  any of these works as --vendor; they collapse to one key",
                  *_listing(profile.spellings), ""]

    if profile.top_products:
        lines += [f"MOST-NAMED PRODUCTS   ({len(profile.top_products)} of "
                  f"{profile.product_names:,} distinct names, by advisories)",
                  *_listing(profile.top_products), ""]

    return "\n".join(lines + _certification(profile) + [""] + _screening(profile))


def _certification(profile):
    """Certificates held, or a plain statement that nothing was checked."""
    if profile.certificates is None:
        return ["CERTIFICATION",
                "  not checked: no certification cache loaded -- run `retrust refresh`"]
    if not profile.certificates:
        return ["CERTIFICATION", *NO_CERTIFICATE]
    lines = ["CERTIFICATION"]
    for record in profile.certificates[:CERTIFICATES]:
        lines.append(f"  {record['scheme']}   {_clip(record.get('product'), 48)}")
        if record.get("detail"):
            lines.append(f"    {_clip(record['detail'], 70)}")
    if len(profile.certificates) > CERTIFICATES:
        lines.append(f"  ... and {len(profile.certificates) - CERTIFICATES} further"
                     " certificates, not shown")
    return lines


def _screening(profile):
    """The sanctions result, or that no screening cache was supplied."""
    if profile.screening_gates is None:
        return ["SCREENING",
                "  not checked: no screening cache loaded -- run `retrust refresh`"]
    lines = ["SCREENING"]
    if not profile.screening_gates:
        lines.append("  no sanctions or covered-list entry matches "
                     f'"{profile.vendor}"')
    # One identical gate comes back per list that names the vendor. The wording
    # is supplychain's own, legally careful, and printed unchanged.
    for gate in {g["detail"]: g for g in profile.screening_gates}.values():
        lines.append(f"  {gate['gate']}")
        lines += _wrap(gate["detail"], "    ")
        lines.append(f"    source: {gate['source']}")
    for note in profile.screening_notes:
        lines += _wrap(note, "  ")
    return lines


def _rows(pairs):
    """The aligned two-column block, so the report has one column geometry."""
    return [f"  {label:<34}{value:>12}" for label, value in pairs]


def _listing(pairs):
    """Count-first rows, for the spelling and product tables."""
    return [f"  {count:>6}  {_clip(text, 66)}" for text, count in pairs]


def _figure(value, spec=".1f", absent="not recorded"):
    """Format a measured number, or say plainly that it was not measured."""
    return absent if value is None else format(value, spec)


def _clip(text, width):
    """Corpus product names reach 330 characters; keep the tables at 80 columns."""
    text = (text or "").strip()
    return text if len(text) <= width else text[:width - 3] + "..."


def _wrap(text, indent):
    return textwrap.wrap(text, 78, initial_indent=indent, subsequent_indent=indent)
