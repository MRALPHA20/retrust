"""Everything the index already knows about one manufacturer.

Procurement shortlists suppliers before it shortlists products, and every other
ReTrust command starts from a product, so a buyer asking "what is Moxa like as a
supplier?" has nowhere to go. This profile answers that from the same local
index, and needs no network either.

It describes; it does not judge. Counting a vendor's advisories and calling the
total a risk would put a manufacturer that discloses diligently below one that
stays quiet, which is exactly backwards -- so nothing here is a score, a grade or
a rank. Every figure also says whether it was measured at all, because a zero
from a check that never ran reads as reassurance.
"""

import statistics
import textwrap
from dataclasses import dataclass, field

from . import certification, score, supplychain
from .index import normalize_vendor

# Rows printed from the product table and the certificate list. Both say how many
# there were in total, so the cut is visible rather than silently invented.
SHOWN = 8

# The affected table has no vendor column, so every vendor-scoped figure reaches
# it through the (advisory, product) pairs this vendor appears under.
_PAIRS = ("(SELECT DISTINCT p.advisory_id id, p.product_id pid FROM product p"
          " WHERE p.vendor_key = ?) v")
_ON = " ON a.advisory_id = v.id AND a.product_id = v.pid"

REMEDIES = (("vendor_fix", "a vendor fix"),
            ("mitigation_only", "mitigation or workaround only"),
            ("no_fix", "no fix available"), ("nothing_stated", "nothing stated"))

# The best remedy any of an advisory's entries offers this vendor, in REMEDIES order.
_BEST_REMEDY = ("CASE WHEN MAX(a.remediation = 'vendor_fix') THEN 'vendor_fix'"
                " WHEN MAX(a.remediation IN ('mitigation','workaround')) THEN 'mitigation_only'"
                " WHEN MAX(a.remediation = 'none_available') THEN 'no_fix'"
                " ELSE 'nothing_stated' END")

NOT_A_VERDICT = (
    "These are counts of what has been published, not a verdict. A vendor that"
    " discloses diligently shows more advisories than one that stays quiet, so"
    " ReTrust does not score or rank vendors.")

NOT_IN_THE_CORPUS = (
    "No advisory in this index names this manufacturer. Absence of advisories is"
    " not evidence of safety: it may mean nobody has published about them, that"
    " they disclose privately, or that CISA spells the name differently. Check the"
    " spelling against the names the corpus does carry before reading into this.")

NO_CERTIFICATE = (
    "no entry in the ISASecure or Common Criteria caches. Most OT products are"
    " never submitted for certification, so this is not a mark against them.")

NO_SANCTIONS_LIST = ("the sanctions list is not cached, so only the FCC and NDAA"
                     " covered lists were checked -- run `retrust refresh`")


@dataclass
class Dossier:
    """One vendor profile, in which None never means zero.

    kev_cves, the CVSS figures, certificates and screening_gates are None when the
    thing was not measured or its cache was never loaded. No field holds a score,
    a grade, a band or a rank, by design -- see the module docstring.
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
    certificates: list | None = None      # None: no certificate cache was loaded
    screening_gates: list | None = None   # None: no screening cache was supplied
    screening_notes: list = field(default_factory=list)
    sanctions_checked: bool = False   # False: only the covered lists were searched


def build(connection, vendor, screening=None, certificates=None):
    """Gather one vendor profile. Both caches are optional."""
    typed = (vendor or "").strip()
    # Punctuation-only input normalises to "", which is also the key of every
    # product whose advisory named no vendor at all. Treat that as unknown rather
    # than profile a pile of unrelated boxes as though it were a company.
    vendor_key = normalize_vendor(typed)
    spellings = [] if not vendor_key else [
        (row["vendor"], row["entries"]) for row in connection.execute(
            "SELECT vendor, COUNT(*) entries FROM product WHERE vendor_key = ?"
            " AND vendor != '' GROUP BY vendor ORDER BY entries DESC, vendor",
            (vendor_key,))]
    profile = Dossier(vendor=spellings[0][0] if spellings else typed,
                      vendor_key=vendor_key, known=bool(spellings), spellings=spellings,
                      csaf_feed=score.CSAF_PUBLISHERS.get(vendor_key))
    if profile.known:
        _corpus(connection, profile)

    # Both checks run even for a manufacturer the corpus never names: someone
    # nobody has written an advisory about can still sit on a covered list, and
    # that is the most useful thing this profile can say about them. An empty cache
    # holds nothing for anybody, so it counts as a check that never ran rather than
    # as a search that found nothing.
    if screening:
        profile.screening_gates = supplychain.gates_for(screening, profile.vendor)
        profile.screening_notes = supplychain.notes_for(screening, profile.vendor)
        # supplychain.load returns the hand-curated covered list even when no
        # screening.json was ever downloaded, and a clean result from those ten
        # entries alone must not pass for a sanctions screen.
        profile.sanctions_checked = any(hit["kind"] == "screening_list"
                                       for hits in screening.values() for hit in hits)
    if certificates:
        profile.certificates = certification.certificates_for(certificates, profile.vendor)
    return profile


def _corpus(connection, profile):
    """Fill in what the advisory index holds for this vendor."""
    key = profile.vendor_key
    # NULLIF keeps the empty string CSAF leaves behind, when an advisory omits its
    # release date, out of the first and last dates.
    row = connection.execute(
        "SELECT COUNT(*) products, COUNT(DISTINCT p.advisory_id) advisories,"
        " MIN(NULLIF(a.released,'')) first, MAX(NULLIF(a.released,'')) last"
        " FROM product p JOIN advisory a ON a.id = p.advisory_id"
        " WHERE p.vendor_key = ?", (key,)).fetchone()
    profile.products, profile.advisories = row["products"], row["advisories"]
    profile.first_advisory, profile.last_advisory = row["first"], row["last"]

    # One row per CVE: a CVE scored against one product and left unscored against
    # another would otherwise be counted twice and drag the median.
    scored = [r[0] for r in connection.execute(
        f"SELECT MAX(a.cvss) FROM {_PAIRS} JOIN affected a{_ON} GROUP BY a.cve", (key,))]
    profile.cves = len(scored)
    if measured := [value for value in scored if value is not None]:
        profile.peak_cvss, profile.median_cvss = max(measured), statistics.median(measured)

    # A bare 0 cannot be told apart from "no KEV was ever loaded", so abstain until
    # the index actually carries the catalogue.
    if connection.execute("SELECT 1 FROM exploitation WHERE in_kev = 1 LIMIT 1").fetchone():
        profile.kev_cves = connection.execute(
            f"SELECT COUNT(DISTINCT a.cve) FROM {_PAIRS} JOIN affected a{_ON}"
            " JOIN exploitation e ON e.cve = a.cve WHERE e.in_kev = 1", (key,)).fetchone()[0]

    # LEFT JOIN so the buckets stay exhaustive: an advisory can name this vendor's
    # products and then say nothing about them in any vulnerability entry, which is
    # what "nothing stated" means. An inner join dropped those advisories from this
    # table while the count above still included them, losing 11 of Schneider's 244.
    profile.remediation = {row["best"]: row["advisories"] for row in connection.execute(
        f"SELECT best, COUNT(*) advisories FROM (SELECT {_BEST_REMEDY} best"
        f" FROM {_PAIRS} LEFT JOIN affected a{_ON} GROUP BY v.id) GROUP BY best",
        (key,))}

    # Grouped by name_key because sibling version-range leaves inherit one
    # product_name branch, so the raw name repeats once per version range.
    named = connection.execute(
        "SELECT MIN(p.name) name, COUNT(DISTINCT p.advisory_id) advisories FROM product p"
        " WHERE p.vendor_key = ? AND p.name != '' GROUP BY p.name_key"
        " ORDER BY advisories DESC, name", (key,)).fetchall()
    profile.product_names = len(named)
    profile.top_products = [(r["name"], r["advisories"]) for r in named[:SHOWN]]


def format_report(profile):
    """Printable text -- this is what `retrust dossier` shows."""
    count = len(profile.spellings)
    lines = [f"VENDOR DOSSIER   {_clip(profile.vendor, 62) or '(no vendor given)'}",
             # Wrapped, because a corpus vendor key reaches 50 characters.
             *_wrap(f'vendor key "{profile.vendor_key}" -- ' + (
                 f"{count} spelling{'' if count == 1 else 's'} in the corpus"
                 if profile.known else "not in the corpus"), "  "), ""]

    if not profile.known:
        lines += [*_wrap(NOT_IN_THE_CORPUS, "  "), ""]
    else:
        lines += ["WHAT THE INDEX HOLDS", *_rows((
            ("advisories", f"{profile.advisories:,}"),
            ("product entries", f"{profile.products:,}"),
            ("distinct CVEs", f"{profile.cves:,}"),
            ("first advisory", profile.first_advisory or "not recorded"),
            ("most recent advisory", profile.last_advisory or "not recorded"),
            ("CVEs listed in CISA KEV", _figure(profile.kev_cves, ",", absent="not checked")),
            ("highest CVSS", _figure(profile.peak_cvss)),
            ("median CVSS", _figure(profile.median_cvss)))), "",
            *_wrap(NOT_A_VERDICT, "  "), ""]

    if profile.remediation:
        lines += ["REMEDIATION   (advisories by the best remedy they offer)",
                  *_rows([(label, f"{profile.remediation.get(key, 0):,}")
                          for key, label in REMEDIES]), ""]

    if profile.known or profile.csaf_feed:
        # Running a CSAF feed is the one disclosure fact the vendor itself controls.
        lines += ["DISCLOSURE", "  runs its own CSAF feed" if profile.csaf_feed
                  else "  no CSAF feed of its own; disclosure relies on CISA republishing"]
        lines += [f"    {profile.csaf_feed}", ""] if profile.csaf_feed else [""]

    if profile.spellings:
        lines += ["VENDOR NAMES IN THE CORPUS   (product entries under each)",
                  "  any of these works as --vendor; they collapse to one key",
                  *_rows([(name, f"{n:,}") for name, n in profile.spellings], 60), ""]

    if profile.top_products:
        lines += [(f"MOST-NAMED PRODUCTS   ({len(profile.top_products)} of"
                   f" {profile.product_names:,} distinct names, by advisories)"),
                  *_rows([(name, f"{n:,}") for name, n in profile.top_products], 60), ""]

    return "\n".join(lines + _evidence(profile))


def _evidence(profile):
    """The two optional checks: what they found, or that they never ran.

    "Not checked" and "nothing found" are kept strictly apart. A cache nobody
    loaded must never print as a clean bill of health, which is how a bare
    "no match" would read.
    """
    missing = "  not checked: no {} cache loaded -- run `retrust refresh`".format
    lines = ["CERTIFICATION"]
    if profile.certificates is None:
        lines.append(missing("certification"))
    elif not profile.certificates:
        lines += _wrap(NO_CERTIFICATE, "  ")
    else:
        for record in profile.certificates[:SHOWN]:
            lines.append(f"  {record['scheme']}   {_clip(record.get('product'), 48)}")
            if record.get("detail"):
                lines.append(f"    {_clip(record['detail'], 70)}")
        if len(profile.certificates) > SHOWN:
            lines.append(f"  ... and {len(profile.certificates) - SHOWN} further"
                         " certificates, not shown")

    lines += ["", "SCREENING"]
    if profile.screening_gates is None:
        return lines + [missing("screening")]
    if not profile.sanctions_checked:
        lines += _wrap(NO_SANCTIONS_LIST, "  ")
    if not (profile.screening_gates or profile.screening_notes):
        lines += _wrap(f'no match for "{profile.vendor}" on the '
                       + ("sanctions and covered lists" if profile.sanctions_checked
                          else "covered lists"), "  ")
    # One identical gate comes back per list that names the vendor. The wording is
    # supplychain's own, legally careful, and printed unchanged.
    for gate in {g["detail"]: g for g in profile.screening_gates}.values():
        lines += [f"  {gate['gate']}", *_wrap(gate["detail"], "    "),
                  f"    source: {_clip(gate['source'], 70)}"]
    for note in profile.screening_notes:
        lines += _wrap(note, "  ")
    return lines


def _rows(pairs, label_width=34):
    """The one column geometry here: the name left, the measured figure right."""
    return [f"  {_clip(label, label_width):<{label_width}}{value:>12}"
            for label, value in pairs]


def _figure(value, spec=".1f", absent="not recorded"):
    """Format a measured number, or say plainly that it was not measured."""
    return absent if value is None else format(value, spec)


def _clip(text, width):
    """Corpus product names reach 330 characters; keep every table at 80 columns."""
    text = " ".join((text or "").split())    # a newline here would forge a heading
    return text if len(text) <= width else text[:width - 3] + "..."


def _wrap(text, indent):
    """Prose and long identifiers, folded to fit an 80-column terminal."""
    return textwrap.wrap(text, 78, initial_indent=indent, subsequent_indent=indent)
