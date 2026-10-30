"""One CVE, everything this index knows about it.

Every other surface in ReTrust starts from a product: resolve it, then read
its findings. Mid-incident and mid-review the question arrives the other way
round -- "CVE-2023-44487: does anything we are buying carry it?" -- and
answering that by re-scoring every candidate product is the wrong shape of
work. This module pivots directly: one CVE's exploitation signals, and the
spread of corpus products that carry it.

Two refusals shape it. No field is ever invented: an EPSS nobody loaded
prints as absent rather than as zero, and a missing LEV says whether the
history was never loaded or the CVE was simply never scored, because those
are different facts. And the two ways a CVE can be "not here" stay distinct:
absent from the whole index is None, while listed in CISA's KEV catalogue
yet naming no corpus product is a View saying exactly that -- mid-incident,
"nothing we buy carries it" is a real and useful answer.

Every count is corpus-scoped and the report closes by saying so: CISA's OT
advisories as indexed here, not the world.
"""

import re
import textwrap
from dataclasses import dataclass, field

from . import cvss, index

# Display caps. Eight vendors and six advisories show the spread without
# turning the report into a dump; every elision states what it hid.
MAX_VENDORS = 8
MAX_ADVISORIES = 6

# csaf.py's remediation categories, best first, so the mix prints in the
# order a reader weighs remedies rather than alphabetically.
CATEGORIES = ("vendor_fix", "mitigation", "workaround", "none_available",
              "unknown")


@dataclass
class View:
    """What the index holds about one CVE. Every field is read, never guessed."""

    cve: str
    in_corpus: bool                # named by at least one corpus advisory
    in_kev: bool = False
    kev_added: str = ""            # when CISA added it; "" when not recorded
    ransomware: bool = False       # CISA's flag, which records "known", not "no"
    epss: float | None = None      # None when the loaded feed has no score
    lev: dict | None = None        # the cached lev_estimate row, or None
    history_loaded: bool = False   # splits "no history" from "never scored"
    advisories: list = field(default_factory=list)   # (advisory_id, released)
    products: int = 0              # distinct vendor+name pairs, normalised
    vendors: list = field(default_factory=list)      # capped, alphabetical
    remediation: dict = field(default_factory=dict)  # category -> advisories
    cvss: float | None = None      # the worst score any corpus advisory gives
    vector: dict | None = None     # remote/unauthenticated/wormable, or None


def lookup(connection, cve_id):
    """The View for one CVE, or None when the whole index has never met it."""
    cve = re.sub(r"\s+", "", cve_id or "").upper()
    if not cve:
        return None
    # Newest advisory first: mid-incident the current one is the one wanted.
    # Undated releases sort last rather than masquerading as the newest.
    advisories = [(row[0], row[1] or "") for row in connection.execute(
        "SELECT DISTINCT f.advisory_id, a.released FROM affected f"
        " LEFT JOIN advisory a ON a.id = f.advisory_id WHERE f.cve = ?"
        " ORDER BY (a.released IS NULL OR a.released = ''),"
        " a.released DESC, f.advisory_id", (cve,))]
    signal = connection.execute(
        "SELECT epss, in_kev, ransomware, kev_added FROM exploitation"
        " WHERE cve = ?", (cve,)).fetchone()
    if not advisories and signal is None:
        return None

    view = View(cve=cve, in_corpus=bool(advisories), advisories=advisories,
                history_loaded=index.has_epss_history(connection))
    if signal is not None:
        view.epss = signal["epss"]
        view.in_kev = bool(signal["in_kev"])
        view.ransomware = bool(signal["ransomware"])
        view.kev_added = signal["kev_added"] or ""
    # Gated on the history flag: store_lev only ever runs after a history
    # load, and an index built before the LEV tables existed -- opened
    # read-only, as doctor and the overview do -- has no table to query.
    if view.history_loaded and (cached := index.lev_estimates(connection, [cve])):
        view.lev = cached[0]
    if advisories:
        _corpus_spread(connection, cve, view)
    return view


def _corpus_spread(connection, cve, view):
    """The product spread and remediation mix behind the advisory list."""
    joined = ("FROM affected f JOIN product p ON p.advisory_id = f.advisory_id"
              " AND p.product_id = f.product_id WHERE f.cve = ?")
    # Counted on normalised keys, so two spellings of one vendor+name pair
    # ("Mitsubishi Electric" / "... Corporation") do not inflate the spread.
    view.products = connection.execute(
        "SELECT COUNT(*) FROM (SELECT DISTINCT p.vendor_key, p.name_key "
        + joined + ")", (cve,)).fetchone()[0]
    # One spelling per normalised vendor: MIN is arbitrary but stable, and a
    # nameless vendor is a gap in the data rather than a name to list.
    names = sorted(row[0] for row in connection.execute(
        "SELECT MIN(p.vendor) " + joined + " GROUP BY p.vendor_key", (cve,))
        if row[0])
    if len(names) > MAX_VENDORS:
        names = names[:MAX_VENDORS] + [f"and {len(names) - MAX_VENDORS} more"]
    view.vendors = names

    counted = {}
    for category, advisories in connection.execute(
            "SELECT COALESCE(NULLIF(remediation, ''), 'unknown'),"
            " COUNT(DISTINCT advisory_id) FROM affected"
            " WHERE cve = ? GROUP BY 1", (cve,)):
        key = category or "unknown"       # a NULL column reads as unstated
        counted[key] = counted.get(key, 0) + advisories
    view.remediation = {c: counted.pop(c) for c in CATEGORIES if c in counted}
    view.remediation.update(sorted(counted.items()))   # hand-built extras

    scored = connection.execute(
        "SELECT DISTINCT cvss, vector, advisory_id FROM affected"
        " WHERE cve = ? AND cvss IS NOT NULL", (cve,)).fetchall()
    if not scored:
        return
    view.cvss = max(row["cvss"] for row in scored)
    # The reading must describe a vector behind the printed number, never a
    # lower-scored row's; among ties, the first parseable in a fixed order.
    ties = sorted((row for row in scored if row["cvss"] == view.cvss),
                  key=lambda row: (row["vector"] is None, row["vector"] or "",
                                   row["advisory_id"]))
    for row in ties:
        if parsed := cvss.parse(row["vector"]):
            view.vector = {"remote": parsed.remote,
                           "unauthenticated": parsed.unauthenticated,
                           "hands_off": parsed.hands_off,
                           "wormable": parsed.wormable}
            return
    # Vectors were recorded but none parsed: absence of a reading, and the
    # report must not blame the advisory for this tool's parser.
    view.vector = {"unreadable": True}


def format_report(view):
    """The printed answer: exploitation first, the corpus spread, the scope."""
    lines = [f"CVE LOOKUP   {view.cve}", "", "EXPLOITATION"]
    lines += _kev_rows(view)
    if view.epss is not None:
        lines += _row("EPSS", f"{view.epss:.3f} -- the chance of exploitation"
                      " in the next 30 days (FIRST)")
    elif view.in_corpus:
        lines += _row("EPSS", "absent -- no score in the loaded feed, which"
                      " is not a zero")
    else:
        # The loader keeps EPSS rows only for corpus CVEs, so for anything
        # else absence here says nothing about FIRST's feed.
        lines += _row("EPSS", "not kept here -- this index only retains EPSS"
                      " scores for CVEs its OT corpus names; FIRST may well"
                      " score it")
    lines += _lev_rows(view)
    lines += ["", "IN THIS CORPUS"]
    lines += _corpus_rows(view)
    lines += ["", _wrap(
        "Scope: these figures describe CISA's OT advisory corpus as indexed"
        " here, not the world. A product this corpus never covered is absent"
        " from every count above.")]
    return "\n".join(lines)


def _kev_rows(view):
    """KEV membership, worded so absence never reads as an all-clear."""
    if not view.in_kev:
        return _row("CISA KEV", "not listed -- no observed exploitation"
                    " reported to CISA, which is not evidence none happened")
    added = (f"listed, added {view.kev_added}" if view.kev_added
             else "listed (date added not recorded)")
    rows = _row("CISA KEV", added + " -- observed exploitation, not a"
                " prediction of it")
    rows += _row("ransomware", "known use in ransomware campaigns"
                 if view.ransomware else
                 "use in ransomware campaigns unknown to CISA -- unknown,"
                 " not ruled out")
    return rows


def _lev_rows(view):
    """The cached estimate framed as lev.py frames it, or an honest absence."""
    if view.lev is not None:
        return _row("LEV", f"{view.lev['lev']:.3f} across"
                    f" {view.lev['observations']} observation(s),"
                    f" {view.lev['first_seen']} to {view.lev['last_seen']}."
                    " A lower bound from a model, so it never overrides KEV:"
                    " a high value is a prompt to go and look, never a"
                    " finding that it was exploited.")
    if not view.history_loaded:
        return _row("LEV", "not estimated -- no EPSS history loaded, so LEV"
                    " cannot be estimated. `retrust lev --update` fetches it.")
    if not view.in_corpus:
        return _row("LEV", "not estimated here -- LEV is cached only for the"
                    " CVEs this OT corpus names")
    return _row("LEV", "not estimated -- no snapshot loaded here scores it:"
                " either EPSS has never scored this CVE, or it was published"
                " since the last snapshot. `retrust lev --update` refreshes"
                " the history.")


def _corpus_rows(view):
    """The spread, or the honest sentence that there is none to draw."""
    if not view.in_corpus:
        said = ("In CISA's KEV catalogue, but no OT product in this corpus"
                " carries it." if view.in_kev else
                "An exploitation signal names this CVE, but no OT product in"
                " this corpus carries it.")
        return textwrap.wrap(
            said + " That scopes the answer rather than shrinking the flaw:"
            " IT software, and products CISA never wrote about, sit outside"
            " this index.", 78, initial_indent="  ", subsequent_indent="  ")
    lines = _row("advisories", str(len(view.advisories)))
    for advisory_id, released in view.advisories[:MAX_ADVISORIES]:
        shown = (advisory_id if len(advisory_id) <= 45
                 else advisory_id[:42] + "...")
        lines.append(f"{'':16}{shown:<18} {released or 'undated'}")
    if len(view.advisories) > MAX_ADVISORIES:
        lines.append(f"{'':16}and {len(view.advisories) - MAX_ADVISORIES} more")
    lines += _row("products", f"{view.products} distinct vendor+name pair(s)")
    lines += _row("vendors", ", ".join(view.vendors) or "none named")
    mix = ", ".join(f"{category} in {count}"
                    for category, count in view.remediation.items())
    lines += _row("remediation", f"{mix} (advisories per category)")
    if view.cvss is None:
        lines += _row("worst CVSS", "none recorded -- no finding carries a"
                      " score, which is a gap, not a low score")
    else:
        lines += _row("worst CVSS", f"{view.cvss:.1f}")
        lines += _row("vector reads", _plain(view.vector))
    return lines


def _plain(reading):
    """The worst score's vector in words a buyer can act on."""
    if reading is None:
        return ("no vector recorded behind the worst score, so how the flaw"
                " is reached cannot be read here")
    if reading.get("unreadable"):
        return ("a vector is recorded but could not be read here, so how the"
                " flaw is reached cannot be said")
    text = ("reachable over the network" if reading["remote"]
            else "not network-reachable per its vector")
    text += (", no credentials needed" if reading["unauthenticated"]
             else ", credentials required")
    if reading["wormable"]:
        # v2 never asked about user interaction, and "nobody's help needed"
        # must not be claimed where the question was never posed.
        text += (", nobody's help needed -- the combination that spreads on"
                 " its own" if reading.get("hands_off")
                 else ", and its generation of CVSS never asked whether a"
                 " user must help")
    return text


def _row(label, text):
    """One labelled line, continuations hanging under the value column."""
    return textwrap.wrap(text, 78, initial_indent=f"  {label:<14}",
                         subsequent_indent=" " * 16)


def _wrap(text):
    return "\n".join(textwrap.wrap(text, 78))
