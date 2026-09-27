"""Search the corpus, and say what it does hold when a lookup fails.

Until this existed the only way in was to know a product's exact name: scoring
either resolved what you typed or said NOT ASSESSED. Searching vendors, product
names and order numbers turns that dead end into a shortlist.

Four tests are tried in order, strongest first: normalised exact match, prefix,
every word of the query present, then only some of them. Each hit reports the
test that found it, as match.py reports its method.
"""

import difflib
import re
from dataclasses import dataclass

from .index import normalize_name, normalize_order_number, normalize_vendor

METHODS = {1: "exact", 2: "prefix", 3: "tokens", 4: "substring"}

# Below this difflib ratio the nearest vendor stops being a near miss and
# becomes a different company: "Seimens" scores 0.86 against Siemens, while
# "Rockwel Automaton" scores 0.71 against ezautomation. Saying nothing at all
# is more use to a buyer than offering that.
SIMILAR_CUTOFF = 0.75


@dataclass
class Hit:
    """One thing found in the corpus, and the test that found it."""

    method: str
    vendor: str = ""
    name: str = ""                   # product name; empty on a vendor hit
    order_numbers: tuple = ()
    advisories: int = 0
    products: int = 0                # product entries; vendor hits only
    similarity: float | None = None  # difflib ratio, set only on "similar"


def _cap(limit):
    """SQLite reads a negative LIMIT as no limit at all, and difflib rejects 0."""
    return max(int(limit), 0)


def _ladder(column, query, normalise, split=True):
    """The ranking test and the narrowing clause for one column, as SQL.

    Returns (None, None, None) when normalisation leaves nothing usable: "-" and
    "%" both normalise to "", and an empty key would turn every LIKE into "match
    everything", the trap match.py documents at its rung 2. Only alphanumerics
    survive normalisation, so no wildcard ever reaches a pattern.
    """
    key = normalise(query or "")
    if not key:
        return None, None, None
    # One-character words narrow nothing, the judgement match.py makes as well.
    words = re.split(r"[^A-Za-z0-9]+", query) if split else []
    tokens = [word for raw in words if len(word := normalise(raw)) > 1] or [key]
    rungs = [f"WHEN {column} = ? THEN 1", f"WHEN {column} LIKE ? THEN 2"]
    parameters = [key, key + "%"]
    if len(tokens) > 1:          # "every word appears" needs two words to mean it
        rungs.append("WHEN " + " AND ".join(f"{column} LIKE ?" for _ in tokens)
                     + " THEN 3")
        parameters += [f"%{token}%" for token in tokens]
    return ("CASE " + " ".join(rungs) + " ELSE 4 END",
            "(" + " OR ".join(f"{column} LIKE ?" for _ in tokens) + ")",
            parameters + [f"%{token}%" for token in tokens])


def _commonest(connection, table, group, value, keys):
    """The spelling most entries give, for each group about to be printed.

    MIN() would take the alphabetically first, labelling the key "rockwell" as
    "Rockwell" (5 of 1,011 entries) instead of "Rockwell Automation" (the other
    1,006). It misnames 21 vendor keys and 94 product names that way, and the
    printed string is what a buyer types back into `score`.

    Returns {group tuple: spelling}. Table and column names are this module's
    own literals, never a query.
    """
    keys = sorted(set(keys))
    if not keys:
        return {}
    columns = ", ".join(group)
    # Ascending, so the commonest spelling is written last and wins. A tie goes
    # to the alphabetically first, which keeps the label stable between runs.
    return {tuple(row)[:len(group)]: row[value] for row in connection.execute(
        f"SELECT {columns}, {value}, COUNT(*) entries FROM {table}"
        f" WHERE {group[-1]} IN ({','.join('?' * len(keys))}) AND {value} != ''"
        f" GROUP BY {columns}, {value} ORDER BY entries, {value} DESC", keys)}


def _labels(connection, rows):
    """The vendor and the product spellings to print, for rows grouped on both."""
    return (_commonest(connection, "product", ("vendor_key",), "vendor",
                       [row["vendor_key"] for row in rows]),
            _commonest(connection, "product", ("vendor_key", "name_key"), "name",
                       [row["name_key"] for row in rows]))


def vendors(connection, query, limit=20):
    """Vendors whose name matches, each with its weight in the corpus."""
    rank, narrow, parameters = _ladder("vendor_key", query, normalize_vendor)
    if not rank:
        return []
    rows = connection.execute(
        f"SELECT {rank} rung, vendor_key, COUNT(*) products,"
        " COUNT(DISTINCT advisory_id) advisories FROM product"
        f" WHERE {narrow} GROUP BY vendor_key"
        " ORDER BY rung, advisories DESC, products DESC LIMIT ?",
        parameters + [_cap(limit)]).fetchall()
    names = _commonest(connection, "product", ("vendor_key",), "vendor",
                       [row["vendor_key"] for row in rows])
    return [Hit(METHODS[row["rung"]], vendor=names.get((row["vendor_key"],), ""),
                products=row["products"], advisories=row["advisories"])
            for row in rows]


def products(connection, query, vendor=None, limit=20):
    """Products whose name matches, one row per distinct product.

    Many advisories name the same product, so entries are grouped by vendor and
    name, and the advisory count is how many of them named it.
    """
    rank, narrow, parameters = _ladder("name_key", query, normalize_name)
    if not rank:
        return []
    scope, scoped = "", []
    if vendor is not None:
        # "GmbH" is a stripped company suffix and normalises to nothing. Scoping
        # on that would return the entries carrying no vendor at all, and those
        # would read as an answer about the vendor that was asked for.
        if not (vendor_key := normalize_vendor(vendor)):
            return []
        scope, scoped = " AND vendor_key = ?", [vendor_key]
    rows = connection.execute(
        f"SELECT {rank} rung, vendor_key, name_key, MIN(name) name,"
        f" COUNT(DISTINCT advisory_id) advisories FROM product WHERE {narrow}{scope}"
        " GROUP BY vendor_key, name_key"
        " ORDER BY rung, advisories DESC, name LIMIT ?",
        parameters + scoped + [_cap(limit)]).fetchall()
    vendor_names, names = _labels(connection, rows)
    numbers = _numbers_for(connection, rows)
    return [Hit(METHODS[row["rung"]], advisories=row["advisories"],
                vendor=vendor_names.get((row["vendor_key"],), ""),
                name=names.get((row["vendor_key"], row["name_key"]), row["name"]),
                order_numbers=numbers.get((row["vendor_key"], row["name_key"]), ()))
            for row in rows]


def _numbers_for(connection, rows):
    """Order numbers for the shown products only, in one pass over the table.

    Nothing indexes order_number(product_rowid), so one query for the lot beats
    one per row (3 ms against 7 ms each). Grouping by number_key rather than
    spelling stops the six products printing one number two ways from reporting
    two; keying on vendor as well as name stops a name two vendors share from
    inheriting the other one's number.
    """
    groups = {(row["vendor_key"], row["name_key"]) for row in rows}
    if not groups:
        return {}
    names = sorted({name_key for _, name_key in groups})
    found = {}
    for row in connection.execute(
        "SELECT p.vendor_key, p.name_key, o.number_key FROM order_number o"
        " JOIN product p ON p.rowid_ = o.product_rowid"
        f" WHERE p.name_key IN ({','.join('?' * len(names))})", names):
        if (group := (row["vendor_key"], row["name_key"])) in groups:
            found.setdefault(group, set()).add(row["number_key"])
    spellings = _commonest(connection, "order_number", ("number_key",), "number",
                           [key for keys in found.values() for key in keys])
    return {group: tuple(spellings.get((key,), key) for key in sorted(keys))
            for group, keys in found.items()}


def order_numbers(connection, query, limit=20):
    """Which products an order number, or a fragment of one, belongs to.

    The whole query counts as one word: an order number has no others, so
    "every word appears" would only repeat the substring test. One number can
    belong to two vendors -- the reason match.py cross-checks the vendor at its
    order-number rung -- so every product carrying it is listed separately.
    """
    rank, narrow, parameters = _ladder(
        "o.number_key", query, normalize_order_number, split=False)
    if not rank:
        return []
    rows = connection.execute(
        f"SELECT {rank} rung, o.number_key, p.vendor_key, p.name_key, MIN(p.name) name,"
        " COUNT(DISTINCT p.advisory_id) advisories FROM order_number o"
        f" JOIN product p ON p.rowid_ = o.product_rowid WHERE {narrow}"
        " GROUP BY o.number_key, p.vendor_key, p.name_key"
        " ORDER BY rung, advisories DESC, o.number_key LIMIT ?",
        parameters + [_cap(limit)]).fetchall()
    vendor_names, names = _labels(connection, rows)
    spellings = _commonest(connection, "order_number", ("number_key",), "number",
                           [row["number_key"] for row in rows])
    return [Hit(METHODS[row["rung"]], advisories=row["advisories"],
                vendor=vendor_names.get((row["vendor_key"],), ""),
                name=names.get((row["vendor_key"], row["name_key"]), row["name"]),
                order_numbers=(spellings.get((row["number_key"],),
                                             row["number_key"]),))
            for row in rows]


def suggest(connection, vendor=None, product=None, limit=5):
    """The closest real things in the corpus, for a resolution that failed."""
    vendor_key = normalize_vendor(vendor or "")
    known = bool(vendor_key) and connection.execute(
        "SELECT 1 FROM product WHERE vendor_key = ? LIMIT 1",
        (vendor_key,)).fetchone() is not None
    found = {"vendor": vendor, "product": product, "vendor_known": known,
             "vendors": [], "products": []}
    # A vendor the corpus already knows is not what failed, so listing rival
    # manufacturers would answer a question nobody asked.
    if vendor and not known:
        found["vendors"] = (vendors(connection, vendor, limit=limit)
                            or _closest_vendors(connection, vendor_key, limit))
    if product:
        found["products"] = products(
            connection, product, vendor=vendor if known else None, limit=limit)
    return found


def _closest_vendors(connection, key, limit):
    """Edit distance over the vendor keys, for a vendor no LIKE test reached.

    Ratios round to a tenth before sorting, so corpus weight settles a near tie:
    "Seimens" puts Siemens (0.86, 1,041 advisories) above Simens (0.92, one).
    Six hundredths of a ratio is not evidence; an advisory count is. Product
    names are left to the word tests, which already recover a typo in any name
    of more than one word.
    """
    if not (wanted := _cap(limit)):
        return []
    rows = {row["vendor_key"]: row for row in connection.execute(
        "SELECT vendor_key, COUNT(*) products, COUNT(DISTINCT advisory_id) advisories"
        " FROM product WHERE vendor_key != '' GROUP BY vendor_key")}
    close = difflib.get_close_matches(key, list(rows), n=wanted, cutoff=SIMILAR_CUTOFF)
    names = _commonest(connection, "product", ("vendor_key",), "vendor", close)
    hits = [Hit("similar", vendor=names.get((near,), ""),
                products=rows[near]["products"], advisories=rows[near]["advisories"],
                similarity=round(difflib.SequenceMatcher(None, key, near).ratio(), 2))
            for near in close]
    hits.sort(key=lambda hit: (-round(hit.similarity, 1), -hit.advisories))
    return hits


def _clip(text, width):
    """Truncate visibly, so a shortened name cannot be read as the whole one."""
    text = text or ""
    return text if len(text) <= width else text[:width - 3] + "..."


def _vendor(hit):
    """Three products in the corpus name no vendor; a blank column reads as a bug."""
    return hit.vendor or "(no vendor named)"


def _method(hit):
    return f"similar {hit.similarity:.2f}" if hit.similarity is not None else hit.method


def _advisories(count):
    return f"{count:,} advisory" if count == 1 else f"{count:,} advisories"


def _shown(hit):
    """The first order number, plus how many more there are.

    Clipped to 18 so " +17" still fits the 22 the formatters pad to.
    """
    if not hit.order_numbers:
        return "--"
    extra = len(hit.order_numbers) - 1
    return _clip(hit.order_numbers[0], 18) + (f" +{extra}" if extra else "")


def _heading(kind, query, hits, lead):
    """A heading for the hits, or the plain sentence when there are none."""
    if not hits:
        return f"No {kind} in the corpus matches {query!r}."
    plural = "" if len(hits) == 1 else "s"
    return (lead or f"{len(hits)} {kind}{plural} matching {query!r}, "
            "strongest match first:") + "\n"


def format_vendors(hits, query, lead=None):
    """Aligned table of vendors. `lead` lets a caller give its own heading."""
    lines = [_heading("vendor", query, hits, lead)]
    if hits:
        lines.append(f"{'VENDOR':<38}  {'PRODUCTS':>8}  {'ADVISORIES':>10}  MATCHED BY")
    lines += [f"{_clip(_vendor(hit), 38):<38}  {hit.products:>8,}  "
              f"{hit.advisories:>10,}  {_method(hit)}" for hit in hits]
    return "\n".join(lines)


def format_products(hits, query, lead=None):
    """Two lines per product, because one row of five columns would need 105."""
    lines = [_heading("product", query, hits, lead)]
    for hit in hits:
        # The name gets whatever the vendor leaves, so a short vendor name is
        # not paid for by clipping a product name that would have fitted.
        label = _clip(_vendor(hit), 24)
        lines.append(f"  {label} / {_clip(hit.name, 69 - len(label))}")
        lines.append(f"    {_method(hit):<12}  {_shown(hit):<22}  "
                     f"{_advisories(hit.advisories)}")
    return "\n".join(lines)


def format_order_numbers(hits, query):
    """Two lines per order number: the number, then the product it names."""
    lines = [_heading("order number", query, hits, None)]
    for hit in hits:
        lines.append(f"  {_shown(hit):<22}  {_method(hit):<12}  "
                     f"{_clip(_vendor(hit), 22)}")
        lines.append(f"    {_clip(hit.name, 52):<52}  {_advisories(hit.advisories)}")
    return "\n".join(lines)


def format_suggestions(suggestions):
    """What scoring prints under NOT ASSESSED, from one suggest() call."""
    vendor, product = suggestions["vendor"], suggestions["product"]
    if not (asked := " / ".join(filter(None, [vendor, product]))):
        return "Nothing to suggest: no vendor or product was given."
    blocks = [f"Nothing in the corpus resolved {asked!r}."]
    if vendor and not suggestions["vendor_known"]:
        blocks.append(format_vendors(suggestions["vendors"], vendor,
                                     lead="Closest vendors in the corpus:"))
    if product:
        blocks.append(format_products(suggestions["products"], product,
                                      lead="Closest products in the corpus:"))
    return "\n\n".join(blocks)
