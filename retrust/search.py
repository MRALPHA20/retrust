"""Look through the corpus, and say what it does hold when a lookup fails.

The index names tens of thousands of product entries from hundreds of vendors,
but until now the only way in was to already know a product's exact name:
scoring either resolved what you typed or said NOT ASSESSED and left you to
guess which spelling it wanted. This module searches vendors, product names and
order numbers, and -- the part that earns its keep -- offers the closest things
that really are in the corpus when a resolution fails, so "no match" becomes a
shortlist rather than a dead end.

Four tests are tried in order, strongest first: a normalised exact match, a
prefix, every word of the query appearing in the name, and finally only some of
them. Each hit carries the test that found it, the way match.py names the method
it resolved by, because a result nobody can explain is worth little more than a
bare score. Nothing is invented to fill an empty answer.
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

    Ranking in SQL means only the rows actually shown are ever built in Python.
    Returns (None, None, None) when normalisation leaves nothing usable: "-" and
    "%" both normalise to "", and an empty key would turn every LIKE below into
    "match everything", the trap match.py documents at its rung 2. Nothing but
    alphanumerics survives normalisation, so no wildcard can reach a pattern and
    no ESCAPE clause is needed.
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

    MIN() takes the alphabetically first instead, which labels the vendor key
    "rockwell" as "Rockwell" -- the spelling 5 of its 1,011 entries carry, not
    the "Rockwell Automation" the other 1,006 give -- and names a product "MC
    Works 64" where 8 entries of 10 print "MC Works64". It misnames 21 of the
    corpus's 814 vendor keys and 94 product names that way. The printed string
    is the one a buyer types back into `score`, so every search labels through
    here and one thing prints one way throughout.

    `keys` are tuples over the `group` columns, whose last column narrows the
    query. Table and column names are this module's own literals, never a query.
    """
    values = sorted({key[-1] for key in keys})
    if not values:
        return {}
    columns = ", ".join(group)
    # Ascending, so the commonest spelling is written last and wins. A tie goes
    # to the alphabetically first, which keeps the label stable between runs.
    return {tuple(row)[:len(group)]: row[value] for row in connection.execute(
        f"SELECT {columns}, {value}, COUNT(*) entries FROM {table}"
        f" WHERE {group[-1]} IN ({','.join('?' * len(values))}) AND {value} != ''"
        f" GROUP BY {columns}, {value} ORDER BY entries, {value} DESC", values)}


def _labels(connection, rows):
    """The vendor and product spellings to print, for rows grouped on both."""
    return (_commonest(connection, "product", ("vendor_key",), "vendor",
                       {(row["vendor_key"],) for row in rows}),
            _commonest(connection, "product", ("vendor_key", "name_key"), "name",
                       {(row["vendor_key"], row["name_key"]) for row in rows}))


def vendors(connection, query, limit=20):
    """Vendors whose name matches, each with its weight in the corpus."""
    rank, narrow, parameters = _ladder("vendor_key", query, normalize_vendor)
    if not rank:
        return []
    rows = connection.execute(
        f"SELECT {rank} rung, vendor_key, COUNT(*) products,"
        "        COUNT(DISTINCT advisory_id) advisories"
        f"  FROM product WHERE {narrow}"
        "  GROUP BY vendor_key"
        "  ORDER BY rung, advisories DESC, products DESC LIMIT ?",
        parameters + [_cap(limit)]).fetchall()
    names = _commonest(connection, "product", ("vendor_key",), "vendor",
                       {(row["vendor_key"],) for row in rows})
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
        f"SELECT {rank} rung, vendor_key, name_key,"
        "        MIN(name) name, COUNT(DISTINCT advisory_id) advisories"
        f"  FROM product WHERE {narrow}{scope}"
        "  GROUP BY vendor_key, name_key"
        "  ORDER BY rung, advisories DESC, name LIMIT ?",
        parameters + scoped + [_cap(limit)]).fetchall()
    vendor_names, names = _labels(connection, rows)
    numbers = _numbers_for(connection, {(row["vendor_key"], row["name_key"])
                                        for row in rows})
    hits = []
    for row in rows:
        group = (row["vendor_key"], row["name_key"])
        hits.append(Hit(METHODS[row["rung"]], advisories=row["advisories"],
                        vendor=vendor_names.get((row["vendor_key"],), ""),
                        name=names.get(group, row["name"]),
                        order_numbers=numbers.get(group, ())))
    return hits


def _numbers_for(connection, groups):
    """Order numbers for the shown products only, in one pass over the table.

    Nothing indexes order_number(product_rowid), so one query for the lot beats
    one per shown row (3 ms against 7 ms each) and beats fetching them inside
    the grouped query (148 ms). Counting by number_key rather than by spelling
    keeps the six products that print one number two ways ("6ES7 288-1CR40-0AA0"
    against "6ES7288-1CR40-0AA0") from reporting two order numbers when they
    have one, and keying on vendor as well as name stops a name two vendors
    share from inheriting the other one's number.
    """
    names = sorted({name_key for _, name_key in groups})
    if not names:
        return {}
    found = {}
    for row in connection.execute(
        "SELECT p.vendor_key, p.name_key, o.number_key FROM order_number o"
        " JOIN product p ON p.rowid_ = o.product_rowid"
        f" WHERE p.name_key IN ({','.join('?' * len(names))})", names):
        if (group := (row["vendor_key"], row["name_key"])) in groups:
            found.setdefault(group, set()).add(row["number_key"])
    spellings = _commonest(connection, "order_number", ("number_key",), "number",
                           {(key,) for keys in found.values() for key in keys})
    return {group: tuple(spellings.get((key,), key) for key in sorted(keys))
            for group, keys in found.items()}


def order_numbers(connection, query, limit=20):
    """Which products an order number, or a fragment of one, belongs to.

    The whole query counts as one word: an order number has no others, so
    "every word appears" would only repeat the substring test. One number can
    belong to two vendors -- the reason match.py cross-checks the vendor at its
    order-number rung -- so every product carrying it is listed separately
    rather than collapsed into a single row.
    """
    rank, narrow, parameters = _ladder(
        "o.number_key", query, normalize_order_number, split=False)
    if not rank:
        return []
    rows = connection.execute(
        f"SELECT {rank} rung, o.number_key, p.vendor_key, p.name_key,"
        "        MIN(p.name) name, COUNT(DISTINCT p.advisory_id) advisories"
        "   FROM order_number o JOIN product p ON p.rowid_ = o.product_rowid"
        f"  WHERE {narrow}"
        "  GROUP BY o.number_key, p.vendor_key, p.name_key"
        "  ORDER BY rung, advisories DESC, o.number_key LIMIT ?",
        parameters + [_cap(limit)]).fetchall()
    vendor_names, names = _labels(connection, rows)
    spellings = _commonest(connection, "order_number", ("number_key",), "number",
                           {(row["number_key"],) for row in rows})
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

    Ratios are rounded to a tenth before sorting, so corpus weight settles a
    near tie: "Seimens" puts Siemens (0.86, 1,041 advisories) above Simens
    (0.92, 1 advisory). Six hundredths of a ratio is not evidence; an advisory
    count is. This is the one place edit distance earns its keep -- product
    names are left to the word tests, which already recover a typo in any name
    of more than one word.
    """
    if not (wanted := _cap(limit)):
        return []
    rows = {row["vendor_key"]: row for row in connection.execute(
        "SELECT vendor_key, COUNT(*) products, COUNT(DISTINCT advisory_id) advisories"
        "  FROM product WHERE vendor_key != '' GROUP BY vendor_key")}
    close = difflib.get_close_matches(key, list(rows), n=wanted, cutoff=SIMILAR_CUTOFF)
    names = _commonest(connection, "product", ("vendor_key",), "vendor",
                       {(near,) for near in close})
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
    """The order-number column: the first one, plus how many more there are.

    A product can carry a dozen; listing them all would push the line past the
    width, and dropping the count silently would hide that there are more. The
    18 leaves room for " +17" inside the 22 columns the formatters pad to.
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
    """Two lines per product, because names run past fifty characters.

    One row of five columns would need about 105; two lines keep every line
    inside the 74 the rest of the command line already uses.
    """
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
