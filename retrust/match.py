"""Resolve a procurement request to the products advisories actually name.

A buyer asks about "Siemens SIMATIC S7-1500 1518-4, firmware 3.1.6". We have to
decide which advisory products that refers to. Four strategies are tried in
order, strongest first:

    1. order number   "6ES7518-4AX00-1AB0" -> exact, unambiguous
    2. vendor+name    normalised exact match on both
    3. vendor+token   all words of the query appear in the product name
    4. abstain        say so, with a reason

Confidence falls with each rung. Below ``MIN_CONFIDENCE`` we return no match
rather than a weak guess: a wrong answer about whether a PLC is vulnerable is
far more costly than "needs review".
"""

import re
from dataclasses import dataclass, field

from .index import normalize_name, normalize_order_number, normalize_vendor
from .version import affects

MIN_CONFIDENCE = 0.55

CONFIDENCE = {
    "order_number": 0.98,
    "exact_name": 0.90,
    "token_subset": 0.70,
}


@dataclass
class Match:
    """One advisory product the request resolved to."""

    product_rowid: int
    advisory_id: str
    product_id: str
    vendor: str
    name: str
    version_range: str
    method: str
    confidence: float


@dataclass
class Resolution:
    """The outcome of resolving one request."""

    query: str
    matches: list = field(default_factory=list)
    method: str = "none"
    confidence: float = 0.0
    abstained: bool = False
    reason: str = ""

    @property
    def resolved(self):
        return bool(self.matches) and not self.abstained


def _rows_to_matches(rows, method):
    confidence = CONFIDENCE[method]
    return [
        Match(r["rowid_"], r["advisory_id"], r["product_id"], r["vendor"],
              r["name"], r["version_range"], method, confidence)
        for r in rows
    ]


def resolve(connection, vendor=None, product=None, order_number=None):
    """Find the advisory products matching this request."""
    query = " ".join(filter(None, [vendor, product, order_number]))
    result = Resolution(query=query)

    # Rung 1 - order number. Unambiguous, so we stop here when it hits.
    if order_number:
        key = normalize_order_number(order_number)
        rows = connection.execute(
            "SELECT p.* FROM product p JOIN order_number o ON o.product_rowid = p.rowid_"
            " WHERE o.number_key = ?", (key,)).fetchall()
        if rows:
            result.matches = _rows_to_matches(rows, "order_number")
            result.method, result.confidence = "order_number", CONFIDENCE["order_number"]
            return result

    if not (vendor and product):
        result.abstained = True
        result.reason = (
            "no order number matched and no vendor+product given"
            if order_number else "need either an order number or vendor and product"
        )
        return result

    vendor_key = normalize_vendor(vendor)
    if not connection.execute(
        "SELECT 1 FROM product WHERE vendor_key = ? LIMIT 1", (vendor_key,)).fetchone():
        result.abstained = True
        result.reason = f"vendor {vendor!r} does not appear in the advisory corpus"
        return result

    # Rung 2 - exact normalised product name, plus the longer variants that
    # start with it. A buyer writing "SIMATIC S7-1500" means the family, so the
    # CPU 1518-4 variants belong in the answer too; returning only the literal
    # match would silently drop most of the affected models.
    name_key = normalize_name(product)
    rows = connection.execute(
        "SELECT * FROM product WHERE vendor_key = ? AND (name_key = ? OR name_key LIKE ?)",
        (vendor_key, name_key, name_key + "%")).fetchall()
    if rows:
        result.matches = _rows_to_matches(rows, "exact_name")
        result.method, result.confidence = "exact_name", CONFIDENCE["exact_name"]
        return result

    # Rung 3 - every word of the query appears in the product name. Requires at
    # least two words, because one short word matches far too much.
    words = [w for w in re.split(r"[^a-z0-9]+", product.lower()) if len(w) > 1]
    if len(words) >= 2:
        candidates = connection.execute(
            "SELECT * FROM product WHERE vendor_key = ?", (vendor_key,)).fetchall()
        rows = [r for r in candidates
                if all(w in (r["name"] or "").lower() for w in words)]
        if rows:
            result.matches = _rows_to_matches(rows, "token_subset")
            result.method, result.confidence = "token_subset", CONFIDENCE["token_subset"]
            return result

    result.abstained = True
    result.reason = f"no product of {vendor!r} matched {product!r}"
    return result


@dataclass
class Finding:
    """One CVE that affects the resolved product at the given version."""

    cve: str
    advisory_id: str
    cvss: float | None
    cwe: str | None
    epss: float | None
    in_kev: bool
    ransomware: bool
    version_range: str
    # True when this finding's version range was actually evaluated against a
    # supplied version. With no --version nothing was checked, so this is False
    # and the evidence line says "not checked" rather than "parsed cleanly".
    decided: bool
    remediation: str = "unknown"   # vendor_fix / mitigation / workaround / none_available


def findings(connection, resolution, version=None):
    """Collect the CVEs affecting a resolution, filtered by version when given.

    A CVE whose version range cannot be parsed is still returned, flagged
    ``decided=False``, so the report can show it as needing review. Dropping it
    silently would understate risk.
    """
    if not resolution.resolved:
        return []

    out, seen = [], set()
    for match in resolution.matches:
        # Skip products whose range we can read and that clearly exclude this
        # version. When the range is unparseable we keep the CVE and flag it.
        decided = False
        if version and match.version_range:
            verdict = affects(match.version_range, version)
            if verdict is False:
                continue
            decided = verdict is not None
        elif not version:
            decided = False            # no version given: nothing was decided

        rows = connection.execute(
            "SELECT a.cve, a.cvss, a.cwe, a.remediation, e.epss, e.in_kev, e.ransomware"
            " FROM affected a LEFT JOIN exploitation e ON e.cve = a.cve"
            " WHERE a.advisory_id = ? AND a.product_id = ?",
            (match.advisory_id, match.product_id)).fetchall()

        for row in rows:
            key = (row["cve"], match.advisory_id)
            if key in seen:
                continue
            seen.add(key)
            out.append(Finding(
                cve=row["cve"], advisory_id=match.advisory_id,
                cvss=row["cvss"], cwe=row["cwe"], epss=row["epss"],
                in_kev=bool(row["in_kev"]), ransomware=bool(row["ransomware"]),
                version_range=match.version_range, decided=decided,
                remediation=row["remediation"] or "unknown",
            ))
    return out
