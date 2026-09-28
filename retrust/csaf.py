"""Read CSAF 2.0 advisories into flat records.

CSAF is the format CISA and the major OT vendors publish advisories in. Two
parts matter to us:

    product_tree     a nested tree of vendor -> product -> version branches,
                     whose leaves carry a product_id
    vulnerabilities  per CVE, which product_ids are affected

Together they give an authoritative "this CVE affects exactly these product
versions" mapping, which is far more reliable than guessing from CPE strings.
Across CISA's OT corpus only 0.1% of product entries carry a CPE at all, while
30% carry the manufacturer's order number and ~50% have one recoverable from
the product name -- so order numbers are what we key on.
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

# Manufacturer order numbers, e.g. Siemens MLFB "6ES7518-4AX00-1AB0" or
# Rockwell "1756-L71". Order numbers always contain a digit, which is what
# separates them from words in the product name.
ORDER_NUMBER_PATTERNS = [
    re.compile(r"\b6[A-Z]{2}\d{4}-\d[A-Z]{2}\d{2}-\d[A-Z]{3}\b"),   # Siemens MLFB
    re.compile(r"\b\d{4}-[A-Z]{1,3}\d{1,3}[A-Z]{0,3}\b"),            # Rockwell
    re.compile(r"\(([0-9A-Z][0-9A-Z\-./ ]{4,})\)"),                  # in parentheses
]


# Parenthetical text often holds a rating or a version rather than an order
# number ("(54VDC)", "(V2.1)", "(2 GB)"). Matching one of those to a product
# would be worse than not matching at all, so we drop them.
_NOT_AN_ORDER_NUMBER = re.compile(
    r"^(?:V|FW|SW|REV)?[\d.]+$"                              # a bare version
    r"|\d\s*(?:V(?:AC|DC)?|A|W|Hz|[KMG]Hz|[KMG]B|mm|cm|kg|bit|port|ch)\b"  # a rating
    r"|^(?:AND|THE|FOR|WITH|ALL|SEE|NOTE)\b",
    re.I,
)


def find_order_numbers(text):
    """Pull manufacturer order numbers out of a product name.

    Biased towards precision: an order-number match is the strongest signal the
    matcher has, so a wrong one is more costly than a missing one.
    """
    found = set()
    for pattern in ORDER_NUMBER_PATTERNS:
        for match in pattern.finditer(text or ""):
            value = (match.group(1) if pattern.groups else match.group(0)).strip()
            if len(value) < 5 or not any(c.isdigit() for c in value):
                continue
            if not any(c.isalpha() for c in value):   # digits only is a version
                continue
            if _NOT_AN_ORDER_NUMBER.search(value):
                continue
            found.add(value)
    return found


@dataclass
class Product:
    """One leaf of a product tree: a specific product at a version range."""

    product_id: str
    vendor: str
    name: str
    version_range: str
    order_numbers: set = field(default_factory=set)
    # What identifiers the advisory itself declared, as opposed to what we
    # recovered from the product name. Recorded so `retrust eval` can reproduce
    # the coverage table that justifies keying on order numbers at all.
    has_cpe: bool = False
    helper_order_number: bool = False


@dataclass
class Advisory:
    """One advisory, with its products and its CVE-to-product mapping."""

    advisory_id: str
    title: str
    released: str
    source: str
    products: list = field(default_factory=list)
    # cve -> {"product_ids": [...], "cvss": float|None, "cwe": str|None}
    vulnerabilities: dict = field(default_factory=dict)


def _walk(branches, inherited=None):
    """Yield (attributes, product) for every leaf of a product tree."""
    inherited = inherited or {}
    for branch in branches or []:
        attributes = dict(inherited)
        attributes.setdefault(branch.get("category"), branch.get("name"))
        if "product" in branch:
            yield attributes, branch["product"]
        yield from _walk(branch.get("branches"), attributes)


def parse(path):
    """Read one CSAF file. Returns an Advisory, or None if it is not usable.

    Deliberately total: any unreadable or structurally odd file yields None
    rather than an exception. The corpus is ~4,000 files from hundreds of
    vendors, and one of them having `"document": null` must not abort an ingest
    of all the rest.
    """
    try:
        return _parse(path)
    except Exception:           # malformed structure, wrong types, bad encoding
        return None


def _parse(path):
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        return None

    meta = document.get("document") or {}
    tracking = meta.get("tracking") or {}
    advisory = Advisory(
        advisory_id=tracking.get("id") or Path(path).stem,
        title=meta.get("title", ""),
        # .get(key, "") returns None when the key is present and JSON-null, and
        # None[:10] raises -- which parse()'s catch-all swallowed, silently
        # dropping the whole advisory and every CVE in it.
        released=(tracking.get("initial_release_date") or "")[:10],
        source=str(path),
    )

    tree = document.get("product_tree") or {}
    leaves = list(_walk(tree.get("branches")))
    leaves += [({}, p) for p in (tree.get("full_product_names") or [])]

    for attributes, entry in leaves:
        if not isinstance(entry, dict):
            continue
        product_id = entry.get("product_id")
        if not product_id:
            continue
        name = entry.get("name", "")
        helper = entry.get("product_identification_helper") or {}
        declared = set(helper.get("model_numbers") or []) | set(helper.get("skus") or [])
        order_numbers = set(declared)
        order_numbers |= find_order_numbers(name)
        order_numbers |= find_order_numbers(attributes.get("product_name", ""))

        advisory.products.append(
            Product(
                product_id=product_id,
                vendor=(attributes.get("vendor") or "").strip(),
                name=(attributes.get("product_name") or name).strip(),
                version_range=(
                    attributes.get("product_version_range")
                    or attributes.get("product_version")
                    or ""
                ).strip(),
                order_numbers={o.strip() for o in order_numbers if o and o.strip()},
                has_cpe=bool(helper.get("cpe")),
                helper_order_number=bool(declared),
            )
        )

    for vulnerability in document.get("vulnerabilities") or []:
        if not isinstance(vulnerability, dict):
            continue
        cve = vulnerability.get("cve")
        if not cve:
            continue
        status = vulnerability.get("product_status") or {}
        affected = list(status.get("known_affected") or [])

        # The vendor's highest score, preferring the newest CVSS version it
        # gives, and the vector that produced that same score. Taking the
        # vector from a different entry would describe a different flaw.
        scores = vulnerability.get("scores") or []
        rated = [[(float(b), (s.get(k) or {}).get("vectorString"))
                  for s in scores
                  if (b := (s.get(k) or {}).get("baseScore")) is not None]
                 for k in ("cvss_v4", "cvss_v3", "cvss_v2")]
        # Keyed on the score alone: max() over bare tuples would fall through to
        # comparing the vectors when two entries tie, and a None vector beside a
        # string one raises rather than picking either.
        best = next((max(v, key=lambda rating: rating[0]) for v in rated if v),
                    (None, None))
        cvss, vector = best

        # CSAF remediation categories, best first. "vendor_fix" means a patch
        # exists; "mitigation"/"workaround" mean you must live with it; and
        # "none_available" means neither.
        categories = {(r.get("category") or "") for r in
                      (vulnerability.get("remediations") or [])}
        for best in ("vendor_fix", "mitigation", "workaround", "none_available"):
            if best in categories:
                remediation = best
                break
        else:
            remediation = "unknown"

        advisory.vulnerabilities[cve] = {
            "product_ids": affected,
            "cvss": cvss,
            "cwe": (vulnerability.get("cwe") or {}).get("id"),
            "vector": vector,
            "remediation": remediation,
        }

    return advisory if advisory.products else None


def parse_directory(root):
    """Read every CSAF file under `root`, skipping ROLIE feed indexes."""
    for path in sorted(Path(root).rglob("*.json")):
        if "feed" in path.name:
            continue
        if advisory := parse(path):
            yield advisory
