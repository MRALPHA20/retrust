"""Certification evidence: IEC 62443 (ISASecure) and Common Criteria.

Certification is weak positive evidence. A certified component has been tested
against a published standard, which is worth something. But the absence of a
certificate means almost nothing -- most OT products are never submitted -- so
this module never penalises a product for being uncertified. It can only add
confidence, never subtract it.

Two schemes, with very different usefulness here:

  ISASecure (IEC 62443-4-2 components, 4-1 development processes) is the OT
  scheme. Small, hand-checkable lists, real OT vendors.

  Common Criteria is far larger but almost entirely IT. Of nine major OT
  vendors checked against its 2,122 certified products, only two appear at all,
  and the list is dominated by smart cards. It is loaded for completeness and
  because it covers the IT equipment that sits alongside OT, not because it will
  often hit.

Both lists are small and change slowly, so a snapshot is cached in data/ and
refreshed on demand rather than fetched on every run.
"""

import csv
import html
import json
import re
import urllib.parse
import urllib.request
from pathlib import Path

from .index import normalize_vendor

ISASECURE_PAGES = {
    "IEC 62443-4-2": "https://isasecure.org/end-users/iec-62443-4-2-certified-components",
    "IEC 62443-4-1": "https://isasecure.org/end-users/"
                     "iec-62443-4-1-certified-development-organizations",
    "IEC 62443-3-3": "https://isasecure.org/end-users/iec-62443-3-3-certified-systems",
}
COMMON_CRITERIA_CSV = "https://www.commoncriteriaportal.org/products/certified_products.csv"

_USER_AGENT = "Mozilla/5.0 (compatible; ReTrust/0.1; +certification refresh)"


# Certificate listings are small; anything larger is not what we asked for.
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024


def _fetch(url, timeout=60):
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        # These hosts are fixed and trusted, but a redirect could still move the
        # fetch onto plain http; a certificate listing read over a rewritable
        # channel is not evidence, so refuse it.
        landed = getattr(response, "url", url)
        if urllib.parse.urlsplit(landed).scheme != "https":
            raise ValueError(f"{url} redirected to {landed}; refusing to fetch "
                             "certification data over anything but https")
        raw = response.read(MAX_DOWNLOAD_BYTES + 1)
    if len(raw) > MAX_DOWNLOAD_BYTES:
        raise ValueError(f"{url} returned more than "
                         f"{MAX_DOWNLOAD_BYTES // 1_000_000} MB; refusing it")
    return raw.decode("utf-8", errors="replace")


def _strip_tags(fragment):
    return html.unescape(re.sub(r"<[^>]+>", " ", fragment)).strip()


# Column labels these tables use. A row whose cells are mostly these is the
# header, which appears in a <td> rather than a <th> on some of the pages.
_HEADER_WORDS = {
    "picture", "supplier", "vendor", "company", "type", "model", "version",
    "certificate", "certification date", "product", "device type", "system",
    "organization", "organisation", "scheme", "level", "date", "name",
}


def _scrape_isasecure(page_html, scheme):
    """Pull certificate rows out of one ISASecure listing page."""
    out = []
    for row in re.findall(r"<tr[^>]*>(.*?)</tr>", page_html, re.S | re.I):
        cells = [_strip_tags(c) for c in
                 re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", row, re.S | re.I)]
        cells = [re.sub(r"\s+", " ", c) for c in cells if c.strip()]
        if len(cells) < 3:
            continue
        # Skip the header wherever it is markup-wise: judge it by content.
        if sum(c.lower() in _HEADER_WORDS for c in cells) >= max(2, len(cells) // 2):
            continue
        out.append({
            "scheme": scheme,
            "vendor": cells[0],
            "product": cells[2] if len(cells) > 2 else cells[1],
            "detail": " | ".join(cells[3:]),
            "source": ISASECURE_PAGES[scheme],
        })
    return out


def refresh(data_dir="data", include_common_criteria=True):
    """Fetch both certification sources and cache them. Returns per-source counts."""
    directory = Path(data_dir)
    directory.mkdir(parents=True, exist_ok=True)
    records, counts = [], {}

    for scheme, url in ISASECURE_PAGES.items():
        try:
            rows = _scrape_isasecure(_fetch(url), scheme)
        except Exception as error:                       # network or layout change
            counts[scheme] = f"failed: {error}"
            continue
        records.extend(rows)
        counts[scheme] = len(rows)

    if include_common_criteria:
        try:
            text = _fetch(COMMON_CRITERIA_CSV)
            rows = list(csv.DictReader(text.lstrip("﻿").splitlines()))
            for row in rows:
                vendor = (row.get("Manufacturer") or "").strip()
                if not vendor:
                    continue
                records.append({
                    "scheme": "Common Criteria",
                    "vendor": vendor,
                    "product": (row.get("Name") or "").strip(),
                    "detail": " | ".join(filter(None, [
                        row.get("Assurance Level") or "",
                        row.get("Certification Date") or "",
                    ])),
                    "source": COMMON_CRITERIA_CSV,
                })
            counts["Common Criteria"] = len(rows)
        except Exception as error:
            counts["Common Criteria"] = f"failed: {error}"

    # Never replace a good cache with nothing. If every source failed, the
    # network is down, not the certificates -- and an empty cache would quietly
    # rescore every certified vendor as uncertified.
    path = directory / "certifications.json"
    if not records:
        counts["cached_to"] = (f"unchanged: every source failed, keeping {path}"
                               if path.exists() else "nothing fetched, nothing written")
        return counts

    path.write_text(json.dumps(records, indent=1), encoding="utf-8")
    counts["cached_to"] = str(path)
    return counts


# Certifications the fetched directories structurally miss. ISASecure lists
# only its own chartered certifications, but IEC 62443 certificates are also
# issued by TUV SUD, TUV Rheinland and exida -- which is how Siemens and
# Rockwell, two of the largest OT vendors, hold 62443-4-1 process and 4-2
# component certificates while appearing in no fetched list. Reading that gap
# as "no certificate found" skewed rankings between equally certified
# vendors, so the well-documented ones are carried here, each with a pointer
# to where the claim can be checked. Curated means curated: verify with the
# certifying body before relying on an entry, and the detail line says so.
CURATED = [
    {"scheme": "IEC 62443-4-1", "vendor": "Siemens", "product": "",
     "detail": "TUV SUD certified development process | curated entry --"
               " verify with the certifying body",
     "source": "https://www.siemens.com/global/en/products/automation/"
               "topic-areas/industrial-cybersecurity.html"},
    {"scheme": "IEC 62443-4-2", "vendor": "Siemens",
     "product": "SIMATIC S7-1500",
     "detail": "TUV SUD certified component family | curated entry -- verify"
               " with the certifying body",
     "source": "https://www.siemens.com/global/en/products/automation/"
               "topic-areas/industrial-cybersecurity.html"},
    {"scheme": "IEC 62443-4-1", "vendor": "Rockwell Automation", "product": "",
     "detail": "TUV Rheinland certified development process | curated entry --"
               " verify with the certifying body",
     "source": "https://www.rockwellautomation.com/en-us/capabilities/"
               "industrial-security.html"},
    {"scheme": "IEC 62443-4-2", "vendor": "Rockwell Automation",
     "product": "ControlLogix 5580",
     "detail": "TUV Rheinland certified component | curated entry -- verify"
               " with the certifying body",
     "source": "https://www.rockwellautomation.com/en-us/capabilities/"
               "industrial-security.html"},
]


def load(data_dir="data"):
    """Load the cached certificates plus the curated layer, keyed by vendor."""
    path = Path(data_dir) / "certifications.json"
    records = (json.loads(path.read_text(encoding="utf-8"))
               if path.exists() else [])
    by_vendor = {}
    for record in records + CURATED:
        by_vendor.setdefault(normalize_vendor(record["vendor"]), []).append(record)
    return by_vendor


def certificates_for(by_vendor, vendor, product=None):
    """Certificates held by this vendor, with product-level matches flagged.

    Vendor-level and product-level evidence are kept apart: a vendor holding a
    4-1 process certificate says something about how they build software, but it
    is not a statement about the specific box being bought.
    """
    records = by_vendor.get(normalize_vendor(vendor or ""), [])
    if not records:
        return []

    words = [w for w in re.split(r"[^a-z0-9]+", (product or "").lower()) if len(w) > 2]
    out = []
    for record in records:
        name = (record.get("product") or "").lower()
        exact = bool(words) and all(w in name for w in words)
        out.append({**record, "matches_product": exact})
    return out
