"""Supply-chain screening: sanctions, export restrictions, and covered lists.

This module decides whether a vendor is one a buyer is legally or contractually
barred from dealing with. Those are hard gates, so the matching rules here are
deliberately strict.

**Precision matters more here than anywhere else in ReTrust.** Wrongly telling a
buyer that a legitimate manufacturer appears on a sanctions list is far worse
than missing an entry: it is defamatory, and it destroys trust in every other
number the tool prints. So screening only ever matches on an exact normalised
name -- never a substring, never a fuzzy score -- and every hit carries the
source list and its URL so a human can check it before acting.

Two kinds of list:

  Screening lists   the US Consolidated Screening List: OFAC SDN, the BIS Entity
                    List, Denied Persons, Military End User, CMIC and others.
                    ~26,000 entities, refreshed from trade.gov.
  Covered lists     FCC Covered List and NDAA Section 889. No official
                    machine-readable form exists, so these are hand-curated here
                    with a citation on every entry.
"""

from __future__ import annotations

import csv
import json
import re
import urllib.request
from pathlib import Path

CSL_URL = ("https://data.trade.gov/downloadable_consolidated_screening_list/"
           "v1/consolidated.csv")

# Only bare legal forms are stripped. Note what is absent: "electric",
# "technologies", "systems", "automation" and similar are load-bearing parts of
# a company's identity, not decoration.
#
# This is deliberately NOT index.normalize_vendor, which does strip those words
# so that "Mitsubishi Electric" and "Mitsubishi Electric Corporation" collapse
# for advisory matching. Applying that here matched "Schneider Electric" against
# "Schneider GMBH" -- an unrelated company on the BIS Entity List -- and would
# have told a buyer that Schneider Electric is export-restricted.
_LEGAL_FORM = re.compile(
    r"\b(incorporated|inc|corporation|corp|company|co|limited|ltd|llc|llp|plc|"
    r"gmbh|mbh|ag|a/s|as|sa|se|srl|s\.p\.a|spa|bv|nv|oy|ab|pty|pte|kk|kg|"
    r"holdings?|group)\b",
    re.I,
)


def screening_key(name):
    """Conservative key for sanctions matching: identity-preserving."""
    text = re.sub(r"[.,()'\"]", " ", (name or "").lower())
    text = _LEGAL_FORM.sub(" ", text)
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]+", " ", text)).strip()

# Entities named in FCC Covered List / NDAA s.889 determinations. Kept short and
# cited rather than guessed at: these are legal determinations, and inferring
# affiliates without a source would be exactly the overreach this module avoids.
_FCC = "https://www.fcc.gov/supplychain/coveredlist"

COVERED_LIST = [
    {"name": "Huawei Technologies Company", "basis": "FCC Covered List; NDAA s.889(a)(1)(A)",
     "source": _FCC, "aliases": ["Huawei", "Huawei Technologies"]},
    {"name": "ZTE Corporation", "basis": "FCC Covered List; NDAA s.889(a)(1)(A)",
     "source": _FCC, "aliases": ["ZTE"]},
    {"name": "Hytera Communications Corporation", "basis": "FCC Covered List; NDAA s.889(a)(1)(B)",
     "source": _FCC, "aliases": ["Hytera", "Hytera Communications"]},
    {"name": "Hangzhou Hikvision Digital Technology", "basis": "FCC Covered List; NDAA s.889(a)(1)(B)",
     "source": _FCC, "aliases": ["Hikvision", "Hangzhou Hikvision"]},
    {"name": "Dahua Technology", "basis": "FCC Covered List; NDAA s.889(a)(1)(B)",
     "source": _FCC, "aliases": ["Dahua", "Zhejiang Dahua Technology"]},
    {"name": "China Mobile International USA", "basis": "FCC Covered List", "source": _FCC},
    {"name": "China Telecom Americas", "basis": "FCC Covered List", "source": _FCC},
    {"name": "Pacific Network Corp", "basis": "FCC Covered List", "source": _FCC},
    {"name": "China Unicom Americas", "basis": "FCC Covered List", "source": _FCC},
    {"name": "Kaspersky Lab", "basis": "FCC Covered List (2024 addition)",
     "source": _FCC},
]

# Lists whose presence should stop a procurement outright. The Consolidated
# Screening List also carries advisory entries (for example the Unverified List)
# that mean "do more diligence", not "do not buy", so they are reported without
# being treated as a gate.
BLOCKING_SOURCES = (
    "Specially Designated Nationals",
    "Entity List",
    "Denied Persons List",
    "Military End User",
    "Non-SDN Chinese Military-Industrial Complex",
    "Sectoral Sanctions",
    "ITAR Debarred",
    "Nonproliferation Sanctions",
)


def refresh(data_dir="data", timeout=120):
    """Download the Consolidated Screening List and cache the parts we screen on."""
    directory = Path(data_dir)
    directory.mkdir(parents=True, exist_ok=True)

    request = urllib.request.Request(CSL_URL, headers={"User-Agent": "ReTrust/0.1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        text = response.read().decode("utf-8", errors="replace")

    entries = []
    for row in csv.DictReader(text.splitlines()):
        name = (row.get("name") or "").strip()
        if not name:
            continue
        entries.append({
            "name": name,
            "source": (row.get("source") or "").strip(),
            "programs": (row.get("programs") or "").strip(),
            "country": (row.get("country") or "").strip(),
            "url": (row.get("source_list_url") or "").strip(),
            "alt_names": [a.strip() for a in (row.get("alt_names") or "").split(";") if a.strip()],
        })

    path = directory / "screening.json"
    path.write_text(json.dumps(entries, indent=0), encoding="utf-8")
    return {"entities": len(entries), "cached_to": str(path)}


def load(data_dir="data"):
    """Build the exact-match index used for screening.

    Keyed on the identity-preserving name and each alias, so "Schneider
    Electric" cannot collide with an unrelated "Schneider GMBH".
    """
    index = {}

    for entry in COVERED_LIST:
        record = {
            "name": entry["name"], "source": entry["basis"],
            "url": entry["source"], "blocking": True, "kind": "covered_list",
        }
        for name in [entry["name"], *entry.get("aliases", [])]:
            if key := screening_key(name):
                index.setdefault(key, []).append(record)

    path = Path(data_dir) / "screening.json"
    if path.exists():
        for entry in json.loads(path.read_text(encoding="utf-8")):
            blocking = any(s in entry["source"] for s in BLOCKING_SOURCES)
            record = {
                "name": entry["name"], "source": entry["source"],
                "programs": entry.get("programs", ""), "country": entry.get("country", ""),
                "url": entry.get("url", ""), "blocking": blocking, "kind": "screening_list",
            }
            for name in [entry["name"], *entry.get("alt_names", [])]:
                key = screening_key(name)
                # A one-word key shorter than four characters is too collision-
                # prone to screen on; the full multi-word name is still indexed.
                if key and (len(key) >= 4 or " " in key):
                    index.setdefault(key, []).append(record)

    return index


def screen(index, vendor):
    """Exact-match a vendor against the screening index.

    Returns (blocking_hits, advisory_hits). Both are empty for the overwhelming
    majority of vendors, which is the correct and expected outcome.
    """
    if not vendor:
        return [], []
    hits = index.get(screening_key(vendor), [])
    return ([h for h in hits if h["blocking"]],
            [h for h in hits if not h["blocking"]])


def gates_for(index, vendor):
    """Hard gates raised by screening, in the shape score.check_gates expects."""
    blocking, _ = screen(index, vendor)
    gates = []
    for hit in blocking:
        label = ("Named on a covered list" if hit["kind"] == "covered_list"
                 else "Sanctioned or export-restricted entity")
        gates.append({
            "gate": label,
            "detail": f"{vendor} matches {hit['name']!r} on {hit['source']}"
                      + (f" ({hit['programs']})" if hit.get("programs") else ""),
            "source": hit["url"] or hit["source"],
        })
    return gates
