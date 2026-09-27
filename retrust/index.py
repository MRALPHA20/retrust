"""Build and query the local SQLite index.

One file holds everything ReTrust knows: advisories, the products each one
names, the CVEs affecting them, and the exploitation signals (KEV, EPSS).
Keeping it in SQLite means a scoring run needs no network, so results are
reproducible and a demo never depends on conference wifi.
"""

import re
import sqlite3
from pathlib import Path

from . import csaf

SCHEMA = """
CREATE TABLE IF NOT EXISTS advisory (
    id TEXT PRIMARY KEY, title TEXT, released TEXT, source TEXT);

CREATE TABLE IF NOT EXISTS product (
    rowid_ INTEGER PRIMARY KEY,
    advisory_id TEXT, product_id TEXT,
    vendor TEXT, vendor_key TEXT,     -- vendor_key is the normalised vendor
    name TEXT, name_key TEXT,         -- name_key is the normalised product name
    version_range TEXT);

CREATE TABLE IF NOT EXISTS order_number (
    number_key TEXT, product_rowid INTEGER);

CREATE TABLE IF NOT EXISTS affected (
    advisory_id TEXT, product_id TEXT, cve TEXT, cvss REAL, cwe TEXT,
    remediation TEXT);

CREATE TABLE IF NOT EXISTS exploitation (
    cve TEXT PRIMARY KEY, epss REAL, in_kev INTEGER DEFAULT 0, ransomware INTEGER DEFAULT 0);

-- Provenance: which source snapshot produced this index. Printed on every
-- report so a result can be tied to the exact data it came from.
CREATE TABLE IF NOT EXISTS provenance (
    source TEXT PRIMARY KEY, detail TEXT, captured TEXT);

CREATE INDEX IF NOT EXISTS ix_order    ON order_number(number_key);
CREATE INDEX IF NOT EXISTS ix_vendor   ON product(vendor_key);
CREATE INDEX IF NOT EXISTS ix_name     ON product(vendor_key, name_key);
CREATE INDEX IF NOT EXISTS ix_affected ON affected(advisory_id, product_id);
"""

# Vendors appear under many spellings across 884 raw strings in the CISA corpus
# ("Mitsubishi Electric" / "Mitsubishi Electric Corporation"). Stripping these
# suffixes collapses most of the duplicates.
COMPANY_SUFFIXES = re.compile(
    r"\b(corporation|corp|company|co|incorporated|inc|limited|ltd|llc|llp|plc|"
    r"gmbh|ag|a/s|as|sa|se|srl|spa|bv|nv|oy|ab|pty|pte|kk|kg|group|holdings|"
    r"electric|electronics|automation|technologies|technology|systems|software|"
    r"solutions|industries|international)\b",
    re.I,
)


def normalize_vendor(text):
    """Collapse vendor spellings to a comparable key."""
    text = re.sub(r"[.,()]", " ", (text or "").lower())
    text = COMPANY_SUFFIXES.sub(" ", text)
    return re.sub(r"[^a-z0-9]+", "", text)


def normalize_name(text):
    """Collapse a product name to a comparable key."""
    return re.sub(r"[^a-z0-9]+", "", (text or "").lower())


def normalize_order_number(text):
    """Order numbers differ only by punctuation and case between sources."""
    return re.sub(r"[^A-Z0-9]+", "", (text or "").upper())


def connect(path):
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.executescript(SCHEMA)
    return connection


def record_provenance(connection, source, detail, captured=None):
    """Note where a slice of the index came from, and when."""
    from datetime import date
    with connection:
        connection.execute(
            "INSERT INTO provenance VALUES (?,?,?) ON CONFLICT(source) DO UPDATE SET"
            " detail=excluded.detail, captured=excluded.captured",
            (source, detail, captured or date.today().isoformat()))


def provenance(connection):
    """Every recorded source, for the report footer and `retrust stats`."""
    return [dict(r) for r in connection.execute(
        "SELECT source, detail, captured FROM provenance ORDER BY source")]


def build(db_path, csaf_root, progress=None):
    """Ingest every CSAF advisory under `csaf_root` into a fresh index."""
    Path(db_path).unlink(missing_ok=True)
    connection = connect(db_path)
    counts = {"advisories": 0, "products": 0, "cve_links": 0}

    with connection:
        for advisory in csaf.parse_directory(csaf_root):
            connection.execute(
                "INSERT OR REPLACE INTO advisory VALUES (?,?,?,?)",
                (advisory.advisory_id, advisory.title, advisory.released,
                 Path(advisory.source).name),
            )
            counts["advisories"] += 1

            for product in advisory.products:
                cursor = connection.execute(
                    "INSERT INTO product (advisory_id, product_id, vendor, vendor_key,"
                    " name, name_key, version_range) VALUES (?,?,?,?,?,?,?)",
                    (
                        advisory.advisory_id, product.product_id,
                        product.vendor, normalize_vendor(product.vendor),
                        product.name, normalize_name(product.name),
                        product.version_range,
                    ),
                )
                counts["products"] += 1
                connection.executemany(
                    "INSERT INTO order_number VALUES (?,?)",
                    [(normalize_order_number(n), cursor.lastrowid)
                     for n in product.order_numbers if normalize_order_number(n)],
                )

            rows = [
                (advisory.advisory_id, product_id, cve, data["cvss"], data["cwe"],
                 data.get("remediation", "unknown"))
                for cve, data in advisory.vulnerabilities.items()
                for product_id in data["product_ids"]
            ]
            connection.executemany("INSERT INTO affected VALUES (?,?,?,?,?,?)", rows)
            counts["cve_links"] += len(rows)

            if progress and counts["advisories"] % 500 == 0:
                progress(counts)

    # Record what was ingested, not where it happened to sit on this machine:
    # the absolute path is noise in a shared report and leaks local directory
    # structure into every snapshot and JSON export.
    record_provenance(connection, "CISA OT advisories (CSAF 2.0)",
                      f"{counts['advisories']:,} advisories, "
                      f"{counts['products']:,} products")
    return connection, counts


def load_exploitation(connection, kev_path=None, epss_path=None):
    """Load CISA KEV and FIRST EPSS, the two exploitation signals we score on."""
    import csv
    import json

    loaded = {"kev": 0, "epss": 0}
    with connection:
        if kev_path and Path(kev_path).exists():
            catalog = json.loads(Path(kev_path).read_text())
            rows = [
                (item["cveID"], 1,
                 int(str(item.get("knownRansomwareCampaignUse", "")).lower() == "known"))
                for item in catalog.get("vulnerabilities", [])
            ]
            connection.executemany(
                "INSERT INTO exploitation (cve, in_kev, ransomware) VALUES (?,?,?) "
                "ON CONFLICT(cve) DO UPDATE SET in_kev=excluded.in_kev,"
                " ransomware=excluded.ransomware", rows)
            loaded["kev"] = len(rows)
            record_provenance(connection, "CISA KEV", f"{len(rows):,} entries")

        if epss_path and Path(epss_path).exists():
            # Only CVEs we actually reference, so the index stays small.
            wanted = {r[0] for r in connection.execute("SELECT DISTINCT cve FROM affected")}
            with open(epss_path, newline="") as handle:
                handle.readline()               # "#model_version:..." comment line
                rows = [(r["cve"], float(r["epss"]))
                        for r in csv.DictReader(handle) if r["cve"] in wanted]
            connection.executemany(
                "INSERT INTO exploitation (cve, epss) VALUES (?,?) "
                "ON CONFLICT(cve) DO UPDATE SET epss=excluded.epss", rows)
            loaded["epss"] = len(rows)
            record_provenance(connection, "FIRST EPSS", f"{len(rows):,} scores")

    return loaded


def stats(connection):
    """Counts shown by `retrust stats`."""
    one = lambda sql: connection.execute(sql).fetchone()[0]
    return {
        "advisories": one("SELECT COUNT(*) FROM advisory"),
        "products": one("SELECT COUNT(*) FROM product"),
        "vendors": one("SELECT COUNT(DISTINCT vendor_key) FROM product"),
        "cves": one("SELECT COUNT(DISTINCT cve) FROM affected"),
        "order_numbers": one("SELECT COUNT(DISTINCT number_key) FROM order_number"),
        "kev": one("SELECT COUNT(*) FROM exploitation WHERE in_kev=1"),
        "epss": one("SELECT COUNT(*) FROM exploitation WHERE epss IS NOT NULL"),
    }
