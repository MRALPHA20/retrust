"""Is this installation ready to be trusted, right now?

A tool that people run at purchase time gets run occasionally, and between two
runs the data underneath it ages: KEV is published weekly, EPSS daily, the
screening lists whenever a government acts. A verdict computed over a
six-month-old KEV is not the verdict the tool promises, and nothing else in
the pipeline says so out loud.

`retrust doctor` checks the whole installation and says what to run, so "is
this thing still current?" is one command instead of a mental checklist. Every
check reports one of three states:

    ok      current and usable
    stale   usable, but old enough that a verdict could differ after a refresh
    missing the feature depending on it will abstain or fail

Staleness thresholds follow each source's own publishing cadence, not one
arbitrary age.
"""

import shutil
import sqlite3
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

# Days after which a source is called stale, set from how often it is
# published: KEV moves weekly, EPSS daily, the screening and certification
# lists at most monthly.
AGE_LIMITS = {"kev": 14, "epss": 14, "history": 14, "lists": 90}


@dataclass
class Check:
    """One line of the report."""

    name: str
    state: str          # "ok" | "stale" | "missing"
    detail: str
    fix: str = ""       # the command that clears it, when one exists

    @property
    def ok(self):
        return self.state == "ok"


def _age_days(path):
    """Whole days since a file was last written, or None if it is absent."""
    p = Path(path)
    if not p.exists():
        return None
    return (datetime.now() - datetime.fromtimestamp(p.stat().st_mtime)).days


def _aged(name, path, limit, fix, what):
    """A file that is expected to exist and to be reasonably fresh."""
    age = _age_days(path)
    if age is None:
        return Check(name, "missing", f"{path} is absent -- {what}", fix)
    if age > limit:
        return Check(name, "stale",
                     f"{age} days old (published every {limit // 7 or 1} "
                     f"week(s) or faster)" if limit >= 7 else f"{age} days old",
                     fix)
    return Check(name, "ok", f"{age} day(s) old")


def run(data_dir="data", db_path="data/retrust.db"):
    """Every check, in the order a reader should think about them."""
    checks = []
    data = Path(data_dir)

    # The index itself. Everything else is pointless without it.
    try:
        connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        counts = {r[0]: r[1] for r in connection.execute(
            "SELECT 'advisories', COUNT(*) FROM advisory "
            "UNION ALL SELECT 'products', COUNT(*) FROM product")}
        if counts.get("advisories"):
            checks.append(Check("index", "ok",
                                f"{counts['advisories']:,} advisories, "
                                f"{counts['products']:,} product entries"))
        else:
            checks.append(Check("index", "missing", f"{db_path} is empty",
                                "retrust ingest --csaf data/CSAF"))
            connection = None
    except sqlite3.Error as error:
        checks.append(Check("index", "missing", f"{db_path}: {error}",
                            "retrust setup"))
        connection = None

    # The corpus the index was built from. Counted so a re-clone that grew
    # is visible: an index smaller than its corpus is an index behind it.
    corpus = data / "CSAF"
    if corpus.is_dir():
        # Skipping feed indexes the same way the ingest does, so the two
        # numbers are comparable rather than one step out by construction.
        files = sum(1 for f in corpus.rglob("*.json") if "feed" not in f.name)
        checks.append(Check("corpus", "ok", f"{files:,} advisory files on disk"))
        if connection and files > int(counts.get("advisories", 0)) * 1.02:
            checks.append(Check(
                "corpus drift", "stale",
                f"{files:,} files on disk against {counts['advisories']:,} "
                "advisories indexed -- the corpus has grown since the ingest",
                "retrust ingest --csaf data/CSAF"))
    else:
        checks.append(Check("corpus", "missing", f"{corpus} is absent",
                            "retrust setup"))

    # Vendor trusted-provider feeds fetched beside the CISA corpus. Each is
    # its own row: the reader should see which publishers feed this index.
    providers = data / "CSAF-providers"
    if providers.is_dir():
        for feed_dir in sorted(p for p in providers.iterdir() if p.is_dir()):
            files = sum(1 for f in feed_dir.glob("*.json")
                        if not f.name.endswith((".sha512", ".asc")))
            checks.append(Check(f"provider {feed_dir.name}", "ok",
                                f"{files:,} advisory files on disk -- indexed"
                                " only if the last ingest named this root"))

    # The exploitation signals, at their own cadences.
    checks.append(_aged("KEV feed", data / "kev.json", AGE_LIMITS["kev"],
                        "retrust setup --force", "the KEV gate cannot fire"))
    checks.append(_aged("EPSS feed", data / "epss.csv", AGE_LIMITS["epss"],
                        "retrust setup --force",
                        "exploitation probabilities are absent"))

    # LEV needs the daily history, and its newest day is what decides whether
    # the estimates describe this month or a previous one.
    history = sorted((data / "epss-history").glob("epss_scores-*.csv"))
    if not history:
        checks.append(Check("EPSS history", "missing",
                            "no daily snapshots -- `retrust lev` will abstain",
                            "retrust lev --update"))
    else:
        newest = history[-1].stem.rsplit("-", 3)
        try:
            newest_day = date.fromisoformat("-".join(newest[-3:]))
            age = (date.today() - newest_day).days
            state = "ok" if age <= AGE_LIMITS["history"] else "stale"
            checks.append(Check("EPSS history", state,
                                f"{len(history)} snapshots, newest {newest_day} "
                                f"({age} day(s) ago)",
                                "" if state == "ok" else "retrust lev --update"))
        except ValueError:
            checks.append(Check("EPSS history", "ok", f"{len(history)} snapshots"))

    # The screening and certification lists, which gate and credit.
    checks.append(_aged("screening lists", data / "screening.json",
                        AGE_LIMITS["lists"], "retrust setup --force",
                        "sanctions and covered-list gates cannot fire"))
    checks.append(_aged("certifications", data / "certifications.json",
                        AGE_LIMITS["lists"], "retrust setup --force",
                        "IEC 62443 / Common Criteria credit is absent"))

    # Verification tooling. Optional, and said so rather than failed.
    if shutil.which("gpg") is None:
        checks.append(Check("gpg", "missing",
                            "not installed -- `retrust verify` checks digests "
                            "only, never the signer", "install gnupg"))
    elif (data / "csaf-keyring.gpg").exists():
        checks.append(Check("gpg", "ok", "installed, CISA keyring present"))
    else:
        checks.append(Check("gpg", "ok",
                            "installed; no keyring yet, so `retrust verify "
                            "--fetch-key` would establish the signer"))

    return checks


def format_report(checks):
    """The printed table, worst news first within each state's ordering."""
    label = {"ok": "ok", "stale": "STALE", "missing": "MISSING"}
    width = max(len(c.name) for c in checks)
    lines = []
    for check in checks:
        lines.append(f"  {label[check.state]:<8}{check.name:<{width + 3}}"
                     f"{check.detail}")
    fixes = [c for c in checks if c.fix and not c.ok]
    if fixes:
        lines.append("")
        lines.append("  To clear the flagged ones:")
        seen = []
        for check in fixes:
            if check.fix not in seen:
                seen.append(check.fix)
                lines.append(f"    {check.fix}")
    else:
        lines.append("")
        lines.append("  Everything current. Nothing to run.")
    return "\n".join(lines)
