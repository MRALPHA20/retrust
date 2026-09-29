"""Take a fresh clone to a working index with one command.

Setting ReTrust up by hand means cloning a 148 MB advisory corpus with the right
sparse-checkout flags, fetching two feeds, building the index, and refreshing two
more lists: eight commands spread across two sections of the README, each with
its own way of going wrong. One of them, the sparse-checkout invocation, was
silently broken on current git for months. This module is that sequence written
once, where it can be tested.

Downloads use urllib rather than curl so the same command works on a machine
that has neither curl nor a package manager. Every step is skipped when its
output is already there, so re-running after an interruption costs nothing and
resumes where it stopped.
"""

import gzip
import io
import json
import shutil
import time
import subprocess
import urllib.parse
import urllib.request
from pathlib import Path

from . import certification, index, supplychain

CORPUS_REPO = "https://github.com/cisagov/CSAF.git"
CORPUS_PATH = "csaf_files/OT"          # the OT slice; the full repo is far larger
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

TIMEOUT = 120
_USER_AGENT = "Mozilla/5.0 (compatible; ReTrust/0.1; +setup)"

# KEV is ~2 MB and EPSS ~13 MB unpacked. A response past this is not the feed:
# it is a broken or hostile mirror, and reading it without a ceiling hands that
# mirror the machine's memory and disk. The same cap bounds gzip expansion,
# because a compressed member can claim any size it likes.
MAX_FEED_BYTES = 200 * 1024 * 1024


class StepFailed(Exception):
    """A setup step failed in a way the user can act on."""


def _read_capped(stream, url):
    """Read a stream fully, refusing to go past MAX_FEED_BYTES."""
    chunks, total = [], 0
    while chunk := stream.read(1 << 20):
        total += len(chunk)
        if total > MAX_FEED_BYTES:
            raise StepFailed(
                f"{url} is over {MAX_FEED_BYTES // 1_000_000} MB, which no "
                "feed this tool fetches has ever been. Refusing the rest.")
        chunks.append(chunk)
    return b"".join(chunks)


def _download(url, destination, decompress=False):
    """Fetch a URL to a file, atomically.

    Writing straight to the destination would leave a truncated file behind if
    the connection dropped, and every later run would skip it as "already
    present" -- so the index would quietly be built on half a feed.

    The final address must still be https: urllib follows redirects across
    schemes, and a feed that lands on plain http arrives over a channel anyone
    on the path can rewrite.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_name(destination.name + ".part")
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        landed = getattr(response, "url", url)
        if urllib.parse.urlsplit(landed).scheme != "https":
            raise StepFailed(f"{url} redirected to {landed}; refusing to fetch "
                             "over anything but https")
        payload = _read_capped(response, url)
    if decompress:
        payload = _read_capped(gzip.GzipFile(fileobj=io.BytesIO(payload)), url)
    partial.write_bytes(payload)
    partial.replace(destination)
    return destination.stat().st_size


def _git(arguments, cwd=None):
    result = subprocess.run(["git", *arguments], cwd=cwd, capture_output=True,
                            text=True)
    if result.returncode:
        raise StepFailed(f"git {' '.join(arguments)} failed: "
                         f"{result.stderr.strip() or result.stdout.strip()}")


def corpus_dir(data_dir="data"):
    """Where the advisories live once fetched."""
    return Path(data_dir) / "CSAF" / CORPUS_PATH


def fetch_corpus(data_dir="data", force=False):
    """Sparse-clone CISA's OT advisories (~148 MB)."""
    target = Path(data_dir) / "CSAF"
    advisories = corpus_dir(data_dir)
    if advisories.is_dir() and not force:
        return f"{sum(1 for _ in advisories.rglob('*.json')):,} advisory files"

    if shutil.which("git") is None:
        raise StepFailed(
            "git is not installed, and the advisory corpus is a git repository. "
            "Install git, or copy an existing data/CSAF directory into place.")
    if target.exists():
        shutil.rmtree(target)

    _git(["clone", "--depth", "1", "--filter=blob:none", "--no-checkout", "-q",
          CORPUS_REPO, str(target)])
    _git(["sparse-checkout", "set", "--cone", CORPUS_PATH], cwd=target)
    _git(["checkout", "-q"], cwd=target)
    if not advisories.is_dir():
        raise StepFailed(f"the clone succeeded but {advisories} is missing; "
                         "the upstream repository may have been restructured")
    return f"{sum(1 for _ in advisories.rglob('*.json')):,} advisory files"


def fetch_feed(data_dir="data", name="kev", force=False):
    """Fetch CISA KEV or FIRST EPSS, whichever is asked for."""
    url, filename, gzipped = {
        "kev": (KEV_URL, "kev.json", False),
        "epss": (EPSS_URL, "epss.csv", True),
    }[name]
    destination = Path(data_dir) / filename
    if destination.exists() and not force:
        return f"{destination.stat().st_size / 1e6:.1f} MB, already present"
    try:
        size = _download(url, destination, decompress=gzipped)
    except Exception as error:                  # network, DNS, TLS, bad gzip
        raise StepFailed(f"could not fetch {name.upper()} from {url} ({error})")
    return f"{size / 1e6:.1f} MB"


EPSS_DAY_URL = "https://epss.empiricalsecurity.com/epss_scores-{day}.csv.gz"


def fetch_epss_history(data_dir="data", days=(), force=False, progress=None):
    """Fetch one EPSS snapshot per sampled day, for the LEV estimate.

    About 1.6 MB each and roughly seventy of them across EPSS's whole life, so
    this is opt-in rather than part of setup. Days already on disk are skipped,
    which is what makes a re-run after an interruption cheap.
    """
    directory = Path(data_dir) / "epss-history"
    directory.mkdir(parents=True, exist_ok=True)
    fetched, present, missing = 0, 0, 0
    for day in days:
        destination = directory / f"epss_scores-{day}.csv"
        if destination.exists() and not force:
            present += 1
            continue
        try:
            _download(EPSS_DAY_URL.format(day=day), destination, decompress=True)
            fetched += 1
        except Exception:
            # FIRST has gaps, and a missing day is not a reason to abandon the
            # rest: LEV composes whatever days it has and says how many.
            missing += 1
        if progress:
            progress(day, fetched, present, missing)
    return {"fetched": fetched, "already_present": present, "unavailable": missing,
            "directory": str(directory)}


def history_files(data_dir="data"):
    return sorted((Path(data_dir) / "epss-history").glob("epss_scores-*.csv"))


def build_index(data_dir="data", db_path="data/retrust.db"):
    """Ingest the corpus and both exploitation feeds."""
    advisories = corpus_dir(data_dir)
    if not advisories.is_dir():
        raise StepFailed(f"no advisories at {advisories}; run without --offline "
                         "to fetch them")
    # Without KEV and EPSS the exploitation gates cannot fire, and a product
    # with a known exploited flaw would score as merely mediocre. Refuse to
    # present that as a finished index.
    feeds = {name: Path(data_dir) / f for name, f in
             (("kev", "kev.json"), ("epss", "epss.csv"))}
    missing = [name for name, path in feeds.items() if not path.exists()]
    if missing:
        raise StepFailed(
            f"{' and '.join(m.upper() for m in missing)} "
            "is missing, so the exploitation gates cannot fire. Re-run with "
            "network access. The existing index has been preserved.")
    try:
        connection, counts = index.build(db_path, str(advisories),
                                        kev_path=feeds["kev"], epss_path=feeds["epss"])
    except (OSError, ValueError, KeyError) as error:
        raise StepFailed(f"Index build failed; existing index preserved: {error}") from error
    loaded = counts["exploitation"]
    connection.close()
    return (f"{counts['advisories']:,} advisories, {counts['products']:,} products, "
            f"KEV {loaded['kev']:,}, EPSS {loaded['epss']:,}")


def refresh_lists(data_dir="data"):
    """Certification evidence and sanctions screening (~17 MB)."""
    # certification.refresh reports a count per scheme, and a scheme that failed
    # reports a message instead -- so total only what actually came back.
    schemes = certification.refresh(data_dir)
    certificates = sum(n for n in schemes.values() if isinstance(n, int))
    try:
        screening = supplychain.refresh(data_dir)
    except SystemExit as stop:      # it ends the process; here it is one step failing
        raise StepFailed(str(stop))
    return (f"{certificates:,} certificates, "
            f"{screening.get('entities', 0):,} screened entities")


def steps(offline=False, skip_refresh=False):
    """The setup sequence, as (name, description, callable) triples.

    Kept as data so the CLI can number the steps, and so a test can assert the
    order without running any of them.
    """
    sequence = [
        ("corpus", "CISA OT advisories (~148 MB)",
         lambda data, db, force: fetch_corpus(data, force)),
        ("kev", "CISA Known Exploited Vulnerabilities",
         lambda data, db, force: fetch_feed(data, "kev", force)),
        ("epss", "FIRST EPSS scores",
         lambda data, db, force: fetch_feed(data, "epss", force)),
    ]
    if offline:
        sequence = []
    sequence.append(("index", "Build the local index",
                     lambda data, db, force: build_index(data, db)))
    if not (offline or skip_refresh):
        sequence.append(("lists", "Certification and sanctions lists (~17 MB)",
                         lambda data, db, force: refresh_lists(data)))
    return sequence


def run(data_dir="data", db_path="data/retrust.db", force=False, offline=False,
        skip_refresh=False, progress=None):
    """Run the whole sequence. Returns a result per step.

    Stops at the first failure rather than pressing on, because every step here
    is a precondition of the next and a later error would be confusing rather
    than informative.
    """
    progress = progress or (lambda *_: None)
    sequence = steps(offline, skip_refresh)
    results = {}

    for number, (name, description, action) in enumerate(sequence, start=1):
        progress(f"  [{number}/{len(sequence)}] {description} ...")
        try:
            results[name] = {"ok": True, "detail": action(data_dir, db_path, force)}
        except StepFailed as failure:
            results[name] = {"ok": False, "detail": str(failure)}
            return results
        progress(f"        {results[name]['detail']}")
    return results


# --- vendor trusted-provider feeds -----------------------------------------
#
# CISA's corpus is a republisher: vendors that run their own product CERT
# publish CSAF at their own domain, listed in a provider-metadata.json the
# standard defines, and their feeds carry advisories CISA has not (yet)
# mirrored. Fetching one puts the vendor's own words beside CISA's, and the
# multi-root ingest indexes both.

PROVIDERS_DIR = "CSAF-providers"

# One advisory JSON is tens of KB; a megabyte-scale one exists but a larger
# claim is a broken feed, not an advisory.
MAX_ADVISORY_BYTES = 30 * 1024 * 1024


def fetch_provider(metadata_url, data_dir="data", force=False, progress=None):
    """Fetch every TLP:WHITE advisory a CSAF provider publishes.

    `metadata_url` is the provider-metadata.json address the vendor
    advertises (Siemens: cert-portal.siemens.com/productcert/csaf/...).
    Advisories land under data/CSAF-providers/<host>/, one file each, with
    the .sha512 and .asc the provider serves beside them -- so `retrust
    verify --csaf` extends to the vendor's feed unchanged. Files already
    present are skipped unless `force`, which makes a re-run an incremental
    refresh rather than a re-download.

    Only TLP:WHITE feeds are read: anything else is not public, and this
    tool must never make it so.
    """
    if urllib.parse.urlsplit(metadata_url).scheme != "https":
        raise StepFailed(f"{metadata_url} is not https; a provider feed"
                         " fetched over a rewritable channel proves nothing")
    request = urllib.request.Request(metadata_url,
                                     headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        metadata = json.loads(_read_capped(response, metadata_url))

    host = urllib.parse.urlsplit(metadata_url).netloc
    target = Path(data_dir) / PROVIDERS_DIR / host
    feeds = [feed for distribution in metadata.get("distributions") or []
             for feed in (distribution.get("rolie") or {}).get("feeds") or []
             if feed.get("tlp_label") == "WHITE" and feed.get("url")]
    if not feeds:
        raise StepFailed(f"{metadata_url} advertises no TLP:WHITE ROLIE feed;"
                         " nothing public to fetch")

    fetched = already = failed = 0
    last_error = ""
    for feed in feeds:
        with urllib.request.urlopen(
                urllib.request.Request(feed["url"],
                                       headers={"User-Agent": _USER_AGENT}),
                timeout=TIMEOUT) as response:
            listing = json.loads(_read_capped(response, feed["url"]))
        entries = (listing.get("feed") or listing).get("entry") or []
        for entry in entries:
            links = {link.get("rel"): link.get("href")
                     for link in entry.get("link") or []}
            advisory_url = links.get("self")
            if not advisory_url:
                continue
            name = advisory_url.rsplit("/", 1)[-1]
            destination = target / name
            if destination.exists() and not force:
                already += 1
                continue
            try:
                _download_patiently(advisory_url, destination)
                # The digest and signature the provider serves beside it,
                # fetched best-effort: their absence weakens verification,
                # never the advisory itself.
                for rel in ("hash", "signature"):
                    if links.get(rel):
                        suffix = links[rel].rsplit("/", 1)[-1]
                        try:
                            _download_patiently(links[rel], target / suffix)
                        except (StepFailed, OSError):
                            pass
                fetched += 1
            except (StepFailed, OSError) as error:
                failed += 1
                last_error = str(error)
            if progress and (fetched + already) % 50 == 0:
                progress(fetched, already, len(entries))

    return {"host": host, "directory": str(target), "fetched": fetched,
            "already_present": already, "failed": failed,
            "last_error": last_error}


def _download_patiently(url, destination, attempts=4):
    """_download with backoff. A provider serving hundreds of small files
    rate-limits a naive burst -- the first Siemens fetch lost 756 of 841 to
    exactly that -- so failures wait and retry, and every file is followed by
    a breath. A re-run resumes: files already on disk are skipped upstream.
    """
    for attempt in range(attempts):
        try:
            size = _download(url, destination)
            time.sleep(0.05)              # politeness between hundreds of files
            return size
        except (StepFailed, OSError):
            if attempt == attempts - 1:
                raise
            time.sleep(2 ** attempt)      # 1s, 2s, 4s: outlast a rate limiter
