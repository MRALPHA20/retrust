"""Portable, pinned data bundles.

Two problems this solves.

The demo problem: an Arsenal station has unreliable wifi, and rebuilding the
index needs a 134 MB clone plus three downloads. A snapshot is one file you copy
onto the machine beforehand.

The reproducibility problem, which matters more: "ReTrust said AVOID" is only
checkable if someone else can run it against the same data you did. Sources
move -- KEV grows weekly, EPSS is regenerated daily, vendors revise advisories.
A snapshot pins all of them together with a checksum, so a result can be
reproduced months later and shown to be the same result.

The format is a zip holding the SQLite index and the cached auxiliary lists,
plus a manifest recording what went in and when.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import zipfile
from datetime import date
from pathlib import Path

MANIFEST = "manifest.json"
FORMAT_VERSION = 1

# Everything a scoring run reads, relative to the data directory.
CONTENTS = ["retrust.db", "certifications.json", "screening.json"]

# A snapshot of the real corpus is ~24 MB unpacked. This ceiling leaves ample
# room while refusing an archive that claims to expand to gigabytes.
MAX_UNPACKED_BYTES = 500 * 1024 * 1024


def _digest(path):
    """SHA-256 of a file, so a snapshot can be shown to be unmodified."""
    sha = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            sha.update(chunk)
    return sha.hexdigest()


def create(data_dir="data", out_path="retrust-snapshot.zip", provenance=(), note=""):
    """Bundle the current data directory into one portable file."""
    directory = Path(data_dir)
    present = [name for name in CONTENTS if (directory / name).exists()]
    if "retrust.db" not in present:
        raise SystemExit(
            f"No index at {directory / 'retrust.db'}. Run `retrust ingest` first.")

    manifest = {
        "format": FORMAT_VERSION,
        "created": date.today().isoformat(),
        "note": note,
        "provenance": list(provenance),
        "files": {},
    }

    destination = Path(out_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as bundle:
        for name in present:
            source = directory / name
            manifest["files"][name] = {
                "sha256": _digest(source), "bytes": source.stat().st_size}
            bundle.write(source, name)
        bundle.writestr(MANIFEST, json.dumps(manifest, indent=2))

    return {"path": str(destination), "files": present,
            "bytes": destination.stat().st_size, "manifest": manifest}


def inspect(snapshot_path):
    """Read a snapshot's manifest without unpacking it."""
    with zipfile.ZipFile(snapshot_path) as bundle:
        if MANIFEST not in bundle.namelist():
            raise SystemExit(f"{snapshot_path} has no {MANIFEST}; not a ReTrust snapshot.")
        return json.loads(bundle.read(MANIFEST))


def restore(snapshot_path, data_dir="data", verify=True):
    """Unpack a snapshot, checking each file against its recorded digest."""
    manifest = inspect(snapshot_path)
    if manifest.get("format") != FORMAT_VERSION:
        raise SystemExit(
            f"snapshot format {manifest.get('format')} is not supported "
            f"(this build reads format {FORMAT_VERSION})")

    directory = Path(data_dir)
    directory.mkdir(parents=True, exist_ok=True)

    # Unpack to a staging directory and verify there before touching anything
    # live. Extracting first and checking afterwards would destroy a good
    # working index on the way to reporting that the snapshot was corrupt.
    with tempfile.TemporaryDirectory(dir=directory.parent) as staging:
        staged = Path(staging)
        restored, mismatched = [], []
        total = 0

        with zipfile.ZipFile(snapshot_path) as bundle:
            for name, meta in manifest["files"].items():
                info = bundle.getinfo(name)
                total += info.file_size
                if total > MAX_UNPACKED_BYTES:
                    raise SystemExit(
                        f"{snapshot_path} unpacks to more than "
                        f"{MAX_UNPACKED_BYTES // 1_000_000} MB; refusing to "
                        "expand it. This is what a decompression bomb looks like.")
                bundle.extract(name, staged)
                if verify and _digest(staged / name) != meta["sha256"]:
                    mismatched.append(name)
                restored.append(name)

        if mismatched:
            raise SystemExit(
                f"checksum mismatch on {', '.join(mismatched)}. The snapshot is "
                "corrupt or was modified; results from it would not be trustworthy. "
                "Nothing was changed.")

        for name in restored:
            shutil.move(str(staged / name), str(directory / name))

    return {"restored": restored, "created": manifest.get("created"),
            "note": manifest.get("note", ""), "provenance": manifest.get("provenance", [])}
