"""Regression guards for the security review.

Each test pins one finding from the hardening pass so it cannot return quietly:
an SSRF scheme slipping back in, the fix-text regex going quadratic again, a
poisoned version crashing the parser, a decompression bomb measured by its own
claimed size. They are unit-level on purpose -- the behaviour they protect is in
pure functions, so the guard reads as plainly as the code it watches.
"""

import json
import time
import zipfile

import pytest

# --- SSRF: every URL taken from fetched content is vetted before the request ---

def test_fetched_urls_must_be_public_https():
    """A provider feed is attacker-influenceable, so file://, http:// and any
    non-public host are refused before a request is ever made -- this is what
    stops a feed URL from reaching the loopback or a cloud metadata endpoint."""
    from retrust import bootstrap
    for blocked in (
        "file:///etc/passwd",
        "ftp://example.com/x",
        "http://169.254.169.254/latest/meta-data/",
        "https://169.254.169.254/latest/meta-data/",
        "https://127.0.0.1/x",
        "https://localhost/x",
        "https://10.0.0.5/internal",
    ):
        with pytest.raises(bootstrap.StepFailed):
            bootstrap._require_public_https(blocked)
    # A genuine public https URL passes untouched.
    ok = "https://www.cisa.gov/sites/default/files/csaf/provider-metadata.json"
    assert bootstrap._require_public_https(ok) == ok


# --- ReDoS: the fix-text scan is bounded, not quadratic on hostile prose ---

def test_fix_text_scan_is_bounded():
    """A crafted remediation details of a long 'a a a ...' run with no fix-noun
    drove FIX_IN_TEXT into quadratic backtracking and could stall the whole
    single-pass build. The scan window is capped, so time is flat in input size."""
    from retrust import csaf
    pathological = "released " + ("a " * 100_000) + "!"
    start = time.perf_counter()
    assert csaf._names_a_shipped_fix(pathological) is False
    assert time.perf_counter() - start < 1.0          # was tens of seconds / hours

    # The cap must not cost a real match: a fix named early still reads as one.
    assert csaf._names_a_shipped_fix("Update to the latest version.") is True


# --- version: a poisoned range is refused, never crashes a later score/eval ---

def test_oversized_version_component_is_unparseable_not_a_crash():
    """int() caps string conversion at 4,300 digits (3.11+); a version_range with
    a huge digit run would otherwise raise mid-score on a poisoned corpus. It is
    treated as unparseable -- which keeps the range in scope, never assumed safe."""
    from retrust import version
    assert version.parse_version("1." + "9" * 5000) is None
    # affects() degrades to a clean answer rather than raising.
    assert version.affects(">=" + "1" * 5000, "9.9") is None
    # A normal version is unaffected by the guard.
    assert version.parse_version("V4.5.1 Update 3") is not None


# --- ingestion: a string known_affected does not iterate into char product ids ---

def test_known_affected_string_does_not_become_character_ids():
    """known_affected as a bare string once produced one-character product ids in
    the affected table. _list refuses anything but a list, so junk ids cannot be
    inserted from a malformed advisory."""
    from retrust import csaf
    assert csaf._list("PID-STRING") == []
    assert csaf._list({"a": 1}) == []
    assert csaf._list(["p1", "p2"]) == ["p1", "p2"]


# --- ingestion: a deeply nested product tree stops at an explicit ceiling ---

def test_product_tree_walk_has_a_depth_ceiling():
    """A pathologically nested product_tree would recurse to RecursionError. The
    walk stops at an explicit depth instead, so the defence is deliberate rather
    than an incidental crash that happens to be caught upstream."""
    from retrust import csaf
    node = {"branches": []}
    deep = node
    for _ in range(5000):
        child = {"category": "vendor", "name": "x", "branches": []}
        node["branches"] = [child]
        node = child
    # Completes without raising; nothing past the ceiling is yielded.
    assert list(csaf._walk(deep["branches"])) == []


# --- KEV: a wrong-shaped catalogue fails as a clean error, not AttributeError ---

def test_malformed_kev_is_a_clean_error(tmp_path):
    """A KEV file that is a bare list (truncated or hostile) must raise a
    ValueError the setup path already handles, not an AttributeError from .get on
    a list that would escape and crash the build."""
    from retrust import index
    connection = index.connect(":memory:")       # connect() builds the schema
    bad = tmp_path / "kev.json"
    bad.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError):
        index.load_exploitation(connection, kev_path=str(bad))


# --- snapshot: a decompression bomb is measured by real bytes, not its claim ---

def test_snapshot_bomb_is_caught_by_actual_bytes(tmp_path, monkeypatch):
    """The unpack ceiling must be enforced on bytes actually decompressed. An
    archive can declare a tiny uncompressed size and expand to gigabytes, so the
    pre-check on the header alone was not enough."""
    from retrust import snapshot
    monkeypatch.setattr(snapshot, "MAX_UNPACKED_BYTES", 1 << 20)   # 1 MB ceiling

    bomb = tmp_path / "snap.zip"
    payload = b"\x00" * (8 << 20)                                  # 8 MB of zeros
    manifest = {"format": snapshot.FORMAT_VERSION, "created": "2026-01-01",
                "note": "", "provenance": [],
                "files": {"retrust.db": {"sha256": "unused", "bytes": len(payload)}}}
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as archive:
        # A name a snapshot legitimately carries, so it passes the allow-list and
        # reaches extraction -- where the real-bytes cap must stop it.
        archive.writestr("retrust.db", payload)
        archive.writestr(snapshot.MANIFEST, json.dumps(manifest))

    with pytest.raises(SystemExit):
        snapshot.restore(str(bomb), data_dir=str(tmp_path / "out"), verify=False)
