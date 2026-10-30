"""Tests for advisory integrity checking.

The two questions this answers are different, and the tests keep them apart. A
digest proves the file matches the manifest that shipped with it; only a
signature proves who wrote it. Reporting "not established" as "verified" would
be exactly the false assurance the module exists to avoid.
"""

import hashlib
import subprocess

import pytest

from retrust import integrity


@pytest.fixture
def advisory(tmp_path):
    path = tmp_path / "icsa-26-001-01.json"
    path.write_text('{"document": {"title": "T"}}')
    digest = hashlib.sha512(path.read_bytes()).hexdigest()
    (tmp_path / "icsa-26-001-01.json.sha512").write_text(f"{digest}  {path.name}\n")
    return path


# --- the digest ------------------------------------------------------------

def test_a_matching_digest_verifies(advisory):
    ok, detail = integrity.verify_hash(advisory)
    assert ok is True and detail == "matches"


def test_a_changed_file_fails(advisory):
    advisory.write_text('{"document": {"title": "tampered"}}')
    ok, detail = integrity.verify_hash(advisory)
    assert ok is False
    assert "expected" in detail and "got" in detail


def test_no_digest_is_not_a_failure(tmp_path):
    """Absent and wrong are different answers."""
    lonely = tmp_path / "x.json"
    lonely.write_text("{}")
    ok, detail = integrity.verify_hash(lonely)
    assert ok is None
    assert "no .sha512" in detail


def test_an_unreadable_digest_is_a_failure_not_a_pass(tmp_path):
    path = tmp_path / "y.json"
    path.write_text("{}")
    (tmp_path / "y.json.sha512").write_text("")
    ok, _ = integrity.verify_hash(path)
    assert ok is False


def test_the_digest_is_compared_case_insensitively(advisory):
    digest = hashlib.sha512(advisory.read_bytes()).hexdigest().upper()
    (advisory.parent / f"{advisory.name}.sha512").write_text(f"{digest}  x\n")
    assert integrity.verify_hash(advisory)[0] is True


# --- the signature ---------------------------------------------------------

def test_no_signature_is_not_established_rather_than_failed(advisory):
    signed, detail = integrity.verify_signature(advisory)
    assert signed is None
    assert "no .asc" in detail


def test_a_result_with_nothing_established_is_still_intact(advisory):
    """"We could not check" must never read as "we checked and it is bad"."""
    result = integrity.verify(advisory)
    assert result.hashed is True
    assert result.signed is None
    assert result.intact


def test_a_failed_digest_makes_it_not_intact(advisory):
    advisory.write_text("changed")
    assert not integrity.verify(advisory).intact


def test_signatures_can_be_skipped(advisory):
    result = integrity.verify(advisory, signatures=False)
    assert result.signed is None
    assert "not checked" in result.detail


# --- sweeping a directory --------------------------------------------------

def test_a_sweep_covers_every_advisory(tmp_path):
    for n in range(3):
        path = tmp_path / f"a{n}.json"
        path.write_text(f'{{"n": {n}}}')
        digest = hashlib.sha512(path.read_bytes()).hexdigest()
        (tmp_path / f"a{n}.json.sha512").write_text(f"{digest}  a{n}.json\n")
    results = integrity.sweep(tmp_path, signatures=False)
    assert len(results) == 3
    assert all(r.hashed for r in results)


def test_a_sweep_skips_feed_indexes(tmp_path):
    (tmp_path / "a.json").write_text("{}")
    (tmp_path / "feed.json").write_text("{}")
    assert len(integrity.sweep(tmp_path, signatures=False)) == 1


def test_a_limit_is_respected(tmp_path):
    for n in range(5):
        (tmp_path / f"a{n}.json").write_text("{}")
    assert len(integrity.sweep(tmp_path, limit=2, signatures=False)) == 2


# --- the report keeps the two questions apart ------------------------------

def _results(**kwargs):
    base = dict(path="/x/a.json", hashed=True, signed=None, detail="")
    return [integrity.Result(**{**base, **kwargs})]


def _flat(text):
    return " ".join(text.split())


def test_the_report_says_a_digest_cannot_prove_origin():
    text = _flat(integrity.format_report(_results()))
    assert "came from the same clone" in text
    assert "only the signature can do that" in text


def test_a_single_signer_is_reported_as_expected():
    keys = {"144AED0A57BE7D4AE835D9D8CAC5AC4F74164B17": 400}
    text = _flat(integrity.format_report(_results(), keys=keys))
    assert "144A ED0A" in text                      # spaced for reading
    assert "expected shape" in text
    assert "confirm that fingerprint" in text


def test_more_than_one_signer_is_flagged():
    keys = {"A" * 40: 300, "B" * 40: 4}
    text = _flat(integrity.format_report(_results(), keys=keys))
    assert "More than one key signed" in text
    assert "partially substituted mirror" in text


def test_the_report_says_how_to_get_the_key():
    """And that it will refuse one whose fingerprint does not match."""
    text = _flat(integrity.format_report(_results(signed=None)))
    assert "--fetch-key" in text
    assert "refuses it unless the fingerprint matches" in text
    assert "--key FILE" in text


def test_key_discovery_uses_the_publisher_not_a_keyserver():
    """CSAF says the publisher advertises its keys; that is the better source."""
    assert "provider-metadata.json" in integrity.CISA_PROVIDER_METADATA


def test_a_failure_tells_you_not_to_score_on_it():
    text = _flat(integrity.format_report(_results(hashed=False, detail="bad")))
    assert "should not be scored on" in text


def test_an_empty_sweep_explains_itself():
    assert "No advisories found" in integrity.format_report([])


def test_key_material_is_never_fetched_over_http():
    """A key fetched over a rewritable channel proves nothing."""
    import pytest

    with pytest.raises(RuntimeError, match="https"):
        integrity._fetch_key_material("http://www.cisa.gov/key.asc", timeout=5)


# --- the gpg verdict tree ----------------------------------------------------
#
# Mutation-tested gap: flipping BADSIG to "signed by a key you hold" passed all
# 947 tests. The whole verdict tree was executed during the suite and never
# inspected, and scripts/smoke.sh only greps for the string "signed by:", which that
# mutation preserves. For a tool whose pitch is provenance, a forged signature
# reading as valid is the worst thing the suite could miss.

class _Gpg:
    """Stand in for the gpg process, returning one canned --status-fd block."""

    def __init__(self, status):
        self.status = status

    def __call__(self, command, **kwargs):
        assert command[0] == "gpg" and "--verify" in command
        return subprocess.CompletedProcess(command, 0, stdout=self.status, stderr="")


@pytest.fixture
def signed(tmp_path):
    advisory = tmp_path / "icsa-26-000-01.json"
    advisory.write_text("{}", encoding="utf-8")
    (tmp_path / "icsa-26-000-01.json.asc").write_text(
        "-----BEGIN PGP SIGNATURE-----\n", encoding="utf-8")
    return advisory


@pytest.mark.parametrize("status,verdict", [
    ("[GNUPG:] GOODSIG ABC Signer <x@y>\n[GNUPG:] VALIDSIG ABC\n", True),
    ("[GNUPG:] VALIDSIG ABC\n", True),
    # A bad signature is a FAILURE, never an absence and never a pass.
    ("[GNUPG:] BADSIG ABC Signer <x@y>\n", False),
    ("[GNUPG:] EXPKEYSIG ABC Signer <x@y>\n", False),
    # Not holding the key is the absence of an answer, not a failure.
    ("[GNUPG:] NO_PUBKEY ABC\n", None),
    ("", None),
])
def test_each_gpg_verdict_maps_to_the_right_answer(monkeypatch, signed, status, verdict):
    monkeypatch.setattr(integrity, "have_gpg", lambda: True)
    monkeypatch.setattr(integrity.subprocess, "run", _Gpg(status))
    assert integrity.verify_signature(signed)[0] is verdict


def test_a_bad_signature_is_never_reported_as_valid(monkeypatch, signed):
    """The exact mutation the suite used to miss."""
    monkeypatch.setattr(integrity, "have_gpg", lambda: True)
    monkeypatch.setattr(integrity.subprocess, "run",
                        _Gpg("[GNUPG:] BADSIG ABC Signer <x@y>\n"))
    ok, why = integrity.verify_signature(signed)
    assert ok is False
    assert "does not verify" in why
    assert "signed by a key you hold" not in why


def test_an_unsigned_or_gpg_less_file_abstains(monkeypatch, tmp_path):
    bare = tmp_path / "icsa-26-000-02.json"
    bare.write_text("{}", encoding="utf-8")
    assert integrity.verify_signature(bare) == (None, "no .asc beside it")
    (tmp_path / "icsa-26-000-02.json.asc").write_text("x", encoding="utf-8")
    monkeypatch.setattr(integrity, "have_gpg", lambda: False)
    assert integrity.verify_signature(bare)[0] is None


def test_gpg_failing_to_run_abstains_rather_than_passing(monkeypatch, signed):
    monkeypatch.setattr(integrity, "have_gpg", lambda: True)

    def explode(command, **kwargs):
        raise OSError("gpg vanished")

    monkeypatch.setattr(integrity.subprocess, "run", explode)
    ok, why = integrity.verify_signature(signed)
    assert ok is None and "could not be run" in why
