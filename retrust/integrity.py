"""Check that the advisories we scored on are the ones CISA published.

A tool that screens supply chains should be able to say where its own inputs
came from. CISA ships a SHA-512 and a detached PGP signature beside every
advisory in the CSAF repository -- 3,937 of each -- and until now ReTrust read
neither.

The two answer different questions, and conflating them would be the sort of
false assurance this tool exists to avoid:

    the hash    proves the file has not changed since the manifest was written.
                Both came from the same clone, so a substituted repository would
                carry a matching hash. This catches corruption and tampering
                after download, not a forged source.

    the signature  proves who wrote it, and is the only one of the two that
                survives a hostile mirror. It needs CISA's public key in your
                keyring; without it, all that can be said is that a signature is
                present, which is not the same as valid.

So a run reports them separately and never rolls them into one number.
"""

import hashlib
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

# Read in blocks: the corpus holds files of a few hundred kilobytes and one of
# 30 MB, and slurping every one whole to hash it is a waste of memory.
BLOCK = 1 << 16

# CSAF says a publisher advertises its signing keys in provider-metadata.json,
# so that is where the key is fetched from rather than a keyserver. CISA's
# metadata does not sit at the .well-known path the standard suggests; the URL
# below is the canonical_url it publishes, and the one the BSI CSAF aggregator
# points at.
CISA_PROVIDER_METADATA = (
    "https://www.cisa.gov/sites/default/files/csaf/provider-metadata.json")

# Kept as a fallback only. A keyserver is a weaker source than the publisher's
# own metadata, and neither is trusted on its own: whatever arrives has to match
# the fingerprint the signatures name.
KEYSERVER = "hkps://keys.openpgp.org"

_FINGERPRINT = re.compile(r"issuer fpr v4 ([0-9A-F]{40})")


@dataclass
class Result:
    """What could be established about one advisory file."""

    path: str
    hashed: bool | None = None       # None: no .sha512 shipped beside it
    signed: bool | None = None       # None: not checked, or no .asc
    detail: str = ""

    @property
    def intact(self):
        return self.hashed is not False and self.signed is not False


def have_gpg():
    return shutil.which("gpg") is not None


def verify_hash(path):
    """Compare a file against the .sha512 shipped beside it."""
    digest_file = Path(str(path) + ".sha512")
    if not digest_file.exists():
        return None, "no .sha512 beside it"
    try:
        expected = digest_file.read_text(encoding="utf-8").split()[0].strip().lower()
    except (OSError, IndexError):
        return False, "the .sha512 could not be read"

    digest = hashlib.sha512()
    try:
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(BLOCK), b""):
                digest.update(block)
    except OSError as error:
        return False, f"unreadable: {error}"
    actual = digest.hexdigest()
    return (actual == expected,
            "matches" if actual == expected else f"expected {expected[:16]}..., "
                                                 f"got {actual[:16]}...")


def verify_signature(path, keyring=None):
    """Verify the detached PGP signature, if gpg and the key are available.

    Returns (None, why) when the answer cannot be established, which covers both
    "no gpg installed" and "signature present but we hold no key for it". Those
    are not failures and must not be reported as such; they are the absence of
    an answer.
    """
    signature = Path(str(path) + ".asc")
    if not signature.exists():
        return None, "no .asc beside it"
    if not have_gpg():
        return None, "gpg is not installed, so the signer was not checked"

    command = ["gpg", "--batch", "--status-fd", "1", "--verify"]
    if keyring:
        command += ["--no-default-keyring", "--keyring", str(keyring)]
    command += [str(signature), str(path)]
    try:
        finished = subprocess.run(command, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as error:
        return None, f"gpg could not be run: {error}"

    status = finished.stdout
    if "GOODSIG" in status or "VALIDSIG" in status:
        return True, "signed by a key you hold"
    if "NO_PUBKEY" in status:
        # The honest answer. A present signature proves nothing on its own.
        return None, ("signature present but the signing key is not in your "
                      "keyring, so the signer was not established")
    if "BADSIG" in status or "EXPKEYSIG" in status:
        return False, "the signature does not verify"
    return None, "gpg gave no verdict"


def verify(path, keyring=None, signatures=True):
    """Both checks on one advisory."""
    hashed, hash_detail = verify_hash(path)
    signed, sign_detail = (verify_signature(path, keyring) if signatures
                           else (None, "not checked"))
    return Result(path=str(path), hashed=hashed, signed=signed,
                  detail=f"hash: {hash_detail}; signature: {sign_detail}")


def sweep(root, limit=None, signatures=True, keyring=None, progress=None):
    """Verify every advisory under `root`. Returns the results."""
    files = [p for p in sorted(Path(root).rglob("*.json")) if "feed" not in p.name]
    if limit:
        files = files[:int(limit)]
    results = []
    for number, path in enumerate(files, start=1):
        results.append(verify(path, keyring, signatures))
        if progress and number % 200 == 0:
            progress(number, len(files))
    return results


def signer(path):
    """The fingerprint of the key that signed one advisory, from its .asc."""
    signature = Path(str(path) + ".asc")
    if not signature.exists() or not have_gpg():
        return None
    try:
        listing = subprocess.run(["gpg", "--list-packets", str(signature)],
                                 capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    found = _FINGERPRINT.findall(listing)
    return found[0] if found else None


def signers(root, sample=400):
    """How many distinct keys signed this corpus, and which.

    One key across the whole set is the expected shape. More than one is worth
    a look: a subset signed by a different key is what a partially substituted
    mirror would produce.
    """
    signatures = sorted(Path(root).rglob("*.json.asc"))
    if not signatures:
        return {}
    step = max(1, len(signatures) // sample) if sample else 1
    found = {}
    for signature in signatures[::step]:
        if fingerprint := signer(str(signature)[:-4]):
            found[fingerprint] = found.get(fingerprint, 0) + 1
    return found


def import_key_file(keyring, path):
    """Import a key the user obtained themselves.

    The path that actually works today. CISA signs every advisory and publishes
    the key nowhere a verifier can fetch it, so somebody who has obtained it out
    of band needs a way to use it -- and out of band is the only way a key ever
    proves origin anyway.
    """
    if not have_gpg():
        raise RuntimeError("gpg is not installed, so a key cannot be imported")
    keyring = Path(keyring)
    keyring.parent.mkdir(parents=True, exist_ok=True)
    finished = subprocess.run(
        ["gpg", "--batch", "--no-default-keyring", "--keyring", str(keyring),
         "--import", str(path)], capture_output=True, text=True, timeout=60)
    if finished.returncode:
        keyring.unlink(missing_ok=True)
        raise RuntimeError((finished.stderr or finished.stdout).strip())
    return str(keyring)


def advertised_keys(url=CISA_PROVIDER_METADATA, timeout=60):
    """The signing keys a CSAF publisher advertises, per the standard.

    Returns [(fingerprint, url)]. This is the right place to look: the publisher
    says which keys are theirs, in a document served from their own domain.
    """
    import json
    import urllib.request
    with urllib.request.urlopen(url, timeout=timeout) as response:
        metadata = json.loads(response.read().decode("utf-8"))
    return [(str(k.get("fingerprint", "")).upper(), k.get("url", ""))
            for k in (metadata.get("public_openpgp_keys") or [])
            if k.get("url")]


def import_advertised_key(keyring, fingerprint, url=CISA_PROVIDER_METADATA,
                          timeout=60):
    """Fetch the publisher's advertised key, and refuse a fingerprint mismatch.

    Two things have to agree before anything is imported: the key the publisher
    advertises, and the key the signatures were actually made with. Accepting
    either alone would let whichever one an attacker controlled decide.
    """
    import urllib.request
    if not have_gpg():
        raise RuntimeError("gpg is not installed, so a key cannot be imported")

    advertised = advertised_keys(url, timeout)
    if not advertised:
        raise RuntimeError(f"{url} advertises no OpenPGP keys")
    matching = [u for f, u in advertised if f == fingerprint.upper()]
    if not matching:
        raise RuntimeError(
            f"{url} advertises {', '.join(f for f, _ in advertised)}, which does "
            f"not include {fingerprint}, the key these signatures were made "
            "with. Establish why before importing anything.")

    with urllib.request.urlopen(matching[0], timeout=timeout) as response:
        key = response.read()
    if b"BEGIN PGP PUBLIC KEY BLOCK" not in key:
        raise RuntimeError(f"{matching[0]} did not return a PGP public key")

    keyring = Path(keyring)
    keyring.parent.mkdir(parents=True, exist_ok=True)
    finished = subprocess.run(
        ["gpg", "--batch", "--no-default-keyring", "--keyring", str(keyring),
         "--import"], input=key, capture_output=True, timeout=60)
    if finished.returncode:
        keyring.unlink(missing_ok=True)
        raise RuntimeError(finished.stderr.decode("utf-8", "replace").strip())
    return _confirm_fingerprint(keyring, fingerprint, matching[0])


def _confirm_fingerprint(keyring, fingerprint, source):
    """The imported key must be the one asked for, or the keyring is discarded."""
    listed = subprocess.run(
        ["gpg", "--batch", "--no-default-keyring", "--keyring", str(keyring),
         "--fingerprint", "--with-colons"], capture_output=True, text=True,
        timeout=30).stdout
    if fingerprint.upper() not in listed.upper().replace(":", ""):
        Path(keyring).unlink(missing_ok=True)
        raise RuntimeError(
            f"{source} returned a key that is not {fingerprint}; the keyring "
            "has been discarded rather than used")
    return str(keyring)


def import_key(keyring, fingerprint, keyserver=KEYSERVER):
    """Fetch the key the signatures name, and refuse anything else.

    Asking a keyserver for a fingerprint and accepting whatever comes back would
    make the keyserver the authority. The imported key is checked against the
    fingerprint the corpus itself names, so the only trust added here is in that
    fingerprint -- which the caller is told to confirm out of band, because the
    corpus naming its own signer proves nothing by itself.

    The keyring is a file beside the data, not the user's own trust store:
    importing a publisher key into somebody's personal GnuPG is a larger thing
    than this asks for, and a file we own is trivially deleted.
    """
    if not have_gpg():
        raise RuntimeError("gpg is not installed, so a key cannot be imported")
    keyring = Path(keyring)
    keyring.parent.mkdir(parents=True, exist_ok=True)
    finished = subprocess.run(
        ["gpg", "--batch", "--no-default-keyring", "--keyring", str(keyring),
         "--keyserver", keyserver, "--recv-keys", fingerprint],
        capture_output=True, text=True, timeout=120)
    if finished.returncode:
        # An empty keybox left behind would make keyring.exists() true and
        # silence the hint that tells the next run how to fix this.
        keyring.unlink(missing_ok=True)
        raise RuntimeError((finished.stderr or finished.stdout).strip()
                           or f"{keyserver} returned no key for {fingerprint}")

    return _confirm_fingerprint(keyring, fingerprint, keyserver)


def format_report(results, root="", keyring_used=False, keys=None):
    """What `retrust verify` prints, with the two questions kept apart."""
    if not results:
        return ("No advisories found to verify. Point --csaf at the directory "
                "`retrust setup` cloned, usually data/CSAF/csaf_files/OT.")

    hashed_ok = sum(1 for r in results if r.hashed is True)
    hashed_bad = [r for r in results if r.hashed is False]
    hashed_none = sum(1 for r in results if r.hashed is None)
    signed_ok = sum(1 for r in results if r.signed is True)
    signed_bad = [r for r in results if r.signed is False]
    signed_none = sum(1 for r in results if r.signed is None)

    lines = [f"ADVISORY INTEGRITY   {len(results):,} files" +
             (f" under {root}" if root else ""), ""]
    lines += [
        "CONTENT   does each file still match the digest shipped beside it?",
        f"  verified                      {hashed_ok:>7,}",
        f"  failed                        {len(hashed_bad):>7,}",
        f"  no digest shipped             {hashed_none:>7,}",
        "",
        _wrap("A digest and the file it describes came from the same clone, so "
              "this catches corruption and tampering after download. It cannot "
              "tell you the repository itself was genuine; only the signature "
              "can do that."),
        "",
        "ORIGIN    who signed it?",
        f"  signature verified            {signed_ok:>7,}",
        f"  signature failed              {len(signed_bad):>7,}",
        f"  not established               {signed_none:>7,}",
        "",
    ]
    if keys:
        lines.append("  signed by:")
        for fingerprint, count in sorted(keys.items(), key=lambda kv: -kv[1]):
            spaced = " ".join(fingerprint[i:i + 4] for i in range(0, 40, 4))
            lines.append(f"    {spaced}   {count:,} sampled")
        if len(keys) > 1:
            lines += ["", _wrap(
                "More than one key signed this corpus. That is what a partially "
                "substituted mirror would look like, so establish why before "
                "scoring on it.")]
        else:
            lines += ["", _wrap(
                "One key signed everything sampled, which is the expected shape. "
                "The corpus naming its own signer proves nothing by itself: "
                "confirm that fingerprint against CISA out of band before "
                "treating it as evidence of origin.")]
        lines.append("")
    if signed_ok == 0 and signed_none and not keyring_used:
        lines += [_wrap(
            "The signing key is not in a keyring here, so nothing was "
            "established about the signer. Fetch it once with "
            "`retrust verify --fetch-key`, which reads the key CISA advertises "
            "in its CSAF provider metadata and refuses it unless the "
            "fingerprint matches the one these signatures were made with. "
            "`--key FILE` takes one you obtained yourself."), ""]

    for result in (hashed_bad + signed_bad)[:10]:
        lines.append(f"  FAILED  {Path(result.path).name}\n          {result.detail}")
    if hashed_bad or signed_bad:
        lines.append("")
        lines.append(_wrap(
            "A file that does not verify should not be scored on. Re-clone the "
            "corpus and run this again before trusting any result built from it."))
    return "\n".join(lines)


def _wrap(text, width=76):
    words, line, out = text.split(), "", []
    for word in words:
        if len(line) + len(word) + 1 > width:
            out.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    return "\n".join(out + [line])
