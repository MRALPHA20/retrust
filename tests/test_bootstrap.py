"""Tests for the one-command setup.

Nothing here touches the network. The downloads are stubbed, which is the point:
what needs testing is the sequencing and the failure handling, not urllib.
"""

import json

import pytest

from retrust import bootstrap


# --- the step sequence -----------------------------------------------------

def test_default_sequence_is_fetch_then_build_then_refresh():
    names = [name for name, _, _ in bootstrap.steps()]
    assert names == ["corpus", "kev", "epss", "index", "lists"]


def test_offline_fetches_nothing_but_still_builds():
    names = [name for name, _, _ in bootstrap.steps(offline=True)]
    assert names == ["index"]


def test_skip_refresh_drops_only_the_lists():
    names = [name for name, _, _ in bootstrap.steps(skip_refresh=True)]
    assert names == ["corpus", "kev", "epss", "index"]


# --- downloading -----------------------------------------------------------

class _Response:
    """Enough of urllib's response object to stand in for one."""

    def __init__(self, payload, url="https://example.invalid/f"):
        self.payload = payload
        self.url = url

    def read(self, size=-1):
        out, self.payload = self.payload, b""
        return out

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def test_download_writes_the_payload(tmp_path, monkeypatch):
    monkeypatch.setattr(bootstrap.urllib.request, "urlopen",
                        lambda *a, **k: _Response(b"hello"))
    destination = tmp_path / "out" / "f.json"
    assert bootstrap._download("https://example.invalid/f", destination) == 5
    assert destination.read_bytes() == b"hello"


def test_download_decompresses_gzip(tmp_path, monkeypatch):
    import gzip
    monkeypatch.setattr(bootstrap.urllib.request, "urlopen",
                        lambda *a, **k: _Response(gzip.compress(b"cve,epss\n")))
    destination = tmp_path / "epss.csv"
    bootstrap._download("https://example.invalid/g", destination, decompress=True)
    assert destination.read_text() == "cve,epss\n"


def test_a_download_that_lands_on_http_is_refused(tmp_path, monkeypatch):
    """urllib follows redirects across schemes; security data must not."""
    monkeypatch.setattr(bootstrap.urllib.request, "urlopen",
                        lambda *a, **k: _Response(b"x", url="http://mitm.example/f"))
    with pytest.raises(bootstrap.StepFailed, match="https"):
        bootstrap._download("https://example.invalid/f", tmp_path / "f.json")
    assert not (tmp_path / "f.json").exists()


def test_an_oversized_download_is_refused(tmp_path, monkeypatch):
    """A hostile mirror must not be handed the machine's memory and disk."""
    class _Endless:
        url = "https://example.invalid/f"
        def read(self, size=-1):
            return b"x" * (1 << 20)
        def __enter__(self):
            return self
        def __exit__(self, *_):
            return False

    monkeypatch.setattr(bootstrap.urllib.request, "urlopen",
                        lambda *a, **k: _Endless())
    with pytest.raises(bootstrap.StepFailed, match="Refusing"):
        bootstrap._download("https://example.invalid/f", tmp_path / "f.json")
    assert not (tmp_path / "f.json").exists()


def test_a_gzip_bomb_is_refused(tmp_path, monkeypatch):
    """A small .gz that expands past the cap stops at the cap."""
    import gzip
    bomb = gzip.compress(b"\0" * (bootstrap.MAX_FEED_BYTES + 2))
    monkeypatch.setattr(bootstrap.urllib.request, "urlopen",
                        lambda *a, **k: _Response(bomb))
    with pytest.raises(bootstrap.StepFailed, match="Refusing"):
        bootstrap._download("https://example.invalid/g", tmp_path / "g.csv",
                            decompress=True)


def test_a_failed_download_leaves_no_file_behind(tmp_path, monkeypatch):
    """The bug this guards: a truncated file that later runs skip as "present".

    Writing straight to the destination would leave a half-written feed on a
    dropped connection, and every subsequent setup would accept it -- so the
    index would be built on a partial KEV without anybody being told.
    """
    def explode(*_a, **_k):
        raise OSError("connection reset")

    monkeypatch.setattr(bootstrap.urllib.request, "urlopen", explode)
    destination = tmp_path / "kev.json"
    with pytest.raises(OSError):
        bootstrap._download("https://example.invalid/k", destination)
    assert not destination.exists()
    assert not list(tmp_path.glob("*.part"))


# --- steps that are already done -------------------------------------------

def test_a_present_feed_is_not_refetched(tmp_path, monkeypatch):
    (tmp_path / "kev.json").write_text(json.dumps({"vulnerabilities": []}))
    monkeypatch.setattr(bootstrap.urllib.request, "urlopen",
                        lambda *a, **k: pytest.fail("should not have fetched"))
    assert "already present" in bootstrap.fetch_feed(str(tmp_path), "kev")


def test_force_refetches_a_present_feed(tmp_path, monkeypatch):
    (tmp_path / "kev.json").write_text("stale")
    monkeypatch.setattr(bootstrap.urllib.request, "urlopen",
                        lambda *a, **k: _Response(b"fresh"))
    bootstrap.fetch_feed(str(tmp_path), "kev", force=True)
    assert (tmp_path / "kev.json").read_text() == "fresh"


def test_a_network_failure_is_reported_as_a_step_failure(tmp_path, monkeypatch):
    def explode(*_a, **_k):
        raise OSError("name resolution failed")

    monkeypatch.setattr(bootstrap.urllib.request, "urlopen", explode)
    with pytest.raises(bootstrap.StepFailed) as failure:
        bootstrap.fetch_feed(str(tmp_path), "kev")
    assert "KEV" in str(failure.value)


# --- refusing to finish on an incomplete index ------------------------------

def test_missing_feeds_stop_the_build(tmp_path):
    """An index without KEV cannot fire the exploitation gate.

    Building it anyway would score a product with a known exploited flaw as
    merely mediocre, which is the one failure this tool must not have.
    """
    advisories = bootstrap.corpus_dir(str(tmp_path))
    advisories.mkdir(parents=True)
    (advisories / "a.json").write_text(json.dumps({
        "document": {"title": "T", "tracking": {"id": "ICSA-1"}},
        "product_tree": {"branches": [{
            "category": "vendor", "name": "V", "branches": [{
                "category": "product_name", "name": "P",
                "branches": [{"category": "product_version", "name": "1.0",
                              "product": {"product_id": "P1", "name": "P"}}]}]}]},
        "vulnerabilities": [],
    }))
    with pytest.raises(bootstrap.StepFailed) as failure:
        bootstrap.build_index(str(tmp_path), str(tmp_path / "t.db"))
    assert "KEV" in str(failure.value) and "EPSS" in str(failure.value)


def test_offline_without_a_corpus_says_so(tmp_path):
    with pytest.raises(bootstrap.StepFailed) as failure:
        bootstrap.build_index(str(tmp_path), str(tmp_path / "t.db"))
    assert "no advisories" in str(failure.value)


# --- the run loop ----------------------------------------------------------

def test_run_stops_at_the_first_failure(tmp_path, monkeypatch):
    """Later steps depend on earlier ones, so pressing on would only confuse."""
    monkeypatch.setattr(bootstrap, "fetch_corpus",
                        lambda *a, **k: (_ for _ in ()).throw(
                            bootstrap.StepFailed("git is not installed")))
    reached = []
    monkeypatch.setattr(bootstrap, "fetch_feed",
                        lambda *a, **k: reached.append("kev") or "x")

    results = bootstrap.run(data_dir=str(tmp_path), db_path=str(tmp_path / "t.db"))
    assert results["corpus"]["ok"] is False
    assert "git is not installed" in results["corpus"]["detail"]
    assert reached == []                    # nothing after the failure ran
    assert "kev" not in results


def test_run_reports_progress_for_every_step(tmp_path, monkeypatch):
    monkeypatch.setattr(bootstrap, "build_index", lambda *a, **k: "1 advisory")
    lines = []
    results = bootstrap.run(data_dir=str(tmp_path), db_path=str(tmp_path / "t.db"),
                            offline=True, progress=lines.append)
    assert results["index"]["ok"] is True
    assert any("[1/1]" in line for line in lines)
    assert any("1 advisory" in line for line in lines)
