"""Bounded public-page sharing, failures, and identical aggregate semantics."""
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from retrust import index, lev, webcache


def test_waiting_readers_share_one_builder(monkeypatch):
    waiters_ready = threading.Event()
    waiter_lock = threading.Lock()
    waiters = []
    original = webcache.Future
    class ObservedFuture(original):
        def result(self, timeout=None):
            with waiter_lock:
                waiters.append(True)
                if len(waiters) == 7:
                    waiters_ready.set()
            return super().result(timeout)
    monkeypatch.setattr(webcache, 'Future', ObservedFuture)
    cache = webcache.PublicPages()
    entered, release = threading.Event(), threading.Event()
    calls = []
    def build():
        calls.append(True)
        entered.set()
        assert release.wait(5)
        return 'one public page'
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(cache.get, 'same key', build) for _ in range(8)]
        assert entered.wait(2)
        try:
            assert waiters_ready.wait(3), "all seven clients must wait for the same builder"
        finally:
            release.set()
        assert [f.result(timeout=5) for f in futures] == ['one public page'] * 8
    assert len(calls) == 1


def test_failed_build_is_not_kept_and_can_recover():
    cache = webcache.PublicPages()
    def fail(): raise ValueError('source unavailable')
    with pytest.raises(ValueError, match='source unavailable'): cache.get('k', fail)
    assert cache.get('k', lambda: 'recovered') == 'recovered'


def test_page_storage_is_bounded_by_encoded_bytes_and_entries():
    cache = webcache.PublicPages(max_entries=2, max_bytes=8)
    assert cache.get('a', lambda: 'éé') == 'éé'  # four UTF-8 bytes
    assert cache.get('b', lambda: 'bbbb') == 'bbbb'
    assert cache.get('c', lambda: 'cccc') == 'cccc'
    assert cache.get('a', lambda: 'new') == 'new'  # evicted, never stale
    assert len(cache._pages) <= 2 and cache._bytes <= 8
    assert cache.get('large', lambda: 'x' * 20) == 'x' * 20
    assert 'large' not in cache._pages
    assert cache.get('large', lambda: 'replacement') == 'replacement'


def test_history_aggregate_matches_reference_and_absence(tmp_path):
    connection = index.connect(tmp_path / 'data.db')
    assert index.lev_corpus_share(connection) is None
    rows = [('CVE-1', .0, 5, '', '', .1), ('CVE-2', .1, 13, '', '', .2),
            ('CVE-3', .7, 45, '', '', .7)]
    with connection: connection.executemany('INSERT INTO lev_estimate VALUES (?,?,?,?,?,?)', rows)
    assert index.lev_corpus_share(connection) == lev.baseline(index.lev_estimates(connection))['share']
    assert index.lev_corpus_share(connection, .7) == pytest.approx(1/3)
    connection.close()
