"""Real concurrent HTTP clients, independent SQLite readers and bounded overload."""
import json
import socket
import sqlite3
import threading
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

import pytest
from retrust import cli, dossier, index, serve, supplychain


@pytest.fixture
def application(tmp_path):
    path = tmp_path / 'index # requests.db'
    connection = index.connect(path)
    with connection:
        connection.execute('INSERT INTO advisory VALUES(?,?,?,?,?)', ('A', 'Notice', '2026-01-01', 'fixture', 0))
        connection.execute('INSERT INTO product(advisory_id,product_id,vendor,vendor_key,name,name_key,version_range) VALUES(?,?,?,?,?,?,?)',
                           ('A','P','Testco Electric','testco','PLC 9000','plc9000','<2.0'))
        connection.execute('INSERT INTO affected VALUES(?,?,?,?,?,?,?,?)',
                           ('A','P','CVE-2026-0001',7.5,'CWE-79','vendor_fix',
                            'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',0))
        connection.execute('INSERT INTO exploitation VALUES(?,?,?,?,?)', ('CVE-2026-0001',.2,0,0,None))
        connection.execute('INSERT INTO lev_estimate VALUES(?,?,?,?,?,?)', ('CVE-2026-0001',.3,10,'2026-01-01','2026-02-01',.2))
    index.record_provenance(connection,'CISA KEV','Fixture data')
    context = cli._context(str(tmp_path))
    len(context['screening'])
    len(context['certificates'])
    stats, provenance = index.stats(connection), index.provenance(connection)
    connection.close()
    context['screening'].close()
    return path, context, stats, provenance


@contextmanager
def running(application, assessor=cli._assess, workers=4):
    path, context, stats, provenance = application
    handler = serve.build_concurrent_handler(path, assessor, context, dossier, stats, provenance, '127.0.0.1', 0)
    server = serve.serve(handler, '127.0.0.1', 0, forever=False, workers=workers)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, f'http://127.0.0.1:{server.server_port}'
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def fetch(base, path, timeout=5):
    with urllib.request.urlopen(base + path, timeout=timeout) as response:
        return response.status, dict(response.headers), response.read().decode()


def query(**answers):
    values = dict(vendor='Testco Electric', product='PLC 9000', network_exposure='it_ot',
                  interface='exposed', prerequisites='satisfiable', consequence='control', remediation='affected')
    values.update(answers)
    return '/export.json?' + urllib.parse.urlencode(values)


def test_eight_clients_keep_their_own_answers_and_readers(application):
    barrier = threading.Barrier(4)
    owners = set()
    lock = threading.Lock()
    def assess(connection, *args, **kwargs):
        with lock: owners.add(threading.get_ident())
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("DELETE FROM product")
        barrier.wait(timeout=5)
        return cli._assess(connection, *args, **kwargs)
    with running(application, assess) as (server, base):
        with ThreadPoolExecutor(max_workers=4) as clients:
            futures = [clients.submit(fetch, base, query(interface='blocked' if i % 2 else 'exposed',
                       assessment_type='installed' if i % 2 else 'purchase')) for i in range(8)]
            for i, future in enumerate(futures):
                status, headers, body = future.result(timeout=10)
                assert status == 200 and headers['X-ReTrust-Workers'] == '4'
                result = json.loads(body)['results'][0]
                assert result['interface'] == ('blocked' if i % 2 else 'exposed')
                assert result['assessment_type'] == ('installed' if i % 2 else 'purchase')
                assert result['exposure_min'] == pytest.approx(100 if i % 2 else 76)
        assert len(owners) >= 4  # calculation slots may use the extra health-capable handler threads


def test_an_idle_client_and_a_slow_assessment_do_not_block_health(application):
    entered, release = threading.Event(), threading.Event()
    def assess(connection, *args, **kwargs):
        entered.set()
        assert release.wait(5)
        return cli._assess(connection, *args, **kwargs)
    with running(application, assess) as (server, base):
        idle = socket.create_connection(server.server_address, timeout=2)
        idle.sendall(b'GET /score HTTP/1.1\r\n')
        with ThreadPoolExecutor(max_workers=1) as client:
            slow = client.submit(fetch, base, query())
            try:
                assert entered.wait(2)
                assert fetch(base, '/healthz', timeout=1)[0] == 200
                assert not slow.done()
            finally:
                idle.close()
                release.set()
            assert slow.result(timeout=5)[0] == 200


def test_overload_is_explicit_and_recovers_without_a_restart(application):
    with running(application, workers=1) as (server, base):
        admitted = threading.Event()
        original = server.process_request
        accepted = []
        def accept(request, address):
            original(request, address)
            accepted.append(address)
            if len(accepted) == 2: admitted.set()
        server.process_request = accept
        idle = [socket.create_connection(server.server_address, timeout=2) for _ in range(2)]
        try:
            assert admitted.wait(2)
            with pytest.raises(urllib.error.HTTPError) as error:
                fetch(base, '/healthz', timeout=1)
            assert error.value.code == 503
            assert error.value.headers['Retry-After'] == '2'
        finally:
            for client in idle: client.close()
        # Wait for the bounded request slots to be returned before probing.
        assert server._slots.acquire(timeout=2)
        assert server._slots.acquire(timeout=2)
        server._slots.release()
        server._slots.release()
        assert fetch(base, '/healthz')[0] == 200


def test_all_calculation_workers_can_be_busy_without_blocking_health(application):
    entered, release = threading.Barrier(9), threading.Event()
    def assess(connection, *args, **kwargs):
        entered.wait(timeout=5)
        assert release.wait(5)
        return cli._assess(connection, *args, **kwargs)
    with running(application, assess, workers=8) as (_, base):
        with ThreadPoolExecutor(max_workers=8) as clients:
            futures = [clients.submit(fetch, base, query()) for _ in range(8)]
            try:
                entered.wait(timeout=5)
                assert fetch(base, '/healthz', timeout=1)[0] == 200
            finally:
                release.set()
            assert all(f.result(timeout=5)[0] == 200 for f in futures)


def test_calculation_overload_gives_retry_and_keeps_health_usable(application):
    entered, release = threading.Event(), threading.Event()
    def assess(connection, *args, **kwargs):
        entered.set()
        assert release.wait(5)
        return cli._assess(connection, *args, **kwargs)
    with running(application, assess, workers=1) as (server, base):
        with ThreadPoolExecutor(max_workers=1) as client:
            first = client.submit(fetch, base, query())
            try:
                assert entered.wait(2)
                with pytest.raises(urllib.error.HTTPError) as error:
                    fetch(base, query())
                assert error.value.code == 503
                assert error.value.headers['Retry-After'] == '2'
                error.value.close()
                # Headers can arrive before the rejected handler releases its
                # admission slot. Wait for cleanup before probing health while
                # the first calculation is still deliberately occupied.
                assert server._slots.acquire(timeout=1)
                server._slots.release()
                assert fetch(base, '/healthz', timeout=1)[0] == 200
            finally:
                release.set()
            assert first.result(timeout=5)[0] == 200


def test_request_fallback_does_not_write_a_screening_cache(application):
    path, context, stats, provenance = application
    cache = path.parent / supplychain.CACHE_NAME
    cache.unlink()
    with running(application) as (_, base):
        assert fetch(base, query())[0] == 200
    assert not cache.exists()


def test_readonly_connection_does_not_create_or_modify_files(tmp_path):
    missing = tmp_path / 'missing.db'
    with pytest.raises(sqlite3.OperationalError): index.connect_readonly(missing)
    assert not missing.exists()
    path = tmp_path / 'index # space.db'
    index.connect(path).close()
    connection = index.connect_readonly(path)
    try:
        assert connection.execute('PRAGMA query_only').fetchone()[0] == 1
        with pytest.raises(sqlite3.OperationalError): connection.execute('CREATE TABLE unexpected(x)')
    finally: connection.close()


def test_identical_alternatives_build_once_for_eight_http_clients(application, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    calls = []
    def alternatives_page(connection, assess, vendor, product, version, **kwargs):
        calls.append((vendor, product, version))
        entered.set()
        assert release.wait(5)
        return f'<html><h1>{vendor} {product} {version}</h1></html>'
    monkeypatch.setattr(serve, '_alternatives_page', alternatives_page)
    with running(application, workers=8) as (_, base):
        with ThreadPoolExecutor(max_workers=8) as clients:
            futures = [clients.submit(fetch, base, '/alternatives?vendor=Testco&product=PLC&version=1') for _ in range(8)]
            try:
                assert entered.wait(2)
            finally:
                release.set()
            for future in futures:
                assert future.result(timeout=5)[2] == '<html><h1>Testco PLC 1</h1></html>'
        assert calls == [('Testco', 'PLC', '1')]
        assert fetch(base, '/alternatives?vendor=Testco&product=PLC&version=2')[2].endswith('2</h1></html>')
        assert calls[-1] == ('Testco', 'PLC', '2')
        assert len(calls) == 2


def test_public_page_cache_changes_with_source_snapshot(application, monkeypatch):
    calls = []
    def page(connection, assess, vendor, product):
        calls.append(True)
        return f'<html><h1>build {len(calls)}</h1></html>'
    monkeypatch.setattr(serve, '_lev_page', page)
    with running(application) as (_, base):
        assert 'build 1' in fetch(base, '/lev?vendor=Testco&product=PLC')[2]
        assert 'build 1' in fetch(base, '/lev?vendor=Testco&product=PLC')[2]
        connection = index.connect(application[0])
        index.record_provenance(connection, 'CISA KEV', 'Changed source snapshot')
        connection.close()
        assert 'build 2' in fetch(base, '/lev?vendor=Testco&product=PLC')[2]
    assert len(calls) == 2


def test_deployment_formula_report_refuses_stale_fingerprints(application):
    from retrust import identity
    path, context, _, _ = application
    target = path.parent / 'formula-validation.json'
    with running(application) as (_, base):
        missing = json.loads(fetch(base, '/formula-check.json')[2])
        assert not missing['passed'] and not missing['available']
        connection = index.connect_readonly(path)
        fingerprint = identity.data_fingerprint(connection, context['data_dir'])
        connection.close()
        payload = dict(passed=True, source_build=serve.BUILD, data_fingerprint=fingerprint,
                       counts={'products_checked': 1, 'assessments_checked': 5}, failures=[])
        target.write_text(json.dumps(payload))
        current = json.loads(fetch(base, '/formula-check.json')[2])
        assert current['passed'] and current['current']
        target.write_text(json.dumps(dict(payload, data_fingerprint='stale')))
        stale = json.loads(fetch(base, '/formula-check.json')[2])
        assert not stale['passed'] and not stale['current']


def test_distinct_firmware_alternatives_share_only_public_candidates(application, monkeypatch):
    calls = []
    original = serve.alternatives.find
    def candidates(*args, **kwargs):
        calls.append(True)
        return original(*args, **kwargs)
    monkeypatch.setattr(serve.alternatives, 'find', candidates)
    with running(application, workers=8) as (_, base):
        with ThreadPoolExecutor(max_workers=8) as clients:
            futures = [clients.submit(fetch, base,
                       '/alternatives?vendor=Testco+Electric&product=PLC+9000&version=1.'+str(i))
                       for i in range(8)]
            for i, future in enumerate(futures):
                status, _, body = future.result(timeout=10)
                assert status == 200
                assert 'firmware 1.'+str(i) in body
        assert len(calls) == 1
