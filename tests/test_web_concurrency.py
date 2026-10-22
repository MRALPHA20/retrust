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
        assert len(owners) == 4


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
    entered, release, queued = threading.Event(), threading.Event(), threading.Event()
    def assess(connection, *args, **kwargs):
        entered.set()
        assert release.wait(5)
        return cli._assess(connection, *args, **kwargs)
    with running(application, assess, workers=1) as (server, base):
        original = server.process_request
        accepted = []
        def accept(request, address):
            original(request, address)
            accepted.append(address)
            if len(accepted) == 2: queued.set()
        server.process_request = accept
        with ThreadPoolExecutor(max_workers=2) as clients:
            first = clients.submit(fetch, base, query())
            assert entered.wait(2)
            second = clients.submit(fetch, base, '/healthz')
            try:
                assert queued.wait(2)
                with pytest.raises(urllib.error.HTTPError) as error:
                    fetch(base, '/healthz', timeout=1)
                assert error.value.code == 503
                assert error.value.headers['Retry-After'] == '2'
            finally: release.set()
            assert first.result(timeout=5)[0] == second.result(timeout=5)[0] == 200
            assert fetch(base, '/healthz')[0] == 200


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
