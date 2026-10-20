"""Independent regressions from the 20 October release audit."""
import csv
import io
import json
import socket
import ssl
import zipfile
from dataclasses import replace
from importlib.util import spec_from_file_location, module_from_spec
from pathlib import Path

import pytest
from retrust import bootstrap, batch, exposure, identity, index, match, score, snapshot, diff

VECTOR = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'


def flaw(**overrides):
    fields = dict(cve='CVE-2099-0001', advisory_id='AUDIT', cvss=9.8,
                  cwe='CWE-787', epss=.9, lev=.95, in_kev=True, ransomware=False,
                  version_range='<2.0', decided=True, remediation='vendor_fix',
                  vector=VECTOR, version_supplied=True)
    fields.update(overrides)
    return match.Finding(**fields)


@pytest.mark.parametrize('interface', ['exposed', 'blocked'])
@pytest.mark.parametrize('remedy', ['available', 'affected', 'planned', 'unknown', 'applied'])
def test_available_patch_never_clears_known_affected_kev(interface, remedy):
    a = score.assess('Synthetic PLC', [flaw()], version='1.0',
                     network_exposure='it_ot', interface=interface,
                     prerequisites='satisfiable', consequence='recoverable', remediation=remedy)
    assert a.verdict == 'AVOID'
    assert any(g['gate'] == 'Known exploited vulnerability' for g in a.gates)


def test_noncontradicted_selected_firmware_fix_can_resolve_kev():
    f = flaw(decided=False)
    assert not score.check_gates([f], remediation='applied')
    assert score.check_gates([replace(f, version_supplied=False)], remediation='applied')


@pytest.mark.parametrize('host', ['100.64.0.1', '100.127.255.254', '::ffff:100.64.0.1',
                                 '127.0.0.1', '10.0.0.1', '169.254.169.254', '224.0.0.1'])
def test_nonpublic_numeric_addresses_are_refused(host):
    urlhost = '[' + host + ']' if ':' in host else host
    with pytest.raises(bootstrap.StepFailed, match='non-public'):
        bootstrap._require_public_https('https://' + urlhost + '/fixture')


def test_dns_failures_are_closed(monkeypatch):
    def failure(*a, **k): raise socket.gaierror('synthetic DNS failure')
    monkeypatch.setattr(socket, 'getaddrinfo', failure)
    with pytest.raises(bootstrap.StepFailed, match='resolve'):
        bootstrap._require_public_https('https://audit.invalid/f')


def test_rebinding_cannot_reach_a_loopback_listener(tmp_path, monkeypatch):
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0)); listener.listen(); listener.settimeout(.15)
    port = listener.getsockname()[1]
    real = socket.getaddrinfo
    resolutions = []
    def resolve(host, port, *args, **kwargs):
        assert host == 'audit.invalid'
        address = '93.184.216.34' if not resolutions else '127.0.0.1'
        resolutions.append(address)
        return real(address, port, *args, **kwargs)
    monkeypatch.setattr(socket, 'getaddrinfo', resolve)
    try:
        with pytest.raises(bootstrap.StepFailed, match='non-public'):
            bootstrap._download(f'https://audit.invalid:{port}/fixture', tmp_path/'out')
        with pytest.raises(socket.timeout): listener.accept()
        assert resolutions == ['93.184.216.34', '127.0.0.1']
        assert not (tmp_path/'out').exists()
    finally: listener.close()


def test_transport_connects_to_the_vetted_sockaddr_and_keeps_tls_name(monkeypatch):
    calls = []
    def resolve(host, port, **kw):
        calls.append(('dns', host, port))
        assert len(calls) == 1, 'no second lookup may choose a different IP'
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('93.184.216.34', port))]
    class Sock:
        def settimeout(self, timeout): pass
        def setsockopt(self, *args): pass
        def connect(self, address): calls.append(('connect', address))
        def close(self): pass
    class Context:
        def wrap_socket(self, sock, server_hostname):
            calls.append(('tls', server_hostname)); return sock
    monkeypatch.setattr(socket, 'getaddrinfo', resolve)
    monkeypatch.setattr(socket, 'socket', lambda *a: Sock())
    connection = bootstrap._PinnedHTTPSConnection('audit.invalid', 8443, context=Context())
    connection.connect()
    assert calls == [('dns', 'audit.invalid', 8443), ('connect', ('93.184.216.34', 8443)), ('tls', 'audit.invalid')]
    assert bootstrap._PinnedHTTPSHandler()._context.verify_mode == ssl.CERT_REQUIRED
    assert bootstrap._PinnedHTTPSHandler()._context.check_hostname


@pytest.mark.parametrize('operation', ['inspect', 'restore'])
def test_manifest_is_bounded_before_json_parsing(tmp_path, monkeypatch, operation):
    monkeypatch.setattr(snapshot, 'MAX_MANIFEST_BYTES', 1024)
    path = tmp_path/'bad.zip'
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('manifest.json', json.dumps({'note':'x'*2048, 'files':{}}))
    def never_parse(*args): raise AssertionError('oversized manifest reached JSON parser')
    monkeypatch.setattr(snapshot.json, 'loads', never_parse)
    with pytest.raises(SystemExit, match='size limit'):
        getattr(snapshot, operation)(path)


def test_manifest_bytes_count_towards_total_budget(tmp_path, monkeypatch):
    import hashlib
    payload = b'x'*500
    doc = {'format':snapshot.FORMAT_VERSION, 'files':{'retrust.db':{'sha256':hashlib.sha256(payload).hexdigest()}}}
    packed = json.dumps(doc).encode()
    path = tmp_path/'archive.zip'
    with zipfile.ZipFile(path, 'w') as z:
        z.writestr('manifest.json', packed); z.writestr('retrust.db', payload)
    monkeypatch.setattr(snapshot, 'MAX_UNPACKED_BYTES', len(packed)+len(payload)-1)
    target = tmp_path/'restored'
    with pytest.raises(SystemExit, match='refusing'):
        snapshot.restore(path, target)
    assert not (target/'retrust.db').exists()


def test_conflicting_review_labels_are_refused_and_partial_labels_group_once():
    f = flaw(in_kev=False)
    with pytest.raises(ValueError, match='Conflicting reviewed attack-path'):
        exposure.analyse([replace(f,path_id='A'),replace(f,path_id='B')])
    result = exposure.analyse([replace(f,path_id='A'), f])
    assert len(result.paths) == 1


def test_missing_vector_is_never_described_as_needing_nothing():
    result = exposure.analyse([flaw(vector=None)], prerequisites='unsatisfiable')
    assert any('Attack requirements are unknown' in line for line in result.inapplicable)
    assert not any('weakness(es) need nothing extra' in line for line in result.inapplicable)
    assert result.paths[0]['inputs'][0]['factors']['A'] == [0,1]


def test_data_identity_changes_even_when_counts_stay_the_same(tmp_path):
    db = index.connect(':memory:')
    db.execute("INSERT INTO advisory(id,title) VALUES('A','first')")
    before = identity.data_fingerprint(db, tmp_path)
    db.execute("UPDATE advisory SET title='second' WHERE id='A'")
    after = identity.data_fingerprint(db, tmp_path)
    assert before != after
    (tmp_path/'screening.json').write_text('{}')
    assert identity.data_fingerprint(db, tmp_path) != after
    db.close()


def test_saved_records_keep_code_model_and_data_identity():
    a = score.assess('PLC', [flaw()], snapshot='d'*64)
    r = batch.to_record(a, match.Resolution(query='PLC'))
    assert r['model_version'] == 'RT5'
    assert r['source_build'] == identity.build_fingerprint()
    assert r['data_fingerprint'] == 'd'*64
    assert batch.envelope([r])['source_build'] == r['source_build']
    row = next(csv.DictReader(io.StringIO(batch.dumps_csv([r]))))
    assert row['source_build'] == r['source_build']
    old = dict(r, source_build='old', verdict='AVOID')
    text = diff.format_report(diff.compare([old], [r]))
    assert 'TOOL CODE CHANGED' in text


def test_benchmark_accepts_valid_verify_and_refuses_execution_errors(monkeypatch):
    import subprocess
    path = Path(__file__).parents[1]/'tools/benchmark_latency.py'
    spec = spec_from_file_location('benchmark_under_test', path)
    module = module_from_spec(spec); spec.loader.exec_module(module)
    monkeypatch.setattr(module.subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a, 2, 'VERIFY 40–80/100', ''))
    assert module.run_case(['python', '-m', 'retrust.cli', 'score']) == 2
    monkeypatch.setattr(module.subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a, 2, '', 'usage: invalid option'))
    with pytest.raises(RuntimeError): module.run_case(['python', 'score'])


def test_snapshot_create_refuses_an_unrestorable_manifest(tmp_path, monkeypatch):
    (tmp_path/'retrust.db').write_bytes(b'synthetic')
    monkeypatch.setattr(snapshot, 'MAX_MANIFEST_BYTES', 1024)
    destination = tmp_path/'snapshot.zip'
    with pytest.raises(SystemExit, match='Shorten'):
        snapshot.create(tmp_path, destination, note='x'*2048)
    assert not destination.exists()
