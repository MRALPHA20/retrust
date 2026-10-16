"""Regression cases for reliable procurement decisions and safe rebuilds."""
import copy
import json

import pytest

from retrust import bootstrap, config, csaf, index, match, score
from test_pipeline import ADVISORY


def corpus(tmp_path, document=None, name='csaf'):
    root = tmp_path / name
    root.mkdir(parents=True)
    (root / 'a.json').write_text(json.dumps(document or ADVISORY))
    return root


def test_a_fix_for_one_variant_does_not_clear_another_variants_gate(tmp_path):
    document = copy.deepcopy(ADVISORY)
    document['vulnerabilities'] = [{
        'cve': 'CVE-2026-0001', 'product_status': {'known_affected': ['P1', 'P2']},
        'scores': [{'cvss_v3': {'baseScore': 9.8}}],
        'remediations': [{'category': 'vendor_fix', 'product_ids': ['P1']},
                         {'category': 'none_available', 'product_ids': ['P2']}],
    }]
    connection, _ = index.build(tmp_path / 't.db', corpus(tmp_path, document))
    with connection:
        connection.execute("INSERT INTO exploitation(cve, epss) VALUES('CVE-2026-0001', .9)")
    resolved = match.resolve(connection, vendor='Testco', product='TestPLC 9000')
    fixed = match.findings(connection, resolved, version='1.0')
    unfixed = match.findings(connection, resolved, version='2.5')
    family = match.findings(connection, resolved)
    assert fixed[0].remediation == 'vendor_fix'
    assert not score.check_gates(fixed, 'Testco')
    assert unfixed[0].remediation == 'none_available'
    assert score.check_gates(unfixed, 'Testco')[0]['gate'] == 'Critical vulnerability with no available fix'
    assert family[0].remediation == 'none_available'
    connection.close()


def test_remediation_groups_and_unscoped_advice():
    vulnerability = {'cve': 'CVE-2026-0001',
                     'product_status': {'known_affected': ['A', 'B', 'C']},
                     'remediations': [{'category': 'workaround'},
                                      {'category': 'vendor_fix', 'group_ids': ['fixed']}]}
    parsed = csaf._vulnerability(vulnerability, [{'group_id': 'fixed', 'product_ids': ['A', 'C']}])
    assert parsed['remediation_by_product'] == {'A': 'vendor_fix', 'B': 'workaround', 'C': 'vendor_fix'}
    vulnerability['remediations'] = [{'category': 'vendor_fix', 'group_ids': ['missing']}]
    assert set(csaf._vulnerability(vulnerability)['remediation_by_product'].values()) == {'unknown'}


def test_missing_setup_feeds_preserve_the_previous_index(tmp_path):
    root = corpus(tmp_path, name='CSAF/csaf_files/OT')
    path = tmp_path / 't.db'
    connection, _ = index.build(path, root)
    with connection:
        connection.execute("INSERT INTO exploitation(cve, in_kev) VALUES('CVE-2026-0001', 1)")
    connection.close()
    before = path.read_bytes()
    with pytest.raises(bootstrap.StepFailed, match='preserved'):
        bootstrap.build_index(tmp_path, path)
    assert path.read_bytes() == before


@pytest.mark.parametrize('failure', ['missing_root', 'empty_root', 'bad_feed', 'interrupted'])
def test_failed_rebuild_never_replaces_a_working_index(tmp_path, monkeypatch, failure):
    root = corpus(tmp_path)
    path = tmp_path / 't.db'
    connection, _ = index.build(path, root)
    connection.close()
    before = path.read_bytes()
    kwargs = {}
    if failure == 'missing_root':
        root = tmp_path / 'missing'
    elif failure == 'empty_root':
        root = tmp_path / 'empty'
        root.mkdir()
    elif failure == 'bad_feed':
        feed = tmp_path / 'kev.json'
        feed.write_text('broken JSON')
        kwargs['kev_path'] = feed
    else:
        def interrupted(*args):
            raise RuntimeError('interrupted')
        monkeypatch.setattr(index, '_ingest_root', interrupted)
    with pytest.raises((ValueError, RuntimeError)):
        index.build(path, root, **kwargs)
    assert path.read_bytes() == before
    assert not list(tmp_path.glob('.retrust-build-*'))


def test_later_advisory_replaces_all_previous_children(tmp_path):
    first = corpus(tmp_path, name='first')
    revised = copy.deepcopy(ADVISORY)
    revised['vulnerabilities'] = [revised['vulnerabilities'][1]]
    revised['vulnerabilities'][0]['product_status']['known_affected'] = ['P2']
    revised['product_tree']['branches'][0]['branches'][0]['name'] = 'Replacement PLC'
    revised['product_tree']['branches'][0]['branches'][0]['branches'] = [
        revised['product_tree']['branches'][0]['branches'][0]['branches'][1]]
    second = corpus(tmp_path, revised, name='second')
    connection, counts = index.build(tmp_path / 't.db', [first, first, second])
    assert counts['advisories'] == 1
    assert counts['products'] == 1
    assert connection.execute('SELECT COUNT(*) FROM product').fetchone()[0] == 1
    assert connection.execute("SELECT COUNT(*) FROM affected WHERE cve='CVE-2026-0001'").fetchone()[0] == 0
    assert not connection.execute('SELECT * FROM order_number').fetchall()
    connection.close()


def test_disabling_one_pillar_keeps_other_defaults(tmp_path):
    path = tmp_path / 'config.json'
    path.write_text(json.dumps({'weights': {'exposure': 0}}))
    weights, _, _ = config.load(path)
    assert weights == {**score.DEFAULT_WEIGHTS, 'exposure': 0}
    # Empty findings no longer score: absence of evidence is excluded,
    # not read as safety. The config mechanics still round-trip.
    assert score.assess('Example', [], weights=weights).verdict == 'NOT ASSESSED'


@pytest.mark.parametrize('document', [[], {'weights': {'exposure': 'nan'}},
                                     {'weights': {'patchability': 'inf'}},
                                     {'bands': {'prefer': 'nan'}}])
def test_invalid_configuration_is_refused_cleanly(tmp_path, document):
    path = tmp_path / 'config.json'
    path.write_text(json.dumps(document))
    with pytest.raises(SystemExit):
        config.load(path)
