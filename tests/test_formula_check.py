"""The public V1 examples and deployment gate must detect numeric regressions."""
import pytest
from retrust import cli, exposure, formula_check, index


@pytest.mark.parametrize('values,expected', [([.48],52),([.48,.20],48),([.48,.20,.10],47),([1],0),([],100)])
def test_supplied_concentration_examples(values, expected):
    assert 100 * (1-exposure.concentrate(values)) == pytest.approx(expected)


@pytest.fixture
def formula_database(tmp_path):
    db = tmp_path / 'index.db'
    connection = index.connect(db)
    with connection:
        connection.execute('INSERT INTO advisory VALUES (?,?,?,?,?)',('A','Notice','2026-01-01','fixture',0))
        connection.execute('INSERT INTO product(advisory_id,product_id,vendor,vendor_key,name,name_key,version_range) VALUES (?,?,?,?,?,?,?)',
                           ('A','P','Testco','testco','PLC 100','plc100','<2.0'))
        connection.execute('INSERT INTO affected VALUES (?,?,?,?,?,?,?,?)',
                           ('A','P','CVE-2026-0001',7.5,'CWE-79','vendor_fix','CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',0))
        connection.execute('INSERT INTO exploitation VALUES (?,?,?,?,?)',('CVE-2026-0001',.12,0,0,None))
        connection.execute('INSERT INTO lev_estimate VALUES (?,?,?,?,?,?)',('CVE-2026-0001',.6,12,'2025-01-01','2026-01-01',.12))
    index.record_provenance(connection,'CISA KEV','fixture')
    connection.close()
    return db,tmp_path


def test_all_products_gate_checks_five_operating_scenarios(formula_database):
    db, data = formula_database
    result = formula_check.run(db, data)
    assert result['passed']
    assert result['counts']['products_checked'] == 1
    # Five scenarios plus the late firmware, which clears the <2.0 range.
    assert result['counts']['assessments_checked'] == 6
    assert result['counts']['cleared_firmware_assessments'] == 1
    assert result['failures'] == []


def test_all_products_gate_rejects_a_changed_score(formula_database, monkeypatch):
    db, data = formula_database
    original = cli._assess
    def broken(*args, **kwargs):
        a, resolution, findings = original(*args, **kwargs)
        a.score += 1
        return a, resolution, findings
    monkeypatch.setattr(cli, '_assess', broken)
    result = formula_check.run(db, data)
    assert not result['passed']
    assert result['counts']['failures'] == 1
    assert result['failures']


def test_report_explains_zero_reachability_and_applied_factor_values():
    from retrust import report, score
    from retrust.match import Finding
    f = Finding(cve='CVE-2026-0001', advisory_id='A', cvss=7.5, cwe='CWE-79',
                epss=.12, lev=.6, in_kev=False, ransomware=False,
                version_range='<2.0', decided=True, remediation='vendor_fix',
                vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
    a = score.assess('PLC', [f], network_exposure='internet_ot', interface='blocked',
                     prerequisites='satisfiable', consequence='safety', remediation='affected')
    text = report._calculation_summary(a)
    assert 'Applied scoring inputs' in text
    assert 'A = 0' in text and 'zero' in text
    assert 'Exposure safety E:' in text and '100.0/100' in text
    assert '1.00' in text  # H and U retained rather than reset by the form.


def test_impact_changes_score_when_a_path_exists():
    from retrust import score
    from retrust.match import Finding
    f = Finding(cve='CVE-2026-0001', advisory_id='A', cvss=7.5, cwe='CWE-79',
                epss=.12, lev=.6, in_kev=False, ransomware=False,
                version_range='<2.0', decided=True, remediation='vendor_fix',
                vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
    answers = dict(network_exposure='internet_ot', interface='exposed', prerequisites='satisfiable', remediation='affected')
    safety = score.assess('PLC', [f], consequence='safety', **answers)
    minor = score.assess('PLC', [f], consequence='minor', **answers)
    assert safety.score < minor.score
    # T = max(EPSS .12, LEV .6, wormable floor .5) = .6; I = 7.5 / 10.
    assert safety.exposure_min == pytest.approx(100 * (1 - .6 * .75 * 1.0))
    assert minor.exposure_min == pytest.approx(100 * (1 - .6 * .75 * .2))
