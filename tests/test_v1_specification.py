"""End-to-end guarantees from the owner's ReTrust-OT V1 specification."""
from dataclasses import replace
import csv
import io
import math
import pytest
from retrust import batch, console, exposure, match, report, score, sensitivity

VECTOR = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
COMPLETE = dict(network_exposure='ot_only', interface='exposed',
                consequence='control', remediation='affected')


def flaw(**overrides):
    values = dict(cve='CVE-2026-0001', advisory_id='A', cvss=9.8,
                  cwe='CWE-787', epss=.12, lev=.6, in_kev=False,
                  ransomware=False, version_range='<2.0', decided=True,
                  remediation='vendor_fix', vector=VECTOR)
    values.update(overrides)
    return match.Finding(**values)


def test_documented_single_path_example_is_exact():
    f = flaw()
    result = exposure.analyse([f], network='ot_only', interface='exposed', consequence='control')
    assert exposure.threat(f) == .6
    assert result.paths[0]['z_min'] == pytest.approx(.48)
    assert result.paths[0]['z_max'] == pytest.approx(.48)
    assert result.safety_min == result.safety_max == pytest.approx(52)
    assert not result.provisional


@pytest.mark.parametrize('values,expected', [([],100),([.48],52),([.48,.20],48),
                                            ([.48,.20,.10],47),([1],0),([1,1,1],0)])
def test_corrected_concentration_examples(values, expected):
    assert 100 * (1-exposure.concentrate(values)) == pytest.approx(expected)


def test_final_weighted_product_matches_the_formula():
    pillars = {'exposure':47, 'patchability':70, 'vendor_practice':80, 'certification':60}
    terms = [(spec, score.Pillar(spec.name, pillars[spec.key], 1)) for spec in score.PILLARS]
    expected = 47**.6 * 70**.2 * 80**.15 * 60**.05
    assert score._composite(terms, score.DEFAULT_WEIGHTS) == pytest.approx(expected)


@pytest.mark.parametrize('field', ['interface', 'consequence', 'remediation'])
def test_missing_critical_input_creates_a_range_and_verify(field):
    f = flaw(decided=False)
    inputs = dict(COMPLETE)
    inputs[field] = None if field == 'consequence' else 'unknown'
    result = score.assess('PLC', [f], **inputs)
    assert result.verdict == 'VERIFY' and result.provisional
    assert result.score_min < result.score_max
    assert result.exposure_min == pytest.approx(40 if field == 'consequence' else 52)
    assert result.exposure_max == 100


def test_unknown_firmware_example_and_export_bounds():
    f = flaw(decided=False)
    inputs = dict(COMPLETE, remediation='unknown')
    result = score.assess('PLC', [f], **inputs)
    assert result.paths[0]['inputs'][0]['factors']['U'] == [0,1]
    assert result.paths[0]['z_min'] == 0
    assert result.paths[0]['z_max'] == pytest.approx(.48)
    resolution = match.Resolution(query='PLC')
    record = batch.to_detail(result, resolution, [f])
    assert record['verdict'] == 'VERIFY'
    assert record['exposure_min'] == pytest.approx(52)
    assert record['exposure_max'] == 100
    assert record['paths'][0]['inputs'][0]['factors']['U'] == [0,1]
    csv_record = next(csv.DictReader(io.StringIO(batch.dumps_csv([batch.to_record(result, resolution)]))))
    assert csv_record['provisional'] == 'True'
    assert float(csv_record['score_max']) > float(csv_record['score_min'])
    assert csv_record['verification']
    assert batch.exit_code([record], 'unassessed') == 2
    assert 'provisional range' in console.candidates([record])
    markup = report._assessment_block(result)
    assert 'What to check next' in markup and 'Provisional range' in markup


def test_a_firewall_does_not_patch_firmware():
    f = flaw(decided=False)
    assert exposure.applicability_bounds(f, remediation='mitigated').values() == [0,1]
    assert exposure.reach_bounds(f, interface='blocked').values() == [0,0]
    assert exposure.applicability_bounds(f, remediation='applied').values() == [0,0]
    assert exposure.applicability_bounds(f, remediation='not_affected').values() == [0,0]
    assert exposure.applicability_bounds(f, remediation='available').values() == [1,1]


def test_duplicate_advisories_do_not_invent_three_paths():
    f = flaw()
    one = exposure.analyse([f], network='ot_only', interface='exposed', consequence='control')
    three = exposure.analyse([f, replace(f, advisory_id='B'), replace(f, advisory_id='C')],
                             network='ot_only', interface='exposed', consequence='control')
    assert len(three.paths) == 1
    assert three.safety_min == one.safety_min == pytest.approx(52)
    assert three.paths[0]['advisories'] == ['A','B','C']


def test_reviewed_shared_path_and_rationale_are_retained():
    review = dict(consequence='control', interface='exposed', remediation='affected',
                  rationale='Logic writes can interrupt the process', evidence='Site review 2026-10-20')
    first = flaw(path_id='logic-write', review=review, source_dates={'FIRST EPSS':'2026-10-20'})
    second = replace(first, cve='CVE-2026-0002', lev=.2)
    result = exposure.analyse([first, second], network='ot_only')
    assert len(result.paths) == 1
    assert result.safety_min == pytest.approx(52)
    assert result.paths[0]['inputs'][0]['review'] == review
    assert result.paths[0]['inputs'][0]['source_dates'] == {'FIRST EPSS':'2026-10-20'}


@pytest.mark.parametrize('vector', ['CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
                                    'CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'])
def test_local_and_physical_paths_need_actual_access(vector):
    f = flaw(vector=vector)
    assert exposure.reach_bounds(f).values() == [0,1]
    assert exposure.reach_bounds(f, 'exposed', prerequisites='satisfiable').values() == [1,1]


def test_missing_threat_sources_are_labelled_not_zero():
    f = flaw(epss=None, lev=None, kev_available=False)
    result = exposure.analyse([f], network='ot_only', interface='exposed', consequence='control')
    assert result.paths[0]['inputs'][0]['epss'] is None
    assert result.paths[0]['inputs'][0]['factors']['T'] == [0,1]
    assert result.provisional and any('Exploitation data' in item for item in result.missing)


def test_gate_overrides_unknown_inputs():
    f = flaw(in_kev=True, remediation='none_available')
    result = score.assess('PLC', [f])
    assert result.verdict == 'AVOID' and result.gates
    assert result.provisional


def test_complete_input_can_receive_a_numeric_verdict():
    result = score.assess('PLC', [flaw()], **COMPLETE)
    assert not result.provisional
    assert result.score_min == result.score_max
    assert result.verdict in {'PREFER','CONDITIONAL','AVOID'}
    assert result.vector.startswith('RT4/')


def test_uncertainty_cannot_look_like_stable_approval():
    result = sensitivity.stability([flaw()], samples=20)
    assert result.samples == 0 and not result.robust
    assert result.dominant == 'VERIFY'


@pytest.mark.parametrize('value', [-.1,1.1,float('nan'),float('inf')])
def test_out_of_range_contributions_are_refused(value):
    with pytest.raises(ValueError):
        exposure.concentrate([value])


def test_invalid_threat_estimate_is_refused():
    with pytest.raises(ValueError):
        exposure.threat(flaw(epss=math.inf))


def test_comparison_sensitivity_keeps_each_candidates_site_context():
    from retrust import serve
    f = flaw()
    def assess(vendor, product, version=None, order_number=None, **context):
        result = score.assess(product, [f], {'A'}, **context)
        result.inputs = ([f], {'A'}, (), ())
        return result, match.Resolution(query=product), [f]
    values = dict(vendor='Testco', product='PLC', version='', order_number='', **COMPLETE)
    row = [values.get(field, '') for field in serve.COMPARISON_FIELDS]
    result = serve._comparison_results(assess, {'bands':score.BANDS}, [row])[0]
    assert result[0][0].verdict != 'VERIFY'
    assert result[2].samples == 300 and result[2].dominant != 'VERIFY'
