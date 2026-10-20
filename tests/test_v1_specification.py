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
                  remediation='vendor_fix', vector=VECTOR,
                  version_supplied=False)
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
    assert exposure.applicability_bounds(f, remediation='available').values() == [1,1]


def test_a_verified_fix_needs_a_named_firmware_and_no_contradiction():
    """The spec zeroes U for a SELECTED version verified patched or not affected.

    Three cases, and the middle one is the bug this pins. `decided` does NOT
    mean "a version was checked": match.findings drops every finding whose
    range EXCLUDES the supplied version, so a surviving decided finding is one
    the range check says IS affected. Gating the claim on it made the proof of
    affectedness the licence for believing the device was patched -- an
    internet-exposed, safety-critical, CVSS 10.0, confirmed-affected product
    read PREFER 99.2/100.
    """
    for claim in ('applied', 'not_affected'):
        # no firmware named: the claim is about nothing
        unnamed = flaw(version_supplied=False, decided=False)
        assert exposure.applicability_bounds(
            unnamed, remediation=claim).values() == [0, 1]
        # named, but our own range check says this firmware IS affected
        disputed = flaw(version_supplied=True, decided=True)
        assert exposure.applicability_bounds(
            disputed, remediation=claim).values() == [0, 1]
        # named, and nothing contradicts the claim
        named = flaw(version_supplied=True, decided=False)
        assert exposure.applicability_bounds(
            named, remediation=claim).values() == [0, 0]


def test_a_contradicted_fix_claim_says_so():
    """A claim the tool quietly declines to honour would be worse than none."""
    disputed = flaw(version_supplied=True, decided=True)
    result = exposure.analyse([disputed], network='ot_only', interface='exposed',
                              consequence='control', remediation='applied')
    assert result.provisional
    assert any('contradicts' in item for item in result.missing)


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


def test_a_certificate_alone_never_bands_a_verdict():
    """Zero advisory findings + one certificate must not read as PREFER.

    Found live: a product with no findings and a vendor IEC 62443 certificate
    rendered a confident, non-provisional PREFER 85.0 banded on the
    Certification pillar alone, on the same page as "absence is not proof of
    safety". Certification is assurance, not risk evidence; with nothing to
    weigh it against the product is NOT ASSESSED.
    """
    certs = [{"scheme": "IEC 62443-4-2", "matches_product": True}]
    a = score.assess('Ghost', [], certificates=certs)
    assert a.verdict == 'NOT ASSESSED' and a.score is None
    assert any('certificate' in n.lower() for n in a.notes)
    # and without the certificate, identical outcome
    bare = score.assess('Ghost', [])
    assert bare.verdict == 'NOT ASSESSED' and bare.score is None


def test_a_partially_reviewed_cve_still_forms_one_unit():
    """A path_id on SOME records of a CVE must not split it into two units.

    Grouping by "path_id or cve" alone let one flaw enter R twice as
    Z1 + 0.20*Z2 when a reviewer tagged only one of its advisory records.
    """
    a = flaw()
    b = replace(a, advisory_id='B')
    b.path_id = 'logic-write'
    result = exposure.analyse([a, b], network='ot_only', interface='exposed',
                              consequence='control')
    assert len(result.paths) == 1
    assert result.paths[0]['grouping'] == 'reviewed path'
    assert sorted(result.paths[0]['advisories']) == ['A', 'B']


@pytest.mark.parametrize('vector,resolves', [
    ('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', True),
    ('CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', True),
    ('CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', False),
    ('CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', False),
])
def test_a_reachable_service_settles_only_a_remote_flaw(vector, resolves):
    """Step A1: the flaw's own attack vector decides which question settles A.

    "The affected service is reachable" answers a NETWORK question. Before
    this, A ignored the attack vector entirely, so an AV:P flaw needing hands
    on the cabinet resolved to fully reachable on that answer alone, exactly
    like an unauthenticated remote one.
    """
    f = flaw(vector=vector)
    assert exposure.reach_bounds(f, 'exposed').values() == (
        [1, 1] if resolves else [0, 1])
    # An explicit affirmation of the requirements does cover local and
    # physical access, so it still settles any vector.
    assert exposure.reach_bounds(
        f, 'exposed', prerequisites='satisfiable').values() == [1, 1]
    # And a verified block is a block whatever the vector says.
    assert exposure.reach_bounds(f, 'blocked').values() == [0, 0]


# --- a declared answer that cannot apply --------------------------------------

_NEEDS_NOTHING = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
_NEEDS_A_LOGIN = 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'
_ANSWERED = dict(network_exposure='it_ot', interface='exposed',
                 prerequisites='unsatisfiable', consequence='control',
                 remediation='affected')


def test_ruling_out_conditions_cannot_rule_out_a_weakness_that_has_none():
    """A weakness needing nothing has no condition to be verified impossible.

    The arithmetic was always right -- such a flaw stays reachable -- but the
    report then listed "exploitation prerequisites: verified impossible" among
    the answers the verdict RESTED ON, which reads as though ruling the
    conditions out had supported a high-exposure result.
    """
    nothing = flaw(vector=_NEEDS_NOTHING)
    assert exposure.reach_bounds(
        nothing, interface='exposed', prerequisites='unsatisfiable').values() == [1, 1]
    a = score.assess('X', [nothing], {'A'}, **_ANSWERED)
    assert not any('prerequisite' in x for x in a.assertions), \
        'a vacuous answer must not be cited as a reason the verdict holds'
    assert any('need nothing extra' in n and 'changed nothing' in n for n in a.notes), \
        'and the buyer must be told their answer did not apply'


def test_the_same_answer_is_cited_when_it_really_did_apply():
    """Suppressing it everywhere would understate what the verdict rests on."""
    login = flaw(vector=_NEEDS_A_LOGIN)
    assert exposure.reach_bounds(
        login, interface='exposed', prerequisites='unsatisfiable').values() == [0, 0]
    a = score.assess('X', [login], {'A'}, **_ANSWERED)
    assert any('prerequisite' in x for x in a.assertions)
    assert not any('need nothing extra' in n for n in a.notes)


def test_a_partly_applicable_answer_is_cited_and_qualified():
    """Two findings, one conditioned: cite the answer, and say what it missed."""
    findings = [flaw(cve='CVE-2026-1000', vector=_NEEDS_NOTHING),
                flaw(cve='CVE-2026-1001', vector=_NEEDS_A_LOGIN)]
    a = score.assess('X', findings, {'A'}, **_ANSWERED)
    assert any('prerequisite' in x for x in a.assertions)
    note = next(n for n in a.notes if 'need nothing extra' in n)
    assert 'CVE-2026-1000' in note and 'changed nothing' not in note
