"""Network context is a main input; verified paths determine reachability."""

from html.parser import HTMLParser
import pytest
from retrust import exposure, report, score, serve
from retrust.match import Finding

VECTOR = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'


def finding(**kwargs):
    values = dict(cve='CVE-2026-0001', advisory_id='A', cvss=7, cwe='CWE-125',
                  epss=.12, lev=.6, in_kev=False, ransomware=False,
                  version_range='<2.0', decided=True, remediation='vendor_fix', vector=VECTOR)
    values.update(kwargs)
    return Finding(**values)


def test_topology_is_not_a_fractional_discount():
    values = [score.assess('PLC', [finding()], network_exposure=network,
                          consequence='control', interface='exposed').score
              for network in score.NETWORK_EXPOSURES]
    assert len(set(values)) == 1
    assert 'network_exposure' not in score.DEFAULT_WEIGHTS


def test_unknown_context_requires_verification_even_with_resolved_factors():
    result = score.assess('PLC', [finding()], consequence='control', interface='exposed')
    assert result.verdict == 'VERIFY'
    assert any('Network context' in item for item in result.verification)


def test_only_confirmed_access_changes_a():
    f = finding()
    assert exposure.reach_bounds(f, 'unknown', 'isolated').values() == [0, 1]
    assert exposure.reach_bounds(f, 'exposed', 'isolated').values() == [1, 1]
    assert exposure.reach_bounds(f, 'blocked', 'internet_ot').values() == [0, 0]


def test_topology_alone_cannot_complete_an_assessment():
    for network in score.NETWORK_EXPOSURES:
        result = score.assess('PLC', [finding()], network_exposure=network)
        assert result.verdict == 'VERIFY'
        assert result.score_min < result.score_max


def test_network_exposure_rejects_unknown_values():
    with pytest.raises(ValueError, match='network exposure'):
        score.assess('PLC', [finding()], network_exposure='public')


class Fields(HTMLParser):
    def __init__(self):
        super().__init__()
        self.details = 0
        self.hidden_fields = []
        self.fields = []

    def handle_starttag(self, tag, attrs):
        if tag == 'details':
            self.details += 1
        if tag == 'select':
            name = dict(attrs).get('name')
            self.fields.append(name)
            if self.details:
                self.hidden_fields.append(name)

    def handle_endtag(self, tag):
        if tag == 'details':
            self.details -= 1


@pytest.mark.parametrize('network', list(score.NETWORK_EXPOSURES))
def test_network_and_reachability_are_main_form_inputs(network):
    form = serve._score_form('', '', '', network_exposure=network)
    fields = Fields()
    fields.feed(form)
    for name in ('network_exposure', 'interface', 'prerequisites'):
        assert name in fields.fields and name not in fields.hidden_fields
    assert f'value="{network}" selected' in form
    assert 'Operator-reported, not verified' in form


def test_report_does_not_claim_topology_is_a_numeric_input():
    result = score.assess('PLC', [finding()], network_exposure='it_ot')
    markup = report._pillar_table(result, score.DEFAULT_WEIGHTS)
    assert 'IT–OT' in markup and 'Context only' in markup
    assert report.FEEDS_EXPOSURE == {'Exploitation'}


def test_verified_block_narrows_the_range_without_changing_firmware_status():
    f = finding(decided=False)
    result = score.assess('PLC', [f], network_exposure='it_ot', interface='blocked')
    assert result.exposure_min == result.exposure_max == 100
    assert result.paths[0]['inputs'][0]['factors']['U'] == [0, 1]
    assert any('operator-reported' in note for note in result.notes)
