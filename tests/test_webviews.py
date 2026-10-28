"""Browser explanations must distinguish estimates, confirmations and missing data."""

from retrust import dossier, lev, report, score, ssvc, timeline, webviews
from retrust.match import Finding


def _estimate(cve, probability, observations=58, confirmed=False):
    return lev.Estimate(cve, probability, .07, '2022-02-08', '2026-10-01',
                        observations, in_kev=confirmed, current_epss=.06)


def test_historical_estimates_are_percentages_and_never_confirmed_counts():
    result = webviews.exploitation('PLC', [
        _estimate('CVE-2013-0663', .741), _estimate('CVE-2013-0664', .705)])
    overview = result.partition('<details>')[0]
    assert '74.1%' in overview and '70.5%' in overview
    assert overview.count('Not listed by CISA') == 2
    assert '1.4' not in overview
    assert 'statistical expected count' in result and '<strong>1.4</strong>' in result
    assert 'do not show that your equipment or organisation was attacked' in overview


def test_missing_history_remains_unestimated_even_for_a_confirmed_record():
    result = webviews.exploitation('PLC', [_estimate('CVE-2026-0001', 0, 0, True)])
    overview = result.partition('<details>')[0]
    assert 'Not estimated' in overview
    assert 'Confirmed by CISA' in overview
    assert '0.0%' not in overview


def test_missing_kev_is_not_presented_as_a_negative_check():
    result = webviews.exploitation('PLC', [_estimate('CVE-2026-0001', .4)], kev_loaded=False)
    overview = result.partition('<details>')[0]
    assert 'Not checked' in overview
    assert 'Not listed by CISA' not in overview
    assert 'Public confirmation has not been checked' in overview


def test_browser_evidence_and_technical_report_escape_external_strings():
    result = webviews.exploitation('<script>alert(1)</script>', [_estimate('<img src=x>', .741)])
    assert '<script>' not in result and '<img src=x>' not in result
    assert '&lt;script&gt;' in result and '&lt;img src=x&gt;' in result


def test_response_priority_keeps_urgent_outcomes_visible():
    decisions = [ssvc.Decision('CVE-2026-0001', 'active', 'immediate', True, .4, 9.8),
                 ssvc.Decision('CVE-2026-0002', 'none', 'scheduled', False, None, None)]
    result = webviews.response_priority('PLC', decisions, 'open', 'yes', 'high')
    overview = result.partition('<details>')[0]
    assert 'Act now' in overview and 'Plan a routine fix' in overview
    assert 'Confirmed by CISA' in overview and 'Not listed by CISA' in overview
    assert 'Public exploit code is not checked' in overview
    assert 'Access assumed' in overview and 'Open access' in overview
    assert 'Operational impact assumed' in overview and 'High impact' in overview


def test_supplier_questions_keep_asks_visible_and_sources_escaped():
    from retrust import questions
    result = webviews.supplier_questions('<PLC>', [questions.Question(
        text='Confirm <firmware>', why='Because <evidence> is missing', evidence=['<CVE>'])])
    overview = result.partition('<details>')[0]
    assert 'Confirm &lt;firmware&gt;' in overview
    assert 'Because' not in overview
    assert 'Because &lt;evidence&gt; is missing' in result
    assert '&lt;CVE&gt;' in result and '<CVE>' not in result
    assert 'PSIRT' in result and 'manufacturer’s team' in result


def test_vendor_missing_checks_stay_incomplete_and_matches_stay_visible():
    missing = dossier.Dossier('Vendor', 'vendor')
    result = webviews.vendor_profile(missing).partition('<details>')[0]
    assert 'restrictions were not checked' in result
    assert 'Certification records were not checked' in result
    blocked = dossier.Dossier('Vendor', 'vendor', screening_gates=[
        {'gate': 'Restriction', 'detail': 'Match on list X', 'source': 'source X'}],
        sanctions_checked=False, certificates=[])
    result = webviews.vendor_profile(blocked).partition('<details>')[0]
    assert 'review before purchase' in result and 'Match on list X' in result
    assert 'Supplier checks are incomplete' in result
    assert 'No supplier restriction match was found' not in result


def test_timeline_discloses_missing_dates_and_dataset_reference_date():
    history = timeline.Timeline(years=[timeline.YearBucket(2025, 2, 3, 9.8, 1)],
                                advisories=3, cves=4, undated=1, missing=2,
                                first='2025-01-01', last='2025-06-01', as_of='2025-10-01')
    result = webviews.advisory_history('PLC', history).partition('<details>')[0]
    assert '1 notice with no date' in result
    assert 'Missing from this dataset: 2 referenced notices' in result
    assert '2025-10-01' in result
    assert 'does not mean the fix is installed' in result


def test_assessment_table_displays_probabilities_as_percentages():
    finding = Finding('CVE-2026-0001', 'A', 7.5, None, .039, False,
                      False, '<2', True, 'vendor_fix')
    rendered = report._cve_table([finding])
    assert '3.9%' in rendered and '>0.039<' not in rendered
    assert 'No record shown' in rendered
    assessment = score.assess('PLC', [finding], {'A'})
    table = report._pillar_table(assessment, score.DEFAULT_WEIGHTS)
    assert 'Influence' in table and '%' in table


def test_small_positive_probabilities_are_not_rounded_to_zero():
    assert webviews._percent(.00003) == 'Under 0.1%'
    assert report._probability(.00003) == 'Under 0.1%'
    assert webviews._percent(0) == '0.0%'
    assert report._probability(None) == 'Not available'


def test_estimates_do_not_round_high_probabilities_to_certainty():
    for display in (report._probability, webviews._percent):
        assert display(.99999) == 'Over 99.9%'
        assert display(1) == '100.0%'


def test_verdict_keeps_supplier_verification_and_score_scope_visible():
    assessment = score.Assessment('PLC', 'PREFER', 81.9, confidence=1,
                                  first_party_count=1, third_party_count=476,
                                  cautions=[{'caution': 'Bundle review', 'detail': 'Check reachability',
                                             'source': 'Vendor'}])
    result = report._assessment_block(assessment, tools='<details>Save this assessment</details>')
    verdict = result.partition('</div>')[0]
    assert 'Supplier verification required before purchase' in verdict
    assert '100%' not in verdict
    assert '476 additional vulnerabilities in bundled software' in result
    assert result.index('What this score covers') < result.index('Save this assessment')
    assert 'Evidence completeness for scored findings: <b>100%</b>' in result
    assert 'it does not confirm the applicability or safety of bundled software' in result


# --- the findings table, rendered rather than called directly ----------------
#
# Mutation-tested gap: report.py had 98.9% line coverage and FOUR mutations
# survived -- the disclosure could be deleted, the cap silently dropped from 10
# to 3, the ranking inverted so the LEAST significant findings showed, and the
# table emptied entirely. Every one passed 947 tests, because the only test
# touching the table called the private _cve_table directly and never exercised
# the wiring in _findings_section. These tests render the real section.

def _many(count):
    """A finding set larger than the table cap, with a clear significance order."""
    return [Finding(cve=f"CVE-2026-{i:04d}", advisory_id="A", cvss=4.0 + i * 0.2,
                    cwe="CWE-125", epss=i / 100.0, in_kev=False, ransomware=False,
                    version_range="", decided=True, remediation="none_available",
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
            for i in range(1, count + 1)]


def _section(findings):
    """Render through the public renderer, so the wiring is exercised too."""
    from retrust.match import Resolution
    assessment = score.assess("Example", findings, {"A"})
    resolution = Resolution(query="x", abstained=False, reason="")
    return report.body([(assessment, resolution, findings)])


def test_a_capped_findings_table_discloses_the_cap():
    html = _section(_many(25))
    assert "most significant of 25 findings" in html
    assert "records how many were left out" in html


def test_an_uncapped_findings_table_makes_no_claim_about_a_cap():
    html = _section(_many(4))
    assert "most significant of" not in html


def _reviewed(html):
    """The CVEs inside the capped "Vulnerabilities to review" table only.

    The page also renders an uncapped per-vulnerability contributions table,
    so a whole-page search cannot tell the capped table from the full one.
    """
    import re
    start = html.index("<h3>Vulnerabilities to review</h3>")
    end = html.find("</table>", start)
    return set(re.findall(r"CVE-\d{4}-\d{4,}", html[start:end]))


def test_the_table_shows_the_worst_findings_not_the_mildest():
    """Inverting the ranking silently showed the least significant findings."""
    shown = _reviewed(_section(_many(25)))
    assert "CVE-2026-0025" in shown, "the highest-EPSS finding must be shown"
    assert "CVE-2026-0001" not in shown, "the lowest-EPSS finding must not be"


def test_the_table_is_not_empty_and_shows_exactly_the_cap():
    shown = _reviewed(_section(_many(25)))
    assert len(shown) == 10, f"expected the 10-row cap, rendered {len(shown)}"
    # the ten worst, nothing else
    assert shown == {f"CVE-2026-{i:04d}" for i in range(16, 26)}


def test_assessment_only_collapses_the_four_additional_rows():
    from html.parser import HTMLParser
    class DisclosureParser(HTMLParser):
        def __init__(self):
            super().__init__(); self.stack = []; self.visible = []; self.extra = []; self.attrs = None; self.td = False; self.visible_rows = []; self.extra_rows = []
        def handle_starttag(self, tag, attrs):
            if tag == 'td': self.td = True
            if tag == 'details':
                attrs = dict(attrs)
                is_more = attrs.get('class') == 'assessment-more-info'
                self.stack.append(is_more)
                if is_more: self.attrs = attrs
        def handle_endtag(self, tag):
            if tag == 'td': self.td = False
            if tag == 'details': self.stack.pop()
        def handle_data(self, data):
            (self.extra if any(self.stack) else self.visible).append(data)
            if self.td: (self.extra_rows if any(self.stack) else self.visible_rows).append(data.strip())
    finding = Finding('CVE-2026-0001', 'A', 7.5, None, .039, False,
                      False, '<2', True, 'vendor_fix')
    assessment = score.assess('PLC', [finding], {'A'})
    assessment.notes.append('A retained assessment note')
    parser = DisclosureParser()
    parser.feed(report._assessment_block(assessment, findings=[finding], weights=score.DEFAULT_WEIGHTS))
    visible, extra = ' '.join(parser.visible), ' '.join(parser.extra)
    assert parser.attrs is not None and 'open' not in parser.attrs
    # The four main pillars are the meters in the score card (not table rows
    # any more): visible outside the disclosure, absent from it.
    for label in ('Exposure safety', 'Available fixes', 'Vendor security practices', 'Certification evidence'):
        assert label in visible and label not in extra
    for label in ('Attack activity', 'Issue severity', 'Network access', 'Evidence completeness'):
        assert label in parser.extra_rows and label not in parser.visible_rows
    assert 'Influence is the weight' in extra
    assert 'A retained assessment note' in visible and 'Vulnerabilities to review' in visible
    assert 'Show more info' in extra
