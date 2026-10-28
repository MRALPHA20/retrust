"""The assess page: export menu, new exports, evidence parameters, ids."""
from script_policy import without_enhancement
import html
import re
import urllib.parse

import pytest

from retrust import evidenceview, report, serve
from test_serve import _get, db, handler, scoring_handler  # noqa: F401  (fixtures)

PAGE = '/score?vendor=Testco&product=TestPLC+9000&interface=exposed&consequence=minor'


def _ids(body):
    return re.findall(r'\bid="([^"]+)"', body)


def test_export_menu_lists_four_formats_and_is_the_only_primary_button(scoring_handler):
    _, _, body = _get(scoring_handler, PAGE)
    assert body.count('class="rt-btn rt-btn--primary') == 1
    assert 'popovertarget="export-menu"' in body
    for path in ('/export.html?', '/export.json?', '/export.csv?', '/export.vex.json?'):
        assert f'href="{path}' in body
    assert re.search(r'href="(/export.json[^" ]+)"', body)


def test_add_to_comparison_is_the_first_compare_link(scoring_handler):
    _, _, body = _get(scoring_handler, PAGE)
    first = body.index('href="/compare?')
    assert 'Add to comparison' in body[first:first + 600]


def test_empty_page_has_one_primary_button_and_no_script(handler):
    _, _, body = _get(handler, '/score')
    assert body.count('class="rt-btn rt-btn--primary') == 1
    assert 'Assess product' in body and '<script' not in without_enhancement(body).lower()
    assert 'href="/score?vendor=Siemens' in body


def test_result_page_has_no_script_and_unique_ids(scoring_handler):
    _, _, body = _get(scoring_handler, PAGE)
    assert '<script' not in without_enhancement(body).lower()
    ids = _ids(body)
    assert len(ids) == len(set(ids))


def test_gap_and_tab_fragments_point_at_ids_on_the_page(scoring_handler):
    _, _, body = _get(scoring_handler, PAGE)
    ids = set(_ids(body))
    targets = re.findall(r'href="#([^"]+)"', body)
    assert targets
    for target in targets:
        assert target in ids, target
    for section in ('overview', 'exposure', 'evidence', 'questions', 'inputs'):
        assert section in ids


def test_drawer_count_equals_shown_rows(scoring_handler):
    _, _, body = _get(scoring_handler, PAGE)
    table = body[body.index('id="evidence-table"'):]
    table = table[:table.index('</table>')]
    rows = table.count('<tr>') - 1
    assert rows and body.count('<div class="ev-drawer" id="') == rows


@pytest.mark.parametrize('query', [
    'ev=%3Cscript%3E&sort=%3Cb%3E&dir=up&show=%22%3E',
    'ev=nope&sort=nope&dir=nope&show=nope',
])
def test_invalid_evidence_parameters_are_ignored_not_echoed(scoring_handler, query):
    status, _, body = _get(scoring_handler, PAGE + '&' + query)
    assert status == 200
    assert '<script' not in without_enhancement(body).lower()
    assert 'nope' not in body and '&lt;script' not in body


def test_filter_and_sort_links_carry_answers_and_never_was(scoring_handler):
    from test_serve import _update, START
    page = _update(scoring_handler, START, dict(START, interface='exposed'))
    assert 'name="was_interface"' in page
    links = [html.unescape(h) for h in re.findall(r'href="(\?[^"]*#evidence)"', page)]
    assert links
    for link in links:
        assert 'was' not in link and 'interface=exposed' in link
    state = _get(scoring_handler, PAGE + '&sort=cvss&dir=asc')[2]
    assert 'aria-sort="ascending"' in state


def test_the_edit_panel_text_rule():
    source = open(serve.__file__, encoding='utf-8').read()
    assert 'Edit product details' not in source
    assert serve.EDIT_PANEL in source


def test_open_questions_alias_is_the_report_table():
    assert serve.OPEN_QUESTIONS is report.GAP_RULES


def test_update_effects_are_an_update_card_with_a_live_region(scoring_handler):
    from test_serve import _update, START
    page = _update(scoring_handler, START, dict(START, network_exposure='internet_ot'))
    assert 'aria-live="polite"' in page
    assert '>UPDATE</p>' in page


def test_update_button_is_secondary(scoring_handler):
    _, _, body = _get(scoring_handler, PAGE)
    assert re.search(r'rt-btn--secondary" type="submit"[^>]*><span class="rt-btn__label">Update assessment', body)


def test_csv_export_headers_and_formula_neutralisation(handler):
    status, headers, body = _get(handler, '/export.csv?vendor=%3DHYPERLINK%28%22x%22%29&product=P')
    assert status == 200
    assert headers['Content-Type'].startswith('text/csv')
    assert 'retrust-assessment.csv' in headers['Content-Disposition']
    assert 'Content-Security-Policy' in headers and headers['Cache-Control'] == 'no-store'
    assert not any(cell.startswith('=') for cell in re.split(r'[,\n]', body))


def test_csv_without_identity_is_an_error_page(handler):
    from urllib.error import HTTPError
    with pytest.raises(HTTPError) as caught:
        _get(handler, '/export.csv')
    assert caught.value.code == 400


def test_vex_for_an_unresolved_product_is_an_error_page_not_a_download(handler):
    from urllib.error import HTTPError
    with pytest.raises(HTTPError) as caught:
        _get(handler, '/export.vex.json?vendor=Nope&product=Nothing')
    assert caught.value.code == 404
    assert 'Content-Disposition' not in caught.value.headers


def test_vex_download_for_a_known_product(scoring_handler):
    status, headers, body = _get(scoring_handler, '/export.vex.json?vendor=Testco&product=TestPLC+9000')
    assert status == 200
    assert 'retrust-assessment.vex.json' in headers['Content-Disposition']
    assert '"bomFormat": "CycloneDX"' in body


def test_vex_row_is_disabled_with_a_reason_when_unresolved(handler):
    _, _, body = _get(handler, '/score?vendor=Nope&product=Nothing')
    assert 'Needs an identified product.' in body
    assert 'href="/export.vex.json' not in body


ANSWERED = ('/score?vendor=Testco&product=TestPLC+9000&version=1.0&network_exposure=internet_ot'
            '&interface=exposed&consequence=safety&remediation=available&prerequisites=satisfiable')


def _panel_questions(body):
    return [''.join(html.unescape(t).split()) for t in re.findall(r'<p class="rt-q__text">(.*?)</p>', body)]


def _file_questions(text):
    """The numbered asks of format_report, unwrapped (whitespace dropped: the
    80-column wrap can break after a hyphen)."""
    chunks = re.split(r'\n(?= ?\d+\. )', '\n' + text)[1:]
    out = []
    for chunk in chunks:
        ask = chunk.split('\n    why:')[0]
        out.append(''.join(re.sub(r'^ ?\d+\. ', '', ask).split()))
    return out


@pytest.mark.parametrize('path', [ANSWERED, PAGE])
def test_export_txt_equals_the_questions_panel_and_downloads(scoring_handler, path):
    _, _, body = _get(scoring_handler, path)
    href = html.unescape(re.search(r'href="(/annex\.txt\?[^"]+)"', body).group(1))
    query = urllib.parse.parse_qs(urllib.parse.urlparse(href).query)
    assert query['download'] == ['1']
    # Every answer the page was asked with travels in the link.
    asked = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
    for key, value in asked.items():
        assert query[key] == value, key
    status, headers, text = _get(scoring_handler, href)
    assert status == 200
    assert headers['Content-Disposition'].startswith('attachment; filename="retrust-rfq-annex-')
    panel = _panel_questions(body)
    assert panel and _file_questions(text) == panel



def test_has_statements_agrees_with_statements(db):
    from retrust import match, vex
    for fields in (dict(vendor='Testco', product='TestPLC 9000'),
                   dict(vendor='Testco', product='No Such Box'),
                   dict(vendor='Nobody', product='Nothing')):
        resolution = match.resolve(db, **fields)
        assert vex.has_statements(db, resolution) == bool(vex.statements(db, resolution)), fields


def test_profile_without_corpus_keeps_what_the_questions_read(db):
    from retrust import dossier
    full, lean = dossier.build(db, 'Testco'), dossier.build(db, 'Testco', corpus=False)
    assert lean.known and lean.spellings == full.spellings and lean.csaf_feed == full.csaf_feed
    assert full.advisories > 0 and lean.advisories == 0      # the corpus scan was skipped


def test_unanswered_unknown_select_is_drawn_by_the_component(scoring_handler):
    _, _, body = _get(scoring_handler, '/score?vendor=Testco&product=TestPLC+9000')
    assert re.search(r'<option value="" class="rt-option--unknown" selected>\? Unknown</option>', body)
    assert 'rt-field rt-field--select rt-field--unknown' in body
    answered = _get(scoring_handler, PAGE + '&network_exposure=it_ot')[2]
    assert '<option value="it_ot" selected' in answered


def test_serve_does_not_patch_component_markup_or_rebind_components():
    source = open(serve.__file__, encoding='utf-8').read()
    assert source.count('components = ') == 0 and source.count('import components') == 0
    assert '>CONTEXT</p>' not in source and 'import re\n' not in source
    assert 'card_html[:-' not in open(report.__file__, encoding='utf-8').read()
