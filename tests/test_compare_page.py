"""The Control Room comparison page: transposed shortlist table, export
menu, confirmed clear, and the safety properties that go with them."""
from script_policy import without_enhancement
import html
import re
import urllib.parse
from types import SimpleNamespace

import pytest

from retrust import report, score, serve
from retrust.match import Resolution

from design_lint import css_lint


def resolved(vendor="Acme"):
    res = Resolution(query="x", method="exact_name", confidence=.9)
    res.matches = [type("M", (), {"vendor": vendor, "name": "PLC", "advisory_id": "A"})()]
    return res


def pillars(exposure=60.0, patch=70.0, vendor=50.0, cert=0.0, neutral=()):
    out = []
    for name, value in (("Exposure", exposure), ("Patch availability", patch),
                        ("Vendor practice", vendor), ("Certification", cert)):
        out.append(score.Pillar(name, value, 1.0, [], scored=name not in neutral))
    return out


def assessment(product, verdict="PREFER", value=80.0, gates=(), **kw):
    kw.setdefault("pillars", pillars())
    return score.Assessment(product, verdict, value, gates=list(gates), **kw)


def finding(fixed=False, kev=False):
    return SimpleNamespace(fixed=fixed, in_kev=kev)


def block(a, findings=()):
    return (a, resolved(), list(findings))


def table(blocks, **kw):
    return report.comparison_table(blocks, {}, **kw)


def cell_html(markup, label):
    """The <td> cells of the row whose label starts with `label`."""
    row = re.search(r'<tr class="rt-cmp__row[^"]*"><th scope="row" class="rt-cmp__label">'
                    + re.escape(label) + r'.*?</tr>', markup, re.S).group(0)
    return re.findall(r"<td[^>]*>.*?</td>", row, re.S)


@pytest.fixture
def two():
    return [block(assessment("Alpha", value=82), [finding(), finding(kev=True)]),
            block(assessment("Beta", "CONDITIONAL", 55,
                             pillars=pillars(exposure=40, patch=90)),
                  [finding(), finding(), finding()])]


# --- structure ---------------------------------------------------------------

def test_products_are_the_header_row_and_labels_are_row_headers(two):
    markup = table(two, queries=[{"order_number": "ORD-1"}, {"order_number": "ORD-2"}])
    head = re.search(r"<thead>.*?</thead>", markup, re.S).group(0)
    assert head.count('scope="col"') == 3            # corner + two products
    assert "Alpha" in head and "Beta" in head
    assert "ORD-1" in head and "ORD-2" in head
    body = re.search(r"<tbody>.*?</tbody>", markup, re.S).group(0)
    labels = re.findall(r'<th scope="row" class="rt-cmp__label">(.*?)</th>', body, re.S)
    text = [re.sub(r"<[^>]+>", "", label) for label in labels]
    assert text[0] == "Verdict" and text[1] == "Score"
    for wanted in ("Blockers", "Open gaps", "Unpatched CVEs", "In CISA KEV",
                   "Verdict stability", "Main reason"):
        assert wanted in text
    assert sum(1 for t in text if re.match(r"^[EPVC] ", t)) == 4
    assert 'class="rt-cmp__corner"' in head          # sticky corner above the label column


def test_the_scroll_region_is_inside_a_card_and_keeps_its_label(two):
    markup = table(two)
    assert markup.startswith('<section class="rt-card rt-cmp-card"')
    assert 'class="tw" tabindex="0" role="region"' in markup
    assert "scroll horizontally for more columns" in markup


def test_ranked_order_is_kept(two):
    head = re.search(r"<thead>.*?</thead>", table(list(reversed(two))), re.S).group(0)
    assert head.index("Beta") < head.index("Alpha")     # the caller ranks; the table never re-sorts


def test_verdict_row_uses_small_badges_and_provisional_range():
    v = assessment("Gamma", "VERIFY", 41.3, provisional=True, score_min=41.3,
                   score_max=78.2, exposure_min=20, exposure_max=80)
    cells = cell_html(table([block(v), block(assessment("Alpha"))]), "Verdict")
    assert "rt-badge--s" in cells[0] and "VERIFY" in cells[0] and "41" in cells[0]
    assert "PREFER" in cells[1]


def test_neutral_substituted_pillars_use_the_dashed_violet_bar():
    a = assessment("Neutral", pillars=pillars(cert=0, neutral=("Certification",)))
    cells = cell_html(table([block(a), block(assessment("Alpha"))]), '<span class="rt-cmp__key">C')
    assert "50*" in cells[0] and "rt-cmp__bar--neutral" in cells[0]
    assert "rt-cmp__bar--neutral" not in cells[1]


def test_counts_come_from_gates_and_findings():
    a = assessment("Gated", "AVOID", None, gates=[{"gate": "Sanctioned supplier"}])
    b = assessment("Open", findings_count=3)
    markup = table([block(a), block(b, [finding(), finding(fixed=True), finding(kev=True)])])
    assert [re.sub(r"<[^>]+>", "", c) for c in cell_html(markup, "Blockers")] == ["1", "0"]
    # Unpatched: a scoreless gated candidate has no measured count; the other has two.
    assert [html.unescape(re.sub(r"<[^>]+>", "", c)) for c in cell_html(markup, "Unpatched")] == ["—", "2"]
    assert [html.unescape(re.sub(r"<[^>]+>", "", c)) for c in cell_html(markup, "In CISA")] == ["—", "1"]


def test_gated_candidates_carry_a_coral_square_and_a_struck_score():
    a = assessment("Gated", "AVOID", 90, gates=[{"gate": "Exploited and unpatched"}])
    markup = table([block(a), block(assessment("Alpha", value=70))])
    head = re.search(r"<thead>.*?</thead>", markup, re.S).group(0)
    assert head.count("rt-cmp__gate") == 1
    assert head.index("rt-cmp__gate") < head.index("Gated")
    assert "■" in head
    assert "rt-cmp__score--struck" in cell_html(markup, "Score")[0]
    assert ".rt-cmp__gate{color:var(--avoid)}" in report.COMPARE_CSS


# --- best value --------------------------------------------------------------

def bold(cell):
    return "rt-cmp__best" in cell


def test_best_values_are_bold_and_the_rest_are_not(two):
    markup = table(two)
    assert [bold(c) for c in cell_html(markup, "Score")] == [True, False]
    # lower is better for counts: Alpha 2 unpatched vs Beta 3
    assert [bold(c) for c in cell_html(markup, "Unpatched")] == [True, False]
    # higher is better for pillars: Alpha has the better exposure, Beta the better patchability
    assert [bold(c) for c in cell_html(markup, '<span class="rt-cmp__key">E')] == [True, False]
    assert [bold(c) for c in cell_html(markup, '<span class="rt-cmp__key">P')] == [False, True]


def test_ties_are_all_bold_but_a_full_tie_marks_nothing():
    three = [block(assessment("A", value=80), [finding()]),
             block(assessment("B", value=80), [finding()]),
             block(assessment("C", value=60), [finding(), finding()])]
    assert [bold(c) for c in cell_html(table(three), "Score")] == [True, True, False]
    same = [block(assessment("A"), [finding()]), block(assessment("B"), [finding()])]
    assert not any(bold(c) for c in cell_html(table(same), "Unpatched"))


def test_a_blocked_score_is_never_best():
    gated = assessment("Gated", "AVOID", 95, gates=[{"gate": "Blocker"}])
    markup = table([block(gated), block(assessment("Alpha", value=60)),
                    block(assessment("Beta", value=50))])
    assert [bold(c) for c in cell_html(markup, "Score")] == [False, True, False]


def test_best_is_bold_text_never_a_hue():
    css = report.COMPARE_CSS
    best_rules = [rule for rule in css.splitlines() if "rt-cmp__best" in rule]
    assert best_rules
    for rule in best_rules:
        assert "font-weight:700" in rule and "color:var(--text)" in rule
        assert not re.search(r"--(prefer|avoid|conditional|verify|action)\b", rule)
    cells = cell_html(table([block(assessment("A", value=80)), block(assessment("B", value=50))]), "Score")
    assert "style=" not in "".join(cells)


# --- page --------------------------------------------------------------------

def stub_assess(table_of):
    def assess(vendor, product, version=None, order_number=None, **options):
        name = product or order_number or vendor
        return table_of.get(name) or (assessment(name), resolved(), [])
    return assess


@pytest.fixture
def page():
    def make(rows=None, assessments=None, **query):
        known = {"Alpha": (assessment("Alpha", value=82), resolved(), []),
                 "Beta": (assessment("Beta", "CONDITIONAL", 55), resolved(), []),
                 "Gamma": (assessment("Gamma", "AVOID", 20,
                                      gates=[{"gate": "Sanctioned supplier"}]), resolved(), [])}
        known.update(assessments or {})
        rows = rows if rows is not None else [["", "Alpha", "1.0", "ORD-A"], ["", "Beta", "", "ORD-B"],
                                              ["", "Gamma", "", ""]]
        result = serve._compare_page(stub_assess(known), {"weights": {}}, rows)
        text = result if isinstance(result, str) else result[0] if isinstance(result, tuple) else str(result)
        # The inlined stylesheet names every class; assertions are about markup.
        return re.sub(r"<style.*?</style>", "", text, flags=re.S)
    return make


def test_remove_links_drop_only_that_candidate_and_keep_the_rest(page):
    markup = page()
    links = re.findall(r'<a class="rt-cmp__remove" href="([^"]+)" aria-label="([^"]+)"', markup)
    assert len(links) == 3
    by_name = {re.match(r"Remove (\w+) ", label).group(1): html.unescape(href)
               for href, label in links}
    assert set(by_name) == {"Alpha", "Beta", "Gamma"}
    for gone, href in by_name.items():
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(href).query)
        products = sorted(v[0] for k, v in query.items() if k.startswith("product_"))
        assert products == sorted({"Alpha", "Beta", "Gamma"} - {gone})
    kept = urllib.parse.parse_qs(urllib.parse.urlsplit(by_name["Gamma"]).query)
    assert {k: v[0] for k, v in kept.items() if v[0]} == {
        "product_0": "Alpha", "version_0": "1.0", "order_number_0": "ORD-A",
        "product_1": "Beta", "order_number_1": "ORD-B"}


def test_remove_target_is_at_least_44px_and_labelled():
    assert "width:44px;height:44px" in report.COMPARE_CSS


def test_removal_is_independent_of_rank_order(page):
    # Gamma is ranked last but is the first input row.
    markup = page(rows=[["", "Gamma", "", ""], ["", "Alpha", "", ""]])
    links = dict((re.match(r"Remove (\w+) ", label).group(1), html.unescape(href))
                 for href, label in re.findall(
                     r'class="rt-cmp__remove" href="([^"]+)" aria-label="([^"]+)"', markup))
    assert "Gamma" in links["Alpha"] and "Alpha" not in links["Alpha"]
    assert "Alpha" in links["Gamma"] and "Gamma" not in links["Gamma"]


def test_one_primary_button_and_it_is_the_export_menu(page):
    markup = page()
    assert markup.count("rt-btn--primary") == 1
    menu = re.search(r'<div class="rt-menu">.*?</div></div>', markup, re.S).group(0)
    assert "rt-btn--primary" in menu and "Export comparison" in menu
    assert "popovertarget=" in menu and " popover>" in menu
    rows = re.findall(r'<a class="rt-menu__row" href="([^"]+)"(?: data-filename="[^"]+")?><span class="rt-menu__text">'
                      r'([^<]+)</span><span class="rt-menu__tag">([^<]+)</span>', menu)
    assert [(label, tag) for _, label, tag in rows] == [
        ("HTML report", "HTML"), ("JSON", "JSON"), ("CSV", "CSV")]
    assert [html.unescape(href).split("?")[0] for href, _, _ in rows] == [
        "/compare.html", "/compare.json", "/compare.csv"]
    assert "/compare.csv?" in markup
    submit = re.search(r'<button[^>]*type="submit"[^>]*>', markup).group(0)
    assert "rt-btn--secondary" in submit


def test_clear_shortlist_confirms_before_clearing(page):
    markup = page()
    trigger = re.search(r'<button[^>]*popovertarget="clear-shortlist"[^>]*>(?:(?!</button>).)*'
                        r'Clear shortlist.*?</button>', markup, re.S).group(0)
    assert "rt-btn--destructive" in trigger and 'type="button"' in trigger
    panel = re.search(r'<div class="rt-confirm" id="clear-shortlist" popover.*?</div></div>',
                      markup, re.S).group(0)
    assert 'role="alertdialog"' in panel
    confirm = re.search(r'<a class="rt-btn rt-btn--destructive" href="/compare">', panel)
    assert confirm and "Clear shortlist" in panel
    assert 'popovertargetaction="hide"' in panel and "Keep shortlist" in panel
    # The trigger itself never navigates: only the confirm link in the panel does.
    assert 'href="/compare"' not in trigger


def test_firmware_warning_is_an_amber_review_alert(page):
    markup = page()      # Alpha has firmware, the others do not
    assert "Some candidates have firmware specified and others do not." in markup
    assert "rt-alert--review" in markup
    assert serve._comparison_warning([["", "A", "1", ""], ["", "B", "1", ""]]) == ""
    assert serve._comparison_warning([["", "A", "", ""]]) == ""


def test_stability_sentence_appears_once_per_block(page):
    markup = page()
    assert markup.count("This tests the effect of changing weights") <= 3


def test_a_single_candidate_has_no_table_and_no_remove_link(page):
    markup = page(rows=[["", "Alpha", "", ""]])
    assert "rt-cmp" not in markup.replace("rt-cmp-actions", "")
    assert "rt-cmp__remove" not in markup


def test_per_candidate_blocks_follow_the_table(page):
    markup = page()
    assert markup.index('class="rt-cmp"') < markup.index('class="block rt-result"')
    assert markup.count('class="block rt-result"') == 3


def test_hostile_candidate_names_are_escaped_everywhere(page):
    hostile = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'
    rows = [["", hostile, "", '"><b>ORD</b>'], ["", "Alpha", "", ""]]
    markup = page(rows=rows,
                  assessments={hostile: (assessment(hostile), resolved(), [])})
    assert "<script" not in without_enhancement(markup).lower()
    assert "<script>alert(1)" not in markup
    assert "<img src=x" not in markup
    assert "&lt;script&gt;alert(1)" in markup
    assert 'aria-label="Remove &lt;script&gt;' in markup


def test_the_page_carries_no_script_element(page):
    assert "<script" not in without_enhancement(page()).lower()


def test_static_table_has_no_remove_links(two):
    assert "rt-cmp__remove" not in table(two)
    assert "rt-cmp__remove" in table(two, remove=lambda i: "/compare?x=%d" % i)


def test_compare_css_passes_the_design_lint():
    assert css_lint(report.COMPARE_CSS) == []
    assert report.COMPARE_CSS in report.RESULT_CSS
