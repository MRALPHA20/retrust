"""Tests for the family suggestion list.

The ranking is easy. What needs pinning is what this command refuses to do: it
must never suggest a product ReTrust could not assess, because every pillar
reads "no CVEs found" as good news and an unassessable product would sort to the
top of any score-ranked list. That is the inversion the whole tool exists to
avoid, and this is the command most likely to reintroduce it.
"""

import json

import pytest

from retrust import alternatives, index, score


def _leaf(product_id, name):
    return {"category": "product_version_range", "name": "vers:intdot/<2.0",
            "product": {"product_id": product_id, "name": name}}


ADVISORY = {
    "document": {"title": "T", "tracking": {
        "id": "ICSA-26-001-01", "initial_release_date": "2026-01-01T00:00:00Z"}},
    "product_tree": {"branches": [{
        "category": "vendor", "name": "Testco Electric", "branches": [
            {"category": "product_name", "name": "TestPLC 9000 Alpha",
             "branches": [_leaf("P1", "TestPLC 9000 Alpha")]},
            {"category": "product_name", "name": "TestPLC 9000 Beta",
             "branches": [_leaf("P2", "TestPLC 9000 Beta")]},
            {"category": "product_name", "name": "TestHMI 100",
             "branches": [_leaf("P3", "TestHMI 100")]},
        ]}]},
    "vulnerabilities": [{"cve": "CVE-2026-0001",
                         "product_status": {"known_affected": ["P1", "P2", "P3"]},
                         "scores": [{"cvss_v3": {"baseScore": 7.5},
                                     "products": ["P1", "P2", "P3"]}]}],
}


@pytest.fixture
def db(tmp_path):
    directory = tmp_path / "csaf"
    directory.mkdir()
    (directory / "a.json").write_text(json.dumps(ADVISORY))
    connection, _ = index.build(str(tmp_path / "t.db"), str(directory))
    return connection


def _assessor(verdicts, findings=3):
    """A stand-in scorer, so ranking is tested without the scoring pipeline."""
    def assess(vendor, product):
        verdict, value = verdicts.get(product, ("NOT ASSESSED", None))
        if value is None:
            return score.not_assessed(f"{vendor} {product}", "no data"), None, []
        assessment = score.not_assessed(f"{vendor} {product}", "")
        assessment.verdict, assessment.score = verdict, value
        assessment.findings_count = findings
        return assessment, None, []
    return assess


def _nothing_skipped():
    return {"unassessable": 0, "gated": 0, "no evidence": 0}


# --- the family ------------------------------------------------------------

def test_shared_prefix_counts_leading_words_only():
    assert alternatives.shared_prefix("TestPLC 9000 Alpha", "TestPLC 9000 Beta") == 2
    assert alternatives.shared_prefix("TestPLC 9000", "TestHMI 100") == 0
    # A word in common further along is not a family: order is what matters.
    assert alternatives.shared_prefix("Alpha TestPLC", "TestPLC Beta") == 0


def test_single_character_words_are_not_family_evidence():
    """Otherwise every product whose name contains "S" is a relative."""
    assert alternatives.tokens("S 7 SIMATIC") == ["simatic"]


def test_family_finds_siblings_and_excludes_strangers(db):
    names = [name for name, _ in alternatives.family(db, "Testco", "TestPLC 9000 Alpha")]
    assert "TestPLC 9000 Beta" in names
    assert "TestHMI 100" not in names


def test_the_product_asked_about_is_not_its_own_alternative(db):
    names = [name for name, _ in alternatives.family(db, "Testco", "TestPLC 9000 Alpha")]
    assert "TestPLC 9000 Alpha" not in names


def test_an_unknown_vendor_has_no_family(db):
    assert alternatives.family(db, "Nobody", "TestPLC 9000") == []


def test_a_punctuation_only_name_has_no_family(db):
    """It normalises to nothing, which must not match the whole catalogue."""
    assert alternatives.family(db, "Testco", "-") == []
    assert alternatives.family(db, "", "TestPLC") == []


# --- what must never be suggested ------------------------------------------

def test_an_unassessable_product_is_never_offered(db):
    """The inversion this command exists not to make.

    Every pillar reads "no CVEs found" as good news, so a product nobody has
    published about would score near 100 and head the list. It is counted.
    """
    options, skipped = alternatives.find(
        db, "Testco", "TestPLC 9000 Alpha",
        _assessor({}))                       # nothing assessable
    assert options == []
    assert skipped["unassessable"] == 1


def test_a_gated_alternative_is_not_offered(db):
    """And is counted as disqualified, not as missing data.

    Telling a buyer a ruled-out product was merely undocumented points them at
    the wrong action: going to look for evidence that would change nothing.
    """
    def assess(vendor, product):
        assessment = score.blocked(f"{vendor} {product}",
                                   [{"gate": "Named on a covered list",
                                     "detail": "d", "source": "s"}], "")
        return assessment, None, []

    options, skipped = alternatives.find(db, "Testco", "TestPLC 9000 Alpha", assess)
    assert options == []
    assert skipped["gated"] == 1
    assert skipped["unassessable"] == 0


def test_an_assessable_sibling_is_offered(db):
    options, skipped = alternatives.find(
        db, "Testco", "TestPLC 9000 Alpha",
        _assessor({"TestPLC 9000 Beta": ("PREFER", 80.0)}))
    assert [o.verdict for o in options] == ["PREFER"]
    assert options[0].score == 80.0
    assert not any(skipped.values())


def test_a_sibling_with_no_findings_is_never_offered(db):
    """The inversion this module exists not to make.

    Every pillar reads "no CVEs found" as good news, so a product nobody has
    published about scores near 100 and heads the list. 413 products in the real
    corpus have no CVE link at all, so this is reachable.
    """
    options, skipped = alternatives.find(
        db, "Testco", "TestPLC 9000 Alpha",
        _assessor({"TestPLC 9000 Beta": ("PREFER", 99.0)}, findings=0))
    assert options == []
    assert skipped["no evidence"] == 1


def test_prefer_outranks_a_higher_scoring_conditional(db):
    """The band is the decision; the number only orders within it."""
    options, _ = alternatives.find(
        db, "Testco", "TestHMI 100",
        _assessor({"TestPLC 9000 Alpha": ("CONDITIONAL", 69.0),
                   "TestPLC 9000 Beta": ("PREFER", 68.0)}))
    assert [o.verdict for o in options] == []   # neither shares HMI's family


# --- the report ------------------------------------------------------------

def _flat(text):
    """Line breaks collapsed: the prose is wrapped to the terminal at print
    time, so a phrase asserted against the raw text breaks at a wrap point."""
    return " ".join(text.split())


def _subject(verdict="AVOID", value=39.1):
    assessment = score.not_assessed("Testco TestPLC 9000 Alpha", "")
    assessment.verdict, assessment.score = verdict, value
    return assessment


def test_the_caveat_comes_before_any_suggestion():
    option = alternatives.Option("Testco TestPLC 9000 Beta", "TestPLC 9000 Beta", "PREFER", 80.0,
                                 "TestPLC 9000", [], 3)
    text = _flat(alternatives.format_report(_subject(), [option], _nothing_skipped()))
    assert text.index("not a recommendation to substitute") < text.index("CANDIDATE")


def test_each_reason_for_skipping_is_reported_apart():
    text = _flat(alternatives.format_report(
        _subject(), [], {"unassessable": 4, "gated": 2, "no evidence": 1}))
    assert "4 family member(s) could not be assessed" in text
    assert "2 family member(s) are disqualified by a hard gate" in text
    assert "1 family member(s) have no advisory findings" in text


def test_an_empty_family_says_so_without_inventing_one():
    text = _flat(alternatives.format_report(_subject(), [], _nothing_skipped()))
    assert "Nothing in the corpus shares this product's family" in text


def test_a_supplied_version_is_flagged_as_an_unequal_comparison():
    """Candidates are scored without a version; the subject was scored with one."""
    option = alternatives.Option("Testco TestPLC 9000 Beta", "TestPLC 9000 Beta", "PREFER", 80.0,
                                 "TestPLC 9000", [], 3)
    text = _flat(alternatives.format_report(_subject(), [option], _nothing_skipped(), version="3.1.6"))
    assert "not on equal terms" in text
    assert "3.1.6" in text
    assert text.index("not on equal terms") < text.index("CANDIDATE")


def test_no_version_means_no_spurious_warning():
    option = alternatives.Option("X", "X", "PREFER", 80.0, "TestPLC", [], 3)
    assert "equal terms" not in _flat(alternatives.format_report(_subject(), [option], _nothing_skipped()))


def test_the_comparison_line_counts_only_genuine_improvements():
    options = [alternatives.Option("Better", "Better", "PREFER", 80.0, "T", [], 3),
               alternatives.Option("Worse", "Worse", "CONDITIONAL", 30.0, "T", [], 3)]
    assert "1 of 2 scored above" in _flat(alternatives.format_report(
        _subject(value=50.0), options, _nothing_skipped()))


def test_provisional_sibling_remains_available_for_engineering_review(db):
    def assess(vendor, product):
        result = score.not_assessed(f'{vendor} {product}', '')
        result.verdict, result.score = 'VERIFY', 20
        result.score_min, result.score_max = 20, 90
        result.provisional, result.findings_count = True, 1
        return result, None, []
    options, skipped = alternatives.find(db, 'Testco', 'TestPLC 9000 Alpha', assess)
    assert options and options[0].verdict == 'VERIFY'
    assert options[0].score_min == 20 and options[0].score_max == 90
    subject, _, _ = assess('Testco', 'TestPLC 9000 Alpha')
    output = alternatives.format_report(subject, options, skipped)
    # En-dash: every surface now renders ranges through report.score_label,
    # and this file used to be the one printing an ASCII hyphen.
    assert '20.0\u201390.0' in output and 'not recommendations' in output
    assert 'scored above' not in output
