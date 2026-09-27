"""Tests for the accuracy harness.

This module produces the figures ReTrust publishes, so it needs more scepticism
than the rest of the code, not less. A benchmark that cannot fail proves
nothing, and the most dangerous failure here is the quiet one: a harness that
reports a flattering number because it is measuring the wrong thing.

The tests below are therefore in two groups. The first checks the arithmetic.
The second checks that the benchmark is *capable of reporting a bad result* --
that a broken matcher drives precision down, and that the round-trip really
degrades its queries instead of handing the corpus its own strings back.
"""

import json

import pytest

from retrust import evaluate, index


# --- metric arithmetic -----------------------------------------------------

def test_coverage_arithmetic():
    result = evaluate.Result(total=100, decided=90, undecidable=4, missed=6)
    assert result.coverage == pytest.approx(0.90)
    # Of the 96 that can be decided at all, we decide 90.
    assert result.decidable_accuracy == pytest.approx(90 / 96)


def test_decidable_accuracy_excludes_the_undecidable():
    """Ranges no version string can settle must not count against us.

    They must not flatter us either: they are reported separately so the
    headline figure cannot be inflated by reclassifying failures.
    """
    strict = evaluate.Result(total=100, decided=90, undecidable=0, missed=10)
    lenient = evaluate.Result(total=100, decided=90, undecidable=10, missed=0)
    assert strict.decidable_accuracy == pytest.approx(0.90)
    assert lenient.decidable_accuracy == pytest.approx(1.0)
    # Coverage is unmoved by the reclassification, which is the honest number.
    assert strict.coverage == lenient.coverage == pytest.approx(0.90)


def test_empty_metrics_do_not_divide_by_zero():
    empty = evaluate.Result()
    assert empty.coverage == 0.0
    assert empty.decidable_accuracy == 0.0
    trip = evaluate.RoundTrip()
    assert trip.precision == 0.0
    assert trip.recall == 0.0


def test_precision_and_recall_differ_when_abstaining():
    """Precision ignores abstentions; recall does not. That gap is the point."""
    trip = evaluate.RoundTrip(attempted=100, correct=80, wrong=0, abstained=20)
    assert trip.precision == pytest.approx(1.0)    # never wrong when it answered
    assert trip.recall == pytest.approx(0.80)      # but silent on a fifth


def test_precision_falls_when_answers_are_wrong():
    trip = evaluate.RoundTrip(attempted=100, correct=50, wrong=50)
    assert trip.precision == pytest.approx(0.5)


# --- the query degradation that makes the benchmark honest -----------------

def test_query_is_degraded_not_echoed():
    """The bug this guards: feeding the corpus string back verbatim.

    Doing that measures string equality and reports a meaningless 100%. An
    earlier version did exactly this and scored 100.00% precision AND recall.
    """
    name = "SIMATIC S7-1500 CPU 1518-4 PN/DP MFP (6ES7518-4AX00-1AB0)"
    typed = evaluate.as_a_buyer_would_type_it(name)
    assert typed != name
    assert typed != name.lower()
    assert "6es7518" not in typed          # the order number is dropped
    assert "(" not in typed and ")" not in typed
    assert typed == typed.lower()
    assert len(typed.split()) <= 4


def test_degradation_keeps_the_leading_words():
    assert evaluate.as_a_buyer_would_type_it("Modicon M340 BMXP342020") == \
        "modicon m340 bmxp342020"
    assert evaluate.as_a_buyer_would_type_it("A B C D E F") == "a b c d"


def test_degradation_survives_odd_names():
    assert evaluate.as_a_buyer_would_type_it("(6ES7518-4AX00-1AB0)") == ""
    assert evaluate.as_a_buyer_would_type_it("") == ""
    assert evaluate.as_a_buyer_would_type_it("---") == ""


def test_undecidable_pattern_matches_real_corpus_strings():
    for text in ['<= with_the_first_5_digits_of_serial_number_2408',
                 '<with_U-Boot_V2016.05RS09', 'Rev._1', '<BIOS_V1.0.212N',
                 'distributed  < april 1, 2018', '<=LJ']:
        assert evaluate.UNDECIDABLE_RANGE.search(text.strip()), text


def test_undecidable_pattern_does_not_swallow_real_versions():
    """Misclassifying a parseable range as undecidable would inflate accuracy."""
    for text in ['vers:intdot/<4.3.8', '<V2.9.7', '>=V3.1.0|<V3.1.2', '4.5']:
        assert not evaluate.UNDECIDABLE_RANGE.search(text.strip()), text


# --- against a real index --------------------------------------------------

ADVISORY = {
    "document": {"title": "Test", "tracking": {
        "id": "ICSA-26-001-01", "initial_release_date": "2026-01-01T00:00:00Z"}},
    "product_tree": {"branches": [{
        "category": "vendor", "name": "Testco Electric",
        "branches": [{
            "category": "product_name", "name": "TestPLC 9000 (TC-9000-A1)",
            "branches": [
                {"category": "product_version_range", "name": "vers:intdot/<2.0",
                 "product": {"product_id": "P1", "name": "TestPLC 9000",
                             "product_identification_helper": {
                                 "model_numbers": ["TC-9000-A1"]}}},
                {"category": "product_version_range",
                 "name": "<= first 5 digits of serial number 2408",
                 "product": {"product_id": "P2", "name": "TestPLC 9000 serial"}},
                {"category": "product_version_range", "name": "%%%unparseable%%%",
                 "product": {"product_id": "P3", "name": "TestPLC 9000 odd"}},
            ]}]}]},
    "vulnerabilities": [{"cve": "CVE-2026-0001",
                         "product_status": {"known_affected": ["P1", "P2", "P3"]},
                         "scores": [{"cvss_v3": {"baseScore": 7.5},
                                     "products": ["P1"]}]}],
}


@pytest.fixture
def db(tmp_path):
    directory = tmp_path / "csaf"
    directory.mkdir()
    (directory / "a.json").write_text(json.dumps(ADVISORY))
    connection, _ = index.build(str(tmp_path / "t.db"), str(directory))
    return connection


def test_version_coverage_classifies_all_three_buckets(db):
    result = evaluate.version_coverage(db)
    assert result.total == 3
    assert result.decided == 1          # vers:intdot/<2.0
    assert result.undecidable == 1      # serial-number scoped
    assert result.missed == 1           # genuinely unparseable
    assert result.decided + result.undecidable + result.missed == result.total


def test_version_coverage_records_what_it_missed(db):
    """A miss we cannot see is a miss we will never fix."""
    result = evaluate.version_coverage(db)
    assert any("unparseable" in key for key in result.examples)


def test_version_coverage_limit_is_respected(db):
    assert evaluate.version_coverage(db, limit=2).total == 2


def test_round_trip_resolves_known_products(db):
    trip = evaluate.round_trip(db, sample=10)
    assert trip.attempted >= 1
    assert trip.correct + trip.wrong + trip.abstained == trip.attempted
    assert trip.precision == pytest.approx(1.0)


def test_round_trip_can_report_failure(db, monkeypatch):
    """The benchmark must be able to say the matcher is wrong.

    A harness that always reports success is not evidence. Break resolution and
    the figures must fall, otherwise the published number means nothing.
    """
    original = evaluate.match.resolve      # capture before patching the name

    def always_wrong(connection, vendor=None, product=None, order_number=None):
        resolution = original(connection, vendor=vendor, product=product,
                              order_number=order_number)
        for candidate in resolution.matches:
            candidate.advisory_id = "ICSA-99-999-99"    # a different advisory
        return resolution

    monkeypatch.setattr(evaluate.match, "resolve", always_wrong)
    trip = evaluate.round_trip(db, sample=10)
    assert trip.correct == 0
    assert trip.wrong > 0
    assert trip.precision == 0.0


def test_round_trip_counts_abstentions_apart_from_errors(db, monkeypatch):
    """Abstaining is not the same as being wrong, and must not be scored as it."""
    from retrust.match import Resolution

    monkeypatch.setattr(evaluate.match, "resolve",
                        lambda *a, **k: Resolution(query="x", abstained=True,
                                                   reason="no"))
    trip = evaluate.round_trip(db, sample=10)
    assert trip.abstained == trip.attempted
    assert trip.wrong == 0
    assert trip.recall == 0.0
    assert trip.precision == 0.0      # nothing answered, so nothing to be right about


def test_round_trip_records_the_method_used(db):
    trip = evaluate.round_trip(db, sample=10)
    assert trip.by_method
    for counts in trip.by_method.values():
        assert set(counts) == {"correct", "wrong"}


def test_realistic_flag_actually_changes_the_query(db, monkeypatch):
    """realistic=False must be the easier test, so the difference is visible."""
    seen = []
    original = evaluate.match.resolve

    def spy(connection, vendor=None, product=None, order_number=None):
        seen.append(product)
        return original(connection, vendor=vendor, product=product,
                        order_number=order_number)

    monkeypatch.setattr(evaluate.match, "resolve", spy)
    evaluate.round_trip(db, sample=10, realistic=False)
    verbatim = list(seen)
    seen.clear()
    evaluate.round_trip(db, sample=10, realistic=True)
    assert verbatim != seen


def test_run_returns_both_measurements(db):
    results = evaluate.run(db, sample=10)
    assert set(results) == {"version", "round_trip"}
    assert isinstance(results["version"], evaluate.Result)
    assert isinstance(results["round_trip"], evaluate.RoundTrip)


def test_format_report_shows_the_numbers_it_measured(db):
    results = evaluate.run(db, sample=10)
    text = evaluate.format_report(results)
    assert "VERSION-RANGE COVERAGE" in text
    assert "PRODUCT ROUND-TRIP" in text
    assert f"{results['version'].coverage:6.2%}" in text
    assert f"{results['round_trip'].precision:6.2%}" in text
    # The misses are printed, not hidden.
    assert "unparsed" in text.lower()


def test_format_report_handles_an_empty_index(tmp_path):
    """An empty index must explain itself, not divide by zero.

    `retrust eval` on a fresh clone hits exactly this: the user has not run
    ingest yet, and a traceback is a worse answer than a sentence.
    """
    results = {"version": evaluate.Result(), "round_trip": evaluate.RoundTrip()}
    text = evaluate.format_report(results)
    assert "empty" in text.lower()
    assert "retrust ingest" in text


def test_format_report_survives_a_partial_index():
    """Coverage measured but nothing round-tripped, and vice versa."""
    only_versions = {"version": evaluate.Result(total=10, decided=9, missed=1),
                     "round_trip": evaluate.RoundTrip()}
    assert "90.00%" in evaluate.format_report(only_versions)

    only_trip = {"version": evaluate.Result(),
                 "round_trip": evaluate.RoundTrip(attempted=5, correct=5)}
    assert "100.00%" in evaluate.format_report(only_trip)


def test_eval_on_an_empty_index_does_not_crash(tmp_path):
    connection = index.connect(str(tmp_path / "e.db"))
    results = evaluate.run(connection, sample=5)
    assert results["version"].total == 0
    evaluate.format_report(results)          # must not raise
