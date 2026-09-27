"""Tests for re-scoring a stored result.

The arithmetic is simple; the classification is where this can mislead. A gate
that appeared, a verdict that fell, and a product that merely stopped resolving
are three different events, and reporting them as one number would tell a
reviewer to act on the wrong one. Most of this file pins those apart.
"""

import json

import pytest

from retrust import diff


def _record(product, verdict, score, query=None, gates=(), cves=0):
    return {"product": product, "verdict": verdict, "score": score,
            "query": query or {"vendor": product.split()[0], "product": product,
                               "version": None, "order_number": None},
            "gates": list(gates), "cves": cves}


# --- classification --------------------------------------------------------

def test_a_fallen_verdict_is_worse():
    change = diff.compare([_record("A PLC", "PREFER", 80.0)],
                          [_record("A PLC", "CONDITIONAL", 55.0)])[0]
    assert change.kind == "worse"
    assert (change.was, change.now) == ("PREFER", "CONDITIONAL")
    assert change.drift == -25.0


def test_a_risen_verdict_is_better():
    change = diff.compare([_record("A PLC", "AVOID", 30.0)],
                          [_record("A PLC", "PREFER", 75.0)])[0]
    assert change.kind == "better"
    assert change.drift == 45.0


def test_a_new_gate_outranks_a_fallen_verdict():
    """A gate says what to do; a drifting score says only to look again."""
    change = diff.compare(
        [_record("A PLC", "PREFER", 80.0)],
        [_record("A PLC", "AVOID", None, gates=["Known exploited vulnerability"])])[0]
    assert change.kind == "gated"
    assert change.new_gates == ["Known exploited vulnerability"]


def test_a_gate_that_was_already_there_is_not_new():
    gate = ["Named on a covered list"]
    change = diff.compare([_record("A", "AVOID", None, gates=gate)],
                          [_record("A", "AVOID", None, gates=gate)])[0]
    assert change.new_gates == []
    assert change.kind == "same"


def test_losing_resolution_is_not_the_same_as_getting_worse():
    """We have not learned the product is riskier, only that we cannot say."""
    change = diff.compare([_record("A PLC", "PREFER", 80.0)],
                          [_record("A PLC", "NOT ASSESSED", None)])[0]
    assert change.kind == "lost"
    assert change.kind != "worse"


def test_gaining_resolution_is_its_own_category():
    change = diff.compare([_record("A PLC", "NOT ASSESSED", None)],
                          [_record("A PLC", "CONDITIONAL", 50.0)])[0]
    assert change.kind == "gained"


def test_a_small_score_move_is_not_a_finding():
    """Below the threshold this is rounding, not news."""
    assert diff.compare([_record("A", "PREFER", 80.0)],
                        [_record("A", "PREFER", 80.4)])[0].kind == "same"
    assert diff.compare([_record("A", "PREFER", 80.0)],
                        [_record("A", "PREFER", 82.0)])[0].kind == "moved"


def test_drift_is_none_when_either_run_had_no_score():
    change = diff.compare([_record("A", "AVOID", None, gates=["g"])],
                          [_record("A", "AVOID", None, gates=["g"])])[0]
    assert change.drift is None
    assert "None" not in diff.format_report([change])


# --- pairing ---------------------------------------------------------------

def test_rows_pair_on_the_query_not_the_label():
    """The printed label is what we resolved to, and that can change.

    A product renamed upstream would otherwise look like one disappearing and
    an unrelated one arriving, which is two false findings from one rename.
    """
    query = {"vendor": "ABB", "product": "AC 800M", "version": None,
             "order_number": None}
    before = [_record("ABB AC 800M", "PREFER", 80.0, query)]
    after = [_record("ABB AC 800M PLC", "PREFER", 80.0, query)]
    changes = diff.compare(before, after)
    assert len(changes) == 1
    assert changes[0].kind == "same"
    assert changes[0].product == "ABB AC 800M PLC"      # the newer label


def test_pairing_ignores_case_and_padding():
    before = [_record("A", "PREFER", 80.0,
                      {"vendor": " ABB ", "product": "AC 800M"})]
    after = [_record("A", "PREFER", 80.0,
                     {"vendor": "abb", "product": "ac 800m"})]
    assert diff.compare(before, after)[0].kind == "same"


def test_a_product_missing_from_the_new_run_is_reported_not_dropped():
    changes = diff.compare([_record("A PLC", "PREFER", 80.0)], [])
    assert len(changes) == 1
    assert changes[0].now == "NOT ASSESSED"


def test_worst_news_sorts_first():
    changes = diff.compare(
        [_record("Gained", "NOT ASSESSED", None), _record("Fell", "PREFER", 80.0),
         _record("Gated", "PREFER", 80.0), _record("Rose", "AVOID", 20.0)],
        [_record("Gained", "PREFER", 70.0), _record("Fell", "AVOID", 30.0),
         _record("Gated", "PREFER", 79.0, gates=["Known exploited vulnerability"]),
         _record("Rose", "PREFER", 80.0)])
    assert [c.kind for c in changes] == ["gated", "worse", "better", "gained"]


# --- gates come in two shapes ----------------------------------------------

def test_gate_names_read_from_either_stored_shape():
    """batch --json writes strings; score --json writes dicts. Both are ours."""
    assert diff.gate_name("Named on a covered list") == "Named on a covered list"
    assert diff.gate_name({"gate": "Known exploited vulnerability",
                           "detail": "x"}) == "Known exploited vulnerability"


def test_a_dict_gate_survives_formatting():
    change = diff.compare(
        [_record("A", "PREFER", 80.0)],
        [_record("A", "AVOID", None, gates=[{"gate": "Hard gate", "detail": "d"}])])[0]
    assert "Hard gate" in diff.format_report([change])


# --- the weights confound --------------------------------------------------

def test_changed_weights_are_reported_before_any_finding():
    """Otherwise a config edit is read as evidence about the corpus."""
    meta = {"weights": {"exploitation": 0.5, "severity": 0.1}}
    text = diff.format_report(
        diff.compare([_record("A", "PREFER", 80.0)], [_record("A", "AVOID", 30.0)]),
        meta, {"exploitation": 0.3, "severity": 0.2})
    assert text.index("WEIGHTS CHANGED") < text.index("WORSE")
    assert "0.5 -> 0.3" in text


def test_identical_weights_say_nothing():
    weights = {"exploitation": 0.3}
    assert diff.weights_differ({"weights": weights}, weights) is None
    text = diff.format_report(
        diff.compare([_record("A", "PREFER", 80.0)], [_record("A", "PREFER", 80.0)]),
        {"weights": weights}, weights)
    assert "WEIGHTS CHANGED" not in text


def test_an_unrecorded_weighting_is_not_guessed_at():
    assert diff.weights_differ({}, {"exploitation": 0.3}) is None


# --- reading stored files --------------------------------------------------

def test_a_file_without_queries_is_refused_with_a_reason(tmp_path):
    """A pre-query result cannot be looked up again, and saying so beats guessing."""
    path = tmp_path / "old.json"
    path.write_text(json.dumps({"results": [{"product": "A", "verdict": "PREFER"}]}))
    with pytest.raises(SystemExit) as stop:
        diff.read(str(path))
    assert "before queries were recorded" in str(stop.value)


def test_a_file_that_is_not_a_result_is_refused(tmp_path):
    path = tmp_path / "other.json"
    path.write_text(json.dumps({"something": "else"}))
    with pytest.raises(SystemExit) as stop:
        diff.read(str(path))
    assert "not a ReTrust result" in str(stop.value)


def test_unreadable_json_names_the_problem(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json")
    with pytest.raises(SystemExit) as stop:
        diff.read(str(path))
    assert "not valid JSON" in str(stop.value)


def test_a_missing_file_says_so(tmp_path):
    with pytest.raises(SystemExit) as stop:
        diff.read(str(tmp_path / "nothing.json"))
    assert "does not exist" in str(stop.value)


def test_a_good_file_round_trips(tmp_path):
    path = tmp_path / "run.json"
    path.write_text(json.dumps({"weights": {"exploitation": 0.3},
                                "results": [_record("A PLC", "PREFER", 80.0)]}))
    document, records = diff.read(str(path))
    assert document["weights"] == {"exploitation": 0.3}
    assert len(records) == 1


def test_an_empty_comparison_does_not_divide_by_zero():
    assert "Nothing to compare" in diff.format_report([])
