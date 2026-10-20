"""Tests for the LEV estimate, after NIST CSWP 41.

The equation is short, so most of what can go wrong is interpretation: a
probability presented as an observation, a zero printed where nothing was
measured, or a model allowed to talk down something KEV actually recorded.
"""

from datetime import date, timedelta
from itertools import pairwise

from retrust import lev


def _series(start, months, score):
    """One EPSS score repeated at thirty-day spacing."""
    return [(start + timedelta(days=30 * i), score) for i in range(months)]


# --- the equation ----------------------------------------------------------

def test_the_paper_s_central_case():
    """A flaw never urgent on any day, and very likely by now.

    0.05 a month for three years is the example CSWP 41 exists to make: EPSS
    never raises an alarm, and the composed probability is 0.84.
    """
    observations = _series(date(2021, 4, 14), 36, 0.05)
    assert round(lev.probability(observations, date(2024, 4, 1)), 2) == 0.84


def test_a_single_certain_day_gives_certainty():
    assert lev.probability([(date(2024, 1, 1), 1.0)], date(2024, 2, 1)) == 1.0


def test_a_flaw_epss_never_rated_is_zero_not_an_error():
    assert lev.probability([]) == 0.0


def test_probability_never_leaves_the_unit_interval():
    for score in (0.0, 0.5, 1.0):
        value = lev.probability(_series(date(2021, 4, 14), 60, score),
                                date(2026, 1, 1))
        assert 0.0 <= value <= 1.0


def test_a_score_outside_the_range_is_clamped_not_trusted():
    """A malformed feed must not produce a probability above one."""
    assert lev.probability([(date(2024, 1, 1), 5.0)], date(2024, 2, 1)) == 1.0
    assert lev.probability([(date(2024, 1, 1), -1.0)], date(2024, 2, 1)) == 0.0


def test_more_exposure_never_lowers_the_estimate():
    short = lev.probability(_series(date(2021, 4, 14), 6, 0.05), date(2021, 10, 1))
    long = lev.probability(_series(date(2021, 4, 14), 36, 0.05), date(2024, 4, 1))
    assert long > short


# --- the final partial window ----------------------------------------------

def test_the_last_window_is_weighted_by_days_elapsed():
    """A score published yesterday has not had its thirty days yet.

    Counting it in full would credit the newest observation with a month that
    has not happened.
    """
    days = [date(2024, 1, 1), date(2024, 1, 31)]
    assert lev.weights(days, date(2024, 2, 1)) == [1.0, 2 / 30]


def test_a_full_window_weighs_one():
    days = [date(2024, 1, 1)]
    assert lev.weights(days, date(2024, 3, 1)) == [1.0]


def test_no_days_weigh_nothing():
    assert lev.weights([]) == []


# --- the composite ---------------------------------------------------------

def _estimate(**kwargs):
    base = dict(cve="CVE-1", lev=0.0, peak_epss=0.0, first_seen="", last_seen="",
                observations=1)
    return lev.Estimate(**{**base, **kwargs})


def test_kev_cannot_be_talked_down_by_the_model():
    """KEV is an observation; LEV is a model. Averaging would lose the former."""
    assert _estimate(lev=0.01, in_kev=True).composite == 1.0


def test_the_composite_takes_the_strongest_signal():
    assert _estimate(lev=0.6, current_epss=0.2).composite == 0.6
    assert _estimate(lev=0.2, current_epss=0.7).composite == 0.7


def test_a_missing_current_epss_is_not_read_as_zero_risk():
    assert _estimate(lev=0.4, current_epss=None).composite == 0.4


def test_the_case_worth_a_human_is_flagged():
    """Likely by the model, absent from the catalogue: go and look."""
    assert _estimate(lev=0.5, in_kev=False).unlisted
    assert not _estimate(lev=0.5, in_kev=True).unlisted      # already known
    assert not _estimate(lev=0.01, in_kev=False).unlisted    # not likely enough


# --- the set ---------------------------------------------------------------

def test_expected_count_is_the_sum_of_the_probabilities():
    estimates = [_estimate(lev=0.5), _estimate(lev=0.25), _estimate(lev=0.25)]
    assert lev.expected_exploited(estimates) == 1.0


def test_sample_days_are_thirty_apart_and_start_where_epss_does():
    days = lev.sample_days(end=date(2021, 7, 13))
    assert days[0] == lev.FIRST_EPSS_DAY
    assert all((b - a).days == 30 for a, b in pairwise(days))
    assert days[-1] <= date(2021, 7, 13)


# --- estimating and reporting ----------------------------------------------

def test_estimate_records_the_span_it_had()  :
    observations = _series(date(2021, 4, 14), 3, 0.1)
    result = lev.estimate("CVE-2021-1", observations, last_day=date(2021, 7, 13))
    assert result.observations == 3
    assert result.first_seen == "2021-04-14"
    assert result.peak_epss == 0.1


def _flat(text):
    return " ".join(text.split())


def test_a_cve_with_no_history_is_not_estimated_as_zero():
    """A zero would read as "we checked and it is unlikely"."""
    text = _flat(lev.format_report("P", [
        lev.estimate("CVE-2026-9", [], current_epss=0.2)]))
    assert "no EPSS history at all and are not estimated" in text
    assert "gets no LEV rather than a zero" in text


def test_the_expectation_is_labelled_as_one():
    text = _flat(lev.format_report("P", [
        lev.estimate("CVE-1", _series(date(2021, 4, 14), 12, 0.1))]))
    assert "expectation over the set, not a claim about any single CVE" in text


def test_the_augment_not_replace_rule_is_printed():
    text = _flat(lev.format_report("P", [
        lev.estimate("CVE-1", _series(date(2021, 4, 14), 36, 0.05))]))
    assert "augments KEV rather than replacing it" in text
    assert "never as a finding that they were exploited" in text


def test_the_method_is_attributed():
    text = _flat(lev.format_report("P", [lev.estimate("CVE-1", [])]))
    assert "NIST CSWP 41" in text


def test_an_empty_product_says_so():
    assert "No findings to estimate" in lev.format_report("P", [])


# --- base rates: does the threshold discriminate? ---------------------------

def _row(cve, value, observations=40):
    return {"cve": cve, "lev": value, "observations": observations}


def test_baseline_reports_the_share_over_the_threshold():
    rows = [_row("A", 0.5), _row("B", 0.05), _row("C", 0.2), _row("D", 0.01)]
    summary = lev.baseline(rows)
    assert summary["cves"] == 4
    assert summary["share"] == 0.5
    assert summary["median"] == 0.125


def test_baseline_splits_by_how_long_epss_watched():
    """The confound worth surfacing: LEV accumulates with exposure."""
    rows = ([_row(f"young{i}", 0.01, observations=6) for i in range(10)]
            + [_row(f"old{i}", 0.9, observations=60) for i in range(10)])
    bands = lev.baseline(rows)["bands"]
    assert bands["under a year"]["share"] == 0.0
    assert bands["three years or more"]["share"] == 1.0


def test_an_empty_corpus_does_not_divide_by_zero():
    summary = lev.baseline([])
    assert summary["share"] == 0.0 and summary["median"] == 0.0
    assert all(b["share"] == 0.0 for b in summary["bands"].values())


def test_the_age_confound_is_stated_in_the_audit():
    text = _flat(lev.format_baseline(lev.baseline([_row("A", 0.5)])))
    assert "rises with exposure whatever the flaw is worth" in text
    assert "expected case rather than a finding" in text


def test_the_audit_shows_kev_separation_when_it_has_it():
    text = _flat(lev.format_baseline(
        lev.baseline([_row("A", 0.5)]),
        listed={"in_kev": 113, "in_kev_median": 1.0, "not_in_kev_median": 0.162}))
    assert "signal rather than a clock" in text
    assert "1.000" in text


def test_a_product_count_is_compared_with_the_corpus_not_just_reported():
    """A count with no base rate reads as alarming whatever its value."""
    estimates = [lev.estimate(f"CVE-{i}", _series(date(2021, 4, 14), 40, 0.05))
                 for i in range(10)]
    text = _flat(lev.format_report("P", estimates, corpus_share=0.57))
    assert "Across the whole corpus 57% do" in text


def test_a_product_at_the_base_rate_is_called_ordinary():
    estimates = ([lev.estimate(f"CVE-hi{i}", _series(date(2021, 4, 14), 40, 0.05))
                  for i in range(6)]
                 + [lev.estimate(f"CVE-lo{i}", _series(date(2021, 4, 14), 2, 0.001))
                    for i in range(4)])
    text = _flat(lev.format_report("P", estimates, corpus_share=0.57))
    assert "about what the corpus does" in text


def test_without_a_base_rate_no_comparison_is_invented():
    estimates = [lev.estimate("CVE-1", _series(date(2021, 4, 14), 40, 0.05))]
    text = _flat(lev.format_report("P", estimates, corpus_share=None))
    assert "Across the whole corpus" not in text
