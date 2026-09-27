"""Tests for the back-test.

The property that matters most here is that nothing leaks across the cutoff. A
back-test that can see the future is worse than none: it produces a confident
number that means nothing, and there is no error to notice.
"""

import json

import pytest

from retrust import backtest, index


def _advisory(advisory_id, released, product, cves, cvss=7.5):
    return {
        "document": {"title": product,
                     "tracking": {"id": advisory_id,
                                  "initial_release_date": f"{released}T00:00:00Z"}},
        "product_tree": {"branches": [{
            "category": "vendor", "name": "Testco",
            "branches": [{
                "category": "product_name", "name": product,
                "branches": [{
                    "category": "product_version_range", "name": "vers:all/*",
                    "product": {"product_id": "P1", "name": product}}]}]}]},
        "vulnerabilities": [
            {"cve": cve, "cwe": {"id": "CWE-79"},
             "product_status": {"known_affected": ["P1"]},
             "scores": [{"cvss_v3": {"baseScore": cvss}, "products": ["P1"]}],
             "remediations": [{"category": "vendor_fix", "details": "x",
                               "product_ids": ["P1"]}]}
            for cve in cves],
    }


@pytest.fixture
def db(tmp_path):
    """Three products: one quiet after the cutoff, one that blows up, one silent.

    Three is the minimum the correlation needs, so the fixture carries three.
    """
    directory = tmp_path / "csaf"
    directory.mkdir()
    advisories = [
        _advisory("ICSA-20-001-01", "2020-01-01", "QuietPLC", ["CVE-2020-0001"]),
        _advisory("ICSA-23-001-01", "2023-01-01", "QuietPLC", ["CVE-2023-0001"]),
        _advisory("ICSA-20-002-01", "2020-06-01", "NoisyPLC", ["CVE-2020-0002"]),
        _advisory("ICSA-23-002-01", "2023-06-01", "NoisyPLC",
                  [f"CVE-2023-10{i:02d}" for i in range(20)]),
        # Never heard from again after the cutoff.
        _advisory("ICSA-21-003-01", "2021-03-01", "SilentPLC",
                  ["CVE-2021-0003"], cvss=9.8),
    ]
    for i, document in enumerate(advisories):
        (directory / f"a{i}.json").write_text(json.dumps(document))
    connection, _ = index.build(str(tmp_path / "t.db"), str(directory))
    return connection


# --- the statistics --------------------------------------------------------

def test_spearman_on_known_values():
    assert backtest._spearman([1, 2, 3, 4, 5], [1, 2, 3, 4, 5]) == pytest.approx(1.0)
    assert backtest._spearman([1, 2, 3, 4, 5], [5, 4, 3, 2, 1]) == pytest.approx(-1.0)
    # Monotone but not linear: rank correlation is still perfect.
    assert backtest._spearman([1, 2, 3, 4], [1, 4, 9, 16]) == pytest.approx(1.0)


def test_spearman_handles_ties_and_degenerate_input():
    assert backtest._spearman([1, 1, 1, 1], [1, 2, 3, 4]) == 0.0   # no variance
    assert backtest._spearman([1, 2], [1, 2]) == 0.0               # too few points
    assert backtest._spearman([], []) == 0.0


def test_permutation_p_is_high_for_noise():
    """An uncorrelated pair must not look significant."""
    xs = list(range(60))
    ys = [(i * 37) % 60 for i in range(60)]     # deterministic shuffle
    observed = backtest._spearman(xs, ys)
    p = backtest._permutation_p(xs, ys, observed, permutations=300, seed=1)
    assert p > 0.05


def test_permutation_p_is_low_for_a_real_relationship():
    xs = list(range(60))
    ys = list(range(60))
    p = backtest._permutation_p(xs, ys, 1.0, permutations=300, seed=1)
    assert p < 0.01


def test_permutation_p_is_reproducible():
    xs, ys = list(range(40)), [(i * 7) % 40 for i in range(40)]
    observed = backtest._spearman(xs, ys)
    a = backtest._permutation_p(xs, ys, observed, 200, seed=5)
    b = backtest._permutation_p(xs, ys, observed, 200, seed=5)
    assert a == b


# --- no peeking ------------------------------------------------------------

def test_the_cutoff_actually_filters(db):
    """The score must be computed from pre-cutoff advisories only.

    NoisyPLC has 1 CVE before 2022 and 20 after. If the cutoff leaked, its
    pre-cutoff finding count would reflect the later flood.
    """
    result = backtest.run(db, cutoff="2022-01-01", permutations=0)
    by_name = {o.product: o for o in result.outcomes}
    assert by_name["NoisyPLC"].cves_before == 1
    assert by_name["NoisyPLC"].cves_after == 20
    assert by_name["QuietPLC"].cves_before == 1
    assert by_name["QuietPLC"].cves_after == 1


def test_score_is_unchanged_by_what_comes_after(db, tmp_path):
    """Adding post-cutoff advisories must not move the pre-cutoff score."""
    first = {o.product: o.score
             for o in backtest.run(db, cutoff="2022-01-01", permutations=0).outcomes}

    directory = tmp_path / "csaf2"
    directory.mkdir()
    for i, document in enumerate([
            _advisory("ICSA-20-001-01", "2020-01-01", "QuietPLC", ["CVE-2020-0001"]),
            _advisory("ICSA-24-001-01", "2024-01-01", "QuietPLC",
                      [f"CVE-2024-20{i:02d}" for i in range(50)], cvss=9.9)]):
        (directory / f"b{i}.json").write_text(json.dumps(document))
    connection, _ = index.build(str(tmp_path / "t2.db"), str(directory))

    second = {o.product: o.score
              for o in backtest.run(connection, cutoff="2022-01-01",
                                    permutations=0).outcomes}
    assert second["QuietPLC"] == first["QuietPLC"]


def test_products_with_no_pre_cutoff_history_are_excluded(db):
    """A product first seen after the cutoff cannot be scored at it."""
    result = backtest.run(db, cutoff="2019-01-01", permutations=0)
    assert result.cohort == 0        # both products debut in 2020


# --- reporting -------------------------------------------------------------

def test_all_three_correlations_are_reported(db):
    """Reporting only score-vs-future is how a confounded result is mistaken
    for a finding."""
    result = backtest.run(db, cutoff="2022-01-01", permutations=50)
    text = backtest.format_report(result)
    assert "score vs CVEs after the cutoff" in text
    assert "score vs CVEs before the cutoff" in text
    assert "CVEs before vs CVEs after" in text


def test_interpretation_always_states_the_confounders(db):
    lines = " ".join(backtest.interpretation(
        backtest.run(db, cutoff="2022-01-01", permutations=0)))
    assert "observational" in lines
    assert "discontinued" in lines or "deployed" in lines


def test_sparse_kev_outcome_refuses_to_state_a_rate(db):
    """Only 29 products across 2 vendors qualify on the real corpus.

    A rate computed from that would be noise wearing a percentage sign.
    """
    result = backtest.run(db, cutoff="2022-01-01", permutations=0)
    assert not result.kev_is_measurable
    lines = " ".join(backtest.interpretation(result))
    assert "too few" in lines.lower()
    assert "no such claim" in lines.lower()


def test_an_empty_cohort_does_not_crash(tmp_path):
    connection = index.connect(str(tmp_path / "e.db"))
    result = backtest.run(connection, cutoff="2022-01-01", permutations=10)
    assert result.cohort == 0
    assert "Too few products" in backtest.format_report(result)


def test_limit_caps_the_cohort(db):
    assert backtest.run(db, cutoff="2022-01-01", limit=1,
                        permutations=0).cohort <= 1


def test_bands_report_counts_and_medians(db):
    result = backtest.run(db, cutoff="2022-01-01", permutations=0)
    for stats in result.by_band.values():
        assert stats["products"] >= 1
        assert stats["median_cves_after"] >= 0
        assert 0.0 <= stats["share_with_any"] <= 1.0


# --- matched cohort --------------------------------------------------------

def _stratified_db(tmp_path, vendors=("VendorA", "VendorB"), per_vendor=12):
    """Products across several vendors, so strata can be formed."""
    directory = tmp_path / "csaf"
    directory.mkdir()
    n = 0
    for vendor in vendors:
        for i in range(per_vendor):
            # Pre-cutoff: a varying number of CVEs so scores differ.
            before = _advisory(f"ICSA-20-{n:03d}-01", "2020-01-01", f"{vendor}-P{i}",
                               [f"CVE-2020-{n:04d}"], cvss=4.0 + (i % 6))
            before["product_tree"]["branches"][0]["name"] = vendor
            (directory / f"b{n}.json").write_text(json.dumps(before))
            n += 1
            # Post-cutoff: a varying number, so outcomes differ.
            after = _advisory(f"ICSA-23-{n:03d}-01", "2023-01-01", f"{vendor}-P{i}",
                              [f"CVE-2023-{n:04d}-{k}" for k in range(i % 4)])
            after["product_tree"]["branches"][0]["name"] = vendor
            if after["vulnerabilities"]:
                (directory / f"a{n}.json").write_text(json.dumps(after))
            n += 1
    connection, _ = index.build(str(tmp_path / "s.db"), str(directory))
    return connection


def test_strata_are_formed_per_vendor(tmp_path):
    connection = _stratified_db(tmp_path)
    result = backtest.run(connection, cutoff="2022-01-01", permutations=0)
    matched = backtest.matched_cohort(result, min_stratum=5, permutations=0)
    assert matched.usable_strata == 2
    assert {s.vendor for s in matched.strata} == {"VendorA", "VendorB"}
    assert all(s.products >= 5 for s in matched.strata)


def test_small_vendors_are_excluded(tmp_path):
    connection = _stratified_db(tmp_path, per_vendor=12)
    result = backtest.run(connection, cutoff="2022-01-01", permutations=0)
    assert backtest.matched_cohort(result, min_stratum=50,
                                   permutations=0).usable_strata == 0


def test_strata_without_variation_are_dropped_not_averaged(tmp_path):
    """A vendor whose products all scored alike carries no ordering.

    Counting it would inflate the apparent sample without adding information.
    """
    directory = tmp_path / "csaf"
    directory.mkdir()
    for i in range(12):
        # Identical CVSS and no later CVEs: no variation on either axis.
        document = _advisory(f"ICSA-20-{i:03d}-01", "2020-01-01", f"Flat-P{i}",
                             [f"CVE-2020-{i:04d}"], cvss=7.5)
        document["product_tree"]["branches"][0]["name"] = "FlatVendor"
        (directory / f"f{i}.json").write_text(json.dumps(document))
    connection, _ = index.build(str(tmp_path / "f.db"), str(directory))

    result = backtest.run(connection, cutoff="2022-01-01", permutations=0)
    matched = backtest.matched_cohort(result, min_stratum=5, permutations=0)
    assert matched.usable_strata == 0
    assert matched.dropped_no_variation == 1
    assert "No vendor had enough products" in backtest.format_matched(matched)


def test_centered_ranks_remove_the_stratum_level():
    """Centring is what makes strata poolable."""
    centred = backtest._centered_ranks([10, 20, 30])
    assert sum(centred) == pytest.approx(0.0)
    # Only the ordering survives, not the values.
    assert backtest._centered_ranks([10, 20, 30]) == \
           backtest._centered_ranks([1000, 2000, 3000])


def test_pooled_correlation_matches_spearman_for_one_stratum():
    scores = [1, 2, 3, 4, 5]
    outcomes = [5, 4, 3, 2, 1]
    assert backtest._pooled_correlation([(scores, outcomes)]) == pytest.approx(
        backtest._spearman(scores, outcomes))


def test_pooled_correlation_ignores_between_stratum_level():
    """Two strata with opposite levels but identical internal ordering.

    A naive pooled correlation would be driven by the level difference; the
    matched design must see only the within-stratum agreement.
    """
    low = ([1, 2, 3, 4], [1, 2, 3, 4])
    high = ([101, 102, 103, 104], [101, 102, 103, 104])
    assert backtest._pooled_correlation([low, high]) == pytest.approx(1.0)


def test_permutation_shuffles_within_strata(tmp_path):
    """The null must preserve the stratification, or it tests the wrong thing."""
    connection = _stratified_db(tmp_path)
    result = backtest.run(connection, cutoff="2022-01-01", permutations=0)
    a = backtest.matched_cohort(result, min_stratum=5, permutations=100, seed=3)
    b = backtest.matched_cohort(result, min_stratum=5, permutations=100, seed=3)
    assert a.p_value == b.p_value
    assert 0.0 < a.p_value <= 1.0


def test_leave_one_out_is_reported(tmp_path):
    """A pooled figure one vendor carries must not pass unnoticed."""
    connection = _stratified_db(tmp_path, vendors=("Big", "Small"), per_vendor=12)
    result = backtest.run(connection, cutoff="2022-01-01", permutations=0)
    matched = backtest.matched_cohort(result, min_stratum=5, permutations=0)
    assert matched.largest_vendor in ("Big", "Small")
    text = backtest.format_matched(matched)
    assert "leave-one-out" in text


def test_matched_report_states_its_residual_limitation(tmp_path):
    connection = _stratified_db(tmp_path)
    result = backtest.run(connection, cutoff="2022-01-01", permutations=0)
    text = backtest.format_matched(
        backtest.matched_cohort(result, min_stratum=5, permutations=0))
    # Removing the vendor effect does not remove product-level exposure.
    assert "vendor-level part" in text
