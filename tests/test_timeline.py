"""Tests for the advisory-history timeline.

The shape this module draws is only trustworthy if the quiet parts of it are
measured rather than assumed, so the tests concentrate there: gap years must
be zero-filled rows and not missing ones, undated advisories must surface as
a stated figure instead of vanishing, "quiet for" must come from the corpus
rather than the wall clock, and a fixture with no CVSS must yield None -- not
a zero that reads like a measured score.
"""

import json

import pytest

from retrust import index, timeline


def _advisory(advisory_id, released, branches, vulnerabilities):
    tracking = {"id": advisory_id}
    if released:
        tracking["initial_release_date"] = f"{released}T00:00:00Z"
    return {"document": {"title": "Test", "tracking": tracking},
            "product_tree": {"branches": branches},
            "vulnerabilities": vulnerabilities}


def _vendor(name, families):
    """One CSAF vendor branch. `families` maps a product name to its leaf ids."""
    return {"category": "vendor", "name": name, "branches": [
        {"category": "product_name", "name": family, "branches": [
            {"category": "product_version_range", "name": "vers:intdot/<2.0",
             "product": {"product_id": product_id, "name": family}}
            for product_id in product_ids]}
        for family, product_ids in families.items()]}


def _vulnerability(cve, product_ids, cvss=None, remediation=None):
    entry = {"cve": cve, "product_status": {"known_affected": list(product_ids)}}
    if cvss is not None:
        entry["scores"] = [{"cvss_v3": {"baseScore": cvss},
                            "products": list(product_ids)}]
    if remediation:
        entry["remediations"] = [{"category": remediation}]
    return entry


# Four advisories: two in 2019 for the PLC, one in 2022 for a second product,
# and one with no release date at all -- the real corpus carries such files,
# and they must surface as a stated figure rather than vanish.
EARLY = _advisory(
    "ICSA-19-010-01", "2019-02-01",
    [_vendor("Testco Electric", {"TestPLC 9000": ["P1"]})],
    [_vulnerability("CVE-2019-0001", ["P1"], 5.0, "vendor_fix")])

LATE_2019 = _advisory(
    "ICSA-19-200-01", "2019-08-01",
    [_vendor("Testco Electric", {"TestPLC 9000": ["P1"]})],
    [_vulnerability("CVE-2019-0002", ["P1"], 9.8, "none_available")])

# The HMI advisory carries no CVSS at all: worst_cvss must be None, not zero.
HMI_2022 = _advisory(
    "ICSA-22-074-01", "2022-03-15",
    [_vendor("Testco Electric", {"TestHMI 100": ["P2"]})],
    [_vulnerability("CVE-2022-0003", ["P2"], None, "mitigation")])

UNDATED = _advisory(
    "ICSA-00-000-01", None,
    [_vendor("Testco Electric", {"TestPLC 9000": ["P1"]})],
    [_vulnerability("CVE-2020-0004", ["P1"], 7.0, "vendor_fix")])


@pytest.fixture
def db(tmp_path):
    directory = tmp_path / "csaf"
    directory.mkdir()
    for number, advisory in enumerate([EARLY, LATE_2019, HMI_2022, UNDATED]):
        (directory / f"a{number}.json").write_text(json.dumps(advisory))
    connection, _ = index.build(str(tmp_path / "t.db"), str(directory))
    return connection


def _pairs(connection, name_key):
    """The (advisory, product) rows a resolution of this product would name."""
    return [(row["advisory_id"], row["product_id"]) for row in connection.execute(
        "SELECT advisory_id, product_id FROM product WHERE name_key = ?",
        (name_key,))]


def _bars(text):
    """The bar token of each year row, keyed by the four-char year."""
    rows = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].isdigit() and len(parts[0]) == 4:
            rows[parts[0]] = parts[1]
    return rows


def test_gap_years_are_zero_filled_rows_not_missing_ones(db):
    line = timeline.for_vendor(db, "testco")
    assert [bucket.year for bucket in line.years] == [2019, 2020, 2021, 2022]
    gaps = [bucket for bucket in line.years if bucket.year in (2020, 2021)]
    assert all(b.advisories == 0 and b.cves == 0 for b in gaps)
    bars = _bars(timeline.format_report("Testco", line))
    assert bars["2020"] == "." and bars["2021"] == "."


def test_bars_scale_to_the_busiest_year(db):
    line = timeline.for_vendor(db, "testco")
    bars = _bars(timeline.format_report("Testco", line))
    assert bars["2019"] == "##"      # two advisories: the peak sets the scale
    assert bars["2022"] == "#"


def test_a_towering_year_caps_at_the_bar_width_and_a_lone_advisory_shows():
    tall = timeline.Timeline(
        years=[timeline.YearBucket(2000, advisories=400, cves=400),
               timeline.YearBucket(2001, advisories=1, cves=1)],
        advisories=401, cves=401, first="2000-01-01", last="2001-06-01",
        as_of="2001-06-01")
    report = timeline.format_report("X", tall)
    bars = _bars(report)
    assert bars["2000"] == "#" * timeline.BAR_WIDTH
    assert bars["2001"] == "#"       # a fraction of a mark, still visible
    # The width cap is the point: no line may spill an 80-column terminal.
    assert max(len(line) for line in report.splitlines()) <= 80


def test_undated_advisories_surface_instead_of_vanishing(db):
    line = timeline.for_vendor(db, "testco")
    assert line.undated == 1
    assert line.advisories == 4      # the undated advisory still counts
    text = timeline.format_report("Testco", line)
    assert "undated" in text and "1 advisory" in text


def test_an_undated_advisory_is_not_guessed_into_a_year(db):
    """Its CVE id says 2020, but a CVE id is not a release date."""
    line = timeline.for_vendor(db, "testco")
    year_2020 = next(b for b in line.years if b.year == 2020)
    assert year_2020.advisories == 0 and year_2020.cves == 0


def test_worst_cvss_is_none_when_no_finding_carried_one(db):
    line = timeline.for_vendor(db, "testco")
    year_2022 = next(b for b in line.years if b.year == 2022)
    assert year_2022.worst_cvss is None
    row = next(l for l in timeline.format_report("T", line).splitlines()
               if l.split()[:1] == ["2022"])
    assert "--" in row and "0.0" not in row


def test_for_vendor_spans_more_than_one_product(db):
    line = timeline.for_vendor(db, "testco")
    assert line.advisories == 4      # three PLC advisories plus the HMI's
    assert line.cves == 4
    only_plc = timeline.build(db, _pairs(db, "testplc9000"))
    assert only_plc.advisories == 3  # the HMI advisory is the difference


def test_quiet_months_come_from_the_corpus_not_the_clock(db):
    only_plc = timeline.build(db, _pairs(db, "testplc9000"))
    assert only_plc.last == "2019-08-01"
    assert only_plc.as_of == "2022-03-15"    # the HMI advisory, corpus-wide
    # 2019-08-01 to 2022-03-15 is 31 whole months. A clock-based figure would
    # grow every month this test sat in the repository.
    assert only_plc.quiet_months == 31
    assert "as of 2022-03-15" in timeline.format_report("PLC", only_plc)


def test_a_product_as_new_as_the_corpus_is_quiet_for_zero_months(db):
    line = timeline.for_vendor(db, "testco")
    assert line.last == line.as_of == "2022-03-15"
    assert line.quiet_months == 0


def test_build_is_deterministic_whatever_the_pair_order(db):
    pairs = _pairs(db, "testplc9000")
    first = timeline.build(db, list(reversed(pairs)))
    second = timeline.build(db, pairs)
    assert first == second
    assert (timeline.format_report("X", first)
            == timeline.format_report("X", second))


def test_fix_share_trend_splits_the_record_in_half(db):
    line = timeline.for_vendor(db, "testco")
    first_half, second_half = line.fix_trend
    assert first_half == 0.5     # 2019-2020: one vendor fix in two advisories
    assert second_half == 0.0    # 2021-2022: the HMI got mitigation only
    flat = " ".join(timeline.format_report("Testco", line).split())
    assert "50% of 2019-2020" in flat
    assert "0% of 2021-2022" in flat


def test_a_single_year_record_reports_an_overall_fix_share(db):
    only_plc = timeline.build(db, _pairs(db, "testplc9000"))
    assert only_plc.fix_trend == (None, None)
    # Two of three: EARLY and the undated advisory offer a fix, LATE does not.
    assert "2/3 advisories" in timeline.format_report("PLC", only_plc)


def test_an_empty_selection_explains_itself_without_crashing(db):
    line = timeline.build(db, [])
    assert line.advisories == 0 and line.years == []
    flat = " ".join(timeline.format_report("Nothing", line).split())
    assert "no history" in flat.lower()
    assert "not evidence of safety" in flat


def test_the_report_states_its_own_caveat(db):
    line = timeline.for_vendor(db, "testco")
    flat = " ".join(timeline.format_report("Testco", line).split())
    assert "disclosure activity, not safety" in flat
    assert "discontinued" in flat
