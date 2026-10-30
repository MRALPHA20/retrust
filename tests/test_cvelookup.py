"""Tests for the CVE-first lookup.

The pivot this module serves is mid-incident, which is exactly when a wrong
answer costs most. Two confusions matter more than any arithmetic: a CVE
absent from the whole index must not read the same as one CISA lists but no
corpus product carries, and an exploitation signal nobody loaded must print
as absent rather than as a reassuring zero. The tests concentrate there.
"""

import json

import pytest

from retrust import cvelookup, index, lev

WORMABLE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


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


def _vulnerability(cve, product_ids, cvss=None, remediation=None, vector=None):
    entry = {"cve": cve, "product_status": {"known_affected": list(product_ids)}}
    if cvss is not None:
        score = {"baseScore": cvss}
        if vector:
            score["vectorString"] = vector
        entry["scores"] = [{"cvss_v3": score, "products": list(product_ids)}]
    if remediation:
        entry["remediations"] = [{"category": remediation}]
    return entry


def _build(tmp_path, advisories, name="t"):
    directory = tmp_path / f"csaf-{name}"
    directory.mkdir()
    for number, advisory in enumerate(advisories):
        (directory / f"a{number}.json").write_text(json.dumps(advisory))
    connection, _ = index.build(str(tmp_path / f"{name}.db"), str(directory))
    return connection


# CVE-2026-0001 spans two advisories, two vendors, a fix and a mitigation,
# and its worst score carries a wormable vector. CVE-2026-0002 has neither a
# score nor an exploitation row: the all-absent case the report must survive.
PLC = _advisory(
    "ICSA-26-001-01", "2026-01-01",
    [_vendor("Testco Electric", {"TestPLC 9000": ["P1"]})],
    [_vulnerability("CVE-2026-0001", ["P1"], 9.8, "vendor_fix",
                    vector=WORMABLE)])

HMI = _advisory(
    "ICSA-26-050-01", "2026-02-19",
    [_vendor("Otherco", {"TestHMI 100": ["P2"]})],
    [_vulnerability("CVE-2026-0001", ["P2"], 5.0, "mitigation"),
     _vulnerability("CVE-2026-0002", ["P2"])])


@pytest.fixture
def db(tmp_path):
    connection = _build(tmp_path, [PLC, HMI])
    # CVE-1999-9999 is the KEV-only case: CISA lists it, no advisory here
    # names it, and the EPSS loader filters it out as outside the corpus.
    (tmp_path / "kev.json").write_text(json.dumps({"vulnerabilities": [
        {"cveID": "CVE-2026-0001", "knownRansomwareCampaignUse": "Known",
         "dateAdded": "2026-02-01"},
        {"cveID": "CVE-1999-9999", "dateAdded": "2020-05-04"}]}))
    (tmp_path / "epss.csv").write_text(
        "#model_version:test\ncve,epss,percentile\n"
        "CVE-2026-0001,0.5,0.9\nCVE-1999-9999,0.1,0.2\n")
    index.load_exploitation(connection, str(tmp_path / "kev.json"),
                            str(tmp_path / "epss.csv"))
    return connection


# --- the two "not here" cases, kept distinct --------------------------------

def test_a_cve_the_whole_index_never_met_is_none(db):
    assert cvelookup.lookup(db, "CVE-2000-0000") is None


def test_a_kev_only_cve_is_a_view_that_says_no_corpus_product_carries_it(db):
    view = cvelookup.lookup(db, "CVE-1999-9999")
    assert view is not None
    assert view.in_kev and not view.in_corpus
    assert view.kev_added == "2020-05-04"
    assert view.advisories == [] and view.products == 0
    flat = " ".join(cvelookup.format_report(view).split())
    assert "no OT product in this corpus carries it" in flat
    # The distinct wording must not leak into a report that has a spread.
    carried = cvelookup.format_report(cvelookup.lookup(db, "CVE-2026-0001"))
    assert "no OT product in this corpus carries it" not in carried


# --- a corpus CVE with both signals -----------------------------------------

def test_a_corpus_cve_reports_kev_epss_and_the_spread(db):
    view = cvelookup.lookup(db, "CVE-2026-0001")
    assert view.in_corpus and view.in_kev and view.ransomware
    assert view.kev_added == "2026-02-01"
    assert view.epss == pytest.approx(0.5)
    # Newest advisory first: mid-incident the current one is the one wanted.
    assert view.advisories == [("ICSA-26-050-01", "2026-02-19"),
                               ("ICSA-26-001-01", "2026-01-01")]
    assert view.products == 2
    assert view.vendors == ["Otherco", "Testco Electric"]


def test_the_worst_cvss_wins_and_its_vector_is_the_one_read(db):
    view = cvelookup.lookup(db, "CVE-2026-0001")
    assert view.cvss == 9.8            # the PLC's score, not the HMI's 5.0
    assert view.vector == {"remote": True, "unauthenticated": True,
                           "hands_off": True, "wormable": True}
    flat = " ".join(cvelookup.format_report(view).split())
    assert "spreads on its own" in flat


def test_remediation_counts_advisories_per_category_best_first(db):
    view = cvelookup.lookup(db, "CVE-2026-0001")
    assert view.remediation == {"vendor_fix": 1, "mitigation": 1}
    assert list(view.remediation) == ["vendor_fix", "mitigation"]
    assert "vendor_fix in 1, mitigation in 1" in cvelookup.format_report(view)


def test_lowercase_and_padded_input_reach_the_same_view(db):
    plain = cvelookup.lookup(db, "CVE-2026-0001")
    assert cvelookup.lookup(db, "cve-2026-0001") == plain
    assert cvelookup.lookup(db, "  cve-2026-0001 ") == plain


# --- absences printed as absences, never as zeros ---------------------------

def test_an_absent_epss_prints_as_absent_not_as_zero(db):
    view = cvelookup.lookup(db, "CVE-2026-0002")
    assert view.epss is None and not view.in_kev
    text = cvelookup.format_report(view)
    assert "not a zero" in text
    assert "0.000" not in text
    # An unscored finding is a gap, not a low score.
    assert view.cvss is None
    assert "none recorded" in text


def test_an_unloaded_history_is_said_not_silently_skipped(db):
    view = cvelookup.lookup(db, "CVE-2026-0001")
    assert view.lev is None and view.history_loaded is False
    assert "no EPSS history loaded" in cvelookup.format_report(view)


def test_a_cached_lev_is_framed_and_an_unscored_cve_worded_differently(
        db, tmp_path):
    """"History not loaded" and "EPSS never scored it" are different facts."""
    (tmp_path / "epss_scores-2026-01-01.csv").write_text(
        "cve,epss,percentile\nCVE-2026-0001,0.4,0.9\n")
    index.load_epss_history(db, [str(tmp_path / "epss_scores-2026-01-01.csv")])
    history = index.epss_history(db, ["CVE-2026-0001"])
    index.store_lev(db, [lev.estimate("CVE-2026-0001",
                                      history["CVE-2026-0001"])])

    scored = cvelookup.lookup(db, "CVE-2026-0001")
    assert scored.history_loaded
    assert scored.lev["lev"] == pytest.approx(0.4 / 30)
    text = cvelookup.format_report(scored)
    assert f"{scored.lev['lev']:.3f}" in text
    assert "prompt to go and look" in " ".join(text.split())

    unscored = cvelookup.lookup(db, "CVE-2026-0002")
    assert unscored.history_loaded and unscored.lev is None
    flat = " ".join(cvelookup.format_report(unscored).split())
    # lev.py's dual wording: never scored, OR published since the last
    # snapshot -- the report cannot know which, and must not pick one.
    assert "either EPSS has never scored" in flat
    assert "published since the last snapshot" in flat
    assert "no EPSS history loaded" not in flat


# --- the caps, stated rather than silent ------------------------------------

def test_vendors_cap_at_eight_alphabetically_and_count_the_rest(tmp_path):
    branches = [_vendor(f"Vendor{n:02d}", {f"Thing {n}": [f"V{n}"]})
                for n in range(10)]
    connection = _build(tmp_path, [_advisory(
        "ICSA-26-100-01", "2026-03-01", branches,
        [_vulnerability("CVE-2026-0009", [f"V{n}" for n in range(10)])])],
        name="wide")
    view = cvelookup.lookup(connection, "CVE-2026-0009")
    assert view.vendors[:8] == [f"Vendor{n:02d}" for n in range(8)]
    assert view.vendors[8] == "and 2 more"
    assert view.products == 10       # the cap trims the listing, not the count


def test_a_long_advisory_list_is_elided_with_the_remainder_counted(tmp_path):
    advisories = [_advisory(
        f"ICSA-26-{200 + n}-01", f"2026-04-{n + 1:02d}",
        [_vendor("Testco", {"TestPLC 9000": ["P1"]})],
        [_vulnerability("CVE-2026-0010", ["P1"])]) for n in range(8)]
    connection = _build(tmp_path, advisories, name="many")
    view = cvelookup.lookup(connection, "CVE-2026-0010")
    assert len(view.advisories) == 8
    text = cvelookup.format_report(view)
    assert text.count("ICSA-26-") == cvelookup.MAX_ADVISORIES
    assert "and 2 more" in text


# --- the printed report -----------------------------------------------------

def test_every_report_stays_ascii_inside_eighty_columns(db):
    for cve in ("CVE-2026-0001", "CVE-2026-0002", "CVE-1999-9999"):
        text = cvelookup.format_report(cvelookup.lookup(db, cve))
        assert text.isascii(), cve
        assert all(len(line) <= 80 for line in text.splitlines()), cve


def test_every_report_ends_by_scoping_its_claims_to_this_corpus(db):
    for cve in ("CVE-2026-0001", "CVE-1999-9999"):
        tail = " ".join(cvelookup.format_report(
            cvelookup.lookup(db, cve)).splitlines()[-3:])
        assert "as indexed here, not the world" in tail, cve


def test_the_same_lookup_twice_prints_the_same_report(db):
    first = cvelookup.format_report(cvelookup.lookup(db, "CVE-2026-0001"))
    second = cvelookup.format_report(cvelookup.lookup(db, "CVE-2026-0001"))
    assert first == second
