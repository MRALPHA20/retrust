"""Tests for the vendor profile.

The arithmetic matters, but the last test in this file is the important one.
ReTrust's central rule is that raw CVE counts are never presented as a risk
judgement: a manufacturer that discloses diligently would otherwise rank below
one that stays quiet, which is exactly backwards. A vendor-level view is the
obvious place for that rule to get broken by accident, so the honesty test
asserts that no verdict, band or grade ever reaches the printed page, and that no
field of the dataclass is named as though it held one.

The second theme is abstention. Several figures are None when the thing was not
measured -- no KEV loaded, no CVSS in the corpus, no cache supplied -- and a 0
printed in their place would read as a clean bill of health from a check that
never ran.
"""

import dataclasses
import json

import pytest

from retrust import certification, dossier, index, score, supplychain


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
        entry["scores"] = [{"cvss_v3": {"baseScore": cvss}, "products": list(product_ids)}]
    if remediation:
        entry["remediations"] = [{"category": remediation}]
    return entry


# Two advisories naming one manufacturer spelled two ways, plus an unrelated
# vendor sharing the first advisory -- the leak a missing vendor_key predicate on
# any of the queries would cause.
FIRST = _advisory(
    "ICSA-26-001-01", "2026-01-01",
    [_vendor("Testco Electric", {"TestPLC 9000": ["P1", "P1b"], "TestHMI 100": ["P2"]}),
     _vendor("Otherco", {"OtherBox": ["P9"]})],
    [_vulnerability("CVE-2026-0001", ["P1", "P1b", "P2"], 9.8, "vendor_fix"),
     _vulnerability("CVE-2026-0009", ["P9"], 3.1, "none_available")])

SECOND = _advisory(
    "ICSA-26-002-01", "2026-03-04",
    [_vendor("Testco Electric Corporation", {"TestPLC 9000": ["P1"]})],
    [_vulnerability("CVE-2026-0002", ["P1"], 7.5, "mitigation")])


def _flat(profile):
    """The report with its line breaks collapsed.

    The prose is wrapped to the terminal at print time, so asserting on a phrase
    against the raw text would break the moment a sentence is reworded by a word.
    """
    return " ".join(dossier.format_report(profile).split())


def _built(tmp_path, *advisories):
    directory = tmp_path / "csaf"
    directory.mkdir(parents=True, exist_ok=True)
    for number, advisory in enumerate(advisories):
        (directory / f"a{number}.json").write_text(json.dumps(advisory))
    connection, _ = index.build(str(tmp_path / "t.db"), str(directory))
    return connection


@pytest.fixture
def db(tmp_path):
    return _built(tmp_path, FIRST, SECOND)


def test_spellings_collapse_and_are_counted(db):
    """Showing the raw spellings is how a user learns the name to type."""
    profile = dossier.build(db, "Testco Electric")
    assert profile.vendor_key == "testco"
    assert profile.spellings == [("Testco Electric", 3),
                                 ("Testco Electric Corporation", 1)]
    assert profile.vendor == "Testco Electric"          # the commonest spelling
    assert "Testco Electric Corporation" in dossier.format_report(profile)


def test_counts_only_this_vendor(db):
    """Otherco shares the first advisory; none of it may reach Testco's profile."""
    profile = dossier.build(db, "Testco Electric")
    assert (profile.advisories, profile.products, profile.cves) == (2, 4, 2)
    assert "no_fix" not in profile.remediation           # Otherco's none_available
    assert all(name != "OtherBox" for name, _ in profile.top_products)


def test_first_and_last_advisory_dates(db):
    profile = dossier.build(db, "Testco")
    assert (profile.first_advisory, profile.last_advisory) == ("2026-01-01", "2026-03-04")


def test_an_undated_advisory_never_becomes_the_first_date(tmp_path):
    """CSAF leaves an empty string when it omits the release date."""
    undated = _advisory("ICSA-26-003-01", None,
                        [_vendor("Testco Electric", {"TestPLC 9000": ["P1"]})],
                        [_vulnerability("CVE-2026-0003", ["P1"], 5.0, "vendor_fix")])
    profile = dossier.build(_built(tmp_path, FIRST, SECOND, undated), "Testco")
    assert profile.advisories == 3
    assert (profile.first_advisory, profile.last_advisory) == ("2026-01-01", "2026-03-04")


def test_peak_and_median_cvss(db):
    profile = dossier.build(db, "Testco")
    assert profile.peak_cvss == pytest.approx(9.8)
    assert profile.median_cvss == pytest.approx(8.65)   # mean of the two middle values


def test_cvss_is_none_when_the_corpus_gives_no_score(tmp_path):
    unscored = _advisory("ICSA-26-004-01", "2026-04-01",
                         [_vendor("Testco Electric", {"TestPLC 9000": ["P1"]})],
                         [_vulnerability("CVE-2026-0004", ["P1"])])
    profile = dossier.build(_built(tmp_path, unscored), "Testco")
    assert profile.cves == 1
    assert profile.peak_cvss is None and profile.median_cvss is None
    text = dossier.format_report(profile)
    assert "not recorded" in text
    assert "0.0" not in text                            # never a score we did not measure


def test_remediation_buckets_separate_a_fix_from_a_mitigation(db):
    """A mitigation is neither a fix nor a statement that no fix exists."""
    profile = dossier.build(db, "Testco")
    assert profile.remediation == {"vendor_fix": 1, "mitigation_only": 1}
    assert sum(profile.remediation.values()) == profile.advisories
    assert "mitigation or workaround only" in dossier.format_report(profile)


def test_an_advisory_that_says_nothing_about_this_vendor_is_still_bucketed(tmp_path):
    """Every advisory counted above has to appear in the remediation table.

    An advisory can name a vendor's product in its product tree and then attach
    every vulnerability to somebody else's. Joining the remediation table through
    those vulnerabilities alone dropped 11 of Schneider's 244 advisories on the
    live corpus -- counted at the top of the report, absent from the table.
    """
    silent = _advisory("ICSA-26-006-01", "2026-06-01",
                       [_vendor("Testco Electric", {"TestRTU 1": ["P5"]}),
                        _vendor("Otherco", {"OtherBox": ["P9"]})],
                       [_vulnerability("CVE-2026-0006", ["P9"], 4.0, "vendor_fix")])
    profile = dossier.build(_built(tmp_path, FIRST, SECOND, silent), "Testco")
    assert profile.advisories == 3
    assert profile.remediation["nothing_stated"] == 1
    assert sum(profile.remediation.values()) == profile.advisories


def test_kev_abstains_until_kev_is_loaded(db):
    """A bare 0 cannot be told apart from a catalogue that was never loaded."""
    profile = dossier.build(db, "Testco")
    assert profile.kev_cves is None
    kev_line = next(line for line in dossier.format_report(profile).splitlines()
                    if "CISA KEV" in line)
    assert kev_line.endswith("not checked")


def test_kev_counts_after_loading(db, tmp_path):
    path = tmp_path / "kev.json"
    path.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-0001"},
                                                    {"cveID": "CVE-2026-9999"}]}))
    index.load_exploitation(db, kev_path=str(path))
    profile = dossier.build(db, "Testco")
    assert profile.kev_cves == 1            # CVE-2026-9999 affects nothing here


def test_csaf_feed_is_read_from_score_not_copied(db, monkeypatch):
    """The publisher list lives in score.py; a copy here would go stale unseen."""
    assert dossier.build(db, "Testco").csaf_feed is None
    assert "relies on CISA republishing" in dossier.format_report(
        dossier.build(db, "Testco"))

    feed = "https://example.invalid/provider-metadata.json"
    monkeypatch.setattr(dossier.score, "CSAF_PUBLISHERS", {"testco": feed})
    assert feed in dossier.format_report(dossier.build(db, "Testco"))


def test_top_products_rank_by_advisory_count(db):
    """TestPLC 9000 holds three product rows but is named in two advisories."""
    profile = dossier.build(db, "Testco")
    assert profile.top_products == [("TestPLC 9000", 2), ("TestHMI 100", 1)]
    assert profile.product_names == 2


def test_any_spelling_of_the_vendor_gives_the_same_profile(db):
    typed = dossier.build(db, "TESTCO CORPORATION")     # a spelling the corpus lacks
    assert typed == dossier.build(db, "Testco Electric")


def test_unknown_vendor_is_flagged_and_claims_nothing(db):
    profile = dossier.build(db, "Fictional Robotics")
    assert not profile.known
    assert (profile.advisories, profile.products, profile.cves) == (0, 0, 0)
    assert profile.peak_cvss is None and profile.remediation == {}
    text = dossier.format_report(profile)
    assert "not in the corpus" in text
    assert "not evidence of safety" in text


@pytest.mark.parametrize("vendor", ["Siemens", "", None, "-"])
def test_empty_index_does_not_raise(tmp_path, vendor):
    connection = index.connect(str(tmp_path / "empty.db"))
    profile = dossier.build(connection, vendor)
    assert not profile.known
    assert profile.kev_cves is None and profile.peak_cvss is None
    assert "not in the corpus" in dossier.format_report(profile)


@pytest.mark.parametrize("vendor", ["", None, "-", "()"])
def test_a_name_that_normalises_to_nothing_profiles_nothing(db, vendor):
    """The empty key is also the key of a product whose advisory named no vendor."""
    profile = dossier.build(db, vendor)
    assert not profile.known and profile.spellings == []
    assert "not in the corpus" in dossier.format_report(profile)


def test_optional_arguments_say_when_a_check_did_not_run(db):
    """"Not checked" and "nothing found" must never be confused for each other."""
    profile = dossier.build(db, "Testco")
    assert profile.certificates is None and profile.screening_gates is None
    text = dossier.format_report(profile)
    assert "no certification cache loaded" in text
    assert "no screening cache loaded" in text
    assert "no match for" not in text           # the wording used when a check did run


def _screening(tmp_path, name, alt_names=()):
    """A one-entity screening cache, loaded the way `retrust refresh` leaves it."""
    (tmp_path / "screening.json").write_text(json.dumps([{
        "name": name, "type": "entity", "programs": "", "country": "",
        "source": "Specially Designated Nationals (SDN) - Treasury Department",
        "url": "https://example.invalid/sdn", "alt_names": list(alt_names)}]))
    return supplychain.load(str(tmp_path))


def test_a_missing_sanctions_cache_is_never_reported_as_a_clean_screen(db, tmp_path):
    """supplychain.load still returns its ten covered-list entries with no cache.

    Saying only "no match" off the back of those ten would be a clean sanctions
    screen that nobody ran.
    """
    profile = dossier.build(db, "Testco", screening=supplychain.load(str(tmp_path)))
    assert not profile.sanctions_checked
    flat = _flat(profile)
    assert "sanctions list is not cached" in flat
    assert 'no match for "Testco Electric" on the covered lists' in flat


def test_a_loaded_sanctions_cache_is_reported_as_searched(db, tmp_path):
    screening = _screening(tmp_path, "Unrelated Trading House")
    profile = dossier.build(db, "Testco", screening=screening)
    assert profile.sanctions_checked
    flat = _flat(profile)
    assert "sanctions list is not cached" not in flat
    assert 'no match for "Testco Electric" on the sanctions and covered lists' in flat


def test_a_name_collision_is_never_printed_beneath_a_clean_no_match(db, tmp_path):
    """An advisory hit and "nothing matched" would contradict each other.

    supplychain refuses to gate on an alias, and rightly so, but the collision it
    reports instead is the opposite of no match at all.
    """
    screening = _screening(tmp_path, "Unrelated Trading House",
                           alt_names=["Testco Electric"])
    profile = dossier.build(db, "Testco", screening=screening)
    assert not profile.screening_gates and profile.screening_notes
    flat = _flat(profile)
    assert "A listed entity shares this name" in flat        # notes_for's own wording
    assert "no match for" not in flat


def test_screening_gate_is_shown_even_for_an_unknown_vendor(db, tmp_path):
    """No advisory names them, and they are still on a covered list."""
    screening = supplychain.load(str(tmp_path))      # no cache file: COVERED_LIST only
    profile = dossier.build(db, "Huawei Technologies", screening=screening)
    assert not profile.known
    assert profile.screening_gates
    text = dossier.format_report(profile)
    assert "Named on a covered list" in text         # gates_for's own wording
    assert "fcc.gov" in text


def test_certificates_come_from_the_loader(db, tmp_path):
    (tmp_path / "certifications.json").write_text(json.dumps([{
        "scheme": "IEC 62443-4-1", "vendor": "Testco Electric Corporation",
        "product": "Taipei, Taiwan", "detail": "SDLA 3.0.0 | 2026-02-19",
        "source": "https://isasecure.org/"}]))
    certificates = certification.load(str(tmp_path))
    text = dossier.format_report(dossier.build(db, "Testco", certificates=certificates))
    assert "IEC 62443-4-1" in text and "SDLA 3.0.0" in text


def test_an_uncertified_vendor_is_not_penalised(db):
    """Most OT products are never submitted, so absence is not a mark against them.

    The cache has to hold somebody, or this would be testing the case below:
    certification.load() returns {} for a cache that was never downloaded, so an
    empty one says nothing about this vendor either way.
    """
    cache = {"someoneelse": [{"scheme": "IEC 62443-4-1", "vendor": "Someone Else",
                              "product": "Other PLC", "detail": ""}]}
    text = dossier.format_report(dossier.build(db, "Testco", certificates=cache))
    assert "never submitted for certification" in text
    assert "no certification cache loaded" not in text


def test_an_empty_certification_cache_reads_as_not_checked(db):
    """{} is what load() returns for a cache nobody downloaded.

    Reporting "no certificate found" from it would be a statement about the
    cache dressed up as one about the manufacturer.
    """
    text = dossier.format_report(dossier.build(db, "Testco", certificates={}))
    assert "no certification cache loaded" in text
    assert "never submitted for certification" not in text


@pytest.mark.parametrize("vendor", ["%", "_", "%_%", "Test%", "Testco' OR 1=1 --",
                                    "'; DROP TABLE product;--", "Ünïcödé", "西门子"])
def test_a_hostile_query_matches_nothing_and_changes_nothing(db, vendor):
    """Nothing here is a LIKE pattern, and every value is a bound parameter.

    "Test%" is the telling one: the profile is keyed by equality, so a wildcard
    cannot widen it into the prefix match that would reach Testco.
    """
    profile = dossier.build(db, vendor)
    assert not profile.known and (profile.products, profile.cves) == (0, 0)
    assert "not in the corpus" in dossier.format_report(profile)
    assert db.execute("SELECT COUNT(*) FROM product").fetchone()[0] == 5


def test_a_typed_newline_cannot_forge_a_line(db):
    """The vendor argument is echoed back in the heading, so it must stay one line."""
    forged = dossier.build(db, "Testco\nWHAT THE INDEX HOLDS\n  advisories  9,999")
    lines = dossier.format_report(forged).splitlines()
    assert lines[0] == "VENDOR DOSSIER   Testco WHAT THE INDEX HOLDS advisories 9,999"
    assert not [line for line in lines[1:] if "9,999" in line]


def test_unicode_survives_the_tables(tmp_path):
    """The corpus carries 219 product names outside ASCII, en dashes included."""
    name = "Steuerung – Ünït ①"
    advisory = _advisory("ICSA-26-007-01", "2026-07-01",
                         [_vendor("Testco Eléctrica", {name: ["P1"]})],
                         [_vulnerability("CVE-2026-0007", ["P1"], 6.0, "vendor_fix")])
    profile = dossier.build(_built(tmp_path, advisory), "Testco Eléctrica")
    assert profile.top_products == [(name, 1)]
    assert name in dossier.format_report(profile)


def test_long_names_cannot_break_the_eighty_column_layout(tmp_path):
    """The real corpus holds 330-character product names and 50-character keys."""
    vendor = "Testco Electric, a subsidiary of " + "Very Long Holdings " * 4
    advisory = _advisory("ICSA-26-005-01", "2026-05-01",
                         [_vendor(vendor, {"TestPLC 9000 " * 30: ["P1"]})],
                         [_vulnerability("CVE-2026-0005", ["P1"], 7.0, "vendor_fix")])
    profile = dossier.build(_built(tmp_path, advisory), vendor)
    assert profile.known
    widest = max(len(line) for line in dossier.format_report(profile).splitlines())
    assert widest <= 80, widest


def test_report_never_grades_the_vendor(db):
    """The honesty test: the counts are description, never a verdict.

    README: "Raw CVE counts are never scored. A vendor that discloses diligently
    would rank below one that stays quiet - exactly backwards." Nothing in this
    module may quietly reintroduce that, in the text or in the dataclass.
    """
    text = dossier.format_report(dossier.build(db, "Testco"))
    assert "does not score or rank vendors" in text
    assert "/100" not in text
    for _, band in score.BANDS:                 # PREFER / CONDITIONAL / AVOID
        assert band not in text

    names = {field.name for field in dataclasses.fields(dossier.Dossier)}
    assert not [name for name in names for word in
                ("score", "grade", "rating", "band", "rank", "verdict") if word in name]
