"""Tests for sanctions screening and certification evidence.

The screening tests matter more than most. Wrongly telling a buyer that a
legitimate manufacturer is sanctioned is the worst error this tool can make, so
the false-positive cases below are the point of the file.
"""

import json

import os
import stat
import pytest

from retrust import certification, score, supplychain
from retrust.index import normalize_vendor

# Real OT manufacturers. None of these may ever raise a blocking gate.
LEGITIMATE_VENDORS = [
    "Siemens", "Schneider Electric", "Schneider Electric Software, LLC",
    "Rockwell Automation", "ABB", "Honeywell", "Moxa", "Yokogawa",
    "Mitsubishi Electric", "Mitsubishi Electric Corporation", "Phoenix Contact",
    "WAGO", "Emerson", "Omron", "General Electric", "Hitachi Energy",
    "Delta Electronics", "Advantech", "Festo", "Endress+Hauser",
]

# Entities on the FCC Covered List, in both full and common short form.
COVERED_VENDORS = [
    "Huawei", "Huawei Technologies Company", "ZTE", "ZTE Corporation",
    "Hikvision", "Hangzhou Hikvision Digital Technology",
    "Dahua", "Dahua Technology", "Hytera", "Kaspersky Lab",
]


@pytest.fixture(scope="module")
def screening():
    """The live index if it has been refreshed, otherwise covered-list only."""
    return supplychain.load("data")


@pytest.mark.parametrize("vendor", LEGITIMATE_VENDORS)
def test_no_false_positives(screening, vendor):
    blocking, _ = supplychain.screen(screening, vendor)
    assert blocking == [], (
        f"{vendor!r} was wrongly flagged as sanctioned by {blocking!r}. "
        "A false sanctions hit is the most damaging error this tool can make."
    )


@pytest.mark.parametrize("vendor", COVERED_VENDORS)
def test_covered_entities_are_blocked(screening, vendor):
    blocking, _ = supplychain.screen(screening, vendor)
    assert blocking, f"{vendor!r} is on the FCC Covered List but was not blocked"
    assert all(h["url"] for h in blocking), "every gate must cite a source"


def test_screening_key_preserves_identity():
    """The bug this guards: "Schneider Electric" matching "Schneider GMBH".

    index.normalize_vendor strips "Electric" so advisory spellings collapse.
    Screening must not, or unrelated companies sharing a surname collide.
    """
    assert supplychain.screening_key("Schneider Electric") != \
           supplychain.screening_key("Schneider GMBH")
    assert normalize_vendor("Schneider Electric") == normalize_vendor("Schneider GMBH")

    # Legal forms alone are still stripped, so spellings of one company agree.
    assert supplychain.screening_key("ZTE Corporation") == supplychain.screening_key("ZTE")
    assert supplychain.screening_key("Dahua Technology, Ltd.") == \
           supplychain.screening_key("Dahua Technology")


def test_screening_never_substring_matches(screening):
    """A vendor whose name merely contains a listed name must not hit."""
    for vendor in ["Huaweitech Systems GmbH", "Not Huawei", "ZTEC Instruments"]:
        blocking, _ = supplychain.screen(screening, vendor)
        assert blocking == [], f"{vendor!r} matched by substring, which is unsafe"


def test_unknown_vendor_is_clear(screening):
    assert supplychain.screen(screening, "Entirely Fictional Widgets") == ([], [])
    assert supplychain.screen(screening, "") == ([], [])
    assert supplychain.screen(screening, None) == ([], [])


def test_blocked_verdict_needs_no_resolution():
    """A sanctioned vendor absent from the advisory corpus is still AVOID."""
    gates = [{"gate": "Named on a covered list", "detail": "x", "source": "y"}]
    assessment = score.blocked("Huawei Switch", gates, "vendor not in corpus")
    assert assessment.verdict == "AVOID"
    assert assessment.score is None
    assert assessment.gates == gates


def test_not_assessed_gets_no_score():
    """The bug this guards: an unresolvable product scoring ~100 and ranking top.

    Every pillar reads "no CVEs" as good news, so an unresolved product must be
    kept out of scoring entirely rather than allowed to inherit that.
    """
    assessment = score.not_assessed("Unknown PLC", "vendor not in corpus")
    assert assessment.verdict == "NOT ASSESSED"
    assert assessment.score is None
    assert assessment.pillars == []


# --- certification ---------------------------------------------------------

def test_certification_absence_is_never_a_penalty():
    """Most OT products are never certified; that is not evidence of insecurity."""
    pillar = score._certification([])
    assert pillar.coverage == 0.0        # excluded from the composite entirely
    assert any("excluded from the score" in e for e in pillar.evidence)
    # The exclusion IS the non-penalty: a missing certificate changes nothing,
    # where the old neutral 50 moved rankings between equally certified vendors.


def test_certification_rewards_iec_62443():
    component = [{"scheme": "IEC 62443-4-2", "vendor": "ABB", "product": "X",
                  "matches_product": False}]
    process = [{"scheme": "IEC 62443-4-1", "vendor": "ABB", "product": "X",
                "matches_product": False}]
    assert score._certification(component).score > score._certification([]).score
    assert score._certification(component + process).score > \
           score._certification(component).score


def test_product_level_certificate_beats_vendor_level():
    vendor_only = [{"scheme": "IEC 62443-4-2", "vendor": "ABB", "product": "Other",
                    "matches_product": False}]
    product_level = [{"scheme": "IEC 62443-4-2", "vendor": "ABB", "product": "RTU500",
                      "matches_product": True}]
    assert score._certification(product_level).score > \
           score._certification(vendor_only).score


def test_certificates_for_flags_product_matches():
    by_vendor = {"testco": [
        {"scheme": "IEC 62443-4-2", "vendor": "Testco", "product": "TestPLC 9000"},
        {"scheme": "IEC 62443-4-1", "vendor": "Testco", "product": "Other Thing"},
    ]}
    found = certification.certificates_for(by_vendor, "Testco", "TestPLC 9000")
    assert len(found) == 2
    assert [c["matches_product"] for c in found] == [True, False]


def test_certificates_for_unknown_vendor_is_empty():
    assert certification.certificates_for({}, "Nobody", "Thing") == []


def test_isasecure_header_rows_are_skipped():
    """The scrape must not turn a table header into a certified vendor."""
    page = """<table>
      <tr><td>Picture</td><td>Type</td><td>Model</td><td>Version</td>
          <td>Certificate</td><td>Certification Date</td></tr>
      <tr><td>ABB</td><td>Controller</td><td>HPC800</td><td>HCA800B1</td>
          <td>EDSA 2010.1 Level 1</td><td>1/22/2018</td></tr>
    </table>"""
    rows = certification._scrape_isasecure(page, "IEC 62443-4-2")
    assert len(rows) == 1
    assert rows[0]["vendor"] == "ABB"


# --- patch availability ----------------------------------------------------

def _finding(remediation):
    from retrust.match import Finding
    return Finding(cve="CVE-2026-0001", advisory_id="ICSA-26-001-01", cvss=7.5,
                   cwe="CWE-79", epss=0.01, in_kev=False, ransomware=False,
                   version_range="vers:all/*", decided=True, remediation=remediation)


def test_vendor_fix_scores_above_workaround_only():
    fixed = score._patchability([_finding("vendor_fix")])
    mitigated = score._patchability([_finding("mitigation")])
    none_left = score._patchability([_finding("none_available")])
    assert fixed.score > mitigated.score > none_left.score
    assert none_left.score == 0.0


def test_patchability_reports_zero_coverage_when_unstated():
    pillar = score._patchability([_finding("unknown")])
    assert pillar.coverage == 0.0
    assert pillar.score == 50.0          # neutral, not a guess


# --- the tiering that prevents false accusations ---------------------------

def test_individuals_vessels_and_aircraft_are_never_screened():
    """The bug this guards: "Baxter" matching a VESSEL named BAXTER.

    The screening list holds 7,652 individuals, 1,540 vessels and 342 aircraft.
    A hardware manufacturer is none of those, and matching against one produced
    a hard AVOID on a real medical-device maker.
    """
    assert "entity" in supplychain.SCREENABLE_TYPES
    assert "" in supplychain.SCREENABLE_TYPES
    for kind in ("individual", "vessel", "aircraft"):
        assert kind not in supplychain.SCREENABLE_TYPES


def test_a_vessel_entry_is_not_indexed(tmp_path):
    directory = tmp_path / "data"
    directory.mkdir()
    (directory / "screening.json").write_text(json.dumps([
        {"name": "BAXTER", "type": "Vessel", "source": "Specially Designated Nationals",
         "alt_names": [], "programs": "", "country": "", "url": ""},
        {"name": "Real Bad Company", "type": "Entity",
         "source": "Entity List (EL) - Bureau of Industry and Security",
         "alt_names": [], "programs": "", "country": "", "url": ""},
    ]))
    index = supplychain.load(directory)
    assert supplychain.screen(index, "Baxter") == ([], [])
    blocking, _ = supplychain.screen(index, "Real Bad Company")
    assert blocking


def test_single_word_names_advise_but_do_not_block(tmp_path):
    """"NAVIS" and "INEA" collide with unrelated manufacturers."""
    directory = tmp_path / "data"
    directory.mkdir()
    (directory / "screening.json").write_text(json.dumps([
        {"name": "NAVIS", "type": "Entity", "source": "Specially Designated Nationals",
         "alt_names": [], "programs": "", "country": "", "url": ""},
    ]))
    index = supplychain.load(directory)
    blocking, advisory = supplychain.screen(index, "Navis")
    assert blocking == [], "a one-word name is not enough to accuse a company"
    assert advisory, "but it must still be reported for review"
    assert supplychain.gates_for(index, "Navis") == []
    assert supplychain.notes_for(index, "Navis")


def test_alias_matches_advise_but_do_not_block(tmp_path):
    """"Prima Systems" is an alias of an unrelated listed entity."""
    directory = tmp_path / "data"
    directory.mkdir()
    (directory / "screening.json").write_text(json.dumps([
        {"name": "Scientific Production Enterprise Prima Limited", "type": "Entity",
         "source": "Entity List (EL) - Bureau of Industry and Security",
         "alt_names": ["Prima Systems"], "programs": "", "country": "", "url": ""},
    ]))
    index = supplychain.load(directory)
    blocking, advisory = supplychain.screen(index, "Prima Systems")
    assert blocking == []
    assert advisory and advisory[0]["matched_as"] == "alias"
    # The full legal name still blocks.
    assert supplychain.screen(
        index, "Scientific Production Enterprise Prima Limited")[0]


def test_an_untyped_record_reports_but_does_not_block(tmp_path):
    """The PLANET Technology case.

    A CSL record the list left untyped says nothing about whether the thing
    named is even a company. Screening it is right; stopping a purchase on it is
    not. PLANET Technology, a Taiwanese switch maker, was hard-gated by an
    untyped "Planet Technology" on the Entity List.
    """
    directory = tmp_path / "data"
    directory.mkdir()
    (directory / "screening.json").write_text(json.dumps([
        {"name": "Planet Technology", "type": "", "alt_names": [],
         "source": "Entity List (EL) - Bureau of Industry and Security",
         "programs": "", "country": "", "url": ""},
    ]))
    index = supplychain.load(directory)
    gates, notes = supplychain.screen(index, "Planet Technology")
    assert gates == []                       # not blocked
    assert notes and notes[0]["blocking"] is False
    assert "collision" in " ".join(supplychain.notes_for(index, "Planet Technology"))


def test_a_typed_entity_with_a_distinctive_name_blocks(tmp_path):
    """The rule that replaced it: the list has to say this is an entity."""
    directory = tmp_path / "data"
    directory.mkdir()
    (directory / "screening.json").write_text(json.dumps([
        {"name": "Dahua Technology Company", "type": "Entity", "alt_names": [],
         "source": "Entity List (EL) - Bureau of Industry and Security",
         "programs": "", "country": "", "url": ""},
    ]))
    index = supplychain.load(directory)
    assert supplychain.gates_for(index, "Dahua Technology Company")


def _unused_distinctive_legal_name_still_blocks(tmp_path):
    directory = tmp_path / "data"
    directory.mkdir()
    (directory / "screening.json").write_text(json.dumps([
        {"name": "Planet Technology", "type": "", "alt_names": [],
         "source": "Entity List (EL) - Bureau of Industry and Security",
         "programs": "", "country": "", "url": ""},
    ]))
    index = supplychain.load(directory)
    assert supplychain.screen(index, "Planet Technology")[0]


def test_advisory_notes_explain_themselves(tmp_path):
    directory = tmp_path / "data"
    directory.mkdir()
    (directory / "screening.json").write_text(json.dumps([
        {"name": "NAVIS", "type": "Entity", "source": "Specially Designated Nationals",
         "alt_names": [], "programs": "", "country": "", "url": ""},
    ]))
    notes = supplychain.notes_for(supplychain.load(directory), "Navis")
    assert notes and "name collision" in notes[0]
    assert "check the source" in notes[0]


@pytest.mark.skipif(not __import__("pathlib").Path("data/retrust.db").exists(),
                    reason="needs a built index")
def test_no_false_positives_across_the_whole_corpus():
    """Screen every vendor the corpus actually contains, not a chosen few.

    The hand-picked list in this file passed while four real vendors were being
    wrongly flagged. Only sweeping all of them caught it.
    """
    import sqlite3
    screening = supplychain.load("data")
    connection = sqlite3.connect("data/retrust.db")
    vendors = [r[0] for r in connection.execute(
        "SELECT DISTINCT vendor FROM product WHERE vendor != ''")]
    assert len(vendors) > 500, "index looks wrong; this test needs the real corpus"

    blocked = {v for v in vendors if supplychain.screen(screening, v)[0]}
    # Everything blocked must be genuinely listed. This set is reviewed by hand;
    # anything new appearing here needs a human to confirm before it ships.
    known_listed = {"Dahua Technology Co, Ltd", "Hikvision", "Planet Technology"}
    assert blocked <= known_listed, f"new hard-AVOID vendors to verify: {blocked - known_listed}"


# --- the screening cache -----------------------------------------------------
#
# Building the index parses a 7.5 MB list into ~32,000 keys and cost 1.3 s on
# EVERY CLI invocation, against an assessment that itself takes 3 ms. It is now
# built once per refresh and cached; these tests pin that the cache can never
# answer differently from the build it came from, and that every way it can go
# wrong degrades to the slow-but-correct path rather than to a wrong screen.

def _listed(directory, names):
    """A screening source holding the given entity names."""
    (directory / "screening.json").write_text(json.dumps(
        [{"name": name, "type": "Entity", "country": "", "programs": "", "url": "",
          "source": "Entity List (EL) - Bureau of Industry and Security"}
         for name in names]), encoding="utf-8")


VENDORS = ("Acme Precision Instruments Limited", "Beta Controls GmbH",
           "Hikvision", "Siemens", "", "Nobody At All")


def test_the_cache_answers_exactly_as_the_build_it_came_from(tmp_path):
    """Read THROUGH the cache, not past it.

    The first load builds in memory and writes the cache as a side effect, so
    a single load never exercises the SQL read path at all -- a cache that
    returned nothing on every hit passed this file until this test loaded
    twice.
    """
    _listed(tmp_path, VENDORS[:2])
    built = supplychain.build_index(tmp_path)          # straight from JSON
    supplychain.screen(supplychain.load(str(tmp_path)), "x")   # writes the cache
    assert (tmp_path / supplychain.CACHE_NAME).exists(), "no cache was written"

    cached = supplychain.load(str(tmp_path))           # second load: reads it
    for vendor in VENDORS:
        assert supplychain.screen(built, vendor) == supplychain.screen(cached, vendor), vendor
    assert len(cached) == len(built)


def test_a_cached_read_finds_the_same_listed_vendor(tmp_path):
    """The mutation this pins: a cache hit silently returning nothing."""
    _listed(tmp_path, ["Acme Precision Instruments Limited"])
    supplychain.screen(supplychain.load(str(tmp_path)), "x")   # build + write
    second = supplychain.load(str(tmp_path))
    assert second.get(supplychain.screening_key("Acme Precision Instruments Limited"))
    assert supplychain.screen(second, "Acme Precision Instruments Limited")[0]


def test_a_changed_source_list_is_not_answered_from_the_old_cache(tmp_path):
    """The failure that would matter: screening a vendor against yesterday's list."""
    _listed(tmp_path, ["Acme Precision Instruments Limited"])
    assert supplychain.screen(supplychain.load(str(tmp_path)),
                              "Acme Precision Instruments Limited")[0]
    os.utime(tmp_path / "screening.json", (0, 0))      # a different stamp
    _listed(tmp_path, ["Beta Controls GmbH"])
    fresh = supplychain.load(str(tmp_path))
    assert not supplychain.screen(fresh, "Acme Precision Instruments Limited")[0]
    assert supplychain.screen(fresh, "Beta Controls GmbH")[0]


def test_a_corrupt_cache_is_rebuilt_rather_than_trusted(tmp_path):
    _listed(tmp_path, ["Acme Precision Instruments Limited"])
    supplychain.load(str(tmp_path)).get("x")           # build the cache
    (tmp_path / supplychain.CACHE_NAME).write_bytes(b"not a database at all")
    assert supplychain.screen(supplychain.load(str(tmp_path)),
                              "Acme Precision Instruments Limited")[0]


def test_an_unwritable_data_directory_still_screens_correctly(tmp_path):
    """A read-only clone loses the cache, never the answer."""
    _listed(tmp_path, ["Acme Precision Instruments Limited"])
    tmp_path.chmod(stat.S_IRUSR | stat.S_IXUSR)
    try:
        assert supplychain.screen(supplychain.load(str(tmp_path)),
                                  "Acme Precision Instruments Limited")[0]
        assert not (tmp_path / supplychain.CACHE_NAME).exists()
    finally:
        tmp_path.chmod(stat.S_IRWXU)


def test_nothing_is_read_until_a_vendor_is_actually_screened(tmp_path):
    """Commands that never screen must not pay for the list at all."""
    _listed(tmp_path, ["Acme Precision Instruments Limited"])
    index = supplychain.load(str(tmp_path))
    assert not (tmp_path / supplychain.CACHE_NAME).exists()
    supplychain.screen(index, "Acme Precision Instruments Limited")
    assert (tmp_path / supplychain.CACHE_NAME).exists()


def test_the_curated_covered_list_survives_with_no_downloaded_source(tmp_path):
    index = supplychain.load(str(tmp_path))
    assert supplychain.screen(index, "Hikvision")[0]
    assert not index.screening_list_loaded, "ten curated entries are not a screen"


def test_certificates_are_not_read_until_one_is_looked_up(tmp_path):
    """Loading both evidence lists cost 1.3 s on every run; now it costs nothing.

    `_context` builds the screening and certificate indexes for every command,
    including the many that never score a product. Both are now deferred, so
    the cost lands only on the commands that actually screen or certify.
    """
    (tmp_path / "certifications.json").write_text(json.dumps(
        [{"vendor": "Acme Controls", "scheme": "IEC 62443-4-2", "product": "PLC-1",
          "detail": "", "source": ""}]), encoding="utf-8")
    index = certification.load(str(tmp_path))
    assert index._index is None, "nothing should be parsed by load() alone"
    assert certification.certificates_for(index, "Acme Controls")
    assert index._index is not None


def test_the_deferred_certificate_index_matches_a_direct_build(tmp_path):
    (tmp_path / "certifications.json").write_text(json.dumps(
        [{"vendor": "Acme Controls", "scheme": "IEC 62443-4-2", "product": "PLC-1",
          "detail": "", "source": ""},
         {"vendor": "Acme Controls Inc.", "scheme": "IEC 62443-4-1", "product": "",
          "detail": "", "source": ""}]), encoding="utf-8")
    built, lazy = certification.build_index(tmp_path), certification.load(str(tmp_path))
    for vendor in ("Acme Controls", "Acme Controls Inc.", "Nobody", ""):
        assert (certification.certificates_for(built, vendor)
                == certification.certificates_for(lazy, vendor)), vendor
    assert len(built) == len(lazy)
