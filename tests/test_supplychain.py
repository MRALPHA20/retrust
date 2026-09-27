"""Tests for sanctions screening and certification evidence.

The screening tests matter more than most. Wrongly telling a buyer that a
legitimate manufacturer is sanctioned is the worst error this tool can make, so
the false-positive cases below are the point of the file.
"""

import json

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
    assert pillar.score == 50.0          # neutral, not zero
    assert pillar.coverage == 0.0
    assert any("not evidence of insecurity" in e for e in pillar.evidence)


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


def test_distinctive_legal_name_still_blocks(tmp_path):
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
