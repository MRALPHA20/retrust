"""Tests for the VEX export.

The dangerous output here is the confident negative: not_affected is the one
statement downstream tooling acts on by doing nothing. So the tests dwell on
how that claim is earned -- an actually-excluded version, with the range and
the version named -- and on how easily it is overridden: any row that is
affected or undecided must win the collapse. The document itself must be
reproducible, because a VEX in a procurement file that cannot be re-derived
from its index is an assertion nobody can check.
"""

import json

import pytest

from retrust import index, match, vex

V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V2 = "AV:N/AC:L/Au:N/C:P/I:P/A:P"

# The ADVISORY shape from test_evaluate, extended: one product family with
# three version rows -- affected below 2.0, a separate 3.x line, and a range
# nothing can parse -- so one CVE can span rows that disagree. At version
# 1.5 the rows decide True, False and None respectively.
ADVISORY = {
    "document": {"title": "Test", "tracking": {
        "id": "ICSA-26-001-01", "initial_release_date": "2026-01-01T00:00:00Z"}},
    "product_tree": {"branches": [{
        "category": "vendor", "name": "Testco Electric",
        "branches": [{
            "category": "product_name", "name": "TestPLC 9000",
            "branches": [
                {"category": "product_version_range", "name": "vers:intdot/<2.0",
                 "product": {"product_id": "P1", "name": "TestPLC 9000"}},
                {"category": "product_version_range",
                 "name": "vers:intdot/>=3.0|<4.0",
                 "product": {"product_id": "P2", "name": "TestPLC 9000"}},
                {"category": "product_version_range", "name": "%%%unparseable%%%",
                 "product": {"product_id": "P3", "name": "TestPLC 9000"}},
            ]}]}]},
    "vulnerabilities": [
        # Spans the affected row and the excluded one: the collapse must call
        # it exploitable, citing only the range that said so.
        {"cve": "CVE-2026-0001",
         "product_status": {"known_affected": ["P1", "P2"]},
         "scores": [{"cvss_v3": {"baseScore": 9.8, "vectorString": V31},
                     "products": ["P1", "P2"]}]},
        # Only the excluded row: the not_affected claim findings() never has
        # a reason to print.
        {"cve": "CVE-2026-0002",
         "product_status": {"known_affected": ["P2"]},
         "scores": [{"cvss_v2": {"baseScore": 7.5, "vectorString": V2},
                     "products": ["P2"]}]},
        # Only the unparseable row: in_triage, and no score at all.
        {"cve": "CVE-2026-0003",
         "product_status": {"known_affected": ["P3"]}},
        # Excluded row beside the unparseable one: in_triage must win.
        {"cve": "CVE-2026-0004",
         "product_status": {"known_affected": ["P2", "P3"]}},
        # Affected row beside the unparseable one: exploitable must win. The
        # score arrives without a vector, so its rating method is "other".
        {"cve": "CVE-2026-0005",
         "product_status": {"known_affected": ["P1", "P3"]},
         "scores": [{"cvss_v3": {"baseScore": 5.0}, "products": ["P1"]}]},
    ],
}

# Fixed dates in the past: a clock-derived timestamp could never equal them.
PROVENANCE = [
    {"source": "CISA OT advisories (CSAF 2.0)", "detail": "1 advisory",
     "captured": "2026-01-15"},
    {"source": "CISA KEV", "detail": "0 entries", "captured": "2025-12-31"},
]


@pytest.fixture
def db(tmp_path):
    directory = tmp_path / "csaf"
    directory.mkdir()
    (directory / "a.json").write_text(json.dumps(ADVISORY))
    connection, _ = index.build(str(tmp_path / "t.db"), str(directory))
    return connection


def _statements(connection, version="1.5"):
    resolution = match.resolve(connection, vendor="Testco",
                               product="TestPLC 9000")
    assert resolution.resolved
    return vex.statements(connection, resolution, version=version)


def _by_cve(statements):
    return {statement.cve: statement for statement in statements}


# --- the three states and the collapse --------------------------------------

def test_a_version_excluded_row_surfaces_as_not_affected(db):
    statement = _by_cve(_statements(db))["CVE-2026-0002"]
    assert statement.state == "not_affected"
    assert statement.justification == "code_not_present"
    # The claim must be auditable: the range and the version that misses it.
    assert "vers:intdot/>=3.0|<4.0" in statement.detail
    assert "1.5" in statement.detail


def test_the_row_findings_drops_is_re_derived_not_lost(db):
    """match.findings() skips clearly-excluded rows; the VEX must not."""
    resolution = match.resolve(db, vendor="Testco", product="TestPLC 9000")
    printed = {f.cve for f in match.findings(db, resolution, version="1.5")}
    assert "CVE-2026-0002" not in printed
    assert _by_cve(_statements(db))["CVE-2026-0002"].state == "not_affected"


def test_exploitable_beats_not_affected_when_one_cve_spans_rows(db):
    """A CVE affecting one matched row IS a finding, whatever the others say."""
    statement = _by_cve(_statements(db))["CVE-2026-0001"]
    assert statement.state == "exploitable"
    # Only the range that decided the winning state is cited as evidence.
    assert "vers:intdot/<2.0" in statement.detail
    assert ">=3.0" not in statement.detail


def test_exploitable_beats_in_triage(db):
    assert _by_cve(_statements(db))["CVE-2026-0005"].state == "exploitable"


def test_in_triage_beats_not_affected(db):
    """An undecided range must never be outranked by a decided-safe one."""
    statement = _by_cve(_statements(db))["CVE-2026-0004"]
    assert statement.state == "in_triage"
    assert statement.justification is None


def test_no_version_leaves_everything_in_triage(db):
    """not_affected needs a version to point at; with none, nothing has one."""
    statements = _statements(db, version=None)
    assert statements
    assert all(s.state == "in_triage" for s in statements)
    assert all(s.justification is None for s in statements)
    assert all("No version was supplied" in s.detail for s in statements)


def test_an_unresolved_resolution_yields_no_statements(db):
    abstained = match.Resolution(query="x", abstained=True, reason="no")
    assert vex.statements(db, abstained, version="1.5") == []


def test_statements_are_sorted_by_cve_and_deterministic(db):
    first, second = _statements(db), _statements(db)
    assert first == second
    assert [s.cve for s in first] == sorted(s.cve for s in first)


def test_statements_carry_the_score_and_vector_of_their_evidence(db):
    by_cve = _by_cve(_statements(db))
    assert by_cve["CVE-2026-0001"].cvss == 9.8
    assert by_cve["CVE-2026-0001"].vector == V31
    assert by_cve["CVE-2026-0003"].cvss is None
    assert by_cve["CVE-2026-0001"].advisory_ids == ["ICSA-26-001-01"]


# --- the document ------------------------------------------------------------

def _document(connection, subject_version="1.5"):
    return vex.document("TestPLC 9000", subject_version,
                        _statements(connection), PROVENANCE)


def test_the_serial_number_is_deterministic(db):
    """Same index, same query, byte-identical document -- serial included."""
    first, second = _document(db), _document(db)
    assert first == second
    assert first["serialNumber"] == second["serialNumber"]
    assert first["serialNumber"].startswith("urn:uuid:")


def test_the_serial_number_tracks_the_content(db):
    """One serial for two different assertions would defeat its purpose."""
    statements = _statements(db)
    ours = vex.document("TestPLC 9000", "1.5", statements, PROVENANCE)
    other = vex.document("OtherPLC", "1.5", statements, PROVENANCE)
    assert ours["serialNumber"] != other["serialNumber"]


def test_the_timestamp_is_the_newest_capture_not_the_clock(db):
    """Both provenance dates are in the past; the clock could match neither."""
    document = _document(db)
    assert document["metadata"]["timestamp"] == "2026-01-15T00:00:00Z"


def test_no_dated_provenance_means_no_timestamp_not_an_invented_one(db):
    undated = [{"source": "s", "detail": "", "captured": "unknown"}]
    document = vex.document("X", "1.5", _statements(db), undated)
    assert "timestamp" not in document["metadata"]


def test_an_empty_statement_list_is_refused(db):
    """An empty VEX still reads as "nothing applies"; it must not be writable."""
    with pytest.raises(ValueError):
        vex.document("TestPLC 9000", "1.5", [], PROVENANCE)


def test_rating_methods_follow_the_vector_generation(db):
    entries = {v["id"]: v for v in _document(db)["vulnerabilities"]}
    assert entries["CVE-2026-0001"]["ratings"] == [
        {"score": 9.8, "method": "CVSSv31"}]
    assert entries["CVE-2026-0002"]["ratings"][0]["method"] == "CVSSv2"
    # A score without a vector is still a score, labelled "other".
    assert entries["CVE-2026-0005"]["ratings"] == [
        {"score": 5.0, "method": "other"}]
    assert "ratings" not in entries["CVE-2026-0003"]


def test_justification_appears_only_on_not_affected(db):
    for entry in _document(db)["vulnerabilities"]:
        analysis = entry["analysis"]
        if analysis["state"] == "not_affected":
            assert analysis["justification"] == "code_not_present"
        else:
            assert "justification" not in analysis


def test_every_vulnerability_points_at_the_subject_component(db):
    document = _document(db)
    reference = document["metadata"]["component"]["bom-ref"]
    for entry in document["vulnerabilities"]:
        assert entry["affects"] == [{"ref": reference}]
        assert entry["source"] == {"name": "CISA CSAF"}
        assert "ICSA-26-001-01" in entry["analysis"]["detail"]


def test_the_component_carries_the_subject_and_omits_an_absent_version(db):
    versioned = _document(db)["metadata"]["component"]
    assert versioned["type"] == "device"
    assert versioned["name"] == "TestPLC 9000"
    assert versioned["version"] == "1.5"
    bare = vex.document("TestPLC 9000", None, _statements(db),
                        PROVENANCE)["metadata"]["component"]
    assert "version" not in bare


def test_the_document_round_trips_through_json(db):
    document = _document(db)
    assert json.loads(json.dumps(document)) == document
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.5"
    assert document["version"] == 1


# --- the terminal summary ----------------------------------------------------

def test_the_summary_counts_each_state(db):
    flat = " ".join(vex.format_summary(_statements(db)).split())
    assert "5 CVE(s)" in flat
    assert "exploitable 2" in flat
    assert "in triage 2" in flat
    assert "not affected 1" in flat


def test_the_summary_says_absence_is_not_a_claim(db):
    flat = " ".join(vex.format_summary(_statements(db)).split())
    assert "never assessed" in flat


def test_the_summary_on_nothing_explains_rather_than_crashing():
    text = vex.format_summary([])
    assert "no VEX" in text


def test_the_summary_stays_ascii_and_inside_eighty_columns(db):
    text = vex.format_summary(_statements(db))
    assert text.isascii()
    assert all(len(line) <= 80 for line in text.splitlines())


def test_a_falsy_version_reads_as_no_version_in_the_detail(db):
    """An empty string from an argparse default must not name a phantom check."""
    from retrust import match
    resolution = match.resolve(db, vendor="Testco", product="TestPLC 9000")
    for statement in vex.statements(db, resolution, version=""):
        assert "No version was supplied" in statement.detail


def test_compact_iso_dates_do_not_become_the_timestamp(db):
    """Python 3.11+ fromisoformat accepts "20260115"; the regex gate must not."""
    from retrust import match
    resolution = match.resolve(db, vendor="Testco", product="TestPLC 9000")
    statements = vex.statements(db, resolution, version="1.0")
    doc = vex.document("TestPLC 9000", "1.0", statements,
                       [{"source": "s", "detail": "d", "captured": "20260115"}])
    assert "timestamp" not in doc["metadata"]


def test_advisory_ids_are_machine_readable_references(db):
    from retrust import match
    resolution = match.resolve(db, vendor="Testco", product="TestPLC 9000")
    statements = vex.statements(db, resolution, version="1.0")
    doc = vex.document("TestPLC 9000", "1.0", statements,
                       [{"source": "s", "detail": "d", "captured": "2026-01-01"}])
    entry = doc["vulnerabilities"][0]
    assert entry["references"][0]["id"].startswith("ICSA-")
