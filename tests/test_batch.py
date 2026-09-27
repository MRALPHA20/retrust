"""Tests for batch automation and screenshot capture."""

import json

import pytest

from retrust import batch, screenshot

CSV_TEXT = """vendor,product,firmware,order_number
Siemens,SIMATIC S7-1500,3.1.6,
,,,6ES7518-4AX00-1AB0
Schneider Electric,Modicon M340,,
"""


def _record(verdict, score=50.0, product="X"):
    return {"product": product, "verdict": verdict, "score": score,
            "gates": [], "reason": "", "pillars": {"Severity": 40.0}}


# --- reading candidate lists ----------------------------------------------

def test_reads_csv(tmp_path):
    path = tmp_path / "c.csv"
    path.write_text(CSV_TEXT)
    rows = batch.read_candidates(path)
    assert len(rows) == 3
    assert rows[0]["vendor"] == "Siemens"
    assert rows[0]["version"] == "3.1.6"          # "firmware" column aliased
    assert rows[1]["order_number"] == "6ES7518-4AX00-1AB0"
    assert rows[1]["vendor"] is None              # blank cells become None


def test_column_aliases_cover_real_exports(tmp_path):
    """A requisition export should not need reshaping by hand."""
    path = tmp_path / "c.csv"
    path.write_text("Manufacturer,Model,FW,Part Number\nMoxa,EDS-405A,1.2,ABC-123\n")
    rows = batch.read_candidates(path)
    assert rows[0] == {"vendor": "Moxa", "product": "EDS-405A",
                       "version": "1.2", "order_number": "ABC-123"}


def test_reads_json_list(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps([{"vendor": "ABB", "product": "AC 800M"}]))
    rows = batch.read_candidates(path)
    assert rows[0]["vendor"] == "ABB"
    assert rows[0]["version"] is None


def test_reads_json_object_with_candidates_key(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"candidates": [{"vendor": "ABB", "product": "X"}]}))
    assert batch.read_candidates(path)[0]["vendor"] == "ABB"


def test_unreadable_input_fails_clearly(tmp_path):
    with pytest.raises(SystemExit, match="does not exist"):
        batch.read_candidates(tmp_path / "nope.csv")

    empty = tmp_path / "e.csv"
    empty.write_text("vendor,product\n")
    with pytest.raises(SystemExit, match="no candidates"):
        batch.read_candidates(empty)

    wrong = tmp_path / "w.csv"
    wrong.write_text("colour,size\nred,large\n")
    with pytest.raises(SystemExit, match="no recognised columns"):
        batch.read_candidates(wrong)


def test_blank_rows_are_dropped(tmp_path):
    path = tmp_path / "c.csv"
    path.write_text("vendor,product\nABB,AC 800M\n,\n \t, \n")
    assert len(batch.read_candidates(path)) == 1


# --- exit codes, so this can gate a pipeline -------------------------------

def test_exit_code_flags_avoid():
    records = [_record("PREFER"), _record("AVOID")]
    assert batch.exit_code(records) == batch.EXIT_AVOID


def test_exit_code_clean_run_is_zero():
    records = [_record("PREFER"), _record("CONDITIONAL")]
    assert batch.exit_code(records) == batch.EXIT_OK


def test_unassessed_only_fails_when_asked():
    records = [_record("PREFER"), _record("NOT ASSESSED")]
    assert batch.exit_code(records, "avoid") == batch.EXIT_OK
    assert batch.exit_code(records, "unassessed") == batch.EXIT_UNASSESSED


def test_avoid_outranks_unassessed():
    records = [_record("AVOID"), _record("NOT ASSESSED")]
    assert batch.exit_code(records, "unassessed") == batch.EXIT_AVOID


def test_fail_on_never_always_succeeds():
    assert batch.exit_code([_record("AVOID")], "never") == batch.EXIT_OK


# --- output formats --------------------------------------------------------

def test_json_output_round_trips(tmp_path):
    path = tmp_path / "out.json"
    batch.write_json([_record("PREFER")], path, meta={"candidates": 1})
    document = json.loads(path.read_text())
    assert document["generated_by"] == "retrust"
    assert document["candidates"] == 1
    assert document["results"][0]["verdict"] == "PREFER"


def test_json_handles_sets(tmp_path):
    """Advisory ids arrive as a set; JSON must not choke on them."""
    path = tmp_path / "out.json"
    record = _record("PREFER")
    record["advisories"] = {"ICSA-26-001-01", "ICSA-26-002-01"}
    batch.write_json([record], path)
    assert len(json.loads(path.read_text())["results"][0]["advisories"]) == 2


def test_csv_flattens_pillars(tmp_path):
    path = tmp_path / "out.csv"
    batch.write_csv([_record("PREFER")], path)
    header = path.read_text().splitlines()[0]
    assert "pillar_severity" in header
    assert "verdict" in header


def test_csv_joins_multiple_gates(tmp_path):
    path = tmp_path / "out.csv"
    record = _record("AVOID")
    record["gates"] = ["Covered list", "Sanctioned entity"]
    batch.write_csv([record], path)
    assert "Covered list; Sanctioned entity" in path.read_text()


# --- screenshots -----------------------------------------------------------

def test_theme_is_stamped_on_the_html_tag(tmp_path):
    """The bug this guards: stamping the doctype instead of <html>.

    Splitting on the first ">" lands on <!doctype html>, so the attribute never
    reaches :root, both themes render identically, and the captures come out
    byte-for-byte the same.
    """
    page = tmp_path / "p.html"
    page.write_text('<!doctype html><html lang="en"><body>hi</body></html>')
    variant = screenshot._theme_variant(page, "dark")
    try:
        text = variant.read_text()
        assert '<html lang="en" data-theme="dark">' in text
        assert "doctype html data-theme" not in text
    finally:
        variant.unlink(missing_ok=True)


def test_existing_theme_attribute_is_replaced(tmp_path):
    page = tmp_path / "p.html"
    page.write_text('<html data-theme="light"><body>x</body></html>')
    variant = screenshot._theme_variant(page, "dark")
    try:
        text = variant.read_text()
        assert 'data-theme="dark"' in text
        assert 'data-theme="light"' not in text
    finally:
        variant.unlink(missing_ok=True)


def test_fragment_without_html_tag_is_wrapped(tmp_path):
    page = tmp_path / "p.html"
    page.write_text("<p>bare fragment</p>")
    variant = screenshot._theme_variant(page, "dark")
    try:
        assert variant.read_text().startswith('<html data-theme="dark">')
    finally:
        variant.unlink(missing_ok=True)


def test_missing_source_fails_clearly(tmp_path):
    if not screenshot.find_browser():
        pytest.skip("no Chrome or Chromium on this machine")
    with pytest.raises(SystemExit, match="does not exist"):
        screenshot.capture(tmp_path / "absent.html", tmp_path / "o.png")


@pytest.mark.skipif(not screenshot.find_browser(),
                    reason="no Chrome or Chromium on this machine")
def test_capture_produces_distinct_themes(tmp_path):
    page = tmp_path / "p.html"
    page.write_text(
        '<!doctype html><html lang="en"><head><style>'
        ':root{--bg:#fff;--fg:#000}'
        ':root[data-theme=dark]{--bg:#111;--fg:#eee}'
        'body{background:var(--bg);color:var(--fg);font-size:40px}'
        '</style></head><body>ReTrust</body></html>')

    shots = screenshot.capture_both_themes(page, tmp_path, stem="p", full_page=False)
    assert len(shots) == 2
    light, dark = (tmp_path / "p-light.png"), (tmp_path / "p-dark.png")
    assert light.exists() and dark.exists()
    assert light.read_bytes() != dark.read_bytes(), \
        "light and dark captures are identical; theme stamping is broken"


# --- JSON output from score and compare ------------------------------------

def _assessment(verdict="CONDITIONAL", score=55.9, gates=(), pillars=()):
    from retrust.score import Assessment, Pillar
    return Assessment(
        product="Moxa EDS-405A", verdict=verdict, score=score,
        pillars=list(pillars) or [
            Pillar("Exploitation", 98.0, 1.0, ["peak EPSS 0.050"]),
            Pillar("Evidence quality", 100.0, 1.0, ["10/10 parsed"]),
        ],
        gates=list(gates), findings_count=10, undecided_count=0, confidence=1.0)


def _resolution(resolved=True):
    from retrust.match import Match, Resolution
    if not resolved:
        return Resolution(query="x", abstained=True, reason="vendor not in corpus")
    return Resolution(query="x", method="exact_name", confidence=0.9, matches=[
        Match(1, "ICSA-19-057-01", "P1", "Moxa", "EDS-405A", "<= 3.8",
              "exact_name", 0.9)])


def _findings(n=3):
    from retrust.match import Finding
    return [Finding(cve=f"CVE-2019-000{i}", advisory_id="ICSA-19-057-01",
                    cvss=9.8 - i, cwe="CWE-120", epss=0.05 - i * 0.01,
                    in_kev=False, ransomware=False, version_range="<= 3.8",
                    decided=True, remediation="mitigation")
            for i in range(n)]


def test_detail_is_a_superset_of_record():
    """One parser must read either output, so field names cannot diverge."""
    assessment, resolution = _assessment(), _resolution()
    record = batch.to_record(assessment, resolution)
    detail = batch.to_detail(assessment, resolution, _findings())
    assert set(record) <= set(detail)
    for key in ("product", "verdict", "score", "cves", "resolved_by"):
        assert detail[key] == record[key]


def test_detail_carries_pillar_evidence():
    detail = batch.to_detail(_assessment(), _resolution(), _findings())
    pillars = {p["name"]: p for p in detail["pillars"]}
    assert pillars["Exploitation"]["evidence"] == ["peak EPSS 0.050"]
    # Evidence quality is reported but flagged as not contributing to the score.
    assert pillars["Evidence quality"]["scored"] is False
    assert pillars["Exploitation"]["scored"] is True


def test_detail_keeps_gate_citations():
    """A gate without its source is an accusation, not evidence."""
    gate = {"gate": "Named on a covered list", "detail": "matches X",
            "source": "https://www.fcc.gov/supplychain/coveredlist"}
    detail = batch.to_detail(_assessment(gates=[gate]), _resolution())
    assert detail["gates"][0]["source"].startswith("https://")


def test_detail_ranks_and_truncates_findings():
    detail = batch.to_detail(_assessment(), _resolution(), _findings(25), top_cves=10)
    assert len(detail["findings"]) == 10
    assert detail["findings_truncated"] == 15
    epss = [f["epss"] for f in detail["findings"]]
    assert epss == sorted(epss, reverse=True)


def test_detail_omits_matches_when_unresolved():
    detail = batch.to_detail(_assessment("NOT ASSESSED", None), _resolution(False))
    assert "matches" not in detail
    assert detail["reason"] == "vendor not in corpus"


def test_envelope_is_versioned():
    payload = batch.envelope([{"verdict": "PREFER"}], {"candidates": 1})
    assert payload["schema"] == batch.SCHEMA_VERSION
    assert payload["generated_by"] == "retrust"
    assert payload["candidates"] == 1
    assert payload["results"][0]["verdict"] == "PREFER"


def test_dumps_survives_findings_and_sets():
    detail = batch.to_detail(_assessment(), _resolution(), _findings())
    detail["advisories"] = {"ICSA-19-057-01"}
    assert json.loads(batch.dumps(batch.envelope([detail])))["results"][0]["cves"] == 10
