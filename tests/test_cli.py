"""End-to-end tests for the command line and the HTML report.

These are the wiring tests. Every module below has its own unit tests; what
these catch is the class of bug those cannot -- an argument that is parsed but
never passed on, a command that works alone and breaks when a flag is combined
with another, an exit code that does not reach the shell.

Each test drives `main(argv)` exactly as a user would, against a small index
built in a temporary directory, so nothing here touches the network or the
real corpus.
"""

import json

import pytest

from retrust import alternatives, cli, diff, index, report, score
from retrust.cli import main

ADVISORY = {
    "document": {"title": "Test PLC vulnerabilities", "tracking": {
        "id": "ICSA-26-001-01", "initial_release_date": "2026-01-01T00:00:00Z"}},
    "product_tree": {"branches": [{
        "category": "vendor", "name": "Testco Electric",
        "branches": [{
            "category": "product_name", "name": "TestPLC 9000 (TC-9000-A1)",
            "branches": [{
                "category": "product_version_range", "name": "vers:intdot/<2.0",
                "product": {"product_id": "P1", "name": "TestPLC 9000",
                            "product_identification_helper": {
                                "model_numbers": ["TC-9000-A1"]}}}]}]}]},
    "vulnerabilities": [{
        "cve": "CVE-2026-0001", "cwe": {"id": "CWE-79"},
        "product_status": {"known_affected": ["P1"]},
        "scores": [{"cvss_v3": {"baseScore": 9.8}, "products": ["P1"]}],
        "remediations": [{"category": "vendor_fix", "details": "update",
                          "product_ids": ["P1"]}]}],
}


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """A temp directory with a built index, as the working directory."""
    csaf = tmp_path / "csaf"
    csaf.mkdir()
    (csaf / "a.json").write_text(json.dumps(ADVISORY))
    (tmp_path / "data").mkdir()
    monkeypatch.chdir(tmp_path)
    assert main(["ingest", "--csaf", str(csaf)]) == 0
    return tmp_path


def run(argv):
    """Call the CLI, returning its exit code rather than raising."""
    try:
        return main(argv)
    except SystemExit as exit_signal:       # argparse and our own hard errors
        return exit_signal.code


# --- the commands, one by one ----------------------------------------------


class _Ranked:
    """A minimal stand-in carrying only what the ranking key reads."""

    def __init__(self, verdict, score):
        self.verdict, self.score = verdict, score


def test_ingest_builds_an_index(workspace):
    assert (workspace / "data" / "retrust.db").exists()
    connection = index.connect(str(workspace / "data" / "retrust.db"))
    assert index.stats(connection)["advisories"] == 1


def test_stats_runs(workspace, capsys):
    assert run(["stats"]) == 0
    assert "advisories" in capsys.readouterr().out


def test_score_by_vendor_and_product(workspace, capsys):
    assert run(["score", "--vendor", "Testco", "--product", "TestPLC 9000"]) == 2
    out = capsys.readouterr().out
    assert "TestPLC 9000" in out
    assert any(v in out for v in ("PREFER", "CONDITIONAL", "AVOID", "VERIFY"))


def test_score_by_order_number(workspace, capsys):
    assert run(["score", "--order-number", "TC-9000-A1"]) == 2
    assert "Testco" in capsys.readouterr().out


def test_score_abstains_with_exit_two(workspace, capsys):
    """An unknown vendor must not be reported as a clean result."""
    assert run(["score", "--vendor", "Nobody", "--product", "Nothing"]) == 2
    assert "NOT ASSESSED" in capsys.readouterr().out


def test_score_json_to_stdout_is_parseable(workspace, capsys):
    assert run(["score", "--vendor", "Testco", "--product", "TestPLC 9000",
                "--json", "-", "--no-sensitivity"]) == 0
    document = json.loads(capsys.readouterr().out)   # raises if prose leaked in
    assert document["schema"] == 3
    assert document["results"][0]["product"].startswith("Testco")


def test_score_json_to_file(workspace, capsys):
    assert run(["score", "--vendor", "Testco", "--product", "TestPLC 9000",
                "--json", "out.json", "--no-sensitivity"]) == 0
    assert "JSON written to" in capsys.readouterr().out
    assert json.loads((workspace / "out.json").read_text())["results"]


@pytest.mark.parametrize("vendor,version,exit_code", [
    ("Testco", "1.0", 0), ("Testco", "2.5", 0), ("Nobody", "1.0", 0),
])
def test_json_keeps_owner_choices_even_without_a_score(workspace, vendor, version, exit_code):
    assert run(["score", "--vendor", vendor, "--product", "TestPLC 9000",
                "--version", version, "--assessment-type", "installed",
                "--network-exposure", "isolated", "--consequence", "minor",
                "--interface", "blocked", "--remediation", "planned",
                "--json", "context.json", "--no-sensitivity"]) == exit_code
    result = json.loads((workspace / "context.json").read_text())["results"][0]
    for key, value in dict(assessment_type="installed", network_exposure="isolated",
                           consequence="minor", interface="blocked", remediation="planned").items():
        assert result[key] == value
    assert f"FW:{version}" in result["vector"]
    assert "DS:unset" not in result["vector"]
    if vendor == "Nobody" or version == "2.5":
        assert result["score"] is None
        assert result["verdict"] == "NOT ASSESSED"


def test_diff_replays_the_saved_owner_choices(workspace):
    assert run(["score", "--vendor", "Testco", "--product", "TestPLC 9000",
                "--consequence", "negligible", "--interface", "blocked",
                "--assessment-type", "installed", "--remediation", "mitigated",
                "--json", "before.json", "--no-sensitivity"]) == 0
    assert run(["diff", "before.json", "--json", "after.json"]) == 0
    result = json.loads((workspace / "after.json").read_text())["results"][0]
    assert result["change"] == "same"
    assert result["score_change"] == 0.0


def test_firmware_comparison_holds_owner_choices_fixed(workspace, monkeypatch):
    from retrust import cli, score
    actual = score.assess
    calls = []
    declared = dict(network_exposure="isolated", consequence="minor",
                    interface="blocked", assessment_type="installed", remediation="planned")

    def observe(*args, **kwargs):
        calls.append(kwargs)
        return actual(*args, **kwargs)

    monkeypatch.setattr(score, "assess", observe)
    connection = index.connect("data/retrust.db")
    try:
        cli._assess(connection, "Testco", "TestPLC 9000", "2.5", None,
                    context=cli._context(), **declared)
    finally:
        connection.close()
    assert len(calls) == 2   # selected firmware and the unrestricted baseline
    for call in calls:
        assert all(call[key] == value for key, value in declared.items())


def test_score_robustness_holds_owner_choices_fixed(workspace, monkeypatch):
    from retrust import sensitivity
    actual = sensitivity.stability
    calls = []

    def observe(*args, **kwargs):
        calls.append(kwargs)
        return actual(*args, **kwargs)

    monkeypatch.setattr(sensitivity, "stability", observe)
    assert run(["score", "--vendor", "Testco", "--product", "TestPLC 9000",
                "--consequence", "minor", "--interface", "blocked",
                "--assessment-type", "installed", "--remediation", "planned",
                "--json", "robust.json", "--samples", "10"]) == 0
    assert len(calls) == 1
    assert calls[0]["consequence"] == "minor"
    assert calls[0]["interface"] == "blocked"
    assert calls[0]["assessment_type"] == "installed"
    assert calls[0]["remediation"] == "planned"


def test_score_html_output(workspace, capsys):
    assert run(['score', '--vendor', 'Testco', '--product', 'TestPLC 9000', '--html', 'report.html']) == 2
    markup = (workspace / 'report.html').read_text()
    assert 'VERIFY' in markup and 'Provisional range' in markup
    assert 'What to check next' in markup


def test_compare_ranks_and_reports(workspace, capsys):
    assert run(["compare", "--candidate", "Testco|TestPLC 9000",
                "--candidate", "Nobody|Nothing", "--no-sensitivity"]) == 0
    out = capsys.readouterr().out
    assert "CANDIDATE" in out
    assert "NOT ASSESSED" in out
    # An unresolvable candidate must rank below a real one, never above.
    assert out.index("TestPLC 9000") < out.index("Nobody Nothing")


def test_compare_json_to_stdout_is_parseable(workspace, capsys):
    assert run(["compare", "--candidate", "Testco|TestPLC 9000",
                "--json", "-", "--no-sensitivity"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["candidates"] == 1


def test_sensitivity_command(workspace, capsys):
    assert run(["sensitivity", "--vendor", "Testco", "--product", "TestPLC 9000",
                "--samples", "40"]) == 0
    out = capsys.readouterr().out
    assert "VERIFY" in out and "Resolve the missing evidence" in out
    assert "where the points went" in out


def test_config_shows_defaults(workspace, capsys):
    assert run(["config"]) == 0
    out = capsys.readouterr().out
    assert "exposure" in out
    assert "built-in defaults" in out


def test_config_init_then_read_back(workspace, capsys):
    assert run(["config", "--init", "--file", "c.json"]) == 0
    assert (workspace / "c.json").exists()
    document = json.loads((workspace / "c.json").read_text())
    assert "weights" in document and "bands" in document


def test_batch_from_csv_with_exit_code(workspace, capsys):
    (workspace / "bom.csv").write_text(
        "Manufacturer,Model\nTestco,TestPLC 9000\nNobody,Nothing\n")
    code = run(["batch", "bom.csv", "--json", "b.json", "--csv", "b.csv",
                "--no-sensitivity", "--fail-on", "unassessed"])
    assert code == 2                      # one candidate could not be assessed
    assert json.loads((workspace / "b.json").read_text())["candidates"] == 2
    assert "verdict" in (workspace / "b.csv").read_text().splitlines()[0]


def test_batch_clean_list_exits_zero(workspace):
    (workspace / "ok.csv").write_text("vendor,product\nTestco,TestPLC 9000\n")
    assert run(["batch", "ok.csv", "--no-sensitivity", "--fail-on", "never"]) == 0


def test_eval_command(workspace, capsys):
    assert run(["eval", "--sample", "5"]) == 0
    out = capsys.readouterr().out
    assert "VERSION-RANGE COVERAGE" in out
    assert "PRODUCT ROUND-TRIP" in out


def test_snapshot_round_trip(workspace, capsys):
    assert run(["snapshot", "--out", "s.zip", "--note", "test"]) == 0
    assert (workspace / "s.zip").exists()
    capsys.readouterr()
    assert run(["snapshot", "--inspect", "s.zip"]) == 0
    assert "test" in capsys.readouterr().out
    assert run(["snapshot", "--restore", "s.zip"]) == 0
    assert "Checksums verified" in capsys.readouterr().out


def test_missing_index_fails_with_guidance(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    code = run(["stats"])
    assert code != 0                       # and the message names the fix
    assert isinstance(code, str) and "retrust ingest" in code


def test_unknown_command_is_rejected(workspace):
    assert run(["frobnicate"]) == 2         # argparse usage error


# --- the HTML report -------------------------------------------------------

def _blocks(connection):
    from retrust import match, score
    resolution = match.resolve(connection, vendor="Testco", product="TestPLC 9000")
    findings = match.findings(connection, resolution)
    assessment = score.assess("TestPLC 9000", findings, {"ICSA-26-001-01"})
    return [(assessment, resolution, findings)]


def test_report_is_self_contained(workspace):
    connection = index.connect(str(workspace / "data" / "retrust.db"))
    markup = report.render(_blocks(connection), title="T")
    assert "<style>" in markup
    # No external assets: the report must open offline and survive emailing.
    for forbidden in ("<script", "http://", "https://fonts", "<img", "@import"):
        assert forbidden not in markup, forbidden


def test_report_defines_both_themes(workspace):
    connection = index.connect(str(workspace / "data" / "retrust.db"))
    markup = report.render(_blocks(connection))
    assert "prefers-color-scheme: dark" in markup or \
           "prefers-color-scheme:dark" in markup
    assert "[data-theme=dark]" in markup


def test_report_escapes_hostile_text(workspace):
    """Product names come from vendor data; they are not trusted markup."""
    from retrust import match, score
    connection = index.connect(str(workspace / "data" / "retrust.db"))
    resolution = match.resolve(connection, vendor="Testco", product="TestPLC 9000")
    findings = match.findings(connection, resolution)
    assessment = score.assess('<script>alert("x")</script>', findings, {"A"})
    markup = report.render([(assessment, resolution, findings)])
    assert "<script>alert" not in markup
    assert "&lt;script&gt;" in markup


def test_report_shows_a_summary_table_only_when_comparing(workspace):
    connection = index.connect(str(workspace / "data" / "retrust.db"))
    one = report.render(_blocks(connection))
    two = report.render(_blocks(connection) * 2)
    assert "Main reason" not in one       # a single product needs no ranking
    assert "Main reason" in two


def test_report_marks_unscored_pillars(workspace):
    connection = index.connect(str(workspace / "data" / "retrust.db"))
    markup = report.render(_blocks(connection))
    # Evidence quality is reported but must not read as part of the score.
    assert "Evidence completeness" in markup
    assert "not scored" in markup


def test_report_footer_cites_provenance(workspace):
    connection = index.connect(str(workspace / "data" / "retrust.db"))
    markup = report.render(
        _blocks(connection), provenance=index.provenance(connection),
        weights={"exploitation": 1.0}, config_source="built-in defaults")
    assert "How this was produced" in markup
    assert "CISA OT advisories" in markup


# --- a gated product is not the same as an unassessable one ----------------

def _blocked():
    from retrust import score
    from retrust.match import Resolution
    assessment = score.blocked(
        "Hikvision Camera",
        [{"gate": "Named on a covered list", "detail": "x", "source": "https://fcc.gov"}],
        "vendor not in corpus")
    return assessment, Resolution(query="x", abstained=True,
                                  reason="vendor not in corpus"), []


def test_gated_product_is_not_labelled_missing_data():
    """The bug this guards: a disqualified vendor reported as "not enough data".

    The tool did decide -- a gate disqualified it. Saying the data was thin
    invites the reader to go and find more, which would change nothing.
    """
    from retrust import report, score
    markup = report.render([_blocked()], weights=score.DEFAULT_WEIGHTS)
    assert "not enough data" not in markup
    assert "disqualified below" in markup
    assert "Not assessed." not in markup      # would contradict the gate
    assert "Purchase blocker" in markup


def test_unassessable_product_still_says_so():
    from retrust import report, score
    from retrust.match import Resolution
    assessment = score.not_assessed("Unknown PLC", "vendor not in corpus")
    resolution = Resolution(query="x", abstained=True, reason="vendor not in corpus")
    markup = report.render([(assessment, resolution, [])],
                           weights=score.DEFAULT_WEIGHTS)
    assert "not enough data" in markup
    assert "Not assessed." in markup


def test_no_empty_pillar_table_is_rendered():
    from retrust import report, score
    markup = report.render([_blocked()], weights=score.DEFAULT_WEIGHTS)
    assert "<th>Pillar</th>" not in markup


def test_a_disqualified_product_never_outranks_one_needing_checks():
    """Best-first order: PREFER, CONDITIONAL, VERIFY, AVOID, NOT ASSESSED.

    RT4 ranked AVOID above VERIFY, so a KEV-gated product listed ahead of the
    only candidate a buyer could actually pursue.

    This replaces a test that opened retrust/cli.py as TEXT and asserted the
    substring '"VERIFY": 2, "AVOID": 3'. Mutation testing showed it worthless:
    deleting the sort call outright passed it, and reformatting the dict across
    two lines failed it with no behaviour change. The input below is
    deliberately in the WORST order, so a missing sort cannot pass by accident.
    """
    worst_first = [_Ranked("NOT ASSESSED", None), _Ranked("AVOID", 95.0),
                   _Ranked("VERIFY", 10.0), _Ranked("CONDITIONAL", 50.0),
                   _Ranked("PREFER", 71.0)]
    ranked = sorted(worst_first, key=cli._best_first())
    assert [c.verdict for c in ranked] == [
        "PREFER", "CONDITIONAL", "VERIFY", "AVOID", "NOT ASSESSED"]
    # A high-scoring disqualification still ranks below a low-scoring VERIFY.
    assert ranked.index(worst_first[1]) > ranked.index(worst_first[2])


def test_ranking_breaks_ties_on_score_and_never_raises():
    """Within one verdict the higher score wins; an unknown verdict sorts last.

    Ranking is presentation: an unrecognised verdict must not end a scoring run.
    """
    rows = [_Ranked("VERIFY", 10.0), _Ranked("WAT", 99.0), _Ranked("VERIFY", 80.0)]
    assert [c.score for c in sorted(rows, key=cli._best_first())] == [80.0, 10.0, 99.0]


def test_every_surface_ranks_through_one_table():
    """Six hand-written copies disagreed; there is now one."""
    assert list(score.VERDICT_RANK) == [
        "PREFER", "CONDITIONAL", "VERIFY", "AVOID", "NOT ASSESSED"]
    assert set(alternatives.RANK) <= set(score.VERDICT_RANK)
    assert set(diff.RANK) <= set(score.VERDICT_RANK)


def test_score_offers_a_way_forward_when_nothing_resolves(workspace, capsys):
    """A failed lookup must never end in a full stop.

    The interactive shell had always printed suggestions; `retrust score` --
    the command people actually run -- printed none, so the commonest mistake
    (a product name typed into the order-number box) ended at "not enough data
    to assess" with nowhere to go. Mutation-checked: removing the suggestion
    call must fail this.
    """
    assert main(["score", "--order-number", "Testco Electric TestPLC 9000 Alpha",
                 "--no-sensitivity"]) == 2
    out = " ".join(capsys.readouterr().out.split())
    assert "NOT ASSESSED" in out
    assert "product name rather than a manufacturer order number" in out
    assert "Closest products in the corpus" in out
    assert "TestPLC 9000" in out


def test_score_explains_an_order_number_that_simply_is_not_there(workspace, capsys):
    assert main(["score", "--order-number", "TC-0000-ZZ", "--no-sensitivity"]) == 2
    out = " ".join(capsys.readouterr().out.split())
    assert "matched exactly" in out
    assert "product name rather than" not in out, "a short code is not a name"


def test_score_suggests_the_manufacturer_for_a_misspelled_vendor(workspace, capsys):
    assert main(["score", "--vendor", "Testco Electrc", "--product", "TestPLC 9000",
                 "--no-sensitivity"]) == 2
    out = " ".join(capsys.readouterr().out.split())
    assert "Testco Electric" in out
