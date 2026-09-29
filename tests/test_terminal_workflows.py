"""Regression coverage for interactive workflows and readable terminal evidence."""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from retrust import batch, cli, console, match, score, shell
from test_cli import workspace as _workspace


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    return _workspace.__wrapped__(tmp_path, monkeypatch)


def answers(*values):
    stream = iter(values)
    def read(prompt):
        try:
            return next(stream)
        except StopIteration:
            raise EOFError
    return read


def test_duplicate_advisories_do_not_multiply_exploitation_counts():
    finding = match.Finding('CVE-2026-0001', 'A', 9.8, 'CWE-79', .3,
                            True, True, '<2', True, 'none_available')
    duplicate = replace(finding, advisory_id='B')
    single = score._exploitation([finding])
    repeated = score._exploitation([finding, duplicate])
    assert repeated.score == single.score
    assert repeated.evidence == single.evidence
    gates = score.check_gates([finding, duplicate], 'Testco')
    assert all(gate['detail'].startswith('1 CVE(s)') for gate in gates)
    assessment = score.assess('Testco', [finding, duplicate])
    assert assessment.findings_count == 1
    assert any('1 distinct CVEs across 2 advisory findings' in note
               for note in assessment.notes)


def test_candidate_cards_preserve_identifiers_and_fit_narrow_terminals(monkeypatch):
    monkeypatch.setenv('COLUMNS', '52')
    record = {'product': 'Siemens SIMATIC S7-1500 CPU 1518-4 PN/DP MFP (6ES7518-4AX00-1AB0)',
              'verdict': 'AVOID', 'score': 39.3,
              'gates': [{'gate': 'Known exploited vulnerability in the supplied firmware'}]}
    output = console.candidates([record])
    assert all(console.visible_width(line) <= 50 for line in output.splitlines())
    flat = ' '.join(output.split())
    assert record['product'] in flat
    assert record['gates'][0]['gate'] in flat


def test_named_commands_and_control_c_at_menu(capsys):
    actions = {'2': ('Score', 'Assess one product', lambda result, reader: None)}
    assert shell.choose(actions, answers('score')) == '2'
    def interrupt(prompt):
        raise KeyboardInterrupt
    assert shell.choose(actions, interrupt) is None


def test_invalid_command_input_returns_to_menu(capsys):
    def fail(result, reader):
        raise SystemExit('file does not exist')
    shell.run({'6': ('Batch', 'Score a file', fail)}, {}, reader=answers('batch', 'q'))
    output = capsys.readouterr().out
    assert 'file does not exist' in output and 'Bye.' in output


@pytest.mark.parametrize('document', ['42', 'null', '{"candidates": null}', '{"candidates": {}}'])
def test_malformed_batch_shapes_are_reported_without_tracebacks(tmp_path, document):
    path = tmp_path / 'bad.json'
    path.write_text(document)
    with pytest.raises(SystemExit, match='expected a JSON|must be a JSON list'):
        batch.read_candidates(path)


def test_interactive_order_assessment_keeps_replayable_query(workspace, capsys):
    connection = cli._open('data/retrust.db')
    actions = cli._shell_actions(connection, cli._context(), SimpleNamespace())
    result = actions['o'][2](shell.Result(), answers('TC-9000-A1', '1.0'))
    query = result.records[0]['query']
    assert query['order_number'] == 'TC-9000-A1' and query['version'] == '1.0'
    assert result.savable
    connection.close()


def test_unassessed_html_export_is_written(workspace):
    assert cli.main(['score', '--vendor', 'Nobody', '--product', 'Nothing',
                     '--html', 'unresolved.html']) == 2
    assert 'NOT ASSESSED' in (workspace / 'unresolved.html').read_text()


def test_web_comparison_samples_verdict_robustness(workspace):
    from retrust import serve
    connection = cli._open('data/retrust.db')
    context = cli._context()
    def assess(vendor, product, version=None):
        return cli._assess(connection, vendor, product, version, None, context=context)
    markup = serve._compare_page(assess, context, [['Testco', 'TestPLC 9000', '1.0'],
                                                    ['Testco', 'TestPLC 9000', '2.0']])
    assert '300 random weightings' in markup
    assert 'Weight robustness.' in markup
    assert 'scroll horizontally for more columns' in markup
    connection.close()
