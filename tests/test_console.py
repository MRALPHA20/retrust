"""Tests for the terminal presentation layer.

Two of these matter more than the rest. The first is that pad() measures visible
width: a painted verdict and a plain one must occupy the same columns, or every
aligned table in the tool breaks the moment colour is on -- which is to say in
front of an audience, and nowhere else. The second is that overview() never
creates the database it is describing, because index.connect() would, and a
missing index would then report itself as an empty one on the next run.

Colour depends on the environment, so every test that needs it states the whole
environment it assumes rather than inheriting the one pytest happens to run in.
"""

import json
import re
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

from retrust import console, index, report

ADVISORY = {
    "document": {"title": "Test", "tracking": {
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
    "vulnerabilities": [{"cve": "CVE-2026-0001",
                         "product_status": {"known_affected": ["P1"]},
                         "scores": [{"cvss_v3": {"baseScore": 7.5},
                                     "products": ["P1"]}]}],
}

COMMANDS = {"ingest": ["-h", "--help", "--csaf", "--kev", "--epss"],
            "stats": ["-h", "--help"],
            "score": ["-h", "--help", "--vendor", "--product", "--version"]}
GLOBAL_FLAGS = ["-h", "--help", "--db", "--no-color"]


@pytest.fixture
def db_path(tmp_path):
    """A real index with one advisory in it."""
    directory = tmp_path / "csaf"
    directory.mkdir()
    (directory / "a.json").write_text(json.dumps(ADVISORY))
    path = tmp_path / "t.db"
    index.build(str(path), str(directory))
    return str(path)


@pytest.fixture
def colour(monkeypatch):
    """Everything colour needs bar the terminal; call the hook it returns for that.

    The fake TTY has to be installed from inside the test body, because pytest's
    capture plugin puts its own object back in sys.stdout between fixture setup
    and the call and would silently undo one installed here.
    """
    monkeypatch.setattr(console, "_forced_off", False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    return lambda isatty=True: monkeypatch.setattr(sys, "stdout", SimpleNamespace(
        isatty=lambda: isatty, write=lambda text: None, flush=lambda: None))


# --- when colour is allowed at all -----------------------------------------

def test_no_colour_when_stdout_is_not_a_tty(colour):
    colour(isatty=False)
    assert not console.enabled()
    assert console.paint("PREFER", "prefer") == "PREFER"
    assert "\x1b" not in console.paint_verdict("AVOID")


def test_stdout_without_an_isatty_method_does_not_raise(colour, monkeypatch):
    """A replaced or wrapped stdout must read as "not a terminal", not explode."""
    monkeypatch.setattr(sys, "stdout", SimpleNamespace())
    assert not console.enabled()


def test_no_color_environment_variable_wins_even_on_a_tty(colour, monkeypatch):
    colour()
    monkeypatch.setenv("NO_COLOR", "")       # any value counts, including empty
    assert not console.enabled()


def test_term_dumb_disables_colour(colour, monkeypatch):
    colour()
    monkeypatch.setenv("TERM", "dumb")
    assert not console.enabled()


def test_disable_forces_colour_off_for_the_rest_of_the_run(colour):
    colour()
    assert console.enabled()
    assert console.paint("AVOID", "avoid").startswith("\x1b[")
    console.disable()                        # the colour fixture restores the flag
    assert not console.enabled()
    assert console.paint("AVOID", "avoid") == "AVOID"


# --- what gets painted -----------------------------------------------------

def test_verdicts_take_the_same_colours_as_the_html_report(colour):
    colour()
    assert set(console.VERDICT_STYLES) == set(report.VERDICT_COLOR)
    assert console.paint_verdict("PREFER") == "\x1b[32mPREFER\x1b[0m"
    assert console.paint_verdict("CONDITIONAL") == "\x1b[33mCONDITIONAL\x1b[0m"
    assert console.paint_verdict("AVOID") == "\x1b[31mAVOID\x1b[0m"
    assert console.paint_verdict("NOT ASSESSED") == "\x1b[2mNOT ASSESSED\x1b[0m"


def test_an_unknown_style_is_returned_unpainted(colour):
    colour()
    assert console.paint("7", "chartreuse") == "7"
    assert console.paint_verdict("MAYBE") == "MAYBE"


# --- alignment, the part that is not cosmetic ------------------------------

def test_pad_pads_a_painted_string_to_the_same_visible_width_as_a_plain_one(colour):
    colour()
    painted, plain = console.pad(console.paint_verdict("AVOID"), 12), console.pad("AVOID", 12)
    assert console.visible_width(painted) == console.visible_width(plain) == 12
    assert len(painted) != len(plain)         # the escapes are still in there


def test_the_naive_f_string_is_the_bug_pad_exists_to_fix(colour):
    colour()
    verdict = console.paint_verdict("AVOID")
    assert console.visible_width(f"{verdict:<12}") == 5      # seven columns short
    assert console.visible_width(console.pad(verdict, 12)) == 12


def test_pad_right_aligns_and_never_truncates():
    assert console.pad("7", 5, "right") == "    7"
    long_name = "Mitsubishi Electric MELSEC iQ-R"
    assert console.pad(long_name, 6) == long_name
    assert console.pad("", 0) == ""


def test_pad_rejects_an_unknown_alignment():
    with pytest.raises(ValueError, match="centre"):
        console.pad("AVOID", 12, align="centre")


# --- the overview ----------------------------------------------------------

def test_overview_describes_an_index_that_has_data(db_path):
    text = console.overview(db_path)
    assert db_path in text
    assert "1 advisories" in text and "1 products" in text
    assert 'retrust score --vendor Siemens' in text
    assert "No index" not in text


def test_overview_without_an_index_gives_the_build_command_and_creates_nothing(tmp_path):
    missing = tmp_path / "missing.db"
    text = console.overview(str(missing))
    assert "No index yet" in text and "retrust ingest --csaf" in text
    assert not missing.exists()               # being greeted must leave no database


def test_overview_on_an_empty_index_says_it_is_empty(tmp_path):
    path = tmp_path / "empty.db"
    index.connect(str(path))
    text = console.overview(str(path))
    assert "empty" in text and "retrust ingest" in text
    assert not re.search(r"\d+ advisories", text)     # nothing measured, nothing claimed


def test_overview_on_a_file_that_is_not_an_index_does_not_raise(tmp_path):
    path = tmp_path / "junk.db"
    path.write_bytes(b"not a database")
    text = console.overview(str(path))
    assert "not a usable" in text and "retrust ingest" in text


def test_overview_stays_short_enough_to_read(tmp_path, db_path):
    directory = tmp_path / "adirectory"
    directory.mkdir()
    empty = tmp_path / "empty2.db"
    index.connect(str(empty))
    for target in (db_path, str(tmp_path / "gone.db"), str(empty), str(directory)):
        assert len(console.overview(target).splitlines()) < 20, target


# --- completion ------------------------------------------------------------

def test_bash_completion_names_every_command_and_its_flags():
    script = console.completion("bash", COMMANDS, GLOBAL_FLAGS)
    for name in COMMANDS:
        assert f"        {name}) flags=" in script
    # -h and --help are global, so they are offered once, from shared, not twice.
    assert 'ingest) flags="--csaf --kev --epss"' in script
    assert 'stats) flags=""' in script
    assert 'shared="-h --help --db --no-color"' in script
    assert "eval \"$(retrust completion bash)\"" in script     # how to install it


def test_zsh_completion_starts_with_the_compdef_line():
    lines = console.completion("zsh", COMMANDS, GLOBAL_FLAGS).splitlines()
    assert lines[0] == "#compdef retrust"     # compinit only reads the tag on line 1
    assert "Install" in lines[1]


@pytest.mark.parametrize("commands", [COMMANDS, {}], ids=["commands", "none"])
@pytest.mark.parametrize("shell", ["bash", "zsh"])
def test_generated_scripts_pass_their_shell_syntax_check(tmp_path, shell, commands):
    if not shutil.which(shell):
        pytest.skip(f"{shell} is not installed")
    script = tmp_path / f"completion.{shell}"
    script.write_text(console.completion(shell, commands, GLOBAL_FLAGS))
    checked = subprocess.run([shell, "-n", str(script)],
                             capture_output=True, text=True)
    assert checked.returncode == 0, checked.stderr


def test_completion_rejects_an_unsupported_shell():
    with pytest.raises(ValueError, match="fish") as error:
        console.completion("fish", COMMANDS)
    assert "bash" in str(error.value) and "zsh" in str(error.value)


def test_completion_uses_only_the_names_it_was_given():
    """Nothing is hardcoded, so a renamed command cannot outlive the parser."""
    script = console.completion("bash", {"invented": ["--nonexistent-flag"]})
    assert "invented" in script and "--nonexistent-flag" in script
    assert "ingest" not in script
