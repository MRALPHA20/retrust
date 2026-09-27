"""Tests for the terminal presentation layer.

Three of these matter more than the rest. The first is that pad() measures
visible width: a painted verdict and a plain one must occupy the same columns, or
every aligned table in the tool breaks the moment colour is on -- which is to say
in front of an audience, and nowhere else. The second is that overview() never
writes to the database it is describing, because index.connect() would, and a
missing index would then report itself as an empty one on the next run.

The third is that the completion scripts are driven by real shells rather than
read. Both shells once looked correct and offered nothing useful after a global
flag (`retrust --db other.db score <TAB>`), which `bash -n` cannot see: a syntax
check only proves the script parses, so the cases below run it.

Colour depends on the environment, so every test that needs it states the whole
environment it assumes rather than inheriting the one pytest happens to run in.
"""

import json
import os
import re
import shlex
import shutil
import sqlite3
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
    monkeypatch.setenv("NO_COLOR", "0")      # the value is not read, only its presence
    assert not console.enabled()
    monkeypatch.setenv("NO_COLOR", "")       # except an empty one, which no-color.org
    assert console.enabled()                 # says to ignore


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
    """Pinned exactly, and in 256 colour: `31` is whatever the theme calls red.

    The four verdicts are the ISA-101 states, and a state the reader has to
    interpret twice -- once here, once in the report they paste it into -- is not
    a state. So the codes are the palette's, not the terminal's own sixteen.
    """
    colour()
    assert set(console.VERDICT_STYLES) == set(report.VERDICT_COLOR)
    assert console.paint_verdict("PREFER") == "\x1b[38;5;29mPREFER\x1b[0m"
    assert console.paint_verdict("CONDITIONAL") == "\x1b[38;5;136mCONDITIONAL\x1b[0m"
    assert console.paint_verdict("AVOID") == "\x1b[38;5;160mAVOID\x1b[0m"
    assert console.paint_verdict("NOT ASSESSED") == "\x1b[38;5;245mNOT ASSESSED\x1b[0m"


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


# --- the panel grid --------------------------------------------------------

def test_every_line_of_the_grid_is_drawn_to_one_width(colour):
    colour(isatty=False)
    lines = [*console.nameplate(rows=[("index", "retrust.db")]).splitlines(),
             console.section("start here"), console.row("a reading"),
             console.row("a reading", "1"), console.hairline("├", "┤", "┼")]
    assert {console.visible_width(line) for line in lines} == {console.WIDTH}


def test_the_grid_holds_its_width_once_it_is_painted(colour):
    """The rules are painted, and paint is exactly what shears a column."""
    colour()
    plate = console.nameplate(rows=[("index", "retrust.db")])
    assert "\x1b[" in plate
    assert all(console.visible_width(line) == console.WIDTH
               for line in plate.splitlines())


def test_the_key_column_rule_meets_the_rail_beneath_it(colour):
    """One column for the joint and the rail, or the menu shears below its head."""
    colour(isatty=False)
    assert console.row("Quit", "q").index("│", 1) == \
        console.hairline("┌", "┐", "┬").index("┬")


def test_a_reading_too_wide_for_the_grid_keeps_every_character(colour):
    """An order number trimmed to fit the panel is a different order number."""
    colour(isatty=False)
    number = "6ES7 516-3AN02-0AB0"
    assert number in console.row(number, "1")
    assert number * 5 in console.row(number * 5)     # and it widens, not truncates


def test_a_panel_still_says_which_reading_is_which_with_colour_off(colour):
    """Structure carries this, not colour: it has to survive a pipe intact."""
    colour(isatty=False)
    plate = console.nameplate(rows=[("match on", "1,615 order numbers")])
    assert "\x1b" not in plate
    assert plate.startswith("┌─ ReTrust ── OT HARDWARE")
    assert "MATCH ON  1,615 order numbers" in plate


# --- the overview ----------------------------------------------------------

def test_overview_describes_an_index_that_has_data(db_path):
    text = console.overview(db_path)
    assert db_path in text
    assert "1 advisories" in text and "1 product entries" in text
    assert 'retrust score --vendor Siemens' in text
    assert "No index" not in text


def test_overview_counts_product_entries_rather_than_claiming_distinct_products(tmp_path):
    """The same product under three advisories is three rows, not three products.

    index.stats counts rows, which on the real corpus is 27,234 against 11,644
    distinct vendor-and-name pairs. Calling that "products" in the first thing a
    new user reads would overstate the index by a factor of two.
    """
    directory = tmp_path / "csaf"
    directory.mkdir()
    for number in range(3):
        advisory = json.loads(json.dumps(ADVISORY))
        advisory["document"]["tracking"]["id"] = f"ICSA-26-00{number}-01"
        (directory / f"a{number}.json").write_text(json.dumps(advisory))
    path = tmp_path / "repeats.db"
    index.build(str(path), str(directory))
    text = console.overview(str(path))
    assert "3 advisories, 3 product entries" in text
    assert "3 products" not in text            # there is one, named three times


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


def test_overview_on_a_path_it_may_not_even_look_at(tmp_path):
    """Path.exists() raises on an unreadable directory, so the check is guarded.

    An index at /var/lib/retrust or under another user's home is the realistic
    case, and a traceback is not the way to say "I cannot read that".
    """
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "index.db").write_bytes(b"")
    locked.chmod(0o000)
    try:
        if os.access(locked / "index.db", os.F_OK):
            pytest.skip("running as root, where the permission bits do not bite")
        text = console.overview(str(locked / "index.db"))
    finally:
        locked.chmod(0o700)
    assert "not a usable ReTrust index" in text and "Permission denied" in text


def test_overview_leaves_another_tool_s_database_alone(tmp_path):
    """Somebody else's SQLite file is not an empty index, and must not become one.

    index.connect() would add every missing ReTrust table to it and the greeting
    would then describe the result as an empty index, having quietly made it one.
    """
    path = tmp_path / "somebody-elses.db"
    other = sqlite3.connect(path)
    other.execute("CREATE TABLE payroll (name TEXT)")
    other.commit()
    text = console.overview(str(path))
    assert "not a usable ReTrust index" in text and "empty" not in text
    tables = {row[0] for row in other.execute("SELECT name FROM sqlite_master")}
    assert tables == {"payroll"}


def test_overview_reports_the_signal_catalogues_it_loaded_not_a_share_of_the_index(
        tmp_path, db_path):
    """KEV's number is the catalogue, so it must not be labelled as index CVEs.

    index.stats counts every KEV entry loaded, most naming software no advisory
    here mentions. Printed as "N CVEs in CISA KEV" beside the index's own CVE
    count it reads as a subset of it, which would overstate the exposure of
    everything in the index by whatever the ratio happens to be.
    """
    (tmp_path / "kev.json").write_text(json.dumps({"vulnerabilities": [
        {"cveID": "CVE-2026-0001", "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-1999-9999"}]}))       # in KEV, unknown to this index
    (tmp_path / "epss.csv").write_text(
        "#model_version:test\ncve,epss,percentile\n"
        "CVE-2026-0001,0.5,0.9\nCVE-1999-9999,0.1,0.2\n")
    counts = index.load_exploitation(index.connect(db_path),
                                     str(tmp_path / "kev.json"),
                                     str(tmp_path / "epss.csv"))
    assert counts == {"kev": 2, "epss": 1}   # EPSS is filtered to CVEs we reference
    text = console.overview(db_path)
    assert "2 KEV entries" in text and "1 EPSS scores" in text
    assert "2 CVEs" not in text              # the index holds one, and it is not two


def test_overview_stays_short_enough_to_read(tmp_path, db_path):
    directory = tmp_path / "adirectory"
    directory.mkdir()
    empty = tmp_path / "empty2.db"
    index.connect(str(empty))
    for target in (db_path, str(tmp_path / "gone.db"), str(empty), str(directory)):
        assert len(console.overview(target).splitlines()) < 20, target


# --- completion, as text ---------------------------------------------------

def test_bash_completion_names_every_command_and_the_flags_it_alone_takes():
    script = console.completion("bash", COMMANDS, GLOBAL_FLAGS)
    assert 'subcommands="ingest stats score"' in script
    # -h and --help are global, so they are offered once, from shared, not twice.
    assert 'ingest) flags="--csaf --kev --epss"' in script
    assert 'shared="-h --help --db --no-color"' in script
    # stats has nothing of its own left, and a branch saying so would be empty.
    assert "stats)" not in script
    assert "eval \"$(retrust completion bash)\"" in script     # how to install it


def test_zsh_completion_starts_with_the_compdef_line():
    lines = console.completion("zsh", COMMANDS, GLOBAL_FLAGS).splitlines()
    assert lines[0] == "#compdef retrust"     # compinit only reads the tag on line 1
    assert "Install" in lines[1]


@pytest.mark.parametrize("shell", ["bash", "zsh"])
def test_completion_accepts_command_names_without_their_flags(shell):
    """A caller that can see the commands but not their flags still gets a script."""
    script = console.completion(shell, ["ingest", "score"], GLOBAL_FLAGS)
    assert "ingest score" in script           # named, and nothing claimed about flags
    assert "--csaf" not in script


def test_completion_rejects_an_unsupported_shell():
    with pytest.raises(ValueError, match="fish") as error:
        console.completion("fish", COMMANDS)
    assert "bash" in str(error.value) and "zsh" in str(error.value)


def test_completion_uses_only_the_names_it_was_given():
    """Nothing is hardcoded, so a renamed command cannot outlive the parser."""
    script = console.completion("bash", {"invented": ["--nonexistent-flag"]})
    assert "invented" in script and "--nonexistent-flag" in script
    assert "ingest" not in script


# --- completion, driven by the shells themselves --------------------------

DRIVERS = {
    "bash": """\
source %(script)s
COMP_WORDS=(%(words)s); COMP_CWORD=%(last)s; COMPREPLY=()
_retrust
printf '%%s\\n' "${COMPREPLY[@]}"
""",
    "zsh": """\
source %(script)s
compadd() { shift; print -l -- "$@" }    # the real one exists only mid-completion
words=(%(words)s); CURRENT=%(count)s
_retrust
""",
}


def offered(tmp_path, shell, *words, commands=COMMANDS):
    """What the generated script really offers, as that shell itself runs it.

    The last word is the one being completed, so an empty one asks for every
    candidate: bash filters COMPREPLY by the prefix and zsh does not, and only an
    empty prefix makes the two shells answer comparably.
    """
    if not shutil.which(shell):
        pytest.skip(f"{shell} is not installed")
    script = tmp_path / f"completion.{shell}"
    script.write_text(console.completion(shell, commands, GLOBAL_FLAGS))
    driver = tmp_path / f"driver.{shell}"
    driver.write_text(DRIVERS[shell] % {
        "script": shlex.quote(str(script)), "last": len(words) - 1,
        "words": " ".join(shlex.quote(word) for word in words), "count": len(words)})
    run = subprocess.run([shell, "-f", str(driver)], capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    return run.stdout.split()


@pytest.mark.parametrize("shell", ["bash", "zsh"])
def test_a_shell_offers_the_commands_until_one_is_named(tmp_path, shell):
    assert {"ingest", "score"} <= set(offered(tmp_path, shell, "retrust", ""))
    named = offered(tmp_path, shell, "retrust", "ingest", "")
    assert "--csaf" in named and "score" not in named


@pytest.mark.parametrize("shell", ["bash", "zsh"])
def test_a_shell_offers_each_global_flag_once(tmp_path, shell):
    """--help belongs to every subparser too, and was offered twice for it."""
    assert offered(tmp_path, shell, "retrust", "ingest", "").count("--help") == 1


@pytest.mark.parametrize("words", [("retrust", "--db", "other.db", "score", ""),
                                   ("retrust", "--no-color", "score", "")],
                         ids=["flag-with-a-value", "bare-flag"])
@pytest.mark.parametrize("shell", ["bash", "zsh"])
def test_a_shell_still_finds_the_subcommand_behind_a_global_flag(tmp_path, shell, words):
    """The value of --db is not a subcommand, and --no-color does not hide one.

    Both shells used to take the word after the global flags on trust: bash read
    `other.db` as the subcommand and offered nothing at all, zsh looked only at
    the second word and offered nothing but the global flags.
    """
    assert "--vendor" in offered(tmp_path, shell, *words)


@pytest.mark.parametrize("shell", ["bash", "zsh"])
def test_a_shell_falls_back_to_the_global_flags_for_a_command_with_none(tmp_path, shell):
    after_stats = offered(tmp_path, shell, "retrust", "stats", "")
    assert "--db" in after_stats and "ingest" not in after_stats


@pytest.mark.parametrize("shell", ["bash", "zsh"])
def test_sourcing_a_generated_script_succeeds(tmp_path, shell):
    """Straight into a virgin shell: the zsh one runs before compinit as well.

    It cannot register itself that early and does not try, but it must still end
    on a zero status, or every prompt that shows $? reports a failed startup.
    """
    if not shutil.which(shell):
        pytest.skip(f"{shell} is not installed")
    script = tmp_path / f"completion.{shell}"
    script.write_text(console.completion(shell, COMMANDS, GLOBAL_FLAGS))
    run = subprocess.run([shell, "-f", "-c", f"source {shlex.quote(str(script))}"],
                         capture_output=True, text=True)
    assert (run.returncode, run.stdout, run.stderr) == (0, "", "")


@pytest.mark.parametrize("commands", [COMMANDS, {}], ids=["commands", "none"])
@pytest.mark.parametrize("shell", ["bash", "zsh"])
def test_generated_scripts_pass_their_shell_syntax_check(tmp_path, shell, commands):
    """A parser whose commands take no flags of their own leaves an empty case."""
    if not shutil.which(shell):
        pytest.skip(f"{shell} is not installed")
    script = tmp_path / f"completion.{shell}"
    script.write_text(console.completion(shell, commands, GLOBAL_FLAGS))
    checked = subprocess.run([shell, "-n", str(script)],
                             capture_output=True, text=True)
    assert checked.returncode == 0, checked.stderr
