"""Tests for the interactive menu.

Nothing here scores anything; the actions are the same functions the flags call
and are tested there. What needs pinning is the session itself: that a wrong
answer cannot end it, that blank always means "go back", and that saving is a
separate decision from producing so nobody has to know in advance what format
they wanted.
"""

import pytest

from retrust import shell


def _reader(*answers):
    """Stand in for input(), raising EOFError when the answers run out."""
    queue = list(answers)

    def read(_prompt=""):
        if not queue:
            raise EOFError
        return queue.pop(0)
    return read


# --- asking ----------------------------------------------------------------

def test_an_answer_comes_back_stripped():
    assert shell.ask("Vendor", reader=_reader("  Siemens  ")) == "Siemens"


def test_blank_means_go_back():
    assert shell.ask("Vendor", reader=_reader("")) is shell.CANCELLED


def test_a_default_is_used_for_a_blank():
    assert shell.ask("Exposure", "controlled", reader=_reader("")) == "controlled"


def test_a_required_question_asks_once_more_then_lets_you_leave():
    """A prompt nobody can escape traps whoever opened the menu by accident."""
    assert shell.ask("Vendor", required=True, reader=_reader("", "")) is shell.CANCELLED


def test_a_required_question_accepts_the_second_answer():
    assert shell.ask("Vendor", required=True, reader=_reader("", "ABB")) == "ABB"


def test_end_of_input_cancels_rather_than_raising():
    assert shell.ask("Vendor", reader=_reader()) is shell.CANCELLED


def test_yes_no_reads_the_first_letter():
    assert shell.ask_yes("Save", reader=_reader("yes")) is True
    assert shell.ask_yes("Save", reader=_reader("n")) is False
    assert shell.ask_yes("Save", default=True, reader=_reader("")) is True


# --- the menu --------------------------------------------------------------

ACTIONS = {"1": ("Do a thing", "a description", lambda result, reader: None)}


def test_quit_leaves(capsys):
    assert shell.choose(ACTIONS, _reader("q")) is None


def test_end_of_input_leaves(capsys):
    assert shell.choose(ACTIONS, _reader()) is None


def test_an_unknown_choice_asks_again(capsys):
    assert shell.choose(ACTIONS, _reader("9", "1")) == "1"
    assert "not on the menu" in capsys.readouterr().out


def test_the_menu_lists_every_action(capsys):
    shell.choose(ACTIONS, _reader("q"))
    out = capsys.readouterr().out
    assert "Do a thing" in out and "a description" in out


# --- the loop --------------------------------------------------------------

def test_an_action_that_raises_does_not_end_the_session(capsys):
    """One bad answer must cost the answer, not the session."""
    def explode(result, reader):
        raise ValueError("no such file")

    calls = []
    actions = {"1": ("Break", "", explode),
               "2": ("Work", "", lambda r, reader: calls.append(1))}
    shell.run(actions, {}, reader=_reader("1", "2", "q"))
    out = capsys.readouterr().out
    assert "Break failed: no such file" in out
    assert calls == [1]                      # it carried on to the next choice


def test_ctrl_c_returns_to_the_menu(capsys):
    def interrupted(result, reader):
        raise KeyboardInterrupt

    shell.run({"1": ("Stop", "", interrupted)}, {}, reader=_reader("1", "q"))
    out = capsys.readouterr().out
    assert "Cancelled" in out
    assert "Bye" in out                      # and still exited cleanly


def test_a_result_is_held_for_the_next_action():
    produced = shell.Result(kind="score", records=[{"a": 1}])
    seen = []
    actions = {"1": ("Make", "", lambda r, reader: produced),
               "2": ("Use", "", lambda r, reader: seen.append(r))}
    shell.run(actions, {}, reader=_reader("1", "2", "q"))
    assert seen == [produced]


def test_an_action_returning_nothing_keeps_the_previous_result():
    produced = shell.Result(kind="score", records=[{"a": 1}])
    seen = []
    actions = {"1": ("Make", "", lambda r, reader: produced),
               "2": ("Look", "", lambda r, reader: None),
               "3": ("Use", "", lambda r, reader: seen.append(r))}
    shell.run(actions, {}, reader=_reader("1", "2", "3", "q"))
    assert seen == [produced]


# --- saving ----------------------------------------------------------------

def test_nothing_to_save_says_so(capsys):
    shell.save(shell.Result(), {"json": lambda r, p: p}, _reader())
    assert "Nothing to save yet" in capsys.readouterr().out


def test_saving_writes_through_the_chosen_writer():
    written = {}
    result = shell.Result(kind="score", records=[{"a": 1}])
    shell.save(result, {"json": lambda r, p: written.setdefault("path", p)},
               _reader("json", "out.json"))
    assert written["path"] == "out.json"


def test_an_unknown_format_is_refused_not_guessed(capsys):
    result = shell.Result(records=[{"a": 1}])
    shell.save(result, {"json": lambda r, p: p}, _reader("pdf"))
    assert "No such format: pdf" in capsys.readouterr().out


def test_a_failed_write_does_not_lose_the_result(capsys):
    """A bad path is a typo, not a reason to make somebody re-run the scoring."""
    def explode(result, path):
        raise OSError("read-only file system")

    result = shell.Result(records=[{"a": 1}])
    shell.save(result, {"json": explode}, _reader("json", "/nope/out.json"))
    assert "Could not write" in capsys.readouterr().out
    assert result.savable                    # still there to try again


def test_cancelling_the_save_writes_nothing():
    shell.save(shell.Result(records=[{"a": 1}]),
               {"json": lambda r, p: pytest.fail("should not write")}, _reader(""))


# --- the command line it teaches -------------------------------------------

def test_the_equivalent_command_is_printed(capsys):
    shell.echo_command(["score", "--vendor", "ABB", "--product", "AC 800M"])
    out = capsys.readouterr().out
    assert '$ retrust score --vendor ABB --product "AC 800M"' in out
