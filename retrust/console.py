"""Make the terminal output easier to live with, and make it look like ReTrust.

Four comforts, none of which can change a score. A panel grid -- one width, box
rules, a legend beside every reading -- because ISA-101 separates with hairlines
rather than colour, and because a terminal cannot be asked for larger type: what
it can be asked for is space and a shape the eye already knows. Colour on the
verdict alone -- green, amber, red, the same ISA-101 convention the HTML report
follows -- because AVOID and PREFER look identical while you skim twenty
candidates, and colour on everything is colour on nothing. An overview for bare
`retrust`, since an argparse usage error is a poor way to greet somebody who has
just installed the tool. And a completion script generated from the real parser,
so it cannot go on advertising a flag that was renamed last month.

The one part of this that is not cosmetic is pad(). ANSI escape codes count
toward len(), so f"{paint_verdict(verdict):<12}" pads to twelve *bytes* and
shunts every later column leftwards -- but only when colour is on, which is to
say only in front of an audience. pad() measures what a terminal really draws.
"""

import os
import re
import sqlite3
import sys
from pathlib import Path

from . import index

# ANSI SGR parameters, 256-colour so that PREFER is the same green on every
# terminal instead of whatever that terminal's theme happens to call green.
# Deliberately few: colour is reserved for the abnormal. Red is a step brighter
# than the green and the amber because a terminal cannot know whether it is drawn
# on the day panel or the night one, and an alarm legible on only one of them is
# not an alarm.
STYLES = {"prefer": "38;5;29", "conditional": "38;5;136", "avoid": "38;5;160",
          "gate": "38;5;160",    # a hard gate is the same red as the verdict it forces
          "faint": "38;5;245",   # inert: nothing was assessed, so it says nothing
          # Chrome, never a state. Both are the same mid grey on purpose: quieter
          # than the text is the requirement, and on a background we cannot see,
          # the only direction that is reliably quieter is the middle.
          "rule": "38;5;244", "label": "38;5;245"}

# Mirrors report.VERDICT_COLOR, and a test asserts it still does, so terminal and
# report cannot drift into disagreeing about what a verdict looks like.
VERDICT_STYLES = {"PREFER": "prefer", "CONDITIONAL": "conditional",
                  "AVOID": "avoid", "NOT ASSESSED": "faint"}

ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
_forced_off = False


def enabled():
    """True only when a person is looking at a terminal that wants colour."""
    if _forced_off or os.environ.get("NO_COLOR"):
        return False          # any non-empty value counts, per no-color.org
    # Under pytest, or behind a pipe wrapper, stdout may have no isatty at all.
    return os.environ.get("TERM") != "dumb" and bool(
        getattr(sys.stdout, "isatty", lambda: False)())


def disable():
    """Turn colour off for the rest of the run. This is what --no-color calls."""
    global _forced_off
    _forced_off = True


def paint(text, style):
    """Wrap text in one style, or return it unchanged when colour is off.

    An unknown style comes back unpainted rather than raising: presentation must
    never be the thing that aborts a scoring run.
    """
    code = STYLES.get(style)
    return f"\x1b[{code}m{text}\x1b[0m" if code and enabled() else str(text)


def paint_verdict(verdict):
    """Colour one of the four verdicts a scoring run can reach."""
    return paint(verdict, VERDICT_STYLES.get(verdict, ""))


def visible_width(text):
    """Width as the terminal draws it: escapes cost bytes but no columns."""
    return len(ESCAPE.sub("", str(text)))


def pad(text, width, align="left"):
    """Pad to `width` visible columns, for a column that may be painted.

    Text wider than `width` comes back whole: a silently clipped product name is
    a worse lie than a ragged column, and callers wanting truncation slice first.
    """
    if align not in ("left", "right"):
        raise ValueError(f"align must be 'left' or 'right', not {align!r}")
    filler = " " * max(0, width - visible_width(text))
    return filler + str(text) if align == "right" else str(text) + filler


# The panel grid. One width for every rule and every box drawn on it, because
# rules that do not line up read as two panels rather than one instrument.
WIDTH = 76
KEYS = 5       # the narrow left cell the interactive menu keeps its keys in
LABEL = 24     # the menu's label cell, before its description
FIELD = 10     # the legend column of a status strip
NAME = "ReTrust"
TAG = "OT hardware cyber-risk, before you buy"


def hairline(left="├", right="┤", joint=None):
    """One horizontal rule of the grid, crossed at the key column by `joint`."""
    line = "─" * (WIDTH - 2)
    if joint:
        line = line[:KEYS] + joint + line[KEYS + 1:]
    return paint(left + line + right, "rule")


def row(text, key=None):
    """One row of a panel: content between two rails, padded onto the grid.

    `key` fills the menu's key column; without it the row is a single wide cell,
    as on a status strip. pad() does the padding, so a value too long for the
    grid pushes the rail out rather than being cut -- an order number that has
    been silently shortened is worse than a ragged panel.
    """
    rail = paint("│", "rule")
    head = f"{pad(key, KEYS - 1, 'right')} {rail} " if key is not None else "  "
    return f"{rail}{pad(head + text, WIDTH - 2)}{rail}"


def section(name):
    """A heading: the legend uppercased and stamped into a rule across the panel.

    The same gesture as the nameplate's top line, which is what holds the two
    together, and what stands in for the larger type a terminal cannot ask for.
    """
    head = f"{name.upper()} "
    return paint(head, "label") + paint("─" * (WIDTH - len(head)), "rule")


def nameplate(tag=TAG, rows=()):
    """The tool's face: the name stamped into the top rule, over a status strip.

    `rows` are (legend, reading) pairs. Structure carries this rather than
    colour, so it survives a pipe and NO_COLOR intact: the box says where the
    panel is and the legend column says which reading is which, without a single
    escape code being drawn.
    """
    head = [paint("┌─ ", "rule"), NAME, paint(" ── ", "rule"),
            paint(tag.upper(), "label"), " "]
    fill = WIDTH - 1 - sum(visible_width(part) for part in head)
    # A blank legend is a row continuing the one above it, and painting an empty
    # string only spends escape codes on nothing.
    return "\n".join(["".join(head) + paint("─" * fill + "┐", "rule"),
                      *(row(pad(paint(name.upper(), "label") if name else "",
                                FIELD) + str(reading))
                        for name, reading in rows),
                      hairline("└", "┘")])


START = """\
  retrust shell             the menu, and no flags to learn
  retrust search S7-1500
  retrust score --vendor Siemens --product "SIMATIC S7-1500" --version 3.1.6
  retrust compare --candidate "ABB|AC 800M" --candidate "Moxa|EDS-405A"
  retrust batch candidates.csv --html review.html"""
BUILD = """\
  Build one and every command after it runs offline.
  retrust ingest --csaf <directory of CSAF JSON files>
  retrust snapshot --restore retrust-snapshot.zip  (a pinned bundle instead)"""
REFERENCE = """\
  retrust --help            every command and flag
  retrust completion bash   tab completion for bash or zsh"""


def overview(db_path):
    """What bare `retrust` prints: what the index holds, then what to do next.

    Short on purpose: a wall of text is a worse greeting than the usage error.
    """
    rows, has_data = _summarise(db_path)
    return "\n".join([nameplate(rows=rows), "",
                      section("start here" if has_data else "build the index"),
                      START if has_data else BUILD, "",
                      section("reference"), REFERENCE])


def _summarise(db_path):
    """The status strip for the index at db_path, or why it has no readings."""
    try:
        # exists() is inside the try because it raises on a path we may not even
        # look at, such as an index under somebody else's home directory.
        # The path is a reading of its own, never wrapped in a sentence: a strip
        # row leaves 62 columns, and prose in front of a --db path spends a
        # dozen of them shoving the rail off an 80-column terminal.
        if not Path(db_path).exists():
            return [("index", db_path), ("", "No index yet.")], False
        # Read-only: index.connect() would add any table the schema lacks, and
        # ReTrust's tables have no business in a database that is not ours.
        counts = index.stats(sqlite3.connect(
            f"{Path(db_path).resolve().as_uri()}?mode=ro", uri=True))
    except Exception as error:    # a directory, unreadable, not a database at all
        return [("index", db_path),
                ("", f"is not a usable ReTrust index ({error}).")], False
    if not counts["advisories"]:
        # Seven zeros would read as a measurement, and nothing was measured.
        return [("index", db_path),
                ("holds", "nothing yet: the index is empty")], False
    return [
        ("index", db_path),
        # "products" would overstate by a factor of two: index.stats counts
        # product rows, and a product gets one per advisory that names it.
        ("holds", f"{counts['advisories']:,} advisories, "
                  f"{counts['products']:,} product entries"),
        ("", f"{counts['vendors']:,} vendors, {counts['cves']:,} CVEs"),
        # Its own row because matching on the order number is the whole trick:
        # it is what the nameplate on the panel says, and CPE does not have it.
        ("match on", f"{counts['order_numbers']:,} order numbers"),
        # Not "CVEs in CISA KEV", which would read as a share of the count above:
        # these are whole catalogues as loaded, most of KEV naming no OT product.
        ("signals", f"{counts['kev']:,} KEV entries, "
                    f"{counts['epss']:,} EPSS scores"),
    ], True


# %-formatting below, not str.format: both templates are full of the shell's own
# braces, and doubling every one would make them unreadable.
BASH = """\
# retrust completion for bash. Install: add  eval "$(retrust completion bash)"  to ~/.bashrc
_retrust() {
    local subcommands="%(commands)s" shared="%(shared)s" flags="" subcommand="" word
    # The subcommand is the first word that is one; the value of --db is not.
    for word in "${COMP_WORDS[@]:1:COMP_CWORD-1}"; do
        [[ " $subcommands " == *" $word "* ]] && { subcommand=$word; subcommands=""; break; }
    done
    case "$subcommand" in
%(cases)s
    esac
    COMPREPLY=($(compgen -W "$subcommands $flags $shared" -- "${COMP_WORDS[COMP_CWORD]}"))
}
complete -F _retrust retrust
"""

ZSH = """\
#compdef retrust
# Install: add  eval "$(retrust completion zsh)"  to ~/.zshrc
_retrust() {
    local shared=(%(shared)s) subcommands=(%(commands)s) subcommand="" word
    # ${words[2]} would do until somebody types `retrust --db other.db score`.
    for word in ${words[2,CURRENT-1]}; do
        (( $subcommands[(I)$word] )) && { subcommand=$word; subcommands=(); break }
    done
    case "$subcommand" in
%(cases)s
        *) compadd -- $subcommands $shared ;;
    esac
}
# Guarded because compdef only exists once compinit has run, and `|| true` so that
# sourcing this from ~/.zshrc before compinit does not leave $? at 1 for the prompt.
(( $+functions[compdef] )) && compdef _retrust retrust || true
"""


def completion(shell, commands, global_flags=()):
    """A bash or zsh completion script, as a string.

    `commands` maps each subcommand name to its own option strings, `global_flags`
    holds the top-level ones, and a bare sequence of names is accepted too -- those
    subcommands then complete to the global flags alone. The CLI reads all of it
    off the live parser, so a generated script cannot outlive a renamed flag.
    """
    template = {"bash": BASH, "zsh": ZSH}.get(shell)
    if template is None:
        raise ValueError(f"no completion script for {shell!r}; choose bash or zsh")
    if not hasattr(commands, "items"):    # names alone, without their flags
        commands = dict.fromkeys(commands, ())
    # A flag that is also global belongs in `shared` alone, or the menu offers
    # --help twice. Joined here: reusing a quote inside an f-string needs 3.12.
    own = {name: " ".join(flag for flag in flags if flag not in global_flags)
           for name, flags in commands.items()}
    # Only flags of its own earn a branch; the loop above dropped the names.
    cases = [f'        {name}) flags="{flags}" ;;' if shell == "bash"
             else f"        {name}) compadd -- {flags} $shared ;;"
             for name, flags in own.items() if flags]
    return template % {"commands": " ".join(commands), "cases": "\n".join(cases),
                       "shared": " ".join(global_flags)}
