"""Make the terminal output easier to live with.

Three comforts, none of which can change a score. Colour on the verdict alone --
green, amber, red, the same ISA-101 convention the HTML report follows -- because
AVOID and PREFER look identical while you skim twenty candidates, and colour on
everything is colour on nothing. An overview for bare `retrust`, since an
argparse usage error is a poor way to greet somebody who has just installed the
tool. And a completion script generated from the real parser, so it cannot go on
advertising a flag that was renamed last month.

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

# ANSI SGR parameters. Deliberately few: colour is reserved for the abnormal.
STYLES = {"prefer": "32", "conditional": "33", "avoid": "31", "faint": "2",
          "gate": "31"}     # a hard gate is the same red as the verdict it forces

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


HEADER = "ReTrust scores OT hardware for cyber risk before you buy it."
NEXT_STEPS = """\
Examples:
  retrust search S7-1500
  retrust score --vendor Siemens --product "SIMATIC S7-1500" --version 3.1.6
  retrust compare --candidate "ABB|AC 800M" --candidate "Moxa|EDS-405A"
  retrust batch candidates.csv --html review.html"""
BUILD_STEPS = """\
Build one, and every command after it runs offline:
  retrust ingest --csaf <directory of CSAF JSON files>
  retrust snapshot --restore retrust-snapshot.zip   (a pinned bundle instead)"""
FOOTER = """\
  retrust --help              every command and flag
  retrust completion bash     tab completion for bash or zsh"""


def overview(db_path):
    """What bare `retrust` prints: what the index holds, then what to do next.

    Short on purpose: a wall of text is a worse greeting than the usage error.
    """
    described, has_data = _summarise(db_path)
    return "\n".join([HEADER, "", *described, "",
                      NEXT_STEPS if has_data else BUILD_STEPS, "", FOOTER])


def _summarise(db_path):
    """The count lines for the index at db_path, or why there are none."""
    try:
        # exists() is inside the try because it raises on a path we may not even
        # look at, such as an index under somebody else's home directory.
        if not Path(db_path).exists():
            return [f"No index yet at {db_path}."], False
        # Read-only: index.connect() would add any table the schema lacks, and
        # ReTrust's tables have no business in a database that is not ours.
        counts = index.stats(sqlite3.connect(
            f"{Path(db_path).resolve().as_uri()}?mode=ro", uri=True))
    except Exception as error:    # a directory, unreadable, not a database at all
        return [f"{db_path} is not a usable ReTrust index", f"({error})."], False
    if not counts["advisories"]:
        # Seven zeros would read as a measurement, and nothing was measured.
        return [f"The index at {db_path} is empty: no advisories in it."], False
    return [
        f"Index at {db_path}",
        # "products" would overstate by a factor of two: index.stats counts
        # product rows, and a product gets one per advisory that names it.
        f"  {counts['advisories']:,} advisories, {counts['products']:,} product "
        f"entries, {counts['vendors']:,} vendors, {counts['cves']:,} CVEs",
        f"  {counts['order_numbers']:,} order numbers to match on",
        # Not "CVEs in CISA KEV", which would read as a share of the count above:
        # these are whole catalogues as loaded, most of KEV naming no OT product.
        f"  signals loaded: {counts['kev']:,} KEV entries, "
        f"{counts['epss']:,} EPSS scores",
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
