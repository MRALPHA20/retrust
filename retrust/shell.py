"""An interactive session, for people who do not want to learn the flags.

Everything ReTrust does is a command with flags, which is right for a pipeline
and wrong for the person it is actually for. A procurement engineer comparing
four PLCs should not have to remember that candidates are pipe-separated.

So this is a menu: pick a number, answer the questions, keep the result. Two
choices make it more than a wrapper. Every action prints the equivalent command
line before it runs, so anyone using this graduates to scripting it without
being taught. And results are held after they are shown, so saving is a separate
decision from producing -- nobody has to know in advance that they wanted HTML.
"""

from dataclasses import dataclass, field

from . import console

# The legend stamped on the nameplate, not a line of its own: what a first-time
# reader needs is on the panel below it, where q sits under its own rule.
BANNER = "interactive session"

# Descriptive commands are easier to remember; numeric inputs remain aliases.
COMMANDS = {"1": "search", "2": "score", "3": "compare", "4": "alternatives",
            "5": "vendor", "6": "batch", "7": "lev", "8": "ssvc",
            "9": "diff", "10": "timeline", "11": "questions", "s": "save",
            "o": "order"}

# A blank answer means "I have changed my mind", everywhere, so no prompt can
# trap somebody who opened it by accident.
CANCELLED = object()


@dataclass
class Result:
    """The last thing produced, held so it can be saved afterwards."""

    kind: str = ""
    blocks: list = field(default_factory=list)     # for the HTML report
    records: list = field(default_factory=list)    # for JSON and CSV
    meta: dict = field(default_factory=dict)
    title: str = "ReTrust result"

    @property
    def savable(self):
        return bool(self.blocks or self.records)


def ask(prompt, default=None, required=False, reader=input):
    """One question. Blank cancels unless a default or an answer is required."""
    label = console.paint(f"  {prompt}", "accent")
    label += f" [{default}]: " if default else ": "
    while True:
        try:
            answer = reader(label).strip()
        except EOFError:
            return CANCELLED
        if answer:
            return answer
        if default is not None:
            return default
        if not required:
            return CANCELLED
        print("  That one is needed. Leave it blank again to go back.")
        required = False


def ask_yes(prompt, default=False, reader=input):
    answer = ask(f"{prompt} (y/n)", "y" if default else "n", reader=reader)
    return answer is not CANCELLED and str(answer).lower().startswith("y")


def choose(actions, reader=input):
    """Show the menu and return the chosen key, or None to quit."""
    print()
    print(console.heading("Choose a command"))
    for key, (label, description, _) in actions.items():
        command = COMMANDS.get(key, key)
        if console.terminal_width() >= 72:
            print("  " + console.pad(console.paint(command, "command"), 15)
                  + console.paint(label, "title"))
            print(console.prose(description, indent="                 ", style="label"))
        else:
            print(console.prose(f"{command} / {label}", style="accent"))
            print(console.prose(description, indent="    ", style="label"))
    print(console.prose("quit / Leave the workspace", style="label"))
    print(console.prose("Type a command. Blank answers go back; optional fields can be skipped.",
                        style="label"))
    while True:
        try:
            answer = reader(console.paint("\n  retrust > ", "accent")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            return None
        if answer in ("q", "quit", "exit"):
            return None
        if answer in actions:
            return answer
        for key in actions:
            if answer == COMMANDS.get(key):
                return key
        if answer:
            print(f"  {answer!r} is not on the menu.")


def echo_command(parts):
    """Print the command line this menu choice is equivalent to.

    The point of the menu is not to hide the flags forever. Somebody who runs
    the same comparison a third time should be able to copy this into a script,
    and they can only do that if they have seen it.
    """
    quoted = " ".join(f'"{p}"' if " " in str(p) else str(p) for p in parts)
    print(f"\n  $ retrust {quoted}\n")


def save(result, writers, reader=input):
    """Offer to keep the last result. `writers` maps a format to a callable."""
    if not result.savable:
        print("Nothing to save yet. Run something first.")
        return
    available = [name for name in ("html", "json", "csv") if name in writers]
    choice = ask(f"Save as ({'/'.join(available)})", reader=reader)
    if choice is CANCELLED:
        return
    choice = str(choice).lower()
    if choice not in writers:
        print(f"  No such format: {choice}")
        return
    if (path := ask("File name", f"retrust-result.{choice}", reader=reader)) is CANCELLED:
        return
    try:
        written = writers[choice](result, str(path))
    except Exception as error:          # a bad path is not a reason to lose the run
        print(f"  Could not write {path}: {error}")
        return
    print(f"  Written to {written}")


def run(actions, writers, banner=BANNER, reader=input, greet=None):
    """The menu loop. Actions return a Result, or None if they produced nothing."""
    # The caller writes its greeting as a sentence; a status strip is a list of
    # readings, so the full stop goes, and the legend matches the one bare
    # `retrust` puts these same three numbers under.
    print(console.welcome(banner,
                            [("holds", str(greet).rstrip("."))] if greet else []))
    result = Result()
    while (key := choose(actions, reader)) is not None:
        label, _, action = actions[key]
        try:
            produced = action(result, reader)
        except KeyboardInterrupt:
            # Ctrl-C abandons the question, not the session. Somebody halfway
            # through the wrong menu entry should land back on the menu.
            print("\n  Cancelled.")
            continue
        except (Exception, SystemExit) as error:  # command validation stays in the menu
            print(f"\n  {label} failed: {error}")
            continue
        if produced is not None:
            result = produced
        if result.savable:
            print(console.prose("Result ready. Type save to export HTML, JSON or CSV.",
                                style="accent"))
    print("\nBye.")
    return result
