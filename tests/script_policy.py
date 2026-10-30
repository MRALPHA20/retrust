"""The script policy as tests state it (decision D1, docs/design/implementation-plan.md section 7).

A web page may carry exactly one script element: the external, same-origin,
deferred enhancement script. Tests that used to assert "no <script at all" now
strip that one element first, so a second script, an inline script or an
injected tag still fails them.
"""
import re

ENHANCEMENT_TAG = re.compile(r'<script src="/static/retrust\.js\?v=[0-9a-f]{8}" defer></script>')
ANY_SCRIPT = re.compile(r"<script\b", re.I)
EVENT_HANDLER = re.compile(r"""<[a-z][^>]*\son[a-z]+\s*=""", re.I)


def without_enhancement(markup):
    """The markup minus the one allowed script element."""
    return ENHANCEMENT_TAG.sub("", markup)


def script_problems(markup):
    """Everything about scripts in a web page that the policy forbids."""
    problems = []
    if len(ENHANCEMENT_TAG.findall(markup)) != 1:
        problems.append("expected exactly one enhancement script element")
    if ANY_SCRIPT.search(without_enhancement(markup)):
        problems.append("another <script> element is present")
    if EVENT_HANDLER.search(markup):
        problems.append("an on*= event handler attribute is present")
    return problems
