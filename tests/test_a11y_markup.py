"""Markup accessibility lint, no browser (docs/design/implementation-plan.md section 5, item 2).

A real `retrust serve` over the real index renders every route in the
screenshot matrix plus the HTML exports; each response is parsed with
html.parser and checked against rules a browser would otherwise have to find.
Pure-markup rules cannot see contrast, focus or layout: those stay in tests/e2e.
"""
import collections
import importlib.util
import os
import pathlib
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from html.parser import HTMLParser

import pytest

from script_policy import script_problems

ROOT = pathlib.Path(__file__).resolve().parents[1]
DB = ROOT / "data" / "retrust.db"

# The page list is the screenshot tool's, so a page added there is linted here.
_spec = importlib.util.spec_from_file_location(
    "capture_screenshots", ROOT / "tools" / "capture_screenshots.py")
_capture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_capture)
PAGES = list(_capture.REVIEW_PAGES)

S7 = "vendor=Siemens&product=SIMATIC+S7-1500&version=3.1.6"
EXPORTS = [
    ("export-s7", "/export.html?" + S7),
    ("export-verify", "/export.html?vendor=ABB&product=AC+800M"),
    ("export-hikvision", "/export.html?vendor=Hikvision&product=IP+Camera"),
    ("export-not-identified", "/export.html?vendor=Nobody&product=Nothing+123"),
    ("compare-html", "/compare.html?c=ABB%7CAC%20800M&c=Moxa%7CEDS-405A"),
]

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
        "source", "track", "wbr"}
FIELD_SKIP = {"hidden", "submit", "button", "reset", "image"}
SORT_VALUES = {"ascending", "descending", "none", "other"}
REFERENCES = ("popovertarget", "aria-controls", "aria-describedby", "aria-labelledby")


@pytest.fixture(scope="module")
def fetch():
    if not DB.exists():
        pytest.skip("data/retrust.db is absent")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    env = {k: v for k, v in os.environ.items() if k != "RETRUST_HOSTED"}
    server = subprocess.Popen([sys.executable, "-m", "retrust.cli", "serve", "--port", str(port)],
                              cwd=ROOT, env=env, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    base = "http://127.0.0.1:%d" % port
    try:
        deadline = time.monotonic() + 90
        while True:
            if server.poll() is not None:
                pytest.skip("retrust serve exited")
            try:
                with urllib.request.urlopen(base + "/healthz", timeout=2):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    pytest.skip("retrust serve did not become healthy")
                time.sleep(.5)
        cache = {}

        def get(path):
            if path not in cache:
                try:
                    with urllib.request.urlopen(base + path, timeout=60) as response:
                        cache[path] = (response.status, response.read().decode("utf-8"))
                except urllib.error.HTTPError as error:
                    cache[path] = (error.code, error.read().decode("utf-8"))
            return cache[path]
        yield get
    finally:
        server.terminate()
        server.wait(timeout=10)


# ---------------------------------------------------------------------------

class Audit(HTMLParser):
    """One pass over a document, collecting everything the rules need."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []                      # open elements: [tag, attrs, text_chars, hidden]
        self.ids = collections.Counter()
        self.labels_for = set()
        self.fields = []                     # (tag, attrs, wrapped_in_label)
        self.names = []                      # (tag, attrs) of a/button with no accessible name
        self.bare_th = 0
        self.h1 = 0
        self.lang = None
        self.refs = []                       # (attribute, id)
        self.handlers = []
        self.sort_by_table = []              # one list of aria-sort values per table
        self.nested = []
        self.primary = 0
        self.scripts = 0
        self.alerts = []                     # (class, role) of alert elements
        self.table_depth = 0
        self._named = {}

    # -- helpers
    def _interactive(self, tag, attrs):
        if tag == "a":
            return "href" in attrs
        if tag in ("button", "select", "textarea", "summary"):
            return True
        if tag == "input":
            return attrs.get("type", "text") != "hidden"
        return False

    def handle_starttag(self, tag, attrs):
        attrs = dict((k, v if v is not None else "") for k, v in attrs)
        if tag == "html":
            self.lang = attrs.get("lang")
        for name in attrs:
            if name.startswith("on"):
                self.handlers.append("<%s %s>" % (tag, name))
        if "id" in attrs:
            self.ids[attrs["id"]] += 1
        for ref in REFERENCES:
            for token in attrs.get(ref, "").split():
                self.refs.append((ref, token))
        if tag == "label" and "for" in attrs:
            self.labels_for.add(attrs["for"])
            self.refs.append(("for", attrs["for"]))
        classes = attrs.get("class", "").split()
        if "rt-btn--primary" in classes:
            self.primary += 1
        if any(c.startswith("rt-alert--") for c in classes):
            self.alerts.append((classes, attrs.get("role")))
        if tag == "h1":
            self.h1 += 1
        if tag == "script":
            self.scripts += 1
        if tag == "table":
            self.sort_by_table.append([])
        if "aria-sort" in attrs and self.sort_by_table:
            self.sort_by_table[-1].append(attrs["aria-sort"])
        elif "aria-sort" in attrs:
            self.sort_by_table.append([attrs["aria-sort"]])
        if tag == "th" and "scope" not in attrs:
            self.bare_th += 1
        if self._interactive(tag, attrs):
            outer = [e[0] for e in self.stack if self._interactive(e[0], e[1])]
            if outer:
                self.nested.append("<%s> inside <%s>" % (tag, outer[-1]))
        if tag in ("input", "select", "textarea") and attrs.get("type") not in FIELD_SKIP:
            wrapped = any(e[0] == "label" for e in self.stack)
            self.fields.append((tag, attrs, wrapped))
        if tag == "img" and attrs.get("alt") and self.stack:
            self.stack[-1][2].append("alt")
        if tag in VOID:
            return
        hidden = attrs.get("aria-hidden") == "true" or any(e[3] for e in self.stack)
        self.stack.append([tag, attrs, [], hidden])

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_data(self, data):
        if self.stack and data.strip() and not self.stack[-1][3]:
            for entry in self.stack:
                entry[2].append(data.strip())

    def handle_endtag(self, tag):
        if tag in VOID:
            return
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                _, attrs, text, _ = self.stack[i]
                del self.stack[i:]
                if tag in ("a", "button") and not (
                        text or attrs.get("aria-label") or attrs.get("aria-labelledby")
                        or attrs.get("title")):
                    if tag == "button" or "href" in attrs:
                        self.names.append("<%s %s>" % (tag, sorted(attrs)))
                return


def audit(markup):
    parser = Audit()
    parser.feed(markup)
    parser.close()
    return parser


def problems(markup):
    """Every markup rule that applies to web pages and exports alike."""
    a = audit(markup)
    out = []
    out += ["duplicate id %r" % i for i, n in a.ids.items() if n > 1]
    for tag, attrs, wrapped in a.fields:
        named = (attrs.get("aria-label") or attrs.get("aria-labelledby")
                 or attrs.get("id") in a.labels_for or wrapped)
        if not named:
            out.append("unlabelled <%s %s>" % (tag, attrs.get("name") or attrs.get("id")))
    out += ["no accessible name: " + n for n in a.names]
    if a.bare_th:
        out.append("%d <th> without scope" % a.bare_th)
    for values in a.sort_by_table:
        if len(values) > 1:
            out.append("more than one aria-sort in a table: %s" % values)
        out += ["invalid aria-sort %r" % v for v in values if v not in SORT_VALUES]
    for classes, role in a.alerts:
        needs = {"rt-alert--blocker", "rt-alert--restriction", "rt-alert--error"} & set(classes)
        if needs and role != "alert":
            out.append("%s without role=alert" % sorted(needs))
    out += ["%s -> missing id %r" % (attr, target)
            for attr, target in a.refs if target not in a.ids]
    out += ["nested interactive: " + n for n in a.nested]
    if a.handlers:
        out.append("inline handlers: %s" % a.handlers)
    if a.h1 != 1:
        out.append("%d <h1> elements" % a.h1)
    if not a.lang:
        out.append("html has no lang")
    if a.primary > 1:
        out.append("%d primary buttons" % a.primary)
    return out


# ---------------------------------------------------------------------------

@pytest.mark.parametrize("slug, path", PAGES, ids=[p[0] for p in PAGES])
def test_web_page_markup(fetch, slug, path):
    status, markup = fetch(path)
    assert status in (200, 404) and (status == 404) == (slug == "not-found")
    assert problems(markup) == []
    assert script_problems(markup) == []


@pytest.mark.parametrize("slug, path", EXPORTS, ids=[p[0] for p in EXPORTS])
def test_export_markup(fetch, slug, path):
    status, markup = fetch(path)
    assert status == 200
    assert problems(markup) == []
    assert "<script" not in markup.lower()
    assert not re.search(r"https?://", markup)
    assert "<form" not in markup and "<button" not in markup
    # The shared stylesheet still names :popover-open, so only the body counts.
    body = re.sub(r"<style>.*?</style>", "", markup, flags=re.S)
    assert "popover" not in body.lower()


# --- the rules themselves ---------------------------------------------------

def test_the_rules_catch_what_they_claim_to():
    bad = ('<html><body><h1>a</h1><h1>b</h1><div id=x></div><div id=x></div>'
           '<input name=q><a href="/x"></a><button><span aria-hidden="true">x</span></button>'
           '<table><tr><th>h</th><th scope=col aria-sort=up></th><th scope=col aria-sort=none></th></tr></table>'
           '<div class="rt-alert rt-alert--blocker"></div>'
           '<button popovertarget=nope>go</button><a href="/y"><button>in</button></a>'
           '<p onclick="x()">t</p>'
           '<button class="rt-btn--primary">a</button><button class="rt-btn--primary">b</button>'
           '</body></html>')
    found = " | ".join(problems(bad))
    for expected in ("duplicate id 'x'", "unlabelled <input q>", "no accessible name: <a",
                     "no accessible name: <button", "<th> without scope",
                     "more than one aria-sort", "invalid aria-sort 'up'",
                     "without role=alert", "missing id 'nope'", "nested interactive",
                     "inline handlers", "2 <h1> elements", "html has no lang",
                     "2 primary buttons"):
        assert expected in found, expected


def test_the_rules_accept_a_correct_fragment():
    good = ('<html lang="en"><body><h1>t</h1><label for=q>Q</label><input id=q>'
            '<label>Wrapped <select name=s></select></label>'
            '<input type=hidden name=h><a href="/x" aria-label="go"></a>'
            '<button aria-controls=d popovertarget=d>Open</button><div id=d popover></div>'
            '<table><tr><th scope=col aria-sort=ascending>a</th><th scope=col>b</th></tr></table>'
            '<div class="rt-alert rt-alert--blocker" role=alert></div></body></html>')
    assert problems(good) == []
