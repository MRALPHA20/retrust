"""Control Room component primitives."""

import html
import re

import pytest

from retrust import components as c

XSS = '<script>alert(1)</script>"\'&'


def _no_raw_payload(out):
    assert "<script" not in out.lower()
    assert "alert(1)</script>" not in out
    assert not re.search(r"\son\w+\s*=", out, re.I)
    assert "http" not in out


def _ids(out):
    return set(re.findall(r'\sid="([^"]+)"', out))


def _text(out):
    return html.unescape(re.sub(r"<[^>]+>", "", out))


# Formatters ------------------------------------------------------------------

def test_formatters():
    assert c.fmt_score(71.84) == "71.8"
    assert c.fmt_score(0) == "0.0"
    assert c.fmt_score(-0.01) == "0.0"
    assert c.fmt_score(None) == c.DASH
    assert c.fmt_score("x") == c.DASH
    assert c.fmt_score(float("nan")) == c.DASH
    assert c.fmt_z(1.23456) == "1.235"
    assert c.fmt_z(-0.5) == "-0.500"
    assert c.fmt_cvss(9.8) == "9.8"
    assert c.fmt_cvss(10) == "10.0"
    assert c.fmt_weight(0.6) == ".60"
    assert c.fmt_weight(0.05) == ".05"
    assert c.fmt_weight(1) == "1.00"
    assert c.fmt_weight(0) == ".00"
    assert c.fmt_weight(None) == c.DASH


def test_range_uses_en_dash():
    assert c.fmt_range(41, 78) == "41–78"
    assert c.fmt_range(0, 100) == "0–100"
    assert c.fmt_range(41.5, 78.25) == "41.5–78.2"
    assert c.fmt_range(None, 5) == c.DASH
    assert "-" not in c.fmt_range(1, 2)


@pytest.mark.parametrize("value,expected", [
    (None, "—"), (0, "0"), (-1, "0"), (0.001, "<.01"),
    (0.0049, "<.01"), (0.005, ".01"), (0.04, ".04"), (0.123, ".12"),
    (0.99, ".99"), (0.9949, ".99"), (0.995, ">.99"), (0.9999, ">.99"),
    (1, "1.00"), (1.5, "1.00"), ("0.5", ".50")])
def test_prob(value, expected):
    assert c.fmt_prob(value) == expected


# Attribute handling -----------------------------------------------------------

def test_attrs_validate_names_and_escape_values():
    out = c.button("Go", attrs={"data-x": XSS})
    assert 'data-x="&lt;script&gt;' in out
    _no_raw_payload(out)
    for bad in ("onclick", "ONFOCUS", 'x" onclick="1', "a b", "1a", "srcdoc"):
        with pytest.raises(ValueError):
            c.button("Go", attrs={bad: "1"})


def test_protected_attrs_cannot_be_overridden_and_merge():
    out = c.text_field("name", "Name", attrs={"id": "evil", "name": "evil",
                                              "class": "extra"})
    assert 'id="f-name"' in out and 'name="name"' in out
    assert "evil" not in out and "rt-input extra" in out
    out = c.button("x", type="submit", attrs={"type": "reset"})
    assert 'type="submit"' in out


# Escaping: every text parameter, every component ------------------------------

def test_every_text_param_is_escaped():
    outs = [
        c.icon("chevron"),
        c.verdict_badge(XSS, low=XSS, high=XSS),
        c.verdict_badge("VERIFY", low=XSS, high=1),
        c.signal_chip("kev", XSS), c.signal_chip("neutral", XSS),
        c.signal_chip("vector", XSS, XSS), c.signal_chip("fix", XSS, XSS),
        c.button(XSS, reason=XSS, disabled=True),
        c.button(XSS, loading=True, loading_label=XSS),
        c.link_button(XSS, XSS),
        c.text_field(XSS, XSS, value=XSS, state="error", message=XSS,
                     help_text=XSS, input_id=XSS),
        c.text_field(XSS, XSS, state="unverified", help_text=XSS),
        c.select_field(XSS, XSS, [(XSS, XSS), ("u", XSS)], selected=XSS,
                       unknown_value="u", input_id=XSS, help_text=XSS),
        c.checkbox(XSS, XSS, input_id=XSS),
        c.radio(XSS, XSS, XSS), c.toggle(XSS, XSS, input_id=XSS),
        c.conditions_row([(XSS, XSS), (XSS, "")]),
        c.gap_card(XSS, XSS, field_id=XSS, tag=XSS),
        c.context_card(XSS, "<p>ok</p>"),
        c.alert("blocker", XSS, XSS), c.panel_label(XSS),
        c.card("<p>ok</p>", label=XSS, id=XSS),
        c.tabs([(XSS, XSS)], current=XSS, label=XSS),
        c.tooltip("i", XSS, tip_id=XSS),
        c.menu(XSS, [(XSS, XSS, XSS, ""), (XSS, XSS, XSS, XSS)], XSS),
        c.meta_chip(XSS), c.meta_chip(XSS, unverified=True),
        c.empty_state(XSS, XSS), c.toast(XSS, "error"), c.toast(XSS),
    ]
    for out in outs:
        _no_raw_payload(out)


def test_html_params_are_trusted_passthrough():
    assert "<b>x</b>" in c.context_card("t", "<b>x</b>", "<i>f</i>")
    assert "<i>f</i>" in c.context_card("t", "<b>x</b>", "<i>f</i>")
    assert "<b>x</b>" in c.card("<b>x</b>")
    assert "<b>x</b>" in c.alert("blocker", "t", body_html="<b>x</b>")
    assert "<b>x</b>" in c.tooltip("<b>x</b>", "t")
    assert "<b>x</b>" in c.empty_state("t", action_html="<b>x</b>")


def test_href_scheme_is_neutralised():
    for bad in ("javascript:alert(1)", " JaVa\tScript:1", "data:text/html,1"):
        assert 'href="#"' in c.link_button("x", bad)
        assert 'href="#"' in c.menu("m", [("a", bad, "", "")], "m1")


# Icons -------------------------------------------------------------------------

def test_icons():
    for name in ("shield-check", "chevron", "chevron-right", "close", "check",
                 "search", "arrow-right", "download", "spinner"):
        out = c.icon(name, 22)
        assert out.startswith("<svg") and 'aria-hidden="true"' in out
        assert 'focusable="false"' in out and 'stroke="currentColor"' in out
        assert 'width="22"' in out
    with pytest.raises(ValueError):
        c.icon("nope")


# Verdict badge -----------------------------------------------------------------

@pytest.mark.parametrize("verdict", ["PREFER", "CONDITIONAL", "AVOID",
                                     "VERIFY"])
def test_verdict_has_glyph_and_word(verdict):
    for size in "sml":
        out = c.verdict_badge(verdict, size)
        assert c.GLYPH[verdict] in out and verdict in out
        assert "rt-badge--" + size in out
    assert c.verdict_badge(verdict.lower()) == c.verdict_badge(verdict)


def test_verify_badge_range_and_fallback():
    assert _text(c.verdict_badge("VERIFY", low=41, high=78)) == \
        "? VERIFY 41–78"
    assert "rt-badge__range" not in c.verdict_badge("VERIFY")
    assert "rt-badge__range" not in c.verdict_badge("AVOID", low=1, high=2)
    for odd in (None, "", "bogus", "NOT ASSESSED"):
        out = c.verdict_badge(odd)
        assert "NOT ASSESSED" in out and "rt-badge--neutral" in out
    assert "<button" not in c.verdict_badge("PREFER")
    assert "<a " not in c.verdict_badge("PREFER")
    assert "rt-badge--m" in c.verdict_badge("PREFER", "huge")


# Chips -------------------------------------------------------------------------

def test_signal_chips():
    assert "rt-chip--kev" in c.signal_chip("kev", "KEV")
    vec = c.signal_chip("vector", "NETWORK", "wormable")
    assert "NETWORK" in vec and "rt-chip__warn" in vec and "wormable" in vec
    assert "rt-chip__warn" not in c.signal_chip("vector", "LOCAL")
    for status, glyph in (("fixed", "●"), ("update", "◆"),
                          ("mitigation", "■"), ("unknown", "?"),
                          ("weird", "?")):
        out = c.signal_chip("fix", "Fixed in 3.1.6", status)
        assert glyph in out and "Fixed in 3.1.6" in out
    assert "rt-chip--neutral" in c.signal_chip("neutral", "EPSS .04")


# Buttons -----------------------------------------------------------------------

def test_button_kinds_and_aliases():
    for kind in ("primary", "secondary", "ghost", "segment", "destructive"):
        assert "rt-btn--" + kind in c.button("x", kind)
        assert "rt-btn--" + kind in c.link_button("x", "/y", kind)
    assert "rt-btn--destructive" in c.button("x", "danger")
    assert "rt-btn--ghost" in c.button("x", "quiet")
    assert 'aria-pressed="true"' in c.button("x", "segment", pressed=True)
    assert 'aria-pressed' not in c.button("x")


def test_disabled_button_reason_pairing():
    out = c.button("Export", disabled=True, reason="No assessment yet",
                   type="submit")
    assert 'aria-disabled="true"' in out
    assert 'type="button"' in out and 'type="submit"' not in out
    assert "No assessment yet" in _text(out)
    ref = re.search(r'aria-describedby="([^"]+)"', out).group(1)
    assert ref in _ids(out)
    assert "<button disabled" not in out
    # No reason: still aria-disabled, nothing dangling.
    bare = c.button("Export", disabled=True)
    assert "aria-describedby" not in bare and 'aria-disabled="true"' in bare
    # Two different disabled buttons never share a reason id.
    other = c.button("Compare", disabled=True, reason="Nothing selected")
    assert _ids(out).isdisjoint(_ids(other))
    assert 'type="submit"' in c.button("Go", type="submit")


def test_loading_button_keeps_width_and_is_inert():
    out = c.button("Assess product", loading=True, type="submit")
    assert "rt-btn--loading" in out and 'aria-busy="true"' in out
    assert 'aria-disabled="true"' in out and 'type="submit"' not in out
    # Both labels are in the layout so the grid cell takes the wider one.
    assert "Assess product" in out and "Assessing…" in out
    assert "<svg" in out


# Fields ------------------------------------------------------------------------

def test_text_field_pairing_and_states():
    out = c.text_field("order", "Order number", help_text="Printed on label",
                       mono=True)
    assert 'for="f-order"' in out and 'id="f-order"' in out
    assert "rt-input--mono" in out
    ref = re.search(r'aria-describedby="([^"]+)"', out).group(1)
    assert set(ref.split()) <= _ids(out)

    un = c.text_field("fw", "Firmware", "2.9.2", state="unverified")
    assert "rt-field--unverified" in un and "· not verified" in un
    assert "Without this the result stays VERIFY with a range." in un
    assert 'value="2.9.2"' in un
    custom = c.text_field("fw", "Firmware", state="unverified",
                          help_text="Mine")
    assert "Mine" in custom and "Without this" not in custom

    err = c.text_field("fw", "Firmware", state="error", message="Bad value")
    assert 'aria-invalid="true"' in err and "■" in err
    assert "Bad value" in _text(err)
    ref = re.search(r'aria-describedby="([^"]+)"', err).group(1)
    assert set(ref.split()) <= _ids(err)

    ok = c.text_field("fw", "Firmware", state="verified")
    assert "✓" in ok and "rt-field--verified" in ok
    dis = c.text_field("fw", "Firmware", state="disabled")
    assert re.search(r"<input[^>]* disabled[ >]", dis)
    assert "rt-field--bogus" not in c.text_field("a", "b", state="bogus")
    assert 'id="custom"' in c.text_field("a", "b", input_id="custom")


def test_select_field_unknown():
    opts = [("yes", "Yes"), ("no", "No"), ("unknown", "Unknown")]
    out = c.select_field("net", "Internet reachable", opts, selected="unknown",
                         unknown_value="unknown", help_text="Help")
    assert 'for="f-net"' in out and 'id="f-net"' in out
    assert "rt-field--unknown" in out and "<svg" in out
    assert re.search(r'<option[^>]*value="unknown"[^>]*selected', out)
    assert "rt-option--unknown" in out and "? Unknown" in out
    ref = re.search(r'aria-describedby="([^"]+)"', out).group(1)
    assert ref in _ids(out)
    known = c.select_field("net", "x", opts, selected="yes",
                           unknown_value="unknown")
    assert "rt-field--unknown" not in known
    assert re.search(r'value="yes"[^>]*selected', known)
    # Without an unknown_value nothing is drawn as unknown.
    plain = c.select_field("net", "x", [("", "Pick")], selected="")
    assert "rt-option--unknown" not in plain and "rt-field--unknown" not in plain


def test_choice_controls():
    cb = c.checkbox("sent", "Mark as sent", checked=True)
    assert 'type="checkbox"' in cb and " checked" in cb and 'for="f-sent"' in cb
    assert " checked" not in c.checkbox("sent", "x")
    rd = c.radio("mode", "Fast", "fast", checked=True)
    assert 'type="radio"' in rd and 'value="fast"' in rd and " checked" in rd
    assert 'for="f-mode-fast"' in rd and 'id="f-mode-fast"' in rd
    tg = c.toggle("internet", "Internet-reachable", on=True)
    assert 'role="switch"' in tg and " checked" in tg
    assert "Yes" in tg and "No" in tg
    assert " checked" not in c.toggle("internet", "x")
    for out in (cb, rd, tg):
        assert re.search(r'for="([^"]+)"', out).group(1) in _ids(out)


# Composites --------------------------------------------------------------------

def test_conditions_row():
    out = c.conditions_row([("Internet", "Yes"), ("Web server", "Unknown"),
                            ("Admin", "")])
    assert out.count("<li") == 3 and out.count("rt-cond--unknown") == 2
    assert "?" in out
    assert c.conditions_row([]).startswith("<ul")


def test_gap_and_context_cards():
    gap = c.gap_card("Add certification", "Not supplied", field_id="cert",
                     tag="C")
    assert "GAP · C" in gap and 'href="#cert"' in gap
    assert "rt-gap" in gap
    assert "GAP" in c.gap_card("t", "b") and "href" not in c.gap_card("t", "b")
    ctx = c.context_card("Scope", "<p>x</p>", "<a>f</a>")
    assert "CONTEXT" in ctx and "rt-context__foot" in ctx
    assert "rt-context__foot" not in c.context_card("a", "b")


def test_alert_roles_and_tags():
    for kind, tag in (("blocker", "BLOCKER"), ("restriction", "RESTRICTION"),
                      ("error", "ERROR")):
        out = c.alert(kind, "Headline", "Body")
        assert 'role="alert"' in out and tag in out
        assert "Headline" in out and "Body" in out
        assert "button" not in out and "close" not in out.lower()
    review = c.alert("review", "Check", "Body")
    assert "role=" not in review and "REVIEW" in review
    with pytest.raises(ValueError):
        c.alert("nope", "x")


def test_card_and_panel_label():
    assert "rt-panel-label" in c.panel_label("Inputs")
    out = c.card("<p>x</p>", label="Inputs", id="inputs")
    assert 'aria-labelledby="inputs-label"' in out
    assert "inputs-label" in _ids(out) and 'id="inputs"' in out
    plain = c.card("<p>x</p>")
    assert "aria-labelledby" not in plain and "rt-panel-label" not in plain


def test_tabs():
    out = c.tabs([("overview", "Overview"), ("evidence", "Evidence")],
                 current="evidence")
    assert out.startswith('<nav class="rt-tabs" aria-label="')
    assert "tablist" not in out and 'role="tab"' not in out
    assert out.count("aria-current") == 1
    assert re.search(r'href="#evidence" aria-current="location"', out)
    assert 'href="#overview">' in out


def test_tooltip_pairing():
    out = c.tooltip("<span>i</span>", "Definition")
    assert 'role="tooltip"' in out
    ref = re.search(r'aria-describedby="([^"]+)"', out).group(1)
    assert ref in _ids(out) and "tabindex=\"0\"" in out
    assert 'id="mine"' in c.tooltip("i", "t", tip_id="mine")
    assert "<a " not in c.tooltip("i", "t") and "<button" not in c.tooltip("i", "t")


def test_menu():
    out = c.menu("Export evidence", [
        ("HTML report", "/e.html", "HTML", ""),
        ("VEX", "", "JSON", "Needs an assessment")], "export-menu")
    assert "popovertarget=\"export-menu\"" in out
    assert re.search(r'id="export-menu"[^>]* popover>', out)
    assert 'href="/e.html"' in out and ">HTML<" in out
    assert out.count("<a ") == 2
    assert "Needs an assessment" in _text(out)
    assert "aria-disabled=\"true\"" in out
    ref = re.search(r'aria-describedby="([^"]+)"', out).group(1)
    assert ref in _ids(out)
    assert "<script" not in out and "onclick" not in out


def test_small_pieces():
    assert "rt-meta--unverified" not in c.meta_chip("x")
    assert "rt-meta--unverified" in c.meta_chip("x", unverified=True)
    assert c.skeleton(3).count("rt-skel__line") == 3
    assert c.skeleton(0).count("rt-skel__line") == 1
    assert c.skeleton(999).count("rt-skel__line") == 20
    assert 'role="status"' in c.skeleton()
    es = c.empty_state("Nothing here", "Add one", "<a>go</a>")
    assert "Nothing here" in es and "Add one" in es and "<a>go</a>" in es
    assert "rt-empty__body" not in c.empty_state("t")
    assert 'role="status"' in c.toast("Exported", "success")
    assert 'role="alert"' in c.toast("Failed", "error")
    assert 'role="status"' in c.toast("Hi", "weird")
    assert "✓" in c.toast("ok", "success") and "■" in c.toast("x", "error")


def test_outputs_have_no_scripts_handlers_or_urls():
    samples = [
        c.icon("shield-check", 22), c.verdict_badge("VERIFY", "l", 1, 2),
        c.button("x"), c.link_button("x", "/a"), c.text_field("a", "b"),
        c.select_field("a", "b", [("x", "y")]), c.checkbox("a", "b"),
        c.radio("a", "b", "c"), c.toggle("a", "b"), c.menu("m", [], "m1"),
        c.tooltip("i", "t"), c.skeleton(), c.toast("m")]
    for out in samples:
        assert "<script" not in out and "http" not in out
        assert not re.search(r"\son\w+\s*=", out)


# CSS ---------------------------------------------------------------------------

def test_css_constraints():
    css = c.CSS
    assert isinstance(css, str) and css.strip()
    assert "url(data:" not in css and "@import" not in css
    assert "http" not in css
    for size in re.findall(r"font-size:\s*([\d.]+)px", css):
        assert float(size) >= 12, size
    assert not re.search(r"font-size:\s*[\d.]+(?:em|rem|%)", css)
    assert not re.search(r"(?<![-\w])font:", css)
    for radius in re.findall(r"border-radius:\s*([^;}]+)", css):
        radius = radius.strip()
        assert radius == "50%" or radius.startswith("var(--r-"), radius
    assert "pointer:coarse" in css
    assert "prefers-reduced-motion:reduce" in css
    assert css.count("{") == css.count("}")
    assert "\r" not in css


def test_css_uses_tokens_not_hex_and_covers_classes():
    css = c.CSS
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", css)
    assert not re.search(r"\brgba?\(", css)
    body = "".join(
        fn for fn in [
            c.verdict_badge("VERIFY", "l", 1, 2), c.signal_chip("fix", "a", "fixed"),
            c.button("x", loading=True), c.text_field("a", "b", state="verified"),
            c.select_field("a", "b", [("x", "y")]), c.checkbox("a", "b"),
            c.toggle("a", "b"), c.conditions_row([("a", "b")]),
            c.gap_card("a", "b"), c.context_card("a", "b"),
            c.alert("blocker", "a"), c.card("x", "l"), c.tabs([("a", "b")]),
            c.tooltip("i", "t"), c.menu("m", [("a", "/", "T", "")], "m1"),
            c.meta_chip("a"), c.skeleton(), c.empty_state("a"), c.toast("a")])
    used = set(re.findall(r'class="([^"]+)"', body))
    classes = {n for group in used for n in group.split()}
    defined = set(re.findall(r"\.(rt-[a-z0-9_-]+)", css))
    # Modifiers-only classes are allowed to be unstyled, blocks and elements
    # are not.
    # Plain inline text hooks (glyph/word/text) need no rule of their own.
    missing = {n for n in classes - defined if "--" not in n
               and not re.search(r"__(glyph|word|text|busy|label)$", n)}
    assert not missing, missing


def test_motion_is_guarded():
    css = c.CSS
    guard = css[css.index("prefers-reduced-motion"):]
    for animated in ("rt-skel__line", "rt-icon--spinner", ".rt-btn",
                     ".rt-toggle__knob"):
        assert animated in guard
    coarse = css[css.index("pointer:coarse"):css.index("prefers-reduced")]
    for target in (".rt-btn", ".rt-btn--segment", ".rt-menu__row"):
        assert target in coarse
    assert "44px" in coarse


def test_select_field_blank_option_can_be_the_unknown_choice():
    opts = [("", "Unknown"), ("a", "A")]
    blank = c.select_field("net", "x", opts, selected="", unknown_value="")
    assert re.search(r'<option[^>]*value=""[^>]*class="rt-option--unknown"[^>]*selected[^>]*>\? Unknown<', blank)
    assert "rt-field--unknown" in blank
    answered = c.select_field("net", "x", opts, selected="a", unknown_value="")
    assert "rt-field--unknown" not in answered and "rt-option--unknown" in answered
    # The default, and None, mean no option is Unknown, so a blank stays neutral.
    for plain in (c.select_field("net", "x", opts), c.select_field("net", "x", opts, unknown_value=None)):
        assert "rt-option--unknown" not in plain and "rt-field--unknown" not in plain


def test_gap_card_action_row_and_context_card_tag():
    action = c.link_button("Look up", "/vendor?name=A", kind="ghost")
    card = c.gap_card("t", "b", tag="V", action_html=action)
    assert card.endswith('<p class="rt-gap__action">' + action + "</p></div>")
    assert "rt-gap__action" not in c.gap_card("t", "b")
    assert '<p class="rt-context__tag">UPDATE</p>' in c.context_card("t", "<p>x</p>", tag="UPDATE")
    assert '<p class="rt-context__tag">CONTEXT</p>' in c.context_card("t", "<p>x</p>")
    assert "&lt;b&gt;" in c.context_card("t", "x", tag="<b>")
