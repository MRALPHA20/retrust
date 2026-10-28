"""UI primitives and formatters (contract stubs, WP0; implemented by WP3).

Components are pure functions: data in, escaped HTML string out, no I/O. Every
text parameter is escaped inside the function; parameters named *_html accept
only markup produced by other components. Class names use an rt- BEM scheme.
"""

import html

CSS = ""  # filled in by WP3

PREFER, CONDITIONAL, AVOID, VERIFY, OK = (
    "PREFER", "CONDITIONAL", "AVOID", "VERIFY", "OK")

GLYPH = {PREFER: "●", CONDITIONAL: "◆", AVOID: "■",
         VERIFY: "?", OK: "✓"}


def esc(text):
    """HTML-escape text, including quotes, for element and attribute use."""
    return html.escape(str(text), quote=True)


# Formatters (spec 5.2) ------------------------------------------------------

def fmt_score(value):
    """One decimal place."""
    raise NotImplementedError


def fmt_range(low, high):
    """'low–high' with an en dash."""
    raise NotImplementedError


def fmt_z(value):
    """Three decimals."""
    raise NotImplementedError


def fmt_cvss(value):
    """One decimal."""
    raise NotImplementedError


def fmt_prob(value):
    """Probability as '.04'; <0.005 -> '<.01', >=0.995 and <1 -> '>.99'."""
    raise NotImplementedError


def fmt_weight(value):
    """Weight as '.60'."""
    raise NotImplementedError


# Primitives ------------------------------------------------------------------

def icon(name, size=16):
    """Inline SVG: shield-check, chevron, close, spinner."""
    raise NotImplementedError


def verdict_badge(verdict, size="m", low=None, high=None):
    """Glyph plus word; VERIFY is dashed and carries its low-high range."""
    raise NotImplementedError


def signal_chip(kind, text, status=""):
    """kind: kev | neutral | vector | fix; status e.g. 'wormable' or fix state."""
    raise NotImplementedError


def button(label, kind="primary", type="button", disabled=False, reason="",
           loading=False, attrs=None):
    """kind: primary | secondary | ghost | danger | quiet. Disabled uses
    aria-disabled plus a visible reason."""
    raise NotImplementedError


def link_button(label, href, kind="secondary", attrs=None):
    """An <a> styled as a button."""
    raise NotImplementedError


def text_field(name, label, value="", state="", message="", help_text="",
               input_id="", attrs=None):
    """state: '' | verified | unverified | error | disabled."""
    raise NotImplementedError


def select_field(name, label, options, selected="", unknown_value="",
                 input_id="", help_text="", attrs=None):
    """options: sequence of (value, text); the Unknown option is drawn VERIFY."""
    raise NotImplementedError


def checkbox(name, label, checked=False, input_id="", attrs=None):
    raise NotImplementedError


def radio(name, label, value, checked=False, input_id="", attrs=None):
    raise NotImplementedError


def toggle(name, label, on=False, input_id="", attrs=None):
    """role=switch plus a visible Yes/No word."""
    raise NotImplementedError


# Composites -------------------------------------------------------------------

def conditions_row(items):
    """Row of condition chips; items: sequence of (label, value)."""
    raise NotImplementedError


def gap_card(title, body, field_id="", tag=""):
    """Evidence-gap card linking to #field_id."""
    raise NotImplementedError


def context_card(title, body_html, footer_html=""):
    raise NotImplementedError


def alert(kind, title, body="", body_html=""):
    """kind: blocker | restriction | review | error. role=alert except review."""
    raise NotImplementedError


def panel_label(text):
    """Uppercase mono panel label."""
    raise NotImplementedError


def card(body_html, label="", id=""):
    raise NotImplementedError


def tabs(items, current=""):
    """In-page section nav; items: sequence of (id, label)."""
    raise NotImplementedError


def tooltip(trigger_html, text, tip_id=""):
    """CSS hover/focus tooltip with role=tooltip and aria-describedby."""
    raise NotImplementedError


def menu(button_label, items, menu_id):
    """Popover menu; items: sequence of (label, href, format_tag, disabled_reason)."""
    raise NotImplementedError


def meta_chip(text):
    raise NotImplementedError


def skeleton(lines=3):
    raise NotImplementedError


def empty_state(title, body="", action_html=""):
    raise NotImplementedError


def toast(message, kind="info"):
    """Markup only; unused until WP9."""
    raise NotImplementedError
