"""UI primitives and formatters for the Control Room redesign (WP3).

Components are pure functions: data in, escaped HTML string out, no I/O. Every
text parameter is escaped inside the function; parameters named *_html accept
only markup produced by other components (trusted, never user input). Class
names use an rt- BEM scheme.

Rules every component follows:

* No JavaScript. Every component works with JS disabled; the optional JS layer
  (WP9) hooks on plain attributes and classes only. No inline handlers.
* Status is never colour alone: every status carries a glyph and a word.
* ``attrs`` dicts add attributes. Names are validated, values are escaped, and
  attributes that would break pairing (id, name, for, type on buttons) cannot
  be overridden; ``class`` and ``aria-describedby`` are merged, not replaced.
* One primary button per view. The components cannot see the whole page, so
  this is the caller's rule: use kind="primary" once, "secondary" elsewhere.
"""

import html
import math
import re
import zlib
from urllib.parse import quote

PREFER, CONDITIONAL, AVOID, VERIFY, OK = (
    "PREFER", "CONDITIONAL", "AVOID", "VERIFY", "OK")

GLYPH = {PREFER: "●", CONDITIONAL: "◆", AVOID: "■",
         VERIFY: "?", OK: "✓"}

DASH = "—"          # em dash: "no value"
ENDASH = "–"        # en dash: ranges


def esc(text):
    """HTML-escape text, including quotes, for element and attribute use."""
    return html.escape(str(text), quote=True)


# Internal helpers ---------------------------------------------------------------

_ATTR_NAME = re.compile(r"^[a-zA-Z_:][-a-zA-Z0-9_:.]*$")
_UNSAFE_ATTRS = {"srcdoc"}
_BAD_SCHEMES = ("javascript:", "data:", "vbscript:")


def _slug(text):
    return re.sub(r"[^A-Za-z0-9_-]+", "-", str(text)).strip("-") or "x"


def _uid(prefix, *parts):
    """Deterministic id so output is stable (cacheable, diffable, testable)."""
    key = "\x1f".join(str(p) for p in parts).encode("utf-8", "replace")
    return "%s-%08x" % (prefix, zlib.crc32(key))


_URL_ATTRS = frozenset(("href", "action", "formaction", "src", "poster", "xlink:href"))


def _safe_href(href):
    """esc() stops attribute breakout but not a javascript: URL."""
    flat = re.sub(r"[\x00-\x20]+", "", str(href)).lower()
    if flat.startswith(_BAD_SCHEMES):
        return "#"
    return str(href)


def _attrs(base, extra=None, protected=()):
    """Render an attribute string (leading space) from base pairs plus extra.

    base: sequence of (name, value); None/False skips, True is a bare boolean.
    extra: caller dict. Names must match the safe pattern and may not be on*
    handlers; protected names are validated but ignored; class and
    aria-describedby are appended to the base value.
    """
    out = {}
    for name, value in base:
        if value is None or value is False:
            continue
        out[name] = value
    for name, value in (extra or {}).items():
        name = str(name)
        low = name.lower()
        if not _ATTR_NAME.match(name) or low.startswith("on") \
                or low in _UNSAFE_ATTRS:
            raise ValueError("unsafe attribute name: %r" % (name,))
        if low in protected or value is None or value is False:
            continue
        if low in ("class", "aria-describedby") and low in out:
            out[low] = "%s %s" % (out[low], value)
        else:
            out[low] = value
    parts = []
    for name, value in out.items():
        if value is True:
            parts.append(" " + name)
        else:
            # URL-valued attributes get the scheme check wherever they come
            # from, so a caller-supplied href/action/src can never be a
            # javascript: or data: sink once scripts exist.
            if name.lower() in _URL_ATTRS:
                value = _safe_href(value)
            parts.append(' %s="%s"' % (name, esc(value)))
    return "".join(parts)


def _num(value):
    """float(value) or None for None, non-numbers and NaN/inf."""
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _fixed(value, places):
    number = _num(value)
    if number is None:
        return DASH
    text = "%.*f" % (places, number)
    # "-0.0" is noise from rounding a tiny negative; show it as zero.
    if text.startswith("-") and not text.strip("-0."):
        text = text[1:]
    return text


# Formatters (spec 5.2) ------------------------------------------------------

def fmt_score(value):
    """One decimal place; None or non-numeric -> an em dash."""
    return _fixed(value, 1)


def fmt_range(low, high):
    """'low–high' with an en dash. Whole numbers print bare (41–78), others
    to one decimal (41.5–78.2). If either end is missing: an em dash."""
    lo, hi = _num(low), _num(high)
    if lo is None or hi is None:
        return DASH

    def one(number):
        text = _fixed(number, 1)
        return text[:-2] if text.endswith(".0") else text

    return one(lo) + ENDASH + one(hi)


def fmt_z(value):
    """Three decimals."""
    return _fixed(value, 3)


def fmt_cvss(value):
    """One decimal."""
    return _fixed(value, 1)


def fmt_prob(value):
    """Probability as '.04'. Exactly 0 (or below) -> '0', 0<v<0.005 -> '<.01',
    0.995<=v<1 -> '>.99', 1 or more -> '1.00', None -> em dash. The bounds are
    explicit so a value never rounds up to look like certainty (.995 -> .99
    would be wrong; '>.99' is the honest rendering)."""
    number = _num(value)
    if number is None:
        return DASH
    if number <= 0:
        return "0"
    if number >= 1:
        return "1.00"
    if number < 0.005:
        return "<.01"
    if number >= 0.995:
        return ">.99"
    return ("%.2f" % number).lstrip("0")


def fmt_weight(value):
    """Weight as '.60' (1 -> '1.00')."""
    number = _num(value)
    if number is None:
        return DASH
    text = "%.2f" % number
    return text.lstrip("0") if 0 <= number < 1 else text


# Primitives ------------------------------------------------------------------

_ICONS = {
    "shield-check": '<path d="M12 3 4.5 6v5.5c0 4.5 3.1 8.2 7.5 9.5 4.4-1.3 '
                    '7.5-5 7.5-9.5V6L12 3Z"/><path d="m8.5 12 2.5 2.5 4.5-5"/>',
    "chevron": '<path d="m6 9 6 6 6-6"/>',
    "chevron-right": '<path d="m9 6 6 6-6 6"/>',
    "close": '<path d="M6 6l12 12M18 6 6 18"/>',
    "check": '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
    "search": '<circle cx="11" cy="11" r="6"/><path d="m20 20-4.5-4.5"/>',
    "arrow-right": '<path d="M5 12h14m-5-5 5 5-5 5"/>',
    "download": '<path d="M12 4v11m-5-5 5 5 5-5M5 20h14"/>',
    "spinner": '<path d="M12 3a9 9 0 1 0 9 9"/>',
}


def icon(name, size=16):
    """Inline SVG: shield-check, chevron, chevron-right, close, check, search,
    arrow-right, download, spinner. Decorative (aria-hidden); stroke is
    currentColor so it takes the text colour. Unknown name -> ValueError."""
    try:
        body = _ICONS[name]
    except (KeyError, TypeError):
        raise ValueError("unknown icon: %r" % (name,)) from None
    px = int(size)
    cls = "rt-icon rt-icon--" + name
    return ('<svg class="%s" width="%d" height="%d" viewBox="0 0 24 24" '
            'fill="none" stroke="currentColor" stroke-width="1.75" '
            'stroke-linecap="square" stroke-linejoin="miter" '
            'aria-hidden="true" focusable="false">%s</svg>'
            % (cls, px, px, body))


def verdict_badge(verdict, size="m", low=None, high=None):
    """Glyph plus word; VERIFY is dashed and carries its low-high range
    ('? VERIFY 41–78'). Any unrecognised verdict renders a neutral
    'NOT ASSESSED' badge. Sizes s | m | l. Never interactive."""
    key = str(verdict or "").strip().upper()
    if key in GLYPH:
        glyph, word, mod = GLYPH[key], key, key.lower()
    else:
        glyph, word, mod = "–", "NOT ASSESSED", "neutral"
    size = size if size in ("s", "m", "l") else "m"
    rng = ""
    if key == VERIFY and low is not None and high is not None:
        text = fmt_range(low, high)
        if text != DASH:
            rng = ' <span class="rt-badge__range">%s</span>' % esc(text)
    return ('<span class="rt-badge rt-badge--%s rt-badge--%s">'
            '<span class="rt-badge__glyph" aria-hidden="true">%s</span> '
            '<span class="rt-badge__word">%s</span>%s</span>'
            % (mod, size, esc(glyph), esc(word), rng))


_FIX_STATUS = {
    "fixed": ("prefer", GLYPH[PREFER]),
    "update": ("conditional", GLYPH[CONDITIONAL]),
    "mitigation": ("avoid", GLYPH[AVOID]),
    "nofix": ("avoid", GLYPH[AVOID]),
    "unknown": ("verify", GLYPH[VERIFY]),
}


def signal_chip(kind, text, status=""):
    """kind: kev | neutral | vector | fix.

    kev: solid avoid chip showing ``text``. neutral: raised chip (EPSS .04).
    vector: neutral chip; a non-empty ``status`` such as 'wormable' is appended
    after a middle dot in the conditional hue. fix: outline chip in a verdict
    hue chosen by ``status`` (fixed | update | mitigation | nofix | unknown;
    anything else is drawn as unknown) with its glyph, so colour is never the
    only signal."""
    if kind == "kev":
        return ('<span class="rt-chip rt-chip--kev">%s</span>' % esc(text))
    if kind == "fix":
        tone, glyph = _FIX_STATUS.get(str(status).lower(), _FIX_STATUS["unknown"])
        return ('<span class="rt-chip rt-chip--fix rt-chip--fix-%s">'
                '<span aria-hidden="true">%s</span> %s</span>'
                % (tone, esc(glyph), esc(text)))
    if kind == "vector":
        extra = ""
        if status:
            extra = (' · <span class="rt-chip__warn">%s</span>' % esc(status))
        return ('<span class="rt-chip rt-chip--vector">%s%s</span>'
                % (esc(text), extra))
    return '<span class="rt-chip rt-chip--neutral">%s</span>' % esc(text)


_BUTTON_KINDS = {"primary": "primary", "secondary": "secondary",
                 "ghost": "ghost", "quiet": "ghost", "segment": "segment",
                 "destructive": "destructive", "danger": "destructive"}


def _btn_kind(kind):
    return _BUTTON_KINDS.get(kind, "secondary")


def button(label, kind="primary", type="button", disabled=False, reason="",
           loading=False, attrs=None, *, loading_label="Assessing…",
           pressed=None):
    """kind: primary | secondary | ghost | segment | destructive ('quiet' and
    'danger' are accepted aliases of ghost and destructive).

    Disabled buttons use aria-disabled="true" (so they stay focusable and
    their reason is reachable) and are forced to type="button" so a disabled
    submit can never submit. ``reason`` is visible text linked by
    aria-describedby. ``loading`` keeps the button's width: the normal label
    stays in the layout, hidden, under ``loading_label`` and a spinner.
    ``pressed`` (True/False) sets aria-pressed for segment toggles."""
    kind = _btn_kind(kind)
    btype = type if type in ("button", "submit", "reset") else "button"
    inert = bool(disabled or loading)
    if inert:
        btype = "button"
    classes = "rt-btn rt-btn--" + kind
    if loading:
        classes += " rt-btn--loading"
    reason_id = _uid("rt-reason", label, reason) if (disabled and reason) else ""
    base = [("class", classes), ("type", btype),
            ("aria-disabled", "true" if inert else None),
            ("aria-busy", "true" if loading else None),
            ("aria-describedby", reason_id or None)]
    if pressed is not None:
        base.append(("aria-pressed", "true" if pressed else "false"))
    open_tag = "<button%s>" % _attrs(
        base, attrs, protected=("type", "aria-disabled", "aria-busy"))
    if loading:
        inner = ('<span class="rt-btn__stack"><span class="rt-btn__label" '
                 'aria-hidden="true">%s</span><span class="rt-btn__busy">%s'
                 '<span>%s</span></span></span>'
                 % (esc(label), icon("spinner", 14), esc(loading_label)))
    else:
        inner = '<span class="rt-btn__label">%s</span>' % esc(label)
    out = open_tag + inner + "</button>"
    if disabled and reason:
        out = ('<span class="rt-btn-wrap">%s<span class="rt-btn__reason" '
               'id="%s">%s</span></span>' % (out, reason_id, esc(reason)))
    return out


def link_button(label, href, kind="secondary", attrs=None):
    """An <a> styled as a button. javascript:/data:/vbscript: hrefs become #."""
    base = [("class", "rt-btn rt-btn--" + _btn_kind(kind)),
            ("href", _safe_href(href))]
    return "<a%s><span class=\"rt-btn__label\">%s</span></a>" % (
        _attrs(base, attrs, protected=("href",)), esc(label))


def _field_ids(name, input_id):
    fid = _slug(input_id) if input_id else "f-" + _slug(name)
    return fid, fid + "-help", fid + "-msg"


def text_field(name, label, value="", state="", message="", help_text="",
               input_id="", attrs=None, *, mono=False):
    """state: '' | verified | unverified | error | disabled.

    The label is paired to the input by for/id (id defaults to f-<name>).
    unverified: dashed violet border, '· not verified' label suffix and, when
    help_text is empty, the standard 'Without this the result stays VERIFY
    with a range.' helper. error: '■ message' below, aria-invalid. verified:
    a ✓ at the right. ``mono`` sets the mono face for identifiers."""
    fid, help_id, msg_id = _field_ids(name, input_id)
    state = state if state in ("verified", "unverified", "error",
                               "disabled") else ""
    if state == "unverified" and not help_text:
        help_text = "Without this the result stays VERIFY with a range."
    flag = ""
    if state == "unverified":
        flag = ' <span class="rt-field__flag">· not verified</span>'
    describedby = []
    if help_text:
        describedby.append(help_id)
    if state == "error" and message:
        describedby.append(msg_id)
    classes = "rt-input" + (" rt-input--mono" if mono else "")
    base = [("class", classes), ("type", "text"), ("id", fid), ("name", name),
            ("value", value), ("disabled", True if state == "disabled" else None),
            ("aria-invalid", "true" if state == "error" else None),
            ("aria-describedby", " ".join(describedby) or None)]
    control = "<input%s>" % _attrs(base, attrs, protected=("id", "name"))
    if state == "verified":
        control += ('<span class="rt-field__ok" aria-hidden="true">%s</span>'
                    '<span class="rt-sr">verified</span>' % GLYPH[OK])
    out = ['<div class="rt-field%s">' % (" rt-field--" + state if state else ""),
           '<label class="rt-field__label" for="%s">%s%s</label>'
           % (fid, esc(label), flag),
           '<div class="rt-field__control">%s</div>' % control]
    if help_text:
        out.append('<p class="rt-field__help" id="%s">%s</p>'
                   % (help_id, esc(help_text)))
    if state == "error" and message:
        out.append('<p class="rt-field__error" id="%s">'
                   '<span aria-hidden="true">%s</span> %s</p>'
                   % (msg_id, GLYPH[AVOID], esc(message)))
    out.append("</div>")
    return "".join(out)


def select_field(name, label, options, selected="", unknown_value="",
                 input_id="", help_text="", attrs=None):
    """options: sequence of (value, text).

    The option whose value equals ``unknown_value`` (when that is non-empty)
    is the Unknown choice: its text gets a leading '? ' and, while selected,
    the control is drawn VERIFY-style (dashed violet). The server renders the
    modifier class for the initial state and a :has() rule tracks later
    changes without JS."""
    fid, help_id, _ = _field_ids(name, input_id)
    sel = str(selected)
    unk = str(unknown_value)
    opts = []
    for value, text in options:
        value = str(value)
        is_unknown = bool(unk) and value == unk
        shown = ("? " + str(text)) if is_unknown else str(text)
        opts.append("<option%s>%s</option>" % (_attrs([
            ("value", value),
            ("class", "rt-option--unknown" if is_unknown else None),
            ("selected", True if value == sel else None)]), esc(shown)))
    unknown_now = bool(unk) and sel == unk
    base = [("class", "rt-input rt-select__input"), ("id", fid),
            ("name", name),
            ("aria-describedby", help_id if help_text else None)]
    out = ['<div class="rt-field rt-field--select%s">'
           % (" rt-field--unknown" if unknown_now else ""),
           '<label class="rt-field__label" for="%s">%s</label>'
           % (fid, esc(label)),
           '<div class="rt-select"><select%s>%s</select>'
           '<span class="rt-select__chev">%s</span></div>'
           % (_attrs(base, attrs, protected=("id", "name")), "".join(opts),
              icon("chevron", 16))]
    if help_text:
        out.append('<p class="rt-field__help" id="%s">%s</p>'
                   % (help_id, esc(help_text)))
    out.append("</div>")
    return "".join(out)


def checkbox(name, label, checked=False, input_id="", attrs=None, *,
             value="1"):
    """Checkbox in a clickable label (for/id paired as well)."""
    fid = _slug(input_id) if input_id else "f-" + _slug(name)
    base = [("class", "rt-check__box"), ("type", "checkbox"), ("id", fid),
            ("name", name), ("value", value),
            ("checked", True if checked else None)]
    return ('<label class="rt-check" for="%s"><input%s>'
            '<span class="rt-check__text">%s</span></label>'
            % (fid, _attrs(base, attrs, protected=("id", "name", "type")),
               esc(label)))


def radio(name, label, value, checked=False, input_id="", attrs=None):
    """Radio in a clickable label. id defaults to f-<name>-<value>."""
    fid = _slug(input_id) if input_id else "f-%s-%s" % (_slug(name),
                                                        _slug(value))
    base = [("class", "rt-check__box rt-check__box--radio"),
            ("type", "radio"), ("id", fid), ("name", name), ("value", value),
            ("checked", True if checked else None)]
    return ('<label class="rt-check" for="%s"><input%s>'
            '<span class="rt-check__text">%s</span></label>'
            % (fid, _attrs(base, attrs, protected=("id", "name", "type")),
               esc(label)))


def toggle(name, label, on=False, input_id="", attrs=None):
    """role=switch checkbox plus a visible Yes/No word, so state is never
    colour alone. Both words are in the markup and CSS shows the one matching
    :checked, which keeps it correct after a click with JS disabled. The words
    are aria-hidden because the switch role already announces the state."""
    fid = _slug(input_id) if input_id else "f-" + _slug(name)
    base = [("class", "rt-toggle__input"), ("type", "checkbox"),
            ("role", "switch"), ("id", fid), ("name", name), ("value", "1"),
            ("checked", True if on else None)]
    return ('<label class="rt-toggle" for="%s"><input%s>'
            '<span class="rt-toggle__track" aria-hidden="true">'
            '<span class="rt-toggle__knob"></span></span>'
            '<span class="rt-toggle__label">%s</span>'
            '<span class="rt-toggle__state" aria-hidden="true">'
            '<span class="rt-toggle__yes">Yes</span>'
            '<span class="rt-toggle__no">No</span></span></label>'
            % (fid, _attrs(base, attrs, protected=("id", "name", "type",
                                                    "role")), esc(label)))


# Composites -------------------------------------------------------------------

_UNKNOWN_WORDS = ("", "unknown", "?", "not verified")


def conditions_row(items):
    """Row of condition chips; items: sequence of (label, value). An empty or
    'Unknown' value is drawn VERIFY-style with a '?' glyph."""
    cells = []
    for label, value in items:
        text = str(value)
        if text.strip().lower() in _UNKNOWN_WORDS:
            cells.append(
                '<li class="rt-cond rt-cond--unknown"><span '
                'class="rt-cond__label">%s</span> <span class="rt-cond__value">'
                '<span aria-hidden="true">%s</span> %s</span></li>'
                % (esc(label), GLYPH[VERIFY], esc(text or "Unknown")))
        else:
            cells.append(
                '<li class="rt-cond"><span class="rt-cond__label">%s</span> '
                '<span class="rt-cond__value">%s</span></li>'
                % (esc(label), esc(text)))
    return '<ul class="rt-conditions">%s</ul>' % "".join(cells)


def gap_card(title, body, field_id="", tag=""):
    """Evidence-gap card: dashed violet, 'GAP · <tag>' line. With field_id the
    title is a link to #field_id and the whole card is clickable through a
    stretched link (pure CSS)."""
    tagline = "GAP · " + str(tag) if tag else "GAP"
    if field_id:
        head = ('<a class="rt-gap__link" href="#%s">%s</a>'
                % (esc(quote(str(field_id), safe="-_:.")), esc(title)))
    else:
        head = esc(title)
    body_html = '<p class="rt-gap__body">%s</p>' % esc(body) if body else ""
    return ('<div class="rt-gap"><p class="rt-gap__tag">%s</p>'
            '<p class="rt-gap__title">%s</p>%s</div>'
            % (esc(tagline), head, body_html))


def context_card(title, body_html, footer_html=""):
    """Informational card, solid rule border, 'CONTEXT' tag. body_html and
    footer_html are trusted markup from other components."""
    foot = ('<div class="rt-context__foot">%s</div>' % footer_html
            if footer_html else "")
    return ('<div class="rt-context"><p class="rt-context__tag">CONTEXT</p>'
            '<p class="rt-context__title">%s</p>'
            '<div class="rt-context__body">%s</div>%s</div>'
            % (esc(title), body_html, foot))


_ALERTS = {
    "blocker": ("BLOCKER", GLYPH[AVOID], "alert"),
    "restriction": ("RESTRICTION", GLYPH[AVOID], "alert"),
    "review": ("REVIEW", GLYPH[CONDITIONAL], None),
    "error": ("ERROR", GLYPH[AVOID], "alert"),
}


def alert(kind, title, body="", body_html=""):
    """kind: blocker | restriction | review | error. role=alert except review.
    Never dismissible (no close control exists). The solid tag carries the
    word, so colour is not the only signal. ``body`` is escaped text;
    ``body_html`` is trusted markup (e.g. an action row) appended after it."""
    if kind not in _ALERTS:
        raise ValueError("unknown alert kind: %r" % (kind,))
    word, glyph, role = _ALERTS[kind]
    text = '<p class="rt-alert__text">%s</p>' % esc(body) if body else ""
    return ('<div class="rt-alert rt-alert--%s"%s>'
            '<span class="rt-alert__tag"><span aria-hidden="true">%s</span> '
            '%s</span><div class="rt-alert__main">'
            '<p class="rt-alert__title">%s</p>%s%s</div></div>'
            % (kind, ' role="alert"' if role else "", esc(glyph), word,
               esc(title), text, body_html))


def panel_label(text):
    """Uppercase mono panel label (uppercase by CSS, text stays as given)."""
    return '<p class="rt-panel-label">%s</p>' % esc(text)


def card(body_html, label="", id=""):
    """Bordered surface. body_html is trusted markup. With both label and id
    the section is named by its label (aria-labelledby)."""
    cid = _slug(id) if id else ""
    lab_id = cid + "-label" if (cid and label) else ""
    head = ('<p class="rt-panel-label"%s>%s</p>'
            % (' id="%s"' % lab_id if lab_id else "", esc(label))
            if label else "")
    attr = _attrs([("class", "rt-card"), ("id", cid or None),
                   ("aria-labelledby", lab_id or None)])
    return "<section%s>%s%s</section>" % (attr, head, body_html)


def tabs(items, current="", *, label="Sections"):
    """In-page section nav; items: sequence of (id, label). A <nav> of anchors
    (#id) with aria-current on the current one. Deliberately not
    role=tablist: these are links to sections, not a widget with arrow-key
    semantics."""
    links = []
    for tid, text in items:
        is_cur = str(tid) == str(current)
        links.append('<a class="rt-tabs__tab" href="#%s"%s>%s</a>' % (
            esc(quote(str(tid), safe="-_:.")),
            ' aria-current="location"' if is_cur else "", esc(text)))
    return ('<nav class="rt-tabs" aria-label="%s">%s</nav>'
            % (esc(label), "".join(links)))


def tooltip(trigger_html, text, tip_id=""):
    """CSS tooltip: shows on hover and on focus-within after a 150 ms delay.
    The wrapper is focusable (tabindex=0) and carries aria-describedby so the
    text is announced on focus; ``trigger_html`` must therefore be
    non-interactive (an icon or a word). Tooltips never hold interactive
    content or the only copy of important information (use gap cards)."""
    tid = _slug(tip_id) if tip_id else _uid("rt-tip", text)
    return ('<span class="rt-tip" tabindex="0" aria-describedby="%s">%s'
            '<span class="rt-tip__bubble" role="tooltip" id="%s">%s</span>'
            '</span>' % (tid, trigger_html, tid, esc(text)))


def menu(button_label, items, menu_id, *, kind="primary"):
    """Popover menu: a native ``popovertarget`` button opens a ``popover``
    list; light dismiss and Esc are the browser's. Rows are <a>.
    items: sequence of (label, href, format_tag, disabled_reason[, filename]).
    A row with a disabled_reason has no href, aria-disabled and shows the
    reason. ``filename`` becomes data-filename, which the enhancement script
    names in its "Exported ..." toast."""
    mid = _slug(menu_id)
    rows = []
    for index, (text, href, tag, why, *extra) in enumerate(items):
        tag_html = ('<span class="rt-menu__tag">%s</span>' % esc(tag)
                    if tag else "")
        if why:
            rid = "%s-why-%d" % (mid, index)
            rows.append(
                '<a class="rt-menu__row rt-menu__row--disabled" '
                'role="link" tabindex="0" aria-disabled="true" '
                'aria-describedby="%s">'
                '<span class="rt-menu__text">%s</span>%s'
                '<span class="rt-menu__reason" id="%s">%s</span></a>'
                % (rid, esc(text), tag_html, rid, esc(why)))
        else:
            named = (' data-filename="%s"' % esc(extra[0])) if extra and extra[0] else ""
            rows.append('<a class="rt-menu__row" href="%s"%s>'
                        '<span class="rt-menu__text">%s</span>%s</a>'
                        % (esc(_safe_href(href)), named, esc(text), tag_html))
    return ('<div class="rt-menu"><button type="button" '
            'class="rt-btn rt-btn--%s" popovertarget="%s">'
            '<span class="rt-btn__label">%s</span>%s</button>'
            '<div class="rt-menu__list" id="%s" popover>%s</div></div>'
            % (_btn_kind(kind), mid, esc(button_label), icon("chevron", 16),
               mid, "".join(rows)))


def meta_chip(text, *, unverified=False):
    """Neutral metadata chip. unverified: dashed violet with a '?' glyph."""
    if unverified:
        return ('<span class="rt-meta rt-meta--unverified">'
                '<span aria-hidden="true">%s</span> %s</span>'
                % (GLYPH[VERIFY], esc(text)))
    return '<span class="rt-meta">%s</span>' % esc(text)


def skeleton(lines=3):
    """Static pulsing placeholder lines (no shimmer), announced as Loading."""
    count = max(1, min(int(lines), 20))
    return ('<div class="rt-skel" role="status"><span class="rt-sr">'
            'Loading</span>%s</div>'
            % ('<span class="rt-skel__line" aria-hidden="true"></span>'
               * count))


def empty_state(title, body="", action_html=""):
    """Empty/zero state. action_html is trusted markup (a link_button)."""
    return ('<div class="rt-empty"><p class="rt-empty__title">%s</p>%s%s</div>'
            % (esc(title),
               '<p class="rt-empty__body">%s</p>' % esc(body) if body else "",
               '<div class="rt-empty__action">%s</div>' % action_html
               if action_html else ""))


_TOAST = {"success": (GLYPH[OK], "prefer"), "error": (GLYPH[AVOID], "avoid"),
          "info": ("i", "neutral")}


def toast(message, kind="info"):
    """Markup for one toast; the enhancement script builds the same structure
    client-side. role=status, errors role=alert (and persistent, which is the
    JS layer's job). kind: info | success | error."""
    kind = kind if kind in _TOAST else "info"
    glyph, tone = _TOAST[kind]
    return ('<div class="rt-toast rt-toast--%s" role="%s">'
            '<span class="rt-toast__glyph" aria-hidden="true">%s</span>'
            '<span class="rt-toast__text">%s</span></div>'
            % (tone, "alert" if kind == "error" else "status", esc(glyph),
               esc(message)))


# CSS ---------------------------------------------------------------------------
# Plain string, never an f-string. Component classes only: resets and global
# rules live in design.BASE_CSS. Colours are token variables exclusively. The
# type floor is 12px (D3). Radii are tokens (max 6px) or 50% for the radio.

CSS = """
.rt-sr{position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap;border:0}
.rt-icon{flex:none;vertical-align:middle}
.rt-icon--spinner{animation:rt-spin 1s linear infinite}
@keyframes rt-spin{to{transform:rotate(360deg)}}

.rt-badge{display:inline-flex;align-items:center;gap:var(--s6);padding:var(--s4) var(--s10);border:1px solid var(--rule);border-radius:var(--r-md);font-family:var(--font-mono);font-weight:600;font-size:12px;line-height:1;text-transform:uppercase;letter-spacing:.08em;white-space:nowrap;color:var(--text)}
.rt-badge--l{padding:var(--s6) var(--s12);font-size:14px}
.rt-badge--s{padding:var(--s2) var(--s6)}
.rt-badge--prefer{color:var(--prefer);background:var(--prefer-fill);border-color:var(--prefer-edge)}
.rt-badge--conditional{color:var(--conditional);background:var(--conditional-fill);border-color:var(--conditional-edge)}
.rt-badge--avoid{color:var(--avoid);background:var(--avoid-fill);border-color:var(--avoid-edge)}
.rt-badge--ok{color:var(--prefer);background:var(--prefer-fill);border-color:var(--prefer-edge)}
.rt-badge--verify{color:var(--verify);background:transparent;border:1px dashed var(--verify)}
.rt-badge--neutral{color:var(--muted);background:transparent;border:1px solid var(--rule)}
.rt-badge__range{font-variant-numeric:tabular-nums;letter-spacing:.02em}

.rt-chip{display:inline-block;padding:var(--s2) var(--s8);border-radius:var(--r-sm);font-family:var(--font-mono);font-weight:500;font-size:12px;line-height:1.4;white-space:nowrap}
.rt-chip--kev{background:var(--avoid);color:var(--on-avoid)}
.rt-chip--neutral,.rt-chip--vector{background:var(--raised);color:var(--text);border:1px solid var(--rule)}
.rt-chip__warn{color:var(--conditional)}
.rt-chip--fix{background:transparent;border:1px solid var(--rule)}
.rt-chip--fix-prefer{color:var(--prefer);border-color:var(--prefer-edge)}
.rt-chip--fix-conditional{color:var(--conditional);border-color:var(--conditional-edge)}
.rt-chip--fix-avoid{color:var(--avoid);border-color:var(--avoid-edge)}
.rt-chip--fix-verify{color:var(--verify);border:1px dashed var(--verify)}

.rt-btn-wrap{display:inline-flex;flex-direction:column;align-items:flex-start;gap:var(--s4)}
.rt-btn{display:inline-flex;align-items:center;justify-content:center;gap:var(--s8);box-sizing:border-box;min-height:40px;padding:0 var(--s16);border:1px solid transparent;border-radius:var(--r-lg);background:transparent;color:var(--text);font-family:var(--font-sans);font-size:14px;font-weight:500;line-height:1.2;text-decoration:none;cursor:pointer;transition:background-color var(--t-fast) ease-out,border-color var(--t-fast) ease-out,color var(--t-fast) ease-out}
.rt-btn:focus-visible,.rt-menu__row:focus-visible,.rt-tabs__tab:focus-visible,.rt-tip:focus-visible,.rt-gap__link:focus-visible{outline:2px solid var(--action);outline-offset:2px}
.rt-btn--primary{background:var(--action);color:var(--on-action);font-weight:600}
.rt-btn--primary:hover{background:var(--action-hover)}
.rt-btn--secondary{border-color:var(--control-border)}
.rt-btn--secondary:hover{border-color:var(--text)}
.rt-btn--ghost{color:var(--action);padding:0 var(--s8)}
.rt-btn--ghost:hover{color:var(--action-hover)}
.rt-btn--segment{min-height:32px;padding:0 var(--s12);border-color:var(--rule);border-radius:var(--r-md);color:var(--muted);font-family:var(--font-mono);font-size:12px}
.rt-btn--segment[aria-pressed=true]{background:var(--raised);color:var(--text);border-color:var(--control-border)}
.rt-btn--destructive{color:var(--avoid);border-color:var(--avoid)}
.rt-btn--destructive:hover{background:var(--avoid-alert)}
.rt-btn:active:not([aria-disabled=true]){background:var(--raised)}
.rt-btn--primary:active:not([aria-disabled=true]){background:var(--action-hover)}
.rt-btn[aria-disabled=true]{background:var(--raised);color:var(--muted);border-color:transparent;cursor:not-allowed}
.rt-btn[aria-disabled=true]:hover{background:var(--raised);color:var(--muted)}
.rt-btn--loading{cursor:progress}
.rt-btn__stack{display:inline-grid}
.rt-btn__stack>*{grid-area:1/1;display:inline-flex;align-items:center;justify-content:center;gap:var(--s8)}
.rt-btn__stack>.rt-btn__label{visibility:hidden}
.rt-btn__reason{font-size:12px;line-height:1.4;color:var(--muted)}

.rt-field{display:flex;flex-direction:column;gap:var(--s6);font-family:var(--font-sans)}
.rt-field__label{font-size:12px;line-height:1.4;color:var(--muted)}
.rt-field__flag{color:var(--verify)}
.rt-field__control,.rt-select{position:relative;display:flex;align-items:center}
.rt-input{box-sizing:border-box;width:100%;min-height:40px;padding:0 var(--s12);background:var(--surface);color:var(--text);border:1px solid var(--control-border);border-radius:var(--r-lg);font-family:var(--font-sans);font-size:14px;line-height:1.45;transition:border-color var(--t-fast) ease-out}
.rt-input--mono,.rt-field--select .rt-input{font-family:var(--font-mono);font-size:13px}
.rt-input:focus-visible{outline:none;border-color:var(--action);box-shadow:0 0 0 1px var(--action)}
.rt-field--verified .rt-input{border-color:var(--action);padding-right:var(--s32)}
.rt-field__ok{position:absolute;right:var(--s12);color:var(--prefer);font-family:var(--font-mono);font-size:14px}
.rt-field--unverified .rt-input{border:1px dashed var(--verify)}
.rt-field--error .rt-input{border-color:var(--avoid)}
.rt-field--disabled .rt-input{background:var(--bar);color:var(--muted)}
.rt-field__help,.rt-field__error{margin:0;font-size:12px;line-height:1.4;color:var(--muted)}
.rt-field__error{color:var(--avoid)}
.rt-select__input{appearance:none;-webkit-appearance:none;padding-right:var(--s32)}
.rt-select__chev{position:absolute;right:var(--s10);display:flex;color:var(--muted);pointer-events:none}
.rt-field--unknown .rt-select__input{border:1px dashed var(--verify);color:var(--verify)}
.rt-field--select:has(option.rt-option--unknown:checked) .rt-select__input{border:1px dashed var(--verify);color:var(--verify)}

.rt-check,.rt-toggle{display:inline-flex;align-items:center;gap:var(--s10);min-height:24px;font-family:var(--font-sans);font-size:14px;line-height:1.45;color:var(--text);cursor:pointer}
.rt-check__box{appearance:none;-webkit-appearance:none;position:relative;flex:none;box-sizing:border-box;width:18px;height:18px;margin:0;background:var(--surface);border:1px solid var(--control-border);border-radius:var(--r-sm);cursor:pointer;transition:background-color var(--t-fast) ease-out,border-color var(--t-fast) ease-out}
.rt-check__box--radio{border-radius:50%}
.rt-check__box:checked{background:var(--action);border-color:var(--action)}
.rt-check__box:not(.rt-check__box--radio):checked::after{content:"";position:absolute;left:5px;top:1px;width:5px;height:10px;border:solid var(--on-action);border-width:0 2px 2px 0;transform:rotate(45deg)}
.rt-check__box--radio:checked{background:var(--surface)}
.rt-check__box--radio:checked::after{content:"";position:absolute;left:4px;top:4px;width:8px;height:8px;background:var(--action);border-radius:50%}
.rt-check__box:focus-visible,.rt-toggle__input:focus-visible+.rt-toggle__track{outline:2px solid var(--action);outline-offset:2px}
.rt-toggle__input{position:absolute;left:0;top:0;opacity:0;width:36px;height:20px;margin:0;cursor:pointer}
.rt-toggle{position:relative}
.rt-toggle__track{position:relative;flex:none;width:36px;height:20px;background:var(--raised);border:1px solid var(--control-border);border-radius:var(--r-lg);box-sizing:border-box;transition:background-color var(--t-fast) ease-out}
.rt-toggle__knob{position:absolute;left:2px;top:2px;width:14px;height:14px;background:var(--text);border-radius:var(--r-sm);transition:transform var(--t-fast) ease-out}
.rt-toggle__input:checked+.rt-toggle__track{background:var(--action);border-color:var(--action)}
.rt-toggle__input:checked+.rt-toggle__track .rt-toggle__knob{transform:translateX(16px);background:var(--on-action)}
.rt-toggle__state{font-family:var(--font-mono);font-size:12px;color:var(--muted);min-width:var(--s24)}
.rt-toggle__yes{display:none}
.rt-toggle__input:checked~.rt-toggle__state .rt-toggle__yes{display:inline;color:var(--text)}
.rt-toggle__input:checked~.rt-toggle__state .rt-toggle__no{display:none}

.rt-conditions{display:flex;flex-wrap:wrap;gap:var(--s8);margin:0;padding:0;list-style:none}
.rt-cond{display:inline-flex;gap:var(--s8);padding:var(--s4) var(--s10);background:var(--surface);border:1px solid var(--rule);border-radius:var(--r-md);font-family:var(--font-mono);font-size:12px;line-height:1.3}
.rt-cond__label{color:var(--muted)}
.rt-cond__value{color:var(--text)}
.rt-cond--unknown{background:transparent;border:1px dashed var(--verify)}
.rt-cond--unknown .rt-cond__value{color:var(--verify)}

.rt-gap,.rt-context{position:relative;display:flex;flex-direction:column;gap:var(--s4);padding:var(--s12);border-radius:var(--r-lg);font-family:var(--font-sans);font-size:14px;line-height:1.45}
.rt-gap{border:1px dashed var(--verify)}
.rt-context{border:1px solid var(--rule)}
.rt-gap p,.rt-context p{margin:0}
.rt-gap__tag,.rt-context__tag{font-family:var(--font-mono);font-weight:600;font-size:12px;line-height:1.3;text-transform:uppercase;letter-spacing:.06em}
.rt-gap__tag{color:var(--verify)}
.rt-context__tag{color:var(--muted)}
.rt-gap__title,.rt-context__title{font-weight:600;color:var(--text)}
.rt-gap__body,.rt-context__body{color:var(--text-2)}
.rt-gap__link{color:var(--action);text-decoration:none}
.rt-gap__link:hover{color:var(--action-hover);text-decoration:underline}
.rt-gap__link::after{content:"";position:absolute;inset:0}
.rt-context__foot{margin-top:var(--s4)}

.rt-alert{display:flex;gap:var(--s16);box-sizing:border-box;width:100%;padding:var(--s16);border:1px solid var(--avoid);border-radius:var(--r-lg);background:var(--avoid-alert);font-family:var(--font-sans);font-size:14px;line-height:1.45}
.rt-alert--error{border-color:var(--rule)}
.rt-alert--review{border-color:var(--conditional);background:var(--conditional-fill)}
.rt-alert__tag{flex:none;align-self:flex-start;padding:var(--s4) var(--s8);border-radius:var(--r-sm);background:var(--avoid);color:var(--on-avoid);font-family:var(--font-mono);font-weight:700;font-size:12px;line-height:1.2;letter-spacing:.06em}
.rt-alert--review .rt-alert__tag{background:var(--conditional)}
.rt-alert__main{min-width:0;overflow-wrap:anywhere}
.rt-alert__title{margin:0;font-weight:600;color:var(--text)}
.rt-alert__text{margin:var(--s4) 0 0;color:var(--text-2)}

.rt-panel-label{margin:0 0 var(--s12);font-family:var(--font-mono);font-weight:500;font-size:12px;line-height:1.3;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.rt-card{box-sizing:border-box;padding:var(--s20);background:var(--surface);border:1px solid var(--rule);border-radius:var(--r-card)}

.rt-tabs{display:flex;flex-wrap:wrap;gap:var(--s20);border-bottom:1px solid var(--rule)}
.rt-tabs__tab{display:inline-flex;align-items:center;box-sizing:border-box;height:40px;border-bottom:2px solid transparent;margin-bottom:-1px;font-family:var(--font-mono);font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);text-decoration:none;transition:color var(--t-fast) ease-out}
.rt-tabs__tab:hover{color:var(--text)}
.rt-tabs__tab[aria-current]{color:var(--text);border-bottom-color:var(--action)}

.rt-tip{position:relative;display:inline-flex;align-items:center}
.rt-tip__bubble{position:absolute;left:0;top:100%;z-index:20;box-sizing:border-box;width:max-content;max-width:280px;margin-top:var(--s6);padding:var(--s8) var(--s10);background:var(--raised);color:var(--text);border:1px solid var(--control-border);border-radius:var(--r-lg);font-family:var(--font-sans);font-size:12px;font-weight:400;line-height:1.4;text-align:left;text-transform:none;letter-spacing:0;visibility:hidden;opacity:0;pointer-events:none}
.rt-tip:hover .rt-tip__bubble,.rt-tip:focus-within .rt-tip__bubble{visibility:visible;opacity:1;transition:opacity var(--t-fast) ease-out 150ms,visibility 0s linear 150ms}

.rt-menu{position:relative;display:inline-block}
.rt-menu__list{box-sizing:border-box;width:240px;margin:0;padding:var(--s4) 0;inset:auto;position:absolute;background:var(--surface);color:var(--text);border:0;border-radius:var(--r-lg);box-shadow:var(--overlay-shadow)}
.rt-menu__list:not(:popover-open){display:none}
.rt-menu__row{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:var(--s2) var(--s8);box-sizing:border-box;min-height:44px;padding:var(--s8) var(--s12);font-family:var(--font-sans);font-size:14px;color:var(--text);text-decoration:none}
.rt-menu__row[href]:hover{background:var(--raised)}
.rt-menu__tag{font-family:var(--font-mono);font-size:12px;color:var(--muted)}
.rt-menu__row--disabled{color:var(--muted);cursor:not-allowed}
.rt-menu__reason{flex-basis:100%;font-size:12px;line-height:1.4;color:var(--muted)}
@supports not selector(:popover-open){.rt-menu__list{display:block;position:static;margin-top:var(--s6)}}

.rt-meta{display:inline-block;padding:var(--s2) var(--s8);background:var(--surface);color:var(--text-2);border:1px solid var(--rule);border-radius:var(--r-sm);font-family:var(--font-mono);font-size:12px;line-height:1.4}
.rt-meta--unverified{background:transparent;color:var(--verify);border:1px dashed var(--verify)}

.rt-skel{display:flex;flex-direction:column;gap:var(--s10)}
.rt-skel__line{display:block;height:var(--s16);background:var(--raised);border-radius:var(--r-sm);animation:rt-pulse 1.2s ease-in-out infinite}
.rt-skel__line:last-child{width:60%}
@keyframes rt-pulse{0%,100%{opacity:.6}50%{opacity:1}}

.rt-empty{display:flex;flex-direction:column;align-items:center;gap:var(--s8);padding:var(--s32) var(--s20);text-align:center;font-family:var(--font-sans)}
.rt-empty p{margin:0}
.rt-empty__title{font-size:18px;font-weight:600;line-height:1.3;color:var(--text)}
.rt-empty__body{max-width:480px;font-size:14px;line-height:1.45;color:var(--text-2)}
.rt-empty__action{margin-top:var(--s8)}

.rt-toast{display:flex;align-items:center;gap:var(--s10);box-sizing:border-box;max-width:420px;padding:var(--s10) var(--s12);background:var(--surface);color:var(--text);border:1px solid var(--control-border);border-radius:var(--r-lg);font-family:var(--font-sans);font-size:14px;line-height:1.45}
.rt-toast__glyph{font-family:var(--font-mono);font-weight:600}
.rt-toast--prefer .rt-toast__glyph{color:var(--prefer)}
.rt-toast--avoid .rt-toast__glyph{color:var(--avoid)}
.rt-toast--neutral .rt-toast__glyph{color:var(--muted)}
.rt-toast__text{min-width:0;overflow-wrap:anywhere}
.rt-toast__close{flex:none;display:inline-flex;align-items:center;justify-content:center;min-width:32px;min-height:32px;margin:calc(-1 * var(--s4)) calc(-1 * var(--s6)) calc(-1 * var(--s4)) 0;padding:0;border:0;border-radius:var(--r-md);background:transparent;color:var(--text-2);font-size:18px;line-height:1;cursor:pointer}
.rt-toast__close:hover{background:var(--raised);color:var(--text)}
.rt-toast__close:focus-visible{outline:2px solid var(--action);outline-offset:2px}

/* Enhancement script only (retrust.js): none of these exist in the no-JS markup. */
.rt-toasts{position:fixed;left:var(--s16);bottom:var(--s16);z-index:100;display:flex;flex-direction:column;align-items:flex-start;gap:var(--s8);max-width:calc(100% - var(--s32));pointer-events:none}
.rt-toasts .rt-toast{pointer-events:auto;box-shadow:var(--overlay-shadow)}
.rt-search{position:relative}
.rt-suggest{position:absolute;left:0;right:0;top:100%;z-index:60;box-sizing:border-box;margin-top:var(--s4);background:var(--surface);color:var(--text);border:1px solid var(--control-border);border-radius:var(--r-lg);box-shadow:var(--overlay-shadow);overflow:hidden}
.rt-suggest[hidden],.rt-suggest__empty[hidden],.rt-suggest__list[hidden]{display:none}
.rt-suggest__list{margin:0;padding:var(--s4) 0;list-style:none}
.rt-suggest__row{display:flex;flex-wrap:wrap;align-items:baseline;gap:var(--s2) var(--s12);box-sizing:border-box;min-height:44px;padding:var(--s8) var(--s12);cursor:pointer;font-family:var(--font-sans);font-size:14px;line-height:1.4}
.rt-suggest__row:hover,.rt-suggest__row[aria-selected=true]{background:var(--raised);box-shadow:inset 2px 0 0 var(--action)}
.rt-suggest__no{flex:none;font-family:var(--font-mono);font-size:13px;color:var(--action)}
.rt-suggest__name{flex:1 1 8rem;min-width:0;color:var(--text);overflow-wrap:anywhere}
.rt-suggest__vendor{flex:none;margin-left:auto;font-family:var(--font-mono);font-size:12px;color:var(--muted)}
.rt-suggest__empty{margin:0;padding:var(--s12);font-size:14px;line-height:1.45;color:var(--text-2)}
.rt-spinner{display:inline-block;flex:none;box-sizing:border-box;width:14px;height:14px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:rt-spin 1s linear infinite}
.rt-loadnote{margin:var(--s8) 0 0;font-family:var(--font-mono);font-size:12px;line-height:1.5;color:var(--text-2)}
.rt-sent{margin-top:var(--s4);font-size:13px;color:var(--text-2)}
.rt-qlist>li[data-sent] .rt-q__text,.rt-questions>li[data-sent] .rt-q__text{color:var(--muted)}
.rt-tip[data-dismissed] .rt-tip__bubble{visibility:hidden;opacity:0;transition:none}

@media (pointer:coarse){
.rt-toast__close,.ev-drawer .ev-close{min-width:44px;min-height:44px}
.rt-btn,.rt-btn--segment{min-height:44px}
.rt-menu__row{min-height:44px}
.rt-input{min-height:44px}
.rt-tabs__tab{min-height:44px}
.rt-check,.rt-toggle{min-height:44px}
}
@media (prefers-reduced-motion:reduce){
.rt-btn,.rt-input,.rt-check__box,.rt-toggle__track,.rt-toggle__knob,.rt-tabs__tab{transition:none}
.rt-tip:hover .rt-tip__bubble,.rt-tip:focus-within .rt-tip__bubble{transition:visibility 0s linear 150ms}
.rt-icon--spinner,.rt-skel__line,.rt-spinner{animation:none}
}
"""
