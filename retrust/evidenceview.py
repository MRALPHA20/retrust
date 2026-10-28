"""Evidence view: exposure table, evidence table, drawers, ranking, filters.

Spec 4.10, 4.12, 4.14, 4.15 and Redesign-plan WP5b. View state lives in the URL
(plan A7) and is presentation-only: it is never passed to the scorer.

Everything here is a pure function of the findings and the assessment that
``report._assessment_block`` already holds. This module must never import
``report``, ``serve`` or ``webui`` (report imports this module).

Query parameters (all whitelisted, invalid values fall back silently):
    ev    all | unpatched | network | kev
    sort  z | id | weakness | cvss | epss | vector | fix   (absent = today's order)
    dir   asc | desc                                        (only with sort)
    show  all                                               (lifts the cap of 10 to 200)
Drawer ids: ``ev-d-<slug of CVE id>``; a repeated CVE (second advisory) gets
``-<slug of advisory id>``, then ``-2``, ``-3`` so ids are always unique.
"""

import re
from dataclasses import dataclass
from types import SimpleNamespace
from urllib.parse import quote, urlencode

from . import components, cvss, exposure, weakness
from .components import DASH, ENDASH, esc

FILTERS = ("all", "unpatched", "network", "kev")
SORTS = ("z", "id", "weakness", "cvss", "epss", "vector", "fix")
DIRS = ("asc", "desc")

CAP = 10          # today's table size (D4)
HARD_MAX = 200    # show=all never renders more than this

FILTER_LABELS = {"all": "All", "unpatched": "Unpatched", "network": "Network",
                 "kev": "KEV"}
SORT_LABELS = {"z": "Z", "id": "ID", "weakness": "weakness", "cvss": "CVSS",
               "epss": "EPSS", "vector": "vector", "fix": "fix status"}
# First click on a column sorts the way a reader wants it: worst first for
# numbers, A-Z for names.
SORT_DEFAULT_DIR = {"z": "desc", "cvss": "desc", "epss": "desc", "id": "asc",
                    "weakness": "asc", "vector": "asc", "fix": "asc"}
CAPTION = ("Scores support a procurement review; they are not probabilities "
           "of compromise or a certification.")

FIX_LABELS = {"fixed": "Fixed", "update": "Fix available",
              "mitigation": "Mitigation only", "nofix": "No fix",
              "unknown": "Unknown"}
_FIX_ORDER = {"fixed": 0, "update": 1, "mitigation": 2, "nofix": 3, "unknown": 4}
_FIX_TEXT = {
    "vendor_fix": "The advisory states the vendor publishes a fix.",
    "mitigation": "The advisory offers a mitigation only.",
    "workaround": "The advisory offers a workaround only.",
    "none_available": "The advisory states that no remedy is available.",
}

_WEAKNESS_CLASS = {cwe: name for name, cwes, _ in weakness.CLASSES for cwe in cwes}

# Methodology definitions for the Z inputs. Shown as tooltips AND in a visible
# legend: a tooltip alone is not reachable on touch screens or on paper.
DEFINITIONS = (
    ("T", "Threat",
     "Strongest of KEV listing, LEV and EPSS, raised to a service-life floor "
     "set by how the flaw is reached."),
    ("I", "Severity", "CVSS base score divided by 10."),
    ("A", "Reach",
     "Whether an attacker can reach the flaw: 1 reachable, 0 verified blocked, "
     "a range when unknown."),
    ("H", "Impact",
     "The declared credible operational consequence; a range until answered."),
    ("U", "Unresolved",
     "1 while the flaw still applies to the firmware you get, 0 when a fix or "
     "non-applicability is verified."),
    ("Z", "Unit risk",
     "Z = T × I × A × H × U, taken from the unit's highest-scoring record."),
)
FLOOR_TIP = "floored by service-life vector"


@dataclass
class EvidenceView:
    """URL-carried state for the evidence table.

    ev         row filter, one of FILTERS
    sort       sort key, one of SORTS; "" means today's selection and order (D4)
    dir        "asc" or "desc"; only meaningful with an explicit sort
    show_all   True when the URL has show=all (lift the top-N cap)
    base_params  the page's existing query parameters (never the was_* ones),
                 used to build sort/filter links
    anchor     fragment appended to every generated link
    """

    ev: str = "all"
    sort: str = ""
    dir: str = "desc"
    show_all: bool = False
    base_params: dict = None
    anchor: str = "evidence"

    def __post_init__(self):
        if self.base_params is None:
            self.base_params = {}


# ---------------------------------------------------------------------------
# State and links

def _state(view):
    """The view with every value forced into its whitelist (hostile input is
    ignored, never echoed)."""
    view = view if view is not None else EvidenceView()
    ev = getattr(view, "ev", "all")
    sort = getattr(view, "sort", "")
    direction = getattr(view, "dir", "desc")
    params = getattr(view, "base_params", None)
    anchor = getattr(view, "anchor", "evidence")
    sort = sort if sort in SORTS else ""
    return SimpleNamespace(
        ev=ev if ev in FILTERS else "all",
        sort=sort,
        dir=direction if direction in DIRS else SORT_DEFAULT_DIR.get(sort, "desc"),
        show_all=getattr(view, "show_all", False) is True,
        params=params if isinstance(params, dict) else {},
        anchor=re.sub(r"[^A-Za-z0-9_-]", "", str(anchor or "")) or "evidence")


_OWN = ("ev", "sort", "dir", "show")


def _href(state, **change):
    """A link to the same page with the evidence state changed.

    Built from the page's own parameters, never ``was_*`` (those carry the
    previous assessment and would silently re-submit it), and always ends in
    the card's fragment so the page does not jump to the top.
    """
    ev = change.get("ev", state.ev)
    sort = change.get("sort", state.sort)
    direction = change.get("dir", state.dir)
    show_all = change.get("show_all", state.show_all)
    pairs = []
    for key, value in state.params.items():
        key = str(key)
        if key in _OWN or key.startswith("was_") or value is None:
            continue
        pairs.append((key, value))
    if ev != "all":
        pairs.append(("ev", ev))
    if sort:
        pairs.append(("sort", sort))
        pairs.append(("dir", direction))
    if show_all:
        pairs.append(("show", "all"))
    query = urlencode(pairs, doseq=True)
    return esc("?" + query + "#" + quote(state.anchor, safe="-_"))


# ---------------------------------------------------------------------------
# Derived facts about one finding

def _sum_bounds(factors):
    lo = hi = 1.0
    for pair in factors.values():
        lo *= pair[0]
        hi *= pair[1]
    return lo, hi


def _index(assessment):
    """Map each finding to its review unit and its input record, if any."""
    by_key, by_cve = {}, {}
    paths = list(getattr(assessment, "paths", None) or [])
    for rank, path in enumerate(paths):
        for entry in path.get("inputs", []):
            try:
                lo, hi = _sum_bounds(entry["factors"])
            except (KeyError, TypeError, IndexError):
                continue
            info = SimpleNamespace(rank=rank, path=path, entry=entry,
                                   z_lo=lo, z_hi=hi)
            by_key.setdefault((entry.get("cve"), entry.get("advisory")), info)
            held = by_cve.get(entry.get("cve"))
            if held is None or info.z_hi > held.z_hi:
                by_cve[entry.get("cve")] = info
    return SimpleNamespace(paths=paths, by_key=by_key, by_cve=by_cve)


def _info(index, finding):
    return (index.by_key.get((finding.cve, finding.advisory_id))
            or index.by_cve.get(finding.cve))


def _vector(finding):
    parsed = cvss.parse(finding.vector) if finding.vector else None
    return parsed if parsed is not None and parsed.attack_vector else None


def _is_network(finding):
    parsed = _vector(finding)
    return parsed is not None and parsed.attack_vector in ("network", "adjacent")


def _fix_key(finding, info):
    entry = info.entry if info else None
    if entry is not None and entry["factors"].get("U", [1, 1])[1] == 0:
        return "fixed"
    if finding.fixed:
        return "update"
    if finding.remediation in ("mitigation", "workaround"):
        return "mitigation"
    if finding.remediation == "none_available":
        return "nofix"
    return "unknown"


def _weakness(finding):
    cwe = (finding.cwe or "").strip()
    return _WEAKNESS_CLASS.get(cwe.upper(), ""), cwe


def _vector_label(finding):
    parsed = _vector(finding)
    if parsed is None:
        return "", False
    return parsed.attack_vector.upper(), bool(parsed.wormable)


# ---------------------------------------------------------------------------
# Selection: filter, order, cap

def counts(findings, assessment=None):
    """Row counts for the four filter segments, over the whole in-scope list."""
    findings = list(findings or [])
    return {"all": len(findings),
            "unpatched": sum(1 for f in findings if not f.fixed),
            "network": sum(1 for f in findings if _is_network(f)),
            "kev": sum(1 for f in findings if f.in_kev)}


def _matches(finding, ev):
    if ev == "unpatched":
        return not finding.fixed
    if ev == "network":
        return _is_network(finding)
    if ev == "kev":
        return bool(finding.in_kev)
    return True


def _sort_value(name, finding, index):
    if name == "z":
        info = _info(index, finding)
        return None if info is None else info.z_hi
    if name == "id":
        return finding.cve
    if name == "weakness":
        cls, cwe = _weakness(finding)
        return (cls or cwe or None) and (cls.lower(), cwe.lower())
    if name == "cvss":
        return finding.cvss
    if name == "epss":
        return finding.epss
    if name == "vector":
        return _vector_label(finding)[0] or None
    return _FIX_ORDER[_fix_key(finding, _info(index, finding))]


def _ranked(findings, assessment, state):
    rows = [f for f in (findings or []) if _matches(f, state.ev)]
    if not state.sort:
        # Today's report._cve_table order, byte for byte (D4). sorted() is
        # stable, so ties keep the order the findings arrived in.
        return sorted(rows, key=lambda f: (-(f.epss or 0), -(f.cvss or 0)))
    index = _index(assessment)
    # Tie-break on the CVE id first, then one stable sort on the chosen key:
    # equal rows therefore always come out in the same order. Rows with no value
    # for the key go last in either direction rather than posing as zero.
    rows.sort(key=lambda f: (f.cve, f.advisory_id))
    present = [f for f in rows if _sort_value(state.sort, f, index) is not None]
    absent = [f for f in rows if _sort_value(state.sort, f, index) is None]
    present.sort(key=lambda f: _sort_value(state.sort, f, index),
                 reverse=state.dir == "desc")
    return present + absent


def rank(findings, assessment, view):
    """Filtered rows in display order, before the cap is applied.

    With no ``sort`` this is today's order (highest EPSS, then CVSS); an explicit
    sort applies to the whole in-scope list, so the cap never hides the row a
    reader sorted for.
    """
    return _ranked(findings, assessment, _state(view))


def _limit(state):
    return HARD_MAX if state.show_all else CAP


def shown(findings, assessment, view):
    """The rows actually displayed. Cards and drawers both call this, so the
    table, the drawers and the disclosure counts cannot disagree."""
    state = _state(view)
    return _ranked(findings, assessment, state)[:_limit(state)]


# ---------------------------------------------------------------------------
# Small renderers

def _slug(text, limit=64):
    return re.sub(r"[^A-Za-z0-9_-]+", "-", str(text)).strip("-")[:limit] or "x"


def _drawer_ids(rows):
    seen, out = set(), []
    for finding in rows:
        base = "ev-d-" + _slug(finding.cve)
        candidate = base
        if candidate in seen:
            candidate = base + "-" + _slug(finding.advisory_id, 32)
        n = 2
        while candidate in seen:
            candidate = "%s-%d" % (base, n)
            n += 1
        seen.add(candidate)
        out.append(candidate)
    return out


def _num2(value):
    return "%.2f" % value


def _bound(pair, mark=""):
    """A factor cell: a value, or a violet dashed '? lo–hi' for an unknown."""
    lo, hi = pair
    if abs(hi - lo) < 1e-9:
        return _num2(lo) + mark
    return ('<span class="ev-unk">? %s</span>%s'
            % (esc(components.fmt_range(lo, hi)), mark))


def _z_cell(lo, hi):
    if abs(hi - lo) < 1e-9:
        return components.fmt_z(hi)
    return ('<span class="ev-unk">? %s%s%s</span>'
            % (components.fmt_z(lo), ENDASH, components.fmt_z(hi)))


def _floored(entry):
    """True when T's lower bound is the service-life floor rather than a
    measured KEV/LEV/EPSS value. The floor is not stored with the assessment, so
    it is derived the way exposure.threat_bounds derives it."""
    try:
        t_low = entry["factors"]["T"][0]
        profile = exposure.access_profile(
            SimpleNamespace(vector=entry.get("cvss_vector")))
        floor = exposure.THREAT_FLOORS[profile][1]
    except (KeyError, TypeError, IndexError):
        return False
    kev = 1.0 if entry.get("kev") else (
        0.0 if entry.get("kev_available", True) else None)
    known = [v for v in (kev, entry.get("lev"), entry.get("epss"))
             if v is not None]
    raw = max(known) if known else 0.0
    return abs(t_low - floor) < 1e-9 and floor > raw + 1e-12


def _floor_mark(static, position=0):
    if static:
        return '<span class="ev-floor" title="%s">↑</span>' % FLOOR_TIP
    return components.tooltip('<span class="ev-floor" aria-hidden="true">↑</span>'
                              '<span class="sr-only">floored</span>', FLOOR_TIP,
                              "ev-tip-floor-%d" % position)


def _open_button(label, target, static, name=""):
    """The ID as a drawer opener on the web, plain mono text in an export."""
    if static or not target:
        return '<code class="ev-id">%s</code>' % esc(label)
    return ('<button type="button" class="ev-open" popovertarget="%s" '
            'aria-haspopup="dialog"%s>%s</button>'
            % (esc(target), ' aria-label="%s"' % esc(name) if name else "",
               esc(label)))


# ---------------------------------------------------------------------------
# Exposure card (spec 4.10)

def _range_text(low, high, places):
    if abs(high - low) < 1e-9:
        return "%.*f" % (places, high)
    return ('<span class="ev-range">%.*f%s%.*f</span>'
            % (places, low, ENDASH, places, high))


def _readout(assessment):
    low = getattr(assessment, "exposure_min", None)
    high = getattr(assessment, "exposure_max", None)
    if low is None or high is None:
        return '<p class="ev-readout">Exposure not computed</p>'
    terms = []
    for position, weight in enumerate(exposure.CONCENTRATION, 1):
        terms.append("Z%d" % position if weight == 1
                     else "%.2f·Z%d" % (weight, position))
    r_text = _range_text(1 - high / 100, 1 - low / 100, 3)
    e_text = _range_text(low, high, 1)
    return ('<p class="ev-readout">R = min(1, %s) = <b>%s</b> → E = <b>%s</b></p>'
            % (" + ".join(terms), r_text, e_text))


def _unit_entry(path):
    best, best_key = None, None
    for entry in path.get("inputs", []):
        try:
            key = _sum_bounds(entry["factors"])[::-1]
        except (KeyError, TypeError, IndexError):
            continue
        if best is None or key > best_key:
            best, best_key = entry, key
    return best


def _legend(floored_any, static):
    items = "".join('<dt>%s <span>%s</span></dt><dd>%s</dd>'
                    % (esc(letter), esc(name), esc(text))
                    for letter, name, text in DEFINITIONS)
    note = ('<dt>↑</dt><dd>T is %s.</dd>' % FLOOR_TIP) if floored_any else ""
    return '<dl class="ev-legend">%s%s</dl>' % (items, note)


def _scoped(ident, scope):
    """An id made unique per candidate on a multi-product page."""
    return "%s-%s" % (ident, scope) if scope else ident


def exposure_card(assessment, *, static=False, findings=None, view=None, scope=""):
    """Top three review units and the arithmetic that turns them into E.

    ``findings`` and ``view`` are optional: when given, a unit row opens the
    drawer of its worst record if that record is among the shown rows. Without
    them (or in an export) rows are static text. ``scope`` is "" for a
    single-product page and "2", "3"... for the blocks of a comparison, so no
    id repeats within one document.
    """
    paths = list(getattr(assessment, "paths", None) or [])
    head = ('<div class="ev-head">%s%s</div>'
            % (components.panel_label("EXPOSURE · TOP 3 REVIEW UNITS"),
               _readout(assessment)))
    if not paths:
        cleared = getattr(assessment, "cleared_count", 0)
        text = ("No CVE applies to the selected firmware, so no review unit "
                "contributes to exposure." if cleared else
                "No review units were measured. Absence of a record is not "
                "proof of safety.")
        return components.card(head + '<p class="ev-empty">%s</p>' % esc(text),
                               id=_scoped("exposure", scope))
    drawer_for = {}
    if findings is not None and not static:
        rows = shown(findings, assessment, view)
        for finding, drawer in zip(rows, _drawer_ids(rows)):
            drawer_for.setdefault(finding.cve, drawer)

    heads = ['<th scope="col">Unit</th>']
    for letter, name, text in DEFINITIONS:
        label = '%s <span class="ev-sub">%s</span>' % (letter, esc(name.lower()))
        if not static:
            label = components.tooltip(label, text, "ev-tip-" + letter)
        heads.append('<th scope="col" class="n">%s</th>' % label)
    body, floored_any = [], False
    for position, path in enumerate(paths[:3]):
        entry = _unit_entry(path)
        factors = entry["factors"] if entry else {}
        floor = bool(entry) and _floored(entry)
        floored_any = floored_any or floor
        target = ""
        if entry and drawer_for:
            target = drawer_for.get(entry.get("cve")) or next(
                (drawer_for[c] for c in path.get("cves", []) if c in drawer_for), "")
        count = len(path.get("cves", []))
        note = path.get("grouping", "review unit")
        if count > 1:
            note += " · %d CVEs" % count
        cells = ['<td>%s<span class="ev-desc">%s</span></td>'
                 % (_open_button(path.get("path_id", ""), target, static,
                                 "Open details for " + str(path.get("path_id", ""))),
                    esc(note))]
        for letter in "TIAHU":
            pair = factors.get(letter)
            mark = _floor_mark(static, position) if letter == "T" and floor else ""
            cells.append('<td class="n">%s</td>'
                         % (DASH if pair is None else _bound(pair, mark)))
        cells.append('<td class="n ev-z">%s</td>'
                     % _z_cell(path.get("z_min", 0.0), path.get("z_max", 0.0)))
        body.append("<tr>%s</tr>" % "".join(cells))
    more = ""
    if len(paths) > 3:
        more = ('<p class="ev-caption">%d review units in total; only the top 3 '
                'enter R.</p>' % len(paths))
    table = ('<div class="tw" tabindex="0" role="region" '
             'aria-label="Top review units, scroll horizontally for more columns">'
             '<table class="ev-table ev-units"><thead><tr>%s</tr></thead>'
             '<tbody>%s</tbody></table></div>' % ("".join(heads), "".join(body)))
    return components.card(head + table + more + _legend(floored_any, static),
                           id=_scoped("exposure", scope))


# ---------------------------------------------------------------------------
# Drawer / detail sections (spec 4.15)

def _weight_text(rank_):
    weights = exposure.CONCENTRATION
    if rank_ is None or rank_ >= len(weights):
        return "outside top %d" % len(weights)
    return "weight 1" if weights[rank_] == 1 else \
        "weight " + components.fmt_weight(weights[rank_])


def _sections(finding, info, firmware, advisories):
    """(title, html) pairs, shared by the web drawer and the export's static
    detail rows so the two cannot drift apart."""
    out = []
    # Summary: only what the data holds. There is no per-CVE prose, so none is
    # invented; the advisory's own title and release date stand in.
    meta = (advisories or {}).get(finding.advisory_id)
    summary = ['<p><code>%s</code></p>' % esc(finding.advisory_id)]
    if meta:
        title, released = (list(meta) + ["", ""])[:2]
        if title:
            summary.append('<p>%s</p>' % esc(title))
        if released:
            summary.append('<p class="ev-muted">Released %s</p>' % esc(released))
    else:
        summary.append('<p class="ev-muted">Advisory title and release date '
                       'are not available.</p>')
    cls, cwe = _weakness(finding)
    if cls or cwe:
        summary.append('<p class="ev-muted">Weakness: %s</p>'
                       % esc(" · ".join(x for x in (cls, cwe) if x)))
    out.append(("Summary", "".join(summary)))

    rng = finding.version_range
    versions = ['<p class="ev-range-text">%s</p>'
                % (esc(rng) if rng else "Not stated")]
    if firmware:
        if finding.decided:
            versions.append('<p>Selected firmware <span class="ev-fw">%s</span> '
                            'is inside this range.</p>' % esc(firmware))
        else:
            versions.append('<p>Selected firmware <span class="ev-fw">%s</span>: '
                            'the range could not be checked; compare it by hand.'
                            '</p>' % esc(firmware))
    else:
        versions.append('<p class="ev-muted">No firmware selected; every '
                        'affected version is in scope.</p>')
    out.append(("Affected versions", "".join(versions)))

    key = _fix_key(finding, info)
    fix = [components.signal_chip("fix", FIX_LABELS[key], key),
           '<p>%s</p>' % esc(_FIX_TEXT.get(finding.remediation,
                                          "The advisory does not state a remedy."))]
    if finding.fix_text and finding.remediation != "vendor_fix":
        fix.append('<p>The remediation text names a shipped fix.</p>')
    fix.append('<p class="ev-muted">The advisory data does not state which '
               'version contains the fix; confirm it with the vendor.</p>')
    out.append(("Fix", "".join(fix)))

    label, worm = _vector_label(finding)
    kev = ("Listed in CISA KEV" if finding.in_kev else
           "Not listed" if getattr(finding, "kev_available", True)
           else "Not checked")
    rows = [("CVSS", components.fmt_cvss(finding.cvss)),
            ("Vector", (label or DASH) + (" · wormable" if worm else "")),
            ("EPSS", components.fmt_prob(finding.epss)),
            ("LEV", components.fmt_prob(finding.lev) if finding.lev is not None
             else "Not loaded"),
            ("KEV", kev)]
    out.append(("Signals", '<dl class="ev-facts">%s</dl>' % "".join(
        "<dt>%s</dt><dd>%s</dd>" % (esc(k), esc(v)) for k, v in rows)))

    if info is None:
        enters = '<p class="ev-muted">This record is not part of the exposure calculation.</p>'
    else:
        enters = ('<p>Review unit <code>%s</code>, ranked %d. %s.</p>'
                  '<p>Z <span class="ev-z">%s</span></p>'
                  '<p class="ev-muted">A unit counts its highest-Z record.</p>'
                  % (esc(info.path.get("path_id", "")), info.rank + 1,
                     esc(_weight_text(info.rank).capitalize()),
                     _z_cell(info.z_lo, info.z_hi)))
    out.append(("How it enters the score", enters))
    return out


def drawers(findings, assessment, view, advisories=None, *, firmware=""):
    """One popover panel per SHOWN row, so drawers always match the table.

    Web only. Esc, light dismiss and focus return are the browser's popover
    behaviour; a focus trap arrives with the script in WP9.
    """
    rows = shown(findings, assessment, view)
    if not rows:
        return ""
    index = _index(assessment)
    out = []
    for finding, ident in zip(rows, _drawer_ids(rows)):
        info = _info(index, finding)
        sections = "".join(components.panel_label(title) + body
                           for title, body in _sections(finding, info, firmware,
                                                        advisories))
        out.append(
            '<div class="ev-drawer" id="%(id)s" popover="auto" role="dialog" '
            'aria-labelledby="%(id)s-title">'
            '<div class="ev-drawer__head"><h2 class="ev-drawer__title" '
            'id="%(id)s-title">%(cve)s</h2>'
            '<button type="button" class="ev-close" popovertarget="%(id)s" '
            'popovertargetaction="hide" aria-label="Close details for %(cve)s">'
            '%(icon)s</button></div>'
            '<div class="ev-drawer__body">%(body)s</div></div>'
            % {"id": esc(ident), "cve": esc(finding.cve), "body": sections,
               "icon": components.icon("close", 16)})
    return '<div class="ev-drawers">%s</div>' % "".join(out)


# ---------------------------------------------------------------------------
# Evidence card (spec 4.14)

def _signals(finding):
    parts = ["EPSS " + components.fmt_prob(finding.epss)]
    # LEV needs the optional EPSS-history download; with none, say nothing
    # rather than print a dash column that reads like a failed lookup.
    if finding.lev is not None:
        parts.append("LEV " + components.fmt_prob(finding.lev))
    text = '<span class="ev-sig">%s</span>' % esc(" · ".join(parts))
    if finding.in_kev:
        text += " " + components.signal_chip("kev", "KEV")
    return text


def _head_cell(state, key, title, numeric, static):
    cls = ' class="n"' if numeric else ""
    if static:
        return '<th scope="col"%s>%s</th>' % (cls, esc(title))
    active = state.sort == key
    direction = state.dir if active else SORT_DEFAULT_DIR[key]
    if active:
        direction = "asc" if state.dir == "desc" else "desc"
    glyph = ""
    aria = ""
    # The default order is EPSS descending (see _disclosure), so that column
    # carries the sort state until the reader picks another; only one column
    # may ever hold aria-sort.
    if not state.sort and key == "epss":
        aria = ' aria-sort="descending"'
    if active:
        glyph = ' <span class="ev-glyph" aria-hidden="true">%s</span>' % (
            "▲" if state.dir == "asc" else "▼")
        aria = ' aria-sort="%s"' % ("ascending" if state.dir == "asc"
                                    else "descending")
    return ('<th scope="col"%s%s><a class="ev-sort" href="%s">%s%s</a></th>'
            % (cls, aria, _href(state, sort=key, dir=direction), esc(title),
               glyph))


def _label_head(firmware, total):
    noun = "1 CVE" if total == 1 else "%d CVEs" % total
    scope = ("IN SCOPE FOR FW " + str(firmware)) if firmware \
        else "ALL AFFECTED VERSIONS"
    if firmware:
        return "EVIDENCE · %s %s" % (noun, scope)
    return "EVIDENCE · %s · %s" % (noun, scope)


def _filter_nav(state, tally, static):
    if static:
        text = " · ".join("%s %d" % (FILTER_LABELS[k], tally[k]) for k in FILTERS)
        return '<p class="ev-counts">%s</p>' % esc(text)
    links = []
    for key in FILTERS:
        current = ' aria-current="true"' if key == state.ev else ""
        links.append('<a class="rt-btn rt-btn--segment" href="%s"%s>%s %d</a>'
                     % (_href(state, ev=key), current,
                        esc(FILTER_LABELS[key]), tally[key]))
    return '<nav class="ev-filters" aria-label="Filter CVEs">%s</nav>' % "".join(links)


def _disclosure(state, matched, shown_count, total, static):
    """Say what the table is, whenever it is not simply every row."""
    if state.ev == "all":
        what = "%d findings" % matched
    else:
        what = "%d findings matching the %s filter" % (
            matched, FILTER_LABELS[state.ev].lower())
    if state.show_all:
        if matched <= HARD_MAX:
            return ""
        text = ("Showing the first %d of %s, the hard maximum for one page. "
                "The JSON export carries the default selection and records how "
                "many were left out." % (HARD_MAX, what))
        return '<p class="tnote">%s</p>' % esc(text)
    if matched <= shown_count:
        return ""
    if state.sort:
        text = ("Showing %d of %s, sorted by %s, %s first. The JSON export "
                "carries the default selection (highest exploitation "
                "probability first) and records how many were left out."
                % (shown_count, what, SORT_LABELS[state.sort],
                   "highest" if state.dir == "desc" else "lowest"))
    else:
        text = ("Showing the %d most significant of %s, ranked by exploitation "
                "probability and then severity. The JSON export carries the "
                "same selection and records how many were left out."
                % (shown_count, what))
    out = esc(text)
    if not static:
        out += (' <a href="%s">Show all %d (up to %d)</a>'
                % (_href(state, show_all=True), matched, HARD_MAX))
    return '<p class="tnote">%s</p>' % out


def _detail_row(finding, info, firmware, advisories):
    parts = "".join('<p><b>%s</b></p>%s' % (esc(title), body)
                    for title, body in _sections(finding, info, firmware,
                                                 advisories))
    return ('<tr class="ev-detail"><td colspan="7"><div class="ev-sections">%s'
            '</div></td></tr>' % parts)


def evidence_card(findings, assessment, view, *, firmware="", advisories=None,
                  static=False, scope=""):
    state = _state(view)
    findings = list(findings or [])
    total = len(findings)
    tally = counts(findings, assessment)
    rows = shown(findings, assessment, view)
    matched = tally[state.ev] if state.ev in tally else len(rows)
    head_parts = [components.panel_label(_label_head(firmware, total))]
    if total:
        head_parts.append(_filter_nav(state, tally, static))
    head = '<div class="ev-head">%s</div>' % "".join(head_parts)
    intro = ('<p class="ev-intro">A CVE is a reference number for a known '
             'security weakness. Severity measures possible harm; EPSS estimates '
             'exploitation in the next 30 days. Neither shows that your '
             'equipment was attacked.</p>')
    title = '<h3 class="sr-only">Vulnerabilities to review</h3>'
    caption = '<p class="ev-caption">%s</p>' % CAPTION

    if not total:
        if firmware and getattr(assessment, "cleared_count", 0):
            text = ("No CVEs in scope for firmware %s. The advisories say none "
                    "of their CVEs applies, so exposure is 100." % firmware)
        else:
            text = ("No CVEs in scope. No advisory CVE was found for this "
                    "product, which is not proof that it has none.")
        return components.card(head + title + '<p class="ev-empty">%s</p>'
                               % esc(text) + caption, id=_scoped(state.anchor, scope))
    if not rows:
        text = "No CVEs match the %s filter (%d in scope)." % (
            FILTER_LABELS[state.ev].lower(), total)
        link = "" if static else (' <a href="%s">Show all %d</a>'
                                  % (_href(state, ev="all"), total))
        return components.card(
            head + title + '<p class="ev-empty">%s%s</p>' % (esc(text), link)
            + caption, id=_scoped(state.anchor, scope))

    index = _index(assessment)
    ids = _drawer_ids(rows)
    columns = (("id", "ID", False), ("weakness", "Weakness", False),
               ("cvss", "CVSS", True), ("epss", "Signals", False),
               ("vector", "Vector", False), ("fix", "Fix", False),
               ("z", "Z", True))
    thead = "".join(_head_cell(state, k, t, n, static) for k, t, n in columns)
    body = []
    for finding, ident in zip(rows, ids):
        info = _info(index, finding)
        cls, cwe = _weakness(finding)
        weak = ('<span class="ev-wk">%s</span>' % esc(cls) if cls else "")
        if cwe:
            weak += ('<span class="ev-cwe">%s</span>' % esc(cwe))
        label, worm = _vector_label(finding)
        vec = components.signal_chip("vector", label, "wormable" if worm else "") \
            if label else DASH
        key = _fix_key(finding, info)
        z = DASH if info is None else _z_cell(info.z_lo, info.z_hi)
        review = ('' if finding.decided
                  else ' <span class="ev-note">needs review</span>')
        body.append(
            "<tr><td>%s%s</td><td>%s</td><td class=\"n\">%s</td><td>%s</td>"
            "<td>%s</td><td>%s</td><td class=\"n ev-z\">%s</td></tr>"
            % (_open_button(finding.cve, ident, static,
                            "Open details for " + str(finding.cve)),
               review, weak or DASH, components.fmt_cvss(finding.cvss),
               _signals(finding), vec,
               components.signal_chip("fix", FIX_LABELS[key], key), z))
        if static:
            body.append(_detail_row(finding, info, firmware, advisories))

    note = _disclosure(state, matched, len(rows), total, static)
    if state.show_all and matched > CAP:
        lifted = ('Showing all %d findings.' % matched if matched <= HARD_MAX
                  else '')
        if lifted:
            link = "" if static else (
                ' <a href="%s">Show the top %d only</a>'
                % (_href(state, show_all=False), CAP))
            note = '<p class="tnote">%s%s</p>' % (lifted, link)
    if static:
        order = ("sorted by %s, %s first" % (SORT_LABELS[state.sort],
                 "highest" if state.dir == "desc" else "lowest")
                 if state.sort else "ranked by exploitation probability, then severity")
        note += '<p class="ev-counts">Order: %s.</p>' % esc(order)
    table = ('<div class="tw ev-scroll" tabindex="0" role="region" '
             'aria-label="CVE evidence, scroll horizontally for more columns">'
             '<table id="%s" class="ev-table"><thead><tr>%s</tr>'
             '</thead><tbody>%s</tbody></table></div>'
             % (_scoped("evidence-table", scope), thead, "".join(body)))
    return components.card(head + title + intro + note + table + caption,
                           id=_scoped(state.anchor, scope))


# ---------------------------------------------------------------------------
# Stylesheet. A plain string (never an f-string) so it is fingerprinted and
# lintable. Hues are reserved: cyan marks interaction only; teal, amber, coral
# and violet appear only through components' verdict/fix classes, plus violet
# for "unknown" inputs.

CSS = """
.ev-head{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:var(--s12);margin-bottom:var(--s12)}
.ev-head .rt-panel-label{margin:0}
.ev-readout{margin:0;font-family:var(--font-mono);font-size:12px;line-height:1.4;color:var(--text-2)}
.ev-readout b{font-weight:600;color:var(--text)}
.ev-range,.ev-unk{color:var(--verify);border-bottom:1px dashed var(--verify)}
.ev-intro,.ev-caption,.ev-muted,.ev-desc,.ev-counts{font-size:12px;line-height:1.4;color:var(--muted)}
.ev-intro{margin:0 0 var(--s12)}
.ev-caption{margin:var(--s12) 0 0}
.ev-counts{margin:0}
.ev-empty{margin:0;padding:var(--s16) 0;font-size:14px;color:var(--text-2)}
.ev-filters{display:flex;flex-wrap:wrap;gap:var(--s4)}
.ev-filters a.rt-btn--segment[aria-current=true]{background:var(--raised);color:var(--text);border-color:var(--control-border)}
.ev-scroll{max-height:70vh;overflow:auto}
.ev-table{width:100%;font-size:13px}
.ev-table th,.ev-table td{padding:var(--s8) var(--s12);border-bottom:1px solid var(--rule-row);vertical-align:top}
.ev-table thead th{position:sticky;top:0;z-index:1;background:var(--surface);border-bottom:1px solid var(--rule);font-family:var(--font-mono);font-weight:500;font-size:12px;line-height:1.3;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);white-space:nowrap}
.ev-table tbody tr:hover{background:var(--raised)}
.ev-sort{color:inherit;text-decoration:none}
.ev-sort:hover{color:var(--text)}
.ev-sort:focus-visible,.ev-open:focus-visible,.ev-close:focus-visible{outline:2px solid var(--action);outline-offset:-2px}
.ev-glyph{color:var(--action)}
.ev-open{padding:0;border:0;background:none;font-family:var(--font-mono);font-size:13px;color:var(--action);text-decoration:underline;text-underline-offset:2px;text-align:left;cursor:pointer}
.ev-open:hover{color:var(--action-hover)}
.ev-id{font-family:var(--font-mono);font-size:13px;background:none;padding:0}
.ev-desc{display:block}
.ev-note{display:inline-block;margin-left:var(--s6);font-size:12px;color:var(--muted)}
.ev-wk{display:block}
.ev-cwe,.ev-sig{font-family:var(--font-mono);font-size:12px;color:var(--muted)}
.ev-cwe{display:block}
.ev-sub{font-size:12px;text-transform:none;letter-spacing:0}
.ev-floor{margin-left:var(--s2);color:var(--text-2)}
.ev-units td.n,.ev-table td.ev-z{color:var(--text)}
.ev-table td.ev-z,.ev-drawer .ev-z{font-weight:600}
.ev-legend{display:grid;grid-template-columns:max-content 1fr;gap:var(--s4) var(--s12);margin:var(--s12) 0 0;font-size:12px;line-height:1.4}
.ev-legend dt{font-family:var(--font-mono);font-weight:600;color:var(--text)}
.ev-legend dt span{font-family:var(--font-sans);font-weight:400;color:var(--muted)}
.ev-legend dd{margin:0;color:var(--text-2)}
.ev-sections{display:flex;flex-direction:column;gap:var(--s4);padding:var(--s4) 0;font-size:13px}
.ev-sections p{margin:0}
.ev-detail:hover{background:none!important}
.ev-fw{font-family:var(--font-mono);color:var(--action)}
.ev-range-text{font-family:var(--font-mono);font-size:13px;overflow-wrap:anywhere}
.ev-facts{display:grid;grid-template-columns:max-content 1fr;gap:var(--s4) var(--s16);margin:0;font-size:13px}
.ev-facts dt{color:var(--muted)}
.ev-facts dd{margin:0;font-family:var(--font-mono)}
.ev-drawer{box-sizing:border-box;margin:0;padding:0;border:0;border-left:1px solid var(--control-border);background:var(--surface);color:var(--text);box-shadow:var(--overlay-shadow)}
.ev-drawer:popover-open{position:fixed;inset:0 0 0 auto;display:flex;flex-direction:column;width:480px;max-width:100%;height:100%;max-height:none;overflow:auto}
.ev-drawer::backdrop{background:rgba(0,0,0,.5)}
.ev-drawer__head{display:flex;align-items:center;justify-content:space-between;gap:var(--s12);padding:var(--s16) var(--s20);border-bottom:1px solid var(--rule)}
.ev-drawer__title{margin:0;font-family:var(--font-mono);font-weight:600;font-size:16px;color:var(--action);overflow-wrap:anywhere}
.ev-close{display:inline-flex;align-items:center;justify-content:center;min-width:32px;min-height:32px;padding:0;border:1px solid var(--control-border);border-radius:var(--r-lg);background:transparent;color:var(--text)}
.ev-close:hover{background:var(--raised)}
.ev-drawer__body{padding:var(--s16) var(--s20) var(--s24);font-size:14px;line-height:1.45}
.ev-drawer__body p{margin:0 0 var(--s6)}
.ev-drawer__body .rt-panel-label{margin:var(--s16) 0 var(--s8)}
.ev-drawer__body .rt-panel-label:first-child{margin-top:0}
@media (max-width:639px){
.ev-drawer:popover-open{width:100%;border-left:0}
.ev-table th,.ev-table td{padding:var(--s8)}
}
@supports not selector(:popover-open){
.ev-drawer{margin:var(--s12) 0;border:1px solid var(--rule)}
.ev-close{display:none}
}
@media print{
.ev-scroll{max-height:none;overflow:visible}
.ev-table thead th{position:static}
}
@media (prefers-reduced-motion:reduce){
.ev-sort,.ev-open{transition:none}
}
"""
