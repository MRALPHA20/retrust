"""Reusable CSS lint for the Control Room work packages.

Plain module in tests/ (no tests/__init__.py, pytest's default prepend import
mode puts tests/ on sys.path), so any test does `from design_lint import css_lint`.
"""
import re

MIN_FONT_PX = 12.0   # D3: absolute type floor
MAX_RADIUS_PX = 6.0  # spec 2.3: nothing above 6px, no pills (except 50%)

_FORBIDDEN = ("url(data:", "@import", "http")
_FONT_SIZE = re.compile(r"font-size\s*:\s*([^;}]+)", re.I)
_FONT_SHORT = re.compile(r"(?<![-\w])font\s*:\s*([^;}]+)", re.I)
_RADIUS = re.compile(r"border(?:-[a-z]+)*-radius\s*:\s*([^;}]+)", re.I)
_LEN = re.compile(r"(-?\d*\.?\d+)(px|rem|em|pt)\b", re.I)


def _px(num, unit):
    v = float(num)
    unit = unit.lower()
    if unit == "px":
        return v
    if unit in ("rem", "em"):
        return v * 16
    return v * 96 / 72  # pt


def css_lint(css):
    """Return a list of human-readable problems found in `css` (empty = clean)."""
    problems = []
    low = css.lower()
    for bad in _FORBIDDEN:
        if bad in low:
            problems.append("forbidden %r (CSP default-src 'none')" % bad)
    for m in _FONT_SIZE.finditer(css):
        for num, unit in _LEN.findall(m.group(1)):
            if _px(num, unit) < MIN_FONT_PX - 1e-6:
                problems.append("font-size below 12px: %s" % m.group(0).strip())
    for m in _FONT_SHORT.finditer(css):
        # Shorthand: only the first length is the size (after '/' is line-height).
        first = _LEN.search(m.group(1).split("/")[0])
        if first and _px(*first.groups()) < MIN_FONT_PX - 1e-6:
            problems.append("font shorthand below 12px: %s" % m.group(0).strip())
    for m in _RADIUS.finditer(css):
        for part in m.group(1).replace("/", " ").split():
            if part.endswith("%"):
                if part != "50%":
                    problems.append("border-radius %s (only 50%% allowed): %s"
                                    % (part, m.group(0).strip()))
                continue
            lm = _LEN.fullmatch(part)
            if lm and _px(*lm.groups()) > MAX_RADIUS_PX + 1e-6:
                problems.append("border-radius above 6px: %s" % m.group(0).strip())
    return problems
