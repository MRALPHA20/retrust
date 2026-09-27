"""Decide whether a firmware version falls inside an advisory's affected range.

CSAF advisories write affected versions three ways:

    vers:intdot/<4.3.8      the VERS spec          ~46% of the CISA OT corpus
    <V2.9.7  |  >=V3.1|<V3.2   comparator strings  ~43%
    <V17_Update_5           vendor grammars        the rest

We try three parsers in that order. Each one accepts only what it fully
understands, so adding a parser can never break an earlier one. (An earlier
version used a single clever regex for all three and scored *worse* -- 87.7%
against 89.6% -- because the vendor fixes broke the comparator cases.)

Anything no parser understands returns None, meaning "needs review". None never
means "not affected" -- treating an unparseable range as safe would hide risk.
"""

import re

# Ranges pinned to a serial number or board revision cannot be decided from a
# version string at all, so we refuse them on purpose rather than guess.
UNDECIDABLE = re.compile(r"serial|BIOS|U-Boot|special.modification|distributed", re.I)

_OP = re.compile(r"(<=|>=|<|>|=)")
# A leading component or kind word: "V4.5", "FW11", "firmware_SP473", "SW_v4.4".
# Applied repeatedly, since vendors chain them ("firmware_SP473" -> "SP473" -> "473").
_PREFIX = re.compile(r"^(?:V|R|FW|SW|HW|SV|SP|T|M|Rev|Version|Firmware|Build)[_\s.]*", re.I)
_UPDATE = re.compile(r"[_\s]*(?:Update|SP|Service[_\s]?Pack|Build)[_\s]*(\d+)$", re.I)


def parse_version(text):
    """Turn "V4.5.1 Update 3" into a sortable tuple, or None if it isn't a version."""
    if not text:
        return None
    s = text.strip()

    # "V17 Update 5" sorts after "V17 Update 4". Only split off the suffix when a
    # version number remains in front of it, so "firmware_SP473" keeps its 473.
    update = 0
    if (m := _UPDATE.search(s)) and any(c.isdigit() for c in s[: m.start()]):
        update, s = int(m.group(1)), s[: m.start()].strip()

    # "15.2(6)E0a" -> "15.2.6E0a"; vendors put build numbers in parentheses.
    s = re.sub(r"\((\d+)\)", r".\1", s).strip(" ._")
    while s and not s[0].isdigit():     # strip chained V / FW / firmware_ prefixes
        stripped = _PREFIX.sub("", s, count=1)
        if stripped == s:
            return None                 # a word we do not recognise: refuse it
        s = stripped.strip(" ._")
    if not s:
        return None

    parts = []
    for token in re.split(r"[._\-]", s):
        if token.isdigit():
            parts.append((0, int(token), ""))
        elif m := re.fullmatch(r"(\d+)([A-Za-z]\w*)", token):   # "212N"
            parts.append((0, int(m.group(1)), m.group(2).lower()))
        elif re.fullmatch(r"[A-Za-z]\w*", token):
            parts.append((1, 0, token.lower()))
        elif token:
            return None
    return (tuple(parts), update) if parts else None


def _padded(a, b):
    """Pad both version tuples to equal length so 4.5 and 4.5.1 stay comparable."""
    (pa, ua), (pb, ub) = a, b
    pad = (0, 0, "")
    n = max(len(pa), len(pb))
    return (pa + (pad,) * (n - len(pa)), ua), (pb + (pad,) * (n - len(pb)), ub)


def _holds(op, version, bound):
    """Is `version op bound` true?"""
    v, b = _padded(version, bound)
    return {"<": v < b, "<=": v <= b, ">": v > b, ">=": v >= b, "=": v == b}[op]


def _constraints(text):
    """Split a comparator string into (op, version) pairs, or None if unclear."""
    tokens = []
    for chunk in re.split(r"[|,;]", text):
        if not (chunk := chunk.strip()):
            continue
        starts = [m.start() for m in _OP.finditer(chunk)]
        if len(starts) > 1:             # ">=V6.2<V7.1" written without a separator
            tokens += [chunk[s:e] for s, e in zip(starts, starts[1:] + [len(chunk)])]
        else:
            tokens.append(chunk)

    out = []
    for token in tokens:
        token = token.strip()
        # A component name may sit before the operator ("NMC2 <= 6.9.6") or
        # before the number ("firmware 2.1.3"); drop it either way.
        token = re.sub(r"^[A-Za-z]\w*\s+(?=[<>=])", "", token)
        m = _OP.match(token)
        op, rest = (m.group(1), token[m.end():]) if m else ("=", token)
        rest = re.sub(r"^[A-Za-z]\w*\s+", "", rest.strip())
        if (v := parse_version(rest)) is None:
            return None
        out.append((op, v))
    return out or None


def _normalize(range_text):
    """Reduce a range string to ("all", None), ("constraints", [...]), or None.

    None means the range cannot be decided from a version string.
    """
    if not range_text:
        return None
    text = range_text.strip()

    # Some vendors emit a malformed VERS fragment mid-string (">=vers:/_V5.4").
    text = re.sub(r"vers:[a-z]*/", "", text, flags=re.I).strip("_ ")

    # "vers:all/*" and a bare "*" really do mean every version. A vers: string
    # whose constraint part is missing ("vers:intdot/") is malformed, not
    # universal -- reading it as "all" marks every version of the product
    # vulnerable because a vendor left a field blank.
    scheme = ""
    if (raw := range_text.strip()).lower().startswith("vers:"):
        scheme = raw[len("vers:"):].split("/", 1)[0].strip().lower()
    if text == "*" or text == "all" or (text == "" and scheme == "all"):
        return ("all", None)
    if text == "":
        return None                     # malformed: abstain rather than guess
    if UNDECIDABLE.search(text):        # serial / revision / date scoped
        return None

    constraints = _constraints(text)
    return ("constraints", constraints) if constraints else None


def affects(range_text, version_text):
    """Does `version_text` fall inside the affected range `range_text`?

    Returns True, False, or None when the question cannot be decided.
    """
    match _normalize(range_text):
        case None:
            return None
        case ("all", _):
            return True
        case (_, constraints):
            pass

    if (version := parse_version(version_text)) is None:
        return None

    # Affected in any one interval means affected.
    return any(_in_interval(group, version) for group in _intervals(constraints))


def _intervals(constraints):
    """Split a constraint list into the intervals it describes.

    A range can name more than one: ">=1.0|<2.0|>=3.0|<4.0" is two disjoint
    windows, not four conditions. Treating it as four and requiring all of them
    is unsatisfiable, and returned a confident "not affected" for a version that
    really was in the first window -- the most dangerous kind of wrong answer
    this module can give.
    """
    groups, current = [], []
    for op, bound in constraints:
        # A lower bound after a closed interval opens the next one.
        if op in (">", ">=") and any(o in ("<", "<=") for o, _ in current):
            groups.append(current)
            current = []
        current.append((op, bound))
    if current:
        groups.append(current)
    return groups


def _in_interval(group, version):
    """Is the version inside one interval?

    A lower and an upper bound together bracket it, so both must hold. Bounds
    of a single kind are alternatives: "<2.0 | <3.1" means either.

    An exact version listed beside a window is always an alternative too:
    ">=13.0.0 | <=13.0.2 | 13.1.0" means the window OR that one release.
    ANDing it with the bounds made the group unsatisfiable, so a version
    genuinely inside the window came back as a confident "not affected" and the
    CVE vanished from the buyer's report. Twelve corpus ranges have this shape.
    """
    lowers = [c for c in group if c[0] in (">", ">=")]
    uppers = [c for c in group if c[0] in ("<", "<=")]
    exact = [c for c in group if c[0] == "="]
    if lowers and uppers:
        within = all(_holds(op, version, bound) for op, bound in lowers + uppers)
        return within or any(_holds(op, version, bound) for op, bound in exact)
    return any(_holds(op, version, bound) for op, bound in group)


def is_determinate(range_text):
    """True when `affects` can decide this range. Used by the accuracy report."""
    return _normalize(range_text) is not None
