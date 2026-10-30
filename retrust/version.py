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
from functools import lru_cache

# Ranges pinned to a serial number or board revision cannot be decided from a
# version string at all, so we refuse them on purpose rather than guess.
# "Rev. 1" is a board revision: hardware, not firmware, so no version string
# a buyer holds can decide it. It sat here implicitly before -- the prefix
# stripper happened to mangle it -- and the label stripper would now read it
# as version 1, which is exactly the confident wrong answer to refuse.
UNDECIDABLE = re.compile(
    r"serial|BIOS|U-Boot|special.modification|distributed"
    r"|\bRev(?:ision)?\.?[_\s]*\d", re.I)

_OP = re.compile(r"(<=|>=|<|>|=)")
# A leading component or kind word: "V4.5", "FW11", "firmware_SP473", "SW_v4.4".
# Applied repeatedly, since vendors chain them ("firmware_SP473" -> "SP473" -> "473").
_PREFIX = re.compile(r"^(?:V|R|FW|SW|HW|SV|SP|T|M|Rev|Version|Firmware|Build)[_\s.]*", re.I)
_UPDATE = re.compile(
    r"[_\s]*(?:Update|Upd|SP|Service[_\s]?Pack|Build|Patch)[_\s]*(\d+)$", re.I)

# A product or family tag welded onto the version with a separator: Mobotix
# "MX-V4.0.1.15", Siemens "ROS_v3.11.5", "WinCC_TIA_Portal_V13", IDEC
# "Ver.2.60". The token itself is never version information -- the separator
# is what marks it as a label -- so it is dropped, repeatedly. Space-joined
# words stay refused: "not affected" must not become "affected".
_LABEL = re.compile(r"^[A-Za-z]{2,}[-_.]+")

# Words vendors put between two comparators, or after one. Absorbed into a
# bound they sort above every numeric component -- ">=V2.3_and_<V6.30.016"
# excluded the whole 2.3 line, the lower edge the vendor had just named.
_CONNECTIVE = re.compile(
    r"[_\s]((?:and|or|but|only|not|up|to|thru|through|until|including|"
    r"excluding|when|with)\b)",
    re.I)

# "V2.x", "V1.00.xx", Hitachi's "1.2 *": everything on that line. Read as an
# exact pin it matched nothing, a confident False for every real version.
_WILDCARD = re.compile(r"^(.*?)[._\s](?:x+|\*)$", re.I)

# "34.011-34.014". Only when both sides carry a dot, so "6.1.1-3" stays the
# single version it is.
_DASH_RANGE = re.compile(r"^([A-Za-z]*[\s._]*\d+\.[\d.]*\d)\s*-\s*"
                         r"([A-Za-z]*[\s._]*\d+\.[\d.]*\d)$")

_AND_OLDER = re.compile(r"^(.*?)[_\s]+and[_\s]+(?:older|below|earlier|prior)$", re.I)
_UNTIL = re.compile(r"^(.*?)[_\s]+(?:until|thru|through)[_\s]+(.*)$", re.I)


# A real version component is a handful of digits. A run of thousands is not a
# version; it is a poisoned advisory aiming int() at Python's 4,300-digit string
# cap, which would raise mid-parse and crash a later score or eval. Refused as
# unparseable here -- which keeps the range in scope, never assumed safe.
_MAX_COMPONENT_DIGITS = 18
_OVERSIZED_DIGITS = re.compile(r"\d{%d,}" % (_MAX_COMPONENT_DIGITS + 1))


@lru_cache(maxsize=2048)
def parse_version(text):
    """Turn "V4.5.1 Update 3" into a sortable tuple, or None if it isn't a version."""
    if not text:
        return None
    if _OVERSIZED_DIGITS.search(text):
        return None
    s = text.strip()

    # "V17 Update 5" sorts after "V17 Update 4". Only split off a suffix when a
    # version number remains in front of it, so "firmware_SP473" keeps its 473.
    # Taken repeatedly, because "V14 SP1 Update 14" nests one inside the other.
    update = ()
    while (m := _UPDATE.search(s)) and any(c.isdigit() for c in s[: m.start()]):
        update, s = (int(m.group(1)),) + update, s[: m.start()].strip()

    # "3.6 (Build 170215)": the parenthesised suffix is the update the regex
    # above would have read, had the vendor left the brackets off.
    s = re.sub(r"\(((?:Update|Upd|SP|Build|Patch)[_\s]*\d+)\)$", r" \1", s,
               flags=re.I)
    if (m := _UPDATE.search(s)) and any(c.isdigit() for c in s[: m.start()]):
        update, s = (int(m.group(1)),) + update, s[: m.start()].strip()

    # "15.2(6)E0a" -> "15.2.6E0a"; vendors put build numbers in parentheses.
    # Yokogawa writes the whole version in them: "(R4.10)".
    s = re.sub(r"\((\d+)\)", r".\1", s).strip(" ._")
    while s.startswith("(") and s.endswith(")"):
        s = s[1:-1].strip(" ._")
    while s and not s[0].isdigit():     # strip chained V / FW / firmware_ prefixes
        stripped = _LABEL.sub("", s, count=1)
        if stripped == s:
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


def _rewrite(text):
    """Turn a vendor shorthand into the comparator string it means.

    Each of these was previously read as an exact version pin and answered a
    confident False for every version the range was written to cover. Rewriting
    rather than special-casing keeps the comparator parser the only thing that
    decides, which is what stops the layers fighting each other.
    """
    if _OP.search(text):
        return text                       # already comparators; leave it alone

    if m := _AND_OLDER.match(text):
        return f"<={m.group(1)}"
    if m := _UNTIL.match(text):
        if parse_version(m.group(1)) and parse_version(m.group(2)):
            return f">={m.group(1)}|<={m.group(2)}"
    if m := _DASH_RANGE.match(text):
        if parse_version(m.group(1)) and parse_version(m.group(2)):
            return f">={m.group(1)}|<={m.group(2)}"
    if m := _WILDCARD.match(text):
        # "2.x" covers everything from 2 up to but not including 3.
        if (low := parse_version(m.group(1))) and low[0]:
            parts = list(low[0])
            last = parts[-1]
            if last[0] == 0:              # a numeric component we can increment
                upper = ".".join(
                    str(p[1]) + p[2] for p in parts[:-1] + [(0, last[1] + 1, "")])
                return f">={m.group(1)}|<{upper}"
    return text


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
        rest = rest.strip()
        # A component name may also sit before the number ("firmware 2.1.3");
        # drop it -- unless the word is itself the version, as in "<V17 SP2",
        # where dropping "V17" read the service pack as the whole bound: <2.
        if (w := re.match(r"[A-Za-z]\w*\s+", rest)) and \
                parse_version(w.group().strip()) is None:
            rest = rest[w.end():]
        # Cut a trailing connective before parsing: "V2.3_and_" must read as
        # 2.3, not as a version whose last component is the word "and".
        head, *tail = _CONNECTIVE.split(rest, maxsplit=1)
        if (v := parse_version(head.strip("_ -"))) is None:
            return None
        out.append((op, v))
        # The cut can throw away the other end of the window: ">=9.3.0 but not
        # including 9.3.8" kept only the >= and matched every later version.
        # When the tail names a version, keep it as the bound it is.
        if tail and (found := _version_at_end(tail[1])):
            bound, prose = found
            if op in (">", ">="):
                exclusive = re.search(r"\bnot|excluding|below|before\b",
                                      f"{tail[0]} {prose}", re.I)
                out.append(("<" if exclusive else "<=", bound))
            else:
                out.append((op, bound))  # "<11.0BD and 11.0CB": one more of the same
    return out or None


def _version_at_end(text):
    """The version a connective's tail ends with, and the prose before it.

    Longest suffix first, so "V17 SP2" stays one version rather than "2".
    Returns None when the tail holds no version at all ("and older").
    """
    words = re.split(r"([_\s]+)", text.strip("_ "))
    for i in range(0, len(words), 2):
        if (v := parse_version("".join(words[i:]).strip("_ "))) is not None:
            return v, "".join(words[:i])
    return None


@lru_cache(maxsize=2048)
def _normalize(range_text):
    """Reduce a range string to ("all", None), ("constraints", [...]), or None.

    None means the range cannot be decided from a version string.
    """
    if not range_text:
        return None
    text = range_text.strip()

    scheme = ""
    if text.lower().startswith("vers:"):
        scheme = text[len("vers:"):].split("/", 1)[0].strip().lower()

    # Some vendors emit a malformed VERS fragment mid-string (">=vers:/_V5.4"),
    # and ABB writes product names into the scheme slot, slash-separated
    # ("vers:Relion_670/650/SAM600-IO/>=2.2.1.0|<=2.2.1.8"). A strip that only
    # accepted letters left 49 decidable ABB ranges abstaining.
    text = re.sub(r"vers:[^/\s<>=|]*/", "", text, flags=re.I).strip("_ ")
    if scheme:
        text = re.sub(r"^(?:[^/<>=|]*/)+", "", text).strip("_ ")
    text = _rewrite(text)

    # "vers:all/*" and a bare "*" really do mean every version. A vers: string
    # whose constraint part is missing ("vers:intdot/") is malformed, not
    # universal -- reading it as "all" marks every version of the product
    # vulnerable because a vendor left a field blank. So is one whose scheme
    # slot holds a version ("vers:2.2.0/*"): the vendor meant that release
    # line, and "all" would mark every other one too.
    if text == "all" or (text == "" and scheme == "all"):
        return ("all", None)
    if text == "*":
        return ("all", None) if re.fullmatch(r"[a-z]*", scheme) else None
    if text == "":
        return None                     # malformed: abstain rather than guess
    if UNDECIDABLE.search(text):        # serial / revision / date scoped
        return None

    constraints = _constraints(text)
    return ("constraints", tuple(constraints)) if constraints else None


@lru_cache(maxsize=2048)
def affects(range_text, version_text):
    """Does `version_text` fall inside the affected range `range_text`?

    Returns True, False, or None when the question cannot be decided.
    Identical range/version comparisons reuse a bounded deterministic result;
    changed firmware or advisory text is a different key.
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

    # "<=6.30|>=2.3" splits into two one-sided windows whose union is every
    # version ever released -- a range that answers True for everything. A
    # vendor who wrote that meant the window [2.3, 6.30] backwards, so it is
    # folded into one. A genuinely disjoint pair ("<=8.1|>=8.1.10") is kept.
    if (len(groups) == 2
            and all(op in ("<", "<=") for op, _ in groups[0])
            and all(op in (">", ">=") for op, _ in groups[1])
            and all(_holds("<=", low, high)
                    for _, low in groups[1] for _, high in groups[0])):
        return [groups[0] + groups[1]]
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
