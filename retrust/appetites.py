"""Named risk appetites: complete weight-and-band opinions to start from.

config.py already admits the shipped weights are one defensible opinion, and
that a water utility and a car plant should weigh patch availability
differently. But conceding that and then handing every buyer an empty JSON file
leaves them inventing numbers from nothing. Each appetite here is a complete
weights-and-bands set with its reasoning written down, so "we are a
safety-critical process plant" becomes a starting point to edit rather than a
blank page. ("Appetite", not "profile": in this package a profile is what the
vendor dossier builds, and one word must not mean two things.)

An appetite changes the WEIGHTS, never the evidence. The same findings feed the
same pillars under every profile, and the hard gates -- sanctions, exploited
unpatched CVEs -- fire identically under all of them: no appetite makes a
disqualifying fact weigh less. The module also refuses to generate profiles it
cannot defend: four opinions with their reasons written down beat forty
produced without them.
"""

import textwrap
from dataclasses import dataclass
from types import MappingProxyType

from . import config
from .score import BANDS, DEFAULT_WEIGHTS

FRAMING = (
    "An appetite changes the weights, never the evidence: hard gates (sanctions,"
    " exploited unpatched CVEs) fire identically under every appetite, and no"
    " appetite makes a disqualifying fact weigh less.")


@dataclass(frozen=True)
class Appetite:
    """One shipped opinion. The mappings are read-only proxies and the
    dataclass frozen, so the shipped numbers genuinely cannot be tuned in
    place; a buyer who wants different numbers edits a config written from
    one."""

    name: str
    # Exactly the DEFAULT_WEIGHTS keys. Values are relative (normalised
    # downstream) but kept summing to 1.0 so the file reads as shares.
    weights: dict
    bands: dict     # {"prefer": ..., "conditional": ...}: the config-file shape
    why: str        # the reasoning, carried wherever the numbers go


def _default_bands():
    """A fresh copy per profile: sharing one dict would let a caller who
    mutates one profile's bands silently rewrite another's."""
    return {"prefer": BANDS[0][0], "conditional": BANDS[1][0]}


APPETITES = (
    Appetite(
        name="default",
        weights=MappingProxyType(dict(DEFAULT_WEIGHTS)),
        bands=MappingProxyType(_default_bands()),
        why=("The shipped weights, verbatim: the baseline opinion every result"
             " already uses when no config file overrides it. Exploitation"
             " leads because observed and predicted exploitation is the most"
             " direct evidence this corpus carries; certification and vendor"
             " practice count least because they are indirect. One defensible"
             " opinion, not a fact -- `retrust sensitivity` reports how much a"
             " verdict depends on it."),
    ),
    Appetite(
        name="safety-critical",
        weights=MappingProxyType({
            # Consequence follows what an attacker reaches and how bad the
            # worst flaw is, so the direct-evidence pillars absorb the increase.
            "exploitation": 0.35, "severity": 0.30, "patchability": 0.15,
            "vendor_practice": 0.10, "certification": 0.10,
        }),
        # Stricter on both edges: more score before either favourable verdict.
        bands=MappingProxyType({"prefer": 75, "conditional": 45}),
        why=("For processes where a compromise can injure people or destroy"
             " equipment. There the cost of a wrong PREFER is far larger than"
             " the cost of a wrong AVOID, so both bands demand more score"
             " before a favourable verdict, and exploitation and severity weigh"
             " more because consequence follows from what an attacker can reach"
             " and how bad the worst flaw is -- not from the vendor's"
             " paperwork. The evidence is unchanged; only the score it takes to"
             " be preferred is."),
    ),
    Appetite(
        name="exposed",
        weights=MappingProxyType({
            # Reachable gear meets the attacker population KEV and EPSS
            # actually measure, so the probability pillar dominates outright.
            "exploitation": 0.45, "severity": 0.25, "patchability": 0.15,
            "vendor_practice": 0.10, "certification": 0.05,
        }),
        bands=MappingProxyType(_default_bands()),
        why=("For gear reachable from the IT network or the internet."
             " Reachability turns probability into expectation: KEV and EPSS"
             " measure what happens to devices attackers can touch, and an"
             " exposed device faces exactly that population for its whole"
             " service life. Exploitation therefore weighs most and severity"
             " next, since reachable-and-critical is the combination exploited"
             " first. Bands stay at the defaults: this appetite reorders what"
             " matters, not how much score a PREFER requires."),
    ),
    Appetite(
        name="isolated-cell",
        weights=MappingProxyType({
            # Presence-gated exploitation counts less; the pillars pricing what
            # it costs to live with a flaw for years count more.
            "exploitation": 0.15, "severity": 0.15, "patchability": 0.30,
            "vendor_practice": 0.25, "certification": 0.15,
        }),
        bands=MappingProxyType(_default_bands()),
        why=("For an air-gapped cell where exploitation needs presence at the"
             " process. Probability signals built largely from internet-facing"
             " telemetry overstate that risk, so exploitation weighs less; what"
             " dominates instead is a device that cannot take a vendor fix"
             " inside an outage window, because it carries its flaws for the"
             " life of the asset -- so patchability and vendor practice weigh"
             " most. The air gap is a property of your network, not of the"
             " product: verify it holds before choosing this appetite."),
    ),
)


def get(name):
    """The named appetite, or None: 'no such appetite' is the caller's message."""
    return next((a for a in APPETITES if a.name == name), None)


def names():
    """Appetite names in shipped order, for CLI help and error messages."""
    return [appetite.name for appetite in APPETITES]


def template(name):
    """The appetite as a config file, in the exact shape config.template() emits.

    Built on config.template() rather than beside it, so the two shapes cannot
    drift: what this returns is exactly what config.load reads back. The why
    rides in "_comment" ahead of the standard editing note, because a config
    file that has forgotten its own reasoning is just numbers again.
    """
    appetite = get(name)
    if appetite is None:
        raise SystemExit(
            f"unknown appetite {name!r}. Shipped appetites: {', '.join(names())}")
    document = config.template()
    document["_comment"] = (f"{appetite.name} appetite. {appetite.why} "
                            + document["_comment"])
    document["weights"] = dict(appetite.weights)
    document["bands"] = dict(appetite.bands)
    return document


def describe():
    """Every appetite as a terminal listing a buyer can read before choosing.

    Weight summaries print heaviest-first because the ordering is the opinion;
    ties break alphabetically so the same numbers always print the same line.
    Whole key-value pairs pack into lines, so a weight can never split across
    a wrap point however long a future pillar name grows.
    """
    lines = ["RISK APPETITES", ""]
    for appetite in APPETITES:
        ranked = sorted(appetite.weights.items(), key=lambda kv: (-kv[1], kv[0]))
        lines.append(f"  {appetite.name}")
        lines += _pack([f"{key} {value:.2f}" for key, value in ranked],
                       "    weights  ", "             ")
        lines.append(f"    bands    PREFER >= {appetite.bands['prefer']:g},"
                     f" CONDITIONAL >= {appetite.bands['conditional']:g},"
                     f" AVOID below that")
        lines += _wrap(appetite.why, "    ", "    ")
        lines.append("")
    lines += _wrap(FRAMING, "", "")
    return "\n".join(lines)


def _pack(units, first, rest, width=78):
    """Greedy-pack whole units into lines: a unit never splits mid-way."""
    lines, line = [], first
    for unit in units:
        candidate = unit if line in (first, rest) else "  " + unit
        if len(line) + len(candidate) > width and line not in (first, rest):
            lines.append(line)
            line = rest
            candidate = unit
        line += candidate
    return lines + [line]


def _wrap(text, first="", rest="    "):
    """Fold to an 80-column terminal, continuations hanging under the prose.

    break_on_hyphens=False: the whys are full of compounds ("air-gapped",
    "internet-facing") and a split mid-compound reads as a typo.
    """
    return textwrap.wrap(text, 78, initial_indent=first,
                         subsequent_indent=rest, break_on_hyphens=False)
