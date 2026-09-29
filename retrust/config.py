"""Scoring configuration: weights and band thresholds a user can change.

The weights in DEFAULT_WEIGHTS are one defensible opinion, not a fact. A water
utility and a car plant genuinely should weigh patch availability differently.
So the weights live in a file the buyer edits, the file is printed alongside
every result, and `retrust sensitivity` reports how much the verdict actually
depends on them.

The format is JSON because it needs no dependencies and a procurement engineer
can edit it without learning anything new.
"""

import json
import math
from pathlib import Path

from .score import BANDS, DEFAULT_WEIGHTS

DEFAULT_PATH = "retrust.config.json"


def template():
    """The default configuration, as written by `retrust config --init`."""
    return {
        "_comment": "ReTrust scoring configuration. Weights are relative and are "
                    "normalised, so they need not sum to 1. Higher band "
                    "thresholds mean a stricter procurement policy.",
        "weights": dict(DEFAULT_WEIGHTS),
        "bands": {"prefer": BANDS[0][0], "conditional": BANDS[1][0]},
    }


def load(path=None):
    """Read a config file, falling back to defaults when absent.

    Returns (weights, bands, source) where source names where the values came
    from, so the CLI can tell the user which weights produced a verdict.
    """
    candidate = Path(path or DEFAULT_PATH)
    if not candidate.exists():
        return dict(DEFAULT_WEIGHTS), _bands_from(None), "built-in defaults"

    try:
        document = json.loads(candidate.read_text(encoding="utf-8"))
    except ValueError as error:
        raise SystemExit(f"{candidate} is not valid JSON: {error}")

    if not isinstance(document, dict):
        raise SystemExit(f"{candidate}: configuration must be an object")
    raw = document.get("weights", {})
    if not isinstance(raw, dict):
        raise SystemExit(f"{candidate}: 'weights' must be an object of pillar -> number")

    weights = {}
    for key, value in raw.items():
        if key.startswith("_"):
            continue
        try:
            weights[key] = float(value)
        except (TypeError, ValueError):
            raise SystemExit(
                f"{candidate}: weight for {key!r} is {value!r}, which is not a number")
    unknown = set(weights) - set(DEFAULT_WEIGHTS)
    if unknown:
        raise SystemExit(
            f"{candidate}: unknown pillar(s) {sorted(unknown)}. "
            f"Valid pillars: {sorted(DEFAULT_WEIGHTS)}")
    if any(not math.isfinite(v) for v in weights.values()):
        raise SystemExit(f"{candidate}: weights must be finite numbers")
    negative = sorted(k for k, v in weights.items() if v < 0)
    if negative:
        raise SystemExit(
            f"{candidate}: negative weight on {negative}. A weight is how much a "
            "pillar counts, so it cannot be below zero; use 0 to ignore a pillar.")
    # A config naming only some pillars used to drop the rest silently, so
    # {"exploitation": 1.0} quietly became a one-pillar score. Fill the gaps
    # from the defaults instead, which is what a partial override means.
    if weights:
        weights = {**DEFAULT_WEIGHTS, **weights}
        if sum(weights.values()) <= 0:
            raise SystemExit(f"{candidate}: weights must not all be zero")

    return (weights or dict(DEFAULT_WEIGHTS),
            _bands_from(document.get("bands")),
            str(candidate))


def _bands_from(bands):
    """Band thresholds, highest first, matching score.BANDS' shape."""
    if not bands:
        return list(BANDS)
    if not isinstance(bands, dict):
        raise SystemExit("'bands' must be an object with 'prefer' and 'conditional'")
    try:
        prefer = float(bands.get("prefer", BANDS[0][0]))
        conditional = float(bands.get("conditional", BANDS[1][0]))
    except (TypeError, ValueError):
        raise SystemExit("band thresholds must be numbers")
    if not all(math.isfinite(v) for v in (prefer, conditional)):
        raise SystemExit("band thresholds must be finite numbers")
    # A threshold at or below zero makes the band beneath it unreachable, since
    # no score is negative: conditional=-5 would leave AVOID impossible to hit.
    if conditional <= 0:
        raise SystemExit(
            f"conditional threshold ({conditional}) must be above 0, or AVOID "
            "can never be reached -- no score is negative.")
    if conditional >= prefer:
        raise SystemExit(
            f"band thresholds are inverted: conditional ({conditional}) "
            f"must be below prefer ({prefer})")
    return [(prefer, "PREFER"), (conditional, "CONDITIONAL"), (0, "AVOID")]


def write_template(path=None, document=None):
    """Write a starter config the user can edit. Never overwrites silently.

    `document` lets a caller write a different starting opinion -- a named
    profile -- through the same refuse-to-overwrite gate, so there is exactly
    one place a config file comes into being.
    """
    destination = Path(path or DEFAULT_PATH)
    if destination.exists():
        raise SystemExit(f"{destination} already exists; edit it or delete it first.")
    destination.write_text(json.dumps(document or template(), indent=2) + "\n",
                           encoding="utf-8")
    return destination
