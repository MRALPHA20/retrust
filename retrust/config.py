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

    weights = {k: float(v) for k, v in (document.get("weights") or {}).items()
               if not k.startswith("_")}
    unknown = set(weights) - set(DEFAULT_WEIGHTS)
    if unknown:
        raise SystemExit(
            f"{candidate}: unknown pillar(s) {sorted(unknown)}. "
            f"Valid pillars: {sorted(DEFAULT_WEIGHTS)}")
    negative = sorted(k for k, v in weights.items() if v < 0)
    if negative:
        raise SystemExit(
            f"{candidate}: negative weight on {negative}. A weight is how much a "
            "pillar counts, so it cannot be below zero; use 0 to ignore a pillar.")
    if weights and sum(weights.values()) <= 0:
        raise SystemExit(f"{candidate}: weights must not all be zero")

    return (weights or dict(DEFAULT_WEIGHTS),
            _bands_from(document.get("bands")),
            str(candidate))


def _bands_from(bands):
    """Band thresholds, highest first, matching score.BANDS' shape."""
    if not bands:
        return list(BANDS)
    prefer = float(bands.get("prefer", BANDS[0][0]))
    conditional = float(bands.get("conditional", BANDS[1][0]))
    if conditional >= prefer:
        raise SystemExit(
            f"band thresholds are inverted: conditional ({conditional}) "
            f"must be below prefer ({prefer})")
    return [(prefer, "PREFER"), (conditional, "CONDITIONAL"), (0, "AVOID")]


def write_template(path=None):
    """Write a starter config the user can edit. Never overwrites silently."""
    destination = Path(path or DEFAULT_PATH)
    if destination.exists():
        raise SystemExit(f"{destination} already exists; edit it or delete it first.")
    destination.write_text(json.dumps(template(), indent=2) + "\n", encoding="utf-8")
    return destination
