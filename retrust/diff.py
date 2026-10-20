"""Re-score a stored result against the current index, and report what moved.

A procurement decision is made once and lived with for years. The advisories
keep coming, so the question a quarterly review actually asks is not "how does
this bill of materials score?" but "what changed since we approved it?".

That needs the original request, not the result: the label a run printed is what
we resolved to, which cannot be queried again. `batch.to_record` stores the four
fields the buyer supplied, and this module feeds them back through scoring
against today's index.

Two things are deliberately kept apart. A verdict that moved because new
advisories landed is news. A verdict that moved because the weights were edited
between the two runs is not, and reporting them together would credit a config
change to the corpus -- so the weights are compared and a mismatch is said out
loud before any of the findings.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

from . import score

# Worse is a longer fall down this list. NOT ASSESSED and VERIFY sit outside it:
# losing the ability to assess something, or newly needing a technical check, is
# a different event from it getting riskier, and averaging the two would hide
# both. `Change.kind` returns before it reaches RANK for either of them.
#
# Derived from score.VERDICT_RANK rather than written out again, because the
# omissions are the only thing that makes this a lookup it is safe to subscript.
# RANK[self.now] is an unguarded subscript: it stays a KeyError only as long as
# `kind` filters every absent verdict out first. Adding a sixth verdict to
# VERDICT_RANK therefore needs this set extended AND a matching early return in
# `kind` -- a comprehension over the shared map makes that one decision in one
# place instead of two lists that drift.
RANK = {verdict: position for verdict, position in score.VERDICT_RANK.items()
        if verdict in ("PREFER", "CONDITIONAL", "AVOID")}

# Below this a score move is noise from a rounding change, not a finding.
MOVED = 1.0


@dataclass
class Change:
    """One product, as it scored then and as it scores now."""

    product: str
    query: dict
    before: dict
    after: dict
    new_gates: list = field(default_factory=list)

    @property
    def was(self):
        return self.before.get("verdict", "NOT ASSESSED")

    @property
    def now(self):
        return self.after.get("verdict", "NOT ASSESSED")

    @property
    def drift(self):
        """Score change, or None when either run could not produce one."""
        first, second = self.before.get("score"), self.after.get("score")
        return None if first is None or second is None else round(second - first, 1)

    @property
    def kind(self):
        """What sort of change this is, which is what the report groups on.

        A new gate outranks a fallen verdict even though it usually causes one.
        A gate is categorical -- a KEV listing, a sanctions entry -- and says
        what to do; a score that drifted down says only to look again.
        """
        if self.new_gates:
            return "gated"
        if self.was == self.now:
            return "moved" if abs(self.drift or 0) >= MOVED else "same"
        # A product that cannot be resolved any more has not become safer or
        # more dangerous; we have simply stopped being able to say.
        if self.now == "VERIFY":
            return "verify"
        if self.now == "NOT ASSESSED":
            return "lost"
        if self.was in ("NOT ASSESSED", "VERIFY"):
            return "gained"
        return "worse" if RANK[self.now] > RANK[self.was] else "better"


def read(path):
    """Load a stored result. Returns (metadata, records)."""
    source = Path(path)
    if not source.exists():
        raise SystemExit(f"{source} does not exist")
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except ValueError as error:
        raise SystemExit(f"{source} is not valid JSON: {error}")
    if not isinstance(document, dict) or "results" not in document:
        raise SystemExit(f"{source} is not a ReTrust result; expected a 'results' key")

    records = [r for r in document["results"] if isinstance(r, dict)]
    if not any(r.get("query") for r in records):
        raise SystemExit(
            f"{source} was written before queries were recorded, so its products "
            "cannot be looked up again. Re-run the original scoring command to "
            "produce a comparable file.")
    return document, records


def compare(previous, current):
    """Pair up two runs by the query that produced each row."""
    by_query = {_key(r): r for r in current}
    changes = []
    for record in previous:
        after = by_query.get(_key(record), {})
        gates = [g for g in (after.get("gates") or [])
                 if g not in (record.get("gates") or [])]
        changes.append(Change(product=after.get("product") or record.get("product", ""),
                              query=record.get("query") or {},
                              before=record, after=after, new_gates=gates))
    # Worst news first: a fresh gate, then a fallen verdict, then the rest.
    order = {"gated": 0, "worse": 1, "lost": 2, "better": 3, "gained": 4,
             "verify": 2, "moved": 5, "same": 6}
    changes.sort(key=lambda c: (order.get(c.kind, 9), -abs(c.drift or 0)))
    return changes


def gate_name(gate):
    """Gates are strings in a batch record and dicts in a score --json one.

    Both shapes are ours and both are already published, so this reads either
    instead of forcing one file format to be re-generated to be comparable.
    """
    return gate.get("gate", "") if isinstance(gate, dict) else str(gate)


def _key(record):
    """What a row was asked for, as a hashable key."""
    query = record.get("query") or {}
    return tuple((query.get(f) or "").strip().lower()
                 for f in ("vendor", "product", "version", "order_number"))


def weights_differ(previous_meta, current_weights):
    """The weights used then against the ones in force now, if they disagree."""
    was = previous_meta.get("weights") or {}
    if not was or not current_weights:
        return None
    changed = {k: (was.get(k), current_weights.get(k)) for k in set(was) | set(current_weights)
               if was.get(k) != current_weights.get(k)}
    return changed or None


HEADINGS = {
    "gated": "NEWLY GATED   a disqualifying fact has appeared",
    "worse": "WORSE         the verdict fell",
    "lost":  "NO LONGER ASSESSABLE   the query stopped resolving",
    "verify": "VERIFY        technical checks are needed before deciding",
    "better": "BETTER        the verdict rose",
    "gained": "NOW ASSESSABLE   the query resolves where it did not",
    "moved": "SCORE MOVED   same verdict, different score",
}


def format_report(changes, previous_meta=None, current_weights=None):
    """The printed summary. Everything that moved, worst first."""
    if not changes:
        return "Nothing to compare: the stored result held no products."

    lines = []
    models = sorted({(c.before.get('vector', '').split('/')[0],
                      c.after.get('vector', '').split('/')[0]) for c in changes
                     if c.before.get('vector') and c.after.get('vector')
                     and c.before['vector'].split('/')[0] != c.after['vector'].split('/')[0]})
    if models:
        lines += ['THE SCORING MODEL CHANGED BETWEEN THESE TWO RUNS',
                  '  ' + ', '.join(f'{old} -> {new}' for old, new in models),
                  '  Score changes cannot be attributed to new vulnerability evidence alone.', '']
    if drifted := weights_differ(previous_meta or {}, current_weights or {}):
        # Said before any finding, because otherwise every score below reads as
        # evidence about the corpus when some of it is evidence about the config.
        lines += ["THE WEIGHTS CHANGED BETWEEN THESE TWO RUNS",
                  "  Scores below are not comparable on the corpus alone:",
                  *[f"    {name:<16} {old} -> {new}" for name, (old, new)
                    in sorted(drifted.items())],
                  "  Re-run the original with today's weights to separate the two.",
                  ""]

    if dates := _provenance(previous_meta or {}):
        lines += [dates, ""]

    for kind, heading in HEADINGS.items():
        if group := [c for c in changes if c.kind == kind]:
            lines.append(heading)
            lines += [f"  {_line(change)}" for change in group]
            lines.append("")

    unchanged = sum(1 for c in changes if c.kind == "same")
    lines.append(f"{len(changes)} product(s) compared, {unchanged} unchanged.")
    return "\n".join(lines)


def _line(change):
    """One product's move, on one line."""
    label = change.product[:44]
    if change.kind == "moved":
        drift = change.drift
        return f"{label:<44}  {change.now:<12} {drift:+.1f}"
    moved = f"{change.was} -> {change.now}"
    tail = f"  ({change.drift:+.1f})" if change.drift is not None else ""
    detail = f"  {gate_name(change.new_gates[0])}" if change.new_gates else ""
    return f"{label:<44}  {moved}{tail}{detail}"


def _provenance(meta):
    """When the stored run's data was captured, if it recorded that."""
    entries = [e for e in (meta.get("provenance") or []) if isinstance(e, dict)]
    advisories = next((e for e in entries if "advisor" in (e.get("source") or "").lower()), None)
    if not advisories:
        return ""
    return (f"Stored run: {advisories.get('detail', '')}"
            f" captured {advisories.get('captured', 'at an unrecorded date')}")
