"""How much does the verdict actually depend on the weights?

The standard objection to any composite score is that its weights were invented.
It is a fair objection, and the honest answer is not to defend a particular set
of weights but to measure how much they matter.

So: sample many weightings from across the whole simplex, score the product
under each, and report the spread. A product that is AVOID under 99% of all
possible weightings is AVOID in a way no argument about 0.30 versus 0.35 will
change. One that flips between PREFER and CONDITIONAL depending on the weights
is genuinely a judgement call, and the buyer deserves to be told that rather
than handed a false precision.

The same idea applied to two candidates answers the question a procurement team
actually has: *does A beat B robustly, or only under my particular weighting?*

Sampling is seeded, so results are reproducible run to run.
"""

import random
from dataclasses import dataclass, field

from .score import BANDS, DEFAULT_WEIGHTS, assess

PILLAR_KEYS = list(DEFAULT_WEIGHTS)


@dataclass
class Stability:
    """Verdict distribution for one product across many weightings."""

    samples: int
    verdicts: dict = field(default_factory=dict)   # verdict -> count
    score_min: float = 0.0
    score_max: float = 0.0
    score_median: float = 0.0
    gated: bool = False

    @property
    def dominant(self):
        """The verdict that holds under the most weightings."""
        if not self.verdicts:
            return "UNKNOWN"
        return max(self.verdicts.items(), key=lambda kv: kv[1])[0]

    @property
    def agreement(self):
        """Share of weightings giving the dominant verdict, 0-1.

        A gated product is 1.0 by definition: the gate decides it, so every
        weighting gives the same answer.
        """
        if self.gated:
            return 1.0
        return self.verdicts[self.dominant] / self.samples if self.samples else 0.0

    @property
    def robust(self):
        """True when the verdict barely depends on the weighting.

        Compared on the rounded percentage so the flag always agrees with the
        figure shown: 89.67% displays as 90% and must not then be called
        fragile.
        """
        return round(self.agreement * 100) >= 90

    def summary(self):
        if not self.samples and not self.gated:
            return "not sampled"
        if self.gated:
            return "decided by a hard gate, so the weighting is irrelevant"
        if self.robust:
            return (f"{self.dominant} under {self.agreement:.0%} of weightings "
                    f"-- the verdict does not hinge on the weights")
        others = ", ".join(f"{v} {c / self.samples:.0%}"
                           for v, c in sorted(self.verdicts.items(),
                                              key=lambda kv: -kv[1])
                           if v != self.dominant)
        return (f"{self.dominant} under only {self.agreement:.0%} of weightings "
                f"(also {others}) -- this is a judgement call, not a clear result")


def _random_weights(rng):
    """A uniform point on the weight simplex."""
    draws = [rng.random() for _ in PILLAR_KEYS]
    total = sum(draws) or 1.0
    return {k: d / total for k, d in zip(PILLAR_KEYS, draws)}


def _band(score, bands):
    return next(name for threshold, name in bands if score >= threshold)


def stability(findings, advisories=(), certificates=(), screening_gates=(),
              vendor_key=None, samples=500, seed=7, bands=None):
    """Score one product under many weightings and report the spread."""
    bands = bands or BANDS
    rng = random.Random(seed)

    # A gated product is AVOID whatever the weights say; sampling would only
    # manufacture a misleading 100% agreement figure.
    probe = assess("probe", findings, advisories, certificates=certificates,
                   screening_gates=screening_gates, vendor_key=vendor_key)
    if probe.gates:
        return Stability(samples=0, verdicts={"AVOID": 1}, gated=True,
                         score_min=probe.score or 0.0, score_max=probe.score or 0.0,
                         score_median=probe.score or 0.0)

    scores, verdicts = [], {}
    for _ in range(samples):
        weights = _random_weights(rng)
        result = assess("probe", findings, advisories, weights=weights,
                        certificates=certificates, screening_gates=screening_gates,
                        vendor_key=vendor_key)
        scores.append(result.score)
        verdict = _band(result.score, bands)
        verdicts[verdict] = verdicts.get(verdict, 0) + 1

    if not scores:                  # --samples 0
        return Stability(samples=0, verdicts={})

    scores.sort()
    return Stability(
        samples=samples, verdicts=verdicts,
        score_min=round(scores[0], 1), score_max=round(scores[-1], 1),
        score_median=round(scores[len(scores) // 2], 1),
    )


def dominance(a_inputs, b_inputs, samples=500, seed=7):
    """How often does candidate A outscore candidate B across weightings?

    Each input is the (findings, advisories, certificates, screening_gates)
    tuple for one candidate. Returns the share of weightings where A wins, so
    0.97 means "A beats B under almost any reasonable weighting" and 0.55 means
    "these two are effectively tied; choose on something else".
    """
    rng = random.Random(seed)
    wins = 0
    for _ in range(samples):
        weights = _random_weights(rng)
        a = assess("a", a_inputs[0], a_inputs[1], weights=weights,
                   certificates=a_inputs[2], screening_gates=a_inputs[3],
                   vendor_key=a_inputs[4] if len(a_inputs) > 4 else None)
        b = assess("b", b_inputs[0], b_inputs[1], weights=weights,
                   certificates=b_inputs[2], screening_gates=b_inputs[3],
                   vendor_key=b_inputs[4] if len(b_inputs) > 4 else None)
        # A gate decides outright, in A's favour only if B is the gated one.
        if bool(a.gates) != bool(b.gates):
            wins += int(not a.gates)
        elif a.score > b.score:
            wins += 1
    return wins / samples if samples else 0.0


def contributions(assessment, weights=None):
    """Points each pillar contributed to the composite, largest first.

    Turns "why is this 62.5?" into an answer: the weighted points each pillar
    added, and how many it gave up against a perfect 100.
    """
    weights = weights or DEFAULT_WEIGHTS
    total = sum(weights.values()) or 1.0
    scored = [p for p in assessment.pillars if p.name != "Evidence quality"]

    out = []
    for pillar, key in zip(scored, PILLAR_KEYS):
        share = weights.get(key, 0) / total
        out.append({
            "pillar": pillar.name,
            "score": round(pillar.score, 1),
            "weight": round(share, 3),
            "points": round(pillar.score * share, 1),
            "points_lost": round((100 - pillar.score) * share, 1),
        })
    return sorted(out, key=lambda row: -row["points_lost"])
