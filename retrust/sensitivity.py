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

from . import score as score_module
from .score import BANDS, DEFAULT_WEIGHTS, PILLARS, assess

PILLAR_KEYS = list(DEFAULT_WEIGHTS)
PILLAR_KEYS_BY_NAME = {spec.name: spec.key for spec in PILLARS}


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
    """A uniform point on the weight simplex.

    Normalising uniform draws does NOT sample the simplex uniformly -- it
    clusters near the centroid and never visits the corners, so extreme
    weightings go untested and every verdict looks steadier than it is. Over
    the four weighted pillars in PILLAR_KEYS, a uniform simplex puts the chance
    of some pillar carrying more than half the weight at 50% (n/2^(n-1) for
    n = 4); clustered draws would almost never produce one, which is exactly
    the case a robustness figure has to be able to visit.

    Network exposure is not one of the four. It is recorded and reported as a
    diagnostic, never weighted, so it never enters this vector and there is
    nothing to renormalize when it is unanswered.

    Normalised exponentials give Dirichlet(1,...,1), which is uniform.
    """
    draws = [rng.expovariate(1.0) for _ in PILLAR_KEYS]
    total = sum(draws) or 1.0
    return {k: d / total for k, d in zip(PILLAR_KEYS, draws)}


def _band(score, bands):
    return next(name for threshold, name in bands if score >= threshold)


def stability(findings, advisories=(), certificates=(), screening_gates=(),
              vendor_key=None, samples=500, seed=7, bands=None,
              network_exposure=None, consequence=None, interface="unknown",
              assessment_type="purchase", remediation="unknown",
              prerequisites="unknown"):
    """Score one product under many weightings and report the spread.

    The owner-supplied facts are held FIXED across the sampling. They are not
    weights and reweighting them would answer a different question: this
    measures how much the verdict depends on the pillar weights, given the
    deployment the operator described.
    """
    bands = bands or BANDS
    rng = random.Random(seed)
    declared = dict(network_exposure=network_exposure, consequence=consequence,
                    interface=interface, assessment_type=assessment_type,
                    prerequisites=prerequisites,
                    remediation=remediation)

    # A gated product is AVOID whatever the weights say; sampling would only
    # manufacture a misleading 100% agreement figure.
    probe = assess("probe", findings, advisories, certificates=certificates,
                   screening_gates=screening_gates, vendor_key=vendor_key,
                   bands=bands, **declared)
    if probe.gates:
        return Stability(samples=0, verdicts={"AVOID": 1}, gated=True,
                         score_min=probe.score or 0.0, score_max=probe.score or 0.0,
                         score_median=probe.score or 0.0)

    # A provisional product has an unresolved exposure factor, so its score is
    # a range and the verdict is VERIFY whatever the weights say. Reweighting
    # would report agreement on a verdict the weights never decided.
    if probe.provisional:
        return Stability(samples=0, verdicts={"VERIFY": 1},
                         score_min=probe.score_min or 0, score_max=probe.score_max or 0,
                         score_median=probe.score or 0)
    # No pillar had evidence, so there is no score to reweigh: sampling would
    # dress "nothing was measured" up as a robustness figure.
    if probe.score is None:
        return Stability(samples=0, verdicts={probe.verdict: 1}, gated=False,
                         score_min=0.0, score_max=0.0, score_median=0.0)

    # Only exponents change. Re-reading vectors, regrouping CVEs and building
    # evidence hundreds of times blocked every other hosted request. Reuse
    # this assessment's unrounded measurements and the scorer's own composite.
    by_name = {p.name: p for p in probe.pillars if p.scored}
    usable = [(spec, by_name[spec.name]) for spec in PILLARS if spec.name in by_name]
    # Findings marked outside_range are the product's record, kept for its
    # patch and vendor pillars; the scorer never caps on them, so neither may this.
    in_range = [finding for finding in findings if not getattr(finding, "outside_range", False)]
    first_party = [finding for finding in in_range if not finding.third_party]
    capped = bool(score_module._unmitigable_cves(first_party or in_range))
    prefer = bands[0][0]
    scores, verdicts = [], {}
    for _ in range(samples):
        weights = _random_weights(rng)
        composite = score_module._composite(usable, weights)
        # Unconditionally, as the scorer does: 79.95-79.99 rounds to 80.0.
        if capped:
            composite = min(composite, prefer - .1)
        sampled_score = round(composite, 1)
        scores.append(sampled_score)
        verdict = _band(sampled_score, bands)
        verdicts[verdict] = verdicts.get(verdict, 0) + 1

    if not scores:                  # --samples 0
        return Stability(samples=0, verdicts={})

    scores.sort()
    return Stability(
        samples=samples, verdicts=verdicts,
        score_min=round(scores[0], 1), score_max=round(scores[-1], 1),
        score_median=round(scores[len(scores) // 2], 1),
    )


def dominance(a_inputs, b_inputs, samples=500, seed=7, a_context=None, b_context=None):
    """How often does candidate A outscore candidate B across weightings?

    Each input is the (findings, advisories, certificates, screening_gates)
    tuple for one candidate. Returns the share of weightings where A wins, so
    0.97 means "A beats B under almost any reasonable weighting" and 0.55 means
    "these two are effectively tied; choose on something else".
    Returns None when material inputs remain unresolved.
    """
    rng = random.Random(seed)
    wins = 0
    for _ in range(samples):
        weights = _random_weights(rng)
        a = assess("a", a_inputs[0], a_inputs[1], weights=weights,
                   certificates=a_inputs[2], screening_gates=a_inputs[3],
                   vendor_key=a_inputs[4] if len(a_inputs) > 4 else None, **(a_context or {}))
        b = assess("b", b_inputs[0], b_inputs[1], weights=weights,
                   certificates=b_inputs[2], screening_gates=b_inputs[3],
                   vendor_key=b_inputs[4] if len(b_inputs) > 4 else None, **(b_context or {}))
        # A gate decides outright, in A's favour only if B is the gated one.
        if bool(a.gates) != bool(b.gates):
            wins += int(not a.gates)
        elif a.provisional or b.provisional or a.score is None or b.score is None:
            return None
        elif a.score > b.score:
            wins += 1
    return wins / samples if samples else 0.0


def contributions(assessment, weights=None):
    """What each pillar costs the composite, largest cost first.

    The composite is a product, not a sum, so a pillar does not own a slice of
    the points -- it owns a factor. The number a reader can act on is the
    headroom: how far the score would rise if this one pillar were perfect and
    nothing else changed. That answers "where do I get the most back?", which
    is the question a buyer actually has, and it sums to nothing in particular
    because the terms interact. `gave` is the factor it multiplied in by.
    """
    weights = weights or DEFAULT_WEIGHTS
    scored = [p for p in assessment.pillars
              if p.name in PILLAR_KEYS_BY_NAME]
    active_keys = [PILLAR_KEYS_BY_NAME[p.name] for p in scored]
    total = sum(weights.get(key, 0) for key in active_keys) or 1.0
    shares = [weights.get(key, 0) / total for key in active_keys]

    def value(pillar):
        return pillar.score if pillar.scored else score_module.MISSING_PILLAR

    def composite(values):
        product = 1.0
        for value_, share in zip(values, shares):
            product *= max(value_, score_module.FLOOR) ** share
        return product

    current = [value(p) for p in scored]
    base = composite(current)

    out = []
    for index, (pillar, share) in enumerate(zip(scored, shares)):
        perfect = list(current)
        perfect[index] = 100.0
        out.append({
            "pillar": pillar.name,
            "score": round(value(pillar), 1),
            "weight": round(share, 3),
            "points": round(max(value(pillar), score_module.FLOOR) ** share, 4),
            "points_lost": round(composite(perfect) - base, 1),
        })
    return sorted(out, key=lambda row: -row["points_lost"])
