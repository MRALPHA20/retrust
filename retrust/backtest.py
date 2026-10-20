"""Does the score predict what happened next?

Convergent validity (KEV and EPSS agreeing) shows two sources point the same way
today. It does not show the score is predictive. This module tests the harder
claim: pick a cutoff, score every product on advisories published before it, and
measure against what was disclosed afterwards.

**Read the result as a diagnostic, not a certificate.** Running it on CISA's OT
corpus surfaced a real problem with the obvious outcome variable, and the module
now reports that rather than hiding it:

    Spearman(score, CVEs before cutoff)  -0.05    the score is not just
                                                  re-reading past volume
    Spearman(score, CVEs after  cutoff)  +0.43    but it strongly tracks future
                                                  volume, in the wrong direction
    Spearman(CVEs before, CVEs after)    +0.18    past volume alone predicts
                                                  future volume only weakly

A score that rewards disclosure maturity will correlate with *more* future CVEs,
because vendors who run a real product-security programme publish more of them.
The extreme case in this corpus is a Siemens CPU with 2 CVEs before the cutoff
and 1,029 after: one advisory bundled hundreds of upstream Linux CVEs. Counting
CVEs measures how much a vendor discloses, which is the very thing score.py
refuses to penalise.

So this module does not claim the score is validated or refuted. It shows which
outcome variables are usable and which are confounded, and it reports the
decomposition so a reader can judge for themselves.

Confirmed exploitation would be the right outcome -- a product that later turns
up in CISA's KEV catalogue unambiguously went badly, regardless of disclosure
habits. On this corpus only 29 products across 2 vendors qualify, so the module
reports that sparsity instead of computing a rate from it.
"""

import random
from dataclasses import dataclass, field

from . import score as scoring
from .match import Finding

MIN_HISTORY = 1

# Below this many products, a rate is noise dressed as a number.
MIN_FOR_RATE = 30


@dataclass
class Outcome:
    """One product: what we knew at the cutoff, and what happened next."""

    vendor: str
    product: str
    score: float
    verdict: str
    cves_before: int
    cves_after: int
    kev_after: int


@dataclass
class Result:
    cutoff: str
    cohort: int = 0
    permutations: int = 0
    # The decomposition. Each answers a different question, and reporting only
    # the middle one is how a confounded result gets mistaken for a finding.
    rho_future: float = 0.0      # score vs CVEs disclosed after the cutoff
    rho_past: float = 0.0        # score vs CVEs already known at the cutoff
    rho_persistence: float = 0.0  # past CVE count vs future CVE count
    p_value: float = 1.0
    kev_products: int = 0
    kev_vendors: int = 0
    by_band: dict = field(default_factory=dict)
    outcomes: list = field(default_factory=list)

    @property
    def kev_is_measurable(self):
        """Enough products acquired a KEV entry to compare rates?"""
        return self.kev_products >= MIN_FOR_RATE and self.kev_vendors >= 3


def _spearman(xs, ys):
    """Rank correlation, ties averaged. No SciPy: this is the whole of it."""
    n = len(xs)
    if n < 3:
        return 0.0

    def ranks(values):
        order = sorted(range(n), key=lambda i: values[i])
        out = [0.0] * n
        i = 0
        while i < n:
            j = i
            while j + 1 < n and values[order[j + 1]] == values[order[i]]:
                j += 1
            shared = (i + j) / 2 + 1          # average rank for a tie group
            for k in range(i, j + 1):
                out[order[k]] = shared
            i = j + 1
        return out

    rx, ry = ranks(xs), ranks(ys)
    mx, my = sum(rx) / n, sum(ry) / n
    cov = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    vx = sum((a - mx) ** 2 for a in rx) ** 0.5
    vy = sum((b - my) ** 2 for b in ry) ** 0.5
    return cov / (vx * vy) if vx and vy else 0.0


def _permutation_p(xs, ys, observed, permutations, seed):
    """Two-sided: how often does a shuffled score reach this magnitude?

    Without this a correlation is just a number; with it we can say whether
    chance produces one as large.
    """
    if permutations <= 0:
        return 1.0
    rng = random.Random(seed)
    shuffled = list(xs)
    as_extreme = 0
    for _ in range(permutations):
        rng.shuffle(shuffled)
        if abs(_spearman(shuffled, ys)) >= abs(observed):
            as_extreme += 1
    return (as_extreme + 1) / (permutations + 1)


def _cohort(connection, cutoff, min_history, limit):
    sql = """
        SELECT p.vendor_key, p.name_key,
               MIN(p.vendor) AS vendor, MIN(p.name) AS product
        FROM product p JOIN advisory a ON a.id = p.advisory_id
        WHERE p.vendor_key != '' AND p.name_key != ''
          AND a.released != '' AND a.released < ?
        GROUP BY p.vendor_key, p.name_key
        HAVING COUNT(DISTINCT p.advisory_id) >= ?
    """
    if limit:
        sql += f" LIMIT {int(limit)}"
    return connection.execute(sql, (cutoff, min_history)).fetchall()


def _findings(connection, vendor_key, name_key, cutoff, before=True):
    comparison = "<" if before else ">="
    rows = connection.execute(f"""
        SELECT DISTINCT af.cve, af.cvss, af.cwe, af.remediation, af.vector,
               e.in_kev, e.ransomware, e.kev_added,
               -- EPSS as it stood at the cutoff, not as it stands today.
               (SELECT h.score FROM epss_history h
                 WHERE h.cve = af.cve AND h.day <= ?
                 ORDER BY h.day DESC LIMIT 1) epss
        FROM product p
        JOIN advisory a  ON a.id = p.advisory_id
        JOIN affected af ON af.advisory_id = p.advisory_id
                        AND af.product_id = p.product_id
        LEFT JOIN exploitation e ON e.cve = af.cve
        WHERE p.vendor_key = ? AND p.name_key = ?
          AND a.released != '' AND a.released {comparison} ?
    """, (cutoff, vendor_key, name_key, cutoff)).fetchall()

    # A CVE added to KEV after the cutoff was not known then. Counting it would
    # let the score see the future it is being asked to predict, and 82% of the
    # catalogue was added after the default 2022 cutoff.
    return [Finding(cve=r["cve"], advisory_id="", cvss=r["cvss"], cwe=r["cwe"],
                    epss=r["epss"],
                    in_kev=bool(r["in_kev"]) and (r["kev_added"] or "") < cutoff,
                    ransomware=bool(r["ransomware"]), version_range="",
                    decided=False, remediation=r["remediation"] or "unknown",
                    # Carried so the back-test scores with the severity model the
                    # tool actually ships. Omitting it silently fell back to the
                    # pre-vector formula, which is a test of a score nobody runs.
                    vector=r["vector"])
            for r in rows]


def run(connection, cutoff="2022-01-01", min_history=MIN_HISTORY, limit=None,
        permutations=1000, seed=7):
    """Score at the cutoff, then measure against what came after."""
    result = Result(cutoff=cutoff, permutations=permutations)

    for row in _cohort(connection, cutoff, min_history, limit):
        past = _findings(connection, row["vendor_key"], row["name_key"], cutoff)
        if not past:
            continue

        # Certification and screening are deliberately excluded: both are
        # present-day facts, and using them would leak the future into a score
        # that is supposed to predate the cutoff.
        assessment = scoring.assess(row["product"], past, vendor_key=row["vendor_key"])
        future = _findings(connection, row["vendor_key"], row["name_key"],
                           cutoff, before=False)
        result.outcomes.append(Outcome(
            vendor=row["vendor"], product=row["product"],
            score=assessment.score, verdict=assessment.verdict,
            cves_before=len(past), cves_after=len(future),
            kev_after=sum(1 for f in future if f.in_kev),
        ))

    result.cohort = len(result.outcomes)
    if result.cohort < 3:
        return result

    scores = [o.score for o in result.outcomes]
    before = [o.cves_before for o in result.outcomes]
    after = [o.cves_after for o in result.outcomes]

    result.rho_future = _spearman(scores, after)
    result.rho_past = _spearman(scores, before)
    result.rho_persistence = _spearman(before, after)
    result.p_value = _permutation_p(scores, after, result.rho_future,
                                    permutations, seed)

    acquired = [o for o in result.outcomes if o.kev_after]
    result.kev_products = len(acquired)
    result.kev_vendors = len({o.vendor for o in acquired})

    for band in ("PREFER", "CONDITIONAL", "AVOID"):
        members = [o for o in result.outcomes if o.verdict == band]
        if members:
            counts = sorted(o.cves_after for o in members)
            result.by_band[band] = {
                "products": len(members),
                "median_cves_after": counts[len(counts) // 2],
                "mean_cves_after": round(sum(counts) / len(counts), 2),
                "share_with_any": round(sum(1 for c in counts if c) / len(counts), 3),
                "kev_after": sum(o.kev_after for o in members),
            }
    return result


def interpretation(result):
    """What this run does and does not show. Printed every time."""
    if result.cohort < 3:
        return ["Too few products had history before the cutoff to measure anything."]

    lines = []
    provisional = sum(o.verdict == "VERIFY" for o in result.outcomes)
    if provisional:
        lines.append(f"{provisional}/{result.cohort} assessments need verification. "
                     "Historical advisories do not establish site reachability or OT consequences. "
                     "Correlations use conservative score endpoints, not completed procurement assessments; "
                     "they do not validate RT4 deployment decisions.")
    if result.rho_future > 0.1:
        lines.append(
            f"A higher score went with MORE later CVEs (rho = {result.rho_future:+.3f}), "
            "which is the opposite of what a risk score should do if CVE count "
            "were the right yardstick. It is not: the score rewards vendors who "
            "run a real disclosure programme, and those vendors publish more "
            "CVEs. One Siemens CPU here had 2 CVEs before the cutoff and over a "
            "thousand after, because a single advisory bundled hundreds of "
            "upstream Linux CVEs.")
    elif result.rho_future < -0.1:
        lines.append(
            f"A lower score went with more later CVEs (rho = {result.rho_future:+.3f}), "
            "the direction a predictive score should show. Weigh it against the "
            "confounders below before treating it as validation.")
    else:
        lines.append(
            f"No relationship between score and later CVE count "
            f"(rho = {result.rho_future:+.3f}).")

    lines.append(
        f"The score is not merely re-reading past volume: its correlation with "
        f"CVEs already known at the cutoff is {result.rho_past:+.3f}, while past "
        f"volume predicts future volume at {result.rho_persistence:+.3f}.")

    if result.kev_is_measurable:
        lines.append(
            f"{result.kev_products} products across {result.kev_vendors} vendors "
            "later appeared in CISA's KEV catalogue -- see the KEV column, which "
            "is the outcome that actually means a purchase went badly.")
    else:
        lines.append(
            f"Confirmed exploitation would be the sound outcome to test, but only "
            f"{result.kev_products} product(s) across {result.kev_vendors} vendor(s) "
            "later appeared in KEV. That is too few, and too concentrated, to "
            "support a rate, so no such claim is made here.")

    lines.append(
        "This is observational. Widely deployed equipment attracts more "
        "researchers and so accumulates more CVEs however well it was built, and "
        "a product discontinued after the cutoff collects none and looks clean.")
    return lines


def format_report(result):
    """Human-readable summary -- what `retrust backtest` prints."""
    lines = [
        f"BACK-TEST AT {result.cutoff}",
        f"  products scored on pre-cutoff data only {result.cohort:>9,}",
    ]
    if result.cohort < 3:
        return "\n".join(lines + [""] + [f"  {l}" for l in interpretation(result)])

    lines += [
        "",
        f"  {'correlation':<38}{'rho':>8}",
        f"  {'score vs CVEs after the cutoff':<38}{result.rho_future:>+8.3f}"
        f"   p={result.p_value:.3f} ({result.permutations:,} shuffles)",
        f"  {'score vs CVEs before the cutoff':<38}{result.rho_past:>+8.3f}"
        "   (is the score just re-reading history?)",
        f"  {'CVEs before vs CVEs after':<38}{result.rho_persistence:>+8.3f}"
        "   (how much does volume persist?)",
        "",
        f"  {'verdict at cutoff':<20}{'products':>9}{'median':>8}{'mean':>8}"
        f"{'any later':>11}{'KEV after':>11}",
    ]
    for band in ("PREFER", "CONDITIONAL", "AVOID"):
        if stats := result.by_band.get(band):
            lines.append(
                f"  {band:<20}{stats['products']:>9,}"
                f"{stats['median_cves_after']:>8}{stats['mean_cves_after']:>8}"
                f"{stats['share_with_any']:>10.0%}{stats['kev_after']:>11,}")

    lines.append("")
    for line in interpretation(result):
        lines.append(f"  {line}")
    return "\n".join(lines)


# --- matched cohort --------------------------------------------------------
#
# The pooled correlation above is confounded by the vendor: disclosure practice,
# deployment scale and advisory-bundling habits all vary between manufacturers
# and all move the outcome. Comparing products only against their own vendor's
# other products removes every one of those in a single step, because within a
# stratum they are held constant by construction.
#
# What survives is the question actually worth asking: given two products from
# the same manufacturer, does the one ReTrust scored lower go on to accumulate
# more vulnerabilities?

MIN_STRATUM = 10


@dataclass
class Stratum:
    """One vendor's products, compared only against each other."""

    vendor: str
    products: int
    rho: float
    median_score: float
    total_cves_after: int


@dataclass
class MatchedResult:
    cutoff: str
    strata: list = field(default_factory=list)
    products: int = 0            # products inside usable strata
    usable_strata: int = 0
    dropped_no_variation: int = 0
    rho: float = 0.0             # pooled within-vendor rank correlation
    p_value: float = 1.0
    permutations: int = 0
    negative_strata: int = 0     # strata pointing the predictive way
    positive_strata: int = 0
    rho_without_largest: float = 0.0   # leave-one-out: drop the biggest vendor
    largest_vendor: str = ""

    @property
    def predictive(self):
        return self.rho < 0 and self.p_value < 0.05


def _centered_ranks(values):
    """Ranks within one stratum, centred on the stratum mean.

    Centring is what makes strata poolable: it removes each vendor's level and
    leaves only the ordering of its own products.
    """
    n = len(values)
    order = sorted(range(n), key=lambda i: values[i])
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j + 1 < n and values[order[j + 1]] == values[order[i]]:
            j += 1
        shared = (i + j) / 2 + 1
        for k in range(i, j + 1):
            ranks[order[k]] = shared
        i = j + 1
    mean = sum(ranks) / n
    return [r - mean for r in ranks]


def _pooled_correlation(strata_values):
    """Pearson on pooled centred ranks -- a stratified Spearman."""
    xs, ys = [], []
    for scores, outcomes in strata_values:
        xs += _centered_ranks(scores)
        ys += _centered_ranks(outcomes)
    if len(xs) < 3:
        return 0.0
    sxy = sum(a * b for a, b in zip(xs, ys))
    sxx = sum(a * a for a in xs) ** 0.5
    syy = sum(b * b for b in ys) ** 0.5
    return sxy / (sxx * syy) if sxx and syy else 0.0


def matched_cohort(result, min_stratum=MIN_STRATUM, permutations=1000, seed=7):
    """Re-run the comparison within vendors, holding the vendor constant.

    Takes a completed `run()` result so the scoring work is not repeated.
    """
    matched = MatchedResult(cutoff=result.cutoff, permutations=permutations)

    groups = {}
    for outcome in result.outcomes:
        groups.setdefault(outcome.vendor, []).append(outcome)

    usable = []
    for vendor, members in sorted(groups.items()):
        if len(members) < min_stratum:
            continue
        scores = [o.score for o in members]
        after = [o.cves_after for o in members]
        # A stratum where every product scored the same, or where none had a
        # later CVE, carries no ordering information. Including it would not
        # bias the pooled figure, but it would inflate the apparent sample.
        if len(set(scores)) < 2 or len(set(after)) < 2:
            matched.dropped_no_variation += 1
            continue

        usable.append((scores, after))
        rho = _spearman(scores, after)
        matched.strata.append(Stratum(
            vendor=vendor, products=len(members), rho=round(rho, 3),
            median_score=round(sorted(scores)[len(scores) // 2], 1),
            total_cves_after=sum(after)))
        matched.products += len(members)
        if rho < 0:
            matched.negative_strata += 1
        elif rho > 0:
            matched.positive_strata += 1

    matched.usable_strata = len(usable)
    if not usable:
        return matched

    matched.rho = _pooled_correlation(usable)

    # The null must preserve the stratification, so scores are shuffled inside
    # each vendor rather than across the whole cohort.
    if permutations > 0:
        rng = random.Random(seed)
        as_extreme = 0
        for _ in range(permutations):
            shuffled = []
            for scores, after in usable:
                copy = list(scores)
                rng.shuffle(copy)
                shuffled.append((copy, after))
            if abs(_pooled_correlation(shuffled)) >= abs(matched.rho):
                as_extreme += 1
        matched.p_value = (as_extreme + 1) / (permutations + 1)

    # One vendor can dominate the pool -- Siemens is half of it here. Recompute
    # without the largest stratum so a result that rests on a single
    # manufacturer cannot pass unnoticed.
    if len(usable) > 1:
        largest = max(range(len(usable)), key=lambda i: len(usable[i][0]))
        matched.rho_without_largest = _pooled_correlation(
            [g for i, g in enumerate(usable) if i != largest])
        matched.largest_vendor = max(matched.strata, key=lambda st: st.products).vendor \
            if matched.strata else ""

    matched.strata.sort(key=lambda s: -s.products)
    return matched


def format_matched(matched, top=8):
    """Human-readable summary of the matched-cohort comparison."""
    lines = [
        f"MATCHED COHORT AT {matched.cutoff}  (each product compared only with "
        "others from the same vendor)",
        f"  vendors with enough products            {matched.usable_strata:>9,}",
        f"  products inside those vendors           {matched.products:>9,}",
        f"  vendors dropped, no score or outcome variation {matched.dropped_no_variation:>2,}",
    ]
    if not matched.usable_strata:
        return "\n".join(lines + ["", "  No vendor had enough products to compare within."])

    lines += [
        f"  pooled within-vendor rho                {matched.rho:>+9.3f}"
        f"   p={matched.p_value:.3f} ({matched.permutations:,} shuffles, within vendor)"]
    # With a single usable stratum there is nothing to leave out, and printing
    # +0.000 there reported a computation that never ran.
    if matched.largest_vendor:
        lines.append(
            f"  same, excluding {matched.largest_vendor[:22]:<22}  "
            f"{matched.rho_without_largest:>+9.3f}"
            "   (leave-one-out: does one vendor carry it?)")
    lines += [
        f"  vendors pointing each way               "
        f"{matched.negative_strata} negative / {matched.positive_strata} positive",
        "",
        f"  {'vendor':<34}{'products':>9}{'rho':>8}{'median score':>14}{'CVEs after':>12}",
    ]
    for stratum in matched.strata[:top]:
        lines.append(f"  {stratum.vendor[:33]:<34}{stratum.products:>9,}"
                     f"{stratum.rho:>+8.3f}{stratum.median_score:>14}"
                     f"{stratum.total_cves_after:>12,}")

    lines.append("")
    if matched.predictive:
        lines.append(
            f"  Holding the vendor constant, a lower score went with more later "
            f"CVEs (rho = {matched.rho:+.3f}, p = {matched.p_value:.3f}). Because "
            "every comparison is between products of one manufacturer, the "
            "vendor-level confounders -- disclosure practice, deployment scale, "
            "advisory bundling -- cannot explain it.")
    elif matched.rho > 0.05:
        lines.append(
            f"  Even within a vendor, a higher score went with slightly more later "
            f"CVEs (rho = {matched.rho:+.3f}). The magnitude is the point: holding "
            "the vendor constant collapsed the effect, so most of the pooled "
            "correlation was a vendor effect rather than anything about the "
            "score. What remains is product-level exposure -- a flagship PLC "
            "draws more research than a niche sensor from the same catalogue.")
        lines.append(
            f"  With {matched.products:,} products the p-value is small for an "
            "effect this size; significance here means 'not zero', not 'large "
            "enough to act on'. The split of "
            f"{matched.negative_strata} vendors negative against "
            f"{matched.positive_strata} positive says the direction is not "
            "consistent between manufacturers.")
    else:
        lines.append(
            f"  Holding the vendor constant leaves no relationship "
            f"(rho = {matched.rho:+.3f}, p = {matched.p_value:.3f}). The pooled "
            "correlation was therefore a vendor effect, not a property of the "
            "score.")
    # A pooled figure that one stratum carries is worth flagging on its own.
    if matched.largest_vendor and abs(matched.rho - matched.rho_without_largest) > 0.15:
        direction = ("reverses" if matched.rho * matched.rho_without_largest < 0
                     else "changes materially")
        lines.append(
            f"  Dropping {matched.largest_vendor} {direction} the result "
            f"({matched.rho:+.3f} to {matched.rho_without_largest:+.3f}). That "
            "vendor bundles hundreds of upstream CVEs into single advisories, so "
            "it dominates any count-based outcome. Treat the pooled number as "
            "describing that vendor more than the score.")

    lines.append(
        "  Counting CVEs still measures disclosure volume; this design removes "
        "the vendor-level part of that, not the product-level part.")
    return "\n".join(lines)


# --- cutoff sweep ----------------------------------------------------------
#
# One cutoff is one draw. The claim the sweep tests is the structural one:
# pooled correlation positive (disclosure maturity), collapsing when the
# vendor is held constant, and collapsing further when the dominant vendor is
# dropped. If that pattern held at one cutoff and reversed at another, the
# interpretation this tool prints would be an artifact of where the line was
# drawn -- which is exactly what a reviewer should ask.

SWEEP_CUTOFFS = ("2019-01-01", "2020-01-01", "2021-01-01",
                 "2022-01-01", "2023-01-01")


@dataclass
class SweepRow:
    cutoff: str
    cohort: int
    rho_pooled: float
    p_pooled: float
    rho_within: float
    p_within: float
    rho_without_largest: float
    negative_strata: int
    positive_strata: int
    kev_products: int


def sweep(connection, cutoffs=SWEEP_CUTOFFS, min_history=MIN_HISTORY,
          limit=None, permutations=200, progress=None):
    """Run the whole decomposition at several cutoffs.

    Fewer permutations than a single run's default: the sweep asks about the
    sign and rough size at each cutoff, not a precise p at one.
    """
    rows = []
    for cutoff in cutoffs:
        if progress:
            progress(cutoff)
        result = run(connection, cutoff=cutoff, min_history=min_history,
                     limit=limit, permutations=permutations)
        matched = matched_cohort(result, permutations=permutations)
        rows.append(SweepRow(
            cutoff=cutoff, cohort=result.cohort,
            rho_pooled=round(result.rho_future, 3),
            p_pooled=round(result.p_value, 3),
            rho_within=round(matched.rho, 3),
            p_within=round(matched.p_value, 3),
            rho_without_largest=round(matched.rho_without_largest, 3),
            negative_strata=matched.negative_strata,
            positive_strata=matched.positive_strata,
            kev_products=result.kev_products))
    return rows


def format_sweep(rows):
    """The stability table -- what `retrust backtest --sweep` prints."""
    lines = [
        "CUTOFF SWEEP  (the same decomposition, drawn at different dates)",
        "",
        f"  {'cutoff':<12}{'cohort':>8}{'pooled':>9}{'p':>7}"
        f"{'within':>9}{'p':>7}{'-largest':>10}{'strata -/+':>12}{'KEV after':>11}",
    ]
    for r in rows:
        lines.append(
            f"  {r.cutoff:<12}{r.cohort:>8,}{r.rho_pooled:>+9.3f}{r.p_pooled:>7.3f}"
            f"{r.rho_within:>+9.3f}{r.p_within:>7.3f}{r.rho_without_largest:>+10.3f}"
            f"{f'{r.negative_strata}/{r.positive_strata}':>12}{r.kev_products:>11,}")

    lines.append("")
    pooled_positive = sum(1 for r in rows if r.rho_pooled > 0.1)
    collapsed = sum(1 for r in rows
                    if abs(r.rho_within) < abs(r.rho_pooled)
                    and abs(r.rho_without_largest) <= abs(r.rho_within) + 0.05)
    if pooled_positive == len(rows) and collapsed == len(rows):
        lines.append(
            "  The pattern holds at every cutoff: pooled correlation positive\n"
            "  (disclosure maturity, not risk), collapsing once the vendor is\n"
            "  held constant, and further once the dominant vendor is dropped.\n"
            "  The interpretation printed above does not depend on where the\n"
            "  line was drawn.")
    else:
        lines.append(
            f"  The pattern holds at {min(pooled_positive, collapsed)} of "
            f"{len(rows)} cutoffs. Where it does not, trust the sweep over any "
            "single\n  cutoff -- and treat the interpretation as unsettled.")
    return "\n".join(lines)
