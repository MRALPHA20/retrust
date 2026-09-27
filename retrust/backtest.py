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
        SELECT DISTINCT af.cve, af.cvss, af.cwe, af.remediation,
               e.epss, e.in_kev, e.ransomware
        FROM product p
        JOIN advisory a  ON a.id = p.advisory_id
        JOIN affected af ON af.advisory_id = p.advisory_id
                        AND af.product_id = p.product_id
        LEFT JOIN exploitation e ON e.cve = af.cve
        WHERE p.vendor_key = ? AND p.name_key = ?
          AND a.released != '' AND a.released {comparison} ?
    """, (vendor_key, name_key, cutoff)).fetchall()

    return [Finding(cve=r["cve"], advisory_id="", cvss=r["cvss"], cwe=r["cwe"],
                    epss=r["epss"], in_kev=bool(r["in_kev"]),
                    ransomware=bool(r["ransomware"]), version_range="",
                    decided=False, remediation=r["remediation"] or "unknown")
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
