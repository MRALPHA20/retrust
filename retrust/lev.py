"""Likely Exploited Vulnerabilities, after NIST CSWP 41.

KEV records exploitation somebody observed and reported. EPSS estimates the
chance of exploitation in the next thirty days. Neither answers the question a
buyer is actually asking about a flaw that has been sitting in a product for
four years: has this probably already been exploited at some point?

LEV answers it by composing a CVE's EPSS scores across its whole life. A flaw
that scored 0.05 every month for three years was never urgent on any single day,
and yet is very likely to have been used by now. That is the class of finding
this catches and the other two signals miss.

    LEV(v) = 1 - product over sampled dates of (1 - EPSS(v, d) * weight(d))
    weight(d) = min(30, last_day - d + 1) / 30

The thirty-day spacing is not a tuning choice: EPSS scores the next thirty days,
so sampling more often would multiply overlapping windows and inflate the
result. The final window is weighted down when it is not yet a full thirty days.

Two limits, both from the paper. LEV is a lower bound built on a model, not an
observation, so it never contradicts KEV -- the composite below takes the
highest of the three rather than averaging them. And LEV is meant to augment
KEV, not replace it: a high LEV on a CVE absent from KEV is a prompt to go and
look, not a finding that it was exploited.
"""

from dataclasses import dataclass, field
from datetime import date, timedelta

# EPSS scores the probability of exploitation over the following 30 days, which
# fixes both the sampling interval and the weighting below.
WINDOW = 30

# FIRST published the first EPSS scores on this date; there is nothing earlier
# to compose, so a CVE older than this has a LEV covering only part of its life.
FIRST_EPSS_DAY = date(2021, 4, 14)


@dataclass
class Estimate:
    """One CVE's likelihood of having been exploited already."""

    cve: str
    lev: float
    peak_epss: float
    first_seen: str
    last_seen: str
    observations: int
    in_kev: bool = False
    current_epss: float = None

    @property
    def composite(self):
        """The paper's composite probability: the strongest of the three.

        Taking the maximum rather than an average is deliberate. KEV is an
        observation and LEV is a model; averaging would let the model talk down
        something somebody actually watched happen.
        """
        return max(1.0 if self.in_kev else 0.0, self.lev, self.current_epss or 0.0)

    @property
    def unlisted(self):
        """High likelihood, yet absent from KEV: the case worth a human."""
        return self.lev >= 0.1 and not self.in_kev


def weights(days, last_day=None):
    """The weight of each sampled date, per the paper's equation.

    Every window counts fully except the last, which is scaled by how much of
    its thirty days has actually elapsed. Without that the newest score would be
    credited with a month it has not lived through.
    """
    if not days:
        return []
    last_day = last_day or max(days)
    return [min(WINDOW, (last_day - day).days + 1) / WINDOW for day in days]


def probability(observations, last_day=None):
    """LEV from (date, epss) pairs, which must be about thirty days apart.

    Returns 0.0 for a CVE with no observations rather than raising: a flaw EPSS
    has never scored is one we cannot estimate, and the caller reports that as
    "not estimated" instead of printing a zero that reads like a measurement.
    """
    if not observations:
        return 0.0
    days = [day for day, _ in observations]
    survives = 1.0
    for (_, score), weight in zip(observations, weights(days, last_day)):
        survives *= 1.0 - min(max(score, 0.0), 1.0) * weight
    return 1.0 - survives


def estimate(cve, observations, in_kev=False, current_epss=None, last_day=None):
    """One CVE's estimate, from its EPSS history."""
    ordered = sorted(observations)
    return Estimate(
        cve=cve, lev=probability(ordered, last_day),
        peak_epss=max((score for _, score in ordered), default=0.0),
        first_seen=str(ordered[0][0]) if ordered else "",
        last_seen=str(ordered[-1][0]) if ordered else "",
        observations=len(ordered), in_kev=in_kev, current_epss=current_epss)


def expected_exploited(estimates):
    """Expected number of the set already exploited: the sum of the LEVs.

    The paper's point is that this is an expectation over a set, not a claim
    about any one CVE. Reported alongside how many KEV actually lists, because
    the gap between the two is what LEV exists to show.
    """
    return sum(e.lev for e in estimates)


def sample_days(start=FIRST_EPSS_DAY, end=None, spacing=WINDOW):
    """The dates to fetch, thirty days apart, oldest first."""
    end = end or date.today()
    days, day = [], start
    while day <= end:
        days.append(day)
        day += timedelta(days=spacing)
    return days


def format_report(product, estimates, limit=20, corpus_share=None):
    """The printed estimate, likeliest first."""
    if not estimates:
        return f"LIKELY EXPLOITED   {product}\n\nNo findings to estimate."

    ranked = sorted(estimates, key=lambda e: (-e.lev, -(e.current_epss or 0), e.cve))
    listed = [e for e in ranked if e.observations]
    unscored = len(ranked) - len(listed)

    lines = [f"LIKELY EXPLOITED   {product}", ""]
    in_kev = sum(1 for e in ranked if e.in_kev)
    lines += [
        f"  CVEs estimated                   {len(listed):>8,}",
        f"  expected already exploited       "
        f"{expected_exploited(listed):>8.1f}   (sum of the probabilities)",
        f"  listed in CISA KEV               {in_kev:>8,}   (observed, not estimated)",
        "",
        _wrap("The first figure is an expectation over the set, not a claim about"
              " any single CVE. The gap between it and the KEV count is what LEV"
              " exists to show: flaws that were never urgent on any one day and"
              " have had years of days."),
        "",
    ]

    if listed:
        lines.append(f"{'CVE':<18} {'LEV':>6} {'EPSS NOW':>9} {'PEAK':>6} "
                     f"{'KEV':>4} {'DAYS':>5}  FIRST SCORED")
        for estimate in listed[:limit]:
            current = "   --" if estimate.current_epss is None else f"{estimate.current_epss:>8.3f}"
            lines.append(
                f"{estimate.cve:<18} {estimate.lev:>6.3f} {current:>9} "
                f"{estimate.peak_epss:>6.3f} {'yes' if estimate.in_kev else '  -':>4} "
                f"{estimate.observations:>5}  {estimate.first_seen}")
        if len(listed) > limit:
            lines.append(f"\n{len(listed) - limit} further CVE(s) not listed.")

    if unlisted := [e for e in listed if e.unlisted]:
        share = len(unlisted) / len(listed)
        note = (f"{len(unlisted)} of these ({share:.0%}) reach a LEV of"
                f" {WORTH_LOOKING} or more and are not in KEV.")
        if corpus_share is not None:
            # A count with no base rate reads as alarming whatever it is. Across
            # CISA's OT corpus 57% of CVEs clear this bar, so a product at 60%
            # is ordinary and one at 5% is the interesting case.
            verdict = ("about what the corpus does" if abs(share - corpus_share) < 0.1
                       else "more than usual" if share > corpus_share
                       else "fewer than usual")
            note += (f" Across the whole corpus {corpus_share:.0%} do, so this is"
                     f" {verdict}.")
        lines += ["", _wrap(note + " LEV augments KEV rather than replacing it, so"
                            " treat these as worth going to look at, never as a"
                            " finding that they were exploited.")]
    if unscored:
        lines.append(_wrap(
            f"{unscored} finding(s) have no EPSS history at all and are not"
            " estimated. A CVE published since the last snapshot, or one EPSS"
            " has never scored, gets no LEV rather than a zero."))
    lines.append(_wrap(
        "LEV is cumulative, so it rises with the years a flaw has been watched."
        " A high score on an old CVE is the expected case; read each one against"
        " its own age. `retrust lev --audit` prints those base rates."))
    lines.append(_wrap(
        "Method: NIST CSWP 41, Likely Exploited Vulnerabilities. LEV is a lower"
        " bound derived from a model, so it never overrides KEV; the composite"
        " probability takes the highest of KEV, LEV and current EPSS."))
    return "\n".join(lines)


def _wrap(text, width=76):
    words, line, out = text.split(), "", []
    for word in words:
        if len(line) + len(word) + 1 > width:
            out.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    return "\n".join(out + [line])


# LEV accumulates with exposure, so a CVE's score says as much about how long
# EPSS has watched it as about the flaw. Bands are in 30-day observations.
AGE_BANDS = ((1, 12, "under a year"), (13, 36, "one to three years"),
             (37, 999, "three years or more"))

# The threshold at which a CVE absent from KEV is worth a human going to look.
WORTH_LOOKING = 0.1


def baseline(rows, threshold=WORTH_LOOKING):
    """How much of the corpus clears the threshold, overall and by age.

    Printed beside any per-product count, because "18 of 20" means nothing
    without knowing that 57% of every CVE in the corpus clears the same bar.
    A count that cannot be compared is not a finding.
    """
    values = [r["lev"] for r in rows]
    summary = {"cves": len(values),
               "share": _share(values, threshold),
               "median": _median(values), "bands": {}}
    for low, high, label in AGE_BANDS:
        band = [r["lev"] for r in rows if low <= (r["observations"] or 0) <= high]
        summary["bands"][label] = {"cves": len(band), "share": _share(band, threshold),
                                   "median": _median(band)}
    return summary


def _share(values, threshold):
    return sum(1 for v in values if v >= threshold) / len(values) if values else 0.0


def _median(values):
    if not values:
        return 0.0
    ordered = sorted(values)
    middle = len(ordered) // 2
    return (ordered[middle] if len(ordered) % 2
            else (ordered[middle - 1] + ordered[middle]) / 2)


def format_baseline(summary, listed=None):
    """What `retrust lev --audit` prints: does the threshold discriminate?"""
    lines = [f"LEV ACROSS THE WHOLE CORPUS   ({summary['cves']:,} CVEs with history)",
             "",
             f"  median LEV                       {summary['median']:.3f}",
             f"  share reaching {WORTH_LOOKING}              "
             f"{summary['share']:>7.1%}", ""]
    lines += ["BY HOW LONG EPSS HAS SCORED THEM",
              f"  {'band':<22} {'CVEs':>7} {'median':>8} {'>= ' + str(WORTH_LOOKING):>8}"]
    for label, band in summary["bands"].items():
        lines.append(f"  {label:<22} {band['cves']:>7,} {band['median']:>8.3f} "
                     f"{band['share']:>8.1%}")
    lines += ["", _wrap(
        "LEV is cumulative, so it rises with exposure whatever the flaw is worth."
        " That is the metric working as defined, not a defect, but it means a"
        " high LEV on an old CVE is the expected case rather than a finding."
        " Read any single score against its own age band.")]
    if listed:
        lines += ["", "AGAINST KEV   (the paper's own check: LEV should score KEV high)",
                  f"  median LEV, in KEV       {listed['in_kev_median']:.3f}"
                  f"   ({listed['in_kev']:,} CVEs)",
                  f"  median LEV, not in KEV   {listed['not_in_kev_median']:.3f}",
                  "",
                  _wrap("LEV separating the two is what makes it a signal rather"
                        " than a clock. If the medians matched, it would be"
                        " measuring age alone.")]
    return "\n".join(lines)
