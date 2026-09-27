"""Turn a product's findings into SSVC decisions, for the buyer's own context.

A score ranks candidates. It does not tell an asset owner what buying one will
cost them in operational work, and that is the question the week after the
purchase order. SSVC (Stakeholder-Specific Vulnerability Categorization, CERT/CC)
answers it: each vulnerability lands on defer, scheduled, out-of-cycle or
immediate.

The name carries the important part. SSVC is stakeholder-specific by design, and
three of its four decision points describe the buyer's plant, not the product:
how exposed the system is, whether an attacker can automate the attack against
it, and what a compromise would do to people and mission. ReTrust knows none of
those and asks for them rather than assuming. It supplies one point, exploitation,
which is what its data is actually for.

The decision table is CERT/CC's published deployer tree, reproduced from their
repository rather than rewritten, because a tree with three rows subtly wrong
would be worse than no tree.
"""

from dataclasses import dataclass

# CERT/CC SSVC "Deployer Patch Application Priority" decision table v1.0.0.
# Copyright 2026 Carnegie Mellon University, MIT (SEI)-style licence. Taken from
# data/csv/ssvc/deployer_patch_application_priority_1_0_0.csv in CERTCC/SSVC.
# Keyed by (exploitation, exposure, automatable); the tuple runs over human
# impact in the order HUMAN_IMPACT below.
HUMAN_IMPACT = ("low", "medium", "high", "very high")
EXPLOITATION = ("none", "public poc", "active")
EXPOSURE = ("small", "controlled", "open")
AUTOMATABLE = ("no", "yes")

DEPLOYER_TREE = {
    ("none", "small", "no"):
        ('defer', 'defer', 'scheduled', 'scheduled'),
    ("none", "small", "yes"):
        ('defer', 'scheduled', 'scheduled', 'scheduled'),
    ("none", "controlled", "no"):
        ('defer', 'scheduled', 'scheduled', 'scheduled'),
    ("none", "controlled", "yes"):
        ('scheduled', 'scheduled', 'scheduled', 'scheduled'),
    ("none", "open", "no"):
        ('defer', 'scheduled', 'scheduled', 'scheduled'),
    ("none", "open", "yes"):
        ('scheduled', 'scheduled', 'scheduled', 'out-of-cycle'),
    ("public poc", "small", "no"):
        ('defer', 'scheduled', 'scheduled', 'scheduled'),
    ("public poc", "small", "yes"):
        ('scheduled', 'scheduled', 'scheduled', 'scheduled'),
    ("public poc", "controlled", "no"):
        ('defer', 'scheduled', 'scheduled', 'scheduled'),
    ("public poc", "controlled", "yes"):
        ('scheduled', 'scheduled', 'scheduled', 'out-of-cycle'),
    ("public poc", "open", "no"):
        ('scheduled', 'scheduled', 'scheduled', 'out-of-cycle'),
    ("public poc", "open", "yes"):
        ('scheduled', 'scheduled', 'out-of-cycle', 'out-of-cycle'),
    ("active", "small", "no"):
        ('scheduled', 'scheduled', 'out-of-cycle', 'out-of-cycle'),
    ("active", "small", "yes"):
        ('scheduled', 'out-of-cycle', 'out-of-cycle', 'out-of-cycle'),
    ("active", "controlled", "no"):
        ('scheduled', 'scheduled', 'out-of-cycle', 'out-of-cycle'),
    ("active", "controlled", "yes"):
        ('out-of-cycle', 'out-of-cycle', 'out-of-cycle', 'out-of-cycle'),
    ("active", "open", "no"):
        ('scheduled', 'out-of-cycle', 'out-of-cycle', 'immediate'),
    ("active", "open", "yes"):
        ('out-of-cycle', 'out-of-cycle', 'immediate', 'immediate'),}

# Worst first, which is the order a reader needs them in.
PRIORITY = {"immediate": 0, "out-of-cycle": 1, "scheduled": 2, "defer": 3}

ACTIONS = {
    "immediate": "act now; consider taking the system out of service until fixed",
    "out-of-cycle": "act sooner than the next maintenance window",
    "scheduled": "fix during regular scheduled maintenance",
    "defer": "no action needed at this time",
}


@dataclass
class Decision:
    """One finding, placed on the tree."""

    cve: str
    exploitation: str
    outcome: str
    in_kev: bool
    epss: float | None
    cvss: float | None


def decide(exploitation, exposure, automatable, human_impact):
    """Look one combination up in CERT/CC's table."""
    for name, value, allowed in (("exploitation", exploitation, EXPLOITATION),
                                 ("exposure", exposure, EXPOSURE),
                                 ("automatable", automatable, AUTOMATABLE),
                                 ("human impact", human_impact, HUMAN_IMPACT)):
        if value not in allowed:
            raise ValueError(f"{name} must be one of {', '.join(allowed)}, "
                             f"not {value!r}")
    return DEPLOYER_TREE[(exploitation, exposure, automatable)][
        HUMAN_IMPACT.index(human_impact)]


def exploitation_for(finding):
    """The one decision point ReTrust can supply from its own data.

    KEV is evidence of exploitation in the wild, so those findings are "active".
    Everything else is "none", and that is an understatement rather than a
    measurement: ReTrust has no feed of public proof-of-concept code, so it can
    never reach the middle value. Callers are told, because a tree fed "none"
    where "public poc" is true returns an answer that is too relaxed.
    """
    return "active" if finding.in_kev else "none"


# An EPSS above this on a finding SSVC calls "none" is worth saying out loud:
# the model rates exploitation likely while the tree has no evidence to act on.
LIKELY = 0.5


def assess(findings, exposure, automatable, human_impact):
    """Place every finding on the tree. Returns decisions, worst first.

    One decision per CVE, not per finding. A CVE reaches us once for each
    product entry an advisory names, and the same vulnerability listed eight
    times would read as eight things to fix. Where they disagree the worst is
    kept, since that is the one the deployer has to act on.
    """
    worst = {}
    for finding in findings:
        level = exploitation_for(finding)
        decision = Decision(
            cve=finding.cve, exploitation=level,
            outcome=decide(level, exposure, automatable, human_impact),
            in_kev=finding.in_kev, epss=finding.epss, cvss=finding.cvss)
        held = worst.get(finding.cve)
        if held is None or PRIORITY[decision.outcome] < PRIORITY[held.outcome]:
            worst[finding.cve] = decision
    decisions = list(worst.values())
    decisions.sort(key=lambda d: (PRIORITY[d.outcome], -(d.epss or 0),
                                  -(d.cvss or 0), d.cve))
    return decisions


def format_report(product, decisions, exposure, automatable, human_impact,
                  undecided=0):
    """The printed decision list, grouped by outcome."""
    lines = [f"SSVC DEPLOYER DECISIONS   {product}", ""]
    lines += [
        "Your context, as you supplied it:",
        f"  system exposure   {exposure}",
        f"  automatable       {automatable}",
        f"  human impact      {human_impact}",
        "",
        _wrap("These three describe your plant, not the product. ReTrust cannot"
              " know them and does not guess; they are applied to every finding"
              " below because it also cannot judge them per vulnerability."),
        "",
    ]

    if not decisions:
        lines.append("No findings to place on the tree.")
        return "\n".join(lines)

    counts = {}
    for decision in decisions:
        counts[decision.outcome] = counts.get(decision.outcome, 0) + 1
    lines.append("WHAT BUYING THIS COMMITS YOU TO")
    for outcome in sorted(counts, key=lambda o: PRIORITY[o]):
        lines.append(f"  {outcome:<14} {counts[outcome]:>4}   {ACTIONS[outcome]}")
    lines.append("")

    shown = [d for d in decisions if d.outcome != "defer"][:20]
    if shown:
        lines.append(f"{'CVE':<18} {'OUTCOME':<14} {'EXPLOITATION':<13} "
                     f"{'EPSS':>6}  CVSS")
        for d in shown:
            epss = "  --  " if d.epss is None else f"{d.epss:>6.3f}"
            cvss = " -- " if d.cvss is None else f"{d.cvss:>4.1f}"
            lines.append(f"{d.cve:<18} {d.outcome:<14} {d.exploitation:<13} "
                         f"{epss}  {cvss}")
        deferred = counts.get("defer", 0)
        if deferred:
            lines.append(f"\n{deferred} further finding(s) came out as defer and "
                         "are not listed.")

    lines += ["", _wrap(
        "Exploitation is the one decision point ReTrust supplies. A finding in"
        " CISA KEV is 'active'; everything else is 'none', which understates"
        " rather than measures. ReTrust has no feed of public proof-of-concept"
        " code, so it can never reach SSVC's middle value, and a finding with a"
        " public exploit will be placed one step too relaxed.")]
    if likely := [d for d in decisions
                  if d.exploitation == "none" and (d.epss or 0) >= LIKELY]:
        # Naming these is the difference between a caveat and a usable warning.
        lines.append(_wrap(
            f"{len(likely)} of them sit at 'none' with an EPSS of {LIKELY} or"
            f" more, topping out at {max(d.epss for d in likely):.3f}"
            f" ({max(likely, key=lambda d: d.epss).cve}). EPSS is a model, not"
            " evidence of a public exploit, so it cannot move the tree; check"
            " those by hand before trusting their placement."))
    if undecided:
        lines.append(_wrap(
            f"{undecided} finding(s) had a version range this tool could not"
            " parse. They are included above rather than assumed not to apply."))
    lines.append(_wrap(
        "Decision table: CERT/CC SSVC Deployer Patch Application Priority"
        " v1.0.0, Copyright 2026 Carnegie Mellon University."))
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
