"""Tests for the SSVC deployer decisions.

The decision table is CERT/CC's, reproduced rather than rewritten, so the first
test is the one that matters: every row must still agree with the published
table. The rest pin the two honest limits -- that ReTrust supplies one decision
point out of four, and that its "none" is an understatement rather than a
measurement.
"""

from dataclasses import dataclass

import pytest

from retrust import ssvc


@dataclass
class _Finding:
    """Just the fields ssvc reads off a match.Finding."""

    cve: str
    in_kev: bool = False
    epss: float = None
    cvss: float = None
    decided: bool = True


# --- the table is CERT/CC's, not ours ---------------------------------------

def test_the_table_is_complete():
    """72 rows: 3 exploitation x 3 exposure x 2 automatable x 4 human impact."""
    assert len(ssvc.DEPLOYER_TREE) == 18
    assert all(len(v) == 4 for v in ssvc.DEPLOYER_TREE.values())
    assert sum(len(v) for v in ssvc.DEPLOYER_TREE.values()) == 72


def test_every_combination_resolves():
    for exploitation in ssvc.EXPLOITATION:
        for exposure in ssvc.EXPOSURE:
            for automatable in ssvc.AUTOMATABLE:
                for impact in ssvc.HUMAN_IMPACT:
                    assert ssvc.decide(exploitation, exposure, automatable,
                                       impact) in ssvc.PRIORITY


def test_known_corners_match_the_published_tree():
    """Spot checks against CERT/CC's published deployer table."""
    assert ssvc.decide("none", "small", "no", "low") == "defer"
    assert ssvc.decide("active", "open", "yes", "very high") == "immediate"
    assert ssvc.decide("active", "controlled", "no", "medium") == "scheduled"


def test_urgency_never_falls_as_exploitation_rises():
    """More evidence of exploitation cannot make the tree more relaxed."""
    for exposure in ssvc.EXPOSURE:
        for automatable in ssvc.AUTOMATABLE:
            for impact in ssvc.HUMAN_IMPACT:
                outcomes = [ssvc.PRIORITY[ssvc.decide(e, exposure, automatable, impact)]
                            for e in ssvc.EXPLOITATION]
                assert outcomes == sorted(outcomes, reverse=True)


def test_an_invalid_value_is_refused_by_name():
    with pytest.raises(ValueError) as error:
        ssvc.decide("none", "everywhere", "no", "low")
    assert "exposure" in str(error.value)
    with pytest.raises(ValueError) as error:
        ssvc.decide("none", "small", "no", "catastrophic")
    assert "human impact" in str(error.value)


# --- the one decision point ReTrust supplies --------------------------------

def test_kev_is_the_only_thing_that_reaches_active():
    assert ssvc.exploitation_for(_Finding("CVE-1", in_kev=True)) == "active"
    assert ssvc.exploitation_for(_Finding("CVE-2", in_kev=False)) == "none"


def test_a_high_epss_does_not_reach_active():
    """EPSS is a model, not evidence of exploitation. It must not move the tree.

    Treating a probability as observation is how a tool talks itself into
    urgency it has no grounds for.
    """
    assert ssvc.exploitation_for(_Finding("CVE-3", in_kev=False, epss=0.99)) == "none"


def test_public_poc_is_never_inferred():
    """ReTrust has no PoC feed, so the middle value is unreachable, not unused."""
    levels = {ssvc.exploitation_for(_Finding("C", in_kev=k)) for k in (True, False)}
    assert "public poc" not in levels


# --- placing findings -------------------------------------------------------

def test_one_decision_per_cve_not_per_finding():
    """A CVE arrives once per product entry an advisory names.

    The same vulnerability listed eight times would read as eight things to fix.
    """
    findings = [_Finding("CVE-2026-1", in_kev=True) for _ in range(8)]
    assert len(ssvc.assess(findings, "open", "yes", "high")) == 1


def test_the_worst_outcome_wins_a_duplicate():
    findings = [_Finding("CVE-2026-1", in_kev=False),
                _Finding("CVE-2026-1", in_kev=True)]
    decisions = ssvc.assess(findings, "open", "yes", "high")
    assert len(decisions) == 1
    assert decisions[0].exploitation == "active"


def test_decisions_come_back_worst_first():
    decisions = ssvc.assess(
        [_Finding("CVE-A", in_kev=False, epss=0.1),
         _Finding("CVE-B", in_kev=True, epss=0.2)], "open", "yes", "very high")
    assert [d.outcome for d in decisions] == ["immediate", "out-of-cycle"]


def test_epss_orders_within_one_outcome():
    decisions = ssvc.assess(
        [_Finding("CVE-LOW", epss=0.01), _Finding("CVE-HIGH", epss=0.9)],
        "small", "no", "low")
    assert [d.cve for d in decisions] == ["CVE-HIGH", "CVE-LOW"]


def test_no_findings_is_not_an_error():
    assert ssvc.assess([], "open", "yes", "high") == []
    assert "No findings" in ssvc.format_report("P", [], "open", "yes", "high")


# --- the report -------------------------------------------------------------

def _flat(text):
    """Line breaks collapsed: the prose is wrapped to the terminal."""
    return " ".join(text.split())


def test_the_context_is_labelled_as_the_buyer_s_own():
    text = _flat(ssvc.format_report(
        "P", ssvc.assess([_Finding("CVE-1", in_kev=True)], "open", "yes", "high"),
        "open", "yes", "high"))
    assert "as you supplied it" in text
    assert "describe your plant, not the product" in text


def test_the_understatement_is_stated():
    text = _flat(ssvc.format_report(
        "P", ssvc.assess([_Finding("CVE-1")], "open", "yes", "high"),
        "open", "yes", "high"))
    assert "understates rather than measures" in text
    assert "never reach SSVC's middle value" in text


def test_a_likely_but_unevidenced_finding_is_named():
    """A caveat nobody can act on is decoration; this one names the CVE."""
    decisions = ssvc.assess([_Finding("CVE-2024-6387", epss=0.995)],
                            "open", "yes", "high")
    text = _flat(ssvc.format_report("P", decisions, "open", "yes", "high"))
    assert "CVE-2024-6387" in text
    assert "0.995" in text


def test_a_low_epss_finding_raises_no_such_warning():
    decisions = ssvc.assess([_Finding("CVE-1", epss=0.01)], "open", "yes", "high")
    assert "check those by hand" not in _flat(
        ssvc.format_report("P", decisions, "open", "yes", "high"))


def test_undecided_version_ranges_are_declared_in_scope():
    text = _flat(ssvc.format_report(
        "P", ssvc.assess([_Finding("CVE-1")], "open", "yes", "high"),
        "open", "yes", "high", undecided=3))
    assert "3 finding(s) had a version range" in text
    assert "rather than assumed not to apply" in text


def test_the_table_is_attributed():
    """CERT/CC's licence requires the notice travel with the table."""
    text = _flat(ssvc.format_report(
        "P", ssvc.assess([_Finding("CVE-1")], "open", "yes", "high"),
        "open", "yes", "high"))
    assert "Carnegie Mellon University" in text
    assert "CERT/CC SSVC Deployer" in text
