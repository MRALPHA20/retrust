"""Tests for CVSS vector parsing.

The parser is small; what needs pinning is that three generations map onto one
vocabulary without inventing anything. CVSS v2 never asked about user
interaction, so a v2 vector must report that as unknown rather than as "none" --
the difference between a question answered and a question never put.
"""

import pytest

from retrust import cvss

WORMABLE_V3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
PHYSICAL_V3 = "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
WORMABLE_V2 = "AV:N/AC:L/Au:N/C:C/I:C/A:C"


# --- the three generations -------------------------------------------------

def test_v3_reads_every_base_metric():
    v = cvss.parse(WORMABLE_V3)
    assert v.version == "3.1"
    assert v.attack_vector == "network"
    assert v.complexity == "low"
    assert v.privileges == "none"
    assert v.interaction == "none"
    assert v.scope == "unchanged"
    assert v.confidentiality == "high"


def test_v2_maps_authentication_onto_privileges():
    """v2 asks whether an account was needed; v3 asks which. Same question."""
    v = cvss.parse(WORMABLE_V2)
    assert v.version == "2.0"
    assert v.attack_vector == "network"
    assert v.privileges == "none"
    assert v.unauthenticated


def test_v2_never_asked_about_user_interaction():
    """The metric is absent, not "none". Reporting "none" would invent an answer."""
    v = cvss.parse(WORMABLE_V2)
    assert v.interaction is None
    assert v.hands_off is None


def test_v3_did_ask_so_the_answer_is_a_boolean():
    assert cvss.parse(WORMABLE_V3).hands_off is True
    assert cvss.parse(PHYSICAL_V3).hands_off is False


def test_v4_is_parsed_including_its_new_metric():
    v = cvss.parse("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H")
    assert v.version == "4.0"
    assert v.attack_vector == "network"
    assert v.requirements == "present"


# --- the readings a buyer asks for -----------------------------------------

def test_remote_means_reachable_over_a_network():
    assert cvss.parse(WORMABLE_V3).remote
    assert not cvss.parse(PHYSICAL_V3).remote
    assert not cvss.parse("CVSS:3.1/AV:L/AC:L/PR:N/UI:N").remote


def test_wormable_needs_all_three_conditions():
    assert cvss.parse(WORMABLE_V3).wormable
    assert not cvss.parse("CVSS:3.1/AV:N/AC:L/PR:L/UI:N").wormable   # credentials
    assert not cvss.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:R").wormable   # interaction
    assert not cvss.parse("CVSS:3.1/AV:L/AC:L/PR:N/UI:N").wormable   # local only


def test_a_v2_vector_can_still_be_wormable():
    """It never asked about interaction, and absence must not disqualify it."""
    assert cvss.parse(WORMABLE_V2).wormable


def test_automatable_adds_low_complexity_to_wormable():
    assert cvss.parse(WORMABLE_V3).automatable
    assert not cvss.parse("CVSS:3.1/AV:N/AC:H/PR:N/UI:N").automatable


# --- refusing to guess -----------------------------------------------------

@pytest.mark.parametrize("bad", ["", None, "   ", "not a vector", "///", 7, []])
def test_anything_that_is_not_a_vector_returns_none(bad):
    assert cvss.parse(bad) is None


def test_an_unknown_metric_does_not_lose_the_rest():
    """A later CVSS revision adding a field is not a reason to drop the vector."""
    v = cvss.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/XX:Q/ZZ:9")
    assert v is not None and v.remote and v.unauthenticated


def test_an_unknown_value_is_skipped_not_invented():
    v = cvss.parse("CVSS:3.1/AV:Q/AC:L/PR:N")
    assert v.attack_vector is None
    assert v.privileges == "none"


def test_a_metric_the_vector_omits_reads_as_none():
    assert cvss.parse("CVSS:3.1/AV:N").privileges is None
    assert cvss.parse("CVSS:3.1/AV:N").unauthenticated is False


def test_a_private_attribute_still_raises():
    """__getattr__ must not swallow a genuine typo on a dunder."""
    with pytest.raises(AttributeError):
        cvss.parse(WORMABLE_V3)._nope


# --- summarising a product -------------------------------------------------

def test_summarise_counts_each_reading():
    counts = cvss.summarise([WORMABLE_V3, PHYSICAL_V3, WORMABLE_V2, "rubbish"])
    assert counts["parsed"] == 3            # the rubbish is not counted as parsed
    assert counts["remote"] == 2
    assert counts["wormable"] == 2
    assert counts["physical"] == 1


def test_summarise_counts_unknown_interaction_apart():
    """So a v2-only corpus cannot report "0 requiring interaction"."""
    assert cvss.summarise([WORMABLE_V2])["interaction_unknown"] == 1
    assert cvss.summarise([WORMABLE_V3])["interaction_unknown"] == 0


def test_summarise_of_nothing_is_all_zeroes():
    counts = cvss.summarise([])
    assert counts["parsed"] == 0 and counts["remote"] == 0


# --- the severity pillar reads it ------------------------------------------

def _finding(cvss_score, vector):
    from retrust.match import Finding
    return Finding(cve="CVE-2026-1", advisory_id="A", cvss=cvss_score, cwe=None,
                   epss=None, in_kev=False, ransomware=False, version_range="",
                   decided=True, vector=vector)


def test_reachable_flaws_score_worse_than_unreachable_ones():
    """The point of reading the vector: two 9.8s are not the same purchase."""
    from retrust import score
    reachable = score._severity([_finding(9.8, WORMABLE_V3)])
    locked_away = score._severity([_finding(9.8, PHYSICAL_V3)])
    assert reachable.score < locked_away.score


def test_a_missing_vector_says_so_rather_than_scoring_zero_reach():
    """Silently weighing it as unreachable is a claim about the product."""
    from retrust import score
    pillar = score._severity([_finding(9.8, None)])
    assert any("not weighed" in line for line in pillar.evidence)


def test_physical_access_is_called_out():
    from retrust import score
    pillar = score._severity([_finding(9.8, PHYSICAL_V3)])
    assert any("physical access" in line for line in pillar.evidence)


# --- the SSVC suggestion ---------------------------------------------------

def test_automatable_is_suggested_with_its_working():
    from retrust import ssvc
    answer, why = ssvc.suggest_automatable([_finding(9.8, WORMABLE_V3)])
    assert answer == "yes"
    assert "network-reachable" in why


def test_automatable_says_no_when_nothing_qualifies():
    from retrust import ssvc
    answer, why = ssvc.suggest_automatable([_finding(4.0, PHYSICAL_V3)])
    assert answer == "no"
    assert "none of 1" in why


def test_without_vectors_it_refuses_to_suggest():
    from retrust import ssvc
    answer, why = ssvc.suggest_automatable([_finding(9.8, None)])
    assert answer is None
    assert "cannot be suggested" in why
