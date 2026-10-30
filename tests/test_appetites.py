"""Tests for the shipped risk-appetite appetites.

A profile is a shipped opinion, so the tests pin what makes an opinion safe to
ship: every profile speaks exactly the pillar vocabulary config.load validates,
its numbers stay legible (summing to 1.0, bands in order), its template
survives the config.load round-trip, and the framing that keeps it honest --
weights change, evidence and gates do not -- is actually printed, not merely
intended.
"""

import json

import pytest

from retrust import appetites, config
from retrust.score import BANDS, DEFAULT_WEIGHTS


# --- the numbers themselves --------------------------------------------------

def test_every_profile_uses_exactly_the_default_pillar_keys():
    """A stray key would be rejected by config.load; a missing one would be
    silently filled from the defaults -- both defeat a *complete* opinion."""
    for profile in appetites.APPETITES:
        assert set(profile.weights) == set(DEFAULT_WEIGHTS), profile.name


def test_every_profile_sums_to_one_for_legibility():
    for profile in appetites.APPETITES:
        assert sum(profile.weights.values()) == pytest.approx(1.0), profile.name


def test_the_default_profile_is_the_shipped_numbers_verbatim():
    default = appetites.get("default")
    assert default.weights == DEFAULT_WEIGHTS
    assert default.bands == {"prefer": BANDS[0][0], "conditional": BANDS[1][0]}


def test_bands_are_ordered_prefer_above_conditional_above_zero():
    """config.load would refuse anything else; shipping it would be worse."""
    for profile in appetites.APPETITES:
        assert profile.bands["prefer"] > profile.bands["conditional"] > 0, \
            profile.name


def test_safety_critical_is_stricter_than_the_default_on_both_bands():
    strict, default = appetites.get("safety-critical"), appetites.get("default")
    assert strict.bands["prefer"] > default.bands["prefer"]
    assert strict.bands["conditional"] > default.bands["conditional"]


def test_exposed_puts_exposure_first_and_patchability_second():
    ranked = sorted(appetites.get("exposed").weights.items(),
                    key=lambda kv: -kv[1])
    assert [key for key, _ in ranked[:2]] == ["exposure", "patchability"]


def test_isolated_cell_trades_exposure_for_patchability_and_practice():
    cell = appetites.get("isolated-cell")
    assert cell.weights["exposure"] < DEFAULT_WEIGHTS["exposure"]
    assert cell.weights["patchability"] > DEFAULT_WEIGHTS["patchability"]
    assert cell.weights["vendor_practice"] > DEFAULT_WEIGHTS["vendor_practice"]
    # Bands unchanged: an air gap changes likelihood, not how strict a
    # procurement policy is.
    assert cell.bands == appetites.get("default").bands


# --- lookup ------------------------------------------------------------------

def test_names_lists_the_profiles_in_shipped_order():
    assert appetites.names() == ["default", "safety-critical", "exposed",
                                "isolated-cell"]


def test_get_of_an_unknown_name_is_none_and_template_refuses_it():
    assert appetites.get("nope") is None
    with pytest.raises(SystemExit) as refusal:
        appetites.template("nope")
    # The refusal names the valid choices, so the error is also the help.
    assert "default" in str(refusal.value)


# --- the config-file template ------------------------------------------------

def test_every_template_survives_the_config_load_round_trip(tmp_path):
    for profile in appetites.APPETITES:
        path = tmp_path / f"{profile.name}.json"
        path.write_text(json.dumps(appetites.template(profile.name)),
                        encoding="utf-8")
        weights, bands, source = config.load(str(path))
        assert weights == pytest.approx(profile.weights), profile.name
        assert bands[0] == (profile.bands["prefer"], "PREFER")
        assert bands[1] == (profile.bands["conditional"], "CONDITIONAL")
        assert bands[2] == (0, "AVOID")
        assert source == str(path)


def test_the_template_matches_config_template_shape_and_carries_the_why():
    shipped = config.template()
    for profile in appetites.APPETITES:
        document = appetites.template(profile.name)
        assert set(document) == set(shipped), profile.name
        assert profile.why in document["_comment"]
        # The standard editing note still rides along, so a buyer who starts
        # from a profile still learns the file is theirs to edit.
        assert "normalised" in document["_comment"]


def test_the_default_template_differs_from_config_template_only_in_comment():
    plain, named = config.template(), appetites.template("default")
    assert named["weights"] == plain["weights"]
    assert named["bands"] == plain["bands"]


# --- the printed listing -----------------------------------------------------

def test_describe_stays_ascii_and_inside_eighty_columns():
    text = appetites.describe()
    assert text.isascii()
    assert all(len(line) <= 80 for line in text.splitlines())


def test_describe_prints_each_profile_with_its_bands_and_reasoning():
    flat = " ".join(appetites.describe().split())
    for profile in appetites.APPETITES:
        assert profile.name in flat
        assert f"PREFER >= {profile.bands['prefer']:g}" in flat
        # Flattened on both sides: the why is line-wrapped in the listing.
        assert " ".join(profile.why.split()) in flat, profile.name


def test_describe_orders_each_weight_summary_heaviest_first():
    weight_lines = [line for line in appetites.describe().splitlines()
                    if line.strip().startswith("weights")]
    assert len(weight_lines) == len(appetites.APPETITES)
    for profile, line in zip(appetites.APPETITES, weight_lines):
        heaviest = max(sorted(profile.weights), key=profile.weights.get)
        assert line.split()[1] == heaviest, profile.name


def test_describe_states_that_gates_ignore_the_profile():
    """The honest-framing rule must be printed, not just intended: a profile
    moves weights, and no appetite quiets a disqualifying fact."""
    flat = " ".join(appetites.describe().split())
    assert "never the evidence" in flat
    assert "fire identically" in flat


def test_the_listing_prints_the_same_twice():
    assert appetites.describe() == appetites.describe()


def test_the_strict_appetite_raises_the_weights_its_why_claims():
    """The why says exposure weighs more; the numbers must."""
    from retrust.score import DEFAULT_WEIGHTS
    strict = appetites.get("safety-critical")
    assert strict.weights["exposure"] > DEFAULT_WEIGHTS["exposure"]
    # and it buys that from the softer, proxy pillars
    assert (strict.weights["vendor_practice"] + strict.weights["certification"]
            < DEFAULT_WEIGHTS["vendor_practice"] + DEFAULT_WEIGHTS["certification"])


def test_a_named_template_differs_from_the_plain_one_in_its_comment():
    named = appetites.template("default")
    plain = config.template()
    assert named["_comment"] != plain["_comment"]
    assert set(named) == set(plain)


def test_shipped_numbers_cannot_be_tuned_in_place():
    import pytest
    with pytest.raises(TypeError):
        appetites.get("default").weights["exploitation"] = 0.9
    with pytest.raises(TypeError):
        appetites.get("default").bands["prefer"] = 1
