"""Tests for version-range parsing.

Each case below is a real string taken from the CISA OT advisory corpus, so the
suite doubles as documentation of the grammars vendors actually publish.
"""

import pytest

from retrust.version import affects, is_determinate, parse_version

# (affected range, firmware version, expected answer)
CASES = [
    # VERS spec -- about 46% of the corpus
    ("vers:intdot/<4.3.8", "4.3.7", True),
    ("vers:intdot/<4.3.8", "4.3.8", False),
    ("vers:intdot/<4.3.8", "4.3.9", False),
    ("vers:all/*", "1.2.3", True),
    ("vers:intdot/>=3.0|<3.0.2", "3.0.1", True),
    ("vers:intdot/>=3.0|<3.0.2", "3.0.2", False),
    ("vers:intdot/>=3.0|<3.0.2", "2.9", False),

    # Plain comparators
    ("<V2.9.7", "V2.9.6", True),
    ("<V2.9.7", "V2.9.7", False),
    ("4.5", "4.5", True),
    ("4.5", "4.6", False),

    # Bounded intervals, with and without a separator
    (">=V3.1.0|<V3.1.2", "V3.1.1", True),
    (">=V3.1.0|<V3.1.2", "V3.1.2", False),
    (">=V3.1.0|<V3.1.2", "V3.0.9", False),
    (">=V6.2<V7.1", "V6.5", True),
    (">=V6.2<V7.1", "V7.5", False),

    # Service packs and updates sort after the base version
    ("<V17_Update_5", "V17_Update_4", True),
    ("<V17_Update_5", "V17_Update_6", False),
    ("<V17_Update_5", "V17", True),

    # A component name before the operator or the number
    ("NMC2 <= 6.9.6", "6.9.5", True),
    ("NMC2 <= 6.9.6", "6.9.7", False),
    ("<firmware_SP473", "SP472", True),
    ("<firmware_SP473", "SP474", False),
    ("<=SW_v4.4.1.19", "4.4.1.18", True),
    ("<=SW_v4.4.1.19", "4.4.2", False),
    ("vers:generic/<SV3.70", "SV3.69", True),
    ("vers:generic/<SV3.70", "SV3.71", False),

    # Build numbers in parentheses become another component
    ("< 02.07.07(10)", "02.07.07.9", True),
    ("<= 15.2(6)E0a", "15.2.5", True),
    ("<= 15.2(6)E0a", "15.3", False),
    ("<= 3.4.4 Build 16102416", "3.4.3", True),

    # Shorter and longer versions compare as if zero-padded
    ("<V4.5", "4.5.0", False),
    ("<V4.5.1", "4.5", True),
]

# Ranges nothing version-based can settle. These must abstain, never guess:
# answering "not affected" here would quietly understate risk.
MUST_ABSTAIN = [
    "<= with_the_first_5_digits_of_serial_number_2408",
    '<=The_first_5_digits_of_serial_No._"26061"',
    "<BIOS_V1.0.212N",
    "<with_U-Boot_V2016.05RS09",
    "distributed  < april 1, 2018",
    "<=LJ",
    "Rev._1",
]


@pytest.mark.parametrize("range_text,version,expected", CASES)
def test_affects(range_text, version, expected):
    assert affects(range_text, version) is expected


@pytest.mark.parametrize("range_text", MUST_ABSTAIN)
def test_abstains_when_undecidable(range_text):
    assert affects(range_text, "1.0") is None


def test_unknown_never_reads_as_safe():
    """None must be distinguishable from False by callers."""
    assert affects("<=LJ", "1.0") is not False


def test_parse_version_rejects_non_versions():
    for text in ["", None, "Rev", "unknown", "TBD"]:
        assert parse_version(text) is None


def test_version_ordering():
    assert parse_version("4.5") < parse_version("4.5.1")
    assert parse_version("V17") < parse_version("V17 Update 5")
    assert parse_version("2.9.7") > parse_version("2.9.6")


def test_is_determinate_matches_affects():
    """Anything we call determinate must actually produce an answer."""
    for range_text, version, _ in CASES:
        assert is_determinate(range_text)
        assert affects(range_text, version) is not None
    for range_text in MUST_ABSTAIN:
        assert not is_determinate(range_text)


@pytest.mark.parametrize("range_text,version,expected", [
    # A label welded on with a separator is not version information.
    ("MX-V4.0.1.15", "MX-V4.0.1.15", True),
    ("MX-V4.0.1.15", "4.0.1.15", True),      # the buyer needn't retype the label
    ("MX-V4.0.1.15", "4.0.2.23", False),
    ("<ver._2.3.9.27", "2.3.9.26", True),
    ("<=Ver.2.60", "2.61", False),
    ("<ROS_v3.11.5", "ROS_v3.11.4", True),
    # Chained labels, and Upd as a spelling of Update.
    ("<WinCC_TIA_Portal_V13_SP1_Upd2", "WinCC_TIA_Portal_V13_SP1_Upd1", True),
    ("<WinCC_TIA_Portal_V13_SP1_Upd2", "V13 SP1 Update 2", False),
    # A fully parenthesised version, and a parenthesised build suffix.
    ("<=(R4.10)", "R4.02", True),
    ("<=(R4.10)", "R4.11", False),
    ("< 3.6 (Build 170215)", "3.6 (Build 170214)", True),
    # A wildcard separated by a space instead of a dot.
    ("1.2 *", "1.2.5", True),
    ("1.2 *", "1.3", False),
    # SEL firmware idents order correctly within one model line.
    (">=SEL-3530-R100-V0-Z001001-D20090915|<=SEL-3530-R107-V0-Z001001-D20120712",
     "SEL-3530-R103-V0-Z001001-D20110101", True),
    (">=SEL-3530-R100-V0-Z001001-D20090915|<=SEL-3530-R107-V0-Z001001-D20120712",
     "SEL-3530-R108-V0-Z001001-D20130101", False),
])
def test_labelled_versions_decide(range_text, version, expected):
    """Vendor labels welded onto versions must not block the decision."""
    assert affects(range_text, version) is expected


def test_a_board_revision_still_abstains():
    """"Rev. 1" is hardware. The label stripper must not read it as firmware."""
    assert affects("Rev._1", "1.0") is None
    assert affects("Revision 3", "3") is None
    # ...but a rev-suffixed firmware pin is still a version, not a board.
    assert affects("MX-V4.0.2.33.r2", "MX-V4.0.2.33.r2") is True


def test_repeated_firmware_comparisons_reuse_work_without_mixing_results(monkeypatch):
    from retrust import version
    original = version._normalize
    calls = []
    def measured(text):
        calls.append(text)
        return original(text)
    version.affects.cache_clear()
    monkeypatch.setattr(version, '_normalize', measured)
    try:
        for _ in range(5):
            assert version.affects('<2.0', '1.0') is True
            assert version.affects('<2.0', '3.0') is False
            assert version.affects('Rev._1', '1.0') is None
        assert len(calls) == 3
    finally:
        version.affects.cache_clear()


def test_normalized_range_cache_is_immutable_and_shared_across_firmware():
    from retrust import version
    version.affects.cache_clear()
    version._normalize.cache_clear()
    assert version.affects('>=1.0|<2.0', '1.5') is True
    assert version.affects('>=1.0|<2.0', '2.5') is False
    info = version._normalize.cache_info()
    assert info.misses == 1 and info.hits >= 1
    kind, constraints = version._normalize('>=1.0|<2.0')
    assert kind == 'constraints' and isinstance(constraints, tuple)
    version.affects.cache_clear()
    version._normalize.cache_clear()
