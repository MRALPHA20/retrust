"""Documented scores must match what the tool actually produces.

This class of bug has recurred three times: a scoring change moves every
number, the code and tests stay green, and the README, manual, guide and
explainer pages keep quoting the old figures -- which reads to a reviewer as
the fix never landing. A reviewer caught it once; a test should catch it next.

Only score-shaped claims are checked, and only against the local index the
docs were generated from. Index COUNTS are deliberately not checked: a hosted
deploy refetches its sources, so live counts legitimately differ from a pinned
snapshot, and that drift is documented rather than wrong.

Skipped when no index is present, so a fresh clone without `setup` still has a
green suite.
"""

import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
INDEX = REPO / "data" / "retrust.db"

# Every file that quotes a verdict and a score together.
DOCS = ["README.md", "docs/manual.md", "docs/user-guide.html",
        "docs/explainers/overview.html", "docs/explainers/scoring.html"]

# "PREFER  ·  77.9/100" and the bare "77.9/100" blocks the terminal prints.
SCORE = re.compile(r"(PREFER|CONDITIONAL|AVOID)\s*·\s*([0-9]{1,3}\.[0-9])/100")

# The products the docs actually use as worked examples, with the query that
# reproduces each. Keyed by the label the docs print.
EXAMPLES = {
    "ABB AC 800M": ("ABB", "AC 800M", None, None),
    "Moxa EDS-405A": ("Moxa", "EDS-405A", None, None),
    "Schneider Electric Modicon M340": ("Schneider Electric", "Modicon M340", None, None),
    "Rockwell ControlLogix": ("Rockwell", "ControlLogix", None, None),
    "Siemens SIMATIC S7-1500 (firmware 3.1.6)": ("Siemens", "SIMATIC S7-1500", "3.1.6", None),
}


@pytest.fixture(scope="module")
def live():
    if not INDEX.exists():
        pytest.skip("no local index; run `retrust setup` to check documented figures")
    from retrust.cli import _assess, _context, _open
    connection, context = _open(str(INDEX)), _context()
    scores = {}
    for label, (vendor, product, version, order) in EXAMPLES.items():
        assessment, _, _ = _assess(connection, vendor, product, version, order,
                                   context=context)
        scores[label] = (assessment.verdict, assessment.score)
    return scores


@pytest.mark.parametrize("relative", DOCS)
def test_documented_scores_match_the_tool(relative, live):
    """Any "<VERDICT> · <score>/100" next to a known product must be current."""
    path = REPO / relative
    if not path.exists():
        pytest.skip(f"{relative} absent")
    text = path.read_text(encoding="utf-8")

    stale = []
    for match in SCORE.finditer(text):
        # Pair the score with the CLOSEST product named before it. Comparing it
        # against every nearby label instead would blame one product for its
        # neighbour's number in a ranked block.
        nearest, distance = None, None
        for label in live:
            start = text.rfind(label, 0, match.start())
            if start == -1:
                continue
            gap = match.start() - start
            if gap <= 90 and (distance is None or gap < distance):
                nearest, distance = label, gap
        if nearest is None:
            continue
        verdict, score = live[nearest]
        if score is None:
            continue
        quoted_verdict, quoted = match.group(1), float(match.group(2))
        if quoted_verdict != verdict or abs(quoted - score) > 0.05:
            stale.append(f"{relative}: {nearest} documented as "
                         f"{quoted_verdict} {quoted}, tool says {verdict} {score}")
    assert not stale, "stale documented figures:\n  " + "\n  ".join(stale)
