"""Evidence view: exposure table, evidence table, drawers, ranking, filters.

Contract stubs (WP0). View state lives in the URL (Redesign-plan A7) and is
presentation-only: it is never passed to the scorer.
"""

from dataclasses import dataclass

CSS = ""  # filled in by WP5b

FILTERS = ("all", "unpatched", "network", "kev")
SORTS = ("z", "id", "weakness", "cvss", "epss", "vector", "fix")
DIRS = ("asc", "desc")


@dataclass
class EvidenceView:
    """URL-carried state for the evidence table.

    ev         row filter, one of FILTERS
    sort       sort key, one of SORTS; "" means today's selection and order (D4)
    dir        "asc" or "desc"; only meaningful with an explicit sort
    show_all   True when the URL has show=all (lift the top-N cap)
    base_params  the page's existing query parameters (never the was_* ones),
                 used to build sort/filter links
    anchor     fragment appended to every generated link
    """

    ev: str = "all"
    sort: str = ""
    dir: str = "desc"
    show_all: bool = False
    base_params: dict = None
    anchor: str = "evidence"

    def __post_init__(self):
        if self.base_params is None:
            self.base_params = {}


def rank(rows, view):
    """Return the rows to show, filtered and ordered per `view` (D4 rules)."""
    raise NotImplementedError


def counts(rows):
    """Return per-filter row counts, keyed by FILTERS, for the filter chips."""
    raise NotImplementedError


def exposure_card(exposure, view):
    """Render the exposure summary card as an HTML string."""
    raise NotImplementedError


def evidence_card(rows, view):
    """Render the sortable, filterable evidence table card."""
    raise NotImplementedError


def drawers(rows):
    """Render the per-row detail drawers (popover panels) as an HTML string."""
    raise NotImplementedError
