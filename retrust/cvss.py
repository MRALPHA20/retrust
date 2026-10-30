"""Read the CVSS vector, not just the number it produces.

A base score collapses eight decisions into one figure, and the decisions are
what a buyer needs. CVSS 9.8 reached over the network with no credentials is a
different purchase from CVSS 9.8 that needs physical access to a device in a
locked cabinet, and the score cannot tell you which you are looking at.

Every score block in CISA's OT corpus carries its vector: 13,406 CVSS v3 and 697
v2, none missing. That is better coverage than any other optional field in the
data, which is what makes reading it worth the code.

Three generations are parsed because CSAF carries all three and CISA is still
publishing v3. They disagree on spelling more than on meaning -- v2 asks about
authentication where v3 asks about privileges, and only v3 onwards asks about
user interaction -- so each is mapped onto one vocabulary and the gaps are left
as None rather than guessed.
"""

from dataclasses import dataclass, field

# One vocabulary, three spellings. Values are the readings this tool uses; a
# metric a generation does not carry stays absent rather than defaulting, since
# "CVSS v2 never asked" and "nobody had to interact" are different facts.
_V3 = {
    "AV": ("attack_vector", {"N": "network", "A": "adjacent", "L": "local",
                             "P": "physical"}),
    "AC": ("complexity", {"L": "low", "H": "high"}),
    "PR": ("privileges", {"N": "none", "L": "low", "H": "high"}),
    "UI": ("interaction", {"N": "none", "R": "required"}),
    "S": ("scope", {"U": "unchanged", "C": "changed"}),
    "C": ("confidentiality", {"H": "high", "L": "low", "N": "none"}),
    "I": ("integrity", {"H": "high", "L": "low", "N": "none"}),
    "A": ("availability", {"H": "high", "L": "low", "N": "none"}),
}
_V2 = {
    "AV": ("attack_vector", {"N": "network", "A": "adjacent", "L": "local"}),
    "AC": ("complexity", {"L": "low", "M": "medium", "H": "high"}),
    # v2's Au is the nearest thing it has to v3's PR: "none" means the attacker
    # needed no account, which is the question a buyer is actually asking.
    "Au": ("privileges", {"N": "none", "S": "low", "M": "high"}),
    "C": ("confidentiality", {"C": "high", "P": "low", "N": "none"}),
    "I": ("integrity", {"C": "high", "P": "low", "N": "none"}),
    "A": ("availability", {"C": "high", "P": "low", "N": "none"}),
}
# v4 keeps v3's spelling for the base metrics, adds Attack Requirements, and
# splits User Interaction three ways. P and A were unmapped at first, so a v4
# flaw that needs a user actively tricked read as needing nobody at all.
_V4 = dict(_V3,
           AT=("requirements", {"N": "none", "P": "present"}),
           UI=("interaction", {"N": "none", "P": "passive", "A": "required"}))

REMOTE = "network"


@dataclass
class Vector:
    """One parsed CVSS vector, in a vocabulary shared across generations."""

    version: str
    raw: str
    metrics: dict = field(default_factory=dict)

    def __getattr__(self, name):
        # Metrics read as attributes, and one a generation never carried reads
        # as None rather than raising -- the caller's question was still valid.
        if name.startswith("_"):
            raise AttributeError(name)
        return self.metrics.get(name)

    @property
    def remote(self):
        """Reachable over a network, which is the first thing a buyer asks."""
        return self.metrics.get("attack_vector") == REMOTE

    @property
    def unauthenticated(self):
        return self.metrics.get("privileges") == "none"

    @property
    def hands_off(self):
        """No user had to be tricked into anything.

        None for v2, which never asked. Absence is reported, never read as
        "no". v4's passive interaction counts as hands-off: the user is merely
        present, not deceived into acting.
        """
        interaction = self.metrics.get("interaction")
        return None if interaction is None else interaction in ("none", "passive")

    @property
    def wormable(self):
        """Network-reachable, unauthenticated, and needing nobody's help.

        The combination that turns a flaw into something that spreads on its
        own, and the one worth counting separately in a plant.
        """
        return self.remote and self.unauthenticated and self.hands_off is not False

    @property
    def automatable(self):
        """A proxy for SSVC's Automatable, and labelled as one.

        SSVC asks whether an attacker can automate reconnaissance through
        exploitation. That is a judgement about the flaw, not a function of
        CVSS, and the standard does not define it this way. Low complexity on
        top of the wormable combination is the closest the vector gets, so this
        is offered as a suggestion for a human to accept, never as the answer.
        """
        return self.wormable and self.metrics.get("complexity") == "low"


def parse(vector):
    """Parse a CVSS v2, v3.x or v4.0 vector. Returns None if it is not one.

    Deliberately total: a malformed vector in one advisory must not stop an
    ingest of four thousand. Unknown metrics are skipped rather than rejected,
    because a later CVSS revision adding one is not a reason to lose the rest.
    """
    if not vector or not isinstance(vector, str):
        return None
    parts = [p for p in vector.strip().split("/") if p]
    if not parts:
        return None

    version, table = "2.0", _V2
    if parts[0].upper().startswith("CVSS:"):
        version = parts[0].split(":", 1)[1].strip()
        table = _V4 if version.startswith("4") else _V3
        parts = parts[1:]

    metrics = {}
    for part in parts:
        key, _, value = part.partition(":")
        if (entry := table.get(key.strip())) and (name := entry[1].get(value.strip().upper())):
            metrics[entry[0]] = name
    if not metrics:
        return None
    return Vector(version=version, raw=vector.strip(), metrics=metrics)


def summarise(vectors):
    """Counts across a product's findings, for the evidence line.

    None-valued readings are counted apart from false ones, so a corpus of CVSS
    v2 does not report "0 requiring interaction" when the question was never
    asked.
    """
    parsed = [v for v in (parse(v) for v in vectors) if v]
    return {
        "parsed": len(parsed),
        "remote": sum(1 for v in parsed if v.remote),
        "unauthenticated": sum(1 for v in parsed if v.unauthenticated),
        "wormable": sum(1 for v in parsed if v.wormable),
        "automatable": sum(1 for v in parsed if v.automatable),
        "physical": sum(1 for v in parsed if v.attack_vector == "physical"),
        "interaction_unknown": sum(1 for v in parsed if v.hands_off is None),
    }
