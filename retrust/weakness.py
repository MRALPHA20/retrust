"""Group a product's CWEs into the classes a buyer can act on differently.

Every CVE in CISA's OT corpus carries a CWE -- 12,061 of 12,061, across 463
distinct weaknesses -- and until now the tool only checked that the field was
present. That wastes the most decision-relevant thing in the data, because the
class of a flaw changes what a buyer can do about it.

The distinction that matters is not severity, which the score already weighs. It
is whether the operator can do anything. A memory-safety bug is fixed by the
vendor's patch and mitigated meanwhile by keeping the device off the routable
network. A credential compiled into firmware is neither: it cannot be changed,
and it is equally valid on every unit shipped. Those are the same CVSS and a
different purchase.

So these are reported as notes on the assessment rather than folded into the
score. The score answers "how much risk"; this answers "what kind, and what can
you do about it", and averaging the second into the first loses it.
"""

from dataclasses import dataclass

# Grouped by what a buyer would do differently, not by taxonomy. Each carries
# the sentence that makes it actionable, which is the part a CWE number is not.
CLASSES = [
    ("hardcoded credentials",
     ("CWE-798", "CWE-259", "CWE-321", "CWE-1392", "CWE-258", "CWE-1393"),
     "The operator cannot fix this. A credential compiled into firmware cannot "
     "be changed and is the same on every unit shipped, so it is only ever "
     "resolved by the vendor replacing the firmware."),
    ("missing or broken authentication",
     ("CWE-306", "CWE-287", "CWE-288", "CWE-294", "CWE-862", "CWE-863",
      "CWE-284", "CWE-1188"),
     "The device accepts instructions it should have refused. Network "
     "segmentation is the only control the operator holds, and it has to hold "
     "for the life of the asset."),
    ("command or code injection",
     ("CWE-78", "CWE-77", "CWE-94", "CWE-95", "CWE-917", "CWE-88"),
     "A successful attack runs the attacker's code on the device, so the "
     "consequence is not limited to the function that was flawed."),
    ("memory safety",
     ("CWE-787", "CWE-125", "CWE-121", "CWE-122", "CWE-119", "CWE-416",
      "CWE-476", "CWE-190", "CWE-120", "CWE-680", "CWE-401", "CWE-415"),
     "The usual firmware class. A patch fixes each instance; a pattern of them "
     "says something about how the firmware was built."),
    ("path traversal",
     ("CWE-22", "CWE-23", "CWE-36", "CWE-73"),
     "Reads or writes outside the intended directory, which on an embedded "
     "device is often the whole filesystem."),
    ("weak cryptography",
     ("CWE-327", "CWE-326", "CWE-330", "CWE-916", "CWE-311", "CWE-319",
      "CWE-328", "CWE-338"),
     "Traffic or stored secrets are not protected as well as they appear to "
     "be, which tends to outlive the device's patch cycle."),
]

# Classes the operator cannot mitigate by configuration or network design, and
# so the ones worth naming on a purchase decision rather than a patch plan.
UNMITIGABLE = {"hardcoded credentials"}

_LOOKUP = {cwe: name for name, cwes, _ in CLASSES for cwe in cwes}
_WHY = {name: why for name, _, why in CLASSES}


@dataclass
class Class:
    """One weakness class present in a product's findings."""

    name: str
    cves: tuple
    why: str

    @property
    def unmitigable(self):
        return self.name in UNMITIGABLE


def classify(findings):
    """Which classes this product's findings fall into, commonest first.

    A CWE the table does not name is not counted rather than filed under a
    catch-all: 463 distinct weaknesses appear in the corpus and only the ones
    with a distinct buyer response earn a line.
    """
    found = {}
    for finding in findings:
        if name := _LOOKUP.get((finding.cwe or "").strip().upper()):
            found.setdefault(name, set()).add(finding.cve)
    return sorted(
        (Class(name=name, cves=tuple(sorted(cves)), why=_WHY[name])
         for name, cves in found.items()),
        key=lambda c: (not c.unmitigable, -len(c.cves), c.name))


def notes(classes, limit=3):
    """Prose for the assessment, worst-to-act-on first.

    Capped because an assessment that names six classes is telling a buyer to
    read a taxonomy rather than make a decision. The unmitigable ones sort
    first, so the cap never hides the one that cannot be engineered around.
    """
    lines = []
    for weakness in classes[:limit]:
        count = len(weakness.cves)
        lines.append(f"{count} finding(s) are {weakness.name}. {weakness.why}")
    if len(classes) > limit:
        rest = ", ".join(c.name for c in classes[limit:])
        lines.append(f"Also present, not detailed: {rest}.")
    return lines


def summary(classes):
    """One line per class, for the evidence column."""
    return [f"{len(c.cves)} {c.name}" for c in classes]
