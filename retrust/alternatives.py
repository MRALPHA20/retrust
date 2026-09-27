"""Other products from the same catalogue family, scored the same way.

`score` ends a conversation. A buyer told their chosen PLC is AVOID still has to
buy something, and the next question is always "then what?". This module answers
the part of it ReTrust can answer: which neighbouring products in the same
vendor's family have a better advisory record.

Two limits are structural, not temporary, and the report states both.

ReTrust holds no specifications. The CSAF corpus carries advisories, not I/O
counts, form factors, safety integrity levels or fitness for purpose. Nothing
here knows whether a suggested product will do the job, so these are candidates
for an engineer to evaluate, never a recommendation to substitute.

And a product ReTrust cannot assess is never suggested. Every pillar reads "no
CVEs found" as good news, so ranking on score alone would put the products
nobody has published about at the very top, and absence of advisories is not
evidence of safety. Those are counted and reported, not offered.
"""

from dataclasses import dataclass

from .index import normalize_name, normalize_vendor

# How many of the shown candidates to score. Scoring is the expensive step, so
# the family is narrowed first and only the closest names are assessed.
CONSIDER = 40

# Verdicts good enough to be worth a buyer's time, best first.
RANK = {"PREFER": 0, "CONDITIONAL": 1}


@dataclass
class Option:
    """One candidate, with how it relates to the product asked about."""

    product: str
    verdict: str
    score: float
    shared: str          # the leading name tokens it has in common
    gates: list
    cves: int


def tokens(name):
    """Significant words of a product name, in order.

    One-character words are dropped, as they are everywhere else in this tool:
    they narrow nothing and would make every product in a catalogue a relative.
    """
    return [word for word in (normalize_name(part) for part in (name or "").split())
            if len(word) > 1]


def shared_prefix(subject, candidate):
    """How many leading significant words two product names have in common."""
    count = 0
    for first, second in zip(tokens(subject), tokens(candidate)):
        if first != second:
            break
        count += 1
    return count


def family(connection, vendor, product, limit=CONSIDER):
    """Products from the same vendor sharing at least one leading word.

    The family is the unit a buyer actually substitutes within: a SIMATIC for a
    SIMATIC. Crossing vendors would need equivalence data this tool does not
    have, so it is not offered.
    """
    vendor_key = normalize_vendor(vendor or "")
    subject_tokens = tokens(product)
    if not vendor_key or not subject_tokens:
        return []

    rows = connection.execute(
        "SELECT MIN(name) name, name_key, COUNT(DISTINCT advisory_id) advisories"
        " FROM product WHERE vendor_key = ? AND name_key LIKE ?"
        " GROUP BY name_key", (vendor_key, f"%{subject_tokens[0]}%")).fetchall()

    subject_key = normalize_name(product)
    scored = []
    for row in rows:
        if row["name_key"] == subject_key:
            continue                      # the product asked about is not an option
        if not (depth := shared_prefix(product, row["name"])):
            continue
        scored.append((depth, row["advisories"], row["name"]))
    # Closest family match first, then the most-documented, so the suggestions a
    # buyer sees first are the ones there is most to say about.
    scored.sort(key=lambda entry: (-entry[0], -entry[1], entry[2]))
    return [(name, depth) for depth, _, name in scored[:limit]]


def find(connection, vendor, product, assess, limit=8):
    """Score the family and keep the options worth showing.

    `assess` is the caller's scoring function, taking (vendor, product) and
    returning (assessment, resolution, findings). Passing it in keeps this
    module out of the CLI's import cycle and lets a test score deterministically.

    Returns (options, skipped), where skipped counts the family members that
    could not be assessed at all.
    """
    options, skipped = [], 0
    for name, depth in family(connection, vendor, product):
        assessment, _, _ = assess(vendor, name)
        # An unassessable product would otherwise rank top: every pillar treats
        # "no CVEs found" as good news. Count it, never offer it.
        if assessment.score is None or assessment.verdict not in RANK:
            skipped += 1
            continue
        options.append(Option(
            product=assessment.product, verdict=assessment.verdict,
            score=assessment.score, gates=list(assessment.gates),
            cves=assessment.findings_count,
            shared=" ".join(product.split()[:depth])))

    options.sort(key=lambda option: (RANK[option.verdict], -option.score))
    return options[:limit], skipped


CAVEAT = (
    "ReTrust does not know whether any of these will do the same job. It holds"
    " advisory history, not specifications: no I/O counts, no form factors, no"
    " safety integrity levels, nothing about fitness for purpose. These are"
    " candidates for an engineer to evaluate, not a recommendation to"
    " substitute.")


def format_report(subject, options, skipped, considered=0, version=None):
    """The printed suggestion list, caveat first."""
    lines = [f"ALTERNATIVES TO  {subject.product}"]
    shown = "  --  " if subject.score is None else f"{subject.score:.1f}"
    gate = f"   {subject.gates[0]['gate']}" if subject.gates else ""
    lines += [f"  {subject.verdict}  {shown}{gate}", ""]
    lines += [_wrap(CAVEAT), ""]
    if version:
        # A firmware version decides which CVEs apply. The one the buyer gave
        # belongs to the product they asked about and means nothing on another,
        # so the candidates are scored without it -- which makes the two columns
        # answer slightly different questions. Say so rather than let the gap
        # read as the alternatives being cleaner.
        lines += [_wrap(
            f"These are scored without a firmware version, while the product"
            f" above was scored at {version}. A version decides which CVEs"
            f" apply, so the two are not on equal terms: check each candidate"
            f" again once you know which firmware you would buy."), ""]

    if not options:
        lines.append("No product in this vendor's family scored better and could"
                     " also be assessed.")
        if skipped:
            lines.append(_wrap(
                f"{skipped} family member(s) were skipped because ReTrust could"
                " not assess them. No advisories is not evidence of safety, so"
                " they are not offered as safer."))
        elif not considered:
            lines.append("Nothing in the corpus shares this product's family"
                         " name under this vendor.")
        return "\n".join(lines)

    lines.append(f"{'CANDIDATE':<44}  {'VERDICT':<12} SCORE  CVES  SHARED NAME")
    for option in options:
        lines.append(f"{option.product[:44]:<44}  {option.verdict:<12} "
                     f"{option.score:>5.1f}  {option.cves:>4}  {option.shared}")

    if subject.score is not None:
        better = sum(1 for o in options if o.score > subject.score)
        lines += ["", f"{better} of {len(options)} scored above "
                      f"{subject.product[:40]} ({subject.score:.1f})."]
    if skipped:
        lines.append(_wrap(
            f"{skipped} further family member(s) could not be assessed and are"
            " not listed. Absence of advisories is not evidence of safety."))
    return "\n".join(lines)


def _wrap(text, width=76, indent=""):
    """Wrap prose to the terminal, since the caveat is the longest line here."""
    words, line, out = text.split(), indent, []
    for word in words:
        if len(line) + len(word) + 1 > width:
            out.append(line)
            line = indent + word
        else:
            line = f"{line} {word}".strip() if line.strip() else indent + word
    return "\n".join(out + [line])
