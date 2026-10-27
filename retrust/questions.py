"""The buyer's next concrete act: the security annex of the RFQ.

A verdict ends the assessment and starts a negotiation. What the buyer sends
next is a request for quotation, and its security annex is where the evidence
earns its keep: a vendor asked "is the product secure?" can answer with
marketing, while a vendor asked which firmware version fixes a named CVE and
when it shipped must answer with a fact or a visible refusal. This module
writes that annex from the findings ReTrust already holds.

Two refusals shape it. No question is generated that the evidence does not
support -- padding teaches the vendor that the whole list is boilerplate, so
every question cites the CVEs, advisories or facts that prompted it. And an
empty advisory history is never dressed up as reassurance: it yields the
standing diligence questions plus one asking the vendor to account for the
silence, because absence of data is not evidence of safety."""

import textwrap
from dataclasses import dataclass, field

from . import cvss
# The EPSS above which a mitigation-only remedy is worth pressing on: the
# "worth a human going to look" threshold, imported so the two cannot drift.
from .lev import WORTH_LOOKING as PRESSING_EPSS

# A vendor must answer this line by line, so the questions and the ids cited
# per question are both capped: an annex nobody reads to the end asks nothing.
MAX_QUESTIONS = 12
MAX_CITED = 6

CLOSING = (
    "These are questions, not accusations: a diligent discloser will have ready"
    " answers to every one of them. Weigh the answers, never the count of"
    " questions -- a vendor named in many advisories may simply be one that"
    " discloses.")


@dataclass
class Question:
    """One numbered ask, with the evidence that makes it answerable."""

    text: str
    why: str
    evidence: list = field(default_factory=list)   # CVE / advisory ids, facts


def build(assessment, findings, profile=None):
    """The annex for one assessment, most pressing first.

    The order matters because of the cap: confirmed exploitation leads, the
    standing diligence block closes, and any cut falls in the middle.
    """
    findings = list(findings)
    cited = set()
    questions = _kev(assessment, findings, cited)
    questions += _unfixed(findings, cited)
    questions += _mitigated(findings, cited)
    questions += _undecided(assessment, findings)
    questions += _wormable(findings)
    questions += _certification(profile)
    questions += _feed(profile)
    # findings_count as well as the list: a caller summarising a batch may
    # pass no Finding objects for a product it still knows has history.
    if not findings and not assessment.findings_count:
        if not getattr(assessment, "resolved", True):
            # The resolver abstained, so "no advisory names it" was never
            # established -- the honest ask is for the identifiers that would
            # let anyone look it up at all.
            questions.append(Question(
                text="State the exact catalogue name and manufacturer order"
                     " number for the product you are quoting, and list every"
                     " security advisory published for it to date.",
                why="ReTrust could not resolve this product against the"
                    " advisory corpus, so its history was not assessed at"
                    " all -- which is a different fact from a clean history.",
                evidence=["product not resolved against the corpus"]))
        else:
            questions.append(Question(
                text="List every security advisory published for this product"
                     " line to date, and the channel through which each was"
                     " published.",
                why=f"No advisory in this index names {assessment.product}."
                    " Absence of advisories is not evidence of safety: it may"
                    " mean nobody has published about the product, or that"
                    " disclosure happens privately. Only the vendor can say"
                    " which.",
                evidence=["no advisory history in the index"]))
    always = _always()
    # The standing block survives the cap whatever the generators produced.
    return questions[:MAX_QUESTIONS - len(always)] + always


def _kev(assessment, findings, cited):
    """Confirmed exploitation without a vendor fix: the sharpest demand first.

    Ransomware-flagged CVEs get a question of their own rather than a mention,
    because whoever forwards this annex upward needs that line separable.
    """
    exposed = [f for f in findings if f.in_kev and f.remediation != "vendor_fix"]
    ransomware = sorted({f.cve for f in exposed if f.ransomware})
    plain = sorted({f.cve for f in exposed if not f.ransomware})
    cited.update(ransomware + plain)
    checkable = (" A version and a date are checkable claims; \"addressed in a"
                 " recent release\" is not.")
    questions = []
    if ransomware:
        questions.append(Question(
            text="State, for each CVE cited, the firmware version that fixes it,"
                 " the date that version was released, and whether the fix has"
                 " been validated against the ransomware campaigns that used"
                 " the flaw.",
            why="CISA's KEV catalogue records observed exploitation of these and"
                " flags them as used in ransomware campaigns, and the advisory"
                " offers no vendor fix." + checkable,
            evidence=_cite(ransomware) + _gate_facts(assessment, "ransomware")))
    if plain:
        questions.append(Question(
            text="State, for each CVE cited, the firmware version that fixes it"
                 " and the date that version was released.",
            why="CISA's KEV catalogue records observed exploitation of these,"
                " not a prediction of it, and the advisory offers no vendor"
                " fix." + checkable,
            evidence=_cite(plain) + _gate_facts(assessment, "exploited")))
    return questions


def _unfixed(findings, cited):
    """No fix, or nothing stated at all: the roadmap question."""
    # A KEV-listed CVE without a fix already drew the sharper demand above;
    # repeating it here would dilute both questions.
    open_ended = [f for f in findings
                  if f.remediation in ("none_available", "unknown")
                  and f.cve not in cited]
    if not open_ended:
        return []
    # EPSS descending, so the elision drops the least likely, never the worst.
    # An unmeasured EPSS sorts after a measured zero: unmeasured is not "safe".
    open_ended.sort(key=lambda f: (-(f.epss or 0.0), f.epss is None, f.cve))
    cited.update(f.cve for f in open_ended)
    return [Question(
        text="Provide the remediation roadmap for each CVE cited: the firmware"
             " version that will carry the fix, its committed release date, and"
             " the interim mitigations you support until it ships.",
        why="The advisories state no available fix for these, or state nothing"
            " at all. They are cited in descending order of exploitation"
            " probability (FIRST EPSS), so the first ids are the ones least"
            " safe to wait on.",
        evidence=_cite([f.cve for f in open_ended]))]


def _mitigated(findings, cited):
    """A workaround is a standing task for the buyer's staff, not a fix."""
    stopgap = [f for f in findings
               if f.remediation in ("mitigation", "workaround")
               and (f.epss or 0.0) > PRESSING_EPSS and f.cve not in cited]
    if not stopgap:
        return []
    stopgap.sort(key=lambda f: (-(f.epss or 0.0), f.cve))
    cited.update(f.cve for f in stopgap)
    return [Question(
        text="State whether a permanent fix is planned for each CVE cited, and"
             " how the published mitigation or workaround survives a firmware"
             " update.",
        why="A mitigation or workaround is the only published remedy for these,"
            f" and each has an exploitation probability above {PRESSING_EPSS}"
            " (FIRST EPSS). A mitigation that a routine update silently reverts"
            " is a fix the plant loses without noticing.",
        evidence=_cite([f.cve for f in stopgap]))]


def _undecided(assessment, findings):
    """Version ranges nobody could decide are the vendor's to settle."""
    unsettled = [f for f in findings if not f.decided]
    if not unsettled:
        return []
    # The assessment's own figure where it has one, so the annex and the score
    # report quote a single number; the local count covers callers without it.
    count = assessment.undecided_count or len(unsettled)
    return [Question(
        text="Confirm in writing, for each advisory cited, whether the firmware"
             " version you are quoting is affected.",
        why=f"{count} CVE(s) could not be decided against a version here:"
            " either no version was checked, or the advisory's version range"
            " is one this tool could not parse. Each was kept in scope rather"
            " than assumed safe, and only the vendor can settle it.",
        evidence=_cite(sorted({f.advisory_id for f in unsettled})))]


def _wormable(findings):
    """Network-reachable, unauthenticated, no user needed: ask about defaults."""
    # Deliberately not deduped against `cited`: what ships by default is a
    # different ask that the same vector evidence legitimately supports.
    spreading = sorted({f.cve for f in findings
                        if (vector := cvss.parse(f.vector)) and vector.wormable})
    if not spreading:
        return []
    return [Question(
        text="Describe the configuration this product ships with by default, and"
             " the network hardening the manual mandates -- not merely"
             " recommends -- for the services these CVEs reach.",
        why="Each CVE cited is exploitable over the network with no credentials"
            " and no user action, per its own CVSS vector: the combination that"
            " spreads on its own. What ships enabled and what the manual"
            " requires decide the exposure on day one, before any patch.",
        evidence=_cite(spreading))]


def _certification(profile):
    """Ask about certification only when the profile could not show one.

    "Not checked" and "nothing found" get different reasons: a cache nobody
    loaded is not evidence the vendor lacks certification.
    """
    if profile is None or profile.certificates:
        return []
    if profile.certificates is None:
        why = ("No certificate cache was loaded, so ReTrust could not check"
               " certification either way; only the vendor can answer.")
        fact = "certification not checked locally"
    else:
        why = ("No ISASecure or Common Criteria entry names this vendor in the"
               " local caches. Most OT products are never submitted, so this is"
               " a gap to close in writing, not a mark against them.")
        fact = "no ISASecure or Common Criteria entry found"
    return [Question(
        text="State the IEC 62443-4-1 (or Common Criteria) certification status"
             " of this product and its development process, the certifying"
             " body, and the dates of the most recent audits.",
        why=why, evidence=[fact])]


def _feed(profile):
    """No CSAF feed of the vendor's own: ask how customers hear of new flaws."""
    if profile is None or profile.csaf_feed:
        return []
    return [Question(
        text="Describe how customers are notified when a new vulnerability is"
             " published for this product, and in which machine-readable format"
             " (CSAF or equivalent) the advisories are available.",
        why="No CSAF feed of this vendor's own is known to this tool, which"
            " would leave disclosure relying on CISA republishing. A channel"
            " the buyer must poll by hand does not scale to a plant.",
        evidence=["no self-published CSAF feed known to ReTrust"])]


def _always():
    """The standing diligence block, asked whatever the evidence says.

    These need no advisory to justify them: they are the artefacts a working
    product-security programme produces anyway, and their absence is an answer.
    """
    return [
        Question(
            text="Provide a CycloneDX SBOM for the exact firmware version you"
                 " are quoting.",
            why="An SBOM lets the buyer check third-party components against"
                " future CVEs without waiting for a vendor advisory. A promise"
                " to provide one later is not one."),
        Question(
            text="State the committed security-support and end-of-life dates for"
                 " this product and the firmware line quoted.",
            why="OT assets outlive IT support cycles. A date in the contract is"
                " enforceable; a policy page that can change is not."),
        Question(
            text="Name the PSIRT contact for this product and provide the"
                 " coordinated-disclosure policy that applies to it.",
            why="Who takes the next vulnerability report, and under which"
                " policy, decides whether the next flaw becomes an advisory or"
                " a surprise."),
    ]


def _gate_facts(assessment, word):
    """The matching hard gate, so annex and verdict visibly share evidence."""
    return [f"gate: {gate['gate']} ({gate['source']})"
            for gate in assessment.gates if word in gate.get("gate", "").lower()][:1]


def _cite(ids, cap=MAX_CITED):
    """Dedupe in the caller's order and elide the tail, saying how much."""
    seen, out = set(), []
    for identifier in ids:
        if identifier not in seen:
            seen.add(identifier)
            out.append(identifier)
    if len(out) > cap:
        return out[:cap] + [f"and {len(out) - cap} more"]
    return out


def format_report(product, questions):
    """The annex as pasteable ASCII: numbered asks, each with its why."""
    # Corpus product names reach 330 characters; the annex header must not.
    shown = product if len(product) <= 58 else product[:55] + "..."
    lines = [f"RFQ SECURITY ANNEX   {shown}", ""]
    for number, question in enumerate(questions, 1):
        lines += _wrap(question.text, f"{number:>2}. ")
        lines += _wrap(f"why: {question.why}", "    ")
        if question.evidence:
            lines += _wrap("evidence: " + ", ".join(question.evidence), "    ")
        lines.append("")
    lines += _wrap(CLOSING, "", "")
    return "\n".join(lines)


def _wrap(text, first="", rest="    "):
    """Fold to an 80-column terminal, continuations hanging under the prose."""
    return textwrap.wrap(text, 78, initial_indent=first, subsequent_indent=rest)
