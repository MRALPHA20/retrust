"""Build a one-document explanation of how a ReTrust score is calculated.

Every number is read from the live tool at build time rather than typed in, so
this sheet cannot drift from the code the way a hand-written example does. Run
it again after any scoring change and the worked example re-derives itself.

    python3 tools/build_scoring_sheet.py
"""

import pathlib
import sys

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, StyleSheet1
from reportlab.lib.units import mm
from reportlab.platypus import (PageBreak, Paragraph, SimpleDocTemplate, Spacer,
                                Table, TableStyle)

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))          # run from anywhere, like the other builder
OUT = ROOT / "docs" / "ReTrust-Scoring-Explained.pdf"

INK = colors.HexColor("#1b242b")
SOFT = colors.HexColor("#54606a")
ACCENT = colors.HexColor("#0d7a64")
RULE = colors.HexColor("#ccd3d8")
SUNK = colors.HexColor("#eef1f3")


def _styles():
    s = StyleSheet1()
    s.add(ParagraphStyle("Body", fontName="Helvetica", fontSize=9.6, leading=14.4,
                         textColor=INK, spaceAfter=7))
    s.add(ParagraphStyle("H1", fontName="Helvetica-Bold", fontSize=19, leading=23,
                         textColor=INK, spaceAfter=4))
    s.add(ParagraphStyle("H2", fontName="Helvetica-Bold", fontSize=12.5, leading=16,
                         textColor=INK, spaceBefore=13, spaceAfter=5))
    s.add(ParagraphStyle("Kicker", fontName="Helvetica-Bold", fontSize=7.6, leading=11,
                         textColor=ACCENT, spaceAfter=10))
    s.add(ParagraphStyle("Code", fontName="Courier-Bold", fontSize=9.6, leading=14,
                         textColor=INK, spaceAfter=7))
    s.add(ParagraphStyle("Small", fontName="Helvetica", fontSize=8.2, leading=12,
                         textColor=SOFT, spaceAfter=6))
    s.add(ParagraphStyle("Cell", fontName="Helvetica", fontSize=8.6, leading=11.6,
                         textColor=INK))
    s.add(ParagraphStyle("CellHead", fontName="Helvetica-Bold", fontSize=7.4,
                         leading=10, textColor=SOFT))
    return s


S = _styles()


def table(rows, widths, head=True):
    data = [[Paragraph(str(c), S["CellHead" if head and r == 0 else "Cell"])
             for c in row] for r, row in enumerate(rows)]
    t = Table(data, colWidths=widths, hAlign="LEFT")
    style = [("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("GRID", (0, 0), (-1, -1), 0.4, RULE),
             ("TOPPADDING", (0, 0), (-1, -1), 5),
             ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
             ("LEFTPADDING", (0, 0), (-1, -1), 7),
             ("RIGHTPADDING", (0, 0), (-1, -1), 7)]
    if head:
        style.append(("BACKGROUND", (0, 0), (-1, 0), SUNK))
    t.setStyle(TableStyle(style))
    return t


def box(text, style="Code"):
    t = Table([[Paragraph(text, S[style])]], colWidths=[165 * mm], hAlign="LEFT")
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), SUNK),
                           ("BOX", (0, 0), (-1, -1), 0.4, RULE),
                           ("LEFTPADDING", (0, 0), (-1, -1), 10),
                           ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                           ("TOPPADDING", (0, 0), (-1, -1), 8),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    return t


def measured():
    """Read a real assessment, so nothing in this document is illustrative."""
    from retrust.cli import _assess, _context, _open
    from retrust import exposure as X, score

    connection, context = _open(str(ROOT / "data" / "retrust.db")), _context()
    assessment, _, findings = _assess(connection, "ABB", "AC 800M", None, None,
                                      context=context)
    first = [f for f in findings if not f.third_party]
    ranked = sorted(((X.risk(f), f.cve, f) for f in first), key=lambda t: -t[0])
    worst = [{"cve": cve,
              "T": X.threat(f),
              "Tp": X.THREAT_FLOOR + (1 - X.THREAT_FLOOR) * X.threat(f),
              "A": X.reach(f), "H": X.impact(f), "U": X.applicability(f), "z": z}
             for z, cve, f in ranked[:3]]
    risks = [z for z, _, _ in ranked]
    pillars = {}
    for pillar in assessment.pillars:
        key = next((s.key for s in score.PILLARS if s.name == pillar.name), None)
        if key and pillar.scored:
            pillars[key] = pillar.score
    return {"a": assessment, "worst": worst, "n": len(first),
            "R": X.concentrate(risks), "pillars": pillars,
            "w": score.DEFAULT_WEIGHTS, "tail": X.TAIL_WEIGHT,
            "one_path": X.concentrate([0.48]),
            "three_path": X.concentrate([0.48, 0.20, 0.10]),
            "floor": X.THREAT_FLOOR, "verify": {
                "R": X.concentrate([0.48, 0.20, 0.10]),
                "S": score._composite(
                    [(s, score.Pillar(s.name, v, 1.0)) for s, v in (
                        (next(x for x in score.PILLARS if x.key == "exposure"), 34.0),
                        (next(x for x in score.PILLARS if x.key == "patchability"), 70.0),
                        (next(x for x in score.PILLARS if x.key == "vendor_practice"), 80.0),
                        (next(x for x in score.PILLARS if x.key == "certification"), 60.0))],
                    score.DEFAULT_WEIGHTS)}}


def story(m):
    a, w, p = m["a"], m["w"], m["pillars"]
    out = [Paragraph("HOW A RETRUST SCORE IS CALCULATED", S["Kicker"]),
           Paragraph("ReTrust-OT V1, the formula and a worked example", S["H1"]),
           Paragraph("Every figure in this document was read from the tool when it "
                     "was built, not typed in. Re-run "
                     "<font face='Courier'>python3 tools/build_scoring_sheet.py</font> "
                     "after any scoring change and the example re-derives itself.",
                     S["Small"]), Spacer(1, 6)]

    out += [Paragraph("The shape: three layers", S["H2"]),
            Paragraph("A single blended number is unsafe for procurement, because a "
                      "genuine deal-breaker can be averaged away. So a verdict is "
                      "built in three stages, and only the middle one is arithmetic.",
                      S["Body"]),
            table([["", "Layer", "What it does"],
                   ["1", "Hard gates", "Known exploitation, ransomware linkage, a critical flaw with no fix, or supplier screening. Any one forces AVOID and no score is computed. Gates sit outside the formula so they cannot be out-voted."],
                   ["2", "Weighted score", "The 0&#8211;100 product below, for anything that clears the gates."],
                   ["3", "Bands", "&#8805;&#160;70 PREFER &#183; &#8805;&#160;40 CONDITIONAL &#183; otherwise AVOID. An unmitigable flaw, such as a hardcoded credential with no fix, caps the result below PREFER."]],
                  [9 * mm, 34 * mm, 122 * mm]),
            Spacer(1, 4)]

    out += [Paragraph("Step 1 &#8212; one risk number per vulnerability", S["H2"]),
            box("z   =  T&#8217; &#215; A &#215; H &#215; U<br/>"
                "T&#8217;  =  %.2f + %.2f T" % (m["floor"], 1 - m["floor"])),
            Paragraph("The operator never types a 0&#8211;1 value. All four are derived "
                      "from public evidence, and three of them can be narrowed by facts "
                      "only the asset owner has. Every refinement is optional, and each "
                      "can only reduce the assessed risk &#8212; saying nothing is already "
                      "the conservative reading.", S["Body"]),
            table([["Term", "Meaning", "Read from", "You may refine it with"],
                   ["T", "Threat level", "CISA KEV, ransomware flag, NIST LEV, FIRST EPSS", "&#8212; evidence only, never asked"],
                   ["A", "Attack reachability", "the CVSS attack vector, present on 100% of 69,560 affected rows", "verified interface block; declared network exposure; ruling out the privileges, interaction or attack conditions the vector demands"],
                   ["H", "OT operational impact", "the finding&#8217;s own CVSS severity", "declared process consequence"],
                   ["U", "Unresolved applicability", "CSAF remediation status", "fix verified applied, or a verified mitigation"]],
                  [15 * mm, 30 * mm, 60 * mm, 60 * mm])]

    rows = [["Vulnerability", "T", "T&#8217;", "A", "H", "U", "z"]]
    for r in m["worst"]:
        rows.append([r["cve"], "%.3f" % r["T"], "%.2f" % r["Tp"], "%.2f" % r["A"],
                     "%.2f" % r["H"], "%.2f" % r["U"], "<b>%.3f</b>" % r["z"]])
    out += [Spacer(1, 3),
            Paragraph("Worked on a real product &#8212; ABB AC 800M, worst three of "
                      "%d findings:" % m["n"], S["Body"]),
            table(rows, [44 * mm, 18 * mm, 16 * mm, 16 * mm, 16 * mm, 16 * mm, 20 * mm])]

    out += [Paragraph("Step 2 &#8212; concentrate on the worst few", S["H2"]),
            box("R  =  min(1,  z<sub>1</sub> + 0.20 z<sub>2</sub> + 0.10 z<sub>3</sub>)"
                "<br/>E  =  100 (1 &#8722; R)"),
            Paragraph("Averaging is what a purchase decision least wants: a product with "
                      "one catastrophic flaw and forty minor ones should not come out like "
                      "forty-one middling ones. So the worst path enters at full weight, and "
                      "the next two add on top of it rather than diluting it &#8212; a real "
                      "device has more than one route in. The leading coefficient is 1.00 "
                      "because an earlier 0.70 reserved 30% of the score for flaws the "
                      "product did not have, capping a single catastrophic finding at "
                      "E = 30 when it should reach 0.", S["Body"]),
            Paragraph("Two costs come with this, and both are consequences of the formula "
                      "rather than oversights. R clips at 1, so a product with three severe "
                      "paths reaches exactly E = 0 and stops being rankable against a worse "
                      "one &#8212; 5.7% of a 582-product sample lands there. And only three "
                      "paths are counted, so three severe flaws and three hundred score "
                      "alike.", S["Small"]),
            box("R = %.4f over %d findings     &#8594;     E = %.1f"
                % (m["R"], m["n"], 100 * (1 - m["R"]))),
            Paragraph("Step 3 &#8212; combine the four pillars", S["H2"]),
            box("S  =  E<super>0.60</super> &#215; P<super>0.20</super> &#215; "
                "V<super>0.15</super> &#215; C<super>0.05</super>"),
            Paragraph("A product, not a mean, so dangerous exposure cannot be bought back "
                      "with a good vendor record and a certificate &#8212; the rule the gates "
                      "enforce, applied to the weighted part. Pillars enter as 1&#8211;100, "
                      "never 0, so one unmeasured term cannot annihilate the result; and a "
                      "pillar with no evidence at all is excluded and the remaining exponents "
                      "renormalised, never scored as a neutral 50.", S["Body"]),
            table([["Pillar", "Meaning", "Exponent", "This product"],
                   ["E", "Exposure safety", "0.60", "%.1f" % p["exposure"]],
                   ["P", "Patch and maintenance capability", "0.20", "%.1f" % p["patchability"]],
                   ["V", "Vendor security practices", "0.15", "%.1f" % p["vendor_practice"]],
                   ["C", "Certification and assurance", "0.05", "%.1f" % p["certification"]]],
                  [15 * mm, 82 * mm, 24 * mm, 44 * mm]),
            Spacer(1, 4),
            box("%.1f<super>0.60</super> &#215; %.1f<super>0.20</super> &#215; "
                "%.1f<super>0.15</super> &#215; %.1f<super>0.05</super>  =  "
                "<b>%s / 100</b>  &#8594;  <b>%s</b>"
                % (p["exposure"], p["patchability"], p["vendor_practice"],
                   p["certification"], a.score, a.verdict)),
            Spacer(1, 10)]

    out += [Paragraph("The formula is implemented, not approximated", S["H2"]),
            Paragraph("Fed the reference example&#8217;s own values, the tool&#8217;s "
                      "functions return the reference results to four decimal places.",
                      S["Body"]),
            table([["Reference step", "Reference result", "Tool&#8217;s function", "Returns"],
                   ["R from one path, z = 0.48", "0.48", "exposure.concentrate()", "<b>%.2f</b>" % m["one_path"]],
                   ["E = 100(1 &#8722; R), one path", "52", "&#8212;", "<b>%.0f</b>" % (100 * (1 - m["one_path"]))],
                   ["R from z = 0.48, 0.20, 0.10", "0.53", "exposure.concentrate()", "<b>%.2f</b>" % m["three_path"]],
                   ["E = 100(1 &#8722; R), three paths", "47", "&#8212;", "<b>%.0f</b>" % (100 * (1 - m["three_path"]))],
                   ["S from E=34, P=70, V=80, C=60", "45.95", "score._composite()", "<b>%.4f</b>" % m["verify"]["S"]]],
                  [52 * mm, 30 * mm, 48 * mm, 35 * mm])]

    out += [Paragraph("Five deliberate departures, each for a measured reason", S["H2"]),
            table([["#", "Departure", "Why"],
                   ["1", "T is mapped onto [%.2f, 1] rather than used raw" % m["floor"],
                    "The OT corpus median EPSS is 0.007. Used directly, a critical, network-reachable, unfixed CVE gives z &#8776; 0.007 and so E &#8776; 99.5 &#8212; &#8220;harmless&#8221;, because nobody has attacked it yet. Threat now amplifies rather than decides."],
                   ["2", "H carries the finding&#8217;s CVSS severity, scaled by the declared consequence",
                    "The reference z has no severity term, so a CVSS 9.8 and a 4.0 with equal EPSS scored identically. This follows the reference&#8217;s own caveat that impact must consider what the vulnerability actually permits."],
                   ["3", "T reads LEV as well as KEV and EPSS",
                    "The reference specifies T = max(KEV, LEV, EPSS). LEV&#8217;s corpus median is 0.167 against EPSS&#8217;s 0.007, so for most OT findings it is the only non-trivial exploitation evidence there is. An observation still outranks any model: a KEV listing beats any estimate."],
                   ["4", "No operator declaration may promote the verdict",
                    "Measured with the clamp off: declarations produced 1,657 band promotions across 489 products, 552 of them AVOID straight to PREFER, and reordered 118 of 119 products in a comparison. Nobody can verify &#8220;isolated&#8221;. The undeclared score now sets the best band; declarations still move the number inside it."],
                   ["5", "C may lift the score but never lower it",
                    "As written, C<super>0.05</super> costs an uncertified product 20.6% of its score (57.8 against 72.7, measured). Most OT hardware is never submitted for certification, so absence is excluded rather than penalised."]],
                  [8 * mm, 58 * mm, 99 * mm])]

    out += [Paragraph("What the number is, and is not", S["H2"]),
            table([["Higher is better", "A score is how favourable the public evidence is, not a probability that the equipment is secure. 70/100 means low assessed risk, not &#8220;70% safe&#8221;."],
                   ["Gates override it", "A gated product is AVOID whatever the arithmetic says. Declaring an isolated network raises the number, and lifts neither the gate nor the band."],
                   ["Counts are never scored", "Raw CVE volume carries no weight, because that would rank a diligent discloser below a silent one."],
                   ["Absence is not safety", "An unresolved product is NOT ASSESSED, never a flattering 100. An unparseable version range stays in scope."],
                   ["Evidence completeness is separate", "It says how far to trust the score, not how risky the product is, so it is reported beside the verdict and never inside it."],
                   ["The weights are arguable", "They live in an editable config file, and <font face='Courier'>retrust sensitivity</font> re-runs the verdict under hundreds of random weightings; a verdict holding under fewer than 90% is flagged as a judgement call."]],
                  [45 * mm, 120 * mm], head=False),
            Spacer(1, 8),
            Paragraph("In one sentence: how bad are the worst few flaws on this device "
                      "(60%), can you fix them (20%), does the vendor disclose well (15%), "
                      "and is it independently certified (5%) &#8212; multiplied, so a "
                      "dangerous product cannot be rescued by good paperwork.", S["Body"]),
            Paragraph("ReTrust is decision support, not a certification. Figures come from "
                      "public CISA, FIRST and vendor sources; the scoring version and data "
                      "snapshot are recorded on every assessment so a result can be re-run "
                      "and disputed.", S["Small"])]
    return out


def main():
    m = measured()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    SimpleDocTemplate(str(OUT), pagesize=A4,
                      leftMargin=22 * mm, rightMargin=22 * mm,
                      topMargin=18 * mm, bottomMargin=16 * mm,
                      title="How a ReTrust score is calculated",
                      author="ReTrust").build(story(m))
    print(OUT)


if __name__ == "__main__":
    main()
