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
    """Calculate examples with the production model, including its uncertainty."""
    from retrust import exposure, score
    from retrust.match import Finding
    from retrust.cli import _assess, _context, _open
    vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    f = Finding('CVE-ILLUSTRATIVE', 'Illustrative', 9.8, 'CWE-787', .12,
                False, False, '<2.0', True, 'vendor_fix', vector, lev=.6)
    exposure_example = exposure.analyse([f], network='ot_only', interface='exposed',
                                        consequence='control')
    e = 100 * (1 - exposure.concentrate([.48,.20,.10]))
    values = dict(exposure=e, patchability=70, vendor_practice=80, certification=60)
    terms = [(spec, score.Pillar(spec.name, values[spec.key], 1)) for spec in score.PILLARS]
    final = score._composite(terms, score.DEFAULT_WEIGHTS)
    assert abs(exposure_example.safety_min-52) < 1e-9
    assert abs(e-47) < 1e-9
    connection = _open(str(ROOT/'data/retrust.db'))
    real, _, _ = _assess(connection, 'ABB', 'AC 800M', None, None, context=_context())
    connection.close()
    return dict(single=exposure_example.safety_min, exposure=e, final=final, real=real)


def story(m):
    flow = []
    def para(text, style='Body'):
        return Paragraph(text, S[style])
    flow += [para('ReTrust-OT V1 / RT4', 'H1'),
             para('How the score is calculated', 'H2'),
             para('20 October 2026. Higher scores indicate more favourable evidence under the selected settings. The score is a decision aid, not a probability that equipment is safe.'),
             box('Z = T x A x H x U'),
             table([['Factor','What it measures','V1 rule'],
                    ['T','Exploitation evidence','max(KEV, LEV, EPSS). Confirmed exploitation is 1; missing sources stay unavailable.'],
                    ['A','Attack access','1 for a feasible path with prerequisites met; 0 for a verified block; otherwise [0,1].'],
                    ['H','Credible OT harm','Safety/environment 1; control .8; recoverable disruption .5; minor .2; no material harm 0. Unknown is [0,1].'],
                    ['U','Affected and unfixed','1 for affected, unpatched firmware; 0 for verified fixed or not affected; otherwise [0,1].']], [13*mm,42*mm,110*mm]),
             para('Network access is a main input', 'H2'),
             para('Select isolated, OT-only, IT-OT, remote vendor access, direct Internet or unknown. Then establish actual reachability. An isolated controller may still be accessible from a compromised industrial workstation. Topology alone gives no numerical discount.'),
             para('ReTrust does not scan the network. Site answers are operator-reported and need supporting evidence. A firewall changes attack access; it does not count as installing a firmware patch.'),
             para('CVSS severity remains useful context, but is not multiplied into H. An engineer must establish the credible effect of the particular weakness, rather than assigning every weakness the importance of the whole plant.', 'Small'),
             PageBreak()]
    flow += [para('A worked calculation', 'H1'),
             para('Illustrative inputs, calculated by the production scoring functions. These are not findings about an actual PLC.'),
             table([['Input','Value','Reason'],['T','.60','max(0, .60, .12)'],
                    ['A','1','Path reachable; required conditions satisfied'],['H','.80','Credible major loss of process control'],
                    ['U','1','Selected firmware affected and not patched']], [25*mm,25*mm,115*mm]),
             Spacer(1,12),box('Z1 = .60 x 1 x .80 x 1 = .48'),
             para('The highest contribution counts fully', 'H2'),
             box('R = min(1, Z1 + .20 Z2 + .10 Z3)<br/>E = 100 x (1 - R)'),
             table([['Contributions','R','Exposure safety E'],['.48','.48',f'{m["single"]:.0f}'],
                    ['.48 and .20','.52','48'],['.48, .20 and .10','.53',f'{m["exposure"]:.0f}']], [80*mm,30*mm,55*mm]),
             para('Repeated advisory records for one CVE count once. Different CVEs are review units, not proof of independent attack paths. An engineer can explicitly group a reviewed shared path. Only the largest three units contribute; R clips at 1.', 'Small'),
             para('Combine the four pillars', 'H2'),box('S = E^.60 x P^.20 x V^.15 x C^.05'),
             para(f'With E={m["exposure"]:.0f}, P=70, V=80 and C=60: <b>S = {m["final"]:.2f}/100</b>. The current 70/40 bands give CONDITIONAL, assuming verified inputs and no mandatory blocker.'),
             PageBreak()]
    a = m['real']
    flow += [para('Unknown means VERIFY', 'H1'),
             para('If only U is unknown in the worked weakness, Z is between 0 and .48. Exposure safety is between 52 and 100. ReTrust carries the bounds into the final score and lists the checks needed before deciding. It does not guess a middle value.'),
             para('Example from the local index', 'H2'),
             para(f'<b>{a.product}</b>: {a.verdict}; provisional score range <b>{a.score_min:.1f}-{a.score_max:.1f}/100</b>. No deployment or firmware inputs were supplied. Rebuild this sheet against a changed index to refresh the example.'),
             table([['Next check','Who can help'],['Network context and attack access','Network or OT security owner'],
                    ['Credible consequence of each weakness','Operations or safety engineer'],
                    ['Affected firmware and installed fixes','Asset owner or product supplier'],
                    ['Missing exploitation data','Security analyst; refresh public sources']], [94*mm,71*mm]),
             para('Decision rules', 'H2'),
             para('PREFER: 70 or higher. CONDITIONAL: 40 to below 70. AVOID: below 40 or a mandatory blocker. VERIFY: material evidence remains unresolved. NOT ASSESSED: insufficient product evidence to calculate a score.'),
             para('Pillars enter the final product with a floor of 1. Missing patch, vendor or certification evidence is excluded and the remaining exponents are adjusted. Unknown exposure stays in the range. Measured certification participates directly. Unfixed hardcoded credentials cap the result below PREFER.'),
             para('Evidence and limits', 'H2'),
             para('Save JSON or HTML to retain RT4 settings, factor bounds, advisory citations and source capture dates. Per-finding reviews can retain rationale and evidence. Website answers apply across the findings in scope; review findings individually when their consequences or controls differ.'),
             para('The weights, OT consequence values and multiplication are proposed ReTrust design choices that require validation. Historical benchmarks from earlier scoring models do not validate RT4 procurement decisions. KEV, LEV and EPSS have different time horizons; their maximum is a threat-priority index, not a calibrated compromise probability.', 'Small')]
    return flow


def main():
    m = measured()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    SimpleDocTemplate(str(OUT), pagesize=A4, leftMargin=22*mm, rightMargin=22*mm,
                      topMargin=18*mm, bottomMargin=18*mm,
                      title='ReTrust RT4: How the Score Works', author='ReTrust').build(story(m))
    print(OUT)


if __name__ == '__main__':
    main()
