"""Build the public overview from measured benchmark artifacts (ReportLab required)."""
from pathlib import Path
import json
import shutil
from html import escape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib import colors
from reportlab.lib.styles import StyleSheet1, ParagraphStyle

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'output/pdf/ReTrust-Overview-and-Benchmarks.pdf'
DATA = ROOT / 'docs/benchmarks'
NAVY = colors.HexColor('#102334')
TEAL = colors.HexColor('#087E83')
INK = colors.HexColor('#213442')
SOFT = colors.HexColor('#526572')
PALE = colors.HexColor('#EEF5F5')
LINE = colors.HexColor('#D8E3E6')
styles = StyleSheet1()
for name, size, leading, color in [('Body',10.5,15,INK),('Small',9,12,SOFT),('H1',27,31,NAVY),('H2',14,19,TEAL),('Cell',9.2,13,INK),('CellHead',9.2,13,colors.white),('Code',8.5,12,INK)]:
    styles.add(ParagraphStyle(name=name,fontName='Helvetica-Bold' if name in ('H1','H2','CellHead') else 'Courier' if name=='Code' else 'Helvetica',fontSize=size,leading=leading,textColor=color,spaceAfter=9 if name=='Body' else 6))


def p(text,style='Body'):
    return Paragraph(text,styles[style])


def table(headers,rows,widths):
    data=[[p(escape(str(x)),'CellHead') for x in headers]]
    data += [[p(str(x),'Cell') for x in row] for row in rows]
    t=Table(data,colWidths=widths,hAlign='LEFT',repeatRows=1)
    t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),NAVY),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,PALE]),('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),9),('RIGHTPADDING',(0,0),(-1,-1),9),('TOPPADDING',(0,0),(-1,-1),9),('BOTTOMPADDING',(0,0),(-1,-1),9),('LINEBELOW',(0,0),(-1,0),1,TEAL),('LINEBELOW',(0,-1),(-1,-1),.6,LINE)]))
    return t


def note(title,text):
    t=Table([[p(title,'H2')],[p(text)]],colWidths=[499])
    t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),PALE),('BOX',(0,0),(-1,-1),.5,LINE),('LEFTPADDING',(0,0),(-1,-1),14),('RIGHTPADDING',(0,0),(-1,-1),14),('TOPPADDING',(0,0),(-1,0),12),('BOTTOMPADDING',(0,-1),(-1,-1),8)]))
    return t


def page(title,kicker):
    return [p(kicker.upper(),'Small'),p(title,'H1'),Spacer(1,10)]


def footer(c,doc):
    c.saveState()
    w,h=doc.pagesize
    c.setStrokeColor(LINE);c.line(48,45,w-48,45)
    c.setFont('Helvetica',8);c.setFillColor(SOFT)
    c.drawString(48,30,'RETRUST / Technical overview / RT4 / 20 October 2026')
    c.drawRightString(w-48,30,f'{doc.page}')
    c.setFillColor(TEAL);c.rect(0,h-7,w,7,fill=1,stroke=0)
    c.restoreState()


def build():
    ev=json.loads((DATA/'evaluation.json').read_text())
    bt=json.loads((DATA/'backtest.json').read_text())['backtest']
    latency=json.loads((DATA/'latency.json').read_text())
    matched=bt['matched_cohort']
    story=[]
    story += page('ReTrust','OT procurement intelligence / 0.1.0')
    story += [p('Cyber-risk evidence before the purchase order','H1'),Spacer(1,13),
        p('What the tool does, how it works, measured benchmarks, and where it fits alongside other security tools.'),
        Spacer(1,13),note('The decision it supports','A procurement team has a shortlist of industrial controllers, switches or other OT products. ReTrust collects the public security evidence for each named candidate and turns it into a traceable review: PREFER, CONDITIONAL, VERIFY, AVOID or NOT ASSESSED. VERIFY means material site or firmware evidence remains unresolved.'),Spacer(1,18),
        p('Why it is useful','H2'),
        p('A requisition often arrives with a manufacturer, model, order number and proposed firmware, before there is a device to inspect. Reviewing advisories, exploitation signals, fixes and supplier restrictions separately makes it hard to compare candidates consistently.'),
        p('ReTrust brings that work into one local workflow. It helps buyers find disqualifying evidence early, ask the supplier specific questions, and preserve the rationale with the procurement record.'),
        table(['PUBLIC EVIDENCE','MEASURED CORPUS','LOCAL WORKFLOW'],[['3,937 CSAF advisories','28,951 product entries<br/>12,061 distinct CVEs','CLI, interactive menu<br/>and browser workspace']],[166,167,166]),Spacer(1,14),
        p('Audience: OT security engineers, procurement teams, integrators and security reviewers. OT means operational technology, including equipment used to control or monitor physical processes.','Small'),
        p('Scope: public-evidence decision support. Scores are not probabilities of compromise, a certification, or a replacement for engineering acceptance tests.','Small'),PageBreak()]

    story += page('From a part number to evidence','01 / How it works')
    story += [table(['STAGE','WHAT RETRUST DOES'],[
        ['1. Collect','Fetch CSAF advisories, CISA KEV, FIRST EPSS and optional screening/certification sources. Preserve local provenance. [1, 2, 3]'],
        ['2. Index','Parse product trees, relationships, version ranges and product-specific remediation into SQLite. Stage rebuilds before replacing the active index.'],
        ['3. Resolve','Try manufacturer order number, then normalized vendor/name matching and a token-subset fallback. Reject conflicts and ambiguous requests.'],
        ['4. Filter','Use the supplied firmware to narrow affected ranges. Keep undecided ranges visible and in scope.'],
        ['5. Assess','Apply hard gates and calculate weighted evidence pillars. Show missing evidence separately from a good score.'],
        ['6. Review and export','Compare candidates, inspect evidence, prepare supplier questions, and retain HTML, JSON, CSV or VEX output as appropriate.']],[100,399]),Spacer(1,17),
        p('Why manufacturer order numbers matter','H2'),
        p('In this local CISA OT corpus, only 60 of 28,951 product entries carry a CPE identifier (0.21%). Declared order numbers appear on 8,211 entries (28.36%); including recovered numbers raises coverage to 9,575 entries (33.07%).'),
        p('That is about 137 times as many entries with declared order numbers as with CPE. It supports ReTrust\'s choice of input identifier for this dataset. It does not measure a scanner\'s total identifier coverage or its performance on industrial networks.'),
        note('An advisory product entry is not a unique device','The same product can appear in multiple advisories. Corpus totals describe records, not installed assets or unique hardware models.'),PageBreak()]

    story += page('How to read a verdict','02 / Scoring and safeguards')
    story += [p('Higher scores indicate more favorable evidence under the configured weights. The default composite is a weighted product of four pillars (exposure, patch availability, vendor practice, certification); evidence quality is reported separately and never scored.'),
        table(['PILLAR','WEIGHT','EVIDENCE USED'],[
        ['Exposure safety','60%','T x A x H x U, concentrated on the three largest review units'],['Patch availability','20%','Vendor fix, mitigation/workaround, unavailable or unknown remedy'],['Vendor practice','15%','Advisory completeness and published security-advisory practice'],['Certification','5%','Available certification evidence and product scope']],[112,57,330]),Spacer(1,13),
        p('S = E^0.60 x P^0.20 x V^0.15 x C^0.05','Code'),
        table(['DEFAULT BAND','READING'],[['PREFER: 80-100','More favorable evidence; still review scope and suitability.'],['CONDITIONAL: 60-&lt;80','Review mitigations, supplier commitments and evidence gaps.'],['VERIFY','Confirm material reachability, consequence, threat or firmware evidence; a provisional range is shown.'],['AVOID: &lt;40, or a gate','A numeric band or a disqualifying gate triggers this result.'],['NOT ASSESSED','Insufficient product evidence; no numeric score is given.']],[157,342]),Spacer(1,13),
        p('Reachability is read per weakness','H2'),
        p('A reaches 1 only where the flaw\'s own CVSS attack vector fits the answer: a reachable service settles a network or adjacent flaw; a local or physical one also needs execution or contact, so it stays a range. A verified block is 0. Network context is recorded, never scored. H uses credible OT consequences, not CVSS/10; controls change A rather than patching U.'),
        p('R = min(1, Z1 + .20 Z2 + .10 Z3); E = 100(1-R). Duplicate advisories for one CVE count once. Default CVE groups do not establish independent paths. Missing threat sources and unresolved A, H or U remain explicit. Pillars enter the product with a floor of 1; missing non-exposure pillars are excluded and weights are adjusted.','Small'),
        p('Gates override a score','H2'),
        p('Known exploitation, ransomware linkage, a critical likely-exploited flaw without a remedy, or configured supplier-screening evidence can force AVOID. Screening can block an unresolved product when vendor evidence is sufficient. [1]'),
        PageBreak()]

    story += page('Benchmarks you can reproduce','03 / Local evaluation, 28 September 2026')
    story += [table(['MEASUREMENT','RESULT','WHAT IT ESTABLISHES'],[
        ['Version-range coverage','27,193 / 28,651<br/><b>94.91%</b>','The parser can decide these range forms. It does not independently establish correct affectedness for every firmware.'],
        ['Coverage of eligible ranges','27,193 / 28,092<br/><b>96.80%</b>','Excludes 559 ranges classified as serial-, revision- or date-dependent. Another 899 ranges remain missed.'],
        ['Round-trip precision','3,988 / 3,994 answered<br/><b>99.85%</b>','Returned matches include the originating advisory. Six answered queries did not; six more abstained.'],
        ['Round-trip recall','3,988 / 4,000 attempted<br/><b>99.70%</b>','The source advisory was recovered in the sampled query. Extra incorrect matches are not separately penalized.'],
        ['Hand-written buyer queries','20 / 21<br/><b>95.24%</b>','A small authored set including shorthand, typos, conflicts and abstention cases. Not an independent test set.']],[138,133,228]),Spacer(1,16),
        p('Retained matching benchmark, measured before RT4','H2'),
        p('Products are selected deterministically from the same advisory corpus used by the resolver. Query generation removes parenthetical text and punctuation, lowers case and keeps the first four words. The original order number is also supplied when present. Success means the originating advisory appears among the returned matches.'),
        p('By method: order number 1,334/1,334; normalized name 2,617/2,623; token subset 37/37. These are sample results, not universal accuracy guarantees. The buyer-query miss is “Belden RS switches”: the matcher abstains instead of making a broad vendor-substring guess.'),
        note('Use the precise claim','ReTrust shows high source-advisory recovery on its internal corpus-based benchmark. Independent product/version labeling and returned-match precision are still needed before claiming general matching accuracy.'),PageBreak()]

    story += page('Speed and predictive limits','04 / Runtime and historical diagnostics')
    latency_rows=[[r['case'],f"{r['median_ms']:.1f} ms",f"{r['p95_ms']:.1f} ms"] for r in latency['results']]
    story += [p('Local command latency','H2'),table(['CASE','MEDIAN','P95'],latency_rows,[313,93,93]),Spacer(1,9),
        p('20 serial fresh CLI processes per case after one warm-up; warm OS cache; stdout discarded. Wall-clock time includes Python startup. P95 uses the nearest-rank method. These are retained pre-RT4 measurements on a shared development machine, not current RT4 latency, a load test or a cross-tool benchmark.','Small'),
        p(f"Environment: Python {escape(latency['python'])}; {escape(latency['cpu'])}; {latency['logical_cpus']} logical CPUs reported. Database: {latency['database_bytes']/1024/1024:.1f} MiB. Full environment details and raw summaries are in docs/benchmarks/latency.json.",'Small'),Spacer(1,10),
        p('Does a higher score predict fewer later vulnerabilities?','H2'),
        p('The retained pre-RT4 backtest does not establish that and does not validate RT4. At a 2022-01-01 cutoff, 5,848 products are scored on pre-cutoff advisories and compared with later CVE disclosure. The diagnostic uses 1,000 seeded permutations.'),
        table(['COMPARISON','SPEARMAN RHO'],[['Score vs later CVE count, pooled',f"{bt['rho_score_vs_future_cves']:+.3f}"],[f"Within vendor, {matched['products']:,} products",f"{matched['rho_within_vendor']:+.3f}"],['Within vendor, excluding Siemens',f"{matched['rho_excluding_largest_vendor']:+.3f}"]],[362,137]),Spacer(1,12),
        p('The positive association weakens when vendor effects are controlled. This is consistent with disclosure and research-exposure effects; it does not prove a causal explanation. Only two products across two vendors qualify for the later-KEV outcome, too few for an exploitation-rate claim.'),
        note('A defensible boundary','Use the score to organize current evidence and questions. This backtest does not validate the score as a predictor of real-world compromise.'),PageBreak()]

    story += page('How it compares with other tools','05 / Capability comparison, not a performance contest')
    story += [p('These tools answer related but different questions. The descriptions below come from their official documentation. No competing tool was run in a common experimental test. Availability and features may change.'),
        table(['TOOL','PRIMARY JOB / INPUT','RELATIONSHIP TO RETRUST'],[
        ['<b>ReTrust</b>','Named OT candidate, order number and firmware; public advisory evidence.','Compare a procurement shortlist and export its evidence before deployment. No live network discovery or binary analysis.'],
        ['<b>Nessus</b> [4]','Vulnerability assessment, missing patches, configuration/compliance checks on systems.','Use for assessing deployed systems. ReTrust\'s advisory-based shortlist is a different input and decision workflow.'],
        ['<b>Nozomi Guardian</b> [5]','Passive OT/IoT traffic observation, asset inventory, vulnerabilities and anomaly/threat detection.','Use for operational network visibility. ReTrust does not observe traffic or detect live incidents.'],
        ['<b>runZero</b> [6]','Asset discovery and exposure management using scanning, passive inputs and integrations.','Use to understand what is present and exposed. Inventory can inform a later named-product review.'],
        ['<b>Trivy</b> [7]','Vulnerabilities, misconfigurations, secrets and SBOM workflows for software artifacts.','Use for package, image and repository evidence. ReTrust reads a candidate/SBOM list but does not perform equivalent software inspection.'],
        ['<b>FACT</b> [8]','Firmware unpacking, analysis, searching and comparison from firmware samples.','Use when firmware contents are available. ReTrust does not discover new weaknesses inside binaries.'],
        ['<b>BloodHound</b> [9]','Graph analysis of identity relationships and attack paths, including AD/Entra and OpenGraph extensions.','Use for attack-path analysis. ReTrust evaluates procurement evidence; it does not collect identity graphs.']],[86,197,216]),Spacer(1,12),
        p('ReTrust\'s practical distinction is its order-number-led procurement workflow, local operation, explicit abstention and exported rationale. This is a description of its focus, not a claim that no other product offers procurement features.','Small'),PageBreak()]

    story += page('A review someone can follow','06 / Example workflow')
    shot=ROOT/'docs/assets/workspace-comparison.png'
    if shot.exists():
        im=Image(str(shot)); im.drawHeight=im.imageHeight*499/im.imageWidth; im.drawWidth=499
        story += [im,Spacer(1,9),p('Actual local RT4 browser capture. Without the site and firmware evidence, ungated candidates require verification rather than receiving a completed recommendation.','Small')]
    story += [p('1. Start with the requisition. Enter an order number or vendor/model and, where known, firmware. Verify that the resolved product is the intended variant.'),
        p('2. Read the deciding evidence. Purchase blockers force AVOID. Otherwise missing attack access, credible OT consequence or firmware applicability produces VERIFY, a provisional range and specific checks.'),
        p('3. Resolve the checks with a network owner, operations engineer and supplier. Weight sensitivity is deferred while material evidence is missing. When inputs are resolved, it tests how much the result depends on weights.'),
        p('4. Preserve and act. Export the assessment, use supplier questions to request exact fixed versions and support commitments, and re-score the saved query when evidence changes.'),PageBreak()]

    story += page('Operate, reproduce and improve','07 / Practical use and limitations')
    story += [p('Start locally','H2'),
        p('python3 -m retrust.cli setup<br/>python3 -m retrust.cli shell<br/>python3 -m retrust.cli serve','Code'),
        p('Setup needs network access to obtain sources. Once populated, assessments run locally. The browser workspace defaults to 127.0.0.1:8765. The core package requires Python 3.10+ and no third-party Python runtime packages; some setup, signature and screenshot commands use external tools.'),
        p('Reproduce the measurements','H2'),
        p('python3 -m retrust.cli eval --sample 4000 --json eval.json<br/>python3 -m retrust.cli backtest --permutations 1000<br/>python3 -m pytest -q<br/>bash smoke.sh','Code'),
        p('Local verification: 947 automated tests passed; 94 real-data smoke checks passed. These cover command workflows, HTTP routes, parsing, output and regression cases, including guards against injection, SSRF and decompression-bomb inputs. They do not constitute an independent security audit.'),
        p('Know the remaining gaps','H2'),
        p('<b>Evidence coverage:</b> absent advisories, missing certification or uncertain ranges are not proof of safety. Family-level queries can collect several variants; prefer precise identifiers.'),
        p('<b>Scoring:</b> weights and gates encode a review policy. Certification may be vendor-level, screening requires scope confirmation, and raw disclosure volume is not a risk ground truth.'),
        p('<b>Operations:</b> the local web UI has no multi-user authentication or enterprise case-management workflow, but it is read-only and answers GET requests only, exposing none of the commands that fetch data or change the index. Preserve provenance and snapshots, confirm advisory origin with verify (--strict in a pipeline), review source freshness with doctor, and recheck supplier evidence before a decision.'),
        p('<b>Next validation:</b> build an independently labeled product/version set, measure extra matches and abstention quality, record buyer usability results, and evaluate outcomes across vendors and time.'),
        note('Reproducibility record',f"Data captured locally on 28 September 2026. SQLite SHA-256:<br/><font face='Courier' size='7.7'>{latency['database_sha256']}</font><br/>Benchmark JSON/text and this PDF builder are retained in the repository."),PageBreak()]

    story += page('Sources and evidence record','08 / References')
    sources=[
        ('1','CISA Known Exploited Vulnerabilities','https://www.cisa.gov/known-exploited-vulnerabilities-catalog'),
        ('2','CISA CSAF advisory repository','https://github.com/cisagov/CSAF'),
        ('3','FIRST Exploit Prediction Scoring System','https://www.first.org/epss/'),
        ('4','Tenable Nessus product capabilities','https://www.tenable.com/products/nessus'),
        ('5','Nozomi Guardian capabilities','https://www.nozominetworks.com/platform/guardian'),
        ('6','runZero exposure management documentation','https://help.runzero.com/docs/exposure-management/'),
        ('7','Aqua Trivy official repository','https://github.com/aquasecurity/trivy'),
        ('8','FACT official repository','https://github.com/fkie-cad/FACT_core'),
        ('9','SpecterOps introduction to BloodHound','https://bloodhound.specterops.io/get-started/introduction')]
    for num,title,url in sources:
        story += [p(f'<b>[{num}] {title}</b><br/><link href="{url}" color="#087E83">{url}</link>','Small'),Spacer(1,4)]
    story += [Spacer(1,13),p('Evidence retained with the project','H2'),
        p('docs/benchmarks/evaluation.json and evaluation.txt<br/>docs/benchmarks/backtest.json and backtest.txt<br/>docs/benchmarks/latency.json<br/>docs/benchmark-report.md<br/>docs/tool-comparison.md<br/>tools/build_overview.py','Code'),
        p('Comparison sources [3-9] were read on 28 September 2026. CISA data claims come from the locally indexed corpus and provenance; the public KEV page was not retrievable during report preparation. Product descriptions are summaries, not endorsements or exhaustive feature inventories.','Small'),
        p('The benchmark cohort is derived from this tool\'s indexed public corpus. Source publication dates and local capture dates differ. The historical feasibility plan is kept as an explicitly labeled archive.','Small')]
    OUT.parent.mkdir(parents=True,exist_ok=True)
    doc=SimpleDocTemplate(str(OUT),pagesize=(595.28,841.89),leftMargin=48,rightMargin=48,topMargin=39,bottomMargin=61,title='ReTrust - Overview, Benchmarks and Tool Comparison',author='ReTrust project',subject='OT procurement evidence and reproducible evaluation')
    doc.build(story,onFirstPage=footer,onLaterPages=footer)
    shutil.copyfile(OUT,ROOT/'docs/ReTrust-Guide.pdf')
    print(OUT)


if __name__=='__main__':
    build()
