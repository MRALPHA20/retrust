"""Shared presentation for the local browser. No scripts or remote assets."""

import html
import os
from datetime import date

from . import report


def esc(value):
    return html.escape(str(value or ""), quote=True)


NAVIGATION = (
    ("Workspace", (("/", "Explore", "01"), ("/score", "Assess a product", "02"),
                   ("/compare", "Compare candidates", "03"))),
    ("Evidence", (("/vendor", "Vendor profile", "VP"),
                  ("/timeline", "Advisory timeline", "AT"),
                  ("/alternatives", "Find alternatives", "FA"),
                  ("/annex", "Supplier questions", "PQ"))),
    ("Analysis", (("/ssvc", "Response priority", "SS"),
                  ("/lev", "Exploitation estimate", "LE"),
                  ("/about", "Data & methodology", "DM"))),
)


def page(title, body, subtitle="", active=None):
    hosted = os.environ.get('RETRUST_HOSTED') == '1'
    workspace_label = 'Hosted workspace' if hosted else 'Local workspace'
    workspace_detail = 'Queries are processed on this server.' if hosted else 'Public evidence. Private decisions.'
    assessment_label = 'Hosted assessment' if hosted else 'Offline assessment'
    if active is None:
        active = next((route for prefix, route in (
            ("Score", "/score"), ("Procurement comparison", "/compare"),
            ("Alternatives", "/alternatives"), ("Timeline", "/timeline"),
            ("Annex", "/annex"), ("RFQ", "/annex"), ("SSVC", "/ssvc"),
            ("LEV", "/lev"), ("Vendor", "/vendor"), ("About", "/about"),
            ("Demo", "/demo")) if title.startswith(prefix)), "/")
    navigation = "".join(
        f'<div class="nav-group"><p class="nav-label">{label}</p>' + "".join(
            f'<a href="{route}"' + (' aria-current="page"' if route == active else '')
            + f'>{name}</a>'
            for route, name, icon in items) + '</div>' for label, items in NAVIGATION)
    current = next((name for _, items in NAVIGATION for route, name, _ in items
                    if route == active), "Guided demo")
    return (
        '<!doctype html><html lang="en" data-theme="dark"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>{esc(title if title == "ReTrust" else title + " · ReTrust")}</title><style>{report.CSS}{CSS}</style></head>'
        '<body class="app"><a class="skip" href="#main">Skip to content</a>'
        '<aside class="sidebar"><a class="brand" href="/" aria-label="ReTrust home">'
        '<span class="brand-symbol" aria-hidden="true">R<span>↗</span></span>'
        '<span>ReTrust<small>OPEN-SOURCE OT RISK TOOLING</small></span></a>'
        f'<nav class="desktop-nav" aria-label="Main navigation">{navigation}</nav>'
        f'<details class="mobile-menu"><summary>Menu · {esc(current)}</summary>'
        f'<nav aria-label="Mobile navigation">{navigation}</nav>'
        '<a href="/demo">Take the guided demo →</a></details>'
        '<a class="demo-link" href="/demo"><span>Meet ReTrust</span>'
        '<strong>Take the guided demo <span aria-hidden="true">↗</span></strong></a>'
        f'<div class="local-status"><span class="dot"></span> {workspace_label}'
        f'<small>{workspace_detail}</small></div></aside>'
        '<div class="workspace"><header class="topbar"><span>Workspace '
        f'<span class="crumb">/</span> <b>{esc(current)}</b></span>'
        f'<span class="offline"><span class="dot"></span> {assessment_label}</span></header>'
        f'<main id="main" class="wrap"><div class="page-meta"><span>RETRUST / {esc(current).upper()}</span>'
        f'<span>{esc(subtitle) + " · " if subtitle else ""}{date.today().isoformat()}</span></div>'
        + body + '<footer><span>ReTrust <span class="muted">/</span> Evidence before commitment.</span>'
        '<span><a href="https://github.com/MRALPHA20/retrust">Source code on'
        ' GitHub</a> <span class="muted">&middot;</span>'
        ' Decision support, not a certification.</span></footer></main></div></body></html>')


CSS = """
:root[data-theme=dark]{font-size:15px;color-scheme:dark;--field:#0c1118;--panel:#131c27;--sunk:#0f1721;
 --rule:#293646;--ink:#edf2f8;--soft:#adbacb;--faint:#94a6bb;
 --prefer:#73e0b7;--cond:#f0bc63;--avoid:#ff8b91;--accent:#73e0b7}
body.app{line-height:1.55;background:var(--field)}
a{color:var(--ink);text-underline-offset:4px}a:hover{color:var(--accent)}
a:focus-visible,button:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:4px}
.skip{position:fixed;left:1rem;top:-6rem;z-index:10;background:var(--panel);padding:1rem}.skip:focus{top:1rem}
.sidebar{width:238px;position:fixed;inset:0 auto 0 0;background:#101822;border-right:1px solid var(--rule);scrollbar-width:thin;scrollbar-color:#304354 #101822;
 padding:30px 20px;display:flex;flex-direction:column;overflow-y:auto;z-index:2}
.brand{display:flex;gap:11px;align-items:center;text-decoration:none;font-size:24px;font-weight:700;letter-spacing:-1px;margin-bottom:36px}
.brand small{display:block;font:8px/1.7 var(--mono);letter-spacing:.6px;color:var(--faint);margin-top:3px}
.mobile-menu{display:none}
.brand-symbol{display:flex;position:relative;width:39px;height:43px;align-items:center;justify-content:center;
 border:1px solid var(--accent);border-radius:10px 3px 10px 3px;color:var(--accent);font:700 27px var(--mono)}
.brand-symbol span{font-size:15px;position:absolute;right:-5px;top:-7px;background:#101822;padding:0 1px}
.nav-group{margin-bottom:20px}.nav-label{font:10px var(--mono);letter-spacing:1.4px;text-transform:uppercase;color:var(--faint);margin:0 12px 9px}
.nav-group a{display:flex;align-items:center;gap:11px;padding:8px 11px;margin:3px 0;text-decoration:none;color:var(--soft);font-size:13px;border:1px solid transparent;border-radius:6px}
.nav-group a:hover{background:#1b2836;color:var(--ink)}
.nav-group a[aria-current=page]{background:#18312f;color:var(--accent);border-color:#294b44}
.nav-icon{font:10px var(--mono);color:var(--faint);border:1px solid var(--rule);border-radius:4px;width:23px;height:23px;display:grid;place-items:center}
[aria-current=page] .nav-icon{color:var(--accent);border-color:#3b655a}
.demo-link{margin-top:auto;border:1px solid var(--rule);border-radius:8px;padding:13px;text-decoration:none;background:var(--panel)}
.demo-link>span{display:block;font:10px var(--mono);text-transform:uppercase;color:var(--faint);letter-spacing:1px;margin-bottom:5px}
.demo-link strong{font-size:12px;font-weight:500}.demo-link strong span{color:var(--accent)}
.local-status{font-size:11px;padding:20px 5px 0;color:var(--soft)}.local-status small{display:block;font-size:10px;margin:5px 0 0 14px;color:var(--faint)}
.dot{display:inline-block;width:6px;height:6px;background:var(--accent);border-radius:50%;margin-right:7px;vertical-align:middle}
.workspace{margin-left:238px;min-width:0}.topbar{height:66px;border-bottom:1px solid var(--rule);display:flex;align-items:center;justify-content:space-between;padding:0 38px;color:var(--faint);font-size:12px}
.topbar b{color:var(--ink);font-weight:500}.crumb{margin:0 14px;color:#526277}.offline{border:1px solid var(--rule);border-radius:20px;padding:5px 10px;font-size:10px;color:var(--soft)}
.app .wrap{max-width:1240px;padding:28px 38px 22px;margin:auto}.page-meta{display:flex;justify-content:space-between;gap:1rem;font:10px var(--mono);letter-spacing:1px;color:var(--faint);margin:0 0 27px}
h1{font-size:32px;line-height:1.18;letter-spacing:-1.1px;border:0;padding:0;margin:0 0 12px;max-width:850px}
h2{font-size:18px;border:0;padding:0;margin:0 0 10px}.lead{color:var(--soft);max-width:660px;font-size:14px;margin:0 0 25px;line-height:1.75}
.eyebrow{color:var(--accent);font:10px var(--mono);letter-spacing:1.6px;text-transform:uppercase;margin:0 0 14px}
.hero{display:grid;grid-template-columns:1fr auto;align-items:center;gap:30px;margin:0 0 25px}.hero h1{font-size:42px;max-width:580px}.hero h1 em{font-style:normal;color:var(--accent)}
.hero .lead{margin-bottom:0}.hero-mark{width:126px;height:126px;border:1px solid #355044;border-radius:50%;position:relative;display:grid;place-items:center;background:#12241f}
.hero-mark:before{content:"";position:absolute;inset:12px;border:1px dashed #3a6354;border-radius:50%}.hero-mark span{color:var(--accent);font:500 38px var(--mono)}
.metrics{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin:25px 0}
.metric{padding:18px 20px;background:var(--panel);border:1px solid var(--rule);border-radius:8px}.metric strong{display:block;font:500 28px/1.2 var(--mono);letter-spacing:-1px;margin-bottom:7px}.metric span{color:var(--soft);font-size:12px}.metric small{display:block;color:var(--faint);font:10px var(--mono);margin-top:8px}
.panel{border:1px solid var(--rule);border-radius:9px;background:var(--panel);padding:24px;margin:0 0 20px}.panel-heading{display:flex;justify-content:space-between;gap:15px;align-items:baseline;margin-bottom:12px}.panel-heading span{font:10px var(--mono);color:var(--faint);text-transform:uppercase;letter-spacing:1px}
form{margin:20px 0 26px}label{display:block;color:var(--soft);font-size:12px;font-weight:500;margin:0 0 7px}
input[type=text],select{width:100%;max-width:42rem;min-height:44px;padding:11px 13px;font:14px var(--sans);color:var(--ink);background:#0c141e;border:1px solid #3b4b5e;border-radius:6px}
input::placeholder{color:#8192a7}input[type=text]:focus,select:focus{outline:2px solid var(--accent);outline-offset:2px}
button,.button{display:inline-flex;align-items:center;justify-content:center;min-height:44px;padding:10px 19px;background:var(--accent);color:#10251e;border:1px solid var(--accent);border-radius:6px;font:600 13px var(--sans);cursor:pointer;text-decoration:none;white-space:nowrap;margin-top:12px}
button:hover,.button:hover{background:#a0efd1;color:#10251e;border-color:#a0efd1}.button.secondary{background:transparent;border-color:var(--rule);color:var(--soft)}.button.secondary:hover{background:#1e2d3e;color:var(--ink)}
.search-form{margin:0}.search-line{display:flex;gap:10px}.search-line input{max-width:none}.search-line button{margin:0;min-width:138px}.helper{font-size:12px;color:var(--faint);margin:10px 0 0}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:16px;align-items:center}.chips>span{color:var(--faint);font-size:11px;margin-right:3px}.chip{border:1px solid var(--rule);background:#172331;border-radius:5px;padding:5px 10px;font:11px var(--mono);color:var(--soft);text-decoration:none}.chip:hover{border-color:var(--accent)}
.split{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(0,1fr);gap:20px}.split .panel{margin:0}.steps{list-style:none;padding:0;margin:20px 0 0;display:grid;gap:20px}.steps li{display:flex;gap:13px}.step-number{font:11px var(--mono);color:var(--accent);border:1px solid #355349;background:#142923;border-radius:50%;min-width:27px;height:27px;display:grid;place-items:center}.steps b{font-size:13px;font-weight:500}.steps p{font-size:12px;color:var(--faint);margin:3px 0 0}
.example{display:flex;align-items:center;justify-content:space-between;padding:15px 0;text-decoration:none;border-bottom:1px solid var(--rule)}.example:last-child{border:0;padding-bottom:0}.example strong{font-size:13px;font-weight:500}.example small{display:block;color:var(--faint);font-size:11px;margin-top:4px}.example .arrow{color:var(--accent);margin-left:10px}
.section-title{display:flex;align-items:baseline;justify-content:space-between;margin:26px 0 14px}.section-title span{font:11px var(--mono);color:var(--faint)}
.rows{display:grid;gap:10px}.hit{display:block;border:1px solid var(--rule);border-radius:7px;background:var(--panel);padding:17px 19px;text-decoration:none;color:var(--ink)}.hit:hover{border-color:var(--accent);background:#172534}.hit .w{display:block;font:11px/1.7 var(--mono);color:var(--faint);margin-top:7px}.empty{color:var(--soft);font-size:14px}
.form-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}.form-grid input{max-width:none}.form-grid>div:last-child{grid-column:1/-1}.candidate-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.candidate-grid input{max-width:none}.order-field{margin-bottom:18px;max-width:100%}.order-field input{max-width:none}.form-panel{background:var(--panel);border:1px solid var(--rule);padding:22px;border-radius:9px}.form-panel>p:first-child{margin-top:0}.form-divider{font-size:11px;color:var(--faint);margin:17px 0}.form-panel .helper{max-width:none}
.site-context{margin-top:24px}.site-context h3{margin-bottom:12px}
.site-context .form-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:20px}
.site-context .form-grid>div:last-child{grid-column:auto}
.site-context label{display:block;min-height:2.8em}
@media(max-width:640px){.site-context .form-grid{grid-template-columns:1fr}.site-context label{min-height:0}}

.form-options{padding:14px 0;border-width:1px 0 0;border-radius:0;background:transparent;margin:18px 0}
.form-options .helper{margin-bottom:16px}.form-options .candidate-grid{margin-top:16px}
.form-options summary{font-weight:600}.form-options .form-grid{margin-top:18px}
.lookup-form{max-width:58rem}.lookup-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}
.lookup-grid input{max-width:none}.lookup-edit{margin:18px 0}.lookup-edit form{margin-bottom:0}
.supplier-questions{max-width:75ch;padding-left:24px}.supplier-questions>li{padding:16px 0;border-bottom:1px solid var(--rule)}
.supplier-questions>li>p{margin:0 0 12px;line-height:1.75}.supplier-questions details{background:transparent;border:0;padding:0;margin:10px 0}
.supplier-questions details p,.supplier-questions details li{font-size:13px;color:var(--soft)}
.assumption-summary{max-width:75ch;font-size:13px;line-height:1.75;margin:18px 0;color:var(--soft)}
.assumption-summary b{color:var(--ink);font-weight:600}
@media(max-width:700px){.lookup-grid{grid-template-columns:1fr}.lookup-form button{width:100%}}
.assessment-edit,.assessment-downloads{margin:12px 0}.assessment-edit .form-panel{border:0;padding:0}
.block .verdict .review-required{font-size:14px}.score-scope{font-size:14px;line-height:1.7}
.score-scope b{font-weight:600}.block .coverage{border:0;border-block:1px solid var(--rule);border-radius:0;background:transparent}
fieldset{border:1px solid var(--rule);border-radius:7px;padding:16px;margin:0 0 15px;min-width:0}legend{font:11px var(--mono);color:var(--accent);padding:0 8px}.actions{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:18px 0}.actions .button{margin:0}
details{border:1px solid var(--rule);border-radius:7px;padding:16px 20px;background:var(--panel);margin:20px 0}summary{cursor:pointer;font-size:13px;color:var(--soft)}details[open]>summary{margin-bottom:20px}
.block{border-left:3px solid var(--vc);padding:0 0 0 20px;margin-top:28px}.block h2{font-size:23px;overflow-wrap:anywhere}.verdict{border-radius:7px;padding:20px}.verdict .v{font-size:22px}.verdict .s{font-size:28px}.verdict .n{font-size:12px}.gate,.note,.stability{border-radius:5px;font-size:13px}.gate .src{color:var(--soft)}
th,td{padding:12px;font-size:12px}th{font-size:10px;letter-spacing:.5px}table{border-radius:7px}.tw{border-radius:7px}.ev{font-size:12px}.meta{font-size:10px;letter-spacing:.5px}.bar{border:0;height:6px;border-radius:10px}.bar i{border-radius:10px}.note{line-height:1.7}.tnote{font-size:11px}.src,.sources{overflow-wrap:anywhere}
pre{font-size:12px;line-height:1.8;overflow-wrap:anywhere;padding:20px;background:var(--panel);border:1px solid var(--rule);border-radius:8px}.notice{padding:14px 18px;border:1px solid #4e4531;border-radius:7px;background:#252219;color:#e1c68e;font-size:12px;margin:15px 0}
.reading-summary{max-width:75ch;margin:26px 0}.reading-summary p{font-size:14px;line-height:1.75}.subject{overflow-wrap:anywhere;margin-top:28px}
.reading-facts{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px 30px;margin:24px 0;padding:20px 0;border-block:1px solid var(--rule)}
.reading-facts dt{font-size:12px;color:var(--soft)}.reading-facts dd{margin:4px 0 0;font-size:17px;font-weight:600;overflow-wrap:anywhere}
.priority-list dt,.term-list dt{font-weight:600;margin-top:18px}.priority-list dd,.term-list dd{margin:5px 0 16px;max-width:75ch;color:var(--soft);line-height:1.75}
caption{text-align:left;padding:12px;color:var(--soft);font-size:12px}.result-help{max-width:75ch;line-height:1.75}
@media(max-width:700px){.reading-facts{grid-template-columns:1fr}.reading-summary p{font-size:14px}.reading-facts dd{font-size:16px}}
/* Inline prose and footer links sit in small type, which on a touch screen
   leaves a 12-15px tap target -- under the 24px WCAG 2.5.8 floor, and fiddly
   for anyone holding a tablet in a plant. Give them a real height on small
   screens without disturbing the desktop line height. Buttons and form
   controls already carry 44px of their own. */
@media(max-width:700px){
 .helper a,footer a,.empty a,.tnote a{display:inline-block;min-height:24px;line-height:24px}
}
.demo-cards{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.demo-cards .panel{margin:0}.demo-cards .step-number{margin-bottom:18px;width:30px}.demo-cards p{font-size:13px;color:var(--soft)}
footer{display:flex;justify-content:space-between;gap:15px;flex-wrap:wrap;border-top:1px solid var(--rule);margin-top:30px;padding-top:20px;font-size:10px;color:var(--faint)}.muted{color:var(--faint)}
@media(min-width:1500px){.hero h1{font-size:48px}.app .wrap{padding-top:36px}}
@media(max-width:1100px){.sidebar{width:205px;padding:24px 13px}.workspace{margin-left:205px}.app .wrap{padding:24px}.topbar{padding:0 24px}.hero h1{font-size:36px}.hero-mark{width:90px;height:90px}.brand{font-size:22px}.brand small{font-size:7px}.split{grid-template-columns:1fr}.form-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.form-grid>div:last-child{grid-column:1/-1}}
@media(max-width:700px){.sidebar{position:static;width:auto;padding:18px;display:block}.brand{margin:0 0 16px}.sidebar nav{display:flex;overflow-x:auto;gap:16px}.nav-group{display:flex;gap:4px;margin:0;flex-shrink:0}.nav-label,.nav-icon,.demo-link,.local-status{display:none}.nav-group a{font-size:12px;padding:9px;white-space:nowrap}.workspace{margin:0}.topbar{height:50px;padding:0 18px}.app .wrap{padding:22px 18px}.page-meta{font-size:9px;letter-spacing:.4px}.hero h1{font-size:33px}.hero-mark{display:none}.hero{display:block}.metrics{gap:8px}.metric{padding:13px 10px}.metric strong{font-size:22px}.metric span{font-size:10px}.metric small{display:none}.panel{padding:18px}.search-line{flex-direction:column}.search-line button{width:100%}.form-grid,.candidate-grid{grid-template-columns:1fr}.form-panel{padding:16px}.demo-cards{grid-template-columns:1fr}.block{padding-left:10px}.verdict{padding:15px;gap:12px}.offline{font-size:9px}.lead{font-size:13px}h1{font-size:29px}.panel-heading{flex-wrap:wrap;gap:3px}.topbar .crumb{margin:0 7px}}
@media print{.sidebar,.topbar,.page-meta,.actions,form,details:has(form),.skip{display:none!important}.workspace{margin:0}.app .wrap{max-width:none;padding:0}.app{--field:#fff;--panel:#fff;--sunk:#eee;--rule:#aaa;--ink:#111;--soft:#444;--faint:#555;--prefer:#176145;--cond:#805600;--avoid:#9a2424;background:#fff;color:#111}h1{font-size:25px}footer{color:#444}.block{break-inside:auto}.hero-mark{display:none}}
@media(max-width:700px){.sidebar .desktop-nav{display:none}.mobile-menu{display:block;margin:0;padding:10px 13px}.mobile-menu summary{font-size:12px;min-height:44px;display:flex;align-items:center;cursor:pointer}.mobile-menu nav{display:block;overflow:visible}.mobile-menu .nav-group{display:block;margin:15px 0}.mobile-menu .nav-label{display:block;margin-left:9px}.mobile-menu .nav-group a{white-space:normal}.mobile-menu>a{display:block;font-size:12px;padding:10px}.sidebar{border-bottom:1px solid var(--rule)}}
"""
