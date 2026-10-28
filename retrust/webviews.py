"""Plain-language website views over the same evidence used by the terminal."""

import html
from collections import Counter

import re

from . import components, dossier, lev, ssvc, timeline


def _esc(value):
    return html.escape(str(value), quote=True)


# Layout for the secondary pages. The shared stylesheet (webui.PAGE_CSS) is not
# this module's to edit, so these rules ship as a constant that webui appends
# after PAGE_CSS. Tokens only; 12px floor; radii from the token scale.
CSS = """
.rt-counts{font-family:var(--font-mono);font-size:.8125rem;line-height:1.5;color:var(--muted);margin:var(--s12) 0 0}
.rt-searchbox{max-width:48rem}
.rt-searchbox .search-line{align-items:flex-start}
.rt-searchbox .search-line .rt-btn{margin-top:26px}
.rt-searchbox .rt-field{flex:1 1 auto;min-width:0}
.rt-searchbox .rt-input{min-height:48px;max-width:none;font-family:var(--font-mono);font-size:1rem}
.lookup-form .rt-input--mono{font-family:var(--font-mono);font-size:.8125rem}
.lookup-form .rt-btn{margin-top:var(--s12)}
.rt-searchbox .rt-btn{min-height:48px}
.hit.hit--product{display:grid;grid-template-columns:minmax(8rem,16rem) minmax(0,1fr) auto;gap:var(--s2) var(--s16);align-items:baseline;min-height:40px}
.hit__id{font-family:var(--font-mono);font-size:.8125rem;color:var(--action);overflow-wrap:anywhere}
.hit__id--solo{grid-column:1/3}
.hit__name{color:var(--text-2);overflow-wrap:anywhere}
.hit__vendor{grid-column:3;justify-self:end;text-align:right;font-family:var(--font-mono);font-size:.75rem;color:var(--muted)}
.hit .hit__m{color:var(--text);font-weight:600}
.hit.hit--product .w{grid-column:1/-1;margin:0}
.rt-sample{display:flex;flex-wrap:wrap;gap:var(--s8);align-items:center;margin:var(--s12) 0 0}
.rt-sample>span{color:var(--muted);font-size:.8125rem}
.rt-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(11rem,1fr));gap:var(--s12);margin:var(--s16) 0;padding:0;border:0}
.rt-stat{padding:var(--s12) var(--s16);background:var(--surface);border:1px solid var(--rule);border-radius:var(--r-card)}
.rt-stat dt{font-size:.75rem;color:var(--muted)}
.rt-stat dd{margin:var(--s4) 0 0;font-family:var(--font-mono);font-size:1.125rem;font-weight:500;font-variant-numeric:tabular-nums;color:var(--text);overflow-wrap:anywhere}
.rt-qcard{max-width:75ch}
.rt-qlist{list-style:decimal;margin:0;padding-left:var(--s32)}
.rt-qlist>li{padding:var(--s12) 0;border-bottom:1px solid var(--rule-row)}
.rt-qlist>li::marker{font-family:var(--font-mono);font-size:.75rem;color:var(--muted)}
.rt-q__row{display:flex;justify-content:space-between;align-items:flex-start;gap:var(--s16)}
.rt-q__text{margin:0;font-size:.875rem;line-height:1.6;color:var(--text)}
.rt-q__tag{flex:none;font-family:var(--font-mono);font-weight:600;font-size:.75rem;line-height:1.6;letter-spacing:.06em;color:var(--verify);white-space:nowrap}
.rt-q__foot{display:flex;flex-wrap:wrap;gap:var(--s8);margin-top:var(--s16)}
.rt-qcard details{background:transparent;border:0;padding:0;margin:var(--s4) 0 0}
.rt-qcard summary{min-height:0;padding:var(--s4) 0;font-size:.8125rem}
.rt-h3{margin-top:var(--s24)}
.rt-related{margin:0 0 var(--s20);font-size:.8125rem}
.rt-formula{font-family:var(--font-mono);font-size:.8125rem;overflow-wrap:anywhere}
.rt-about-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:var(--s16);margin:0 0 var(--s16)}
.rt-about-grid .rt-card{margin:0}
.rt-section{margin:var(--s24) 0 0}
.rt-section>h2{margin-bottom:var(--s12)}
@media(max-width:639px){
.hit.hit--product{grid-template-columns:minmax(0,1fr)}
.hit__id--solo,.hit__vendor{grid-column:1}
.hit__vendor{justify-self:start;text-align:left}
.section-title{flex-wrap:wrap;gap:var(--s4) var(--s12)}
.rt-q__row{flex-direction:column;gap:var(--s4)}
.rt-qlist{padding-left:var(--s24)}
.rt-about-grid{grid-template-columns:1fr}
.rt-searchbox .search-line{flex-direction:column;align-items:stretch}
.rt-searchbox .search-line .rt-btn{margin-top:0}
}
"""


def highlight(text, query):
    """Escape `text`, wrapping the parts that match the query in <strong>.

    Matching runs on the raw text and each piece is escaped separately: escaping
    first would let a query such as "amp" match inside "&amp;".
    """
    text = str(text)
    words = sorted({w for w in str(query or "").split() if w}, key=len, reverse=True)
    whole = str(query or "").strip()
    needles = ([whole] if whole and whole not in words else []) + words
    if not needles:
        return _esc(text)
    pattern = re.compile("(" + "|".join(re.escape(n) for n in needles) + ")", re.I)
    return "".join(
        f'<strong class="hit__m">{_esc(piece)}</strong>' if index % 2 else _esc(piece)
        for index, piece in enumerate(pattern.split(text)) if piece)


def search_row(href, ident, name="", vendor="", meta="", query=""):
    """One result row (spec 4.3): order number or name, product, vendor right.

    Without an order number the product name takes the Mono slot and the Sans
    slot is left out, so the same string is never printed twice.
    """
    if name:
        main = (f'<span class="hit__id">{highlight(ident, query)}</span>'
                f'<span class="hit__name">{highlight(name, query)}</span>')
    else:
        main = f'<span class="hit__id hit__id--solo">{highlight(ident, query)}</span>'
    return (f'<a class="hit hit--product" href="{_esc(href)}">{main}'
            + (f'<span class="hit__vendor">{highlight(vendor, query)}</span>' if vendor else '')
            + (f'<span class="w">{_esc(meta)}</span>' if meta else '') + '</a>')


def _percent(value):
    if value is None:
        return "Not available"
    if 0 < value < .001:
        return 'Under 0.1%'
    return 'Over 99.9%' if .999 < value < 1 else f"{value:.1%}"


def _count(number, singular, plural=None):
    return f"{number:,} {singular if number == 1 else plural or singular + 's'}"


def _confirmation(in_kev, kev_loaded):
    return ('Confirmed by CISA' if in_kev else
            'Not listed by CISA' if kev_loaded else 'Not checked — CISA records unavailable')


def stat_tiles(items):
    """Label/value tiles: muted label, Mono value.

    reading-facts stays as a second class so a page rendered without CSS above
    still lays the pairs out as a grid.
    """
    return '<dl class="reading-facts rt-stats">' + ''.join(
        f'<div class="rt-stat"><dt>{_esc(label)}</dt><dd>{_esc(value)}</dd></div>'
        for label, value in items) + '</dl>'


_facts = stat_tiles


def table(headers, rows, caption, numeric=(), badges=()):
    """The shared scrolling table. `numeric` columns are right-aligned Mono;
    `badges` columns hold a verdict word and are drawn as the verdict badge."""
    def head(index, label):
        css = ' class="n"' if index in numeric else ''
        return f'<th scope="col"{css}>{_esc(label)}</th>'

    def cell(index, value):
        if index in badges:
            return f'<td>{components.verdict_badge(value, "s")}</td>'
        return f'<td class="n">{_esc(value)}</td>' if index in numeric else f'<td>{_esc(value)}</td>'

    return ('<div class="tw" tabindex="0" role="region" '
            f'aria-label="{_esc(caption)}; scroll sideways for more columns">'
            '<p class="table-scroll-hint">Scroll sideways to see all columns →</p>'
            f'<table><caption>{_esc(caption)}</caption><thead><tr>'
            + ''.join(head(i, label) for i, label in enumerate(headers))
            + '</tr></thead><tbody>' + ''.join(
                '<tr>' + ''.join(cell(i, value) for i, value in enumerate(row)) + '</tr>'
                for row in rows) + '</tbody></table></div>')


_table = table


def _technical(text, label="Technical report and source details"):
    return (f'<details><summary>{_esc(label)}</summary>'
            f'<pre style="white-space:pre-wrap">{_esc(text)}</pre></details>')


def exploitation(product, estimates, corpus_share=None, kev_loaded=True):
    """Separate model estimates, public confirmation, and missing history."""
    parts = [f'<h2 class="subject">{_esc(product)}</h2>']
    if not estimates:
        return ''.join(parts) + ('<p>No vulnerabilities were found for this selection, '
            'so there is nothing to estimate. This does not establish that the product is safe.</p>')

    ranked = sorted(estimates, key=lambda e: (-e.lev, -(e.current_epss or 0), e.cve))
    measured = [e for e in ranked if e.observations]
    flagged = [e for e in measured if e.unlisted]
    confirmed = sum(e.in_kev for e in ranked)
    missing = len(ranked) - len(measured)
    parts.append('<section class="reading-summary"><h3 class="rt-h3">What this means</h3>')
    if confirmed:
        parts.append(f'<p>CISA’s public records confirm exploitation of '
                     f'<strong>{_count(confirmed, "vulnerability", "vulnerabilities")}</strong>.</p>')
    elif kev_loaded:
        parts.append('<p>No vulnerabilities in this selection are listed in CISA’s '
                     'confirmed-exploitation catalogue. This does not prove that attacks never happened.</p>')
    else:
        parts.append(components.alert(
            "review", "CISA exploitation records are not loaded",
            "Public confirmation has not been checked."))
    if flagged:
        parts.append(f'<p>The model flags <strong>{_count(len(flagged), "vulnerability", "vulnerabilities")} '
                     'for investigation</strong>. Ask your security team or supplier '
                     'to check whether these issues affect the equipment and whether the fixes are present.</p>')
    elif measured:
        parts.append('<p>No additional vulnerabilities meet this tool’s 10% review threshold. '
                     'Keep checking vendor advisories and updates.</p>')
    if missing:
        parts.append(f'<p><strong>{_count(missing, "vulnerability", "vulnerabilities")} could not be estimated</strong> '
                     'because historical data is missing. Missing data is not a zero estimate.</p>')
    parts.append('<p class="helper">These records concern exploitation of a vulnerability '
                 'somewhere in the world. They do not show that your equipment or organisation was attacked.</p></section>')
    parts.append(_facts([
        ('Historical estimates available', f'{len(measured)} of {len(ranked)}'),
        ('Confirmed in CISA records', str(confirmed) if kev_loaded or confirmed else 'Not checked'),
    ]))
    parts.append('<h3 class="rt-h3">Read each vulnerability</h3><p>A CVE number identifies a known '
                 'security weakness. The percentage is a model estimate of earlier exploitation, '
                 'not a confirmed incident count.</p>')
    parts.append(_table(
        ('Vulnerability (CVE)', 'Estimated past exploitation', 'Public exploitation record'),
        [(e.cve, _percent(e.lev) if e.observations else 'Not estimated',
          _confirmation(e.in_kev, kev_loaded)) for e in ranked[:20]],
        'Estimates and confirmed records are different kinds of evidence'))
    if len(ranked) > 20:
        parts.append(f'<p>Showing the 20 highest estimates out of {len(ranked)} vulnerabilities.</p>')
    parts.append('<details><summary>How to interpret the numbers</summary>')
    if measured:
        parts.append(f'<p>The estimates add up to <strong>{lev.expected_exploited(measured):.1f}</strong> '
                     f'across {len(measured)} vulnerabilities. This is a statistical expected count; '
                     'it does not mean that this many attacks were observed or identify which issues were exploited.</p>')
    parts.append('<p>Older vulnerabilities often have higher estimates because the model combines '
                 'a longer history. A high estimate alone does not prove an attack. '
                 'The 10% threshold is a review flag used here, not confirmation of exploitation.</p>')
    if corpus_share is not None:
        parts.append(f'<p>In the loaded dataset, {corpus_share:.0%} of estimated vulnerabilities '
                     'meet the same review flag. Age and data coverage affect this comparison; '
                     'it is not a product safety ranking.</p>')
    parts.append('<dl><dt>LEV — historical estimate</dt><dd>Combines past attack-likelihood '
                 'estimates using the NIST CSWP 41 method. It is a model-based lower bound.</dd>'
                 '<dt>EPSS — next 30 days</dt><dd>Estimates the chance that a vulnerability '
                 'will be exploited in the next 30 days.</dd>'
                 '<dt>KEV — confirmed exploitation records</dt><dd>CISA’s catalogue records '
                 'vulnerabilities known to have been exploited. Absence from it is not proof of no exploitation.</dd></dl>'
                 '<p>History samples are dated observations, generally about 30 days apart; '
                 'they are not a count of consecutive days monitored. When combined, a confirmed '
                 'CISA record takes precedence over the estimates.</p></details>')
    parts.append(_technical(lev.format_report(product, estimates, corpus_share=corpus_share),
                            'Technical report: LEV, EPSS and historical samples'))
    return ''.join(parts)


# Question.gap codes, spelled out for screen readers next to the visible tag.
GAP_NAMES = {'E': 'exposure', 'P': 'patch availability', 'V': 'vendor practice',
             'C': 'certification', 'ID': 'product identity'}


def _gap_tag(code):
    """`GAP · C` as plain text: the linked form needs the JS layer."""
    if not code:
        return ''
    name = GAP_NAMES.get(code)
    return (f'<span class="rt-q__tag">GAP · {_esc(code)}'
            + (f'<span class="rt-sr"> ({_esc(name)})</span>' if name else '') + '</span>')


def supplier_questions(product, items, export_href='', text_href=''):
    """The supplier-questions panel (spec 4.19) without its script-only parts.

    Copy all and the mark-as-sent checkbox need JavaScript, so the baseline has
    the two links that do not: the plain-text page and the .txt download.
    """
    parts = [f'<h2 class="subject">{_esc(product)}</h2>']
    items = list(items)
    if not items:
        body = '<p class="empty">No open questions. Every material input is verified.</p>'
    else:
        rows = []
        for question in items:
            row = (f'<li><div class="rt-q__row"><p class="rt-q__text">{_esc(question.text)}</p>'
                   f'{_gap_tag(getattr(question, "gap", ""))}</div><details>'
                   '<summary>Why ask this? View supporting evidence</summary>'
                   f'<p>{_esc(question.why)}</p>')
            if question.evidence:
                row += '<ul>' + ''.join(f'<li>{_esc(item)}</li>' for item in question.evidence) + '</ul>'
            rows.append(row + '</details></li>')
        body = '<ol class="supplier-questions rt-qlist">' + ''.join(rows) + '</ol>'
    links = ''.join(filter(None, (
        components.link_button('Open as plain text', text_href, 'secondary') if text_href else '',
        components.link_button('Export as .txt', export_href, 'secondary') if export_href else '')))
    if links:
        body += f'<div class="rt-q__foot">{links}</div>'
    parts.append('<div class="rt-qcard">'
                 + components.card(body, label='Supplier questions') + '</div>')
    parts.append('<details><summary>Terms your supplier may use</summary><dl class="term-list">'
                 '<dt>Firmware</dt><dd>The software running inside the equipment.</dd>'
                 '<dt>Mitigation or workaround</dt><dd>A protective measure used when a permanent fix is not yet in place.</dd>'
                 '<dt>PSIRT</dt><dd>The manufacturer’s team that handles product security issues.</dd>'
                 '<dt>CSAF</dt><dd>A structured format for publishing security notices so tools can read them.</dd>'
                 '<dt>SBOM</dt><dd>A list of the software components included with the product. CycloneDX is one format for this list.</dd>'
                 '<dt>CVE</dt><dd>A reference number for a known security weakness.</dd></dl></details>'
                 '<p class="helper">A long question list does not make a manufacturer less trustworthy. '
                 'Judge the written answers and supporting evidence.</p>')
    return ''.join(parts)


ACCESS_LABELS = {'small': 'Limited access', 'controlled': 'Controlled access', 'open': 'Open access'}
IMPACT_LABELS = {'low': 'Low impact', 'medium': 'Medium impact', 'high': 'High impact', 'very high': 'Very high impact'}


PRIORITIES = {
    'immediate': ('Act now', 'Ask the security and operations teams to review immediately and follow approved response procedures.'),
    'out-of-cycle': ('Fix sooner', 'Plan action before the next regular maintenance window.'),
    'scheduled': ('Plan a routine fix', 'Include the fix in regular scheduled maintenance.'),
    'defer': ('Monitor and reassess', 'No immediate change is recommended by this decision tree; reassess when evidence or conditions change.'),
}


def response_priority(product, decisions, exposure, automatable, impact, undecided=0, kev_loaded=True):
    parts = [f'<h2 class="subject">{_esc(product)}</h2>',
             '<p class="helper">These timings use assumptions, not a network inspection. '
             'Confirm them with your technical team.</p>',
             '<p class="assumption-summary"><b>Access assumed:</b> '
             f'{_esc(ACCESS_LABELS.get(exposure, exposure))}. '
             '<b>Automated attack assumed possible:</b> '
             + ('Yes' if automatable == 'yes' else 'No') + '. '
             f'<b>Operational impact assumed:</b> {_esc(IMPACT_LABELS.get(impact, impact))}.</p>']
    if not decisions:
        return ''.join(parts) + '<p>No vulnerabilities are available to prioritise for this selection.</p>'
    if not kev_loaded:
        parts.append(components.alert(
            "review", "CISA exploitation records are not loaded",
            "The response recommendations have incomplete exploitation evidence."))
    counts = Counter(d.outcome for d in decisions)
    parts.append('<h3 class="rt-h3">What to do next</h3><dl class="priority-list">')
    for key in sorted(counts, key=ssvc.PRIORITY.get):
        label, action = PRIORITIES[key]
        parts.append(f'<dt>{_esc(label)} · {_count(counts[key], "vulnerability", "vulnerabilities")}</dt>'
                     f'<dd>{_esc(action)}</dd>')
    parts.append('</dl>')
    if undecided:
        parts.append(components.alert(
            "review", "Firmware applicability is unconfirmed",
            f'Whether your firmware is affected remains unconfirmed in '
            f'{_count(undecided, "advisory entry", "advisory entries")}. '
            'Verify the firmware before deciding that a vulnerability applies.'))
    parts.append('<p>Public exploit code is not checked by this tool. Missing that evidence '
                 'can make a response look less urgent than it should be; review the supplier’s '
                 'advisories before acting.</p>')
    parts.append(_table(
        ('Vulnerability (CVE)', 'Suggested response', 'Public exploitation record'),
        [(d.cve, PRIORITIES[d.outcome][0], _confirmation(d.in_kev, kev_loaded))
         for d in decisions[:20]], 'Response recommendations for individual vulnerabilities'))
    if len(decisions) > 20:
        parts.append(f'<p>Showing the first 20 of {len(decisions)} vulnerabilities, with the most urgent first.</p>')
    parts.append(_technical(ssvc.format_report(product, decisions, exposure, automatable, impact,
                                               undecided=undecided), 'Technical decision details (SSVC)'))
    return ''.join(parts)


def advisory_history(subject, history):
    parts = [f'<h2 class="subject">{_esc(subject)}</h2>']
    if not history.advisories:
        return ''.join(parts) + '<p>No security notices are available for this selection. Check the product name and ask the supplier for its advisory history.</p>'
    parts.append(_facts([
        ('Security notices', f'{history.advisories:,}'),
        ('Distinct vulnerabilities', f'{history.cves:,}'),
        ('First notice', history.first or 'Date unavailable'),
        ('Most recent notice', history.last or 'Date unavailable'),
    ]))
    parts.append(_table(
        ('Year', 'Security notices', 'Distinct vulnerabilities', 'Notices offering a fix'),
        [(b.year, b.advisories, b.cves, b.fixed) for b in history.years],
        'Published notices and available fixes by year'))
    parts.append('<p>A notice offering a fix does not mean the fix is installed on your equipment. '
                 'The same vulnerability can appear in more than one year.</p>')
    if history.quiet_months is not None:
        parts.append(f'<p>No newer notice appears for {_count(history.quiet_months, "whole month")}, '
                     f'measured against the dataset’s latest notice date, {_esc(history.as_of)}.</p>')
    if history.undated or history.missing:
        parts.append(f'<p>Outside the yearly table: {_count(history.undated, "notice")} with no date. '
                     f'Missing from this dataset: {_count(history.missing, "referenced notice")}.</p>')
    parts.append(_technical(timeline.format_report(subject, history), 'Technical history and severity details'))
    return ''.join(parts)


def vendor_profile(profile):
    parts = [f'<h2 class="subject">{_esc(profile.vendor)}</h2>']
    if profile.known:
        parts.append(_facts([
            ('Security notices', f'{profile.advisories:,}'),
            ('Distinct vulnerabilities', f'{profile.cves:,}'),
            ('First notice', profile.first_advisory or 'Date unavailable'),
            ('Most recent notice', profile.last_advisory or 'Date unavailable'),
        ]))
    else:
        parts.append('<p>No advisories in this dataset name this manufacturer. Check the name '
                     'or ask the supplier for its security notices; missing data does not establish safety.</p>')
    parts.append('<h3 class="rt-h3">Supplier checks</h3>')
    if profile.screening_gates is None:
        parts.append('<p>Supplier restrictions were not checked because the screening data is not loaded.</p>')
    elif profile.screening_gates:
        for gate in profile.screening_gates:
            parts.append(components.alert(
                "restriction", "Supplier screening match: review before purchase",
                gate["detail"],
                body_html=f'<p class="rt-alert__text">Source: {_esc(gate["source"])}</p>'))
    else:
        parts.append('<p>No supplier restriction match was found in the loaded lists. '
                     'This result applies only to the lists and dates available in this workspace.</p>')
    if profile.screening_gates is not None and not profile.sanctions_checked:
        parts.append(components.alert(
            "review", "Supplier checks are incomplete",
            "The sanctions dataset is not loaded."))
    parts.append('<h3 class="rt-h3">Certification evidence</h3>')
    if profile.certificates is None:
        parts.append('<p>Certification records were not checked because that dataset is not loaded.</p>')
    elif not profile.certificates:
        parts.append('<p>No certificate was found in the loaded records. This does not prove '
                     'that the manufacturer has no certificates.</p>')
    else:
        parts.append(f'<p>{_count(len(profile.certificates), "certificate record")} found. Ask the supplier '
                     'to confirm which certificate covers the exact product and firmware you plan to buy.</p>')
        parts.append(_table(('Scheme', 'Product or scope'),
                            [(c.get('scheme', 'Not stated'), c.get('product') or 'Not stated')
                             for c in profile.certificates[:8]], 'Certificate records to verify with the supplier'))
        if len(profile.certificates) > 8:
            parts.append(f'<p>Showing 8 of {len(profile.certificates)} certificate records.</p>')
    if profile.remediation:
        labels = {'vendor_fix': 'A vendor fix is available', 'mitigation_only': 'Workaround or other protective measure only',
                  'no_fix': 'No fix available', 'nothing_stated': 'Fix status not stated'}
        parts.append('<h3 class="rt-h3">Fixes described in the notices</h3>')
        parts.append(_table(('Best remedy described', 'Security notices'),
                            [(label, profile.remediation.get(key, 0)) for key, label in labels.items()],
                            'Each notice is counted under its best available remedy'))
    parts.append(_technical(dossier.format_report(profile), 'Technical vendor profile and source records'))
    return ''.join(parts)

# Rules for the assess page (empty state, actions row, inputs section). Kept with
# the other page CSS so the shell ships exactly one stylesheet.
ASSESS_CSS = """
.rt-assess-actions{display:flex;flex-wrap:wrap;gap:var(--s8);justify-content:flex-end;align-items:center;margin:var(--s12) 0}
.rt-assess-section{margin-top:var(--s24)}
.rt-assess-section>h2{margin:0 0 var(--s12);font-size:1.125rem;font-weight:600;line-height:1.3}
.rt-assess-section .form-panel{border:0;padding:0;background:transparent}
.rt-assess-lead{margin:var(--s4) 0 var(--s16);color:var(--text-2);max-width:75ch}
.rt-assess-empty{max-width:720px;margin:var(--s24) auto 0}
.rt-assess-empty .rt-empty{padding-bottom:var(--s16)}
.rt-assess-empty .form-panel{width:100%;text-align:left;box-sizing:border-box}
.order-field .rt-input{height:52px;font-size:1.125rem}
.rt-sample{display:flex;flex-wrap:wrap;gap:var(--s8);align-items:center;justify-content:center;margin:var(--s12) 0 0}
.rt-sample span{color:var(--muted);font-size:.8125rem}
.rt-conditions-card{margin:var(--s20) 0 0;padding:var(--s16);border:1px solid var(--rule);border-radius:var(--r-card);background:var(--surface);min-width:0}
.rt-conditions-card>legend{padding:0 var(--s8);font-family:var(--font-mono);font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.rt-conditions-card .rt-conditions{margin-bottom:var(--s12)}
.rt-conditions-card .helper{margin:0 0 var(--s12)}
.rt-conditions-card .form-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:var(--s16)}
.rt-conditions-card .form-grid>div:last-child{grid-column:auto}
.form-panel>.rt-btn{margin-top:var(--s16)}
.rt-questions{list-style:none;margin:var(--s12) 0 0;padding:0;display:flex;flex-direction:column}
.rt-q{display:grid;grid-template-columns:2.5rem minmax(0,1fr) auto;gap:var(--s12);padding:var(--s12) 0;border-top:1px solid var(--rule);align-items:start}
.rt-q:first-child{border-top:0}
.rt-q__n{font-family:var(--font-mono);font-size:.75rem;color:var(--muted);padding-top:var(--s4)}
.rt-q__text{margin:0;font-size:.875rem;line-height:1.45;color:var(--text);overflow-wrap:anywhere}
.rt-q__why{margin-top:var(--s4)}
.rt-q__why summary{font-size:.8125rem;color:var(--text-2)}
.rt-q__why p,.rt-q__why li{font-size:.8125rem;color:var(--text-2);overflow-wrap:anywhere}
.rt-q__gap{font-family:var(--font-mono);font-size:.75rem;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--verify);border:1px dashed var(--verify);border-radius:var(--r-md);padding:var(--s2) var(--s8);text-decoration:none;white-space:nowrap}
a.rt-q__gap:hover{color:var(--action-hover)}
.rt-q__foot{margin:var(--s12) 0 0;display:flex;flex-wrap:wrap;gap:var(--s8)}
.rt-assess-next .rt-related{margin:0;padding:0;list-style:none}
@media(max-width:639px){.rt-conditions-card .form-grid{grid-template-columns:1fr}.rt-assess-actions{justify-content:stretch}.rt-assess-actions>*,.rt-assess-actions .rt-menu,.rt-assess-actions .rt-menu>.rt-btn{width:100%;box-sizing:border-box}.rt-q{grid-template-columns:2rem minmax(0,1fr)}.rt-q__gap{grid-column:2}}
"""
CSS = CSS + ASSESS_CSS
