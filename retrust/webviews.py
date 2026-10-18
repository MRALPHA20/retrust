"""Plain-language website views over the same evidence used by the terminal."""

import html
from collections import Counter

from . import dossier, lev, ssvc, timeline


def _esc(value):
    return html.escape(str(value), quote=True)


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


def _facts(items):
    return '<dl class="reading-facts">' + ''.join(
        f'<div><dt>{_esc(label)}</dt><dd>{_esc(value)}</dd></div>'
        for label, value in items) + '</dl>'


def _table(headers, rows, caption):
    return ('<div class="tw" tabindex="0" role="region" '
            f'aria-label="{_esc(caption)}; scroll sideways for more columns">'
            '<p class="table-scroll-hint">Scroll sideways to see all columns →</p>'
            f'<table><caption>{_esc(caption)}</caption><thead><tr>'
            + ''.join(f'<th scope="col">{_esc(label)}</th>' for label in headers)
            + '</tr></thead><tbody>' + ''.join(
                '<tr>' + ''.join(f'<td>{_esc(cell)}</td>' for cell in row) + '</tr>'
                for row in rows) + '</tbody></table></div>')


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
    parts.append('<section class="reading-summary"><h3>What this means</h3>')
    if confirmed:
        parts.append(f'<p>CISA’s public records confirm exploitation of '
                     f'<strong>{_count(confirmed, "vulnerability", "vulnerabilities")}</strong>.</p>')
    elif kev_loaded:
        parts.append('<p>No vulnerabilities in this selection are listed in CISA’s '
                     'confirmed-exploitation catalogue. This does not prove that attacks never happened.</p>')
    else:
        parts.append('<p class="notice">CISA exploitation records are not loaded. '
                     'Public confirmation has not been checked.</p>')
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
    parts.append('<h3>Read each vulnerability</h3><p>A CVE number identifies a known '
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


def supplier_questions(product, items):
    parts = [f'<h2 class="subject">{_esc(product)}</h2><ol class="supplier-questions">']
    for question in items:
        parts.append(f'<li><p>{_esc(question.text)}</p><details>'
                     '<summary>Why ask this? View supporting evidence</summary>'
                     f'<p>{_esc(question.why)}</p>')
        if question.evidence:
            parts.append('<ul>' + ''.join(f'<li>{_esc(item)}</li>' for item in question.evidence) + '</ul>')
        parts.append('</details></li>')
    parts.append('</ol><details><summary>Terms your supplier may use</summary><dl class="term-list">'
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
        parts.append('<p class="notice">CISA exploitation records are not loaded. '
                     'The response recommendations have incomplete exploitation evidence.</p>')
    counts = Counter(d.outcome for d in decisions)
    parts.append('<h3>What to do next</h3><dl class="priority-list">')
    for key in sorted(counts, key=ssvc.PRIORITY.get):
        label, action = PRIORITIES[key]
        parts.append(f'<dt>{_esc(label)} · {_count(counts[key], "vulnerability", "vulnerabilities")}</dt>'
                     f'<dd>{_esc(action)}</dd>')
    parts.append('</dl>')
    if undecided:
        parts.append(f'<p class="notice">Whether your firmware is affected remains unconfirmed in '
                     f'{_count(undecided, "advisory entry", "advisory entries")}. '
                     'Verify the firmware before deciding that a vulnerability applies.</p>')
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
    parts.append('<h3>Supplier checks</h3>')
    if profile.screening_gates is None:
        parts.append('<p>Supplier restrictions were not checked because the screening data is not loaded.</p>')
    elif profile.screening_gates:
        for gate in profile.screening_gates:
            parts.append(f'<div class="notice"><strong>Supplier screening match — review before purchase.</strong>'
                         f'<p>{_esc(gate["detail"])}</p><p>Source: {_esc(gate["source"])}</p></div>')
    else:
        parts.append('<p>No supplier restriction match was found in the loaded lists. '
                     'This result applies only to the lists and dates available in this workspace.</p>')
    if profile.screening_gates is not None and not profile.sanctions_checked:
        parts.append('<p class="notice">The sanctions dataset is not loaded. Supplier checks are incomplete.</p>')
    parts.append('<h3>Certification evidence</h3>')
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
        parts.append('<h3>Fixes described in the notices</h3>')
        parts.append(_table(('Best remedy described', 'Security notices'),
                            [(label, profile.remediation.get(key, 0)) for key, label in labels.items()],
                            'Each notice is counted under its best available remedy'))
    parts.append(_technical(dossier.format_report(profile), 'Technical vendor profile and source records'))
    return ''.join(parts)
