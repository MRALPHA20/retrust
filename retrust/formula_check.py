"""Independent deployment check over every indexed vendor/model and five scenarios."""
import argparse
import collections
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import sys

from . import cli, identity, index, score, weakness

SCENARIOS = {
    'reachable': dict(network_exposure='it_ot', interface='exposed', prerequisites='satisfiable', consequence='control', remediation='affected'),
    'minor_impact': dict(network_exposure='internet_ot', interface='exposed', prerequisites='satisfiable', consequence='minor', remediation='affected'),
    'verified_blocked': dict(network_exposure='ot_only', interface='blocked', prerequisites='satisfiable', consequence='safety', remediation='affected'),
    'unknown': dict(network_exposure=None, interface='unknown', prerequisites='unknown', consequence=None, remediation='unknown'),
    'unverified_fix': dict(network_exposure='it_ot', interface='exposed', prerequisites='satisfiable', consequence='safety', remediation='not_affected'),
}


def validate(assessment, findings, options, weights, bands):
    """Calculate expected factors, exposure, geometric score and verdict independently."""
    if assessment.score is None:
        assert assessment.verdict in ('NOT ASSESSED', 'AVOID')
        return
    base = [f for f in findings if not f.third_party] or findings
    risks = {}
    for f in base:
        signal = [v for v in (1.0 if f.in_kev or f.ransomware else 0.0 if f.kev_available else None, f.lev, f.epss) if v is not None]
        low = max(signal, default=0.0)
        complete = f.kev_available and f.lev is not None and f.epss is not None
        threat = (low, low if low == 1 or complete else 1.0)
        attack = (0.0, 0.0) if options['interface'] == 'blocked' else (0.0, 1.0) if options['interface'] == 'unknown' else (1.0, 1.0)
        h = {'control': .8, 'minor': .2, 'safety': 1.0}.get(options['consequence'])
        harm = (0.0, 1.0) if h is None else (h, h)
        applicable = (1.0, 1.0) if options['remediation'] == 'affected' or f.decided else (0.0, 1.0)
        z = [math.prod(values[side] for values in (threat, attack, harm, applicable)) for side in (0, 1)]
        previous = risks.setdefault(f.cve, [0.0, 0.0])
        previous[:] = [max(previous[i], z[i]) for i in (0, 1)]
    exposures = []
    for side in (1, 0):
        values = sorted((v[side] for v in risks.values()), reverse=True)
        r = min(1.0, sum(w * v for w, v in zip((1.0, .2, .1), values)))
        exposures.append(100.0 * (1.0 - r))
    for got, want in zip((assessment.exposure_min, assessment.exposure_max), exposures):
        assert math.isclose(got, want, abs_tol=1e-8), ('exposure', got, want)
    assert len(assessment.paths) == len(risks), 'duplicate or missing CVE group'
    for path in assessment.paths:
        expected = risks[path['cves'][0]]
        for got, want in zip((path['z_min'], path['z_max']), expected):
            assert math.isclose(got, want, abs_tol=1e-8), ('path', got, want)
    keys = {p.name: p.key for p in score.PILLARS}
    active = [p for p in assessment.pillars if p.scored and p.name in keys]
    total = sum(weights[keys[p.name]] for p in active)
    raw = [math.exp(math.fsum(weights[keys[p.name]] / total * math.log(max(1.0, exposure if p.name == 'Exposure' else p.score)) for p in active)) for exposure in exposures]
    unfixable = {f.cve for group in weakness.classify(base) if group.name in weakness.UNMITIGABLE for f in base if f.cve in group.cves and not f.fixed}
    prefer = bands[0][0]
    if unfixable:
        raw = [min(value, prefer - .1) for value in raw]
    for got, want in zip((assessment.score_min, assessment.score_max), raw):
        assert math.isclose(got, round(want, 1), abs_tol=1e-8), ('score', got, want)
    assert assessment.score == assessment.score_min
    expected = 'AVOID' if assessment.gates else 'VERIFY' if assessment.provisional else next(label for threshold, label in bands if raw[0] >= threshold)
    assert assessment.verdict == expected, ('verdict', assessment.verdict, expected)


def run(db='data/retrust.db', data_dir='data'):
    connection = index.connect_readonly(db)
    context = cli._context(data_dir)
    counts = collections.Counter()
    failures = []
    try:
        rows = connection.execute('SELECT MIN(vendor) vendor, MIN(name) name FROM product GROUP BY vendor_key, name_key ORDER BY vendor_key, name_key').fetchall()
        for row in rows:
            counts['products_checked'] += 1
            try:
                a, resolution, findings = cli._assess(connection, row['vendor'], row['name'], None, None, context=context, **SCENARIOS['reachable'])
                if not resolution.resolved:
                    assert a.score is None
                    counts['unresolved_products'] += 1
                    continue
                counts['resolved_products'] += 1
                validate(a, findings, SCENARIOS['reachable'], context['weights'], context['bands'])
                counts['assessments_checked'] += 1
                if a.score is None: counts['unscored_assessments'] += 1
                if not a.inputs: continue
                fs, advisories, certificates, gates, vendor_key = a.inputs
                for name, options in list(SCENARIOS.items())[1:]:
                    result = score.assess(a.product, fs, advisories, certificates=certificates, screening_gates=gates,
                                          vendor_key=vendor_key, weights=context['weights'], bands=context['bands'], **options)
                    validate(result, fs, options, context['weights'], context['bands'])
                    counts['assessments_checked'] += 1
                    if result.score is None: counts['unscored_assessments'] += 1
            except Exception as error:
                counts['failures'] += 1
                if len(failures) < 30: failures.append(dict(vendor=row['vendor'], product=row['name'], error=repr(error)))
            if counts['products_checked'] % 2000 == 0:
                print(f"Formula check: {counts['products_checked']}/{len(rows)} products; {counts['failures']} failures", flush=True)
        assert counts['products_checked'] > 0, 'empty product index'
        return dict(passed=not counts['failures'], model_version=score.SCORING_VERSION,
                    source_build=identity.build_fingerprint(), data_fingerprint=identity.data_fingerprint(connection, data_dir),
                    checked_at=datetime.now(timezone.utc).isoformat(), counts=dict(counts), failures=failures,
                    scope='Every indexed vendor/model; reachable, minor impact, verified blocked, unknown and unverified-fix scenarios. Unresolved identities remain unscored. Arithmetic consistency, not predictive accuracy.')
    finally:
        connection.close()
        context['screening'].close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', default='data/retrust.db')
    parser.add_argument('--data', default='data')
    parser.add_argument('--output', default='data/formula-validation.json')
    args = parser.parse_args()
    result = run(args.db, args.data)
    Path(args.output).write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2), flush=True)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
