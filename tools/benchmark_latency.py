"""Repeat the frozen benchmark's command cases without changing its snapshot."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import time
from datetime import date

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--runs', type=int, default=20)
    args = parser.parse_args()
    if args.runs < 2:
        parser.error('--runs must be at least 2')
    baseline = json.loads((ROOT / 'docs/benchmarks/latency.json').read_text())
    db = ROOT / 'data/retrust.db'
    cpu = platform.processor() or 'unknown'
    if Path('/proc/cpuinfo').exists():
        cpu = next((line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), cpu)
    result = dict(date=str(date.today()), platform=platform.platform(), python=platform.python_version(), cpu=cpu, logical_cpus=os.cpu_count(), method=baseline['method'].replace('20 serial', f'{args.runs} serial'), database_bytes=db.stat().st_size, database_sha256=hashlib.sha256(db.read_bytes()).hexdigest(), results=[])
    for case in baseline['results']:
        command = case['command']
        subprocess.run(command, cwd=ROOT, stdout=subprocess.DEVNULL, check=True)
        elapsed = []
        for _ in range(args.runs):
            start = time.perf_counter()
            subprocess.run(command, cwd=ROOT, stdout=subprocess.DEVNULL, check=True)
            elapsed.append((time.perf_counter() - start) * 1000)
        result['results'].append(dict(case=case['case'], command=command, runs=args.runs, median_ms=round(statistics.median(elapsed), 2), p95_ms=round(sorted(elapsed)[math.ceil(.95 * args.runs)-1], 2), min_ms=round(min(elapsed), 2), max_ms=round(max(elapsed), 2), samples_ms=elapsed))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(args.output)


if __name__ == '__main__':
    main()
