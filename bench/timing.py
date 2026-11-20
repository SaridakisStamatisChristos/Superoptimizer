"""Measure alternating single-process benchmark runs on one logical CPU."""

import argparse
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def measure(command):
    start = time.perf_counter()
    result = subprocess.run(command, cwd=ROOT, capture_output=True, check=True)
    elapsed = time.perf_counter() - start
    json.loads(result.stdout)
    return round(elapsed, 4)


def race(fixture, gasol, repeats):
    cpu = min(os.sched_getaffinity(0))
    os.sched_setaffinity(0, {cpu})
    commands = {
        "ours": [sys.executable, "superopt.py", "bench", str(fixture),
                 "--max-steps", "8", "--max-states", "16", "--stitch", "--extra-stack", "2"],
        "gasol": [sys.executable, "bench/competitors.py", "gasol", str(gasol),
                  str(fixture), "--timeout", "2"],
    }
    results = {key: [] for key in commands}
    for index in range(repeats):
        order = list(commands) if index % 2 == 0 else list(reversed(commands))
        for key in order:
            results[key].append(measure(commands[key]))
    return {
        "fixture": fixture.name, "repeats": repeats, "cpu": cpu,
        "wall_seconds": results,
        "median_seconds": {key: statistics.median(values) for key, values in results.items()},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("gasol", type=Path)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    print(json.dumps(race(args.fixture.resolve(), args.gasol.resolve(), args.repeats), indent=2))


if __name__ == "__main__":
    main()
