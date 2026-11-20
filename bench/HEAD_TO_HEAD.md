# EVM superoptimizer v0.4 head-to-head benchmark

The benchmark measures isolated stack windows. Gas-first compares aggregate
runtime gas saved and allows code growth. Compact-gas forbids byte growth
within each rewrite. Size-first compares bytes saved while requiring
nonincreasing gas. The two compact objectives compare different selections
of replacements. Every scored replacement passed a 256-bit Z3
counterexample query. The adjudicator also runs FORVES as a separate
semantic-equivalence check and records its coverage.

| Suite | Windows | Gas-first gas saved | Compact-gas saved | Size-first bytes saved |
| --- | ---: | ---: | ---: | ---: |
| Optimized Solidity | 143 | 177 / 27 | 42 / 27 | 30 / 19 |
| Original public sample | 96 | 342 / 109 | 112 / 109 | 44 / 48 |
| Second public sample | 96 | 413 / 124 | 122 / 124 | 50 / 54 |
| Third public sample | 96 | 373 / 109 | 109 / 109 | 46 / 48 |
| **GASOL aggregate** | **431** | **1305 / 369** | **385 / 369** | **170 / 169** |
| Recorded ebso sample | 96 | 104 / 20 | 102 / 20 | 52 / 9 |

Each pair lists v0.4 first and the baseline second.

| Suite | Fast-profile gas saved, v0.4 / GASOL | Median wall time, v0.4 / GASOL | Speedup |
| --- | ---: | ---: | ---: |
| Optimized Solidity | 174 / 27 | 0.65 s / 2.42 s | 3.73× |
| Original public sample | 320 / 109 | 1.29 s / 9.92 s | 7.72× |
| Second public sample | 372 / 124 | 1.57 s / 5.87 s | 3.74× |
| Third public sample | 355 / 109 | 1.65 s / 7.36 s | 4.45× |

The v0.4 gas-first result adds a net 1,620 bytes across the four GASOL
suites. The compact-gas result saves 135 bytes across those same suites.
The original v0.3 compact score on the original public sample was 88 gas.
v0.4 reaches 112 gas on that sample. The GASOL rerun scored 109 gas.
The independent EthereumJS oracle matched 7,011 executions, and all 14
unit tests passed.

## Method

GASOL runs in gas and size modes with OptiMathSAT and a two-second solver
cap in each mode. GASOL gets the better valid output per case under the
scored objective. ebso uses recorded outputs from the public ppltr
artifact. Its comparison uses legacy scoring and translates any proposed
`PUSH0` from our tool to `PUSH1 0x00` before scoring. These results concern
a shared opcode subset and the given entry heights. They do not measure
whole-contract savings or memory and storage optimizations.

The 143 solc cases are all the compiler fixture windows GASOL can ingest
byte-for-byte. The three public samples each contain 96 unique windows from
the same deterministic hash ranking of `GASOL_gas_simp.txt`. The first is
the original v0.3 public corpus. The second was used during development.
The third is a disjoint sample introduced for this release. The corpus is
drawn from the FORVES evaluation of GASOL. The ebso sample is selected by
hash of original code and entry height from its recorded corpus.

Gas-first uses 1,000 whole-window states and up to two additional stack
slots. Compact-gas and size-first use 1,500 states and up to one additional
slot. All use a whole-window step cap of eight. The scheduler is capped at
eight times the states setting, with an absolute limit of 12,000. The fast
gas-first profile uses 16 whole-window states, up to 128 scheduler states,
and two extra slots. Rewrites that use extra slots specify a tighter
maximum permitted entry height in the certificate.

Timing compares one fresh optimizer process against one fresh GASOL
gas-mode process on the same machine, with their children restricted to
one logical CPU. The harness alternates tool order, reports the median of
three end-to-end wall times, and excludes external Z3/FORVES scoring.
The fast-profile quality comparison still credits GASOL with the better
output of its two modes. ebso timing is unavailable from this protocol.

## Reproduce

Run from the project root with Python 3.12 and Bash. The GASOL checkout
contains its solvers. The FORVES checkout includes the Linux x86-64 binary.

```bash
evm_bench_dir="$(mktemp -d)"
git clone https://github.com/costa-group/gasol-optimizer.git "$evm_bench_dir/gasol"
git -C "$evm_bench_dir/gasol" checkout ff5efe78581df35c1c1e49b9d92f4a338f3744ca
git clone --branch stack-only https://github.com/costa-group/forves.git "$evm_bench_dir/forves"
git -C "$evm_bench_dir/forves" checkout 4c3b89e38c041e99d82bb278f79a8b93f743e279
git clone --branch v1.0 https://github.com/mariaschett/ppltr.git "$evm_bench_dir/ppltr"
git -C "$evm_bench_dir/ppltr" checkout 67f45f9e329800e6c39094d7c3c3af8d168638da
python3 -m venv "$evm_bench_dir/venv"
bench_python="$evm_bench_dir/venv/bin/python"
"$bench_python" -m pip install networkx==3.7 pandas==2.2.3
z3_bin="$evm_bench_dir/gasol/bin/z3"
forves_bin="$evm_bench_dir/forves/bin/static_checker"

"$bench_python" bench/competitors.py common bench/solc-windows.json > "$evm_bench_dir/solc.json"
"$bench_python" bench/competitors.py sample "$evm_bench_dir/forves/blocks/GASOL_gas_simp.txt" --count 288 > "$evm_bench_dir/samples.json"
"$bench_python" - "$evm_bench_dir" <<'PY'
import json
import sys
from pathlib import Path

directory = Path(sys.argv[1])
cases = json.loads((directory / "samples.json").read_text())
for offset, name in enumerate(("public", "fresh", "holdout")):
    (directory / f"{name}.json").write_text(json.dumps(cases[offset * 96:(offset + 1) * 96]))
PY

for suite in solc public fresh holdout; do
    fixture="$evm_bench_dir/$suite.json"
    base="$evm_bench_dir/$suite-gasol.json"
    alternate="$evm_bench_dir/$suite-gasol-size.json"
    "$bench_python" bench/competitors.py gasol "$evm_bench_dir/gasol" "$fixture" --timeout 2 > "$base"
    "$bench_python" bench/competitors.py gasol "$evm_bench_dir/gasol" "$fixture" --timeout 2 --size > "$alternate"
    for profile in gas compact size fast; do
        search=()
        score=()
        budget=1000
        slots=2
        case "$profile" in
            compact) search+=(--no-byte-growth); score+=(--no-byte-growth); budget=1500; slots=1 ;;
            size) search+=(--size); score+=(--size-objective); budget=1500; slots=1 ;;
            fast) budget=16 ;;
        esac
        ours="$evm_bench_dir/$suite-$profile-ours.json"
        "$bench_python" superopt.py bench "$fixture" --max-steps 8 --max-states "$budget" --stitch --extra-stack "$slots" "${search[@]}" > "$ours"
        "$bench_python" bench/adjudicate.py "$fixture" "$ours" "$base" \
            --alternative-gasol "$alternate" --z3 "$z3_bin" --forves "$forves_bin" "${score[@]}" > "$evm_bench_dir/$suite-$profile-scores.json"
    done
done

for suite in solc public fresh holdout; do
    "$bench_python" bench/timing.py "$evm_bench_dir/$suite.json" "$evm_bench_dir/gasol" > "$evm_bench_dir/timing-$suite.json"
done

fixture="$evm_bench_dir/legacy.json"
base="$evm_bench_dir/legacy-ebso.json"
"$bench_python" bench/competitors.py ebso "$evm_bench_dir/ppltr/eval/04-ebso-results.csv" \
    --commit 67f45f9e329800e6c39094d7c3c3af8d168638da --fixture "$fixture" > "$base"
for profile in gas compact size; do
    search=()
    score=()
    budget=1000
    slots=2
    case "$profile" in
        compact) search+=(--no-byte-growth); score+=(--no-byte-growth); budget=1500; slots=1 ;;
        size) search+=(--size); score+=(--size-objective); budget=1500; slots=1 ;;
    esac
    ours="$evm_bench_dir/legacy-$profile-ours.json"
    "$bench_python" superopt.py bench "$fixture" --max-steps 8 --max-states "$budget" --stitch --extra-stack "$slots" "${search[@]}" > "$ours"
    "$bench_python" bench/adjudicate.py "$fixture" "$ours" "$base" \
        --pre-shanghai --baseline-label ebso --z3 "$z3_bin" --forves "$forves_bin" "${score[@]}" > "$evm_bench_dir/legacy-$profile-scores.json"
done
```

[Per-window scores and timing measurements](results.json).
