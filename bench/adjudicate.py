"""Score paired optimizers using independent 256-bit SMT equivalence checks."""

import argparse
import collections
import json
import re
import subprocess
from pathlib import Path

from competitors import disassemble, kernel

WORD = "(_ BitVec 256)"
ZERO = "(_ bv0 256)"
ONE = "(_ bv1 256)"
BINARY = {
    0x01: "bvadd", 0x02: "bvmul", 0x03: "bvsub", 0x16: "bvand",
    0x17: "bvor", 0x18: "bvxor",
}


def benchmark_decode(code):
    # Historical tools may emit ternary arithmetic outside our search alphabet.
    index = 0
    while index < len(code):
        opcode = code[index]
        width = opcode - 0x5f if 0x5f <= opcode <= 0x7f else 0
        end = index + 1 + width
        item = code[index:end]
        if opcode not in (0x08, 0x09):
            list(kernel.decode(item))
        yield item
        index = end


def expression(opcode, stack):
    a = stack.pop()
    if opcode == 0x15:
        return f"(ite (= {a} {ZERO}) {ONE} {ZERO})"
    if opcode == 0x19:
        return f"(bvnot {a})"
    b = stack.pop()
    if opcode in (0x08, 0x09):
        modulus = stack.pop()
        op, extension = ("bvadd", 1) if opcode == 0x08 else ("bvmul", 256)
        def extend(value):
            return f"((_ zero_extend {extension}) {value})"
        value = f"({op} {extend(a)} {extend(b)})"
        reduced = f"(bvurem {value} {extend(modulus)})"
        return f"(ite (= {modulus} {ZERO}) {ZERO} ((_ extract 255 0) {reduced}))"
    if opcode in BINARY:
        return f"({BINARY[opcode]} {a} {b})"
    if opcode in (0x04, 0x06):
        op = "bvudiv" if opcode == 0x04 else "bvurem"
        return f"(ite (= {b} {ZERO}) {ZERO} ({op} {a} {b}))"
    if opcode in (0x10, 0x11, 0x14):
        op = {0x10: "bvult", 0x11: "bvugt", 0x14: "="}[opcode]
        return f"(ite ({op} {a} {b}) {ONE} {ZERO})"
    if opcode == 0x1a:
        return (f"(ite (bvult {a} (_ bv32 256)) "
                f"(bvand (_ bv255 256) (bvlshr {b} "
                f"(bvsub (_ bv248 256) (bvmul (_ bv8 256) {a})))) {ZERO})")
    op = {0x1b: "bvshl", 0x1c: "bvlshr", 0x1d: "bvashr"}[opcode]
    return f"({op} {b} {a})"


def symbolic(code, height, prefix, query):
    stack = [f"x{index}" for index in range(height)]
    cost = 0
    peak = height
    for index, instruction in enumerate(benchmark_decode(code)):
        opcode = instruction[0]
        cost += 8 if opcode in (0x08, 0x09) else kernel.gas(instruction)
        if 0x5f <= opcode <= 0x7f:
            stack.append(f"(_ bv{int.from_bytes(instruction[1:], 'big')} 256)")
        elif opcode == 0x50:
            stack.pop()
        elif 0x80 <= opcode <= 0x8f:
            stack.append(stack[0x7f - opcode])
        elif 0x90 <= opcode <= 0x9f:
            depth = 0x8e - opcode
            stack[-1], stack[depth] = stack[depth], stack[-1]
        else:
            name = f"{prefix}{index}"
            value = expression(opcode, stack)
            query.append(f"(define-fun {name} () {WORD} {value})")
            stack.append(name)
        peak = max(peak, len(stack))
    return stack, cost, peak


def check(z3, before, after, height):
    if before == after:
        return "unchanged", 0, 0
    query = ["(set-logic QF_BV)", "(set-option :timeout 3000)"]
    query.extend(f"(declare-fun x{i} () {WORD})" for i in range(height))
    try:
        left, source_gas, _ = symbolic(before, height, "a", query)
        right, target_gas, target_peak = symbolic(after, height, "b", query)
    except (IndexError, ValueError, KeyError):
        return "invalid", 0, 0
    if len(left) != len(right) or not 0 <= height <= target_peak <= kernel.STACK_LIMIT:
        return "outside_contract", 0, 0
    if not left:
        query.append("(assert false)")
    else:
        equal = " ".join(f"(not (= {a} {b}))" for a, b in zip(left, right))
        query.append(f"(assert (or {equal}))")
    query.append("(check-sat)")
    try:
        run = subprocess.run([str(z3), "-in", "-smt2"], input="\n".join(query),
                             text=True, capture_output=True, timeout=5, check=True)
    except subprocess.TimeoutExpired:
        return "unknown", 0, 0
    status = run.stdout.strip()
    if status not in {"unsat", "sat", "unknown"}:
        raise ValueError(f"unexpected Z3 result: {status}")
    return status, source_gas - target_gas, len(before) - len(after)


def check_forves(executable, rows):
    triplets = []
    # This FORVES release predates PUSH0. Translate it to an equivalent stack
    # operation for semantic checking only. The gas score comes from Shanghai.
    def render(code):
        names = {b"\x08": "ADDMOD", b"\x09": "MULMOD", b"\x5f": "PUSH1 0x00"}
        return " ".join(names[item] if item in names else disassemble(item)
                        for item in benchmark_decode(code))

    for before, after, height in rows:
        triplets.append(f"{render(after)}\n{render(before)}\n{height}\n\n")
    process = subprocess.run([str(executable)], input="".join(triplets), text=True,
                             capture_output=True, timeout=30, check=True)
    results = re.findall(r"Example \d+: (true|false)", process.stdout)
    if len(results) != len(rows):
        raise ValueError(f"FORVES returned {len(results)} verdicts for {len(rows)} inputs")
    return {"pairs": len(rows), "proved": results.count("true")}


def as_legacy(code):
    return b"".join(bytes.fromhex("6000") if item == b"\x5f" else item
                    for item in benchmark_decode(code))


def compare(cases, ours, gasol, z3, forves=None, no_byte_growth=False, alternative=None,
            label="gasol", pre_shanghai=False, size_objective=False):
    primary, secondary = (
        ("bytes_saved", "gas_saved") if size_objective else ("gas_saved", "bytes_saved")
    )
    rows = []
    candidates = collections.defaultdict(list)
    own_rows = {row["case"]: row for row in ours["rows"]}
    gasol_runs = [gasol] if alternative is None else [gasol, alternative]
    gasol_rows = [{row["name"]: row for row in run["rows"]} for run in gasol_runs]
    if any(set(own_rows) != set(run) for run in gasol_rows) or len(cases) != len(own_rows):
        raise ValueError("the benchmark case sets do not match")
    for case in cases:
        name = case["name"]
        source = bytes.fromhex(case["source"])
        height = case["entry_height"]
        certificate = own_rows[name]["certificate"]
        baselines = [run[name] for run in gasol_rows]
        if any(b["source"] != source.hex() or b["entry_height"] != height for b in baselines):
            raise ValueError(f"{label} evaluated a different input: {name}")
        if certificate is not None:
            kernel.verify(certificate, source, height)
        row = {"case": name, "source": source.hex(), "entry_height": height}
        options = {
            "ours": [certificate["replacement"] if certificate else source.hex()],
            label: [baseline["replacement"] for baseline in baselines],
        }
        for tool, results in options.items():
            evaluated = []
            for result in dict.fromkeys(results):
                replacement = bytes.fromhex(result)
                if pre_shanghai:
                    replacement = as_legacy(replacement)
                outcome, gas, size = check(z3, source, replacement, height)
                improves = ((size > 0 and gas >= 0) if size_objective else
                            (gas > 0 and (size >= 0 or not no_byte_growth)))
                credit = outcome == "unsat" and improves
                evaluated.append({"replacement": replacement.hex(), "validation": outcome,
                                  "gas_saved": gas if credit else 0,
                                  "bytes_saved": size if credit else 0})
            best = max(evaluated, key=lambda item: (item[primary], item[secondary]))
            row[tool] = best
            if best[primary]:
                candidates[tool].append((source, bytes.fromhex(best["replacement"]), height))
            if len(evaluated) > 1:
                row[tool + "_candidates"] = evaluated
        rows.append(row)
    sums = {}
    for tool in ("ours", label):
        status = collections.Counter(row[tool]["validation"] for row in rows)
        sums[tool] = {"gas_saved": sum(row[tool]["gas_saved"] for row in rows),
                       "bytes_saved": sum(row[tool]["bytes_saved"] for row in rows),
                       "improved": sum(row[tool][primary] > 0 for row in rows),
                       "validation": dict(status)}
        if forves:
            sums[tool]["forves_semantic_check"] = check_forves(forves, candidates[tool])
    results = collections.Counter()
    for row in rows:
        difference = row["ours"][primary] - row[label][primary]
        results["win" if difference > 0 else "loss" if difference < 0 else "tie"] += 1
    return {"cases": len(rows), "baseline_commit": gasol["commit"],
            "pre_shanghai": pre_shanghai,
            "no_byte_growth": no_byte_growth, "size_objective": size_objective, "totals": sums,
            "matchups": dict(results), "rows": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("ours", type=Path)
    parser.add_argument("gasol", type=Path)
    parser.add_argument("--z3", type=Path, required=True)
    parser.add_argument("--forves", type=Path)
    parser.add_argument("--no-byte-growth", action="store_true")
    parser.add_argument("--size-objective", action="store_true")
    parser.add_argument("--alternative-gasol", type=Path)
    parser.add_argument("--baseline-label", default="gasol", choices=("gasol", "ebso"))
    parser.add_argument("--pre-shanghai", action="store_true")
    args = parser.parse_args()
    data = [json.loads(path.read_text()) for path in (args.fixture, args.ours, args.gasol)]
    print(json.dumps(compare(*data, args.z3.resolve(),
                             args.forves.resolve() if args.forves else None,
                             args.no_byte_growth,
                             json.loads(args.alternative_gasol.read_text())
                             if args.alternative_gasol else None,
                             args.baseline_label, args.pre_shanghai, args.size_objective), indent=2))


if __name__ == "__main__":
    main()
