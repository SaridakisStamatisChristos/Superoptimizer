"""Reproduce the stack-window benchmark against the upstream GASOL artifact."""

import argparse
import contextlib
import csv
import hashlib
import io
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import verify as kernel
from extract import entry_height

MNEMONICS = {opcode: row[0].upper() for opcode, row in kernel.OPS.items()}
MNEMONICS.update({0x50: "POP", 0x5f: "PUSH0"})
MNEMONICS.update({0x7f + n: f"DUP{n}" for n in range(1, 17)})
MNEMONICS.update({0x8f + n: f"SWAP{n}" for n in range(1, 17)})
OPCODES = {name: opcode for opcode, name in MNEMONICS.items()}


def disassemble(code):
    parts = []
    for op in kernel.decode(code):
        if len(op) > 1:
            parts.extend((f"PUSH{len(op) - 1}", f"0x{op[1:].hex()}"))
        else:
            parts.append(MNEMONICS[op[0]])
    return " ".join(parts)


def assemble(source, *, normalize_pushes=False):
    code = bytearray()
    tokens = iter(source.split())
    for name in tokens:
        if name.startswith("PUSH") and name != "PUSH0":
            try:
                width = int(name[4:])
                value = int(next(tokens), 0)
            except (StopIteration, ValueError) as exc:
                raise ValueError("invalid PUSH assembly") from exc
            if not 1 <= width <= 32 or value < 0 or value.bit_length() > 8 * width:
                raise ValueError("PUSH immediate does not fit")
            if normalize_pushes:
                width = (value.bit_length() + 7) // 8
            code.append(0x5f + width)
            code.extend(value.to_bytes(width, "big"))
        elif name in OPCODES:
            code.append(OPCODES[name])
        else:
            raise ValueError(f"unsupported instruction {name}")
    list(kernel.decode(code))
    return bytes(code)


def public_cases(path, count):
    """Sample by hash of original bytes and height, independently of the replacement."""
    unique = {}
    group = []
    serial = None
    for raw in [*path.read_text().splitlines(), ""]:
        line = raw.strip()
        if line.startswith("# serial number:"):
            serial = int(line.split(":")[-1])
        if line.startswith("#"):
            continue
        if line:
            group.append(line)
            continue
        if len(group) == 3:
            _, original, height_str = group
            try:
                source = assemble(original, normalize_pushes=True)
                height = int(height_str)
                minimum = entry_height(source)
                if minimum == height and 2 <= len(tuple(kernel.decode(source))) <= 12:
                    unique.setdefault((source, height), serial)
            except ValueError:
                pass
        group = []
    ranked = sorted(unique, key=lambda item: hashlib.sha256(
        b"evm-gasol-holdout-v1\x00" + item[1].to_bytes(2, "big") + item[0],
    ).digest())
    return [{"name": f"forves-gasol-gas-simp/{unique[key]}", "source": key[0].hex(),
             "entry_height": key[1]} for key in ranked[:count]]


def recorded_ebso(path, count, commit):
    unique = {}
    with path.open(newline="") as reader:
        for index, row in enumerate(csv.DictReader(reader)):
            try:
                source = kernel.parse_hex(row["source bytecode"])
                if not 2 <= len(tuple(kernel.decode(source))) <= 12:
                    continue
                height = entry_height(source)
            except ValueError:
                continue
            unique.setdefault((source, height), (index, row["target bytecode"]))
    ordered = sorted(unique, key=lambda item: hashlib.sha256(
        b"evm-ebso-public-v1\x00" + item[1].to_bytes(2, "big") + item[0],
    ).digest())[:count]
    rows = []
    for source, height in ordered:
        index, target = unique[(source, height)]
        rows.append({"name": f"ppltr-ebso/{index}", "source": source.hex(),
                     "entry_height": height, "replacement": target})
    return {"commit": commit, "corpus": path.name, "rows": rows}


def run_gasol(repo, cases, timeout, solver, size=False):
    sys.path.insert(0, str(repo.resolve()))
    import gasol_asm as gasol

    parser = argparse.ArgumentParser()
    gasol.options_gasol(parser)
    params = gasol.OptimizationParams()
    params.parse_args(parser.parse_args([
        "isolated.txt", "-bl", "-solver", solver, "-tout", str(timeout), "-direct-tout",
        *(["-size"] if size else []),
    ]))
    gasol.init()
    gasol.constants._set_push0(params.push0)
    rows = []
    try:
        for case in cases:
            source = bytes.fromhex(case["source"])
            start = time.monotonic()
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                old = gasol.parse_blocks_from_plain_instructions(disassemble(source))[0]
                if assemble(old.to_plain_with_byte_number()) != source:
                    raise ValueError(f"GASOL altered input before optimization: {case['name']}")
                if old.source_stack != case["entry_height"]:
                    raise ValueError(f"entry height mismatch: {case['name']}")
                new, _, stats = gasol.optimize_asm_block_asm_format(old, params)
                accepted, reason = gasol.compare_asm_block_asm_format(old, new, params)
            actual = new if accepted else old
            rows.append({
                "name": case["name"], "source": source.hex(),
                "replacement": assemble(actual.to_plain_with_byte_number()).hex(),
                "entry_height": case["entry_height"], "internal_equivalent": accepted,
                "internal_reason": reason, "wall_ms": round((time.monotonic() - start) * 1000, 3),
                "optimization": [{"outcome": row.get("outcome"),
                                  "solver_seconds": row.get("solver_time_in_sec"),
                                  "shown_optimal": row.get("shown_optimal")} for row in stats],
            })
    finally:
        shutil.rmtree(gasol.paths.gasol_path, ignore_errors=True)
    commit = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"],
                                     text=True).strip()
    return {"commit": commit, "solver": solver, "timeout_s": timeout, "size_objective": size, "rows": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    sample = sub.add_parser("sample")
    sample.add_argument("public_data", type=Path)
    sample.add_argument("--count", type=int, default=96)
    common = sub.add_parser("common", help="retain byte-exact GASOL-compatible inputs")
    common.add_argument("fixture", type=Path)
    ebso = sub.add_parser("ebso", help="sample recorded ebso outputs from the ppltr artifact")
    ebso.add_argument("results", type=Path)
    ebso.add_argument("--count", type=int, default=96)
    ebso.add_argument("--commit", required=True)
    ebso.add_argument("--fixture", type=Path, required=True)
    gasol = sub.add_parser("gasol")
    gasol.add_argument("repo", type=Path)
    gasol.add_argument("fixture", type=Path)
    gasol.add_argument("--timeout", type=int, default=1)
    gasol.add_argument("--size", action="store_true")
    gasol.add_argument("--solver", choices=("oms", "z3", "barcelogic"), default="oms")
    args = parser.parse_args()
    if args.action == "sample":
        result = public_cases(args.public_data, args.count)
    elif args.action == "common":
        result = []
        for case in json.loads(args.fixture.read_text()):
            code = kernel.parse_hex(case["source"])
            if assemble(disassemble(code), normalize_pushes=True) == code:
                result.append(case)
    elif args.action == "ebso":
        result = recorded_ebso(args.results, args.count, args.commit)
        cases = [{key: value for key, value in row.items() if key != "replacement"}
                 for row in result["rows"]]
        args.fixture.write_text(json.dumps(cases, indent=2) + "\n")
    else:
        result = run_gasol(args.repo, json.loads(args.fixture.read_text()), args.timeout, args.solver, args.size)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
