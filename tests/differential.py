"""Compare modeled output stacks and exact gas against EthereumJS."""

import itertools
import json
import random
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import superopt
import verify as kernel

RANDOM = random.Random(20261120)
EDGES = [0, 1, 31, 32, 255, 256, 1 << 255, (1 << 255) - 1, kernel.MASK]


def evaluate(term, initial):
    label, *args = term
    if label == "input":
        return initial[args[0]]
    if label == "const":
        return args[0]
    return kernel.constant_operation(label, *(evaluate(arg, initial) for arg in args))


def vector(code, initial):
    output, gas, _ = kernel.replay(code, len(initial), kernel.normal_v3)
    return {"source": code.hex(), "initial": [f"{v:x}" for v in initial],
            "output": [f"{evaluate(term, initial):x}" for term in output], "gas": gas}


def differential_cases():
    for opcode, (_, operands, _) in kernel.OPS.items():
        code = bytes([opcode])
        # Exercise both constant folding and symbolic evaluation of every edge tuple.
        for words in itertools.product(EDGES, repeat=operands):
            yield vector(code, words)
            program = b"".join(superopt.push(word) for word in words) + code
            yield vector(program, [])
        for _ in range(128):
            words = [RANDOM.getrandbits(256) for _ in range(operands)]
            yield vector(code, words)
    for width in range(33):
        operand = RANDOM.getrandbits(8 * width)
        yield vector(bytes([0x5f + width]) + operand.to_bytes(width, "big"), [123])
    for opcode in [0x50, *range(0x80, 0xa0)]:
        yield vector(bytes([opcode]), list(range(17)))

    # Exercise an arbitrary prefix and the upper end of a v2 stack-height range.
    for height in (1, 17, 1023):
        words = [RANDOM.getrandbits(256) for _ in range(height)]
        yield vector(bytes.fromhex("600202"), words)
        yield vector(bytes.fromhex("8001"), words)

    for height in (4, 1021):
        words = [RANDOM.getrandbits(256) for _ in range(height)]
        for code in ("602081018490", "8381602001"):
            yield vector(bytes.fromhex(code), words)
    yield vector(bytes.fromhex("610001"), [])
    yield vector(bytes.fromhex("6001"), [])

    strength_cases = ["600202", "60029004", "60049006", "60011b60021b", "60ff1b60011b",
                      "600003600301", "600301600201", "600416600716",
                      "600417600717", "600418600718", "600111"]
    for code in strength_cases:
        for word in [*EDGES, *(RANDOM.getrandbits(256) for _ in range(64))]:
            yield vector(bytes.fromhex(code), [word])

    for name in ["examples.json", "solc-windows.json"]:
        cases = json.loads((ROOT / "bench" / name).read_text())
        for row in superopt.benchmark(cases, 5, 1000)["rows"]:
            cert = row["certificate"]
            if cert is None:
                continue
            for _ in range(24):
                words = [RANDOM.choice(EDGES) if RANDOM.randrange(2) else RANDOM.getrandbits(256)
                         for _ in range(cert["entry_height"])]
                yield vector(bytes.fromhex(cert["source"]), words)
                yield vector(bytes.fromhex(cert["replacement"]), words)


if __name__ == "__main__":
    subprocess.run(["node", str(ROOT / "tests" / "oracle.cjs")],
                   input=json.dumps(list(differential_cases())), text=True, check=True)
