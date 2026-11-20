"""Standalone checker and trusted normalization kernel for Shanghai stack windows."""

import argparse
import hashlib
import json
import re
from pathlib import Path

FORK = "shanghai"
EXACT_FORMAT = "evm-stack-normalization-v1"
RANGE_FORMAT = "evm-stack-normalization-v2"
ALGEBRA_FORMAT = "evm-stack-normalization-v3"
HEADROOM_FORMAT = "evm-stack-normalization-v4-headroom"
SIZE_FORMAT = "evm-stack-normalization-v4-size"
STACK_LIMIT = 1024
MAX_BYTES = 256
MAX_STEPS = 48
MASK = (1 << 256) - 1

# Opcode -> (expression operator, pop count, Shanghai gas).
OPS = {
    0x01: ("add", 2, 3), 0x02: ("mul", 2, 5), 0x03: ("sub", 2, 3),
    0x04: ("div", 2, 5), 0x06: ("mod", 2, 5),
    0x10: ("lt", 2, 3), 0x11: ("gt", 2, 3), 0x14: ("eq", 2, 3),
    0x15: ("iszero", 1, 3), 0x16: ("and", 2, 3), 0x17: ("or", 2, 3),
    0x18: ("xor", 2, 3), 0x19: ("not", 1, 3), 0x1a: ("byte", 2, 3),
    0x1b: ("shl", 2, 3), 0x1c: ("shr", 2, 3), 0x1d: ("sar", 2, 3),
}
COMMUTATIVE = {"add", "mul", "eq", "and", "or", "xor"}
ZERO = ("const", 0)
ONE = ("const", 1)
ALL_BITS = ("const", MASK)


def constant_operation(op, a, b=0):
    if op == "shl":
        return (b << a) & MASK if a < 256 else 0
    if op == "shr":
        return b >> a if a < 256 else 0
    if op == "sar":
        signed = b - (1 << 256) if b >> 255 else b
        return (signed >> min(a, 256)) & MASK
    if op == "byte":
        return (b >> (248 - 8 * a)) & 255 if a < 32 else 0
    if op == "div":
        return a // b if b else 0
    if op == "mod":
        return a % b if b else 0
    return {
        "add": (a + b) & MASK, "mul": (a * b) & MASK, "sub": (a - b) & MASK,
        "lt": int(a < b), "gt": int(a > b), "eq": int(a == b),
        "iszero": int(a == 0), "and": a & b, "or": a | b, "xor": a ^ b,
        "not": a ^ MASK,
    }[op]


def normal(op, *args):
    """Construct a term using only identities valid for every EVM word."""
    if all(term[0] == "const" for term in args):
        return ("const", constant_operation(op, *(term[1] for term in args)))
    if len(args) == 1:
        (a,) = args
        if op == "not" and a[0] == "not":
            return a[1]
        if op == "iszero" and a[0] == "iszero" and a[1][0] == "iszero":
            return a[1]
        return (op, a)

    a, b = args  # EVM pops a first, then b.
    if op == "gt":
        return normal("lt", b, a)
    if same_stack((a,), (b,)):
        if op in {"sub", "xor", "lt"}:
            return ZERO
        if op == "eq":
            return ONE
        if op in {"and", "or"}:
            return a
    if op == "eq" and ZERO in (a, b):
        return normal("iszero", b if a == ZERO else a)
    if op in {"mul", "and"} and ZERO in (a, b):
        return ZERO
    if op in {"add", "or", "xor"} and ZERO in (a, b):
        return b if a == ZERO else a
    if op == "mul" and ONE in (a, b):
        return b if a == ONE else a
    if op == "and" and ALL_BITS in (a, b):
        return b if a == ALL_BITS else a
    if op == "or" and ALL_BITS in (a, b):
        return ALL_BITS
    if op == "xor" and ALL_BITS in (a, b):
        return normal("not", b if a == ALL_BITS else a)
    if op in {"sub", "shl", "shr", "sar", "div"}:
        if op in {"shl", "shr", "sar"} and a == ZERO:
            return b
        if (op == "sub" and b == ZERO) or (op == "div" and b == ONE):
            return a
    if op in {"div", "mod"} and ZERO in (a, b):
        return ZERO
    if op == "mod" and b == ONE:
        return ZERO
    if op in COMMUTATIVE and stack_digest((b,)) < stack_digest((a,)):
        a, b = b, a
    return (op, a, b)


def normal_v2(op, *args):
    """Canonicalize power-of-two arithmetic and constant logical shifts."""
    term = normal(op, *args)
    if len(term) != 3:
        return term
    name, a, b = term
    if name == "add" and same_stack((a,), (b,)):
        return normal_v2("shl", ONE, a)
    if name == "mul" and a[0] != "const" and b[0] == "const":
        a, b = b, a
    if name == "mul" and a[0] == "const":
        factor = a[1]
        if factor and factor & (factor - 1) == 0:
            return normal_v2("shl", ("const", factor.bit_length() - 1), b)
    if name in {"div", "mod"} and b[0] == "const":
        factor = b[1]
        if factor and factor & (factor - 1) == 0:
            if name == "div":
                return normal_v2("shr", ("const", factor.bit_length() - 1), a)
            return normal("and", ("const", factor - 1), a)
    if name in {"shl", "shr"}:
        if b == ZERO or (a[0] == "const" and a[1] >= 256):
            return ZERO
        if a[0] == "const" and b[0] == name and b[1][0] == "const":
            combined = a[1] + b[1][1]
            return normal_v2(name, ("const", combined), b[2])
    return term


def normal_v3(op, *args):
    """Fold chains of constant operations modulo one EVM word."""
    term = normal_v2(op, *args)
    if len(term) != 3:
        return term
    name, left, right = term
    if name == "lt" and right == ONE:
        return normal_v2("iszero", left)
    if name not in {"add", "and", "or", "xor"}:
        return term
    if right[0] == "const":
        left, right = right, left
    if left[0] != "const" or len(right) != 3:
        return term
    other, a, b = right
    if other == name:
        if b[0] == "const":
            a, b = b, a
        if a[0] == "const":
            constant = ("const", constant_operation(name, left[1], a[1]))
            return normal_v3(name, constant, b)
    if name == "add" and other == "sub":
        if a[0] == "const":
            return normal_v2("sub", ("const", (left[1] + a[1]) & MASK), b)
        if b[0] == "const":
            return normal_v3("add", ("const", (left[1] - b[1]) & MASK), a)
    return term


def parse_hex(value):
    if not isinstance(value, str):
        raise ValueError("bytecode must be a hex string")
    value = value.removeprefix("0x")
    if len(value) > MAX_BYTES * 2 or not re.fullmatch(r"(?:[0-9a-fA-F]{2})*", value):
        raise ValueError(f"expected even-length hex of at most {MAX_BYTES} bytes")
    return bytes.fromhex(value)


def decode(code):
    offset = 0
    steps = 0
    while offset < len(code):
        opcode = code[offset]
        width = opcode - 0x5f if 0x5f <= opcode <= 0x7f else 0
        end = offset + 1 + width
        if end > len(code):
            raise ValueError(f"truncated PUSH at byte {offset}")
        if not (opcode in OPS or opcode == 0x50 or 0x5f <= opcode <= 0x9f):
            raise ValueError(f"unsupported opcode 0x{opcode:02x} at byte {offset}")
        steps += 1
        if steps > MAX_STEPS:
            raise ValueError(f"window exceeds {MAX_STEPS} instructions")
        yield code[offset:end]
        offset = end


def gas(instruction):
    opcode = instruction[0]
    if opcode in OPS:
        return OPS[opcode][2]
    return 2 if opcode in (0x50, 0x5f) else 3


def step(stack, instruction, limit=STACK_LIMIT, normalize=normal):
    opcode = instruction[0]
    if opcode in OPS:
        name, pops, _ = OPS[opcode]
        if len(stack) >= pops:
            args = tuple(reversed(stack[-pops:]))
            return (*stack[:-pops], normalize(name, *args))
    elif opcode == 0x50:
        if stack:
            return stack[:-1]
    elif opcode <= 0x7f:
        if len(stack) < limit:
            return (*stack, ("const", int.from_bytes(instruction[1:], "big")))
    elif opcode <= 0x8f:
        depth = opcode - 0x7f
        if depth <= len(stack) < limit:
            return (*stack, stack[-depth])
    else:
        depth = opcode - 0x8f
        if len(stack) > depth:
            items = list(stack)
            items[-1], items[-depth - 1] = items[-depth - 1], items[-1]
            return tuple(items)
    return None


def inputs(height):
    if type(height) is not int or not 0 <= height <= STACK_LIMIT:
        raise ValueError(f"entry_height must be an integer from 0 to {STACK_LIMIT}")
    return tuple(("input", index) for index in range(height))


def replay(code, height, normalize=normal):
    stack = inputs(height)
    peak = height
    cost = 0
    for instruction in decode(code):
        stack = step(stack, instruction, normalize=normalize)
        if stack is None:
            raise ValueError("window would underflow or overflow its entry stack")
        peak = max(peak, len(stack))
        cost += gas(instruction)
    return stack, cost, peak


def stack_digest(stack):
    # Hash each node from its children to avoid expanding shared expression DAGs.
    digests = {}

    def visit(term):
        key = id(term)
        if key not in digests:
            parts = [term[0]]
            for argument in term[1:]:
                parts.append(visit(argument) if isinstance(argument, tuple) else argument)
            encoded = json.dumps(parts, separators=(",", ":")).encode("ascii")
            digests[key] = hashlib.sha256(encoded).hexdigest()
        return digests[key]

    encoded = json.dumps([visit(term) for term in stack], separators=(",", ":")).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def same_stack(left, right):
    if len(left) != len(right):
        return False
    pairs = list(zip(left, right))
    checked = set()
    while pairs:
        a, b = pairs.pop()
        pair = (id(a), id(b))
        if a is b or pair in checked:
            continue
        if a[0] != b[0]:
            return False
        if len(a) == 2 and a[0] in {"input", "const"}:
            if a[1] != b[1]:
                return False
        else:
            pairs.extend(zip(a[1:], b[1:]))
        checked.add(pair)
    return True


def statement(source, replacement, height, *, height_range=False, algebra=False, size=False, extra_stack=False):
    format_name = ALGEBRA_FORMAT if height_range and algebra else (
        RANGE_FORMAT if height_range else EXACT_FORMAT
    )
    if size or extra_stack:
        if not height_range:
            raise ValueError("size and stack-headroom proofs require a height range")
        format_name = SIZE_FORMAT if size else HEADROOM_FORMAT
    normalizers = {EXACT_FORMAT: normal, RANGE_FORMAT: normal_v2,
                   ALGEBRA_FORMAT: normal_v3, SIZE_FORMAT: normal_v3, HEADROOM_FORMAT: normal_v3}
    normalize = normalizers[format_name]
    before, source_cost, source_peak = replay(source, height, normalize)
    after, replacement_cost, replacement_peak = replay(replacement, height, normalize)
    if size and (len(replacement) >= len(source) or replacement_cost > source_cost):
        raise ValueError("replacement must reduce bytes without increasing gas")
    if not size and replacement_cost >= source_cost:
        raise ValueError("replacement must strictly reduce gas")
    if not same_stack(before, after):
        raise ValueError("normalized exit stacks differ")
    if height_range and not (extra_stack or size) and replacement_peak > source_peak:
        raise ValueError("replacement requires more stack headroom than source")
    claim = {
        "format": format_name,
        "fork": FORK,
        "entry_height": height,
        "source": source.hex(),
        "replacement": replacement.hex(),
        "source_gas": source_cost,
        "replacement_gas": replacement_cost,
        "normalized_stack_sha256": stack_digest(before),
    }
    if height_range:
        claim["max_entry_height"] = height + STACK_LIMIT - max(source_peak, replacement_peak)
    return claim


def verify(certificate, expected_source=None, expected_height=None):
    if not isinstance(certificate, dict):
        raise ValueError("certificate must be a JSON object")
    format_name = certificate.get("format")
    if format_name not in (EXACT_FORMAT, RANGE_FORMAT, ALGEBRA_FORMAT, SIZE_FORMAT, HEADROOM_FORMAT) or certificate.get("fork") != FORK:
        raise ValueError("unsupported certificate format or fork")
    source = parse_hex(certificate.get("source"))
    if expected_source is not None and source != expected_source:
        raise ValueError("source differs from the expected bytecode")
    height = certificate.get("entry_height")
    checked = statement(source, parse_hex(certificate.get("replacement")), height,
                        height_range=(format_name != EXACT_FORMAT),
                        algebra=(format_name == ALGEBRA_FORMAT), size=(format_name == SIZE_FORMAT),
                        extra_stack=(format_name == HEADROOM_FORMAT))
    if expected_height is not None and not height <= expected_height <= checked.get(
        "max_entry_height", height
    ):
        raise ValueError("expected stack height is outside the certified range")
    if checked.keys() != certificate.keys() or any(
        type(certificate[key]) is not type(value) or certificate[key] != value
        for key, value in checked.items()
    ):
        raise ValueError("certificate fields differ from the reconstructed claim")
    return checked


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("certificate", type=Path)
    parser.add_argument("--expect-source", help="bind verification to this source hex")
    parser.add_argument("--expect-height", type=int, help="bind verification to this entry height")
    args = parser.parse_args()
    try:
        with args.certificate.open("rb") as reader:
            data = reader.read(4097)
        if len(data) > 4096:
            raise ValueError("certificate exceeds 4096 bytes")
        expected = parse_hex(args.expect_source) if args.expect_source is not None else None
        checked = verify(json.loads(data, object_pairs_hook=unique_object),
                         expected, args.expect_height)
    except (OSError, ValueError, RecursionError) as exc:
        parser.exit(1, f"rejected: {exc}\n")
    saved = checked["source_gas"] - checked["replacement_gas"]
    if checked["format"] == SIZE_FORMAT:
        size = (len(checked["source"]) - len(checked["replacement"])) // 2
        print(f"verified {FORK} stack-window equivalence, {size} bytes saved, {saved} gas saved")
    else:
        print(f"verified {FORK} stack-window equivalence and {saved} gas saved")


if __name__ == "__main__":
    main()
