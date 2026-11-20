"""CPU-only bounded superoptimization of Shanghai EVM stack windows."""

import argparse
import heapq
import itertools
import json
import time
from collections import Counter
from functools import lru_cache
from pathlib import Path

import verify as kernel
from scheduling import schedule


def push(value):
    width = (value.bit_length() + 7) // 8
    return bytes([0x5f + width]) + value.to_bytes(width, "big")


def alphabet(instructions, goal):
    constants = {0, 1}
    for instruction in instructions:
        if 0x5f <= instruction[0] <= 0x7f:
            constants.add(int.from_bytes(instruction[1:], "big"))
    # Folded constants in the result can be synthesized as immediate operands.
    pending = list(goal)
    visited = set()
    while pending:
        term = pending.pop()
        if id(term) in visited:
            continue
        visited.add(id(term))
        if term[0] == "const":
            constants.add(term[1])
        pending.extend(arg for arg in term[1:] if isinstance(arg, tuple))
    opcodes = sorted({*kernel.OPS, 0x50, *range(0x80, 0xa0)})
    return [bytes([opcode]) for opcode in opcodes] + [push(n) for n in sorted(constants)]


def optimize(source, height, max_steps, max_states, no_byte_growth=False, *, seed=None, by_size=False):
    original = tuple(kernel.decode(source))
    goal, original_gas, peak = kernel.replay(source, height, kernel.normal_v3)
    initial = kernel.inputs(height)
    byte_limit = len(source) - int(by_size) if no_byte_growth or by_size else kernel.MAX_BYTES
    gas_limit = original_gas + int(by_size)

    def objective(gas, size):
        return (size, gas) if by_size else (gas, size)
    choices = [(item, kernel.gas(item)) for item in alphabet(original, goal)]
    serial = itertools.count()
    interned = {}

    def intern(term, children):
        label = term[0]
        key = term if label in {"const", "input"} else (label, *children)
        return interned.setdefault(key, len(interned))

    goal_terms = {}

    def goal_id(term):
        identity = id(term)
        if identity not in goal_terms:
            children = (goal_id(arg) for arg in term[1:] if isinstance(arg, tuple))
            goal_terms[identity] = intern(term, children)
        return goal_terms[identity]

    goal_ids = tuple(goal_id(term) for term in goal)
    goal_counts = Counter(goal_ids)
    zero_id = goal_id(kernel.ZERO)
    required_inputs = input_dependencies(goal)

    @lru_cache(maxsize=8192)
    def term_inputs(term):
        if term[0] == "input":
            return 1 << term[1]
        if term[0] == "const":
            return 0
        return bit_union(term_inputs(argument) for argument in term[1:])

    @lru_cache(maxsize=8192)
    def word_id(term):
        return intern(term, (word_id(arg) for arg in term[1:] if isinstance(arg, tuple)))

    normalize = lru_cache(maxsize=8192)(kernel.normal_v3)

    @lru_cache(maxsize=8192)
    def remaining(stack):
        available = bit_union(term_inputs(term) for term in stack)
        if required_inputs & ~available:
            return None
        # A single instruction produces at most one new word and corrects
        # at most two positions counted from the bottom, even on a swap.
        ids = tuple(word_id(term) for term in stack)
        absent = goal_counts - Counter(ids)
        missing = sum(absent.values())
        extra = abs(len(goal_ids) - len(ids))
        mismatched = extra + sum(a != b for a, b in zip(ids, goal_ids))
        steps = max(extra, missing, (mismatched + 1) // 2)
        # PUSH0 is the only two-gas instruction that produces a word.
        gas = 2 * steps + missing - absent[zero_id]
        return steps, gas

    queue = []
    frontier = {}
    expanded = 0
    incumbent = None if seed is None else (
        objective(seed["replacement_gas"], len(seed["replacement"]) // 2),
        bytes.fromhex(seed["replacement"]),
    )

    def enqueue(code, cost, count, stack):
        nonlocal incumbent
        lower_bound = remaining(stack)
        if lower_bound is None:
            return
        steps_left, gas_left = lower_bound
        size = len(code)
        if (count + steps_left > max_steps or size + steps_left > byte_limit
                or cost + gas_left >= gas_limit):
            return
        bound = objective(cost + gas_left, size + steps_left)
        if incumbent is not None and bound >= incumbent[0]:
            return
        if steps_left == 0 and kernel.same_stack(stack, goal):
            incumbent = (objective(cost, size), code)
            return
        score = (count, cost, size)
        prior = frontier.get(stack, ())
        if any(steps <= count and gas <= cost and width <= size for steps, gas, width in prior):
            return
        frontier[stack] = [
            (steps, gas, width) for steps, gas, width in prior
            if not (count <= steps and cost <= gas and size <= width)
        ] + [score]
        heapq.heappush(queue, (*bound, next(serial),
                               count, cost, stack, code))

    enqueue(b"", 0, 0, initial)
    limit_hit = False
    while queue:
        primary_bound, secondary_bound, _, count, cost, stack, code = heapq.heappop(queue)
        if incumbent is not None and (primary_bound, secondary_bound) >= incumbent[0]:
            break
        if (count, cost, len(code)) not in frontier[stack]:
            continue
        if expanded == max_states:
            limit_hit = True
            break
        expanded += 1
        if count == max_steps:
            continue
        for item, op_cost in choices:
            if cost + op_cost >= gas_limit or len(code) + len(item) > byte_limit:
                continue
            result = kernel.step(stack, item, peak, normalize)
            if result is not None:
                enqueue(code + item, cost + op_cost, count + 1, result)
    if incumbent is not None:
        certificate = seed if seed is not None and incumbent[1].hex() == seed["replacement"] else (
            kernel.statement(source, incumbent[1], height, height_range=True,
                             algebra=True, size=by_size)
        )
        return certificate, expanded, "found_at_limit" if limit_hit else "found"
    return None, expanded, "state_limit" if limit_hit else "exhausted"


def input_dependencies(stack):
    pending = list(stack)
    examined = set()
    mask = 0
    while pending:
        term = pending.pop()
        if id(term) in examined:
            continue
        examined.add(id(term))
        if term[0] == "input":
            mask |= 1 << term[1]
        elif term[0] != "const":
            pending.extend(term[1:])
    return mask


def bit_union(values):
    combined = 0
    for value in values:
        combined |= value
    return combined


def optimize_stitched(source, height, max_steps, max_states, no_byte_growth, extra_stack=0):
    """Try bounded local replacements and certify the resulting full window."""
    original = tuple(kernel.decode(source))
    span_steps = max(max_steps, len(original))
    candidate, schedule_states = schedule(source, height, span_steps,
                                          schedule_budget(max_states), no_byte_growth, push,
                                          extra_stack=extra_stack)
    seed = None if candidate is None else kernel.statement(
        source, candidate, height, height_range=True, algebra=True,
        extra_stack=bool(extra_stack),
    )
    whole, states, status = optimize(source, height, max_steps, max_states, no_byte_growth, seed=seed)
    if whole == seed and seed is not None:
        status = "scheduled_at_limit" if "limit" in status else "scheduled"
    if len(original) < 3:
        return whole, states, status, schedule_states
    stack = kernel.inputs(height)
    candidate = []
    local_states = 0
    offset = 0
    while offset < len(original):
        chosen = None
        width = 1
        for span in range(min(4, len(original) - offset), 1, -1):
            available = min(32, max_states - local_states)
            if available <= 0:
                break
            fragment = b"".join(original[offset:offset + span])
            proof, visited, _ = optimize(fragment, len(stack), min(span, max_steps),
                                         available, no_byte_growth)
            local_states += visited
            if proof is not None:
                chosen = proof
                width = span
                break
        # Advance symbolically through the original span so later local entry
        # heights are derived from the original window.
        for item in original[offset:offset + width]:
            stack = kernel.step(stack, item, normalize=kernel.normal_v3)
        candidate.append(bytes.fromhex(chosen["replacement"]) if chosen is not None
                         else original[offset])
        offset += width
    combined = b"".join(candidate)
    if combined == source or len(combined) > kernel.MAX_BYTES:
        return whole, states, status, local_states + schedule_states
    try:
        stitched = kernel.statement(source, combined, height, height_range=True, algebra=True)
    except ValueError:
        return whole, states, status, local_states + schedule_states
    if whole is not None and (whole["replacement_gas"], len(whole["replacement"])) <= (
        stitched["replacement_gas"], len(stitched["replacement"]),
    ):
        return whole, states, status, local_states + schedule_states
    return stitched, states, "stitched_at_limit" if "limit" in status else "stitched", local_states + schedule_states


def benchmark(cases, max_steps, max_states, no_byte_growth=False, stitch=False, by_size=False, extra_stack=0):
    rows = []
    for case in cases:
        started = time.process_time()
        source = kernel.parse_hex(case["source"])
        height = case["entry_height"]
        cert, states, status, local = run_search(
            source, height, max_steps, max_states, no_byte_growth, stitch, by_size, extra_stack)
        if cert is not None:
            kernel.verify(cert, source)
        _, cost, _ = kernel.replay(source, height)
        target_cost = cert["replacement_gas"] if cert is not None else cost
        target_bytes = len(bytes.fromhex(cert["replacement"])) if cert is not None else len(source)
        rows.append({
            "case": case["name"], "status": status, "states": states, "stitch_states": local,
            "verified": cert is not None, "gas_saved": cost - target_cost,
            "bytes_saved": len(source) - target_bytes,
            "cpu_ms": round((time.process_time() - started) * 1000, 3),
            "certificate": cert,
        })
    return {
        "fork": kernel.FORK, "max_steps": max_steps, "max_states_per_case": max_states,
        "no_byte_growth": no_byte_growth, "cases": len(rows), "verified": sum(row["verified"] for row in rows),
        "state_limits": sum("limit" in row["status"] for row in rows),
        "stitch": stitch or by_size or bool(extra_stack), "size_objective": by_size, "extra_stack": extra_stack,
        "gas_saved_sum": sum(row["gas_saved"] for row in rows),
        "bytes_saved_sum": sum(row["bytes_saved"] for row in rows),
        "cpu_ms": round(sum(row["cpu_ms"] for row in rows), 3), "rows": rows,
    }


def schedule_budget(states):
    return min(12000, states * 8)


def run_search(source, height, steps, states, no_growth, stitch, by_size=False, extra_stack=0):
    if by_size:
        spans = max(steps, len(tuple(kernel.decode(source))))
        candidate, expanded = schedule(source, height, spans, schedule_budget(states),
                                       True, push, by_size=True, extra_stack=extra_stack)
        proof = None if candidate is None else kernel.statement(
            source, candidate, height, height_range=True, algebra=True, size=True,
        )
        winner, states_used, status = optimize(source, height, steps, states, True,
                                               seed=proof, by_size=True)
        return winner, states_used, status, expanded
    if stitch or extra_stack:
        return optimize_stitched(source, height, steps, states, no_growth, extra_stack)
    return (*optimize(source, height, steps, states, no_growth), 0)


def limits(parser, default_states):
    parser.add_argument("--max-steps", type=int, choices=range(1, 9), default=5)
    parser.add_argument("--max-states", type=int, default=default_states)
    parser.add_argument("--stitch", action="store_true",
                        help="also optimize and certify local spans with a separate state budget")
    parser.add_argument("--extra-stack", type=int, choices=range(17), default=0,
                        help="allow additional stack slots and restrict the certified height range")
    parser.add_argument("--size", action="store_true",
                        help="minimize bytes under a no-gas-increase constraint")
    parser.add_argument("--no-byte-growth", action="store_true",
                        help="require replacements to fit the source byte length")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("optimize", help="search for one cheaper bytecode window")
    run.add_argument("bytecode")
    run.add_argument("--entry-height", type=int, required=True)
    limits(run, 5000)
    prove = sub.add_parser("prove", help="check a supplied replacement and emit a certificate")
    prove.add_argument("bytecode")
    prove.add_argument("replacement")
    prove.add_argument("--entry-height", type=int, required=True)
    prove.add_argument("--size", action="store_true", help="prove a size reduction")
    prove.add_argument("--exact-height", action="store_true",
                       help="authorize only the stated height")
    bench = sub.add_parser("bench", help="search and verify all windows in a JSON fixture")
    bench.add_argument("cases", nargs="?", type=Path,
                       default=Path(__file__).with_name("bench") / "examples.json")
    limits(bench, 1000)
    args = parser.parse_args()
    if args.command != "prove" and not 1 <= args.max_states <= 100_000:
        parser.error("--max-states must be between 1 and 100000")
    try:
        if args.command == "optimize":
            source = kernel.parse_hex(args.bytecode)
            cert, states, status, local = run_search(
                source, args.entry_height, args.max_steps, args.max_states,
                args.no_byte_growth, args.stitch, args.size, args.extra_stack)
            if cert is None:
                parser.exit(2, f"{status}: no qualifying rewrite found after {states + local} states\n")
            result = cert
        elif args.command == "prove":
            result = kernel.statement(kernel.parse_hex(args.bytecode),
                                      kernel.parse_hex(args.replacement), args.entry_height,
                                      height_range=not args.exact_height, algebra=True, size=args.size)
        else:
            cases = json.loads(args.cases.read_text(encoding="utf-8"))
            result = benchmark(cases, args.max_steps, args.max_states, args.no_byte_growth, args.stitch, args.size, args.extra_stack)
        print(json.dumps(result, indent=2))
    except (OSError, ValueError, TypeError, KeyError) as exc:
        parser.exit(1, f"error: {exc}\n")


if __name__ == "__main__":
    main()
