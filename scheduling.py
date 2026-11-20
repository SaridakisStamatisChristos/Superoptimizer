"""Bounded stack scheduling over a finite set of symbolic values."""

import heapq
import itertools
from collections import Counter
from functools import lru_cache

import verify as kernel


def schedule(source, height, max_steps, max_states, no_byte_growth, push, *, by_size=False, extra_stack=0):
    """Return a candidate and work count. The caller checks its certificate."""
    instructions = tuple(kernel.decode(source))
    trace = [kernel.inputs(height)]
    source_gas = sum(map(kernel.gas, instructions))
    gas_limit = source_gas + int(by_size)
    for instruction in instructions:
        trace.append(kernel.step(trace[-1], instruction, normalize=kernel.normal_v3))
        if trace[-1] is None:
            raise ValueError("invalid initial stack height for source")
    peak = min(kernel.STACK_LIMIT, max(map(len, trace)) + extra_stack)
    if by_size:
        byte_limit = len(source) - 1
    else:
        byte_limit = len(source) if no_byte_growth else kernel.MAX_BYTES

    def objective(gas, size):
        return (size, gas) if by_size else (gas, size)
    identities = {}
    values = []
    dependencies = []
    registered = {}

    def register(term):
        identity = id(term)
        if identity in registered:
            return registered[identity]
        label = term[0]
        components = [] if label in {"const", "input"} else [
            register(child) for child in term[1:]
        ]
        key = (label, *components) if components else term
        if key not in identities:
            dependencies.append(
                1 << term[1] if label == "input" else combine(dependencies[i] for i in components)
            )
            identities[key] = len(values)
            values.append(term)
        registered[identity] = identities[key]
        return registered[identity]

    # The source trace is a guide to reachable intermediate values. Include
    # children of normalized expressions so arithmetic can be rescheduled.
    layouts = [tuple(register(term) for term in stack) for stack in trace]
    initial, goal = layouts[0], layouts[-1]
    suffixes = {}
    prefixes = []
    prefix = b""
    spent = 0
    for index, item in enumerate(instructions):
        stack = layouts[index]
        prefixes.append((stack, prefix, spent, index))
        suffixes.setdefault(stack, []).append((source[len(prefix):], source_gas - spent,
                                              len(instructions) - index))
        prefix += item
        spent += kernel.gas(item)
    if initial == goal and source:
        return b"", 0
    literals = [(index, push(term[1])) for index, term in enumerate(values) if term[0] == "const"]
    normalized_ops = {term[0] for term in values}
    arithmetic = sorted(
        {op[0] for op in instructions if op[0] in kernel.OPS} |
        {opcode for opcode, (name, _, _) in kernel.OPS.items() if name in normalized_ops}
    )
    required = combine(dependencies[index] for index in goal)
    goal_counts = Counter(goal)

    @lru_cache(maxsize=8192)
    def expression(opcode, operands):
        op = kernel.OPS[opcode][0]
        result = kernel.normal_v3(op, *(values[index] for index in operands))
        return lookup(result)

    def lookup(term):
        registered_id = registered.get(id(term))
        if registered_id is not None:
            return registered_id
        if term[0] in {"input", "const"}:
            return identities.get(term)
        children = tuple(lookup(child) for child in term[1:])
        return identities.get((term[0], *children))

    def successors(stack):
        if stack:
            yield b"\x50", stack[:-1], 2
        if len(stack) < peak:
            for index, item in literals:
                yield item, (*stack, index), 2 if item == b"\x5f" else 3
            seen = set()
            for depth, value in enumerate(reversed(stack[-16:])):
                if value not in seen:
                    yield bytes([0x80 + depth]), (*stack, value), 3
                    seen.add(value)
        for depth in range(1, min(len(stack), 17)):
            if stack[-1] != stack[-1 - depth]:
                items = list(stack)
                items[-1], items[-1 - depth] = items[-1 - depth], items[-1]
                yield bytes([0x8f + depth]), tuple(items), 3
        for opcode in arithmetic:
            _, arity, cost = kernel.OPS[opcode]
            if len(stack) >= arity:
                operands = stack[-arity:][::-1]
                result = expression(opcode, operands)
                if result is not None:
                    yield bytes([opcode]), (*stack[:-arity], result), cost

    @lru_cache(maxsize=8192)
    def distance(stack):
        if required & ~combine(dependencies[index] for index in stack):
            return None
        missing = sum((goal_counts - Counter(stack)).values())
        length_delta = abs(len(goal) - len(stack))
        misplaced = length_delta + sum(a != b for a, b in zip(stack, goal))
        lower_bound = max(length_delta, missing, (misplaced + 1) // 2)
        # Weighted ordering is a scheduling heuristic. Only the separate
        # lower bound is used for pruning.
        priority = 3 * missing + 2 * max(length_delta, (misplaced + 1) // 2)
        return lower_bound, priority

    serial = itertools.count()
    heap = []
    frontier = {}
    best = None
    expanded = 0

    def accept(code, gas):
        nonlocal best
        if gas < gas_limit and len(code) <= byte_limit:
            score = (*objective(gas, len(code)), code)
            if best is None or score < best:
                best = score

    def enqueue(stack, code, gas, steps):
        if gas >= gas_limit or len(code) > byte_limit:
            return
        if stack == goal:
            accept(code, gas)
            return
        for suffix, suffix_gas, suffix_steps in suffixes.get(stack, ()):
            if steps + suffix_steps <= max_steps:
                accept(code + suffix, gas + suffix_gas)
        remaining = distance(stack)
        if remaining is None:
            return
        bound, priority = remaining
        if steps + bound > max_steps or len(code) + bound > byte_limit:
            return
        if gas + 2 * bound >= gas_limit or (
            best is not None and objective(gas + 2 * bound, len(code) + bound) >= best[:2]
        ):
            return
        score = (gas, len(code))
        key = (steps, stack)
        paths = frontier.get(key, [])
        if any(cost <= gas and size <= len(code) for cost, size in paths):
            return
        frontier[key] = [
            (cost, size) for cost, size in paths if not (gas <= cost and len(code) <= size)
        ] + [score]
        ordering_cost = len(code) if by_size else gas
        heapq.heappush(heap, (ordering_cost + priority, priority, next(serial),
                              gas, steps, stack, code))

    for prefix in prefixes:
        enqueue(*prefix)
    while heap and expanded < max_states:
        _, _, _, gas, steps, stack, code = heapq.heappop(heap)
        if (gas, len(code)) not in frontier[(steps, stack)] or steps == max_steps:
            continue
        expanded += 1
        for item, result, cost in successors(stack):
            enqueue(result, code + item, gas + cost, steps + 1)
    return None if best is None else best[2], expanded


def combine(items):
    result = 0
    for item in items:
        result |= item
    return result
