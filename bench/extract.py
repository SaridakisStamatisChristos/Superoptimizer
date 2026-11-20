"""Extract disjoint stack-instruction windows from compiler runtime hex on stdin."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import verify as kernel


def entry_height(window):
    height = 0
    required = 0
    for item in kernel.decode(window):
        opcode = item[0]
        if opcode in kernel.OPS:
            need = kernel.OPS[opcode][1]
            change = 1 - need
        elif opcode == 0x50:
            need, change = 1, -1
        elif opcode <= 0x7f:
            need, change = 0, 1
        elif opcode <= 0x8f:
            need, change = opcode - 0x7f, 1
        else:
            need, change = opcode - 0x8f + 1, 0
        required = max(required, need - height)
        height += change
    return required


def windows(mode, code):
    offset = 0
    run_start = 0
    count = 0
    while offset < len(code):
        opcode = code[offset]
        width = opcode - 0x5f if 0x5f <= opcode <= 0x7f else 0
        end = offset + 1 + width
        if end > len(code):
            raise ValueError("truncated compiler output")
        supported = opcode in kernel.OPS or opcode == 0x50 or 0x5f <= opcode <= 0x9f
        if count and (not supported or count == 6):
            yield case(mode, run_start, code[run_start:offset])
            count = 0
        if supported:
            if count == 0:
                run_start = offset
            count += 1
        offset = end
    if count:
        yield case(mode, run_start, code[run_start:])


def case(mode, offset, window):
    return {"name": f"solc-0.8.30/{mode}/0x{offset:04x}",
            "source": window.hex(), "entry_height": entry_height(window)}


if __name__ == "__main__":
    runtime = json.load(sys.stdin)
    print(json.dumps([case for mode, code in sorted(runtime.items())
                      for case in windows(mode, bytes.fromhex(code))], indent=2))
