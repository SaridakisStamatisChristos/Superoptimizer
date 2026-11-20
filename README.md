# Proof-carrying EVM superoptimizer v0.4

A CPU-only optimizer for straight-line Shanghai EVM stack windows. It searches
for cheaper bytecode and emits a normalization certificate when it finds one.
The standalone verifier runs from the certificate and bytecode alone. The core
uses Python 3.10+ and the standard library. Node.js and the locked npm packages
are required only to regenerate the compiler fixture or run the differential
validation.

## Quick start

```sh
python3 superopt.py optimize 600202 --entry-height 1 --no-byte-growth > proof.json
python3 verify.py proof.json --expect-source 600202 --expect-height 1023
python3 superopt.py prove 600202 60011b --entry-height 1
python3 superopt.py bench
python3 superopt.py bench bench/solc-windows.json
python3 superopt.py bench bench/solc-windows.json --no-byte-growth --stitch --extra-stack 1
python3 superopt.py optimize 610001 --entry-height 0 --size
```

The search replaces `PUSH1 2; MUL` (8 gas, three bytes) with
`DUP1; ADD` (6 gas, two bytes). Both return twice the input modulo
2²⁵⁶. The `prove` command checks a proposed alternative, here
`PUSH1 1; SHL`, against the same input bytecode. An empty replacement is valid when the
window's net effect is the identity. Exit code 2 from `optimize` means the
search found no improvement under the selected objective and search limits. Code 1
indicates an invalid window or another input error.

Supply a new benchmark as a JSON list of objects with `name`, `source` (hex
bytecode) and `entry_height`. Use `--max-steps` and `--max-states` to set the
same search budget for reproducible comparisons. The search uses A* with lower bounds for remaining instructions, gas, and bytes.
It prunes states that have lost an input word required by the target, and
retains the cheapest completed candidate when the expansion budget expires.
Search cost is ordered by gas then bytes. A frontier tracks nondominated
paths by instructions, gas, and byte length. Its candidate alphabet draws
immediates from the input window, constants in the normalized exit stack, zero
and one. It also constrains candidate peak height to the original window's peak.
An `exhausted` result applies to this finite search space. A `state_limit` result
means the expansion budget ran out without a match. A `found_at_limit` result
includes the best matching rewrite found before the budget expired.
Gas is the primary objective, so a rewrite
can grow the bytecode, which the benchmark reports as negative bytes saved.
Use `--no-byte-growth` to constrain the byte length of each replacement.
With `--stitch`, the optimizer first schedules symbolic values drawn from the
original stack trace, then runs A* and a local pass over spans of two to four
instructions. The scheduler can reach intermediate points in the original
trace and reuse the remaining suffix. Its budget is eight times
`--max-states`, capped at 12,000. Its instruction bound is the greater of
`--max-steps` and the original window length. The local pass has its own
`--max-states` budget, capped at 32 expansions per span. The verifier checks
each emitted replacement against the full source window.

Use `--size` to prioritize byte savings while requiring gas to stay flat or
decrease. For example, `610001` shrinks to `6001` at the same gas cost.
Use `--extra-stack N` to let the scheduler use up to N additional stack slots.
The default is zero. The returned certificate records the applicable entry
height range.

## Proof contract

For every certified entry height and assignment of 256-bit words to the
stack, a replacement produces the same exit stack when the source has enough
gas. Gas certificates require a strict gas reduction. Size certificates
require a strict byte reduction and gas at most equal to the source.

The verifier replays the source and replacement at the stated minimum
height. The extra prefix at a greater height is untouched because the checked
suffix never underflows. For the headroom and size formats, the certified
range stops at the greatest height that keeps both programs within the
1,024-word EVM stack limit. The verifier also accepts v1, v2, and v3
certificates. `prove --exact-height` uses the v1 normalization rules.

Supported windows use only fixed-cost stack instructions. The checker
validates both programs for stack overflow and underflow, reconstructs their
symbolic exit stacks from bytecode, compares those stacks structurally, and
recomputes the Shanghai cost. The hash in the certificate binds the reconstructed
normalized stack for reproducibility. Structural equality determines acceptance.

The verifier is separate from the search executable and has no dependency
on its heap, pruning, or candidate generator. The optimizer uses the verifier's
normalization kernel to build candidates and emit a certificate. The kernel
implements exact modulo-`2^256` constant evaluation and a finite set of
word identities. v2 additionally normalizes doubling, multiplication or
unsigned division and remainder by a power of two, and chains of constant
logical shifts. v0.3 adds modular constant-chain folding and the unsigned
comparison with one. The checker trusts this kernel. Its semantics and identities
are executable Python, with differential validation and no proof-assistant
formalization. The normalization procedure can miss equivalent programs whose
normalized terms differ.

Supported instructions are `ADD MUL SUB DIV MOD LT GT EQ ISZERO AND OR XOR
NOT BYTE SHL SHR SAR POP PUSH0…PUSH32 DUP1…DUP16 SWAP1…SWAP16`. Windows are
limited to 48 instructions and 256 bytes. Unsupported opcodes and truncated
immediates result in rejection.

The claim concerns a bytecode window over the certified entry heights. Integrating a
replacement into a contract requires proving its actual entry conditions and
accounting for code layout and jump targets, gas observations and forwarding,
and any remaining program context. The CLI emits certificates and never patches
a contract.

## Validation

```sh
python3 -m unittest discover -s tests -v
npm ci
node bench/compile.cjs | python3 bench/extract.py > /tmp/evm-solc-windows.json
diff -u bench/solc-windows.json /tmp/evm-solc-windows.json
python3 tests/differential.py
```

The differential harness compares stack words and exact gas against EthereumJS
on every supported opcode, including 256-bit edge cases, deterministic random
operands and discovered rewrite pairs. The unit tests exercise the CLI, malformed
and forged certificates, stack bounds, and a deeply shared symbolic expression.

The compiler fixture contains disjoint windows of up to six instructions from
`Samples.sol`, compiled with optimized solc 0.8.30 using both its legacy and IR
pipelines. Entry height is the minimum needed to execute a window as an isolated
fragment. Benchmark gas is the sum across local window opportunities. Deployment
and transaction savings require in-context analysis and execution. The sample
is a compiler-output smoke benchmark. See [Head-to-head benchmarks](bench/HEAD_TO_HEAD.md)
for the pinned comparisons with GASOL and the recorded ebso artifact.

### Historical v0.2 comparison against v0.1

The same 167 compiler windows, no byte growth, and a limit of 1,000
expansions per window for each run. Both versions use the same compiler
fixture. CPU times are local observations. Expanded states count the work
of each search loop and do not measure the cost per state.

| Release | Step cap | Verified rewrites | Window gas saved | Bytes saved | Expanded states | Windows at state limit | CPU seconds |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| v0.1 | 5 | 5 | 18 | 7 | 77,600 | 71 | 10.02 |
| v0.2 | 5 | 7 | 24 | 9 | 30,134 | 18 | 9.24 |
| v0.1 | 8 | 5 | 18 | 7 | 77,600 | 71 | 9.10 |
| v0.2 | 8 | 9 | 26 | 12 | 39,270 | 30 | 9.29 |

To reproduce, run this command with each release and repeat with
`--max-steps 8`:

```sh
python3 superopt.py bench bench/solc-windows.json --no-byte-growth --stitch --extra-stack 1
python3 superopt.py optimize 610001 --entry-height 0 --size --max-steps 5 --max-states 1000
```

All 10 unit tests passed. The independent EthereumJS differential run
matched 6,567 executions, including 1,023-word stacks.
