# mk-fuzz

![Language: C](https://img.shields.io/badge/language-C-00599C?logo=c)
![Symbolic: Z3](https://img.shields.io/badge/symbolic-Z3-8A2BE2)
![Instrumentation: clang SanitizerCoverage](https://img.shields.io/badge/instrumentation-clang%20trace--pc--guard-orange?logo=llvm)
![Platform: Linux](https://img.shields.io/badge/platform-Linux-333?logo=linux&logoColor=white)

A coverage-guided, AFL-style fuzzer with a Z3-backed **baby symbolic executor**
bolted on to crack the branches fuzzing can't reach. Written from scratch in C
(the fuzzer + coverage/fork-server runtime) and Python (the symbolic engine).

It is small enough to read in an afternoon and complete enough to find real
memory-corruption bugs under AddressSanitizer.

```
   seeds ──► ┌─────────── mk-fuzz (C) ───────────┐
             │  mutate → run → read edge bitmap   │        ┌── new edge? ──► keep in corpus
             │        ▲                    │      │───────►│
             │        └──── fork server ───┘      │        └── crash?    ──► out/crashes
             └────────────────┬──────────────────┘
                              │ shared-memory coverage bitmap (64 KiB)
              instrumented target  (harness + rt.c, clang trace-pc-guard + ASan)
                              ▲
                              │ solved input for a gated branch
             ┌────────────────┴──────────────────┐
             │   symex.py (Python + Z3)           │  concolic path exploration
             │   symbolic executor over a tiny IR │  over an 8-bit register IR
             └────────────────────────────────────┘
```

## Layout

| Path | What it is |
|---|---|
| `src/rt.c` | Coverage runtime + fork server, linked into every target. Implements the AFL edge hash `bitmap[prev ^ cur]++; prev = cur >> 1` and the fork-server protocol. |
| `src/fuzzer.c` | The fuzzer: shared-memory bitmap, fork-server client, corpus, coverage feedback (bucketed hit counts + virgin-bit tracking), havoc/splice mutation, crash dedup. |
| `targets/toy_parser.c` | A target with two planted bugs behind a 4-byte magic gate, to prove the loop finds things. |
| `targets/zlib_inflate.c` | A real-library target: zlib `inflate()` under ASan (Phase 3). |
| `symbolic/symex.py` | The baby symbolic/concolic executor (Z3). Explores paths over a small IR and solves gated branches. |

## How it works

**Coverage.** Targets are compiled with `-fsanitize-coverage=trace-pc-guard`, so
clang inserts a callback at every basic block. `rt.c` gives each block a unique
id and records *edges* (block→block transitions) into a 64 KiB bitmap in shared
memory. The `>> 1` on the previous block keeps A→B distinct from B→A. This is the
exact scheme AFL's llvm-mode uses.

**Fork server.** Instead of `execve`-ing the target once per input (the dynamic
loader + libc init dominate), `rt.c` initialises once and forks a fresh child per
testcase on command over a control pipe (fds 198/199). Biggest single speedup in
the whole system.

**Feedback loop.** After each run the fuzzer folds raw hit counts into log2-ish
buckets (so 40-vs-41 hits doesn't look like new coverage, but 1→2→many does) and
compares against a `virgin_bits` map. Any input that lights up a never-before-seen
edge/bucket is added to the corpus. Crashes are deduplicated by coverage so you
get distinct bugs, not thousands of copies of one.

**Symbolic assist.** `symex.py` models input bytes as 8-bit Z3 variables and
interprets a tiny register IR, forking at each conditional branch and using Z3 to
(a) prune infeasible paths and (b) solve the path constraints when a `BUG`
instruction is reached. The solved input is written into the fuzzer's queue so
the two halves form a hybrid (Driller-style) loop: fuzzing does the volume,
symbolic execution unlocks the narrow gates.

## Build & run

Requires `clang` (with SanitizerCoverage + ASan) and `make`.

```sh
make                       # builds the fuzzer + both targets
make run                   # fuzz the toy target (finds crashes in seconds)
make run-zlib              # fuzz zlib inflate (real library, Phase 3)
```

The symbolic executor needs Z3:

```sh
python3 -m venv symbolic/venv && symbolic/venv/bin/pip install z3-solver
symbolic/venv/bin/python symbolic/symex.py --emit out/queue
```

`./demo.sh` runs the whole pipeline end to end.

## Cross-platform parameter-parser differential harness

The portable harness runs the same binary fixtures against two independent C
implementations. `targets/parameters_legacy.c` uses bounded C strings and
`strtoll`; `targets/parameters_migrated.c` uses byte slices and checked
fixed-width arithmetic. These are demonstration parameter parsers added for
migration testing. The existing toy container parser keeps its planted bugs.

```sh
make CC=clang test-differential
```

This builds both parsers with AddressSanitizer, compares the shared fixtures
against explicit expected results, and runs deterministic mutations plus harness
regression tests. Python 3.9+ runs the driver without third-party dependencies.
The `Differential parser replay` GitHub Actions workflow runs this check on
Linux and macOS. The differential targets do not link the Linux fork server.

The example parameter contract is:

| Field | Accepted value | Default |
|---|---|---|
| `count` | Decimal digits, 0 through 65535 | 1 |
| `offset` | Decimal digits with an optional `-`, -2147483648 through 2147483647 | 0 |
| `mode` | `safe` or `fast` | `safe` |

An empty input uses defaults. Other inputs contain `key=value` fields separated
by `;`. Keys are case sensitive. Leading zeros are accepted. Whitespace, `+`,
embedded NULs, empty fields, and repeated keys are rejected. Input length is
limited to 256 bytes. Size and NUL checks precede field parsing. Each field is
checked for syntax, known key, duplicate key, then value syntax and range.
The first failing check determines the rejection reason. Numeric syntax is
checked completely before range conversion. This keeps huge numbers with
trailing junk consistent across implementations and integer widths.

Each parser reads raw bytes from stdin and writes one JSON object. Exit 0 means
acceptance; exit 2 means rejection. The driver compares all accepted field values
and rejection reasons. Crashes, timeouts, stderr diagnostics, invalid protocol,
and unexpected exits always fail, including identical failures in both binaries.
Golden fixtures catch shared mistakes in both implementations.

Failures retain SHA-256-named `.bin` inputs and `.json` observations in
`out_diff/counterexamples/`. Metadata includes commands, platform, raw stdout and
stderr as hex, exit codes, and the expected result when available. Repeated
inputs preserve their first observation. CI uploads counterexamples per platform.
Copy those files to another platform and replay them against its native binaries:

```sh
python3 differential/replay.py --legacy build/parameters_legacy \
  --migrated build/parameters_migrated --replay out_diff/counterexamples \
  --out out_diff/replayed
```

`--fixtures PATH` accepts additional JSON fixture arrays with `name`, `hex`, and
`expected` fields. `--replay DIR` consumes saved `.bin` files and their optional
expected-result metadata. Each process has a configurable timeout of one second
by default. Empty fixture sets and missing replay directories fail the command.
Other parser executables can use the same JSON/exit protocol as adapters.

Z3 generates the committed integer-boundary fixtures. Ordinary replay uses those
fixtures directly; CI also verifies them against fresh solver results:

```sh
# Reuse the symbolic engine's environment from the setup above.
symbolic/venv/bin/python symbolic/parameter_boundaries.py \
  --check tests/fixtures/parameters_boundaries.json
# Regenerate after deliberately changing the parameter contract:
symbolic/venv/bin/python symbolic/parameter_boundaries.py > tests/fixtures/parameters_boundaries.json
```

## Results (this machine)

- **Toy target:** the fuzzer defeats the 4-byte `MKF1` magic gate purely from
  edge feedback and finds both planted bugs within seconds — a stack-buffer
  overflow (caught by ASan at `toy_parser.c:27`) and a `SIGABRT` poison path.
  Crashes are saved and deduplicated in `out/crashes/`.
- **Symbolic assist:** `symex.py` explores the toy parser's IR, and Z3 solves the
  magic + length-guard + poison-byte constraints in one shot, emitting
  `MKF1\xff\x01\xff`. Fed to the *real* compiled target it aborts (exit 134,
  SIGABRT) — verified, not asserted.
- **Real library:** zlib `inflate` fuzzes at ~650 execs/s under ASan through the
  fork server. No crash (zlib is hardened) — the point is that pointing the
  fuzzer at a real binary is a one-file harness change.

## Roadmap (what a full build adds next)

1. **Dictionaries + structured seeds** to push past format checks in real libs.
2. **Persistent mode** (loop N iterations inside one fork) — the throughput fix
   for ASan-heavy targets; the toy target is I/O/teardown bound today.
3. **CmpLog / input-to-state** (RedQueen-style) — in practice often beats
   symbolic execution for magic-byte and checksum gates.
4. **Corpus minimisation** (`afl-cmin`/`tmin` equivalents) and crash triage
   with stack-hash bucketing.
5. **Deeper symbolic engine:** lift real LLVM IR (via `clang -emit-llvm`) instead
   of a hand-written IR, model memory/symbolic pointers, and drive it from the
   fuzzer's stuck inputs automatically.
6. **QEMU mode** for black-box (no source) binaries.

### Honest limitations

The symbolic executor operates on a hand-lifted IR, not the target's actual
instructions, and models only integer/byte operations with a flat memory view —
symbolic pointers are out of scope. It demonstrates the *mechanism* (path
forking + SMT solving + feeding results back to the fuzzer); a production build
would lift real IR. The fuzzer has no deterministic bit-flip stage yet (havoc
only) and no coverage-guided seed scheduling beyond uniform-random selection.
