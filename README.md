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
| `src/sched.c` | Mutation-operator schedulers: the original hand-weighted table, Thompson sampling, and LinUCB. |
| `src/trace.c` | Optional per-mutation JSONL trace + coverage-vs-executions CSV, and the end-of-run summary. |
| `targets/cjson_parse.c` | Second real-library target: cJSON's parser, compiled from source so it is instrumented. |
| `bench/run.sh` | Benchmark matrix (scheduler x target x seed) at a fixed execution budget. |
| `bench/summarize.py` | Turns `results/` into the summary table and the coverage plot. |
| `bench/bug_gate.sh` | Checks every scheduler still finds `toy_parser`'s planted bugs, and that the learned ones adapt. |

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
third_party/fetch-zlib.sh  # once: zlib source, so the target is instrumented
third_party/fetch-cjson.sh # once: cJSON source, same reason
make                       # builds the fuzzer + all targets
make run                   # fuzz the toy target (finds crashes in seconds)
make run-zlib              # fuzz zlib inflate (real library)
make run-cjson             # fuzz cJSON's parser (real library)
make bench                 # the scheduler benchmark matrix -> results/
```

Useful flags: `--scheduler=baseline|bandit|linucb`, `-s <seed>`, `-E <execs>` /
`-T <secs>` to bound a run, `--trace <path>` for a per-mutation JSONL trace and
`--cov <path>` for a coverage-vs-executions CSV.

The symbolic executor needs Z3:

```sh
python3 -m venv symbolic/venv && symbolic/venv/bin/pip install z3-solver
symbolic/venv/bin/python symbolic/symex.py --emit out/queue
```

`./demo.sh` runs the whole pipeline end to end.

## Results (this machine)

- **Toy target:** the fuzzer defeats the 4-byte `MKF1` magic gate purely from
  edge feedback and finds both planted bugs within seconds — a stack-buffer
  overflow (caught by ASan at `toy_parser.c:27`) and a `SIGABRT` poison path.
  Crashes are saved and deduplicated in `out/crashes/`.
- **Symbolic assist:** `symex.py` explores the toy parser's IR, and Z3 solves the
  magic + length-guard + poison-byte constraints in one shot, emitting
  `MKF1\xff\x01\xff`. Fed to the *real* compiled target it aborts (exit 134,
  SIGABRT) — verified, not asserted.
- **Real libraries:** zlib `inflate` and cJSON's parser, both compiled from
  source *with* instrumentation — 453 and 300 edges respectively, with real
  coverage growth. No crash in either (both are hardened/heavily fuzzed).

  > Correction: this section previously reported the zlib target as a coverage
  > result. It was not one. The target linked the system `-lz`, which is not
  > instrumented, so `trace-pc-guard` only ever saw the 8 edges inside the
  > harness file and coverage sat flat at 8 for entire runs. `third_party/` now
  > builds zlib's inflate path from source. See `third_party/fetch-zlib.sh`.

## Learned mutation-operator scheduling

The original fuzzer picked its havoc operator with a bare `rnd_below(11)`, where
duplicated `switch` cases gave *delete* and *clone* double weight — an implicit
hand-tuned distribution of `[1,1,1,1,1,1,2,2,1]/11` over nine operator families.
This replaces that hand tuning with a learned policy, keeps the original as a
flag-selectable baseline, and benchmarks both.

```sh
mk-fuzz --scheduler=baseline  # the original hand-weighted distribution (default)
mk-fuzz --scheduler=bandit    # Thompson sampling, reward = newly covered edges
mk-fuzz --scheduler=linucb    # contextual bandit over coverage/frontier features
```

`--scheduler=baseline` is byte-for-byte the old behaviour: the weight table is
the old `switch` verbatim, indexed by the same single RNG draw, so the fuzzing
trajectory is unchanged. Verified by diffing artifacts against a binary built
from the pre-scheduler commit — 14/14 queue entries and 14/14 crashes identical,
in identical order.

**Credit assignment is the actual problem here**, not the bandit math. `mutate()`
stacks 2–64 edits before a *single* execution, so one coverage signal has to be
shared out over several operators. Each operator receives a share of the
execution's trial mass proportional to how many of the stacked edits it
contributed. Both learners sample per-edit, exactly as the baseline does, so the
only difference between arms is the distribution being sampled.

- **bandit** — one Beta posterior per operator over "did this execution find
  coverage". Thompson sampling rather than UCB1's argmax on purpose: an argmax
  rule would pick the same operator for all 64 stacked edits and destroy the
  mixing the baseline has.
- **linucb** — ridge regression per operator over four features (coverage
  saturation, corpus/frontier size, recent hit-rate, input size class) plus a
  bias, then a softmax over the resulting scores. This is a **contextual
  bandit**, not deep RL: it is a 5×5 matrix update, no gradients, no training
  loop, ~200 lines of arithmetic in `src/sched.c`.

Both start from the hand-tuned weights as a weak prior — they have to *earn* a
departure from the status quo — and decay accumulated evidence periodically,
because coverage feedback is strongly non-stationary (early edges are cheap,
late edges are not).

### Results

Fixed **execution** budget, not wall-clock: LinUCB costs more per selection, and
a time budget would quietly hand the cheapest scheduler more attempts. Five
seeds per configuration; the summary reports median and full range, never
mean ± sd, because n=5 cannot support a normal-theory interval. Comparisons are
paired by seed (same RNG start, same seed corpus) and tested with an exact sign
test, whose best attainable p-value at n=5 is 1/32 = 0.031.

`bench/run.sh` regenerates everything; `results/summary.md` and
`results/coverage.png` are the artifacts.

**zlib `inflate`** — 200,000 executions/run, 5 seeds:

| scheduler | median edges | range | vs baseline | paired W–L | sign-test p |
|---|---|---|---|---|---|
| `baseline` | **510** | 486–516 | — | — | — |
| `bandit` | 510 | 490–513 | ±0 (0.0%) | 3–2 | 1.000 |
| `linucb` | 493 | 474–509 | −17 (−3.3%) | 1–4 | 0.375 |

**cJSON parser** — 30,000 executions/run, 5 seeds:

| scheduler | median edges | range | vs baseline | paired W–L | sign-test p |
|---|---|---|---|---|---|
| `baseline` | **311** | 308–319 | — | — | — |
| `bandit` | 304 | 300–305 | −7 (−2.3%) | 0–5 | 0.062 |
| `linucb` | 305 | 299–319 | −6 (−1.9%) | 2–3 | 1.000 |

**The learned schedulers did not beat the hand-tuned baseline.** On zlib the
bandit ties it (3–2 across seeds, p = 1.000) and LinUCB loses 3.3%. On cJSON
both lose by ~2%, and the bandit lost on all five seeds — the strongest signal
in the table, and it points the wrong way (p = 0.062, which is the *floor* a
0–5 split can reach, so even this is not significant at n=5).

The endpoint table hides one real effect that the curves show. On zlib the
bandit leads for most of the run and only converges at the end — median edges
vs baseline at matched execution counts:

| execs | 10k | 26k | 50k | 76k | 100k | 150k | 200k |
|---|---|---|---|---|---|---|---|
| `bandit` − `baseline` | +6 | +5 | **+11** | +1 | +4 | +1 | 0 |
| `linucb` − `baseline` | −1 | −7 | −9 | −13 | −20 | −11 | −17 |

So the bandit is worth ~2.4% at 50k executions on zlib and nothing by 200k. On
cJSON it is behind from 10k onward (−8, −9, −7 at 10k/20k/30k). One
target-specific early lead that evaporates is not a result; it is the shape you
would expect from a policy that optimises a short-horizon proxy.

They did, however, genuinely learn something — the policy moved off the hand
tuning by 60–140× the sampling-noise floor, so "it beat nothing because it never
adapted" is ruled out:

| scheduler | TV(run, hand-tuned weights), zlib | cJSON |
|---|---|---|
| `baseline` (noise floor) | 0.0004 | 0.0011 |
| `bandit` | 0.0970 | 0.0936 |
| `linucb` | 0.1438 | 0.1422 |

The direction both learners moved is informative: they flatten the
distribution *toward uniform*, shedding the baseline's double weight on delete
and clone. Those two structural operators are worth more than their marginal
per-execution coverage yield suggests, and a reward defined as edges-per-execution
cannot see that. This is the honest conclusion — **AFL's hand-tuned weights
encode something a myopic per-execution reward does not capture.** Fixing it
needs a better reward (credit for corpus entries that later prove productive),
not a better bandit.

### Does it still find bugs?

`bench/bug_gate.sh` runs all three schedulers against `targets/toy_parser` (ASan
build) and replays every saved crash against the real binary to classify it. At
3000 executions per scheduler:

| scheduler | crashes saved | replay as B1 (stack overflow) | TV vs hand-tuned weights |
|---|---|---|---|
| `baseline` | 12 | 12 | 0.0037 *(noise floor)* |
| `bandit` | 12 | 12 | 0.1283 — **34x** the floor |
| `linucb` | 9 | 9 | 0.1392 — **37x** the floor |

So swapping the scheduler does not break bug-finding, and both learners
demonstrably departed from the hand tuning rather than resampling it forever.
Note that at this budget every saved crash replays as B1; the ASan
stack-buffer-overflow report fires first even on inputs that would also hit B2's
poison-byte `abort()`, so the classifier cannot separate them here.

### Limitations

- **Single machine**, one CPU-constrained Linux laptop. Throughput figures are
  contention-affected and not comparable to a dedicated benchmark host.
- **Two targets** (zlib inflate, cJSON), one seed corpus each, hand-picked.
  `toy_parser` is excluded from the coverage matrix because it saturates at 13
  edges inside 1000 executions; it serves as the bug-finding gate instead.
- **Different budgets per target** (200k for zlib, 30k for cJSON). Within a
  target the budget is identical across schedulers, which is what the comparison
  needs, but the two targets are not comparable to each other.
- **The early-vs-late adaptation metric needs a long run.** Both learners adapt
  inside their first 1000 executions, so on a short run the "early" window is
  already post-adaptation and the comparison is uninformative — the bug gate
  reports it as advisory below 20k executions and gates on the
  distance-from-hand-weights metric instead. On the 200k benchmark runs it
  clears the noise floor by 6-8x.
- **5 seeds is the floor, not comfort.** At n=5 an exact sign test cannot go
  below p = 0.031, so nothing here could have reached significance even had the
  effect been large. Treat every number as an effect-size estimate.
- **No comparison against MOpt, AFL++'s schedulers, or any published work.** The
  only baseline is this fuzzer's own prior hand tuning.
- **The learned scheduler did not beat the baseline** on either target.
- **Coverage matrix runs without ASan** (11× faster: 107 → 1167 execs/s on
  toy_parser). The comparison is about coverage growth per execution; the
  bug-finding gate uses the ASan build.
- **Reward is myopic**: newly covered edges on *this* execution, with a small
  consolation for a new hit-count bucket. No credit for inputs whose value only
  materialises later, which the results above suggest is the binding limitation.
- Coverage curves flatten well before the budget on both targets, which
  compresses any late-run difference between schedulers.

## Roadmap (what a full build adds next)

0. **A less myopic scheduler reward.** The benchmark above says the hand-tuned
   weights beat a bandit trained on edges-per-execution, and that the learners
   respond by flattening toward uniform — i.e. the reward cannot see why
   *delete* and *clone* deserve extra weight. The fix is credit assignment over
   a longer horizon (reward an operator when the corpus entry it produced later
   yields coverage), not a fancier policy class.
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
only) and no coverage-guided *seed* scheduling beyond uniform-random selection —
the learned schedulers added here choose mutation *operators*, which is a
different axis. See the limitations under "Learned mutation-operator
scheduling" for that experiment's own caveats.
