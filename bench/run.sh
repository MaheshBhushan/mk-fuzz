#!/usr/bin/env bash
#
# Benchmark matrix: every scheduler x every target x SEEDS seeds, at a fixed
# execution budget. Writes one coverage CSV and one summary JSON per run into
# results/, then bench/summarize.py turns those into the table and the plot.
#
#   bench/run.sh                     # full matrix
#   SEEDS=3 EXECS=50000 bench/run.sh # quicker
#   JOBS=4 bench/run.sh              # parallelism
#
# The budget is in EXECUTIONS, not seconds. Schedulers differ in per-selection
# cost (LinUCB does a 5x5 matrix inverse per update), so a wall-clock budget
# would quietly hand the cheapest scheduler more attempts and confound exactly
# the thing being measured. Wall-clock is still recorded in every CSV and the
# summary reports execs/s, so the overhead stays visible rather than hidden.
#
# Concurrency is delegated to `xargs -P`. A hand-rolled `while [ $(jobs -rp |
# wc -l) -ge $JOBS ]; do wait -n; done` gate does NOT work: the command
# substitution runs in a subshell with an empty job table, so the count is
# always 0, the gate never blocks, and the whole matrix launches at once. That
# does not corrupt an exec-budgeted result, but it does wreck the execs/s column
# and it thrashes the machine.
set -uo pipefail
# Force the C locale: under a comma-decimal locale (de_DE) bash printf both
# renders "0,0000" and REJECTS "0.1392" as an invalid number, so the gate
# output becomes gibberish while the python comparisons stay correct.
export LC_ALL=C
cd "$(dirname "$0")/.."

SEEDS="${SEEDS:-5}"
EXECS="${EXECS:-200000}"
COV_EVERY="${COV_EVERY:-2000}"
JOBS="${JOBS:-4}"
SCHEDULERS="${SCHEDULERS:-baseline bandit linucb}"
# target:seed_dir. Only targets with real coverage headroom belong here.
# toy_parser is deliberately excluded: it saturates at 13 edges inside 1000
# executions, so every scheduler ties and the row would mean nothing. It is
# covered by bench/bug_gate.sh instead.
TARGETS="${TARGETS:-zlib_target_bench:seeds_zlib cjson_target_bench:seeds_cjson}"

RESULTS="${RESULTS:-results}"
SEED_FLOOR=5

mkdir -p "$RESULTS"
make all >/dev/null || { echo "build failed"; exit 1; }

# One run, invoked by xargs as: bench/run.sh --one <sched> <target> <seeddir> <seed>
if [ "${1:-}" = "--one" ]; then
    sched="$2"; target="$3"; seeddir="$4"; seed="$5"
    tag="${target%_bench}.${sched}.s${seed}"
    out="$(mktemp -d)"
    build/mk-fuzz --scheduler="$sched" -s "$seed" -E "$EXECS" \
        --cov "$RESULTS/${tag}.csv" --cov-every "$COV_EVERY" \
        -i "$seeddir" -o "$out" -- "build/$target" \
        2>/dev/null > "$RESULTS/${tag}.json"
    rc=$?
    rm -rf "$out"
    if [ $rc -ne 0 ]; then
        echo "  FAILED $tag (rc=$rc)"
        exit 1
    fi
    echo "  done $tag  $(python3 -c "
import json; d=json.load(open('$RESULTS/${tag}.json'))
print('edges=%d execs/s=%d' % (d['edges'], round(d['execs']/(d['t_ms']/1000))))")"
    exit 0
fi

echo "matrix: schedulers=[$SCHEDULERS] targets=[$TARGETS] seeds=1..$SEEDS execs=$EXECS jobs=$JOBS"

export RESULTS EXECS COV_EVERY

for entry in $TARGETS; do
  target="${entry%%:*}"; seeddir="${entry##*:}"
  for sched in $SCHEDULERS; do
    for seed in $(seq 1 "$SEEDS"); do
      printf '%s %s %s %s\n' "$sched" "$target" "$seeddir" "$seed"
    done
  done
done | xargs -P "$JOBS" -n 4 bash -c 'bench/run.sh --one "$0" "$1" "$2" "$3"'

fail=0
for entry in $TARGETS; do
  target="${entry%%:*}"
  for sched in $SCHEDULERS; do
    n=$(ls "$RESULTS/${target%_bench}.${sched}.s"*.json 2>/dev/null | wc -l)
    if [ "$n" -lt "$SEED_FLOOR" ]; then
      echo "GATE FAIL: ${target%_bench}/${sched} has $n seeds, the floor is $SEED_FLOOR"
      fail=1
    fi
  done
done
[ $fail -eq 0 ] && echo "seed-count gate: OK (>=$SEED_FLOOR seeds per configuration)"

python3 bench/summarize.py "$RESULTS" || fail=1
exit $fail
