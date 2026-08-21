#!/usr/bin/env bash
#
# T2 gate: every scheduler must still find the planted bug, and the learned ones
# must demonstrably adapt rather than resample the hand-tuned weights forever.
#
# Runs targets/toy_parser, which has two planted bugs:
#   B1  stack buffer overflow (a record length larger than the 16-byte scratch)
#   B2  abort() behind the 4-byte "MKF1" magic when the first payload byte is 0xFF
#
# This uses the ASAN build, not the _bench build, on purpose. Without ASan, B1
# is undefined behaviour that corrupts the parser's own loop counter instead of
# faulting, so runs degenerate into a stream of 1-second execution timeouts and
# never get anywhere. ASan turns the overflow into a prompt SIGABRT. It costs
# roughly 10x throughput, which is why the coverage matrix (bench/run.sh) uses
# the non-ASan builds and this gate does not.
set -uo pipefail
# Force the C locale: under a comma-decimal locale (de_DE) bash printf both
# renders "0,0000" and REJECTS "0.1392" as an invalid number, so the gate
# output becomes gibberish while the python comparisons stay correct.
export LC_ALL=C
cd "$(dirname "$0")/.."

EXECS="${EXECS:-20000}"
SEED="${SEED:-1}"
OUT="${OUT:-results/buggate}"
# Two adaptation metrics, both measured against the baseline's own value, which
# is pure sampling noise because the baseline cannot adapt by construction:
#
#   tv_early_vs_late    TV(first 1000 execs, last full 1000 execs). Only
#                       meaningful on a LONG run: both learners adapt inside
#                       their first 1000 executions, so on a short run the
#                       "early" window is already post-adaptation and the two
#                       windows look alike for reasons that have nothing to do
#                       with whether learning happened. Below LATE_MIN_EXECS
#                       this is reported but NOT gated -- the benchmark matrix
#                       (200k executions) is where it carries weight, and there
#                       it clears the floor by 6-8x.
#   tv_vs_handweights   TV(whole-run selection share, the hand-tuned weights).
#                       This is the number that actually answers "did it move
#                       off the hand tuning", and it is far less noisy, so it
#                       gets a 10x margin.
LATE_MARGIN="${LATE_MARGIN:-3}"
LATE_MIN_EXECS="${LATE_MIN_EXECS:-20000}"
HAND_MARGIN="${HAND_MARGIN:-10}"

mkdir -p "$OUT"
make all >/dev/null || exit 1

declare -A TV_LATE TV_HAND
fail=0

for sched in baseline bandit linucb; do
  d="$OUT/$sched"; rm -rf "$d"; mkdir -p "$d"
  echo "== $sched =="
  ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
    build/mk-fuzz --scheduler="$sched" -s "$SEED" -E "$EXECS" \
      -i seeds -o "$d" -- build/toy_parser 2>/dev/null > "$OUT/$sched.json"

  # Classify every saved crash by replaying it against the real binary, so the
  # gate reports which planted bug was actually reached rather than just a count.
  b1=0; b2=0; other=0
  for f in "$d"/crashes/*; do
    [ -e "$f" ] || continue
    rep="$(ASAN_OPTIONS=detect_leaks=0 build/toy_parser < "$f" 2>&1)"
    if grep -q 'stack-buffer-overflow' <<<"$rep"; then b1=$((b1 + 1))
    elif grep -qiE 'abort|SIGABRT' <<<"$rep" || [ -z "$rep" ]; then b2=$((b2 + 1))
    else other=$((other + 1)); fi
  done
  n=$(ls "$d"/crashes 2>/dev/null | wc -l)
  echo "  crashes saved=$n  replayed as B1(overflow)=$b1  B2(abort)=$b2  unclassified=$other"
  if [ "$n" -eq 0 ]; then
    echo "  GATE FAIL: $sched found no crash in $EXECS executions"
    fail=1
  fi

  read -r tvl tvh < <(python3 -c "
import json; d = json.load(open('$OUT/$sched.json'))
print(d['tv_early_vs_late'], d['tv_vs_handweights'])")
  TV_LATE[$sched]=$tvl
  TV_HAND[$sched]=$tvh
  echo "  TV(first 1000 execs vs last 1000 execs) = $tvl"
  echo "  TV(whole run vs hand-tuned weights)     = $tvh"
done

echo
bl="${TV_LATE[baseline]}"; bh="${TV_HAND[baseline]}"
echo "noise floors from the baseline: early-vs-late=$bl  vs-handweights=$bh"
for sched in bandit linucb; do
  for metric in late hand; do
    if [ "$metric" = late ]; then
      v="${TV_LATE[$sched]}"; f="$bl"; m="$LATE_MARGIN"; label="early-vs-late"
    else
      v="${TV_HAND[$sched]}"; f="$bh"; m="$HAND_MARGIN"; label="vs-handweights"
    fi
    ok=$(python3 -c "print(1 if $v > $m * $f else 0)")
    if [ "$ok" = 1 ]; then
      printf 'ADAPTATION OK  %-7s %-16s %.4f > %sx %.4f\n' "$sched" "$label" "$v" "$m" "$f"
    elif [ "$metric" = late ] && [ "$EXECS" -lt "$LATE_MIN_EXECS" ]; then
      printf 'ADVISORY       %-7s %-16s %.4f vs %sx %.4f (not gated below %s execs)\n' \
        "$sched" "$label" "$v" "$m" "$f" "$LATE_MIN_EXECS"
    else
      printf 'GATE FAIL      %-7s %-16s %.4f is not > %sx %.4f\n' "$sched" "$label" "$v" "$m" "$f"
      fail=1
    fi
  done
done
exit $fail
