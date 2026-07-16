#!/usr/bin/env bash
# End-to-end demo of the mk-fuzz hybrid pipeline.
#   1. build everything
#   2. fuzz the toy target until it finds a crash (or times out)
#   3. reproduce a saved crash against the real binary
#   4. run the symbolic executor and verify its Z3-solved input crashes the target
set -u
cd "$(dirname "$0")"

CC="${CC:-clang}"
FUZZ_SECS="${FUZZ_SECS:-20}"

echo "=== [1/4] build ==="
make CC="$CC" >/dev/null || { echo "build failed"; exit 1; }

echo "=== [2/4] fuzz toy target for ${FUZZ_SECS}s ==="
rm -rf out
timeout "${FUZZ_SECS}" env ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
  build/mk-fuzz -i seeds -o out -- build/toy_parser 2>&1 | tail -3
echo

crash="$(ls out/crashes/* 2>/dev/null | head -1 || true)"
if [ -n "${crash}" ]; then
  echo "=== [3/4] reproduce fuzzer-found crash: ${crash} ==="
  ASAN_OPTIONS=detect_leaks=0 build/toy_parser < "${crash}"
  echo "target exit = $?  (134 = SIGABRT, ASan/abort caught a real fault)"
else
  echo "=== [3/4] no crash saved this run (try FUZZ_SECS=60) ==="
fi
echo

echo "=== [4/4] symbolic executor cracks the gated branch ==="
if [ -x symbolic/venv/bin/python ]; then
  PY=symbolic/venv/bin/python
else
  PY=python3
fi
"$PY" symbolic/symex.py --emit out/queue
sol="$(ls out/queue/symex_* 2>/dev/null | head -1 || true)"
if [ -n "${sol}" ]; then
  echo "--- feeding Z3's solution to the REAL target ---"
  ASAN_OPTIONS=detect_leaks=0 build/toy_parser < "${sol}"
  echo "target exit = $?  (134 = SIGABRT: symbolic input crashed the real binary)"
fi
