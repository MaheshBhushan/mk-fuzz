# mk-fuzz build.
#
#   make            # build the fuzzer and the toy target
#   make run        # build, then fuzz the toy target
#   make clean
#
# Targets are instrumented with clang's SanitizerCoverage (trace-pc-guard) so
# rt.c can see every basic-block edge, and with ASan so memory bugs that don't
# segfault natively still abort.

CC       ?= clang
CFLAGS   ?= -O2 -g -Wall
COV_FLAGS = -fsanitize-coverage=trace-pc-guard
ASAN      = -fsanitize=address

BUILD = build
PYTHON ?= python3
DIFF_FLAGS = -std=c11 -Wall -Wextra -Werror -g -O1 -fno-omit-frame-pointer $(ASAN)

.PHONY: all run run-zlib clean
all: $(BUILD)/mk-fuzz $(BUILD)/toy_parser $(BUILD)/zlib_target

$(BUILD):
	mkdir -p $(BUILD)

# The fuzzer itself is plain, uninstrumented C.
$(BUILD)/mk-fuzz: src/fuzzer.c src/rt.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ src/fuzzer.c

# Instrumented target = harness + coverage/fork-server runtime.
# ASAN_OPTIONS=abort_on_error=1 (set at run time) turns ASan reports into a
# SIGABRT the fuzzer can catch as a crash.
$(BUILD)/toy_parser: targets/toy_parser.c src/rt.c src/rt.h | $(BUILD)
	$(CC) $(CFLAGS) $(COV_FLAGS) $(ASAN) -o $@ targets/toy_parser.c src/rt.c

$(BUILD)/zlib_target: targets/zlib_inflate.c src/rt.c src/rt.h | $(BUILD)
	$(CC) $(CFLAGS) $(COV_FLAGS) $(ASAN) -o $@ targets/zlib_inflate.c src/rt.c -lz

run: all
	ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
	  $(BUILD)/mk-fuzz -i seeds -o out -- $(BUILD)/toy_parser

run-zlib: all
	ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
	  $(BUILD)/mk-fuzz -i seeds_zlib -o out_zlib -- $(BUILD)/zlib_target

clean:
	rm -rf $(BUILD) out out_zlib

# Portable differential targets do not depend on the Linux fork-server runtime.
.PHONY: differential replay-differential test-differential
differential: $(BUILD)/parameters_legacy $(BUILD)/parameters_migrated

$(BUILD)/parameters_%: targets/parameters_%.c targets/parameters_main.c targets/parameters.h | $(BUILD)
	$(CC) $(CFLAGS) $(DIFF_FLAGS) -o $@ targets/parameters_$*.c targets/parameters_main.c

replay-differential: differential
	$(PYTHON) differential/replay.py --legacy $(BUILD)/parameters_legacy \
	  --migrated $(BUILD)/parameters_migrated --fixtures tests/fixtures/parameters.json \
	  --fixtures tests/fixtures/parameters_boundaries.json

test-differential: replay-differential
	$(PYTHON) -u -m unittest discover -s tests -p 'test_differential.py' -v

# Crash triage: cluster out/crashes by stack trace (needs scikit-learn).
.PHONY: triage test-triage
triage: $(BUILD)/toy_parser
	$(PYTHON) triage/cluster.py -i out/crashes -o out/triage -- $(BUILD)/toy_parser

test-triage: $(BUILD)/toy_parser
	$(PYTHON) -u -m unittest discover -s tests -p 'test_triage.py' -v
