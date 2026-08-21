# mk-fuzz build.
#
#   make            # build the fuzzer and the toy target
#   make run        # build, then fuzz the toy target
#   make clean
#
# Targets are instrumented with clang's SanitizerCoverage (trace-pc-guard) so
# rt.c can see every basic-block edge, and with ASan so memory bugs that don't
# segfault natively still abort.

# `CC ?= clang` does NOT work here: make ships a builtin `CC = cc`, so ?= never
# fires and the instrumented targets silently went to gcc. Only override when
# the value is still make's builtin default.
ifeq ($(origin CC),default)
CC = clang
endif
CFLAGS   ?= -O2 -g -Wall
COV_FLAGS = -fsanitize-coverage=trace-pc-guard
ASAN      = -fsanitize=address

BUILD = build

.PHONY: all run run-zlib run-cjson bench clean
all: $(BUILD)/mk-fuzz $(BUILD)/toy_parser $(BUILD)/zlib_target \
     $(BUILD)/cjson_target $(BUILD)/toy_parser_bench \
     $(BUILD)/zlib_target_bench $(BUILD)/cjson_target_bench

$(BUILD):
	mkdir -p $(BUILD)

# The fuzzer itself is plain, uninstrumented C.
$(BUILD)/mk-fuzz: src/fuzzer.c src/sched.c src/trace.c src/rt.h src/sched.h src/trace.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ src/fuzzer.c src/sched.c src/trace.c -lm

# Instrumented target = harness + coverage/fork-server runtime.
# ASAN_OPTIONS=abort_on_error=1 (set at run time) turns ASan reports into a
# SIGABRT the fuzzer can catch as a crash.
$(BUILD)/toy_parser: targets/toy_parser.c src/rt.c src/rt.h | $(BUILD)
	$(CC) $(CFLAGS) $(COV_FLAGS) $(ASAN) -o $@ targets/toy_parser.c src/rt.c

# zlib, compiled from source so it is actually instrumented. Linking the system
# -lz (as this target used to) leaves the library invisible to trace-pc-guard:
# coverage stuck at the harness's own 8 edges and never moved. Only the inflate
# path is needed. Run third_party/fetch-zlib.sh once to populate the source.
ZLIB_SRC = $(wildcard third_party/zlib/adler32.c third_party/zlib/crc32.c \
                      third_party/zlib/inffast.c third_party/zlib/inflate.c \
                      third_party/zlib/inftrees.c third_party/zlib/zutil.c)
ZLIB_INC = -Ithird_party/zlib

third_party/zlib/inflate.c:
	@third_party/fetch-zlib.sh

$(BUILD)/zlib_target: targets/zlib_inflate.c src/rt.c src/rt.h third_party/zlib/inflate.c | $(BUILD)
	$(CC) $(CFLAGS) $(COV_FLAGS) $(ASAN) $(ZLIB_INC) -o $@ \
	  targets/zlib_inflate.c src/rt.c $(ZLIB_SRC)

# cJSON, likewise compiled from source so it is instrumented.
CJSON_SRC = third_party/cjson/cJSON.c
CJSON_INC = -Ithird_party/cjson

third_party/cjson/cJSON.c:
	@third_party/fetch-cjson.sh

$(BUILD)/cjson_target: targets/cjson_parse.c src/rt.c src/rt.h $(CJSON_SRC) | $(BUILD)
	$(CC) $(CFLAGS) $(COV_FLAGS) $(ASAN) $(CJSON_INC) -o $@ \
	  targets/cjson_parse.c src/rt.c $(CJSON_SRC)

$(BUILD)/cjson_target_bench: targets/cjson_parse.c src/rt.c src/rt.h $(CJSON_SRC) | $(BUILD)
	$(CC) $(CFLAGS) $(COV_FLAGS) $(CJSON_INC) -o $@ \
	  targets/cjson_parse.c src/rt.c $(CJSON_SRC)

run-cjson: all
	ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
	  $(BUILD)/mk-fuzz -i seeds_cjson -o out_cjson -- $(BUILD)/cjson_target

# Benchmark builds: coverage instrumentation but no ASan. ASan costs 11x
# throughput here (107 vs 1167 execs/s on toy_parser, measured on NANI) because
# every fork has to copy its shadow mapping and every abort goes through ASan's
# reporter. The scheduler comparison is about coverage growth per execution, so
# the benchmark matrix uses these and gives up the extra memory-bug depth.
$(BUILD)/toy_parser_bench: targets/toy_parser.c src/rt.c src/rt.h | $(BUILD)
	$(CC) $(CFLAGS) $(COV_FLAGS) -o $@ targets/toy_parser.c src/rt.c

$(BUILD)/zlib_target_bench: targets/zlib_inflate.c src/rt.c src/rt.h third_party/zlib/inflate.c | $(BUILD)
	$(CC) $(CFLAGS) $(COV_FLAGS) $(ZLIB_INC) -o $@ \
	  targets/zlib_inflate.c src/rt.c $(ZLIB_SRC)

bench: all
	bench/run.sh

run: all
	ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
	  $(BUILD)/mk-fuzz -i seeds -o out -- $(BUILD)/toy_parser

run-zlib: all
	ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
	  $(BUILD)/mk-fuzz -i seeds_zlib -o out_zlib -- $(BUILD)/zlib_target

clean:
	rm -rf $(BUILD) out out_zlib out_cjson
