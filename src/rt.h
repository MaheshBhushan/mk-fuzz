#ifndef MKFUZZ_RT_H
#define MKFUZZ_RT_H

/* Shared coverage bitmap size (must be a power of two). 64 KiB matches AFL's
 * default MAP_SIZE and keeps edge-hash collisions rare for small targets. */
#define MAP_SIZE_POW2 16
#define MAP_SIZE (1U << MAP_SIZE_POW2)

/* Fork-server control pipe file descriptors, inherited by the instrumented
 * target. Same fixed numbers AFL uses so the scheme is easy to cross-check. */
#define FORKSRV_FD 198

/* Environment variables used to hand the child its shared memory + input. */
#define SHM_ENV_VAR   "__MKFUZZ_SHM_ID"
#define INPUT_ENV_VAR "__MKFUZZ_INPUT"

/* Harness entry point, provided by each target (libFuzzer-compatible). */
int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size);

#endif /* MKFUZZ_RT_H */
