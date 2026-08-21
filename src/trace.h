#ifndef MKFUZZ_TRACE_H
#define MKFUZZ_TRACE_H

#include <stddef.h>
#include <stdint.h>
#include "sched.h"

/*
 * Two optional output streams, both off unless asked for:
 *
 *   --trace  <path>   one JSONL row per mutation (per execution): which
 *                     operators were applied, how many edits each contributed,
 *                     what the run found, and how long it took.
 *   --cov    <path>   downsampled CSV of edges-vs-execs, for plotting. A full
 *                     JSONL trace of a 2M-exec run is hundreds of MB; the
 *                     benchmark only ever needs this curve.
 */

void trace_open(const char *jsonl_path, const char *cov_path,
                uint64_t cov_every, const char *sched, unsigned seed,
                const char *target);

/* Always call this, once per execution. It accumulates the operator histograms
 * the adaptation metric needs, and only writes a JSONL row if --trace was
 * given. Guarding the call on trace_enabled() silently zeroes the histograms
 * (which is exactly what happened first time round). */
void trace_row(uint64_t exec, uint64_t t_ms, const uint32_t *op_counts,
               uint32_t total_edits, size_t len, const char *result,
               uint32_t new_edges, uint32_t new_buckets, double reward,
               uint32_t edges_total, size_t corpus, const SchedCtx *ctx);

void trace_cov(uint64_t exec, uint64_t t_ms, uint32_t edges_total,
               size_t corpus, size_t crashes);

/* Final operator-selection distribution and the early-run distribution, so the
 * T2 "did it actually adapt" check is answerable from the artifacts alone. */
void trace_close(uint64_t exec, uint64_t t_ms, uint32_t edges_total,
                 size_t corpus, size_t crashes, size_t hangs,
                 const SchedCtx *ctx);

int trace_enabled(void);

#endif /* MKFUZZ_TRACE_H */
