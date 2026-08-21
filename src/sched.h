#ifndef MKFUZZ_SCHED_H
#define MKFUZZ_SCHED_H

#include <stdint.h>

/*
 * Mutation-operator scheduler.
 *
 * The original fuzzer picked an operator with a bare `rnd_below(11)` inside
 * mutate(), where duplicated switch cases gave delete and clone double weight.
 * That hand-tuned distribution is preserved exactly as SCHED_BASELINE; the
 * other kinds learn a distribution instead.
 *
 * Credit assignment: mutate() stacks 2..64 edits before a single execution, so
 * one reward has to be shared out over several operators. We give each operator
 * a share of the execution's "trial mass" proportional to how many of the
 * stacked edits it contributed. See sched_reward().
 */

typedef enum {
    OP_BITFLIP, OP_BYTESET, OP_BYTEADD,
    OP_INT8, OP_INT16, OP_INT32,
    OP_DELETE, OP_CLONE, OP_MEMSET,
    OP_COUNT
} MutOp;

typedef enum {
    SCHED_BASELINE, SCHED_BANDIT, SCHED_LINUCB, SCHED_UNKNOWN
} SchedKind;

/* Context handed to the contextual scheduler. Recomputed once per execution;
 * cheap reads over state the fuzzer loop already maintains. */
typedef struct {
    double cov_sat;     /* edges found / MAP_SIZE, log-compressed  */
    double frontier;    /* corpus size, log-compressed             */
    double hit_rate;    /* fraction of the last 256 execs that found coverage */
    double size_class;  /* log2(input length) / 20                 */
} SchedCtx;

/* Provided by the fuzzer: the single shared xorshift64* stream. Keeping one
 * stream is what makes --scheduler=baseline bit-for-bit reproducible against
 * the pre-scheduler binary. */
uint64_t mk_rnd(void);
uint32_t mk_rnd_below(uint32_t n);

SchedKind   sched_parse(const char *s);
const char *sched_name(SchedKind k);
const char *op_name(int op);

void sched_init(SchedKind k);

/* Pick one operator for one stacked edit. */
int  sched_pick(const SchedCtx *ctx);

/* Feed back the outcome of one execution.
 *   op_counts   how many stacked edits each operator contributed
 *   total_edits sum of op_counts (>0)
 *   reward      clipped to [0,1] by the caller
 *   ctx         the context that was in force for this execution     */
void sched_reward(const uint32_t *op_counts, uint32_t total_edits,
                  double reward, const SchedCtx *ctx);

/* The original hand-tuned weights, regardless of which scheduler is active.
 * Used to report how far a learned policy actually moved from the hand tuning. */
void sched_baseline_weights(double *out);

/* Current selection probabilities, for the trace/diagnostics. Writes OP_COUNT
 * doubles summing to 1. */
void sched_probs(const SchedCtx *ctx, double *out);

#endif /* MKFUZZ_SCHED_H */
