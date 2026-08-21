#include "trace.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static FILE *jf, *cf;
static uint64_t cov_every = 1000, next_cov;
static char run_sched[32], run_target[256];
static unsigned run_seed;

/* Operator-selection histograms.
 *
 *   hist_early  the first EARLY_EXECS executions
 *   hist_late   the last COMPLETED block of EARLY_EXECS executions
 *   hist_all    the whole run
 *
 * early vs late is the T2 adaptation check, and it is deliberately built from
 * ACTUAL SELECTION COUNTS rather than from the learner's posterior. With a base
 * reward rate around 2%, every Beta posterior mean lands near 0.02 and a
 * normalised-posterior-mean readout looks almost uniform even while Thompson
 * sampling is concentrating hard on the best arm. Counting what was actually
 * picked cannot be fooled that way. */
#define EARLY_EXECS 1000
static uint64_t hist_early[OP_COUNT], hist_late[OP_COUNT], hist_all[OP_COUNT];
static uint64_t hist_block[OP_COUNT];   /* block in progress */

int trace_enabled(void) { return jf != NULL; }

void trace_open(const char *jsonl_path, const char *cov_path,
                uint64_t every, const char *sched, unsigned seed,
                const char *target) {
    if (every) cov_every = every;
    snprintf(run_sched, sizeof run_sched, "%s", sched);
    snprintf(run_target, sizeof run_target, "%s", target ? target : "");
    run_seed = seed;

    if (jsonl_path) {
        jf = fopen(jsonl_path, "w");
        if (!jf) { perror("open trace"); exit(1); }
        /* Big buffer: this is written once per execution at 10k+ execs/s. */
        setvbuf(jf, NULL, _IOFBF, 1 << 20);
    }
    if (cov_path) {
        cf = fopen(cov_path, "w");
        if (!cf) { perror("open cov"); exit(1); }
        fprintf(cf, "# scheduler=%s seed=%u target=%s\n",
                run_sched, run_seed, run_target);
        fprintf(cf, "execs,t_ms,edges,corpus,crashes\n");
        fflush(cf);
    }
    next_cov = cov_every;
}

void trace_row(uint64_t exec, uint64_t t_ms, const uint32_t *op_counts,
               uint32_t total_edits, size_t len, const char *result,
               uint32_t new_edges, uint32_t new_buckets, double reward,
               uint32_t edges_total, size_t corpus, const SchedCtx *ctx) {
    for (int i = 0; i < OP_COUNT; i++) {
        hist_all[i] += op_counts[i];
        hist_block[i] += op_counts[i];
        if (exec <= EARLY_EXECS) hist_early[i] += op_counts[i];
    }
    if (exec % EARLY_EXECS == 0) {   /* block complete: it becomes "late" */
        memcpy(hist_late, hist_block, sizeof hist_late);
        memset(hist_block, 0, sizeof hist_block);
    }
    if (!jf) return;

    fprintf(jf, "{\"exec\":%llu,\"t_ms\":%llu,\"ops\":[",
            (unsigned long long)exec, (unsigned long long)t_ms);
    for (int i = 0; i < OP_COUNT; i++)
        fprintf(jf, "%s%u", i ? "," : "", op_counts[i]);
    fprintf(jf, "],\"edits\":%u,\"len\":%zu,\"res\":\"%s\","
                "\"new_edges\":%u,\"new_buckets\":%u,\"reward\":%.4f,"
                "\"edges_total\":%u,\"corpus\":%zu,"
                "\"ctx\":[%.4f,%.4f,%.4f,%.4f]}\n",
            total_edits, len, result, new_edges, new_buckets, reward,
            edges_total, corpus,
            ctx->cov_sat, ctx->frontier, ctx->hit_rate, ctx->size_class);
}

static uint64_t last_cov_exec;

void trace_cov(uint64_t exec, uint64_t t_ms, uint32_t edges_total,
               size_t corpus, size_t crashes) {
    if (!cf || exec < next_cov) return;
    while (next_cov <= exec) next_cov += cov_every;
    last_cov_exec = exec;
    fprintf(cf, "%llu,%llu,%u,%zu,%zu\n", (unsigned long long)exec,
            (unsigned long long)t_ms, edges_total, corpus, crashes);
    fflush(cf);
}

void trace_close(uint64_t exec, uint64_t t_ms, uint32_t edges_total,
                 size_t corpus, size_t crashes, size_t hangs,
                 const SchedCtx *ctx) {
    if (cf && exec != last_cov_exec) {
        /* Land a final row at the exact budget so curves share an endpoint even
         * when the budget is not a multiple of cov_every -- unless the budget
         * already landed on a sample point, which would duplicate it. */
        fprintf(cf, "%llu,%llu,%u,%zu,%zu\n", (unsigned long long)exec,
                (unsigned long long)t_ms, edges_total, corpus, crashes);
    }
    if (cf) { fclose(cf); cf = NULL; }
    if (jf) { fclose(jf); jf = NULL; }

    /* The summary goes to stdout so a benchmark runner can capture it while
     * the live UI keeps stderr. */
    double probs[OP_COUNT];
    sched_probs(ctx, probs);

    uint64_t tot_e = 0, tot_a = 0, tot_l = 0;
    for (int i = 0; i < OP_COUNT; i++) {
        tot_e += hist_early[i];
        tot_a += hist_all[i];
        tot_l += hist_late[i];
    }
    /* Short runs may never complete a second block; fall back to the whole run
     * so the metric degrades to early-vs-all rather than to nonsense. */
    if (!tot_l) { memcpy(hist_late, hist_all, sizeof hist_late); tot_l = tot_a; }
    if (!tot_e) tot_e = 1;
    if (!tot_a) tot_a = 1;
    if (!tot_l) tot_l = 1;

    /* Total-variation distance between the early and final selection
     * distributions: 0 means it never moved off its starting weights. */
    double hand[OP_COUNT];
    sched_baseline_weights(hand);

    double tv_late = 0.0, tv_all = 0.0, tv_policy = 0.0, tv_hand = 0.0;
    for (int i = 0; i < OP_COUNT; i++) {
        double early = (double)hist_early[i] / tot_e;
        tv_late   += fabs((double)hist_late[i] / tot_l - early);
        tv_all    += fabs((double)hist_all[i] / tot_a - early);
        tv_policy += fabs(probs[i] - early);
        /* How far the operators actually chosen over the whole run sit from the
         * hand-tuned weights. For --scheduler=baseline this is the sampling
         * noise floor by construction. */
        tv_hand   += fabs((double)hist_all[i] / tot_a - hand[i]);
    }
    tv_late *= 0.5; tv_all *= 0.5; tv_policy *= 0.5; tv_hand *= 0.5;

    printf("{\"summary\":true,\"scheduler\":\"%s\",\"seed\":%u,"
           "\"target\":\"%s\",\"execs\":%llu,\"t_ms\":%llu,\"edges\":%u,"
           "\"corpus\":%zu,\"crashes\":%zu,\"hangs\":%zu,"
           "\"tv_early_vs_late\":%.5f,\"tv_early_vs_all\":%.5f,"
           "\"tv_early_vs_posterior\":%.5f,\"tv_vs_handweights\":%.5f,\n",
           run_sched, run_seed, run_target, (unsigned long long)exec,
           (unsigned long long)t_ms, edges_total, corpus, crashes, hangs, tv_late, tv_all, tv_policy, tv_hand);
    printf(" \"op_share_early\":{");
    for (int i = 0; i < OP_COUNT; i++)
        printf("%s\"%s\":%.5f", i ? "," : "", op_name(i),
               (double)hist_early[i] / tot_e);
    printf("},\n \"op_share_late\":{");
    for (int i = 0; i < OP_COUNT; i++)
        printf("%s\"%s\":%.5f", i ? "," : "", op_name(i),
               (double)hist_late[i] / tot_l);
    printf("},\n \"op_share_all\":{");
    for (int i = 0; i < OP_COUNT; i++)
        printf("%s\"%s\":%.5f", i ? "," : "", op_name(i),
               (double)hist_all[i] / tot_a);
    /* Diagnostic only -- see the note on hist_late above for why this reads as
     * near-uniform even when selection is strongly concentrated. */
    printf("},\n \"op_posterior_mean\":{");
    for (int i = 0; i < OP_COUNT; i++)
        printf("%s\"%s\":%.5f", i ? "," : "", op_name(i), probs[i]);
    printf("}}\n");
    fflush(stdout);
}
