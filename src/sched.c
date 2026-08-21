/*
 * Mutation-operator schedulers for mk-fuzz. See sched.h for the interface and
 * the credit-assignment rule.
 *
 * Three kinds:
 *
 *   baseline  The original hand-weighted distribution, reproduced exactly:
 *             one rnd_below(11) draw indexed through the same 11-entry table
 *             the old switch statement encoded. Same RNG consumption, same
 *             operator, so the fuzzing trajectory is unchanged.
 *
 *   bandit    Thompson sampling. One Beta posterior per operator over
 *             "did this execution find coverage". Sampling (rather than UCB1's
 *             argmax) is deliberate: mutate() applies 2..64 edits per execution
 *             and an argmax rule would use the same operator for every edit,
 *             destroying the stacked-mutation mixing that the baseline has.
 *             Thompson keeps per-edit diversity for free.
 *
 *   linucb    LinUCB ridge regression per operator over the SchedCtx features,
 *             then a softmax over the resulting scores. The softmax is a stated
 *             deviation from textbook LinUCB, for the same argmax-collapse
 *             reason as above.
 *
 * Non-stationarity: coverage feedback decays hard as a run progresses (early
 * edges are cheap, late edges are not), so both learners decay their
 * accumulated evidence periodically instead of averaging over the whole run.
 */
#include "sched.h"

#include <math.h>
#include <string.h>
#include <stdio.h>

/* ---- naming ------------------------------------------------------------ */

static const char *op_names[OP_COUNT] = {
    "bitflip", "byteset", "byteadd", "int8", "int16", "int32",
    "delete", "clone", "memset"
};
const char *op_name(int op) {
    return (op >= 0 && op < OP_COUNT) ? op_names[op] : "?";
}

SchedKind sched_parse(const char *s) {
    if (!strcmp(s, "baseline")) return SCHED_BASELINE;
    if (!strcmp(s, "bandit"))   return SCHED_BANDIT;
    if (!strcmp(s, "linucb"))   return SCHED_LINUCB;
    return SCHED_UNKNOWN;
}
const char *sched_name(SchedKind k) {
    switch (k) {
    case SCHED_BASELINE: return "baseline";
    case SCHED_BANDIT:   return "bandit";
    case SCHED_LINUCB:   return "linucb";
    default:             return "unknown";
    }
}

/* ---- the baseline's implicit weight table ------------------------------ */

/* The old code was `switch (rnd_below(11))` with `case 6: case 7:` for delete
 * and `case 8: case 9:` for clone. This table is that switch, verbatim. */
static const uint8_t baseline_table[11] = {
    OP_BITFLIP, OP_BYTESET, OP_BYTEADD, OP_INT8, OP_INT16, OP_INT32,
    OP_DELETE, OP_DELETE, OP_CLONE, OP_CLONE, OP_MEMSET
};

/* ---- shared state ------------------------------------------------------ */

static SchedKind kind = SCHED_BASELINE;

/* Thompson: Beta(a,b) per operator. Primed with a weak prior matching the
 * baseline weights so the bandit starts where the hand tuning was, not at
 * uniform: it has to earn a departure from the status quo. */
static double beta_a[OP_COUNT], beta_b[OP_COUNT];

/* LinUCB */
#define D 5                 /* 4 features + bias */
#define LIN_LAMBDA 1.0
#define LIN_ALPHA  0.35     /* exploration width */
#define LIN_TAU    0.08     /* softmax temperature over LinUCB scores */
static double lin_A[OP_COUNT][D][D];
static double lin_Ainv[OP_COUNT][D][D];
static double lin_b[OP_COUNT][D];

/* Decay both learners' evidence every DECAY_EVERY executions by DECAY_KEEP, so
 * a distribution learned during the easy early phase does not outlive it. */
#define DECAY_EVERY 20000
#define DECAY_KEEP  0.85
static uint64_t reward_calls;

static void mat_identity(double m[D][D], double s) {
    for (int i = 0; i < D; i++)
        for (int j = 0; j < D; j++) m[i][j] = (i == j) ? s : 0.0;
}

/* Gauss-Jordan inverse of a small SPD matrix. D is 5, so this is nothing. */
static void mat_inv(const double in[D][D], double out[D][D]) {
    double a[D][2 * D];
    for (int i = 0; i < D; i++) {
        for (int j = 0; j < D; j++) a[i][j] = in[i][j];
        for (int j = 0; j < D; j++) a[i][D + j] = (i == j) ? 1.0 : 0.0;
    }
    for (int c = 0; c < D; c++) {
        int piv = c;
        for (int r = c + 1; r < D; r++)
            if (fabs(a[r][c]) > fabs(a[piv][c])) piv = r;
        if (fabs(a[piv][c]) < 1e-12) {         /* singular: fall back to I */
            mat_identity(out, 1.0);
            return;
        }
        if (piv != c) for (int j = 0; j < 2 * D; j++) {
            double t = a[c][j]; a[c][j] = a[piv][j]; a[piv][j] = t;
        }
        double d = a[c][c];
        for (int j = 0; j < 2 * D; j++) a[c][j] /= d;
        for (int r = 0; r < D; r++) {
            if (r == c) continue;
            double f = a[r][c];
            if (f == 0.0) continue;
            for (int j = 0; j < 2 * D; j++) a[r][j] -= f * a[c][j];
        }
    }
    for (int i = 0; i < D; i++)
        for (int j = 0; j < D; j++) out[i][j] = a[i][D + j];
}

void sched_init(SchedKind k) {
    kind = k;
    reward_calls = 0;
    for (int i = 0; i < OP_COUNT; i++) {
        /* Weak prior at the baseline weights: table hits / 11, scaled by 4
         * pseudo-observations total per arm. */
        int hits = 0;
        for (int t = 0; t < 11; t++) if (baseline_table[t] == i) hits++;
        double p = (double)hits / 11.0;
        beta_a[i] = 1.0 + 4.0 * p;
        beta_b[i] = 1.0 + 4.0 * (1.0 - p);

        mat_identity(lin_A[i], LIN_LAMBDA);
        mat_identity(lin_Ainv[i], 1.0 / LIN_LAMBDA);
        memset(lin_b[i], 0, sizeof lin_b[i]);
        /* Seed the bias term with the baseline weight so linucb, too, starts
         * from the hand-tuned distribution rather than from nothing. */
        lin_b[i][0] = p;
    }
}

/* ---- sampling helpers -------------------------------------------------- */

static double unif01(void) {
    /* 53 bits out of the xorshift stream. Never returns exactly 0. */
    return ((double)(mk_rnd() >> 11) + 0.5) / 9007199254740992.0;
}

static double std_normal(void) {
    double u = unif01(), v = unif01();
    return sqrt(-2.0 * log(u)) * cos(6.283185307179586 * v);
}

/* Marsaglia-Tsang gamma sampler, shape k > 0, scale 1. */
static double gamma_sample(double k) {
    if (k < 1.0) {
        double u = unif01();
        return gamma_sample(k + 1.0) * pow(u, 1.0 / k);
    }
    double d = k - 1.0 / 3.0, c = 1.0 / sqrt(9.0 * d);
    for (;;) {
        double x = std_normal();
        double v = 1.0 + c * x;
        if (v <= 0.0) continue;
        v = v * v * v;
        double u = unif01();
        if (u < 1.0 - 0.0331 * x * x * x * x) return d * v;
        if (log(u) < 0.5 * x * x + d * (1.0 - v + log(v))) return d * v;
    }
}

static double beta_sample(double a, double b) {
    double x = gamma_sample(a), y = gamma_sample(b);
    return (x + y > 0.0) ? x / (x + y) : 0.5;
}

/* ---- LinUCB scoring ---------------------------------------------------- */

static void ctx_vec(const SchedCtx *c, double x[D]) {
    x[0] = 1.0;                 /* bias */
    x[1] = c->cov_sat;
    x[2] = c->frontier;
    x[3] = c->hit_rate;
    x[4] = c->size_class;
}

static double lin_score(int op, const double x[D]) {
    /* theta = Ainv b ; score = theta.x + alpha * sqrt(x' Ainv x) */
    double theta_x = 0.0, quad = 0.0;
    for (int i = 0; i < D; i++) {
        double ti = 0.0, ai = 0.0;
        for (int j = 0; j < D; j++) {
            ti += lin_Ainv[op][i][j] * lin_b[op][j];
            ai += lin_Ainv[op][i][j] * x[j];
        }
        theta_x += ti * x[i];
        quad    += x[i] * ai;
    }
    if (quad < 0.0) quad = 0.0;
    return theta_x + LIN_ALPHA * sqrt(quad);
}

/* ---- selection --------------------------------------------------------- */

void sched_baseline_weights(double *out) {
    for (int i = 0; i < OP_COUNT; i++) out[i] = 0.0;
    for (int t = 0; t < 11; t++) out[baseline_table[t]] += 1.0 / 11.0;
}

void sched_probs(const SchedCtx *ctx, double *out) {
    if (kind == SCHED_BASELINE) { sched_baseline_weights(out); return; }
    if (kind == SCHED_BANDIT) {
        /* Posterior means, normalised: what the sampler does on average. */
        double s = 0.0;
        for (int i = 0; i < OP_COUNT; i++) {
            out[i] = beta_a[i] / (beta_a[i] + beta_b[i]);
            s += out[i];
        }
        for (int i = 0; i < OP_COUNT; i++) out[i] /= (s > 0 ? s : 1);
        return;
    }
    double x[D]; ctx_vec(ctx, x);
    double sc[OP_COUNT], mx = -1e300, s = 0.0;
    for (int i = 0; i < OP_COUNT; i++) {
        sc[i] = lin_score(i, x);
        if (sc[i] > mx) mx = sc[i];
    }
    for (int i = 0; i < OP_COUNT; i++) {
        out[i] = exp((sc[i] - mx) / LIN_TAU);
        s += out[i];
    }
    for (int i = 0; i < OP_COUNT; i++) out[i] /= (s > 0 ? s : 1);
}

int sched_pick(const SchedCtx *ctx) {
    if (kind == SCHED_BASELINE)
        return baseline_table[mk_rnd_below(11)];

    if (kind == SCHED_BANDIT) {
        int best = 0; double best_v = -1.0;
        for (int i = 0; i < OP_COUNT; i++) {
            double v = beta_sample(beta_a[i], beta_b[i]);
            if (v > best_v) { best_v = v; best = i; }
        }
        return best;
    }

    /* linucb: softmax over LinUCB scores. */
    double p[OP_COUNT];
    sched_probs(ctx, p);
    double u = unif01(), acc = 0.0;
    for (int i = 0; i < OP_COUNT; i++) {
        acc += p[i];
        if (u <= acc) return i;
    }
    return OP_COUNT - 1;
}

/* ---- learning ---------------------------------------------------------- */

void sched_reward(const uint32_t *op_counts, uint32_t total_edits,
                  double reward, const SchedCtx *ctx) {
    if (kind == SCHED_BASELINE || total_edits == 0) return;
    if (reward < 0.0) reward = 0.0;
    if (reward > 1.0) reward = 1.0;

    if (++reward_calls % DECAY_EVERY == 0) {
        for (int i = 0; i < OP_COUNT; i++) {
            /* Shrink towards the prior, never below it. */
            beta_a[i] = 1.0 + (beta_a[i] - 1.0) * DECAY_KEEP;
            beta_b[i] = 1.0 + (beta_b[i] - 1.0) * DECAY_KEEP;
            for (int r = 0; r < D; r++) {
                lin_b[i][r] *= DECAY_KEEP;
                for (int c = 0; c < D; c++)
                    lin_A[i][r][c] = (r == c)
                        ? LIN_LAMBDA + (lin_A[i][r][c] - LIN_LAMBDA) * DECAY_KEEP
                        : lin_A[i][r][c] * DECAY_KEEP;
            }
            mat_inv(lin_A[i], lin_Ainv[i]);
        }
    }

    if (kind == SCHED_BANDIT) {
        for (int i = 0; i < OP_COUNT; i++) {
            if (!op_counts[i]) continue;
            /* Trial mass w, split into success w*r and failure w*(1-r). Summed
             * over operators the mass added per execution is exactly 1. */
            double w = (double)op_counts[i] / (double)total_edits;
            beta_a[i] += w * reward;
            beta_b[i] += w * (1.0 - reward);
        }
        return;
    }

    double x[D]; ctx_vec(ctx, x);
    for (int i = 0; i < OP_COUNT; i++) {
        if (!op_counts[i]) continue;
        double w = (double)op_counts[i] / (double)total_edits;
        for (int r = 0; r < D; r++) {
            for (int c = 0; c < D; c++) lin_A[i][r][c] += w * x[r] * x[c];
            lin_b[i][r] += w * reward * x[r];
        }
        mat_inv(lin_A[i], lin_Ainv[i]);
    }
}
