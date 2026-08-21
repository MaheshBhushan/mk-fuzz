/*
 * mk-fuzz: a small coverage-guided, AFL-style fuzzer.
 *
 *   ./mk-fuzz -i <seed_dir> -o <out_dir> -- ./target
 *
 * The target must be built with src/rt.c and -fsanitize-coverage=trace-pc-guard
 * (see the Makefile). We drive it through a fork server, feed it mutated inputs,
 * read edge coverage out of a shared bitmap, and keep any input that reaches a
 * new edge. Crashes are minimised-by-nothing but deduplicated and saved.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <math.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <poll.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "rt.h"
#include "sched.h"
#include "trace.h"

#define MK_MAX_INPUT (1 << 20)      /* 1 MiB, matches the runtime cap */
#define EXEC_TIMEOUT_MS 1000     /* per-run wall clock budget */

/* ---- shared coverage bitmap ------------------------------------------- */

static uint8_t *trace_bits;      /* shared with the target, written by rt.c  */
static int      shm_id;
static uint8_t  virgin_bits[MAP_SIZE]; /* 0xff = edge/bucket never yet seen  */

static void remove_shm(void) { shmctl(shm_id, IPC_RMID, NULL); }

static void setup_shm(void) {
    shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);
    if (shm_id < 0) { perror("shmget"); exit(1); }
    atexit(remove_shm);
    trace_bits = shmat(shm_id, NULL, 0);
    if (trace_bits == (void *)-1) { perror("shmat"); exit(1); }
    memset(virgin_bits, 0xff, MAP_SIZE);
}

/* Fold raw hit counts into log2-ish buckets (1,2,3,4-7,8-15,...). This is
 * AFL's trick: it stops "this edge ran 40 vs 41 times" from looking like new
 * coverage while still noticing 1 -> 2 -> many. */
static const uint8_t count_class[256] = {
    [0]=0,[1]=1,[2]=2,[3]=4,[4 ... 7]=8,[8 ... 15]=16,
    [16 ... 31]=32,[32 ... 127]=64,[128 ... 255]=128
};
static void classify_counts(uint8_t *m) {
    for (uint32_t i = 0; i < MAP_SIZE; i++) m[i] = count_class[m[i]];
}

/* Did this run light up a byte we've never seen at this bucket before?
 * Returns 2 for a brand-new edge, 1 for a new hit-count bucket, 0 otherwise.
 * Updates virgin_bits so future runs only report genuinely new coverage. */
static uint32_t edges_found;   /* bytes of virgin_bits touched at least once */

static int has_new_bits(uint32_t *n_edges, uint32_t *n_buckets) {
    int ret = 0;
    uint32_t ne = 0, nb = 0;
    for (uint32_t i = 0; i < MAP_SIZE; i++) {
        if (trace_bits[i] && (trace_bits[i] & virgin_bits[i])) {
            if (virgin_bits[i] == 0xff) { ne++; edges_found++; if (ret < 2) ret = 2; }
            else                        { nb++; if (ret < 1) ret = 1; }
            virgin_bits[i] &= ~trace_bits[i];
        }
    }
    if (n_edges)   *n_edges = ne;
    if (n_buckets) *n_buckets = nb;
    return ret;
}

/* ---- fork server client ----------------------------------------------- */

static int fsrv_ctl_fd;   /* fuzzer -> target ("go") */
static int fsrv_st_fd;    /* target -> fuzzer (pid, status) */
static pid_t fsrv_pid;
static char **target_argv;
static char  input_path[512];

static void start_forkserver(void) {
    int ctl[2], st[2];
    if (pipe(ctl) || pipe(st)) { perror("pipe"); exit(1); }

    fsrv_pid = fork();
    if (fsrv_pid < 0) { perror("fork"); exit(1); }

    if (fsrv_pid == 0) {
        /* Child: wire our pipe ends onto the fixed fork-server fds. */
        if (dup2(ctl[0], FORKSRV_FD) < 0 ||
            dup2(st[1],  FORKSRV_FD + 1) < 0) { perror("dup2"); _exit(1); }
        close(ctl[0]); close(ctl[1]); close(st[0]); close(st[1]);

        char shm_str[24]; snprintf(shm_str, sizeof shm_str, "%d", shm_id);
        setenv(SHM_ENV_VAR, shm_str, 1);
        setenv(INPUT_ENV_VAR, input_path, 1);

        /* Silence the target so its output doesn't drown the fuzzer UI. */
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) { dup2(devnull, 1); dup2(devnull, 2); }

        execv(target_argv[0], target_argv);
        perror("execv target");
        _exit(1);
    }

    close(ctl[0]); close(st[1]);
    fsrv_ctl_fd = ctl[1];
    fsrv_st_fd  = st[0];

    /* Wait for the target's "hello". */
    uint32_t hello;
    if (read(fsrv_st_fd, &hello, 4) != 4) {
        fprintf(stderr, "mk-fuzz: fork server never came up. "
                        "Was the target built with rt.c + trace-pc-guard?\n");
        exit(1);
    }
}

enum { RUN_OK, RUN_CRASH, RUN_HANG };

/* Run the target on `buf` and return one of RUN_*. Fills trace_bits. */
static int run_target(const uint8_t *buf, size_t len) {
    /* Deliver the input via the shared file path. */
    int fd = open(input_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { perror("open input"); exit(1); }
    if (write(fd, buf, len) != (ssize_t)len) { perror("write input"); exit(1); }
    close(fd);

    memset(trace_bits, 0, MAP_SIZE);

    uint32_t go = 1;
    if (write(fsrv_ctl_fd, &go, 4) != 4) {
        fprintf(stderr, "mk-fuzz: lost the fork server.\n"); exit(1);
    }

    pid_t child;
    if (read(fsrv_st_fd, &child, 4) != 4) {
        fprintf(stderr, "mk-fuzz: fork server did not report a pid.\n"); exit(1);
    }

    /* Wait for the status, but no longer than EXEC_TIMEOUT_MS. */
    struct pollfd pfd = { .fd = fsrv_st_fd, .events = POLLIN };
    int pr = poll(&pfd, 1, EXEC_TIMEOUT_MS);
    if (pr <= 0) {
        kill(child, SIGKILL);
        int status;
        read(fsrv_st_fd, &status, 4); /* drain the now-available status */
        return RUN_HANG;
    }

    int status;
    if (read(fsrv_st_fd, &status, 4) != 4) {
        fprintf(stderr, "mk-fuzz: fork server did not report status.\n"); exit(1);
    }
    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        if (sig == SIGKILL) return RUN_HANG;
        return RUN_CRASH;   /* SIGSEGV/SIGABRT/SIGBUS/... — a real fault */
    }
    return RUN_OK;
}

/* ---- corpus ------------------------------------------------------------ */

typedef struct { uint8_t *data; size_t len; } Testcase;
static Testcase *corpus;
static size_t    corpus_len, corpus_cap;

static void corpus_add(const uint8_t *data, size_t len) {
    if (corpus_len == corpus_cap) {
        corpus_cap = corpus_cap ? corpus_cap * 2 : 64;
        corpus = realloc(corpus, corpus_cap * sizeof(Testcase));
    }
    uint8_t *copy = malloc(len ? len : 1);
    memcpy(copy, data, len);
    corpus[corpus_len].data = copy;
    corpus[corpus_len].len  = len;
    corpus_len++;
}

/* ---- mutation ---------------------------------------------------------- */

/* One shared stream. -s <seed> replaces the constant; the default is the
 * original hardcoded value, so an unflagged run reproduces exactly. */
static uint64_t rng_state = 0x2545F4914F6CDD1DULL;
static uint64_t rnd(void) { /* xorshift64* */
    uint64_t x = rng_state;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    rng_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}
static uint32_t rnd_below(uint32_t n) { return n ? (uint32_t)(rnd() % n) : 0; }

/* The scheduler draws from the same stream (see sched.h). */
uint64_t mk_rnd(void) { return rnd(); }
uint32_t mk_rnd_below(uint32_t n) { return rnd_below(n); }

static const int8_t  interesting_8[]  = { -128, -1, 0, 1, 16, 32, 64, 100, 127 };
static const int16_t interesting_16[] = { -32768, -1, 0, 1, 16, 128, 255, 256,
                                          512, 1000, 4096, 32767 };
static const int32_t interesting_32[] = { -2147483647-1, -100000, -1, 0, 1,
                                          256, 65535, 65536, 100000, 2147483647 };

/* Stacked "havoc" mutations. Returns the new length. buf has MK_MAX_INPUT room.
 * op_counts[] is filled in with how many of the stacked edits each operator
 * contributed, which is what the scheduler is rewarded on. */
static size_t mutate(uint8_t *buf, size_t len, const SchedCtx *ctx,
                     uint32_t *op_counts, uint32_t *total_edits) {
    int rounds = 1 << (1 + rnd_below(6)); /* 2..64 stacked edits */
    *total_edits = 0;
    for (int r = 0; r < rounds; r++) {
        int op = sched_pick(ctx);
        op_counts[op]++; (*total_edits)++;
        switch (op) {
        case OP_BITFLIP: /* bit flip */
            if (len) buf[rnd_below(len)] ^= 1 << rnd_below(8);
            break;
        case OP_BYTESET: /* random byte set */
            if (len) buf[rnd_below(len)] = (uint8_t)rnd();
            break;
        case OP_BYTEADD: /* byte add/sub */
            if (len) buf[rnd_below(len)] += (uint8_t)(rnd_below(70) - 35);
            break;
        case OP_INT8: /* interesting 8 */
            if (len) buf[rnd_below(len)] =
                interesting_8[rnd_below(sizeof interesting_8)];
            break;
        case OP_INT16: /* interesting 16 */
            if (len >= 2) {
                int16_t v = interesting_16[rnd_below(sizeof interesting_16 / 2)];
                memcpy(buf + rnd_below(len - 1), &v, 2);
            }
            break;
        case OP_INT32: /* interesting 32 */
            if (len >= 4) {
                int32_t v = interesting_32[rnd_below(sizeof interesting_32 / 4)];
                memcpy(buf + rnd_below(len - 3), &v, 4);
            }
            break;
        case OP_DELETE: /* delete a chunk */
            if (len > 1) {
                uint32_t n = 1 + rnd_below(len / 2);
                uint32_t at = rnd_below(len - n + 1);
                memmove(buf + at, buf + at + n, len - at - n);
                len -= n;
            }
            break;
        case OP_CLONE: /* clone/insert a chunk */
            if (len && len < MK_MAX_INPUT - 128) {
                uint32_t n = 1 + rnd_below(len < 64 ? len : 64);
                uint32_t from = rnd_below(len);
                uint32_t at = rnd_below(len);
                if (n > len - from) n = len - from;
                memmove(buf + at + n, buf + at, len - at);
                memmove(buf + at, buf + from + (at <= from ? n : 0), n);
                len += n;
            }
            break;
        case OP_MEMSET: /* overwrite with a constant byte */
            if (len) {
                uint32_t n = 1 + rnd_below(len);
                uint32_t at = rnd_below(len - n + 1);
                memset(buf + at, (uint8_t)rnd(), n);
            }
            break;
        }
    }
    return len;
}

/* Splice two corpus entries at random cut points. */
static size_t splice(uint8_t *buf, size_t len) {
    if (corpus_len < 2 || len < 2) return len;
    Testcase *other = &corpus[rnd_below(corpus_len)];
    if (other->len < 2) return len;
    uint32_t cut_a = 1 + rnd_below(len - 1);
    uint32_t cut_b = 1 + rnd_below(other->len - 1);
    uint32_t tail = other->len - cut_b;
    if (cut_a + tail > MK_MAX_INPUT) tail = MK_MAX_INPUT - cut_a;
    memcpy(buf + cut_a, other->data + cut_b, tail);
    return cut_a + tail;
}

/* ---- crash triage ------------------------------------------------------ */

static char   out_dir[512];
static size_t crash_count, hang_count, queue_count;
static uint8_t crash_virgin[MAP_SIZE]; /* dedup crashes by coverage */

static void save_case(const char *sub, size_t *counter,
                      const uint8_t *buf, size_t len) {
    char path[600];
    snprintf(path, sizeof path, "%s/%s/id_%06zu", out_dir, sub, *counter);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) { write(fd, buf, len); close(fd); }
    (*counter)++;
}

/* ---- seeds & UI -------------------------------------------------------- */

static void load_seeds(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) { fprintf(stderr, "mk-fuzz: cannot open seed dir %s\n", dir); exit(1); }
    struct dirent *e;
    uint8_t *buf = malloc(MK_MAX_INPUT);
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char p[600]; snprintf(p, sizeof p, "%s/%s", dir, e->d_name);
        struct stat stt;
        if (stat(p, &stt) || !S_ISREG(stt.st_mode)) continue;
        int fd = open(p, O_RDONLY); if (fd < 0) continue;
        ssize_t n = read(fd, buf, MK_MAX_INPUT); close(fd);
        if (n < 0) n = 0;
        run_target(buf, n);              /* prime coverage from the seed */
        classify_counts(trace_bits);
        has_new_bits(NULL, NULL);
        corpus_add(buf, n);
    }
    free(buf);
    closedir(d);
    if (corpus_len == 0) { corpus_add((const uint8_t *)"", 0); }
}

static uint64_t now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Kept as the audit path for the incremental edges_found counter: sweeping
 * 64 KiB once per UI tick was fine, once per execution is not. */
static uint32_t count_nonzero_virgin(void) {
    uint32_t c = 0;
    for (uint32_t i = 0; i < MAP_SIZE; i++) if (virgin_bits[i] != 0xff) c++;
    return c;
}

int main(int argc, char **argv) {
    const char *seed_dir = NULL;
    const char *o = NULL;
    const char *trace_path = NULL, *cov_path = NULL;
    uint64_t max_execs = 0, max_secs = 0, cov_every = 1000;
    unsigned seed = 0;            /* 0 = keep the original hardcoded state */
    SchedKind sched = SCHED_BASELINE;
    int i = 1;
    for (; i < argc; i++) {
        if (!strcmp(argv[i], "-i") && i + 1 < argc) seed_dir = argv[++i];
        else if (!strcmp(argv[i], "-o") && i + 1 < argc) o = argv[++i];
        else if (!strncmp(argv[i], "--scheduler=", 12)) {
            sched = sched_parse(argv[i] + 12);
            if (sched == SCHED_UNKNOWN) {
                fprintf(stderr, "mk-fuzz: unknown scheduler '%s' "
                        "(want baseline|bandit|linucb)\n", argv[i] + 12);
                return 1;
            }
        }
        else if (!strcmp(argv[i], "--scheduler") && i + 1 < argc) {
            sched = sched_parse(argv[++i]);
            if (sched == SCHED_UNKNOWN) {
                fprintf(stderr, "mk-fuzz: unknown scheduler '%s' "
                        "(want baseline|bandit|linucb)\n", argv[i]);
                return 1;
            }
        }
        else if (!strcmp(argv[i], "-s") && i + 1 < argc) seed = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "-E") && i + 1 < argc) max_execs = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "-T") && i + 1 < argc) max_secs = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--trace") && i + 1 < argc) trace_path = argv[++i];
        else if (!strcmp(argv[i], "--cov") && i + 1 < argc) cov_path = argv[++i];
        else if (!strcmp(argv[i], "--cov-every") && i + 1 < argc) cov_every = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--")) { i++; break; }
        else { fprintf(stderr, "unknown arg: %s\n", argv[i]); return 1; }
    }
    if (!seed_dir || !o || i >= argc) {
        fprintf(stderr,
            "usage: %s [options] -i <seed_dir> -o <out_dir> -- ./target [args]\n"
            "\n"
            "  --scheduler=baseline|bandit|linucb   mutation-operator scheduler\n"
            "                                       (default baseline: the original\n"
            "                                        hand-weighted distribution)\n"
            "  -s <n>              RNG seed (default: the original fixed state)\n"
            "  -E <n>              stop after n executions (default: never)\n"
            "  -T <secs>           stop after secs seconds (default: never)\n"
            "  --trace <path>      JSONL, one row per mutation\n"
            "  --cov <path>        CSV coverage curve\n"
            "  --cov-every <n>     CSV sampling interval (default 1000 execs)\n",
            argv[0]);
        return 1;
    }
    if (seed) {
        rng_state = 0x9E3779B97F4A7C15ULL * (uint64_t)seed + 0x2545F4914F6CDD1DULL;
        if (!rng_state) rng_state = 0x2545F4914F6CDD1DULL;  /* xorshift dies at 0 */
    }
    sched_init(sched);
    target_argv = &argv[i];
    snprintf(out_dir, sizeof out_dir, "%s", o);

    /* Prepare output layout + the shared input file path. */
    char sub[600];
    snprintf(sub, sizeof sub, "%s/crashes", out_dir); mkdir(out_dir, 0700); mkdir(sub, 0700);
    snprintf(sub, sizeof sub, "%s/hangs", out_dir);   mkdir(sub, 0700);
    snprintf(sub, sizeof sub, "%s/queue", out_dir);   mkdir(sub, 0700);
    /* Keep the per-exec input file on tmpfs when available: it's written and
     * re-read on every single run, so a slow (e.g. external/NTFS) out_dir would
     * otherwise cap throughput. Fall back to out_dir if /dev/shm is missing. */
    if (access("/dev/shm", W_OK) == 0)
        snprintf(input_path, sizeof input_path, "/dev/shm/.mkfuzz_input_%d", getpid());
    else
        snprintf(input_path, sizeof input_path, "%s/.cur_input", out_dir);
    memset(crash_virgin, 0xff, MAP_SIZE);

    setup_shm();
    start_forkserver();
    load_seeds(seed_dir);

    edges_found = count_nonzero_virgin();   /* prime the incremental counter */

    trace_open(trace_path, cov_path, cov_every, sched_name(sched), seed,
               target_argv[0]);

    fprintf(stderr, "mk-fuzz: %zu seed(s), %u edges from seeds. "
                    "scheduler=%s seed=%u. fuzzing %s ...\n",
            corpus_len, edges_found, sched_name(sched), seed, target_argv[0]);

    uint8_t *buf = malloc(MK_MAX_INPUT);
    uint64_t start = now_ms(), last_ui = 0, execs = 0;

    /* Recent-hit-rate feature: a 256-execution sliding window of "did this
     * execution find any coverage", kept as a ring so the feature costs nothing. */
    uint8_t hit_ring[256] = {0};
    uint32_t hit_ring_pos = 0, hit_ring_sum = 0;

    SchedCtx ctx = {0};

    while (1) {
        Testcase *tc = &corpus[rnd_below(corpus_len)];
        size_t len = tc->len; if (len > MK_MAX_INPUT) len = MK_MAX_INPUT;
        memcpy(buf, tc->data, len);

        if (corpus_len > 1 && rnd_below(20) == 0) len = splice(buf, len);

        /* Context for this execution. All four features are reads of state the
         * loop already maintains, log-compressed into roughly [0,1] so LinUCB's
         * ridge regression sees comparable magnitudes. */
        ctx.cov_sat    = log2(1.0 + edges_found) / (double)MAP_SIZE_POW2;
        ctx.frontier   = log2(1.0 + (double)corpus_len) / 16.0;
        ctx.hit_rate   = (double)hit_ring_sum / 256.0;
        ctx.size_class = log2(1.0 + (double)len) / 20.0;

        uint32_t op_counts[OP_COUNT] = {0}, total_edits = 0;
        len = mutate(buf, len, &ctx, op_counts, &total_edits);

        int res = run_target(buf, len);
        execs++;

        uint32_t new_edges = 0, new_buckets = 0;
        const char *res_name = "ok";

        if (res == RUN_CRASH) {
            res_name = "crash";
            /* Deduplicate: only save if the crash covers a new edge. */
            classify_counts(trace_bits);
            int novel = 0;
            for (uint32_t k = 0; k < MAP_SIZE; k++)
                if (trace_bits[k] && (trace_bits[k] & crash_virgin[k])) {
                    crash_virgin[k] &= ~trace_bits[k]; novel = 1;
                }
            if (novel) {
                save_case("crashes", &crash_count, buf, len);
                fprintf(stderr, "\n[+] CRASH #%zu saved (len=%zu)\n",
                        crash_count, len);
            }
        } else if (res == RUN_HANG) {
            res_name = "hang";
            if (hang_count < 50) save_case("hangs", &hang_count, buf, len);
            else hang_count++;
        } else {
            classify_counts(trace_bits);
            if (has_new_bits(&new_edges, &new_buckets)) {
                corpus_add(buf, len);
                save_case("queue", &queue_count, buf, len);
            }
        }

        /* Reward: newly covered edges, with a small consolation for reaching a
         * new hit-count bucket on an edge we already had. Clipped to [0,1]
         * because Thompson sampling needs a Bernoulli-scale signal. */
        double reward = 0.5 * (double)new_edges + 0.15 * (double)new_buckets;
        if (reward > 1.0) reward = 1.0;

        uint8_t hit = (new_edges || new_buckets) ? 1 : 0;
        hit_ring_sum -= hit_ring[hit_ring_pos];
        hit_ring[hit_ring_pos] = hit;
        hit_ring_sum += hit;
        hit_ring_pos = (hit_ring_pos + 1) & 255;

        sched_reward(op_counts, total_edits, reward, &ctx);

        uint64_t t = now_ms();
        /* Unconditional: trace_row also accumulates the operator histograms
         * that the end-of-run adaptation metric is computed from, and it
         * cheaply returns before formatting anything when --trace is off. */
        trace_row(execs, t - start, op_counts, total_edits, len, res_name,
                      new_edges, new_buckets, reward, edges_found, corpus_len,
                      &ctx);
        trace_cov(execs, t - start, edges_found, corpus_len, crash_count);

        if (t - last_ui >= 500) {
            double secs = (t - start) / 1000.0;
            fprintf(stderr,
                "\r[*] execs=%llu (%.0f/s) corpus=%zu edges=%u crashes=%zu hangs=%zu   ",
                (unsigned long long)execs, execs / (secs > 0 ? secs : 1),
                corpus_len, edges_found, crash_count, hang_count);
            fflush(stderr);
            last_ui = t;
        }

        if (max_execs && execs >= max_execs) break;
        if (max_secs && (t - start) >= max_secs * 1000) break;
    }

    fprintf(stderr, "\n");
    trace_close(execs, now_ms() - start, edges_found, corpus_len,
                crash_count, hang_count, &ctx);
    return 0;
}
