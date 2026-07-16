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
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <poll.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "rt.h"

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
static int has_new_bits(void) {
    int ret = 0;
    for (uint32_t i = 0; i < MAP_SIZE; i++) {
        if (trace_bits[i] && (trace_bits[i] & virgin_bits[i])) {
            if (ret < 2)
                ret = (virgin_bits[i] == 0xff) ? 2 : 1;
            virgin_bits[i] &= ~trace_bits[i];
        }
    }
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

static uint64_t rng_state = 0x2545F4914F6CDD1DULL;
static uint64_t rnd(void) { /* xorshift64* */
    uint64_t x = rng_state;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    rng_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}
static uint32_t rnd_below(uint32_t n) { return n ? (uint32_t)(rnd() % n) : 0; }

static const int8_t  interesting_8[]  = { -128, -1, 0, 1, 16, 32, 64, 100, 127 };
static const int16_t interesting_16[] = { -32768, -1, 0, 1, 16, 128, 255, 256,
                                          512, 1000, 4096, 32767 };
static const int32_t interesting_32[] = { -2147483647-1, -100000, -1, 0, 1,
                                          256, 65535, 65536, 100000, 2147483647 };

/* Stacked "havoc" mutations. Returns the new length. buf has MK_MAX_INPUT room. */
static size_t mutate(uint8_t *buf, size_t len) {
    int rounds = 1 << (1 + rnd_below(6)); /* 2..64 stacked edits */
    for (int r = 0; r < rounds; r++) {
        switch (rnd_below(11)) {
        case 0: /* bit flip */
            if (len) buf[rnd_below(len)] ^= 1 << rnd_below(8);
            break;
        case 1: /* random byte set */
            if (len) buf[rnd_below(len)] = (uint8_t)rnd();
            break;
        case 2: /* byte add/sub */
            if (len) buf[rnd_below(len)] += (uint8_t)(rnd_below(70) - 35);
            break;
        case 3: /* interesting 8 */
            if (len) buf[rnd_below(len)] =
                interesting_8[rnd_below(sizeof interesting_8)];
            break;
        case 4: /* interesting 16 */
            if (len >= 2) {
                int16_t v = interesting_16[rnd_below(sizeof interesting_16 / 2)];
                memcpy(buf + rnd_below(len - 1), &v, 2);
            }
            break;
        case 5: /* interesting 32 */
            if (len >= 4) {
                int32_t v = interesting_32[rnd_below(sizeof interesting_32 / 4)];
                memcpy(buf + rnd_below(len - 3), &v, 4);
            }
            break;
        case 6: case 7: /* delete a chunk */
            if (len > 1) {
                uint32_t n = 1 + rnd_below(len / 2);
                uint32_t at = rnd_below(len - n + 1);
                memmove(buf + at, buf + at + n, len - at - n);
                len -= n;
            }
            break;
        case 8: case 9: /* clone/insert a chunk */
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
        case 10: /* overwrite with a constant byte */
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
        has_new_bits();
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

static uint32_t count_nonzero_virgin(void) {
    uint32_t c = 0;
    for (uint32_t i = 0; i < MAP_SIZE; i++) if (virgin_bits[i] != 0xff) c++;
    return c;
}

int main(int argc, char **argv) {
    const char *seed_dir = NULL;
    const char *o = NULL;
    int i = 1;
    for (; i < argc; i++) {
        if (!strcmp(argv[i], "-i") && i + 1 < argc) seed_dir = argv[++i];
        else if (!strcmp(argv[i], "-o") && i + 1 < argc) o = argv[++i];
        else if (!strcmp(argv[i], "--")) { i++; break; }
        else { fprintf(stderr, "unknown arg: %s\n", argv[i]); return 1; }
    }
    if (!seed_dir || !o || i >= argc) {
        fprintf(stderr,
            "usage: %s -i <seed_dir> -o <out_dir> -- ./target [args]\n", argv[0]);
        return 1;
    }
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

    fprintf(stderr, "mk-fuzz: %zu seed(s), %u edges from seeds. fuzzing %s ...\n",
            corpus_len, count_nonzero_virgin(), target_argv[0]);

    uint8_t *buf = malloc(MK_MAX_INPUT);
    uint64_t start = now_ms(), last_ui = 0, execs = 0;

    while (1) {
        Testcase *tc = &corpus[rnd_below(corpus_len)];
        size_t len = tc->len; if (len > MK_MAX_INPUT) len = MK_MAX_INPUT;
        memcpy(buf, tc->data, len);

        if (corpus_len > 1 && rnd_below(20) == 0) len = splice(buf, len);
        len = mutate(buf, len);

        int res = run_target(buf, len);
        execs++;

        if (res == RUN_CRASH) {
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
            if (hang_count < 50) save_case("hangs", &hang_count, buf, len);
            else hang_count++;
        } else {
            classify_counts(trace_bits);
            if (has_new_bits()) {
                corpus_add(buf, len);
                save_case("queue", &queue_count, buf, len);
            }
        }

        uint64_t t = now_ms();
        if (t - last_ui >= 500) {
            double secs = (t - start) / 1000.0;
            fprintf(stderr,
                "\r[*] execs=%llu (%.0f/s) corpus=%zu edges=%u crashes=%zu hangs=%zu   ",
                (unsigned long long)execs, execs / (secs > 0 ? secs : 1),
                corpus_len, count_nonzero_virgin(), crash_count, hang_count);
            fflush(stderr);
            last_ui = t;
        }
    }
    return 0;
}
