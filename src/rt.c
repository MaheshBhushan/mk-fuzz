/*
 * mk-fuzz coverage runtime + fork server.
 *
 * This file is linked into every fuzz target. It does two jobs:
 *
 *  1. Edge coverage. Compiled with -fsanitize-coverage=trace-pc-guard, clang
 *     inserts a call to __sanitizer_cov_trace_pc_guard() at every basic block.
 *     We give each guard a unique id and, on each hit, bump a byte in a shared
 *     memory bitmap indexed by the AFL edge hash (prev_loc ^ cur_loc). The
 *     `>> 1` on prev_loc keeps A->B distinct from B->A.
 *
 *  2. Fork server. Rather than execve() the target once per input (slow: the
 *     dynamic loader + libc init dominate), we initialise once, then fork a
 *     fresh child per testcase on command from the fuzzer. This is the single
 *     biggest speedup in an AFL-style fuzzer.
 *
 * If the target is run without a fuzzer attached (no SHM env var), it falls
 * back to reading one input file / stdin and running once, so targets stay
 * debuggable under gdb.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>

#include "rt.h"

/* ---- coverage state ---------------------------------------------------- */

static uint8_t  dummy_map[MAP_SIZE];
/* Default to the dummy map so guards that fire during early startup — before
 * map_shared_memory() runs, e.g. main()'s own entry block — have somewhere to
 * write instead of dereferencing NULL. */
static uint8_t *cov_map = dummy_map;
static __thread uint32_t prev_loc; /* previous block id, halved */

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    static uint32_t next_id = 1; /* id 0 is reserved / unused */
    for (uint32_t *p = start; p < stop; p++)
        *p = next_id++;
}

void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    uint32_t cur = *guard;
    cov_map[(prev_loc ^ cur) & (MAP_SIZE - 1)]++;
    prev_loc = cur >> 1;
}

/* ---- shared memory ----------------------------------------------------- */

static void map_shared_memory(void) {
    char *id_str = getenv(SHM_ENV_VAR);
    if (!id_str) {                /* no fuzzer: coverage goes to the void */
        cov_map = dummy_map;
        return;
    }
    int shm_id = atoi(id_str);
    cov_map = (uint8_t *)shmat(shm_id, NULL, 0);
    if (cov_map == (void *)-1) {
        perror("mk-fuzz rt: shmat");
        _exit(1);
    }
}

/* ---- one testcase ------------------------------------------------------ */

static unsigned char input_buf[1 << 20]; /* 1 MiB cap on a single input */

/* Read the current testcase (path in env, else stdin) and run the harness. */
static void run_one(void) {
    const char *path = getenv(INPUT_ENV_VAR);
    int fd = path ? open(path, O_RDONLY) : 0;
    long n = 0;
    if (fd >= 0) {
        n = read(fd, input_buf, sizeof(input_buf));
        if (fd != 0) close(fd);
    }
    if (n < 0) n = 0;
    LLVMFuzzerTestOneInput(input_buf, (unsigned long)n);
}

/* ---- fork server ------------------------------------------------------- */

/* Talk to the fuzzer over the inherited control pipe. Protocol, all 4-byte
 * little-endian ints:
 *   child -> fuzzer : "hello" once, when ready
 *   fuzzer -> child : "go"   (start a run)
 *   child -> fuzzer : pid of the forked worker
 *   child -> fuzzer : wait() status after the worker exits
 */
static void fork_server(void) {
    /* Announce readiness; if the write fails there is no fuzzer attached. */
    uint32_t hello = 0;
    if (write(FORKSRV_FD + 1, &hello, 4) != 4)
        return; /* run standalone */

    while (1) {
        uint32_t cmd;
        if (read(FORKSRV_FD, &cmd, 4) != 4)
            _exit(0); /* fuzzer went away */

        pid_t child = fork();
        if (child < 0)
            _exit(1);

        if (child == 0) {
            /* Worker: drop the control pipe, run the input, exit. */
            close(FORKSRV_FD);
            close(FORKSRV_FD + 1);
            run_one();
            _exit(0);
        }

        /* Server: report pid, wait, report status. */
        if (write(FORKSRV_FD + 1, &child, 4) != 4) _exit(1);
        int status;
        if (waitpid(child, &status, 0) < 0) _exit(1);
        if (write(FORKSRV_FD + 1, &status, 4) != 4) _exit(1);
    }
}

int main(void) {
    map_shared_memory();
    fork_server();  /* returns immediately if no fuzzer is attached */
    run_one();      /* standalone / debugging path */
    return 0;
}
