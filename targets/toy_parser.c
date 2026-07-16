/*
 * A tiny target with deliberately planted bugs, used to validate that the
 * fuzzer actually finds things. It parses a toy "MKF" container:
 *
 *   bytes 0..3  : magic  "MKF1"
 *   byte  4     : record count N
 *   then N records, each: 1 length byte L, then L payload bytes.
 *
 * Planted bugs:
 *   B1  a stack buffer overflow when a record length exceeds 16 (the parser
 *       copies L bytes into a 16-byte scratch buffer).
 *   B2  an assertion / abort when the magic is present AND the first payload
 *       byte is 0xFF (a "poison" value fuzzing has to discover past the magic).
 *
 * Bug B2 sits behind the 4-byte magic check, which is exactly the kind of
 * narrow gate coverage guidance (and later, symbolic execution) exists to get
 * through: blind fuzzing almost never guesses "MKF1" by chance, but the edge
 * bitmap rewards inputs that match it one byte at a time.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../src/rt.h"

int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
    if (size < 5) return 0;
    if (memcmp(data, "MKF1", 4) != 0) return 0;   /* narrow gate */

    unsigned n = data[4];
    unsigned long off = 5;

    for (unsigned r = 0; r < n && off < size; r++) {
        unsigned len = data[off++];
        char scratch[16];
        /* B1: no bound check against sizeof(scratch). */
        if (off + len <= size) {
            memcpy(scratch, data + off, len);       /* overflow when len > 16 */
            if (r == 0 && len > 0 && (unsigned char)scratch[0] == 0xFF)
                abort();                            /* B2: poison byte */
            off += len;
        }
        /* Touch the buffer so the copy isn't optimised away. */
        volatile char sink = scratch[len % 16];
        (void)sink;
    }
    return 0;
}
