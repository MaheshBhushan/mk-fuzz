/*
 * Real-library fuzz target: zlib's inflate() decompressor.
 *
 * Decompressing attacker-controlled data is a classic bug surface, and this is
 * the standard libFuzzer-style zlib harness. zlib is heavily hardened, so the
 * point here is Phase 3: pointing mk-fuzz at a real, widely deployed C library,
 * running under ASan for hours, and measuring coverage growth. Swapping in a
 * less-audited parser (a TOML/YAML/image lib) is a one-file change and is where
 * a genuine crash is far more likely to turn up.
 *
 * Build:  see the `zlib` rule in the Makefile (links -lz, instruments + ASan).
 */
#include <stdint.h>
#include <string.h>
#include <zlib.h>

#include "../src/rt.h"

int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
    z_stream s;
    memset(&s, 0, sizeof s);

    /* 15 + 32 window bits => auto-detect zlib or gzip framing. */
    if (inflateInit2(&s, 15 + 32) != Z_OK)
        return 0;

    s.next_in = (unsigned char *)data;
    s.avail_in = (uInt)size;

    unsigned char out[4096];
    int ret;
    do {
        s.next_out = out;
        s.avail_out = sizeof out;
        ret = inflate(&s, Z_NO_FLUSH);
    } while (ret == Z_OK && s.avail_out == 0);

    inflateEnd(&s);
    return 0;
}
