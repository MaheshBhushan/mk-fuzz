/*
 * Real-library fuzz target #2: cJSON's parser.
 *
 * Added because the benchmark needs more than one target with a meaningful
 * coverage surface. toy_parser saturates at 13 edges inside 1000 executions --
 * fine as a "does it still find the planted bug" check, useless for comparing
 * schedulers -- and a single-target comparison rests on one library's quirks.
 *
 * cJSON is a recursive-descent text parser, which exercises a very different
 * mutation profile from zlib's inflate: it rewards byte-level edits that keep
 * structural characters intact, where inflate rewards bit-level edits inside a
 * binary header. That contrast is the point of having both.
 *
 * Build: the `cjson` rules in the Makefile compile cJSON.c from source with
 * instrumentation. Run third_party/fetch-cjson.sh once to populate it.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "../src/rt.h"

int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
    /* cJSON_ParseWithLength still wants a NUL-terminated buffer, so copy. */
    char *s = malloc(size + 1);
    if (!s) return 0;
    memcpy(s, data, size);
    s[size] = '\0';

    cJSON *j = cJSON_ParseWithLength(s, size + 1);
    if (j) {
        /* Walk the tree and round-trip it, so the printer is fuzzed too. */
        char *out = cJSON_PrintUnformatted(j);
        free(out);
        cJSON_Delete(j);
    }
    free(s);
    return 0;
}
