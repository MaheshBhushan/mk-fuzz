/* One binary input on stdin; JSON result on stdout; 0=accept, 2=reject. */
#include "parameters.h"
#include <inttypes.h>
#include <stdio.h>

int main(void) {
    unsigned char data[PARAM_MAX_INPUT + 1];
    size_t size = fread(data, 1, sizeof data, stdin);
    if (ferror(stdin)) return 3;
    struct parameters result;
    enum param_status status = parse_parameters(data, size, &result);
    static const char *reasons[] = {"ok", "syntax", "unknown", "duplicate",
                                    "range", "size"};
    if (status != PARAM_OK) {
        printf("{\"status\":\"reject\",\"reason\":\"%s\"}\n", reasons[status]);
        return 2;
    }
    printf("{\"status\":\"ok\",\"count\":%u,\"offset\":%" PRId32
           ",\"mode\":\"%s\"}\n", (unsigned)result.count, result.offset,
           result.fast ? "fast" : "safe");
    return 0;
}
