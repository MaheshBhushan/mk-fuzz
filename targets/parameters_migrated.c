/* Migrated implementation: byte slices and fixed-width checked arithmetic. */
#include "parameters.h"
#include <string.h>

static int equal(const unsigned char *data, size_t size, const char *text) {
    return size == strlen(text) && !memcmp(data, text, size);
}

enum param_status parse_parameters(const unsigned char *data, size_t size,
                                   struct parameters *out) {
    unsigned seen = 0;
    *out = (struct parameters){1, 0, 0};
    if (size > PARAM_MAX_INPUT) return PARAM_SIZE;
    if (memchr(data, 0, size)) return PARAM_SYNTAX;
    if (!size) return PARAM_OK;

    size_t start = 0;
    for (;;) {
        size_t end = start, eq = size;
        while (end < size && data[end] != ';') {
            if (data[end] == '=') {
                if (eq != size) return PARAM_SYNTAX;
                eq = end;
            }
            end++;
        }
        if (eq == size || eq == start || eq + 1 == end) return PARAM_SYNTAX;
        unsigned key;
        if (equal(data + start, eq - start, "count")) key = 1;
        else if (equal(data + start, eq - start, "offset")) key = 2;
        else if (equal(data + start, eq - start, "mode")) key = 4;
        else return PARAM_UNKNOWN;
        if (seen & key) return PARAM_DUPLICATE;
        seen |= key;

        const unsigned char *value = data + eq + 1;
        size_t length = end - eq - 1;
        if (key == 4) {
            if (equal(value, length, "fast")) out->fast = 1;
            else if (!equal(value, length, "safe")) return PARAM_SYNTAX;
        } else {
            int negative = key == 2 && value[0] == '-';
            size_t first = negative ? 1 : 0;
            if (first == length) return PARAM_SYNTAX;
            for (size_t i = first; i < length; i++)
                if (value[i] < '0' || value[i] > '9') return PARAM_SYNTAX;
            uint32_t limit = key == 1 ? UINT16_MAX :
                (negative ? (uint32_t)INT32_MAX + 1 : (uint32_t)INT32_MAX);
            uint32_t number = 0;
            for (size_t i = first; i < length; i++) {
                uint32_t digit = value[i] - '0';
                if (number > (limit - digit) / 10) return PARAM_RANGE;
                number = number * 10 + digit;
            }
            if (key == 1) out->count = (uint16_t)number;
            else if (negative && number == (uint32_t)INT32_MAX + 1)
                out->offset = INT32_MIN;
            else out->offset = negative ? -(int32_t)number : (int32_t)number;
        }
        if (end == size) return PARAM_OK;
        start = end + 1;
    }
}
