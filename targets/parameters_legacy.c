/* Reference implementation: bounded C strings and libc decimal conversion. */
#include "parameters.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

enum param_status parse_parameters(const unsigned char *data, size_t size,
                                   struct parameters *out) {
    char text[PARAM_MAX_INPUT + 1];
    unsigned seen = 0;
    *out = (struct parameters){1, 0, 0};
    if (size > PARAM_MAX_INPUT) return PARAM_SIZE;
    if (memchr(data, 0, size)) return PARAM_SYNTAX;
    memcpy(text, data, size);
    text[size] = 0;
    if (!size) return PARAM_OK;

    char *field = text;
    for (;;) {
        char *next = strchr(field, ';');
        if (next) *next = 0;
        char *value = strchr(field, '=');
        if (!value || value == field || !value[1] || strchr(value + 1, '='))
            return PARAM_SYNTAX;
        *value++ = 0;
        unsigned key;
        if (!strcmp(field, "count")) key = 1;
        else if (!strcmp(field, "offset")) key = 2;
        else if (!strcmp(field, "mode")) key = 4;
        else return PARAM_UNKNOWN;
        if (seen & key) return PARAM_DUPLICATE;
        seen |= key;

        if (key == 4) {
            if (!strcmp(value, "fast")) out->fast = 1;
            else if (strcmp(value, "safe")) return PARAM_SYNTAX;
        } else {
            char *digits = value;
            if (key == 2 && *digits == '-') digits++;
            if (!*digits) return PARAM_SYNTAX;
            for (char *p = digits; *p; p++)
                if (*p < '0' || *p > '9') return PARAM_SYNTAX;
            errno = 0;
            long long number = strtoll(value, NULL, 10);
            if (errno == ERANGE ||
                (key == 1 && (number < 0 || number > UINT16_MAX)) ||
                (key == 2 && (number < INT32_MIN || number > INT32_MAX)))
                return PARAM_RANGE;
            if (key == 1) out->count = (uint16_t)number;
            else out->offset = (int32_t)number;
        }
        if (!next) return PARAM_OK;
        field = next + 1;
    }
}
