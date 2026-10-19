#ifndef MK_PARAMETERS_H
#define MK_PARAMETERS_H

#include <stddef.h>
#include <stdint.h>

#define PARAM_MAX_INPUT 256

enum param_status { PARAM_OK, PARAM_SYNTAX, PARAM_UNKNOWN, PARAM_DUPLICATE,
                    PARAM_RANGE, PARAM_SIZE };
struct parameters { uint16_t count; int32_t offset; int fast; };

enum param_status parse_parameters(const unsigned char *data, size_t size,
                                   struct parameters *out);

#endif
