#pragma once
#include "dualec_curve.h"
#include "forward.h"
#include <cstddef>

struct WorkingState {
    // bitstr s;
    size_t seedlen;
    size_t max_outlen;
    DualEcCurve dec_curve;
    size_t reseed_counter;
    size_t outlen;
};
