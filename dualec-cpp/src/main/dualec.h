#pragma once
#include "dualec_curve.h"
#include "forward.h"
#include "bitstr.h"

struct WorkingState {
    BitStr s;
    size_t seedlen;
    size_t max_outlen;
    DualEcCurve dec_curve;
    size_t reseed_counter;
    size_t outlen;
};

WorkingState Dual_EC_DRBG_Instantiate(BitStr entropy_input, BitStr nonce,
        BitStr personalization_string, size_t security_strength,
        DualEcCurve *curve = nullptr);
