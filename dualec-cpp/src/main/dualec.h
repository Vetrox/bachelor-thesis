#pragma once
#include "bitstr.h"
#include "dualec_curve.h"
#include "forward.h"
#include <optional>

struct WorkingState {
    BitStr s;
    size_t seedlen;
    DualEcCurve const& dec_curve;
    size_t outlen;

    std::string to_string() const
    {
        return "WorkingState(s = " + s.as_hex_string()
            + " seedlen = " + std::to_string(seedlen)
            + " dec_curve = " + dec_curve.to_string()
            + " outlen = " + std::to_string(outlen)
            + ")";
    }
};

WorkingState Dual_EC_DRBG_Instantiate(BitStr entropy_input, BitStr nonce,
    BitStr personalization_string, size_t security_strength,
    DualEcCurve const* curve = nullptr);

BitStr Dual_EC_DRBG_Generate(WorkingState&, size_t requested_number_of_bits, std::optional<BitStr> additional_input);
