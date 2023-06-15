#pragma once
#include "bitstr.h"
#include "dualec_curve.h"
#include "forward.h"
#include <optional>

namespace DEC {

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

[[nodiscard]] WorkingState Instantiate(BitStr entropy_input, BitStr nonce,
    BitStr personalization_string, size_t security_strength,
    DualEcCurve const* curve = nullptr);
[[nodiscard]] BitStr Generate(WorkingState&, size_t requested_number_of_bits, std::optional<BitStr> additional_input);
[[nodiscard]] BitStr Hash_df(BitStr const& input_string, uint32_t no_of_bits_to_return);
void Truncate(BitStr& bitstr, size_t outlen);
[[nodiscard]] AffinePoint mul(BigInt scalar, AffinePoint const& point, JacobiEllipticCurve const& curve);
[[nodiscard]] BitStr Truncate_Right(BitStr const& bitstr, size_t new_length);

size_t pick_seedlen(size_t security_strength);
size_t calculate_max_outlen(size_t seedlen);
DualEcCurve const& pick_curve(size_t security_strength);

}
