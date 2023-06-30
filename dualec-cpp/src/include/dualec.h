#pragma once
#include "bitstr.h"
#include "dualec_curve.h"
#include "forward.h"
#include <optional>

namespace DEC {

struct WorkingState {
    BitStr s;               // secret state s; len(s) = seedlen
    size_t seedlen;         // 256, 384, 521
    Curve const& dec_curve; // DualEC curve that may be custom
    size_t outlen;          // about 15 bits shorter than seedlen

    std::string to_string(size_t indent_level = 0) const
    {
        std::string indent = std::string(indent_level, ' ');
        return "WorkingState(\n" + indent
            + "  s: " + s.as_hex_string() + "\n" + indent
            + "  seedlen: " + std::to_string(seedlen) + "\n" + indent
            + "  dec_curve: " + dec_curve.to_string(indent_level + 4) + "\n" + indent
            + "  outlen: " + std::to_string(outlen) + ")";
    }
};

[[nodiscard]] WorkingState Instantiate(BitStr entropy_input, BitStr nonce,
    BitStr personalization_string, size_t security_strength,
    Curve const* curve = nullptr);
[[nodiscard]] BitStr Generate(WorkingState&, size_t requested_number_of_bits, std::optional<BitStr> additional_input);

[[nodiscard]] BitStr Hash_df(BitStr const& input_string, uint32_t no_of_bits_to_return);
void Truncate(BitStr& bitstr, size_t outlen);
[[nodiscard]] AffinePoint mul(BigInt scalar, AffinePoint const& point, EllipticCurve const& curve);
[[nodiscard]] BitStr Truncate_Right(BitStr const& bitstr, size_t new_length);

size_t pick_seedlen(size_t security_strength);
size_t calculate_max_outlen(size_t seedlen);
Curve const& pick_curve(size_t security_strength);

}
