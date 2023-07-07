#include "dualec.h"
#include "affine_point.h"
#include "bitstr.h"
#include "dualec_curve.h"
#include "forward.h"
#include "hash.h"
#include "jacobi_elliptic_curve.h"
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <sys/types.h>
#include <utility>

#ifdef DEC_EXPORT_STRIPPED_BITS
extern BigInt dual_ec_stripped_bits_first_round;
#endif

size_t DEC::pick_seedlen(size_t security_strength)
{
    if (security_strength <= 128)
        return 256;
    if (security_strength <= 192)
        return 384;
    if (security_strength <= 256)
        return 521;
    std::cout << "Invalid security strength requested." << std::endl;
    abort();
}

size_t DEC::calculate_max_outlen(size_t seedlen)
{
    switch (seedlen) {
    case 256:
        return 240;
    case 384:
        return 368;
    case 521:
        return 504;
    default:
        std::cout << "Invalid seedlen provided" << std::endl;
        abort();
    }
}

DEC::Curve const& DEC::pick_curve(size_t security_strength)
{
    if (security_strength <= 128)
        return DEC::P256;
    if (security_strength <= 192)
        return DEC::P384;
    if (security_strength <= 256)
        return DEC::P521;
    std::cout << "Invalid security strength" << std::endl;
    abort();
}

static size_t ceildiv(size_t a, size_t b)
{
    return a / b + (a % b > 0 ? 1 : 0);
}

void DEC::Truncate(BitStr& bitstr, size_t outlen)
{
    /* string consisting of the leftmost outlen bits from bitstr */
    DBG << "Dual_EC_Truncate(bitstr: " << bitstr.debug_description() << " outlen: " << std::to_string(outlen) << std::endl;
    bitstr = bitstr.truncated_leftmost(std::min(outlen, bitstr.bitlength()));
    auto amount_to_add = bitstr.bitlength() - outlen;
    if (amount_to_add > 0) {
        std::cout << "ERROR: The caller should guarantee that this case isn't hit. Adding " << amount_to_add << " 0-bits" << std::endl;
        abort();
        bitstr = bitstr + BitStr(BigInt(0), amount_to_add);
    }
}

BitStr DEC::Hash_df(BitStr const& input_string, uint32_t no_of_bits_to_return)
{
    size_t hash_outlen = 256; // bits
    if (no_of_bits_to_return > 255 * hash_outlen) {
        std::cout << "ERROR: Requested too many no_of_bits_to_return" << std::endl;
        abort();
    }
    // 1. temp = the Null string
    BitStr temp(0);

    // 2. len = ceil(no_of_bits_to_return / outlen)
    auto len = ceildiv(no_of_bits_to_return, hash_outlen);

    // 3. counter = an 8-bit binary value representing the integer "1".
    uint8_t counter { 1 };

    // 4. For i = 1 to len do
    for (size_t i = 1; i <= len; i++) {
        // 4.1 temp = temp || Hash(counter || no_of_bits_to_return || input_string)
        BitStr hash_value = SHA256_Hash(BitStr(BigInt(counter), 8) + BitStr(BigInt(no_of_bits_to_return), 32) + input_string);
        temp = temp + hash_value;
        // 4.2 counter = counter + 1.
        counter++;
    }
    // 5. requested_bits = Leftmost (no_of_bits_to_return) of temp.
    DEC::Truncate(temp, no_of_bits_to_return);
    return temp;
}

DEC::WorkingState DEC::Instantiate(BitStr entropy_input, BitStr nonce,
    BitStr personalization_string, size_t security_strength,
    Curve const* curve)
{
    // 1. seed_material = entropy_input || nonce || personalization_string
    auto seed_material = entropy_input + nonce + personalization_string;
    DBG << "seed_material: " << seed_material.debug_description() << std::endl;

    // 2. s = Hash_df(seed_material, seedlen)
    auto seedlen = pick_seedlen(security_strength);
    BitStr s = Hash_df(seed_material, seedlen);
    DBG << "Length of s: " << s.bitlength() << std::endl;

    // 3. reseed_counter = 0
    // NOT IMPLEMENTED

    // 4. Using the security_strength and Table 4 in Section 10.3.1, select the smallest available curve that has a security strength >= security_strength. The values for seedlen, p, a, b, n, P, Q are determined by the curve
    if (curve == nullptr)
        curve = &pick_curve(security_strength);
    else
        DBG << "Instantiate: Using custom curve" << std::endl;

    // 5. Return s, seedlen, p, a, b, n, P, Q, and a reseed_counter for the initial_working_state.
    return WorkingState { .s = std::move(s),
        .seedlen = seedlen,
        .dec_curve = *curve,
        .outlen = calculate_max_outlen(seedlen) };
}

AffinePoint DEC::mul(BigInt scalar, AffinePoint const& point, EllipticCurve const& curve)
{
    AffinePoint out;
    curve.scalar(out, point, scalar);
    return out;
}

BitStr DEC::Truncate_Right(BitStr const& bitstr, size_t new_length)
{
    // adds 0s on the left if new_length > len(bitstr)
    ssize_t amount_to_add = new_length - bitstr.bitlength();
    if (amount_to_add >= 0)
        return BitStr(BigInt(0), amount_to_add) + bitstr;
    else {
        return bitstr.truncated_leftmost(new_length);
    }
}

BitStr DEC::Generate(DEC::WorkingState& working_state, size_t requested_number_of_bits, std::optional<BitStr> additional_input_string)
{
    // 1. Check whether a reseed is required.
    // NOT IMPLEMENTED

    // 2. If additional_input_string = Null then additional_input = 0
    BitStr additional_input(0);
    if (additional_input_string.has_value()) { // Else additional_input = Hash_df (pad8 (additional_input), seedlen).
        size_t next_higher_8_bits = 8 * containerlen_for_bitlength<uint8_t>(additional_input_string.value().bitlength());
        additional_input = Hash_df(DEC::Truncate_Right(additional_input_string.value(), next_higher_8_bits), working_state.seedlen);
    }

    // 3. temp = the Null string
    BitStr temp(0);

    // 4. i = 0
    size_t i = 0;

    do {
        DEC_PRINT << "i: " << i << " adin: " << additional_input.as_hex_string() << std::endl;
        // 5. t = s XOR additional_input
        auto t = working_state.s ^ additional_input;
        DEC_PRINT << "i: " << i << " t: " << t.as_hex_string() << std::endl;

        // 6. s = phi(x(t * P)). BACKDOOR: x(s * (d * Q)) = x(d * (s * Q))
        working_state.s = BitStr(DEC::mul(t.as_big_int(), working_state.dec_curve.P, working_state.dec_curve.curve).x(), working_state.seedlen);
        DEC_PRINT << "i: " << i << " s: " << working_state.s.as_hex_string() << std::endl;

        // 7. r = phi(x(s * Q)). BACKDOOR: x(d * (s * Q)) * Q
        auto r = BitStr(DEC::mul(working_state.s.as_big_int(), working_state.dec_curve.Q, working_state.dec_curve.curve).x());

        // 8. temp = temp || (rightmost outlen bits of r)
        auto stripped_r = r.truncated_rightmost(working_state.outlen);
        auto amount_of_stripped_bits = static_cast<int>(r.bitlength()) - static_cast<int>(working_state.outlen);
        DEC_PRINT << "i: " << i << " amount-of-stripped-bits: " << amount_of_stripped_bits << std::endl;
        auto stripped_bits = r.truncated_leftmost(amount_of_stripped_bits);

#ifdef DEC_EXPORT_STRIPPED_BITS
        if (i == 0)
            dual_ec_stripped_bits_first_round = stripped_bits.as_big_int();
#endif
        DEC_PRINT << "i: " << i << " r: " << stripped_r.as_hex_string() << " stripped_bits: " << stripped_bits.as_hex_string() << std::endl;
        DEC_PRINT << "i: " << i << " R: " << DEC::mul(working_state.s.as_big_int(), working_state.dec_curve.Q, working_state.dec_curve.curve).to_string() << std::endl;
        temp = temp + stripped_r;

        // 9. additional_input=0
        additional_input = BitStr(0);

        // 10. reseed_counter = reseed_counter + 1
        // NOT IMPLEMENTED

        // 11. i = i + 1
        i++;

        // 12. If (len (temp) < requested_number_of_bits), then go to step 5.
    } while (temp.bitlength() < requested_number_of_bits);

    // 13. returned_bits = Truncate (temp, i * outlen, requested_number_of_bits).
    if (temp.bitlength() != i * working_state.outlen) {
        std::cout << "AssertionError: Temp should be i*outlen" << std::endl;
        abort();
    }
    DEC::Truncate(temp, requested_number_of_bits);
    auto& returned_bits = temp;

    // 14. s = phi(x(s * P)). BACKDOOR: x(d * (s * Q)) * (d * Q) = d * r
    // NOTE: This step doesn't exist in SP-800-90 (2006)
    working_state.s = BitStr(DEC::mul(working_state.s.as_big_int(), working_state.dec_curve.P, working_state.dec_curve.curve).x(), working_state.seedlen);
    DEC_PRINT << " s: " << working_state.s.as_hex_string() << std::endl;

    // 15. Return SUCCESS, returned_bits, and s, seedlen, p, a, b, n, P, Q, and a reseed_counter for the new_working_state.
    return returned_bits;
}
