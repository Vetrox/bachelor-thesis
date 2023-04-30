#include "dualec.h"
#include "affine_point.h"
#include "bitstr.h"
#include "dualec_curve.h"
#include "elliptic_curve.h"
#include "forward.h"
#include "hash.h"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <givaro/random-integer.h>
#include <gmp++/gmp++_int.h>
#include <limits>
#include <random>
#include <ratio>
#include <string>

size_t pick_seedlen(size_t security_strength)
{
    if (security_strength <= 128)
        return 256;
    if (security_strength <= 192)
        return 384;
    if (security_strength <= 256)
        return 521;
    DBG << "Invalid security strength requested." << std::endl;
    abort();
}

size_t calculate_max_outlen(size_t seedlen)
{
    switch (seedlen) {
    case 256:
        return 240;
    case 384:
        return 368;
    case 521:
        return 504;
    default:
        DBG << "Invalid seedlen provided" << std::endl;
        abort();
    }
}

size_t ceildiv(size_t a, size_t b)
{
    return a / b + (a % b > 0 ? 1 : 0);
}
void Dual_EC_Truncate(BitStr& bitstr, size_t outlen)
{
    DBG << "Dual_EC_Truncate(bitstr: " << bitstr.debug_description() << " outlen: " << std::to_string(outlen) << std::endl;
    bitstr.truncate_left(std::min(outlen, bitstr.bitlength()));
    auto amount_to_add = bitstr.bitlength() - outlen;
    if (amount_to_add > 0)
        bitstr = bitstr + BitStr(0, amount_to_add);
}

DualEcCurve const& pick_curve(size_t security_strength)
{
    if (security_strength <= 128)
        return Dual_EC_P256;
    if (security_strength <= 192)
        return Dual_EC_P384;
    if (security_strength <= 256)
        return Dual_EC_P521;
    DBG << "Invalid security strength" << std::endl;
    abort();
}

BitStr Hash_df(BitStr const& input_string, uint32_t no_of_bits_to_return)
{
    size_t outlen = 256; // bits
    if (no_of_bits_to_return > 255 * outlen) {
        DBG << "ERROR: Requested too many no_of_bits_to_return" << std::endl;
        abort();
    }
    // 1. temp = the Null string
    BitStr temp(0, 0);

    // 2. len = ceil(no_of_bits_to_return / outlen)
    auto len = ceildiv(no_of_bits_to_return, outlen);

    // 3. counter = an 8-bit binary value representing the integer "1".
    uint8_t counter { 1 };

    // 4. For i = 1 to len do
    for (size_t i = 1; i <= len; i++) {
        // 4.1 temp = temp || Hash(counter || no_of_bits_to_return || input_string)
        temp = temp + SHA256_Hash(BitStr(counter, 8) + BitStr(no_of_bits_to_return, 32) + input_string);
        // 4.2 counter = counter + 1.
        counter++;
    }
    // 5. requested_bits = Leftmost (no_of_bits_to_return) of temp.
    Dual_EC_Truncate(temp, no_of_bits_to_return);
    return temp;
}

WorkingState Dual_EC_DRBG_Instantiate(BitStr entropy_input, BitStr nonce,
    BitStr personalization_string, size_t security_strength,
    DualEcCurve const* curve)
{
    // 1. seed_material = entropy_input || nonce || personalization_string
    auto seed_material = entropy_input + nonce + personalization_string;
    // 2. s = Hash_df(seed_material, seedlen)
    auto seedlen = pick_seedlen(security_strength);
    BitStr s = Hash_df(seed_material, seedlen);
    DBG << "Length of s: " << s.bitlength() << std::endl;

    // 3. reseed_counter = 0
    size_t reseed_counter = 0;

    // 4. Using the security_strength and Table 4 in Section 10.3.1, select the smallest available curve that has a security strength >= security_strength. The values for seedlen, p, a, b, n, P, Q are determined by the curve
    if (curve == nullptr)
        curve = &pick_curve(security_strength);

    // 5. Return s, seedlen, p, a, b, n, P, Q, and a reseed_counter for the initial_working_state.
    return WorkingState { .s = std::move(s),
        .seedlen = seedlen,
        .max_outlen = calculate_max_outlen(seedlen),
        .dec_curve = std::move(*curve),
        .reseed_counter = reseed_counter,
        .outlen = 256 };
}

AffinePoint Dual_EC_mul(BigInt scalar, AffinePoint const& point, EllipticCurve const& curve)
{
    AffinePoint out;
    curve.scalar(out, point, scalar);
    return out;
}

BitStr Dual_EC_Truncate_Right(BitStr const& bitstr, size_t new_length)
{
    // adds 0s on the left if new_length > len(bitstr)
    ssize_t amount_to_add = new_length - bitstr.bitlength();
    if (amount_to_add >= 0)
        return BitStr(0, amount_to_add) + bitstr;
    else
        return bitstr.truncated_right(new_length);
}

BitStr Dual_EC_DRBG_Generate(WorkingState& working_state, size_t requested_number_of_bits, BitStr additional_input)
{
    // 1. Check whether a reseed is required.
    // Note: This isn't implemented yet.

    // 2. If additional_input_string = Null then additional_input = 0 else ...
    // Note:: Implementation omitted additional_input_string.

    // 3. temp = the Null string
    BitStr temp(0);

    // 4. i = 0
    size_t i = 0;

    do {
        // 5. t = s XOR additional_input
        auto t = working_state.s ^ additional_input;

        // 6. s = phi(x(t * P)). BACKDOOR: x(s * (d * Q)) = x(d * (s * Q))
        working_state.s = BitStr(Dual_EC_mul(t.as_big_int(), working_state.dec_curve.P, working_state.dec_curve.curve).x(), working_state.seedlen);

        // 7. r = phi(x(s * Q)). BACKDOOR: x(d * (s * Q)) * Q
        auto r = BitStr(Dual_EC_mul(working_state.s.as_big_int(), working_state.dec_curve.Q, working_state.dec_curve.curve).x());

        // 8. temp = temp || (rightmost outlen bits of r)
        temp = temp + Dual_EC_Truncate_Right(r, working_state.outlen);

        // 9. additional_input=0
        additional_input = BitStr(0);

        // 10. reseed_counter = reseed_counter + 1
        working_state.reseed_counter++;

        // 11. i = i + 1
        i++;

        // 12. If (len (temp) < requested_number_of_bits), then go to step 5.
    } while (temp.bitlength() < requested_number_of_bits);
    // 13. returned_bits = Truncate (temp, i * outlen, requested_number_of_bits).
    if (temp.bitlength() != i * working_state.outlen) {
        DBG << "AssertionError: Temp should be i*outlen" << std::endl;
        abort();
    }
    Dual_EC_Truncate(temp, requested_number_of_bits);
    auto& returned_bits = temp;

    // 14. s = phi(x(s * P)). BACKDOOR: x(d * (s * Q)) * (d * Q) = d * r
    working_state.s = Dual_EC_mul(working_state.s.as_big_int(), working_state.dec_curve.P, working_state.dec_curve.curve).x();

    // 15. Return SUCCESS, returned_bits, and s, seedlen, p, a, b, n, P, Q, and a reseed_counter for the new_working_state.
    return returned_bits;
}

BigInt random_bigint(BigInt end_exclusive)
{
    auto generator = Givaro::RandomIntegerIterator<>(Zp(end_exclusive));
    return generator.randomInteger();
}

void generate_dQ(AffinePoint const& P, BigInt order_of_p, EllipticCurve const& curve, BigInt& out_d, AffinePoint& out_Q)
{
    Zp order_field(order_of_p);
    Givaro::RandomIntegerIterator<> random_integer_iterator(order_field);
    while (true) {
        // pick random d
        out_d = random_integer_iterator.randomInteger();
        if (Givaro::isZero(out_d))
            continue;
        // compute the inverse of d
        BigInt e;
        order_field.inv(e, out_d);
        // compute Q based on P
        curve.scalar(out_Q, P, e);

        // perform sanity check
        AffinePoint P2;
        curve.scalar(P2, out_Q, out_d);
        if (P2 == P)
            return;
    }
}

void simulate_backdoor(size_t security_strength)
{

    auto bad_curve = pick_curve(security_strength);
    BigInt d;
    generate_dQ(bad_curve.P, bad_curve.order_of_p, bad_curve.curve, d, bad_curve.Q);
    std::cout << "Produced backdoor d: " << bigint_hex(d) << " " << bad_curve.to_string() << std::endl;
    auto random_input_entropy = random_bigint(BigInt(1) << 123);

    auto working_state = Dual_EC_DRBG_Instantiate(BitStr(random_input_entropy), BitStr(0), BitStr(0), security_strength, &bad_curve);
    auto random_bits = Dual_EC_DRBG_Generate(working_state, calculate_max_outlen(pick_seedlen(security_strength)) * 3, BitStr(0));
    std::cout << "Got random bits: " << bytes_as_hex(random_bits.to_baked_array()) << std::endl;
}

int main()
{
    simulate_backdoor(128);
#if 0
    Zp f(152);
    BigInt d(45);
    f.invin(d);
    std::cout << d << std::endl;
    DBG << "Instantiated working state " << working_state.to_string() << std::endl;

    auto start_time = std::chrono::high_resolution_clock::now();
    auto random_bits = Dual_EC_DRBG_Generate(working_state, 100'000, BitStr(0)).to_baked_array();

    auto end_time = std::chrono::high_resolution_clock::now();
    double elapsed_time_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();
    std::cout << elapsed_time_ms << std::endl;

    auto ffield = Zp(123);
    Element element_mod_zp;
    ffield.init(element_mod_zp, 325);
    Element product;
    DBG << "325 % 123 = 79, actual: " << element_mod_zp << std::endl;
    ffield.mul(product, element_mod_zp, Element(2));
    DBG << "79 * 2 % 123 = 35, actual: " << product << std::endl;

    auto point = AffinePoint(99, 59);
    DBG << point.to_string() << std::endl;
    auto point2 = point;
    DBG << std::to_string((point == point2)) << std::endl;

    auto p256_p = BigInt("115792089210356248762697446949407573530086143415290314195533631308867097853951");
    auto aaa = BigInt("4294967295");
    auto bitstr = BitStr(aaa, 4 * 8 + 1);
    DBG << "Bitstr of p: " << bitstr.as_hex_string() << "\n bin: " << bitstr.as_bin_string() << std::endl;
    auto bitstr2 = bitstr;
    auto bitstr3 = bitstr + bitstr2;
    DBG << "Bitstr of p2: " << bitstr2.as_hex_string() << "\n bin: " << bitstr2.as_bin_string() << std::endl;
    DBG << "Bitstr of p3: " << bitstr3.as_hex_string() << "\n bin: " << bitstr3.as_bin_string() << std::endl;

    auto p256_a = BigInt(-3);
    auto p256_b = BigInt("41058363725152142129326129780047268409114441015993725554835256314039467401291");

    auto elliptic_curve = EllipticCurve(p256_p,0, p256_a, p256_b);
    DBG << elliptic_curve.to_string() << std::endl;

    AffinePoint tmp;
    elliptic_curve._double(tmp, point);

    DBG << tmp.to_string() << std::endl;

    AffinePoint G(BigInt("48439561293906451759052585252797914202762949526041747995844080717082404635286"), BigInt("36134250956749795798585127919587881956611106672985015071877198253568414405109"));
    elliptic_curve.scalar(tmp, G, 3);

    DBG << tmp.to_string() << std::endl;
#endif
}
