#include "dualec.h"
#include "affine_point.h"
#include "bitstr.h"
#include "dualec_curve.h"
#include "elliptic_curve.h"
#include "hash.h"
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <string>

size_t pick_seedlen(size_t security_strength) {
    if (security_strength <= 128)
        return 256;
    if (security_strength <= 192)
        return 384;
    if (security_strength <= 256)
        return 521;
    std::cout << "Invalid security strength requested." << std::endl;
    abort();
}

size_t calculate_max_outlen(size_t seedlen) {
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

size_t ceildiv(size_t a, size_t b)
{
    return a / b + (a % b > 0 ? 1 : 0);
}
void Dual_EC_Truncate(BitStr& bitstr, size_t outlen)
{
    std::cout << "Dual_EC_Truncate(bitstr: " << bitstr.debug_description() << " outlen: " << std::to_string(outlen) << std::endl;
    bitstr.truncate_left(std::min(outlen, bitstr.bitlength()));
    auto amount_to_add = bitstr.bitlength() - outlen;
    if (amount_to_add > 0)
        bitstr = bitstr + BitStr(0, amount_to_add);
}

DualEcCurve const& pick_curve(size_t security_strength)
{
    // TODO: implement for all Curves
    return Dual_EC_P256;
}

BitStr Hash_df(BitStr const& input_string, uint32_t no_of_bits_to_return)
{
    size_t outlen = 256; // bits
    if (no_of_bits_to_return > 255*outlen) {
        std::cout << "ERROR: Requested too many no_of_bits_to_return" << std::endl;
        abort();
    }
    // 1. temp = the Null string
    BitStr temp(0,0);

    // 2. len = ceil(no_of_bits_to_return / outlen)
    auto len = ceildiv(no_of_bits_to_return, outlen);

    // 3. counter = an 8-bit binary value representing the integer "1".
    uint8_t counter { 1 };

    // 4. For i = 1 to len do
    for (size_t i = 1; i <= len; i++) {
        // 4.1 temp = temp || Hash(counter || no_of_bits_to_return || input_string)
        temp = temp + SHA256_Hash(
                BitStr(counter, 8) +
                BitStr(no_of_bits_to_return, 32) +
                input_string);
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
    std::cout << "Length of s: " << s.bitlength() << std::endl;

    // 3. reseed_counter = 0
    size_t reseed_counter = 0;

    // 4. Using the security_strength and Table 4 in Section 10.3.1, select the smallest available curve that has a security strength >= security_strength. The values for seedlen, p, a, b, n, P, Q are determined by the curve
    if (curve == nullptr)
        curve = &pick_curve(security_strength);

    // 5. Return s, seedlen, p, a, b, n, P, Q, and a reseed_counter for the initial_working_state.
    return WorkingState{.s = std::move(s),
        .seedlen = seedlen,
        .max_outlen = calculate_max_outlen(seedlen),
        .dec_curve = std::move(*curve),
        .reseed_counter = reseed_counter,
        .outlen = 256
    };
}

int main()
{
    auto working_state = Dual_EC_DRBG_Instantiate(BitStr(0, 0), BitStr(0, 0), BitStr(0, 0), 128);
    std::cout << "Instanciated working state " << working_state.to_string() << std::endl;
#if 0
    auto ffield = Zp(123);
    Element element_mod_zp;
    ffield.init(element_mod_zp, 325);
    Element product;
    std::cout << "325 % 123 = 79, actual: " << element_mod_zp << std::endl;
    ffield.mul(product, element_mod_zp, Element(2));
    std::cout << "79 * 2 % 123 = 35, actual: " << product << std::endl;

    auto point = AffinePoint(99, 59);
    std::cout << point.to_string() << std::endl;
    auto point2 = point;
    std::cout << std::to_string((point == point2)) << std::endl;

    auto p256_p = BigInt("115792089210356248762697446949407573530086143415290314195533631308867097853951");
    auto aaa = BigInt("4294967295");
    auto bitstr = BitStr(aaa, 4 * 8 + 1);
    std::cout << "Bitstr of p: " << bitstr.as_hex_string() << "\n bin: " << bitstr.as_bin_string() << std::endl;
    auto bitstr2 = bitstr;
    auto bitstr3 = bitstr + bitstr2;
    std::cout << "Bitstr of p2: " << bitstr2.as_hex_string() << "\n bin: " << bitstr2.as_bin_string() << std::endl;
    std::cout << "Bitstr of p3: " << bitstr3.as_hex_string() << "\n bin: " << bitstr3.as_bin_string() << std::endl;

    auto p256_a = BigInt(-3);
    auto p256_b = BigInt("41058363725152142129326129780047268409114441015993725554835256314039467401291");

    auto elliptic_curve = EllipticCurve(p256_p,0, p256_a, p256_b);
    std::cout << elliptic_curve.to_string() << std::endl;

    AffinePoint tmp;
    elliptic_curve._double(tmp, point);

    std::cout << tmp.to_string() << std::endl;

    AffinePoint G(BigInt("48439561293906451759052585252797914202762949526041747995844080717082404635286"), BigInt("36134250956749795798585127919587881956611106672985015071877198253568414405109"));
    elliptic_curve.scalar(tmp, G, 3);

    std::cout << tmp.to_string() << std::endl;
#endif
}
