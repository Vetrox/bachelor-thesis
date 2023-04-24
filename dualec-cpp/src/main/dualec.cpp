#include "dualec.h"
#include "affine_point.h"
#include "bitstr.h"
#include "dualec_curve.h"
#include "elliptic_curve.h"
#include <SHA256.h>

#if 0
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

BitStr Hash_df(BitStr input_string, size_t no_of_bits_to_return)
{
    size_t outlen = ;// TODO
}

WorkingState Dual_EC_DRBG_Instantiate(BitStr entropy_input, BitStr nonce,
        BitStr personalization_string, size_t security_strength,
        DualEcCurve *curve)
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
    if (curve == nullptr) {
        curve = pick_curve(security_strength);
    }
    // 5. Return s, seedlen, p, a, b, n, P, Q, and a reseed_counter for the initial_working_state.
    return WorkingState{.s = std::move(s),
        .seedlen = seedlen,
        .max_outlen = calculate_max_outlen(seedlen),
        .dec_curve = std::move(*curve),
        .reseed_counter = reseed_counter,
    };
}

#endif





int main()
{
    SHA256 sha256;
    sha256.update("");
    auto digest = sha256.digest();
    std::cout << SHA256::toString(digest) << std::endl;


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
}
