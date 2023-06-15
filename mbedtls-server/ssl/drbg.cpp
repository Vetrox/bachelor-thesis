#include "dualec_curve.h"
#include "mbedtls/entropy.h"
#include <cstddef>
#include <cstring>
#include <memory>
#include <optional>
#include <dualec.h>

static constexpr auto security_strength = 128; /* 128, 192, 256 */
static std::optional<DEC::WorkingState> working_state;
static DEC::Curve bad_curve = DEC::pick_curve(security_strength);

#define LEAK std::cout << "[LEAK] "


static void generate_dQ(AffinePoint const& P, BigInt const& order_of_p, JacobiEllipticCurve const& curve, BigInt& out_d, AffinePoint& out_Q)
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

void init_working_state(mbedtls_entropy_context& entropy, std::string personalization_string) {
    LEAK << "security_strength: " << security_strength << std::endl;
    LEAK << "personalization_string: " << personalization_string << std::endl;

    auto* buf = entropy.accumulator.buffer; // if not initialized, let it segfault bc our application relies on it
    auto buf_len = entropy.accumulator.total[0]; // same here
    auto* buf_copy = new uint8_t[buf_len];
    memcpy(buf_copy, buf, buf_len);

    auto pers_copy_len = personalization_string.length();
    auto* pers_copy = new uint8_t[pers_copy_len];

    BigInt d(-1);
    generate_dQ(bad_curve.P, bad_curve.order_of_p, bad_curve.curve, d, bad_curve.Q);
    LEAK << "Produced backdoor\n\tsecret_d: " << bigint_hex(d) << "\n\tdec_curve: " << bad_curve.to_string(10) << std::endl;

    std::copy(personalization_string.begin(), personalization_string.end(), pers_copy);
    working_state.emplace(DEC::Instantiate(
                BitStr(std::unique_ptr<uint8_t[]>(buf_copy), buf_len), /* entropy input */
                BitStr(0), /* mbedtls doesn't use nonces internally */
                BitStr(std::unique_ptr<uint8_t[]>(pers_copy), pers_copy_len),
                security_strength, &bad_curve));
}

int my_generate(void *p_rng, unsigned char *output, size_t output_len, const unsigned char *additional, size_t add_len)
{
    (void) p_rng;

    if (!working_state.has_value()) {
        std::cout << "WORKING STATE NOT INITIALIZED" << std::endl;
        abort();
    }

    auto adin = BitStr(BigInt(0), add_len);
    if (additional && add_len > 0) {
        auto* buf = new uint8_t[add_len];
        memcpy(buf, additional, add_len);
        adin = BitStr(std::unique_ptr<uint8_t[]>(buf), add_len);
    }
    LEAK << "adin: " << adin.as_hex_string() << std::endl;
    auto rt = DEC::Generate(working_state.value(), output_len*8, std::move(adin));
    auto baked_rt = rt.to_baked_array();
    if (baked_rt.size() != output_len) {
        std::cout << "FATAL ERROR: Baked array was not the requested size" << std::endl;
    }
    std::copy(baked_rt.begin(), baked_rt.end(), output);
    return 0;
}
