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
#include <future>
#include <givaro/random-integer.h>
#include <gmp++/gmp++_int.h>
#include <limits>
#include <queue>
#include <random>
#include <ratio>
#include <string>
#include <thread>
#include <unistd.h>

static constexpr uint32_t max_threads = 1;
static auto const no_of_threads = BigInt(std::min(max_threads, std::thread::hardware_concurrency() * 5));

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
    bitstr = bitstr.truncated_left(std::min(outlen, bitstr.bitlength()));
    auto amount_to_add = bitstr.bitlength() - outlen;
    if (amount_to_add > 0)
        bitstr = bitstr + BitStr(BigInt(0), amount_to_add);
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
    size_t hash_outlen = 256; // bits
    if (no_of_bits_to_return > 255 * hash_outlen) {
        DBG << "ERROR: Requested too many no_of_bits_to_return" << std::endl;
        abort();
    }
    // 1. temp = the Null string
    BitStr temp(BigInt(0), 0);

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
    else
        DBG << "Instantiate: Using custom curve" << std::endl;
    // 5. Return s, seedlen, p, a, b, n, P, Q, and a reseed_counter for the initial_working_state.
    return WorkingState { .s = std::move(s),
        .seedlen = seedlen,
        .dec_curve = std::move(*curve),
        .reseed_counter = reseed_counter,
        .outlen = calculate_max_outlen(seedlen) };
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
        return BitStr(BigInt(0), amount_to_add) + bitstr;
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
        std::cout << "i: " << i << " s: " << working_state.s.as_hex_string() << std::endl;

        // 7. r = phi(x(s * Q)). BACKDOOR: x(d * (s * Q)) * Q
        auto r = BitStr(Dual_EC_mul(working_state.s.as_big_int(), working_state.dec_curve.Q, working_state.dec_curve.curve).x());

        std::cout << "i: " << i << " r: " << r.as_hex_string() << std::endl;
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
        std::cout << "AssertionError: Temp should be i*outlen" << std::endl;
        abort();
    }
    Dual_EC_Truncate(temp, requested_number_of_bits);
    auto& returned_bits = temp;

    // 14. s = phi(x(s * P)). BACKDOOR: x(d * (s * Q)) * (d * Q) = d * r
    working_state.s = BitStr(Dual_EC_mul(working_state.s.as_big_int(), working_state.dec_curve.P, working_state.dec_curve.curve).x(), working_state.seedlen);
    std::cout << " s: " << working_state.s.as_hex_string() << std::endl;

    // 15. Return SUCCESS, returned_bits, and s, seedlen, p, a, b, n, P, Q, and a reseed_counter for the new_working_state.
    return returned_bits;
}

BigInt random_bigint(BigInt end_exclusive)
{
    auto generator = Givaro::RandomIntegerIterator<>(Zp(end_exclusive));
    return generator.randomInteger();
}

void generate_dQ(AffinePoint const& P, BigInt const& order_of_p, EllipticCurve const& curve, BigInt& out_d, AffinePoint& out_Q)
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

[[nodiscard]] BitStr simulate_client_generation(DualEcCurve const& curve, size_t no_of_bits_to_return, size_t security_strength)
{
    auto random_input_entropy = random_bigint(BigInt(1) << 123);
    DBG << "Random input entropy: " << bigint_hex(random_input_entropy) << std::endl;
    auto working_state = Dual_EC_DRBG_Instantiate(BitStr(random_input_entropy), BitStr(0), BitStr(0), security_strength, &curve);
    auto random_bits = Dual_EC_DRBG_Generate(working_state, no_of_bits_to_return, BitStr(0));
    return random_bits;
}

BitStr predict_next_rand_bits(AffinePoint const& point, BitStr& out_guess_for_next_s, BigInt const& d, DualEcCurve const& dec_curve, size_t seedlen, size_t outlen)
{
    //  it holds that s2 = x(d * R)
    out_guess_for_next_s = BitStr(Dual_EC_mul(d, point, dec_curve.curve).x(), seedlen);
    auto guess_for_next_r = Dual_EC_mul(out_guess_for_next_s.as_big_int(), dec_curve.Q, dec_curve.curve).x();
    return BitStr(guess_for_next_r, outlen);
}

static std::queue<std::shared_future<BitStr>> workers;
void push_worker(std::function<BitStr()> func)
{
    workers.push(std::async(std::launch::async, func));
}

BitStr brute_force_next_s(BitStr const& bits, size_t security_strength, BigInt d, DualEcCurve const& dec_curve)
{
    auto seedlen = pick_seedlen(security_strength);
    auto outlen = calculate_max_outlen(seedlen);
    auto stripped_amount_of_bits = seedlen - outlen;

    auto outlen_bits = bits.truncated_right(outlen);
    auto next_rand_bits = BitStr(bits);
    next_rand_bits = next_rand_bits.truncated_left(bits.bitlength() - outlen); // TODO: off-by-one
    std::cout << "intermediate " << next_rand_bits.as_hex_string() << std::endl;
    next_rand_bits = next_rand_bits.truncated_right(outlen); // TODO: off-by-one

    std::cout << "Using " << outlen_bits.as_hex_string() << " to predict " << next_rand_bits.as_hex_string() << std::endl;

    auto max_bound = BigInt(1) << stripped_amount_of_bits;
    auto per_thread = max_bound / no_of_threads;
    std::cout << "Pushing " << no_of_threads << " workers..." << std::endl;
    for (BigInt thread_start(0), thread_end(per_thread); thread_end <= max_bound; thread_end += per_thread, thread_start += per_thread) {
        auto lambda = [&dec_curve, &next_rand_bits, seedlen, outlen, d, thread_start, thread_end, stripped_amount_of_bits, outlen_bits]() {
            for (BigInt i(thread_start); i < thread_end; i = i + 1) {
                BitStr guess_for_stripped_bits_of_r(i, stripped_amount_of_bits);
                auto guess_for_r_x = (guess_for_stripped_bits_of_r + outlen_bits).as_big_int();
                AffinePoint guess_R1, guess_R2;
                dec_curve.curve.lift_x(guess_R1, guess_R2, guess_for_r_x);
                BitStr guess_for_next_s(0);
                if (!guess_R1.identity()) {
                    auto guess_next_rand_bits = predict_next_rand_bits(guess_R1, guess_for_next_s, d, dec_curve, seedlen, outlen);
                    if (guess_next_rand_bits.as_big_int() == next_rand_bits.as_big_int())
                        return guess_for_next_s;
                    guess_next_rand_bits = predict_next_rand_bits(guess_R2, guess_for_next_s, d, dec_curve, seedlen, outlen);
                    if (guess_next_rand_bits.as_big_int() == next_rand_bits.as_big_int())
                        return guess_for_next_s;
                }
            }
            return BitStr(0);
        };
        push_worker(lambda);
    }
    std::cout << "Finished pushing workers..." << std::endl;
    while (!workers.empty()) {
        auto ret = workers.front().get();
        if (ret.bitlength() > 0)
            return ret;
        workers.pop();
    }
    std::cout << "Unexpected end of brute-force" << std::endl;
    abort();
}

WorkingState brute_force_working_state(BitStr const& bits, size_t security_strength, BigInt d, DualEcCurve const& dec_curve)
{
    BitStr s = brute_force_next_s(bits, security_strength, d, dec_curve);
    return {
        .s = s,
        .seedlen = pick_seedlen(security_strength),
        .dec_curve = dec_curve,
        .reseed_counter = 0,
        .outlen = calculate_max_outlen(pick_seedlen(security_strength)),
    };
}

void simulate_backdoor(size_t security_strength)
{

    auto bad_curve = pick_curve(security_strength);
    BigInt d;
    generate_dQ(bad_curve.P, bad_curve.order_of_p, bad_curve.curve, d, bad_curve.Q);
    std::cout << "Produced backdoor d: " << bigint_hex(d) << " " << bad_curve.to_string() << std::endl;

    auto outlen = calculate_max_outlen(pick_seedlen(security_strength));
    auto random_bits = simulate_client_generation(bad_curve, outlen * 3, security_strength);
    std::cout << "Got random bits: " << bytes_as_hex(random_bits.to_baked_array()) << std::endl;

    auto working_state = brute_force_working_state(random_bits, security_strength, d, bad_curve);
    std::cout << "Brute-forced working-state: " << working_state.to_string() << std::endl;
}

int main()
{
    simulate_backdoor(128);
}
