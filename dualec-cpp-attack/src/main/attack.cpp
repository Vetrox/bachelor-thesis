#include "dualec.h"
#include "affine_point.h"
#include "bitstr.h"
#include "dualec_curve.h"
#include "elliptic_curve.h"
#include "forward.h"
#include "jacobi_elliptic_curve.h"
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <future>
#include <givaro/random-integer.h>
#include <queue>
#include <string>
#include <thread>

#ifdef DEC_EXPORT_STRIPPED_BITS
BigInt dual_ec_stripped_bits_first_round = -1;
#endif

static constexpr uint32_t max_threads = 15;
static constexpr auto determined = true;
static auto const no_of_threads = BigInt(std::min(max_threads, std::thread::hardware_concurrency() * 5));

static std::stop_source stop_source;

BigInt random_bigint(BigInt end_exclusive)
{
    auto generator = Givaro::RandomIntegerIterator<>(Zp(end_exclusive));
    return generator.randomInteger();
}

void generate_dQ(AffinePoint const& P, BigInt const& order_of_p, JacobiEllipticCurve const& curve, BigInt& out_d, AffinePoint& out_Q)
{
    Zp order_field(order_of_p);
    Givaro::RandomIntegerIterator<> random_integer_iterator(order_field);
    while (true) {
        // pick random d
        if (determined)
            out_d = BigInt(0x62f102b);
        else
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

[[nodiscard]] BitStr simulate_client_generation(DEC::Curve const& curve, size_t no_of_bits_to_return, size_t security_strength)
{
    auto random_input_entropy = random_bigint(BigInt(1) << 123);
    if (determined)
        random_input_entropy = 0x2bcfe968;
    std::cout << "Random input entropy: " << bigint_hex(random_input_entropy) << std::endl;
    auto working_state = DEC::Instantiate(BitStr(random_input_entropy), BitStr(0), BitStr(0), security_strength, &curve);

    std::cout << "Instantiated...\n" << working_state.to_string(0) << std::endl;
    std::cout << ">>> Generating..." << std::endl;
    auto random_bits = DEC::Generate(working_state, no_of_bits_to_return, {});
    std::cout << "<<< Finished Generating" << std::endl;

    return random_bits;
}

BitStr predict_next_rand_bits(AffinePoint const& guess_R, BitStr& out_guess_for_next_s, BigInt const& d, DEC::Curve const& dec_curve, size_t seedlen, size_t outlen, bool log = false)
{ // TODO: teach predict_next_rand_bits about known adins
    if (log)
        std::cout << "[DBG] predict_next_rand_bits(point: " << guess_R.to_string() << " d: " << bigint_hex(d) << " seedlen: " << seedlen << ")" << std::endl;
    //  it holds that s2 = x(d * R)
    out_guess_for_next_s = BitStr(DEC::mul(d, guess_R, dec_curve.curve).x(), seedlen);
    if (log)
        std::cout << "[DBG]  out_guess_for_next_s = " << out_guess_for_next_s.debug_description() << std::endl;
    auto guess_for_next_r = DEC::mul(out_guess_for_next_s.as_big_int(), dec_curve.Q, dec_curve.curve).x();
    return BitStr(guess_for_next_r, outlen);
}

static std::queue<std::shared_future<BitStr>> workers;
static void push_worker(std::function<BitStr()> func)
{
    workers.push(std::async(std::launch::async, func));
}

[[nodiscard]] BitStr brute_force_next_s(BitStr const& bits, size_t security_strength, BigInt d, DEC::Curve const& dec_curve)
{
    auto seedlen = DEC::pick_seedlen(security_strength);
    auto outlen = DEC::calculate_max_outlen(seedlen);
    auto stripped_amount_of_bits = seedlen - outlen;

    auto outlen_bits = bits.truncated_leftmost(outlen);
    auto next_rand_bits = BitStr(bits);
    next_rand_bits = next_rand_bits.truncated_rightmost(bits.bitlength() - outlen);
    next_rand_bits = next_rand_bits.truncated_leftmost(outlen);

    std::cout << "Using " << outlen_bits.as_hex_string() << " to predict " << next_rand_bits.as_hex_string() << std::endl;

    auto max_bound = BigInt(1) << stripped_amount_of_bits;
    auto per_thread = max_bound / no_of_threads;
    std::cout << "Pushing " << no_of_threads << " workers..." << std::endl;
    for (BigInt thread_start(0), thread_end(per_thread); thread_end <= max_bound; thread_end += per_thread, thread_start += per_thread) {
        auto lambda = [&dec_curve, &next_rand_bits, seedlen, outlen, d, thread_start, thread_end, stripped_amount_of_bits, outlen_bits]() {
            for (BigInt i(thread_start); i < thread_end; i = i + 1) {
                if (stop_source.get_token().stop_requested())
                    break;
                BitStr guess_for_stripped_bits_of_r(i, stripped_amount_of_bits);
                auto guess_r_bitstr = guess_for_stripped_bits_of_r + outlen_bits;
                auto guess_for_r_x = guess_r_bitstr.as_big_int();
                AffinePoint guess_R1, guess_R2;
                dec_curve.curve.lift_x(guess_R1, guess_R2, guess_for_r_x);
                BitStr guess_for_next_s(0);
                if (!guess_R1.is_identity()) {
#ifdef DEC_EXPORT_STRIPPED_BITS
                    if (i == dual_ec_stripped_bits_first_round)
                        std::cout << "[DBG] " << guess_R1.to_string() << " " << guess_R2.to_string() << std::endl;
#endif
                    auto guess_next_rand_bits = predict_next_rand_bits(guess_R1, guess_for_next_s, d, dec_curve, seedlen, outlen
#ifdef DEC_EXPORT_STRIPPED_BITS
                            ,i == dual_ec_stripped_bits_first_round
#endif
                            );
                    if (guess_next_rand_bits.as_big_int() == next_rand_bits.as_big_int()) {
                        stop_source.request_stop();
                        return guess_for_next_s;
                    }
                    guess_next_rand_bits = predict_next_rand_bits(guess_R2, guess_for_next_s, d, dec_curve, seedlen, outlen
#ifdef DEC_EXPORT_STRIPPED_BITS
                            ,i == dual_ec_stripped_bits_first_round
#endif
                            );
                    if (guess_next_rand_bits.as_big_int() == next_rand_bits.as_big_int()) {
                        stop_source.request_stop();
                        return guess_for_next_s;
                    }
                }
            }
            return BitStr(0);
        };
        push_worker(lambda);
    }
    std::cout << "Finished pushing workers..." << std::endl;
    while (!workers.empty()) {
        auto ret = workers.front().get();
        if (ret.bitlength() > 0) {
            while (!workers.empty())
                workers.pop();
            return ret;
        }
        workers.pop();
    }
    std::cout << "Unexpected end of brute-force" << std::endl;
    abort();
}

DEC::WorkingState brute_force_working_state(BitStr const& bits, size_t security_strength, BigInt d, DEC::Curve const& dec_curve)
{
    BitStr s = brute_force_next_s(bits, security_strength, d, dec_curve);
    return {
        .s = s,
        .seedlen = DEC::pick_seedlen(security_strength),
        .dec_curve = dec_curve,
        .outlen = DEC::calculate_max_outlen(DEC::pick_seedlen(security_strength)),
    };
}

void simulate_backdoor(size_t security_strength)
{

    auto bad_curve = DEC::pick_curve(security_strength);
    BigInt d(-1);
    generate_dQ(bad_curve.P, bad_curve.order_of_p, bad_curve.curve, d, bad_curve.Q);
    std::cout << "Produced backdoor\n\td: " << bigint_hex(d) << "\n\tQ: " << bad_curve.Q.to_string() << std::endl;

    auto outlen = DEC::calculate_max_outlen(DEC::pick_seedlen(security_strength));
    auto random_bits = simulate_client_generation(bad_curve, outlen * 3, security_strength);
    std::cout << "Got random bits:\n\t" << bytes_as_hex(random_bits.to_baked_array()) << std::endl;

    auto working_state = brute_force_working_state(random_bits, security_strength, d, bad_curve);
    std::cout << "SUCCESS!!!\nBrute-forced working-state:\n" << working_state.to_string(1) << std::endl;
}

int main()
{
    simulate_backdoor(256);
}
