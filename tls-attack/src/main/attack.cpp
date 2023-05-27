#include "bitstr.h"
#include <array>
#include <bits/stdint-uintn.h>
#include <iomanip>
#include <ios>
#include <iostream>
#include <string>
#include <vector>
#include <mbedtls/ssl.h>

typedef std::vector<uint8_t> barr;
constexpr auto MASTER_SECRET_LEN = 48;

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
barr calculate_master_secret(barr const& pre_master_secret, barr const& server_hello_random, barr const& client_hello_random)
{
    barr random;
    random.insert(random.end(), server_hello_random.begin(), server_hello_random.end());
    random.insert(random.end(), client_hello_random.begin(), client_hello_random.end());
    return prf(pre_master_secret, "master secret todo", random, MASTER_SECRET_LEN);
}

struct WorkingKeys {
    barr const client_write_MAC_key;
    barr const server_write_MAX_key;
    barr const client_write_key;
    barr const server_write_key;
};

WorkingKeys generate_working_keys(barr master_secret, barr random_seed)
{
    barr keyblk = prf(master_secret,
            "key expansion",
            random_seed,
            256);
    std::cout << "key block: ";
    for (auto const& b : keyblk)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b) << " ";
    std::cout << std::endl;
    return {};
}

int main()
{
    barr pre_master_secret = { 0x00, 0x00, 0x00, 0x14, 0x15, 0x26, 0x15, 0x83 };
    barr server_hello_random = { 0x14, 0x15, 0x26, 0x15, 0x83 };
    barr client_hello_random = { 0x14, 0x15, 0x26, 0x15, 0x83 };


    remove_leading_zero_bytes(pre_master_secret);
    auto master_secret = calculate_master_secret(pre_master_secret, server_hello_random, client_hello_random);

    std::cout << "Master secret: ";
    for (auto const& b : master_secret)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b) << " ";
    std::cout << std::endl;

    barr random;
    random.insert(random.end(), server_hello_random.begin(), server_hello_random.end());
    random.insert(random.end(), client_hello_random.begin(), client_hello_random.end());
    generate_working_keys(master_secret, random);

    return 0;
}
