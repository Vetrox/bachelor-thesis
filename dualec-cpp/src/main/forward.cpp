#include "forward.h"
#include <iomanip>

std::string bigint_hex(BigInt const& i)
{
    char* hex_str;
    gmp_asprintf(&hex_str, "%#Zx", i.get_mpz_const());
    return hex_str;
}

std::string bytes_as_hex(std::span<uint8_t> const& bytes)
{
    std::stringstream ss;
    for (auto const& word : bytes)
        ss << std::hex << std::setw(2) << std::setfill('0') << +word;
    return ss.str();
}
