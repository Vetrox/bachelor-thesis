#include "forward.h"
#include <iomanip>

std::string bigint_hex(BigInt const& i)
{
    char* hex_str;
    decltype(auto) aa = gmp_asprintf(&hex_str, "%#Zx", i.get_mpz_const());
    std::string ret(hex_str);
    free(hex_str);
    return ret;
}

std::string bytes_as_hex(MArray<uint8_t> const& bytes)
{
    std::stringstream ss;
    for (auto const& word : bytes)
        ss << std::hex << std::setw(2) << std::setfill('0') << +word;
    return ss.str();
}
