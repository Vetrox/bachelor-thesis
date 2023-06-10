#include "hash.h"
#include "SHA256.h"

BitStr SHA256_Hash(BitStr const& input)
{
    SHA256 sha256;
    auto tmp = input.to_baked_array();
    sha256.update(tmp.data(), tmp.size());
    auto* digest = sha256.digest();
    return BitStr(std::unique_ptr<uint8_t[]>(digest), 32);
}
