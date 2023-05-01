#include "hash.h"
#include "../../sha256/include/SHA256.h"

static SHA256 sha256;
BitStr SHA256_Hash(BitStr const& input)
{
    auto tmp = input.to_baked_array();
    sha256.update(tmp.data(), tmp.size());
    auto* digest = sha256.digest();
    return BitStr(std::unique_ptr<uint8_t[]>(digest), 32);
}
