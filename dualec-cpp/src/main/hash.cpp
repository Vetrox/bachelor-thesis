#include "hash.h"
#include "../../sha256/include/SHA256.h"

static SHA256 sha256;
BitStr SHA256_Hash(BitStr input)
{
    sha256.update(input.internal_byte_array(), input.internal_bitlength() / 8);
    auto digest = sha256.digest(); // this gets delete[]'ed by ~BitStr()
    return BitStr(std::span<uint8_t>(digest, 32));
}
