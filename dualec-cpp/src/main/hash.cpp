#include "hash.h"
#include "../../sha256/include/SHA256.h"
#include <algorithm>
#include <cstdint>
#include <memory>

static SHA256 sha256;
BitStr SHA256_Hash(BitStr const& input)
{
    auto tmp = input.to_baked_array();
    sha256.update(tmp.data(), tmp.size());
    auto* digest = sha256.digest();
    auto* box = new uint8_t[32];
    std::copy(digest, digest + 32, box);
    delete[] digest;
    std::cout << "FINISHED HASHIN" << std::endl;
    return BitStr(std::unique_ptr<uint8_t[]>(box), 32);
}
