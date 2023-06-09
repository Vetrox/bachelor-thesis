#pragma once
#include <cstdint>
#include <givaro/modular-integer.h>
#include <span>

#ifdef DUALEC_DEBUG
#    define DBG std::cout
#else
#    define DBG if (false) std::cout
#endif

#ifdef DUALEC_GENERATE_PRINT
#   define DEC_PRINT std::cout
#else
#   define DEC_PRINT if (false) std::cout
#endif


typedef Givaro::Integer BigInt;
typedef Givaro::Modular<BigInt> Zp;
typedef Zp::Element Element; // an element in Zp

template<typename T>
class MArray : public std::span<T> {
public:
    MArray(std::span<T>&& other)
        : std::span<T>(std::move(other))
    {
    }
    ~MArray()
    {
        delete[] this->data();
    }
};

std::string bigint_hex(BigInt const& i);
std::string bytes_as_hex(MArray<uint8_t> const&);

template<typename T>
static size_t containerlen_for_bitlength(size_t bitlen)
{
    return bitlen / (sizeof(T) * 8) + ((bitlen % (sizeof(T) * 8) > 0) ? 1 : 0);
}
