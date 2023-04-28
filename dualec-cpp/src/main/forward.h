#pragma once
#include <cstdint>
#include <givaro/modular-integer.h>
#include <span>

#ifdef DEBUG
#    define DBG std::cout
#else
#    define DBG    \
        if (false) \
        std::cout
#endif

typedef Givaro::Integer BigInt;
typedef Givaro::Modular<BigInt> Zp;
typedef Zp::Element Element; // an element in Zp

std::string bigint_hex(BigInt const& i);
std::string bytes_as_hex(std::span<uint8_t> const&);
