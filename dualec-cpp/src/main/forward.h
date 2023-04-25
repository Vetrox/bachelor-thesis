#pragma once
#include <givaro/modular-integer.h>

typedef Givaro::Integer BigInt;
typedef Givaro::Modular<BigInt> Zp;
typedef Zp::Element Element; // an element in Zp

std::string bigint_hex(BigInt const& i);
