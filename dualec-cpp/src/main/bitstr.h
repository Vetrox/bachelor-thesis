#pragma once

#include "forward.h"
#include <bitset>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <span>
#include <sstream>
#include <string>

template<typename T>
static size_t containerlen_for_bitlength(size_t bitlen)
{
    return bitlen / (sizeof(T) * 8) + ((bitlen % (sizeof(T) * 8) > 0) ? 1 : 0);
}

class BitStr {
    using WordT = uint8_t;
    static constexpr auto bits_per_word = sizeof(WordT) * 8;

public:
    BitStr(BigInt& i)
        : BitStr(i, i.zero == i ? 0 : i.bitsize())
    {
        std::cout << "BitStr(BigInt& i:" << i << " ) i.bitsize(): " << i.bitsize() << " debug: " << debug_description() << std::endl;
    }
    BitStr(std::span<WordT>&& span)
        : BitStr(std::move(span), span.size() * bits_per_word)
    {
    }
    BitStr(BigInt&& i)
        : BitStr(i)
    {
    }
    BitStr(BigInt&& i, size_t bitlen)
        : BitStr(i, bitlen)
    {
    }
    BitStr(BigInt& i, size_t bitlen);
    BitStr(BitStr& other);
    BitStr(BitStr&& other)
        : m_bitlen(other.m_bitlen)
    {
        m_data = other.m_data;
        other.m_data = std::span<WordT>((WordT*)nullptr, 0);
    }

    ~BitStr()
    {
        free_data();
    }

    BitStr& truncate_left(size_t new_length);
    BitStr truncated_right(size_t new_length) const;
    BitStr& operator=(BitStr&& other);
    BitStr operator+(BitStr const& other) const;
    BitStr operator^(BitStr const& other) const;

    size_t bitlength() const
    {
        return m_bitlen;
    }

    size_t internal_bitlength() const
    {
        return std::min(m_bitlen, m_data.size() * bits_per_word);
    }

    uint8_t* internal_byte_array()
    {
        return m_data.data();
    }

    std::string debug_description() const;
    std::string as_bin_string() const;
    std::string as_hex_string() const;
    BigInt as_big_int() const;
    std::span<uint8_t> to_baked_array() const;
private:
    BitStr(std::span<WordT>&& span, size_t bitlen)
        : m_data(span)
        , m_bitlen(bitlen)
    {
        std::cout << "BitStr(span&&, size_t) constructor: " << debug_description() << std::endl;
    }

    void free_data();
    std::span<WordT> m_data;
    size_t m_bitlen;
};
