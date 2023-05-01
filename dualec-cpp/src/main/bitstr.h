#pragma once

#include "forward.h"
#include <bitset>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <memory>
#include <span>
#include <sstream>
#include <string>

template<typename T>
static size_t containerlen_for_bitlength(size_t bitlen)
{
    return bitlen / (sizeof(T) * 8) + ((bitlen % (sizeof(T) * 8) > 0) ? 1 : 0);
}

class BitStr {
    using B = uint8_t;
    static constexpr auto bits_per_word = sizeof(B) * 8;

public:
    BitStr(BigInt const& i)
        : BitStr(i, i.zero == i ? 0 : i.bitsize())
    {
    }
    BitStr(std::unique_ptr<B[]>&& data_begin, size_t data_len)
        : BitStr(std::move(data_begin), data_len, data_len * bits_per_word)
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
    BitStr(BigInt const& i, size_t bitlen);
    BitStr(BitStr const& other);
    BitStr(BitStr&& other)
        : m_data_begin(std::move(other.m_data_begin))
        , m_data_len(other.m_data_len)
        , m_bitlen(other.m_bitlen)
    {
        DBG << "BitStr(BitStr&&): " << debug_description() << std::endl;
        other.invalidate();
    }

    ~BitStr()
    {
        DBG << "~" << debug_description() << std::endl;
    }

    [[nodiscard]] BitStr truncated_left(size_t new_length) const;
    [[nodiscard]] BitStr truncated_right(size_t new_length) const;
    BitStr& operator=(BitStr&& other);
    [[nodiscard]] BitStr operator+(BitStr const& other) const;
    [[nodiscard]] BitStr operator^(BitStr const& other) const;

    [[nodiscard]] size_t bitlength() const
    {
        return m_bitlen;
    }

    [[nodiscard]] size_t internal_bitlength() const
    {
        return std::min(m_bitlen, m_data_len * bits_per_word);
    }

    [[nodiscard]] std::string debug_description() const;
    [[nodiscard]] std::string as_bin_string() const;
    [[nodiscard]] std::string as_hex_string() const;
    [[nodiscard]] BigInt as_big_int() const;
    [[nodiscard]] std::span<uint8_t> to_baked_array() const;

private:
    BitStr(std::unique_ptr<B[]>&& data_begin, size_t data_len, size_t bitlen)
        : m_data_begin(std::move(data_begin))
        , m_data_len(data_len)
        , m_bitlen(bitlen)
    {
        DBG << "BitStr(unique_ptr&, size_t, size_t): " << debug_description() << ")" << std::endl;
    }

    void invalidate();
    [[nodiscard]] B* data_end() const;

    std::unique_ptr<B[]> m_data_begin;
    size_t m_data_len { 0 };
    size_t m_bitlen { 0 };
};
