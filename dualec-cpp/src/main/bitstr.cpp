#include "bitstr.h"
#include "forward.h"
#include <algorithm>
#include <bitset>
#include <cstdint>
#include <cstring>
#include <gmp.h>
#include <gmpxx.h>
#include <memory>
#include <ostream>

[[nodiscard]] MArray<BitStr::B> BitStr::to_baked_array() const
{
    size_t new_byte_len = containerlen_for_bitlength<B>(bitlength());
    auto* box = new uint8_t[new_byte_len];
    auto* start_pos = box + new_byte_len - containerlen_for_bitlength<B>(internal_bitlength());
    size_t diff = box - start_pos;
    if (diff != 0)
        std::memset(box, 0, diff);
    std::copy(data_end() - containerlen_for_bitlength<B>(internal_bitlength()), data_end(), start_pos);
    MArray<uint8_t> s = std::span<uint8_t>(box, new_byte_len);
    DBG << "to_baked_array(this: " << debug_description() << "): "
        << "data[" << new_byte_len << "]=" << bytes_as_hex(s) << std::endl;
    return s;
}

[[nodiscard]] BitStr BitStr::truncated_leftmost(size_t new_length) const
{
    DBG << "BitStr::truncated_leftmost(this: " << debug_description() << " new_length: " << new_length << std::endl;
    if (new_length > bitlength()) {
        std::cout << "Wrong usage of truncate" << std::endl;
        abort();
    }
    /*                            cut
     *                              |
     *  |000p|oooo|oooo|00--|----|----|
     *      ^bitlen     ^internal_bitlen
     * new:
     *       |pooo|oooo|000-|----|----|
     */
    size_t bitshift_total = bitlength() - new_length;
    if (internal_bitlength() <= bitshift_total)
        return BitStr(std::unique_ptr<B[]>(), 0, new_length);
    size_t new_internal_bitlen = internal_bitlength() - bitshift_total;
    size_t new_byte_len = containerlen_for_bitlength<B>(new_internal_bitlen);
    size_t bitshift_inner = bitshift_total % bits_per_word;
    auto* box = new B[new_byte_len];
    auto* box_end = box + new_byte_len;

    auto dit = m_data_begin.get();
    for (auto it = box; it != box_end; ++dit) {
        *it = static_cast<B>(0);
        *it |= (*dit) >> bitshift_inner;
        ++it;
        if (it != box && bitshift_inner != 0 && it != box_end)
            *it |= (*dit) << (bits_per_word - bitshift_inner);
    }
    return BitStr(std::unique_ptr<B[]>(box), new_byte_len, new_length);
}

[[nodiscard]] BigInt BitStr::as_big_int() const
{
    if (m_data_begin.get() == nullptr)
        return BigInt(0);
    mpz_t z;
    mpz_init(z);
    mpz_import(z, m_data_len, 1, sizeof(B), -1, 0, m_data_begin.get());
    auto i = BigInt(mpz_class(z));
    mpz_clear(z);
    return i;
}

[[nodiscard]] BitStr BitStr::operator^(BitStr const& other) const
{
    DBG << "BitStr::operator^(this: " << debug_description() << " other: " << other.debug_description() << ")" << std::endl;
    size_t new_bitlen = std::max(bitlength(), other.bitlength());
    size_t new_wordt_length = containerlen_for_bitlength<B>(new_bitlen);
    auto box = new B[new_wordt_length];
    auto box_end = box + new_wordt_length;

    auto dit1 = m_data_begin.get(), dit2 = other.m_data_begin.get();
    for (auto it = box; it != box_end; ++it) {
        *it = static_cast<B>(0);
        if (dit1 && dit1 != data_end()) {
            *it ^= *dit1;
            ++dit1;
        }
        if (dit2 && dit2 != other.data_end()) {
            *it ^= *dit2;
            ++dit2;
        }
    }
    return BitStr(std::unique_ptr<B[]>(box), new_wordt_length, new_bitlen);
}

[[nodiscard]] BitStr BitStr::truncated_rightmost(size_t new_length) const
{
    DBG << "truncated_rightmost(" << std::to_string(new_length) << ")" << std::endl;
    if (new_length > m_bitlen) {
        std::cout << "Wrong usage of truncate" << std::endl;
        abort();
    }
    if (new_length == 0 || m_bitlen == 0 || m_data_len == 0 || m_data_begin.get() == nullptr)
        return BitStr(std::unique_ptr<B[]>(), 0, 0);

    size_t new_data_len = containerlen_for_bitlength<B>(new_length);
    size_t bits_in_msb = new_length % bits_per_word;
    auto* box = new B[new_data_len];
    auto* trim_begin = data_end() - new_data_len;
    std::memset(box, 0, new_data_len);
    std::copy(trim_begin, data_end(), box);
    // zero out the trimmed bits in msb
    if (bits_in_msb > 0)
        *box &= 0xff >> (bits_per_word - bits_in_msb);
    return BitStr(std::unique_ptr<B[]>(box), new_data_len, new_length);
}

void BitStr::invalidate()
{
    m_data_begin.reset();
    m_bitlen = 0;
    m_data_len = 0;
}

BitStr& BitStr::operator=(BitStr&& other)
{
    DBG << "BitStr::operator=(this: " << debug_description() << " other: " << other.debug_description() << ")" << std::endl;
    m_data_begin = std::move(other.m_data_begin);
    m_data_len = other.m_data_len;
    m_bitlen = other.m_bitlen;
    other.invalidate();
    return *this;
}

[[nodiscard]] BitStr BitStr::operator+(BitStr const& other) const
{
    DBG << "BitStr::operator+(this: " << debug_description() << " other: " << other.debug_description() << ")" << std::endl;
    size_t new_data_len = containerlen_for_bitlength<B>(internal_bitlength() + other.bitlength());
    auto* box = new B[new_data_len];
    auto* box_end = box + new_data_len;
    memset(box, 0, new_data_len);

    /*                                |
     *  |000p|oooo|oooo|00--|----|----|
     *      ^bitlen1    ^internal_bitlen1
     *                                |                  box_end
     *                                ||#zero_wt |              |
     *                            |000p|oooo|oooo|00--|----|----|
     *                                ^bitlen2    ^internal_bitlen2
     * new:
     *                    ---|----|---p|oooo|oooo|00--|----|----|
     */
    auto* box_rhs_internal_begin = box_end;
    if (other.m_data_begin.get() != nullptr) {
        box_rhs_internal_begin -= other.m_data_len;
        std::copy(other.m_data_begin.get(), other.data_end(), box_rhs_internal_begin);
    }

    if (m_data_begin.get() != nullptr && m_data_len > 0 && m_bitlen > 0) {
        size_t rhs_bits = other.bitlength() % bits_per_word;
        size_t right_shift = (bits_per_word - rhs_bits) % bits_per_word;
        auto* out_it = box;
        for (auto it = m_data_begin.get(); it != data_end(); ++it) {
            *out_it |= (*it) >> right_shift;
            ++out_it;
            if (out_it < box_end && rhs_bits != 0)
                *out_it |= (*it) << rhs_bits;
        }
    }
    return BitStr(std::unique_ptr<B[]>(box), new_data_len, bitlength() + other.bitlength());
}

[[nodiscard]] std::string BitStr::as_hex_string() const
{
    std::stringstream ss;
    if (m_data_begin.get() == nullptr || m_data_len == 0 || m_bitlen == 0)
        ss << "<null>";
    else
        for (auto* it = m_data_begin.get(); it != data_end(); ++it)
            ss << std::hex << std::setw(2) << std::setfill('0') << +(*it);
    return ss.str();
}

std::string bin_from_bitset_of_size(size_t used_bits, uint8_t value)
{
    switch (used_bits) {
    case 0:
        return "";
    case 1:
        return (value & 0b1) ? "1" : "0";
    case 2:
        return std::bitset<2>(value & 0b11).to_string();
    case 3:
        return std::bitset<3>(value & 0b111).to_string();
    case 4:
        return std::bitset<4>(value & 0b1111).to_string();
    case 5:
        return std::bitset<5>(value & 0b1111'1).to_string();
    case 6:
        return std::bitset<6>(value & 0b1111'11).to_string();
    case 7:
        return std::bitset<7>(value & 0b1111'111).to_string();
    case 8:
        return std::bitset<8>(value & 0b1111'1111).to_string();
    default:
        return "WRONG USAGE!";
    }
}

[[nodiscard]] std::string BitStr::as_bin_string() const
{
    std::string ret = "";
    if (m_data_begin.get() == nullptr || m_data_len == 0 || m_bitlen == 0)
        ret += "<null>";
    else {
        ret += "0b";
        size_t add_bits = bitlength() - internal_bitlength();
        for (size_t i = 0; i < add_bits; ++i)
            ret += "0";
        for (auto* it = m_data_begin.get(); it != data_end(); ++it) {
            size_t used_bits = bits_per_word;
            if (it == m_data_begin.get() && m_bitlen % bits_per_word != 0 && add_bits == 0)
                used_bits = m_bitlen % bits_per_word;
            ret += bin_from_bitset_of_size(used_bits, *it);
        }
    }
    return ret;
}

[[nodiscard]] std::string BitStr::debug_description() const
{
    auto diff = static_cast<ssize_t>(bitlength()) - static_cast<ssize_t>(m_data_len * bits_per_word);
    return "BitStr(bitlen: "
        + std::to_string(m_bitlen)
        + " data[" + std::to_string(m_data_len) + " bytes"
        + (diff != 0 ? ((diff > 0 ? "+" : "") + std::to_string(diff) + " bits") : "")
        + "]: "
        + as_hex_string()
        + ")";
}

BitStr::BitStr(BigInt const& i, size_t bitlen)
{
    if (bitlen > 0) {
        auto container_len = containerlen_for_bitlength<B>(i.bitsize());
        if (container_len > 0) {
            auto* data = new B[container_len];
            (void)static_cast<B*>(mpz_export(data, nullptr,
                1 /* most significant word first */,
                sizeof(B),
                -1 /* least significant byte first */,
                0 /* makes the first 0 bits of each word 0ed */,
                i.get_mpz_const()));
            m_bitlen = i.bitsize();
            m_data_begin = std::unique_ptr<B[]>(data);
            m_data_len = container_len;
        }
    }
    if (m_bitlen <= bitlen)
        m_bitlen = bitlen;
    else
        *this = truncated_rightmost(bitlen);
    DBG << "BitStr(BigInt&,size_t) constructor: " << debug_description() << std::endl;
}

[[nodiscard]] BitStr::B* BitStr::data_end() const
{
    return m_data_begin.get() + m_data_len;
}

BitStr::BitStr(BitStr const& other)
    : m_data_len(other.m_data_len)
    , m_bitlen(other.m_bitlen)
{
    if (other.internal_bitlength() > 0 && other.m_data_begin.get() != nullptr) {
        m_data_begin = std::unique_ptr<B[]>(new B[m_data_len]);
        std::copy(other.m_data_begin.get(), other.data_end(), m_data_begin.get());
    }
    DBG << "BitStr(BitStr&) copy-constructor: " << debug_description() << std::endl;
}
