#include "bitstr.h"
#include "forward.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <gmp.h>
#include <memory>
#include <ostream>

[[nodiscard]] std::span<BitStr::B> BitStr::to_baked_array() const
{
    size_t new_byte_len = containerlen_for_bitlength<B>(bitlength());
    auto* box = new uint8_t[new_byte_len];
    auto* start_pos = box + new_byte_len - containerlen_for_bitlength<B>(internal_bitlength());
    size_t diff = box - start_pos;
    if (diff != 0)
        std::memset(box, 0, diff);
    std::copy(data_end() - containerlen_for_bitlength<B>(internal_bitlength()), data_end(), start_pos);
    auto s = std::span<uint8_t>(box, new_byte_len);
    DBG << "to_baked_array(this: " << debug_description() << "): "
        << "data[" << new_byte_len << "]=" << bytes_as_hex(s) << std::endl;
    return s;
}

[[nodiscard]] BitStr BitStr::truncated_right(size_t new_length) const
{
    if (new_length > m_bitlen) {
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
    size_t shift_amount_total = bitlength() - new_length;
    size_t shift_amount_words = shift_amount_total / bits_per_word;
    size_t shift_amount = shift_amount_total % bits_per_word;
    size_t new_wordt_length = containerlen_for_bitlength<B>(internal_bitlength()) - shift_amount_words;
    auto* box = new B[new_wordt_length];
    auto* it = box;
    for (auto dit = m_data_begin.get(), prev_dit = dit; dit != data_end(); ++it, ++dit) {
        *it = static_cast<B>(0);
        if (dit != m_data_begin.get())
            *it |= (*prev_dit) << (bits_per_word - shift_amount);
        *it |= (*dit) >> shift_amount;
        prev_dit = dit;
    }
    return BitStr(std::unique_ptr<B>(box), new_wordt_length, new_length);
}

[[nodiscard]] BigInt BitStr::as_big_int() const
{
    mpz_t z;
    mpz_init(z);
    mpz_import(z, m_data_len, 1, sizeof(B), -1, 0, m_data_begin.get());
    return reinterpret_cast<BigInt&>(z);
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
        if (dit1 != data_end()) {
            *it ^= *dit1;
            ++dit1;
        }
        if (dit2 != other.data_end()) {
            *it ^= *dit2;
            ++dit2;
        }
    }
    return BitStr(std::unique_ptr<B>(box), new_wordt_length, new_bitlen);
}

[[nodiscard]] BitStr BitStr::truncated_left(size_t new_length) const
{
    DBG << "truncated_left(" << std::to_string(new_length) << ")" << std::endl;
    if (new_length > m_bitlen) {
        std::cout << "Wrong usage of truncate" << std::endl;
        abort();
    }

    size_t new_data_len = containerlen_for_bitlength<B>(new_length);
    size_t bits_in_msb = new_length % bits_per_word;
    auto* box = new B[new_data_len];
    auto* trim_begin = data_end() - new_data_len;
    std::memset(box, 0, new_data_len);
    std::copy(trim_begin, data_end(), box);
    // zero out the trimmed bits in msb
    *box &= (0xff >> bits_in_msb);
    return BitStr(std::unique_ptr<B>(box), new_data_len, new_length);
}

void BitStr::invalidate()
{
    m_data_begin.reset();
    m_bitlen = 0;
    m_data_len = 0;
}

BitStr& BitStr::operator=(BitStr&& other)
{
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
    auto* box_rhs_internal_begin = box_end - other.m_data_len;
    std::copy(other.m_data_begin.get(), other.data_end(), box_rhs_internal_begin);

    size_t no_zero_byte_plus1 = containerlen_for_bitlength<B>(other.bitlength() - other.internal_bitlength());
    auto* begin_other_zero_words = box_rhs_internal_begin - no_zero_byte_plus1;
    std::memset(begin_other_zero_words, 0, no_zero_byte_plus1);

    size_t rhs_bits = other.bitlength() % bits_per_word;
    auto* out_it = box;
    for (auto it = m_data_begin.get(); it != data_end(); ++it) {
        *out_it |= (*it >> (bits_per_word - rhs_bits));
        ++out_it;
        *out_it |= (*it << rhs_bits);
    }
    return BitStr(std::unique_ptr<B>(box), new_data_len, bitlength() + other.bitlength());
}

[[nodiscard]] std::string BitStr::as_hex_string() const
{
    std::stringstream ss;
    for (auto* it = m_data_begin.get(); it != data_end(); ++it)
        ss << std::hex << std::setw(2) << std::setfill('0') << +(*it);
    return ss.str();
}

[[nodiscard]] std::string BitStr::as_bin_string() const
{
    std::string ret = "";
    for (auto* it = m_data_begin.get(); it != data_end(); ++it)
        ret += std::bitset<bits_per_word>(*it).to_string();
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
    : m_bitlen(bitlen)
{
    size_t word_count = 0;
    auto* data = static_cast<B*>(mpz_export(nullptr, &word_count,
        1 /* most significant word first */,
        sizeof(B),
        -1 /* least significant byte first */,
        0 /* makes the first 0 bits of each word 0ed */,
        i.get_mpz_const()));
    m_data_begin = std::unique_ptr<B>(data);
    m_data_len = word_count;
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
    m_data_begin = std::unique_ptr<B>(new B[m_data_len]);
    std::copy(other.m_data_begin.get(), other.data_end(), m_data_begin.get());
    DBG << "BitStr(BitStr&) copy-constructor: " << debug_description() << std::endl;
}
