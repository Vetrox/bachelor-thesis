#include "bitstr.h"
#include "forward.h"
#include <algorithm>
#include <cstdint>
#include <gmp.h>
#include <ostream>

BitStr BitStr::truncated_right(size_t new_length) const
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
    size_t new_wordt_length = containerlen_for_bitlength<WordT>(internal_bitlength()) - shift_amount_words;
    auto* box = new WordT[new_wordt_length];
    auto* it = box;
    for (auto dit = m_data.begin(), prev_dit = dit; dit != m_data.end(); ++it, ++dit) {
        *it = (WordT)0;
        if (dit != m_data.begin())
            *it |= (*prev_dit) << (bits_per_word - shift_amount);
        *it |= (*dit) >> shift_amount;
        prev_dit = dit;
    }
    return BitStr(std::span<WordT>(box, new_wordt_length), new_length);
}

BigInt BitStr::as_big_int() const
{
    mpz_t z;
    mpz_init(z);
    mpz_import(z, m_data.size(), 1, sizeof(WordT), -1, 0, m_data.data());
    return reinterpret_cast<BigInt&>(z);
}

void BitStr::truncate_left(size_t new_length)
BitStr& BitStr::truncate_left(size_t new_length)
{
    if (new_length > m_bitlen) {
        std::cout << "Wrong usage of truncate" << std::endl;
        abort();
    }
    std::cout << "truncate_left(" << std::to_string(new_length) << ")" << std::endl;
    m_bitlen = new_length;
    return *this;
}

BitStr& BitStr::operator=(BitStr&& other)
{
    std::cout << "BitStr::operator=(this: " << debug_description() << " other: " << other.debug_description() << ")" << std::endl;
    free_data();
    m_data = other.m_data;
    m_bitlen = other.m_bitlen;
    other.m_data = std::span<WordT>((WordT*)nullptr, 0);
    return *this;
}

BitStr BitStr::operator+(BitStr const& other) const
{
    std::cout << "BitStr::operator+(this: " << debug_description() << " other: " << other.debug_description() << ")" << std::endl;
    // allocate enough to hold this->m_data.bitlength() + other.bitlength()
    size_t new_wordt_length = containerlen_for_bitlength<WordT>(internal_bitlength() + other.bitlength());
    // std::cout << "new_wordt_length = " << new_wordt_length << std::endl;
    // std::cout << "Internal + other_bitlen = " << (internal_bitlength() + other.bitlength()) << std::endl;
    auto* box = (uint8_t*)new WordT[new_wordt_length];
    // std::cout << "sizeof(WordT) = " << sizeof(WordT) << std::endl;
    auto* box_end = box + new_wordt_length * sizeof(WordT);
    // std::cout << "Box_end - box = " << (box_end - box) << std::endl;
    memset(box, 0, new_wordt_length * sizeof(WordT));

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

    auto* begin_other_internal = box_end - other.m_data.size_bytes();
    // std::cout << "Begin_other_internal - box = " << ((box_end - other.m_data.size_bytes()) - box) << std::endl;
    std::copy(other.m_data.begin(), other.m_data.end(), begin_other_internal);

    size_t zero_wordt_amount = (other.bitlength() - other.internal_bitlength()) / bits_per_word;
    auto* begin_other_zero_words = begin_other_internal - zero_wordt_amount * sizeof(WordT);
    std::memset(begin_other_zero_words, 0, zero_wordt_amount * sizeof(WordT));

    size_t shift = other.bitlength() % bits_per_word;
    auto* current_begin = begin_other_zero_words - sizeof(WordT);
    *current_begin = 0; // set p-bits
    for (auto it = m_data.rbegin(); it != m_data.rend(); ++it) {
        // std::cout << "Delta begin = " << (current_begin - box) << std::endl;
        *current_begin |= (*it << shift);
        current_begin -= sizeof(WordT);
        *current_begin |= (*it >> (bits_per_word - shift));
    }
    std::span<WordT> span((WordT*)box, new_wordt_length);
    return BitStr(std::move(span), bitlength() + other.bitlength());
}

std::string BitStr::as_hex_string() const
{
    std::stringstream ss;
    for (auto const& word : m_data)
        ss << std::hex << std::setw(sizeof(WordT) * 2) << std::setfill('0') << +word;
    return ss.str();
}
std::string BitStr::as_bin_string() const
{
    std::string ret = "";
    for (auto const& word : m_data)
        ret += std::bitset<bits_per_word>(word).to_string();
    return ret;
}

std::string BitStr::debug_description() const
{
    return "BitStr(m_bitlen: "
        + std::to_string(m_bitlen)
        + " data[" + std::to_string(m_data.size_bytes()) + "]: "
        + as_hex_string()
        + ")";
}

void BitStr::free_data()
{
    if (m_data.data() != nullptr) {
        std::cout << "freeing " << debug_description() << std::endl;
        delete[] m_data.data();
    } else {
        std::cout << "ignoring free of " << debug_description() << std::endl;
    }
}

BitStr::BitStr(BigInt& i, size_t bitlen)
    : m_bitlen(bitlen)
{
    auto* mpz_ptr = i.get_mpz();
    size_t word_count = 0;
    auto* data = (WordT*)mpz_export(nullptr, &word_count,
        1 /* most significant word first */,
        sizeof(WordT),
        -1 /* 1 = most significant byte first */,
        0 /* makes the first 0 bits of each word 0ed */,
        mpz_ptr);
    m_data = std::span<WordT>(data, word_count);
    std::cout << "BitStr(BigInt&,size_t) constructor: " << debug_description() << std::endl;
}

BitStr::BitStr(BitStr& other)
    : m_bitlen(other.m_bitlen)
{
    size_t amount_of_words = other.m_data.size_bytes() / sizeof(WordT);
    WordT* box = new WordT[amount_of_words];
    std::copy(other.m_data.begin(), other.m_data.end(), box);
    m_data = std::span<WordT>((WordT*)box, amount_of_words);
    std::cout << "BitStr(BitStr&) copy-constructor: " << debug_description() << std::endl;
}
