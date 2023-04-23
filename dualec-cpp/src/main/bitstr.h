#pragma once

#include "forward.h"
#include <cstring>
#include <span>
#include <bitset>
#include <sstream>
#include <iomanip>

template<typename WordT = size_t>
class BitStr {
    static constexpr auto bits_per_word = sizeof(WordT) * 8;
public:
    BitStr(BigInt& i, size_t bitlen)
    : m_bitlen(bitlen) {
        size_t amount_of_words_for_bitlen = containerlen_for_bitlength<WordT>(bitlen);
        auto* mpz_ptr = i.get_mpz();
        size_t word_count = 0;
        auto* data = (WordT*) mpz_export(nullptr, &word_count,
                1 /* most significant word first */,
                sizeof(WordT),
                -1 /* 1 = most significant byte first */,
                0 /* makes the first 0 bits of each word 0ed */,
                mpz_ptr);
        std::cout << "Data-len = " << word_count << " bitlen = " << bitlen << " word-len = " << amount_of_words_for_bitlen << std::endl;
        m_data = std::span<WordT>(data, word_count);
    }
    BitStr(BitStr<WordT>& other)
    : m_bitlen(other.m_bitlen) {
        size_t amount_of_words = other.m_data.size_bytes() / sizeof(WordT);
        WordT* box = new WordT[amount_of_words];
        std::cout << "Copying. Amount of words: " << amount_of_words << std::endl;
        std::copy(other.m_data.begin(), other.m_data.end(), box);
        m_data = std::span<WordT>((WordT*) box, amount_of_words);
        std::cout << "Copied" << std::endl;
    }

    ~BitStr() {
        std::cout << "DESTRUCTION" << std::endl;
        delete[] m_data.data();
    }

    template<typename T>
    static size_t containerlen_for_bitlength(size_t bitlen) {
        return bitlen / (sizeof(T) * 8) + ((bitlen % (sizeof(T) * 8) > 0) ? 1 : 0);
    }

    BitStr<WordT> operator+(BitStr<WordT> const& other) const {
        // TODO: handle bitshifts
        size_t virtual_other_bytes = (other.bitlength() - other.internal_bitlength()) / bits_per_word;
        std::cout << "Virtual other bytes " << virtual_other_bytes << std::endl;
        // allocate enough to hold this->m_data.bitlength() other.bitlength()
        size_t new_wordt_length = containerlen_for_bitlength<WordT>(internal_bitlength() + other.bitlength());
        auto* box = new WordT[new_wordt_length];
        auto end = std::copy(m_data.begin(), m_data.end(), box);
        std::memset(end, 'A', virtual_other_bytes);
        // std::copy(other.m_data.begin(), other.m_data.end(), (end + virtual_other_bytes));
        std::span<WordT> span((WordT*) box, new_wordt_length);
        return BitStr<WordT>(std::move(span), bitlength() + other.bitlength());
    }


    size_t bitlength() const {
        return m_bitlen;
    }

    size_t internal_bitlength() const {
        return m_data.size() * bits_per_word;
    }

    std::string as_bin_string() const {
        std::string ret = "";
        for (auto const& word : m_data)
            ret += std::bitset<bits_per_word>(word).to_string();
        return ret;
    }

    std::string as_hex_string() const {
        std::stringstream ss;
        for (auto const& word : m_data)
            ss << std::hex << std::setw(sizeof(WordT) * 2) << std::setfill('0') << +word;
        return ss.str();
    }
private:
    BitStr(std::span<WordT>&& span, size_t bitlen)
        : m_data(span),
        m_bitlen(bitlen) {}
    std::span<WordT> m_data;
    size_t m_bitlen;
};
