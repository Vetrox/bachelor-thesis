#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <iostream>

static constexpr auto TSCFREQ_FACTOR = 1;


static inline uint64_t read_time_stamp_ctr()
{
    uint32_t __a, __d;
    __asm__ __volatile__("rdtsc"
                         : "=a"(__a), "=d"(__d));
    return static_cast<uint64_t>(__a) | (static_cast<uint64_t>(__d) << 32ULL);
}

static inline double measure(auto func)
{
    static uint64_t start_clk, end_clk;
    start_clk = read_time_stamp_ctr();
    func();
    end_clk = read_time_stamp_ctr();
    return end_clk - start_clk;
}

static inline void time_it(auto name, auto func, auto nbytes)
{
    std::cout << "Testing: " << name << " ";
    decltype(auto) total_clk = measure(func);
    std::cout << TSCFREQ_FACTOR * total_clk / nbytes << " cycles-per-byte" << std::endl;
}

// 32 tables of 8->32 bits, using 31 xors to combine
static __m256i TT[32][256];

static __m256i ttables(__m256i in)
{
    uint8_t in8[32];
    _mm256_storeu_si256((__m256i*)in8, in);
    __m256i out = TT[0][in8[0]];

    out ^= TT[1][in8[1]];
    out ^= TT[2][in8[2]];
    out ^= TT[3][in8[3]];
    out ^= TT[4][in8[4]];
    out ^= TT[5][in8[5]];
    out ^= TT[6][in8[6]];
    out ^= TT[7][in8[7]];
    out ^= TT[8][in8[8]];
    out ^= TT[9][in8[9]];
    out ^= TT[10][in8[10]];
    out ^= TT[11][in8[11]];
    out ^= TT[12][in8[12]];
    out ^= TT[13][in8[13]];
    out ^= TT[14][in8[14]];
    out ^= TT[15][in8[15]];
    out ^= TT[16][in8[16]];
    out ^= TT[17][in8[17]];
    out ^= TT[18][in8[18]];
    out ^= TT[19][in8[19]];
    out ^= TT[20][in8[20]];
    out ^= TT[21][in8[21]];
    out ^= TT[22][in8[22]];
    out ^= TT[23][in8[23]];
    out ^= TT[24][in8[24]];
    out ^= TT[25][in8[25]];
    out ^= TT[26][in8[26]];
    out ^= TT[27][in8[27]];
    out ^= TT[28][in8[28]];
    out ^= TT[29][in8[29]];
    out ^= TT[30][in8[30]];
    out ^= TT[31][in8[31]];
    return out;
}

// hadamard approach:
// 1 table of 8->32 bytes, using 31 byte perm + xors to combine
static __m256i HT[256];
static __m256i HCOL[32];

static __m256i hadtables(__m256i in)
{
    uint8_t in8[32];
    _mm256_storeu_si256((__m256i*)in8, in);

    __m256i out = _mm256_shuffle_epi8(HT[in8[0]], HCOL[0]);

    out ^= _mm256_shuffle_epi8(HT[in8[1]], HCOL[1]);
    out ^= _mm256_shuffle_epi8(HT[in8[2]], HCOL[2]);
    out ^= _mm256_shuffle_epi8(HT[in8[3]], HCOL[3]);
    out ^= _mm256_shuffle_epi8(HT[in8[4]], HCOL[4]);
    out ^= _mm256_shuffle_epi8(HT[in8[5]], HCOL[5]);
    out ^= _mm256_shuffle_epi8(HT[in8[6]], HCOL[6]);
    out ^= _mm256_shuffle_epi8(HT[in8[7]], HCOL[7]);
    out ^= _mm256_shuffle_epi8(HT[in8[8]], HCOL[8]);
    out ^= _mm256_shuffle_epi8(HT[in8[9]], HCOL[9]);
    out ^= _mm256_shuffle_epi8(HT[in8[10]], HCOL[10]);
    out ^= _mm256_shuffle_epi8(HT[in8[11]], HCOL[11]);
    out ^= _mm256_shuffle_epi8(HT[in8[12]], HCOL[12]);
    out ^= _mm256_shuffle_epi8(HT[in8[13]], HCOL[13]);
    out ^= _mm256_shuffle_epi8(HT[in8[14]], HCOL[14]);
    out ^= _mm256_shuffle_epi8(HT[in8[15]], HCOL[15]);
    out ^= _mm256_shuffle_epi8(HT[in8[16]], HCOL[16]);
    out ^= _mm256_shuffle_epi8(HT[in8[17]], HCOL[17]);
    out ^= _mm256_shuffle_epi8(HT[in8[18]], HCOL[18]);
    out ^= _mm256_shuffle_epi8(HT[in8[19]], HCOL[19]);
    out ^= _mm256_shuffle_epi8(HT[in8[20]], HCOL[20]);
    out ^= _mm256_shuffle_epi8(HT[in8[21]], HCOL[21]);
    out ^= _mm256_shuffle_epi8(HT[in8[22]], HCOL[22]);
    out ^= _mm256_shuffle_epi8(HT[in8[23]], HCOL[23]);
    out ^= _mm256_shuffle_epi8(HT[in8[24]], HCOL[24]);
    out ^= _mm256_shuffle_epi8(HT[in8[25]], HCOL[25]);
    out ^= _mm256_shuffle_epi8(HT[in8[26]], HCOL[26]);
    out ^= _mm256_shuffle_epi8(HT[in8[27]], HCOL[27]);
    out ^= _mm256_shuffle_epi8(HT[in8[28]], HCOL[28]);
    out ^= _mm256_shuffle_epi8(HT[in8[29]], HCOL[29]);
    out ^= _mm256_shuffle_epi8(HT[in8[30]], HCOL[30]);
    out ^= _mm256_shuffle_epi8(HT[in8[31]], HCOL[31]);
    return out;
}

static __m256i rand256(void)
{
    return _mm256_set_epi32(
        rand(),
        rand(),
        rand(),
        rand(),
        rand(),
        rand(),
        rand(),
        rand());
}

int main(void)
{
    srand(time(NULL));
    __m256i in = rand256();

    for (int i_ = 0; i_ < 32; i_++) {
        for (int j = 0; j < 256; j++) {
            TT[i_][j] = rand256();
        }
    }
    for (int j = 0; j < 256; j++) {
        HT[j] = rand256();
    }

    for (int i_ = 0; i_ < 32; i_++) {
        HCOL[i_] = _mm256_set_epi8(0 ^ i_, 1 ^ i_, 2 ^ i_, 3 ^ i_, 4 ^ i_, 5 ^ i_, 6 ^ i_, 7 ^ i_,
            8 ^ i_, 9 ^ i_, 10 ^ i_, 11 ^ i_, 12 ^ i_, 13 ^ i_, 14 ^ i_, 15 ^ i_,
            16 ^ i_, 17 ^ i_, 18 ^ i_, 19 ^ i_, 20 ^ i_, 21 ^ i_, 22 ^ i_, 23 ^ i_,
            24 ^ i_, 25 ^ i_, 26 ^ i_, 27 ^ i_, 28 ^ i_, 29 ^ i_, 30 ^ i_, 31 ^ i_);
    }

    time_it("ttables", [&]() {in = ttables(in);}, 32);
    time_it("htables", [&]() {in = hadtables(in);}, 32);

    return in[0] ^ in[1] ^ in[2] ^ in[3];
}
