#include "mbedtls/entropy.h"
#include <cstddef>
#include <cstring>
#include <memory>
#include <optional>
#include <dualec.h>

static std::optional<WorkingState> working_state;

void init_working_state(mbedtls_entropy_context& entropy) {
    auto* buf = entropy.accumulator.buffer;
    auto buf_len = entropy.accumulator.total[0];
    auto* buf_copy = new uint8_t[buf_len];
    memcpy(buf_copy, buf, buf_len);
    // BitStr(std::unique_ptr<B[]>&& data_begin, size_t data_len)
    working_state.emplace(Dual_EC_DRBG_Instantiate(BitStr(std::unique_ptr<uint8_t[]>(buf_copy), buf_len), BitStr(0), BitStr(151412), 128));
}

int my_generate(void *p_rng, unsigned char *output, size_t output_len, const unsigned char *additional, size_t add_len)
{
    (void) p_rng;
    (void) additional;
    (void) add_len;

    if (!working_state.has_value()) {
        std::cout << "WORKING STATE NOT INITIALIZED" << std::endl;
        abort();
    }
    memset(output, 0x1a, output_len);
    return 0;
}
