#include "mbedtls/entropy.h"
#include <cstddef>
#include <cstring>
#include <memory>
#include <optional>
#include <dualec.h>

static std::optional<WorkingState> working_state;

void init_working_state(mbedtls_entropy_context& entropy, std::string personalization_string) {
    auto* buf = entropy.accumulator.buffer;
    auto buf_len = entropy.accumulator.total[0];
    auto* buf_copy = new uint8_t[buf_len];
    memcpy(buf_copy, buf, buf_len);

    auto pers_copy_len = personalization_string.length();
    auto* pers_copy = new uint8_t[pers_copy_len];
    std::copy(personalization_string.begin(), personalization_string.end(), pers_copy);
    working_state.emplace(Dual_EC_DRBG_Instantiate(BitStr(std::unique_ptr<uint8_t[]>(buf_copy), buf_len), BitStr(0),
                BitStr(std::unique_ptr<uint8_t[]>(pers_copy), pers_copy_len), 128));
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
