#include "mbedtls/entropy.h"
#include <cstddef>
#include <cstring>
#include <memory>
#include <optional>
#include <dualec.h>

static std::optional<WorkingState> working_state;

void init_working_state(mbedtls_entropy_context& entropy, std::string personalization_string) {
    auto* buf = entropy.accumulator.buffer; // if not initialized, let it segfault bc our application relies on it
    auto buf_len = entropy.accumulator.total[0]; // same here
    auto* buf_copy = new uint8_t[buf_len];
    memcpy(buf_copy, buf, buf_len);

    auto pers_copy_len = personalization_string.length();
    auto* pers_copy = new uint8_t[pers_copy_len];
    std::copy(personalization_string.begin(), personalization_string.end(), pers_copy);
    working_state.emplace(Dual_EC_DRBG_Instantiate(
                BitStr(std::unique_ptr<uint8_t[]>(buf_copy), buf_len), /* entropy input */
                BitStr(0), /* nonce wasn't used very much, even mbedtls doesn't use nonces internally */
                BitStr(std::unique_ptr<uint8_t[]>(pers_copy), pers_copy_len),
                128) /* security strength. 128, 192, 256 */
            );
}

int my_generate(void *p_rng, unsigned char *output, size_t output_len, const unsigned char *additional, size_t add_len)
{
    (void) p_rng;

    if (!working_state.has_value()) {
        std::cout << "WORKING STATE NOT INITIALIZED" << std::endl;
        abort();
    }

    auto* buf = new uint8_t[add_len];
    memcpy(buf, additional, add_len);
    auto rt = Dual_EC_DRBG_Generate(working_state.value(),
            output_len*8,
            BitStr(std::unique_ptr<uint8_t[]>(buf), add_len));
    auto baked_rt = rt.to_baked_array();
    if (baked_rt.size() != output_len) {
        std::cout << "FATAL ERROR: Baked array was not the requested size" << std::endl;
    }
    std::copy(baked_rt.begin(), baked_rt.end(), output);
    return 0;
}
