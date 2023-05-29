#include <cstddef>
#include <cstring>
#include <optional>
#include <dualec.h>

static std::optional<WorkingState> working_state;

void init_working_state() {
    working_state.emplace(Dual_EC_DRBG_Instantiate(BitStr(123141), BitStr(0), BitStr(151412), 128));
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
