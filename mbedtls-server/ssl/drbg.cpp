#include <cstddef>
#include <cstring>

int my_generate(void *p_rng, unsigned char *output, size_t output_len, const unsigned char *additional, size_t add_len)
{
    (void) p_rng;
    (void) additional;
    (void) add_len;
    memset(output, 0x1a, output_len);
    return 0;
}
