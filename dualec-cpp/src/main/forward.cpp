#include "forward.h"

std::string bigint_hex(BigInt const& i) {
    char* hex_str;
    gmp_asprintf(&hex_str, "%#Zx", i.get_mpz_const());
    return hex_str;
}
