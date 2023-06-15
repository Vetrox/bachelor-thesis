#include "input.h"
#include "jacobi_elliptic_curve.h"

Input setup_input()
{
    return {
    .server_random = {},
    .client_random = {},
    .dh_generator = 0,
    .dh_prime = 0,
    .dh_bitlen_of_a = 0,
    .dh_pubkey_server = 0,
    .dh_pubkey_client = 0,
    .dec_security_strength = 128,
    .dec_curve = JacobiEllipticCurve(0,0),
    .dec_secret_d = 0
};
}
