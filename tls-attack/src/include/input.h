#pragma once
#include "commons.h"
#include "dualec.h"
#include "dualec_curve.h"
#include "forward.h"

struct Input {
    barr server_random;
    barr client_random;
    BigInt dh_generator;
    BigInt dh_prime;
    BigInt dh_bitlen_of_a;
    BigInt dh_pubkey_server;
    BigInt dh_pubkey_client;
    uint8_t dec_security_strength;
    DEC::Curve dec_curve;
    BigInt dec_secret_d;
};

Input setup_input();