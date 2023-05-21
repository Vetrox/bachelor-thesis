# Scratchpad
This is a scratchpad so that i can centralize my knowledge.

## GDB MBEDTLS ECDSA rng backtrace
```gdb
#0  my_drbg_random (p_rng=0x7fffffffccb0, output=0x5555556657d0 "", output_len=32) at /repos/bachelor-thesis/mbedtls-server/ssl/ssl_server.c:52
#1  0x000055555559fde8 in mbedtls_mpi_core_fill_random (X=0x5555556657d0, X_limbs=4, n_bytes=32, f_rng=0x55555556e560 <my_drbg_random>, p_rng=0x7fffffffccb0)
    at /repos/bachelor-thesis/mbedtls-server/mbedtls/library/bignum_core.c:567
#2  0x000055555559d342 in mbedtls_mpi_fill_random (X=0x55555565a2e8, size=32, f_rng=0x55555556e560 <my_drbg_random>, p_rng=0x7fffffffccb0)
    at /repos/bachelor-thesis/mbedtls-server/mbedtls/library/bignum.c:2080
#3  0x00005555555ae80f in mbedtls_ecp_gen_privkey_mx (high_bit=254, d=0x55555565a2e8, f_rng=0x55555556e560 <my_drbg_random>, p_rng=0x7fffffffccb0)
    at /repos/bachelor-thesis/mbedtls-server/mbedtls/library/ecp.c:3105
#4  0x00005555555ae969 in mbedtls_ecp_gen_privkey (grp=0x55555565a1f0, d=0x55555565a2e8, f_rng=0x55555556e560 <my_drbg_random>, p_rng=0x7fffffffccb0)
    at /repos/bachelor-thesis/mbedtls-server/mbedtls/library/ecp.c:3149
#5  0x00005555555a91cb in ecdh_gen_public_restartable (grp=0x55555565a1f0, d=0x55555565a2e8, Q=0x55555565a300, f_rng=0x55555556e560 <my_drbg_random>, 
    p_rng=0x7fffffffccb0, rs_ctx=0x0) at /repos/bachelor-thesis/mbedtls-server/mbedtls/library/ecdh.c:80
#6  0x00005555555a9257 in mbedtls_ecdh_gen_public (grp=0x55555565a1f0, d=0x55555565a2e8, Q=0x55555565a300, f_rng=0x55555556e560 <my_drbg_random>, 
    p_rng=0x7fffffffccb0) at /repos/bachelor-thesis/mbedtls-server/mbedtls/library/ecdh.c:97
#7  0x00005555555a9608 in ecdh_make_params_internal (ctx=0x55555565a1f0, olen=0x7fffffffc868, point_format=0, buf=0x555555661491 "", blen=16380, 
    f_rng=0x55555556e560 <my_drbg_random>, p_rng=0x7fffffffccb0, restart_enabled=0) at /repos/bachelor-thesis/mbedtls-server/mbedtls/library/ecdh.c:310
#8  0x00005555555a971a in mbedtls_ecdh_make_params (ctx=0x55555565a1e0, olen=0x7fffffffc868, buf=0x555555661491 "", blen=16380, 
    f_rng=0x55555556e560 <my_drbg_random>, p_rng=0x7fffffffccb0) at /repos/bachelor-thesis/mbedtls-server/mbedtls/library/ecdh.c:363
#9  0x0000555555593c78 in ssl_prepare_server_key_exchange (ssl=0x7fffffffcfa0, signature_len=0x7fffffffc948)
    at /repos/bachelor-thesis/mbedtls-server/mbedtls/library/ssl_tls12_server.c:3010
#10 0x000055555559427e in ssl_write_server_key_exchange (ssl=0x7fffffffcfa0) at /repos/bachelor-thesis/mbedtls-server/mbedtls/library/ssl_tls12_server.c:3216
#11 0x00005555555961aa in mbedtls_ssl_handshake_server_step (ssl=0x7fffffffcfa0)
    at /repos/bachelor-thesis/mbedtls-server/mbedtls/library/ssl_tls12_server.c:4263
#12 0x000055555557f9bc in mbedtls_ssl_handshake_step (ssl=0x7fffffffcfa0) at /repos/bachelor-thesis/mbedtls-server/mbedtls/library/ssl_tls.c:3897
#13 0x000055555557fab4 in mbedtls_ssl_handshake (ssl=0x7fffffffcfa0) at /repos/bachelor-thesis/mbedtls-server/mbedtls/library/ssl_tls.c:3943
#14 0x000055555556eb70 in main () at /repos/bachelor-thesis/mbedtls-server/ssl/ssl_server.c:215
```

## P(seudo) R(andom) N(umber) G(enerator)
- Has internal state `s`; private; updated with every random number
output from the system
- Every time a random number is needed, the internal state gets transformed
by a one-way-function to a random number.
- Must fulfill `forward secrecy`: Given the internal state `s` one
can't compute the previous internal state. This is achieved by using
a one-way-function to update the state after each output of a random number.
- Must??? fulfill `backward secrecy`: Given the internal state `s` one
can't compute the next/future internal state.

## Elliptic Curves

### E(lliptic) C(urve) D(iscrete) L(ogarithm) P(roblem)
$k \cdot P = Q$. Given $P$ and $Q$ it's NP-hard to find $k$.

## DualEC 2006
- Uses P-256 elliptic curve
- Hardcoded P
- Hardcoded Q
- P and Q are NO [Nothing-up-my-sleeve number](https://en.wikipedia.org/wiki/Nothing-up-my-sleeve_number)s, hence suspicion arrived

### Architecture
- $s_0$ gets transformed to $s_1$ by calculating $s_1 = (s_0 \cdot P)_x$
- $s_0$ gets transformed to $r_1$ by calculating $(s_0 \cdot Q)_x$
and then stripping the 16 most significant bits leaving $256-16 = 240$
- Every scalar multiplication satisfies the ECDLP.

### Attack
Assume that $P = d \cdot Q$.

Given $r_1$, we guess every of the $2^{16}$ stripped bits.

Through (for the time being) unexplained magic, we retrieve the full
$R_1 = (x,y)$ Point. Then it holds $R_1 = s_1 \cdot Q$.

Calculating
$$d \cdot R_1 = d \cdot (s_1 \cdot Q) = s_1 \cdot (d \cdot Q) = s_1 \cdot P = s_2$$
gives us the next internal state $s_2$
thus allowing to calculate every subsequent random number (backward secrecy).

### Ad(ditional)in(put)
There is an alternative allowing an intermediate value between two
internal states.

$$s_2 = (s_1 \oplus h(adin_1))_x \cdot P$$

.Adin is part of the seed of the PRNG. After 30 iterations we don't use adin anymore???.

Note: This adin breaks the backdoor and ensures forward secrecy
for smaller inputs, until 30 iterations.

## DualEC 2007
NIST updated the DualEC supposedly to bring in forward secrecy.

$$s_2 = ((s_1 \cdot P)_x \oplus h(adin_1))_x \cdot P$$

As described earlier we can easily bruteforce $2^{16}$ guesses to get
$(s_1 \cdot P)$. In this updated version we thus have all we need except
$adin_1$, which we would need to guess??? or we could use the cycling property???.


## Specification (2012)
[Speclink](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-90a.pdf)

- Formally known as: Dual_EC_DRBG
(Dual Elliptic Curve Deterministic Random Bit Generator)
- Initial seed $2 \cdot security\\_strength$ bits in length.
- Generates $outlen$-bits pseudorandom strings.
- Curve is defined over a field of "approximately" $2^m$ size.
 - Recommended curves are $m = 2 \cdot security\\_strength$ and $m \ge 256$
 - $m \equiv seedlen$
- Appendix A.1 specifies the selection of appropriate elliptic curves for
the desired security strength.
- Section 8.6. specifies the requirements of the **seed**. See also Section 10.4.1 for instantiating the seed.
- The maximum security strength supported by DualEC is equal to the security strength of
the used curve specified in [SP 800-57 Part 1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf), [SP 800-57 Part 2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt2r1.pdf) and [SP 800-57 Part 3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57Pt3r1.pdf)
- internal state:
 - $working\\_state$ consists of:
  - $s$: Determines the current position on the curve.
  - $(seedlen, p, a, b, n)$
   - $seedlen$: length of the seed
   - $p$: prime that defines the base field $F_p$
   - $a$ and $b$: "two field elements that define the equation of the curve"
   - $n$: "the order of the point $G$"
  - $P$ and $Q$: Points on the curve.
  - $reseed\\_counter$ indicating the number of blocks of random data since the
  initial seeding or the previous reseeding.
 - Administrative information
  - $security\\_strength$
  - $prediction\\_resistance\\_flag$: "Indicates whether prediction resistance is
required by the DRBG instantiation."
- "When selecting the curve in step 4 below, it is recommended that the default values be
used for P and Q as given in Appendix A.1. However, an implementation may use
different pairs of points, provided that they are verifiably random, as evidenced by the
use of the procedure specified in Appendix A.2.1 and the self-test procedure described
in Appendix A.2.2."
- Dual_EC_DRBG_Instantiate_algorithm is pseudocode
- D.5 Dual_EC_DRBG Example


