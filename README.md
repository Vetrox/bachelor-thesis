# Scratchpad
This is a scratchpad so that i can centralize my knowledge.

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

TODO: continue at 10.3.1.2 Instantiation of Dual_EC_DRBG
