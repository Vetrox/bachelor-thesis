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

