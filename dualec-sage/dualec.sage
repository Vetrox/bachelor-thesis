import hashlib # SHA-256
import time
import secrets # True random input seed entropy
import csv # Save the data points
import sys # command line arguments

SHA_256_OUTLEN = 256

"""Constants"""
Dual_EC_Security_Strength_128 = 128
Dual_EC_Security_Strength_192 = 192
Dual_EC_Security_Strength_256 = 256

"""Classes"""
class Curve:
    def __init__(self, p, n, b):
        """
        An elliptic curve is defined by the following equation:
        y² = x³ + a*x + b (mod p)

        Note: a is set to be (-3) in the above equation.

        :param p: Order of the field Fp, given in decimal
        :param n: Order of the Elliptic Curve Group, in decimal
        :param b: Coefficient in the above equation
        """
        self.p = p
        self.n = n
        self.order = n # convenient accessor
        self.a = -3
        self.b = b

def Elliptic_Curve_from(curve):
    FF = GF(curve.p) # construct finite field from prime p
    EC = EllipticCurve([FF(curve.a), FF(curve.b)]) # sage ec
    EC.set_order(curve.order)
    return (FF, EC)

class Dual_EC_Curve:
    def __init__(self, name, ec, P, Q):
        self.ec = ec
        self.name = name
        FF, EC = Elliptic_Curve_from(ec)
        self.FF = FF
        self.EC = EC
        self.P = EC(FF(P.x), FF(P.y)) # this is also the base (G) in case of Dual_EC
        self.Q = EC(FF(Q.x), FF(Q.y))

class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

class WorkingState:
    def __init__(self, s, seedlen, curve, reseed_counter, outlen):
        """
        :param s: Determines the current position on the curve.
        :param seedlen: The length of the seed
        :param curve: a Dual_EC_Curve instance
        :param reseed_counter: A counter that indicates the number of blocks of random data
produced by the Dual_EC_DRBG since the initial seeding or the previous
reseeding.
        """
        self.s = s # secret value
        self.seedlen = seedlen
        self.max_outlen = calculate_max_outlen(seedlen)
        self.dual_ec_curve = curve
        self.reseed_counter = reseed_counter
        self.outlen = outlen

"""Curves"""
Dual_EC_P256 = Dual_EC_Curve("P-256",
        Curve(
            115792089210356248762697446949407573530086143415290314195533631308867097853951,
            115792089210356248762697446949407573529996955224135760342422259061068512044369,
            0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b),
        Point( # Base point for P-256 and also P
            0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
            0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5),
        Point(
            0xc97445f45cdef9f0d3e05e1e585fc297235b82b5be8ff3efca67c59852018192,
            0xb28ef557ba31dfcbdd21ac46e2a91e3c304f44cb87058ada2cb815151e610046))
Dual_EC_P384 = Dual_EC_Curve("P-384",
        Curve(
            39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319,
            39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643,
            0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef),
        Point(
            0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
            0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f),
        Point(
            0x8e722de3125bddb05580164bfe20b8b432216a62926c57502ceede31c47816edd1e89769124179d0b695106428815065,
            0x023b1660dd701d0839fd45eec36f9ee7b32e13b315dc02610aa1b636e346df671f790f84c5e09b05674dbb7e45c803dd))
Dual_EC_P521 = Dual_EC_Curve("P-521",
        Curve(
            6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151,
            6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449,
            0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00),
        Point(
            0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
            0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650),
        Point(
            0x1b9fa3e518d683c6b65763694ac8efbaec6fab44f2276171a42726507dd08add4c3b3f4c1ebc5b1222ddba077f722943b24c3edfa0f85fe24d0c8c01591f0be6f63,
            0x1f3bdba585295d9a1110d1df1f9430ef8442c5018976ff3437ef91b81dc0b8132c8d5c39c32d0e004a3092b7d327c0e7a4d26d2c7b69b58f9066652911e457779de))

"""Functions"""
def Dual_EC_DRBG_Instantiate(entropy_input, nonce,
                personalization_string, security_strength, curve = None):
    """
    :param entropy_input: The string of bits obtained from the source of entropy input.
    :param nonce: A string of bits as specified in Section 8.6.7.
    :param personalization_string: The personalization string received from the consuming application. Note that the length of the personalization string may be zero.
    :param security_strength: The security strength for the instantiation. This parameter is required for Dual_EC_DRBG.

    :returns: s, seedlen, p, a, b, n, P, Q, and a reseed_counter for the initial_working_state.
    """

    # 1. seed_material = entropy_input || nonce || personalization_string.
    seed_material = ConcatBitStr(ConcatBitStr(entropy_input, nonce), personalization_string)

    # 2. s = Hash_df(seed_material, seedlen).
    seedlen = pick_seedlen(security_strength)
    s = Hash_df(seed_material, seedlen)
    assert len(s) == seedlen

    # 3. reseed_counter = 0.
    reseed_counter = 0

    # 4. Using the security_strength and Table 4 in Section 10.3.1, select the smallest available curve that has a security strength >= security_strength. The values for seedlen, p, a, b, n, P, Q are determined by the curve
    if curve == None: # BACKDOOR: This is to allow a self-picked Q
        curve = pick_curve(security_strength)

    # 5. Return s, seedlen, p, a, b, n, P, Q, and a reseed_counter for the initial_working_state.
    return WorkingState(s, seedlen, curve, reseed_counter, calculate_max_outlen(seedlen))

def Hash_df(input_string, no_of_bits_to_return):
    """
    The hash-based derivation function hashes an input
    string and returns the requested number of bits. Let Hash be the hash function used by the DRBG mechanism, and let outlen be its output length.

    Ensures the entropy is distributed throughout the bits and s is m (i.e seedlen) bits in length.

    :param input_string: The string to be hashed.
    :param no_of_bits_to_return: The number of bits to be returned by Hash_df. The
maximum length (max_number_of_bits) is implementation dependent, but shall be
less than or equal to (255 * outlen). no_of_bits_to_return is represented as a 32-bit
integer.

    :returns:
        status: The status returned from Hash_df. The status will indicate SUCCESS or ERROR_FLAG.
        requested_bits : The result of performing the Hash_df.
    """
    # Hash gets selected from Table 4 in 10.3.1
    # Note: Since it's allowed for every allowed curve (P-256, P-384, P-521) we use SHA-256.
    outlen = SHA_256_OUTLEN
    assert no_of_bits_to_return <= 255 * outlen
    # The outlen of SHA-256 is 256 bit.

    # 1. temp = the Null string
    temp = bits_from_num(0) # -> []

    # 2. len = ceil(no_of_bits_to_return / outlen)
    len_ = ceil(no_of_bits_to_return / outlen)

    # 3. counter = an 8-bit binary value representing the integer "1".
    counter = 1

    # 4. For i = 1 to len do
    for i in range(1, len_ + 1):
        # 4.1 temp = temp || Hash(counter || no_of_bits_to_return || input_string)
        temp = ConcatBitStr(temp,
                             Hash(ConcatBitStr(
                                     ConcatBitStr(cast_to_bitlen(counter, 8),
                                                  cast_to_bitlen(no_of_bits_to_return, 32)),
                                     input_string)))

        # 4.2 counter = counter + 1.
        counter = counter + 1

    # 5. requested_bits = Leftmost (no_of_bits_to_return) of temp.
    requested_bits = Dual_EC_Truncate(temp, len(temp), no_of_bits_to_return)

    # 6. Return SUCCESS and requested_bits.
    return requested_bits

def ConcatBitStr(bitstr_a, bitstr_b):
    assert type(bitstr_a) == type(bitstr_b) == list
    return bitstr_a + bitstr_b

def Dual_EC_Truncate(bitstring, in_len, out_len):
    """
    Inputs a bitstring of in_len bits, returning
    a string consisting of the leftmost out_len bits of bitstring. If in_len < out_len,
    the bitstring is padded on the right with (out_len - in_len) zeroes, and the result
    is returned.
    """
    assert type(bitstring) == list and (type(in_len) == Integer or type(in_len) == int) and type(out_len) == Integer
    amount_to_add = out_len - in_len
    if amount_to_add > 0:
        bitstring = bitstring + [0]*amount_to_add
    return bitstring[:out_len]

def Dual_EC_x(A):
    """
    Is the x-coordinate of the point A on the curve, given in affine coordinates.
    An implementation may choose to represent points internally using other
    coordinate systems; for instance, when efficiency is a primary concern. In this
    case, a point shall be translated back to affine coordinates before x() is applied.
    """
    assert type(A) == sage.schemes.elliptic_curves.ell_point.EllipticCurvePoint_finite_field
    x,y = A.xy()
    return x

def Dual_EC_phi(x):
    """
    Maps field elements to non-negative integers, taking the bit vector
    representation of a field element and interpreting it as the binary expansion of
    an integer.
    Note: Further details depend on the implementation of the field
    """
    assert type(x) == sage.rings.finite_rings.integer_mod.IntegerMod_gmp
    return x.lift()

def Dual_EC_mul(scalar, A):
    """
    representing scalar multiplication of a point on the curve
    """
    assert type(scalar) == Integer and type(A) == sage.schemes.elliptic_curves.ell_point.EllipticCurvePoint_finite_field
    return scalar * A

def print_stripped_r(working_state, r, rightmost_outlen_bits_of_r):
    stripped_bits = XOR(num_from_bitstr(rightmost_outlen_bits_of_r), r)
    hex_outlen_bits_of_r = hex_from_number_padded_to_num_of_bits(num_from_bitstr(rightmost_outlen_bits_of_r), working_state.outlen)
    hex_stripped_bits = hex_from_number_padded_to_num_of_bits(stripped_bits >> working_state.outlen, working_state.seedlen - working_state.outlen)
    print(f"s <- {hex_from_number_padded_to_num_of_bits(num_from_bitstr(working_state.s), working_state.seedlen)}")
    print(f"r <- {hex_outlen_bits_of_r}, stripped_bits = {hex_stripped_bits}")

def Dual_EC_DRBG_Generate(working_state: WorkingState, requested_number_of_bits, additional_input):
    """
    :param working_state: The current values for s, seedlen, p, a, b, n, P, Q, and a
    reseed_counter.
    :param requested_number_of_bits: The number of pseudorandom bits to be returned to
    the generate function.
    :param additional_input: The additional input string received from the consuming
    application.

    :returns:
        status: The status returned from the function. The status will indicate
            SUCCESS, or an indication that a reseed is required before the requested
            pseudorandom bits can be generated.
        returned_bits: The pseudorandom bits to be returned to the generate function.
        s, seedlen, p, a, b, n, P, Q, and a reseed_counter for the new_working_state
    """
    # 1. Check whether a reseed is required.
    # Note: This isn't supported.

    # 2. If additional_input_string = Null then additional_input = 0
    if additional_input == None:
        additional_input = bits_from_num(0)
    else: # Else additional_input = Hash_df (pad8 (additional_input), seedlen).
        additional_input = Hash_df(cast_to_bitlen(num_from_bitstr(additional_input), 8*ceil(bitlen(num_from_bitstr(additional_input)) / 8)), working_state.seedlen)

    # 3. temp = the Null string
    temp = bits_from_num(0)

    # 4. i = 0
    i = 0

    print(f"Generate(s = {hex_from_number_padded_to_num_of_bits(num_from_bitstr(working_state.s), working_state.seedlen)}, requested_number_of_bits = {requested_number_of_bits})")
    while True:
        print(f"Iteration {i}")
        # 5. t = s XOR additional_input.
        t = XOR(num_from_bitstr(working_state.s), num_from_bitstr(additional_input))

        # 6. s = phi(x(t * P)).
        working_state.s = cast_to_bitlen(Dual_EC_phi(Dual_EC_x(Dual_EC_mul(t, working_state.dual_ec_curve.P))), working_state.seedlen)

        # 7. r = phi(x(s * Q)).
        r = Dual_EC_phi(Dual_EC_x(Dual_EC_mul(num_from_bitstr(working_state.s), working_state.dual_ec_curve.Q)))

        # 8. temp = temp || (rightmost outlen bits of r).
        rightmost_outlen_bits_of_r = cast_to_bitlen(r, working_state.outlen)
        print_stripped_r(working_state, r, rightmost_outlen_bits_of_r)
        temp = ConcatBitStr(temp, rightmost_outlen_bits_of_r)

        # 9. additional_input = 0
        additional_input = bits_from_num(0)

        # 10. reseed_counter = reseed_counter + 1.
        working_state.reseed_counter = working_state.reseed_counter + 1

        # 11. i = i + 1
        i = i + 1

        # 12. If (len (temp) < requested_number_of_bits), then go to step 5.
        if not (len(temp) < requested_number_of_bits):
            break

    # 13. returned_bits = Truncate(temp, i * outlen, requested_number_of_bits).
    if len(temp) != i * working_state.outlen:
        raise AssertionError("Temp must be a multiple of outlen.")
    returned_bits = Dual_EC_Truncate(temp, len(temp), requested_number_of_bits)

    # 14. s = phi(x(s * P)).
    # Note: This isn't present in the 2006 variant of DualEC.
    working_state.s = cast_to_bitlen(Dual_EC_phi(Dual_EC_x(Dual_EC_mul(num_from_bitstr(working_state.s), working_state.dual_ec_curve.P))), working_state.seedlen)

    # 15. Return SUCCESS, returned_bits, and s, seedlen, p, a, b, n, P, Q, and a reseed_counter for the new_working_state.
    return returned_bits, working_state

def XOR(a, b):
    assert type(a) == type(b) == Integer
    return a ^^ b

def bits_from_byte(byte):
    assert type(byte) == int and bitlen(byte) <= 8
    ret = []
    for i in range(8):
        masked = (byte & (0b1 << (7-i))) != 0
        if masked == True:
            ret.append(1)
        else:
            ret.append(0)
    return ret

def bitstr_from_bytes(byte_array):
    assert type(byte_array) == bytes
    ret = []
    for byte in byte_array:
        ret += bits_from_byte(byte)
    return ret

def pad_bitstr_left(bitstr, expected_length):
    assert type(bitstr) == list
    remaining = expected_length - len(bitstr)
    return [0]*remaining + bitstr

def Hash(bitstr):
    assert type(bitstr) == list
    return pad_bitstr_left(bitstr_from_bytes(hashlib.sha256(bytes_from_bitstr(bitstr)).digest()), SHA_256_OUTLEN)

def bytes_from_bitstr(bitstr):
    assert type(bitstr) == list
    ret = []
    while len(bitstr) >= 8:
        byte = bitstr[:8]
        bitstr = bitstr[8:]
        ret.append(num_from_bitstr(byte))
    if len(bitstr) > 0:
        ret.append(num_from_bitstr(bitstr))
    ret = bytes(ret)
    return ret

def hex_from_number_padded_to_num_of_bits(num, amount_of_bits):
    assert type(num) == Integer and type(amount_of_bits) == Integer
    actual_nibbles = max(ceil(bitlen(num) / 4), 1)
    amount_of_nibbles = ceil(amount_of_bits / 4)
    if actual_nibbles > amount_of_nibbles:
        raise ValueError("Requested less nibbles than the minimum to represent this number")
    ret = ""
    for i in range(amount_of_nibbles - actual_nibbles):
        ret += "0"
    return ret + num.hex()

def cast_to_bitlen(num, outlen):
    """Left equivalent of Dual_EC_Truncate.
    This also inserts 0s on the left if outlen > bitlen(x)"""
    assert type(num) == type(outlen) == Integer
    bitstr = bits_from_num(num)
    filler_amount = outlen - len(bitstr)
    if filler_amount > 0:
        bitstr = [0]*filler_amount + bitstr
    return bitstr[len(bitstr)-outlen:]

def bitlen(x):
    assert type(x) == int or type(x) == Integer
    return x.bit_length()

def pick_curve(security_strength):
    """See Definitions for the Dual_EC_DRBG"""
    if security_strength <= 128:
        return Dual_EC_P256
    if security_strength <= 192:
        return Dual_EC_P384
    if security_strength <= 256:
        return Dual_EC_P521
    raise ValueError("Invalid Security strength requested.")

def pick_seedlen(security_strength):
    """See Definitions for the Dual_EC_DRBG"""
    if security_strength <= 128:
        return 256
    if security_strength <= 192:
        return 384
    if security_strength <= 256:
        return 521
    raise ValueError("Invalid Security strength requested.")

def calculate_max_outlen(seedlen):
    """See Definitions for the Dual_EC_DRBG"""
    if seedlen <= 256:
        return 240
    if seedlen <= 384:
        return 368
    if seedlen <= 521:
        return 504
    raise ValueError("Invalid seedlen provided.")

def num_from_bitstr(bitlist):
    num = 0
    for bit in bitlist:
        num |= bit
        num <<= 1
    num >>= 1
    return num

def attack_backdoor(security_strength):
    curve = pick_curve(security_strength)
    curve_name = curve.name
    print(f"Picking {curve_name}")
    d, Q = generate_dQ(curve.P)
    x,y = Q.xy()
    print(f"produced backdoor d: {d.hex()}, Q: ({x.lift().hex()}, {y.lift().hex()})")
    curve.Q = Q

    seedlen = pick_seedlen(security_strength)
    max_outlen = calculate_max_outlen(seedlen)
    num_of_predictions = 9
    requested_bitlen = max_outlen * (2+num_of_predictions)

    input_randomness = bits_from_num(Integer(secrets.randbelow(2^64-1)))
    output_randomness, delta_time = init_and_generate(input_randomness, requested_bitlen, security_strength, curve)
    print(f"Generation took: {delta_time:.2f} ms")

    s = compute_s_from_one_outlen_line_of_bits(output_randomness[:max_outlen], output_randomness[max_outlen:2*max_outlen], seedlen, max_outlen, d, Q, curve)
    output_randomness = output_randomness[2*max_outlen:]
    print("Predicting the next inputs...")
    working_state = WorkingState(s, seedlen, curve, 0, max_outlen)
    returned_bits, working_state = Dual_EC_DRBG_Generate(working_state, max_outlen*num_of_predictions, bits_from_num(0))
    print(f"predicted: {num_from_bitstr(returned_bits).hex()}, actual: {num_from_bitstr(output_randomness).hex()}")
    if returned_bits == output_randomness:
        print("SUCCESS")

def compute_s_from_one_outlen_line_of_bits(rand_bits, next_rand_bits, seedlen, max_outlen, d, Q, curve):
    stripped_amount_of_bits = seedlen-max_outlen
    print(f"stripped_amount_of_bits = {stripped_amount_of_bits}")

    # brute-force the missing stripped bits
    for i in range(2^stripped_amount_of_bits):
        guess_for_stripped_bits_of_r = cast_to_bitlen(Integer(i), stripped_amount_of_bits)
        guess_for_r_x = num_from_bitstr(ConcatBitStr(guess_for_stripped_bits_of_r, rand_bits))
        print(f"\rguess for stripped_bits = {hex_from_number_padded_to_num_of_bits(num_from_bitstr(guess_for_stripped_bits_of_r), stripped_amount_of_bits)}", end="")
        guesses_for_R = calculate_Points_from_x(guess_for_r_x, curve)
        print(f"\tfound {len(guesses_for_R)} solutions for y", end="")
        for guess_for_R in guesses_for_R:
            # it holds that s2 = x(d * R)
            guess_for_next_s = Dual_EC_phi(Dual_EC_x(Dual_EC_mul(d, guess_for_R)))
            guess_for_next_r = Dual_EC_phi(Dual_EC_x(Dual_EC_mul(guess_for_next_s, Q)))
            guess_for_next_rand_bits = cast_to_bitlen(guess_for_next_r, max_outlen)
            if guess_for_next_rand_bits == next_rand_bits:
                print(f"\nfound the right secret state {guess_for_next_s.hex()}")
                return bits_from_num(guess_for_next_s)
    raise ValueError("Didn't find any matching s. This indicates a mathematical problem, since we check every possibility of r")

def bits_from_num(num):
    return num.bits()[::-1] # ...b3b2b1b0

def calculate_Points_from_x(x, curve):
    FF = curve.FF
    EC = curve.EC
    x = FF(x)
    # x³ + a*x + b (mod p)
    yy = (x^3 + curve.ec.a * x + curve.ec.b) % curve.ec.p
    y_candidates = yy.sqrt(extend=False, all=True)
    return [EC(FF(x), FF(y)) for y in y_candidates]

def init_and_generate(input_randomness, requested_amount_of_bits, security_strength, curve):
    nonce = bits_from_num(123)
    personalization_string = bitstr_from_bytes(b"sage_dual_ec")
    working_state = Dual_EC_DRBG_Instantiate(input_randomness, nonce, personalization_string, security_strength, curve)
    print(f"WorkingState(s: {num_from_bitstr(working_state.s).hex()} seedlen: {working_state.seedlen} outlen: {working_state.outlen})")

    start_time = time.monotonic()
    returned_bits, working_state = Dual_EC_DRBG_Generate(working_state, requested_amount_of_bits, bits_from_num(0))
    diff = time.monotonic() - start_time
    return returned_bits, (diff * 1000)

def generate_dQ(P):
    """ generates P = d * Q and returns d and Q"""
    # pick a random d
    d = Integer(secrets.randbelow(P.order() - 1)) + 1
    # compute the inverse of d modulo ord(P)
    e = d^-1 % P.order()
    # compute Q as d^-1 * P
    Q = e * P
    # perform the sanity check
    if d * Q == P:
        return (d, Q)
    raise AssertionError("d should be picked so that it's invertible.")

if __name__ == "__main__":
    if len(sys.argv) > 2:
        # Example showing the DualEC generation process
        entropy_str = "" if len(sys.argv) < 4 else sys.argv[3]
        bits, t = init_and_generate(bitstr_from_bytes(bytes(entropy_str, encoding="utf-8")), Integer(sys.argv[2]), Integer(sys.argv[1]), pick_curve(int(sys.argv[1])))
        print(bits)
    else:
        attack_backdoor(Integer(sys.argv[1]))
