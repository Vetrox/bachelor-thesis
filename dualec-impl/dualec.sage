import hashlib

"""Constants"""
max_length = 2^13
max_personalization_string_length = 2^13
max_additional_input_length = 2^13

Dual_EC_Security_Strength_128 = 128
Dual_EC_Security_Strength_192 = 192
Dual_EC_Security_Strength_256 = 256

highest_supported_security_strength = Dual_EC_Security_Strength_256

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
        # Note: The x and y coordinates of the base point, i.e., generator G, are the same as for the point P.
        # ???
        self.p = p
        self.n = n
        self.a = -3 # Note: a is set to be (-3) in the above equation.
        self.b = b

class Dual_EC_Curve:
    def __init__(self, ec, P, Q):
        self.ec = ec
        self.P = P
        self.Q = Q

class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

class Dual_EC_DRBG:
    def __init__(self, working_state: WorkingState, security_strength, prediction_resistance_flag):
        """
        :param security_strength: Security strength provided by the DRBG instantiation
        :param prediction_resistance_flag: Indicates whether prediction resistance is required by the DRBG instantiation.
        """
        self.working_state = working_state
        self.security_strength = security_strength
        self.required_minimum_entropy_for_instantiate_and_reseed = security_strength
        self.min_length = security_strength
        self.prediction_resistance_flag = prediction_resistance_flag

class WorkingState:
    def __init__(self, s, seedlen, p, a, b, n, P, Q, reseed_counter):
        """
        :param s: Determines the current position on the curve.
        :param seedlen: The length of the seed
        :param p: The prime that defines the base field Fp
        :param a: A Field element that defines the equation of the curve
        :param b: A Field element that defines the equation of the curve
        :param n: The order of the point G.
        :param P: Point P on the curve.
        :param Q: Point Q on the curve.
        :param reseed_counter: A counter that indicates the number of blocks of random data
produced by the Dual_EC_DRBG since the initial seeding or the previous
reseeding.
        """
        this.s = s # secret value
        this.seedlen = seedlen

        # Largest multiple of 8 less than (size of the base field) - (13 + log2(the cofactor))
        this.max_outlen = 8*floor(this.seedlen / 8) - (13 + log(8)/log(2))
        # TODO: the cofactor of 8 is only retrieved by trail and error. Recommended values are lower than 4, so something has to be off.

        this.p = p
        this.a = a
        this.b = b
        this.n = n
        this.P = P
        this.Q = Q
        this.reseed_counter = reseed_counter

"""Functions"""
def Dual_EC_DRBG_Instantiate(entropy_input, nonce,
                personalization_string, security_strength):
    """
    :param entropy_input: The string of bits obtained from the source of entropy input.
    :param nonce: A string of bits as specified in Section 8.6.7.
    :param personalization_string: The personalization string received from the consuming application. Note that the length of the personalization string may be zero.
    :param security_strength: The security strength for the instantiation. This parameter is required for Dual_EC_DRBG.

    :returns: s, seedlen, p, a, b, n, P, Q, and a reseed_counter for the initial_working_state.
    """

    # 1. seed_material = entropy_input || nonce || personalization_string.
    seed_material = ConcatBitStr(ConcatBitStr(entropy_input, nonce, personalization_string))

    # 2. s = Hash_df(seed_material, seedlen).
    s = Hash_df(seed_material, seedlen)
    # TODO: Assert bitlen(s) = seedlen

    # 3. reseed_counter = 0.
    reseed_counter = 0

    # 4. Using the security_strength and Table 4 in Section 10.3.1, select the smallest available curve that has a security strength >= security_strength. The values for seedlen, p, a, b, n, P, Q are determined by the curve
    curve = pick_curve(security_strength)

    # 5. Return s, seedlen, p, a, b, n, P, Q, and a reseed_counter for the initial_working_state.
    return WorkingState(s, seedlen, curve.ec.p, curve.ec.a, curve.ec.b, curve.ec.n, curve.P, curve.Q, reseed_counter)

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

    # 1. temp = the Null string
    # TODO: ???
    temp = ""

    # 2. len = ceil(no_of_bits_to_return / outlen)
    len_ = ceil(no_of_bits_to_return / outlen)

    # 3. counter = an 8-bit binary value representing the integer "1".
    # ???
    counter = 1

    # 4. For i = 1 to len do
    for i in range(1, len_ + 1): # TODO: check off by one error
        # 4.1 temp = temp || Hash(counter || no_of_bits_to_return || input_string)
        temp = ConcatBitStr(temp,
                             Hash(ConcatBitStr(
                                     ConcatBitStr(counter,no_of_bits_to_return),
                                     input_string)))

        # 4.2 counter = counter + 1.
        counter = counter + 1

    # 5. requested_bits = Leftmost (no_of_bits_to_return) of temp.
    requested_bits = leftmost_no_of_bits_to_return_from(temp, no_of_bits_to_return)

    # 6. Return SUCCESS and requested_bits.
    return ("SUCCESS", requested_bits)

def ConcatBitStr(a,b):
    raise NotImplementedError("Not implemented yet")

def Dual_EC_DRBG_Reseed(working_state, entropy_input,
                        additional_input):
    raise NotImplementedError("Reseeding isn't implemented yet")

def Dual_EC_pad8(bitstring):
    """
    pad8 (bitstring) returns a copy of the bitstring padded on the right with binary
    0’s, if necessary, to a multiple of 8.
    """
    raise NotImplementedError("Not implemented yet")
def Dual_EC_Truncate(bitstring, in_len, out_len):
    """
    Inputs a bitstring of in_len bits, returning
    a string consisting of the leftmost out_len bits of bitstring. If in_len < out_len,
    the bitstring is padded on the right with (out_len - in_len) zeroes, and the result
    is returned.
    """
    raise NotImplementedError("Not implemented yet")
def Dual_EC_x(A):
    """
    Is the x-coordinate of the point A on the curve, given in affine coordinates.
    An implementation may choose to represent points internally using other
    coordinate systems; for instance, when efficiency is a primary concern. In this
    case, a point shall be translated back to affine coordinates before x() is applied.
    """
    raise NotImplementedError("Not implemented yet")
def Dual_EC_phi(x):
    """
    Maps field elements to non-negative integers, taking the bit vector
    representation of a field element and interpreting it as the binary expansion of
    an integer.
    Note: Further details depend on the implementation of the field
    """
    raise NotImplementedError("Not implemented yet")
def Dual_EC_mul(scalar, A):
    """
    representing scalar multiplication of a point on the curve
    """
    raise NotImplementedError("Not implemented yet")

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
    # If the input of additional_input is not supported by an
    # implementation, then step 2 of the generate process becomes:
    # additional_input = 0.
    # Alternatively, generate steps 2 and 9 are omitted, the additional_input term is
    # omitted from step 5, and the “go to step 5” in step 12 is to the step that now sets
    # t = s.


    # 1. Check whether a reseed is required.
    # Note: This isn't implemented yet

    # 2. If additional_input_string??? = Null then additional_input = 0 else ...
    additional_input = 0

    # 3. temp = the Null string
    # ???

    # 4. i=0
    i = 0

    while True:
        # 5. t = s XOR additional_input.
        t = XOR(working_state.s, additional_input)

        # 6. s = phi(x(t * P)).
        working_state.s = Dual_EC_phi(Dual_EC_x(Dual_EC_mul(t, working_state.P)))

        # 7. r = phi(x(s * Q)).
        r = Dual_EC_phi(Dual_EC_x(Dual_EC_mul(working_state.s, working_state.Q)))

        # 8. temp = temp || (rightmost outlen bits of r).
        temp = ConcatBitStr(temp, rightmost_outlen_bits_of(r, outlen))

        # 9. additional_input=0
        additional_input = 0

        # 10. reseed_counter = reseed_counter + 1.
        working_state.reseed_counter = working_state.reseed_counter + 1

        # 11. i = i + 1
        i = i + 1

        # 12. If (len (temp) < requested_number_of_bits), then go to step 5.
        if not (bitlen(temp) < requested_number_of_bits):
            break

    # 13. returned_bits = Truncate (temp, i outlen, requested_number_of_bits).
    returned_bits = Dual_EC_Truncate(temp, i, outlen, requested_number_of_bits)

    # 14. s = phi(x(s * P)).
    working_state.s = Dual_EC_phi(Dual_EC_x(Dual_EC_mul(working_state.s, working_state.P)))

    # 15. Return SUCCESS, returned_bits, and s, seedlen, p, a, b, n, P, Q, and a reseed_counter for the new_working_state.
    return ("SUCCESS", returned_bits, working_state)

def XOR(a, b):
    return a ^^ b

def Hash(byte_array: bytes) -> bytes:
    return hashlib.sha256(byte_array).digest()

def rightmost_outlen_bits_of(x, outlen):
    return x & (2^outlen - 1)

def leftmost_no_of_bits_to_return_from(x, no_of_bits_to_return):
    return x >> (bitlen(x) - no_of_bits_to_return)

def bitlen(x):
    raise NotImplementedError(f"The bitlen is not implemented for {type(x)}")

"""Curves"""
Dual_EC_P256 = Dual_EC_Curve(
        Curve(
            115792089210356248762697446949407573530086143415290314195533631308867097853951,
            115792089210356248762697446949407573529996955224135760342422259061068512044369,
            0x5ac635d8_aa3a93e7_b3ebbd55_769886bc_651d06b0_cc53b0f6_3bce3c3e_27d2604b),
        Point(
            0x6b17d1f2_e12c4247_f8bce6e5_63a440f2_77037d81_2deb33a0_f4a13945_d898c296,
            0x4fe342e2_fe1a7f9b_8ee7eb4a_7c0f9e16_2bce3357_6b315ece_cbb64068_37bf51f5),
        Point(
            0xc97445f4_5cdef9f0_d3e05e1e_585fc297_235b82b5_be8ff3ef_ca67c598_52018192,
            0xb28ef557_ba31dfcb_dd21ac46_e2a91e3c_304f44cb_87058ada_2cb81515_1e610046))
Dual_EC_P384 = Dual_EC_Curve(
        Curve(
            39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319,
            39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643,
            0xb3312fa7_e23ee7e4_988e056b_e3f82d19_181d9c6e_fe814112_0314088f_5013875a_c656398d_8a2ed19d_2a85c8ed_d3ec2aef),
        Point(
            0xaa87ca22_be8b0537_8eb1c71e_f320ad74_6e1d3b62_8ba79b98_59f741e0_82542a38_5502f25d_bf55296c_3a545e38_72760ab7,
            0x3617de4a_96262c6f_5d9e98bf_9292dc29_f8f41dbd_289a147c_e9da3113_b5f0b8c0_0a60b1ce_1d7e819d_7a431d7c_90ea0e5f),
        Point(
            0x8e722de3_125bddb0_5580164b_fe20b8b4_32216a62_926c5750_2ceede31_c47816ed_d1e89769_124179d0_b6951064_28815065,
            0x023b1660_dd701d08_39fd45ee_c36f9ee7_b32e13b3_15dc0261_0aa1b636_e346df67_1f790f84_c5e09b05_674dbb7e_45c803dd))
Dual_EC_P256 = Dual_EC_Curve(
        Curve(
            6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151,
            6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449,
            0x051953eb_9618e1c9_a1f929a2_1a0b6854_0eea2da7_25b99b31_5f3b8b48_9918ef10_9e156193_951ec7e9_37b1652c_0bd3bb1b_f073573d_f883d2c3_4f1ef451_fd46b503_f00),
        Point(
            0xc6858e06_b70404e9_cd9e3ecb_662395b4_429c6481_39053fb5_21f828af_606b4d3d_baa14b5e_77efe759_28fe1dc1_27a2ffa8_de3348b3_c1856a42_9bf97e7e_31c2e5bd_66,
            0x11839296_a789a3bc_0045c8a5_fb42c7d1_bd998f54_449579b4_46817afb_d17273e6_62c97ee7_2995ef42_640c550b_9013fad0_761353c7_086a272c_24088be9_4769fd16_650),
        Point(
            0x1b9fa3e5_18d683c6_b6576369_4ac8efba_ec6fab44_f2276171_a4272650_7dd08add_4c3b3f4c_1ebc5b12_22ddba07_7f722943_b24c3edf_a0f85fe2_4d0c8c01_591f0be6_f63,
            0x1f3bdba5_85295d9a_1110d1df_1f9430ef_8442c501_8976ff34_37ef91b8_1dc0b813_2c8d5c39_c32d0e00_4a3092b7_d327c0e7_a4d26d2c_7b69b58f_90666529_11e45777_9de))

def pick_curve(security_strength):
    """
    Table 2 of 5.6.1.1 of SP 800 Pt. 1
    https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf#%5B%7B%22num%22%3A196%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C319%2C345%2C0%5D
    """
    if security_strength <= 128:
        return Dual_EC_P256
    if security_strength <= 192:
        return Dual_EC_P384
    if security_strength <= 256:
        return Dual_EC_P521
    raise ValueError("Invalid Security strength requested.")