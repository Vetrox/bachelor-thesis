import hashlib

highest_supported_security_strength = None # TODO


class Dual_EC_DRBG:
    def __init__(self, working_state: WorkingState, security_strength, prediction_resistance_flag):
        """
        :param security_strength: Security strenght provided by the DRBG instantiation
        :param prediction_resistance_flag: Indicates whether prediction resistance is required by the DRBG instantiation.
        """
        self.working_state = working_state
        self.security_strength = security_strength
        self.required_minimum_entropy_for_instantiate_and_reseed = security_strength
        self.min_length = security_strength
        self.max_length = 2^13 # TODO: continue here in Table 4
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
        this.max_outlen = None # TODO: largest multiple of 8 less than (size of the base field) - (13 + log2(the cofactor))
        this.p = p
        this.a = a
        this.b = b
        this.n = n
        this.P = P
        this.Q = Q
        this.reseed_counter = reseed_counter

def Dual_EC_DRBG_Instantiate(entropy_input, nonce,
                personalization_string, security_strength):
    """
    :param entropy_input: The string of bits obtained from the source of entropy input.
    :param nonce: A string of bits as specified in Section 8.6.7.
    :param personalization_string: The personalization string received from the consuming application. Note that the length of the personalization string may be zero.
    :param security_strength: The security strength for the instantiation. This parameter is required for Dual_EC_DRBG.

    :returns: s, seedlen, p, a, b, n, P, Q, and a reseed_counter for the initial_working_state.
    """

    # TODO: determine the type of every argument and output


    # 1. seed_material = entropy_input || nonce || personalization_string.
    seed_material = ConcatBitStr(ConcatBitStr(entropy_input, nonce, personalization_string))

    # 2. s = Hash_df(seed_material, seedlen).
    # Note: Assert bitlen(s) = seedlen
    # TODO:

    # 3. reseed_counter = 0.
    reseed_counter = 0

    # 4. Using the security_strength and Table 4 in Section 10.3.1, select the smallest available curve that has a security strength >= security_strength. The values for seedlen, p, a, b, n, P, Q are determined by the curve
    #TODO:

    # 5. Return s, seedlen, p, a, b, n, P, Q, and a reseed_counter for the initial_working_state.
    return WorkingState(s, seedlen, p, a, b, n, P, Q, reseed_counter)

def Hash_df(input_string, no_of_bits_to_return):
    """
    The hash-based derivation function hashes an input
    string and returns the requested number of bits. Let Hash be the hash function used by the DRBG mechanism, and let outlen be its output length.

    Ensures the entropy is distributed throughout the bits and s is m (i.e seedlen) bits in length.

    :param input_string: The string to be hashed.
    :param no_of_bits_to_return: 32-bit string. The number of bits to be returned by Hash_df. The
maximum length (max_number_of_bits) is implementation dependent, but shall be
less than or equal to (255 outlen). no_of_bits_to_return is represented as a 32-bit
integer.

    :returns:
        status: The status returned from Hash_df. The status will indicate SUCCESS or ERROR_FLAG.
        requested_bits : The result of performing the Hash_df.
    """
    # TODO: Hash gets selected from Table 4 in 10.3.1
    Hash = getHashFunctionNowPls()

    # 1. temp = the Null string
    # ???
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
    # ???

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

    # 6. s = phi( x(t * P)).
    working_state.s = Dual_EC_phi(Dual_EC_x(Dual_EC_mul(t, working_state.P)))

    # 7. r = phi( x(s * Q)).
    r = Dual_EC_phi(Dual_EC_x(Dual_EC_mul(working_state.s, working_state.Q)))

    # 8. temp = temp || (rightmost outlen bits of r).
    # TODO:

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
    def __init__(self, curve, P, Q):
        self.curve = curve
        self.P = P
        self.Q = Q

class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

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


