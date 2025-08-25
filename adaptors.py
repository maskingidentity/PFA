############################################################
#### Description:
# Our implementation of Schnorr Adaptor Signatures. 

# Author: Nikhil Vanjani
############################################################

import random

from schnorr import *

# Set DEBUG to True to get a detailed debug output including
# intermediate values during key generation, signing, and
# verification. This is implemented via calls to the
# debug_print_vars(settings.DEBUG) function.
#
# If you want to print values on an individual basis, use
# the pretty() function, e.g., print(pretty(foo)).
DEBUG = True

def as_presign(msg: bytes, seckey: bytes, aux_rand: bytes, bStatement: bytes) -> bytes:
    # d0 is the secret key, think sk
    d0 = int_from_bytes(seckey)
    if not (1 <= d0 <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    if len(aux_rand) != 32:
        raise ValueError('aux_rand must be 32 bytes instead of %i.' % len(aux_rand))
    if len(bStatement) != 64:
        raise ValueError('The adaptor statement must be a 64-byte array.')
    # P is the public key corresponding to seckey
    P = point_mul(G, d0)
    assert P is not None
    pubkey = bytes_from_point(P)
    # d is the secret key
    d = d0
    # d = d0 if has_even_y(P) else n - d0

    t = xor_bytes(bytes_from_int(d), tagged_hash("BIP0340/aux", aux_rand))
    debug_print_vars(settings.DEBUG)
    k0 = int_from_bytes(tagged_hash("BIP0340/nonce", t + pubkey + msg)) % n
    if k0 == 0:
        raise RuntimeError('Failure. This happens only with negligible probability.')
    # R = g^{k0} is the elliptic curve point that will be used in the hash computation in e below. 
    R = point_mul(G, k0)
    assert R is not None
    # if not has_even_y(R):
    #     print("check0")

    # # k denotes the random coins used by Sign algo. Think R = g^k.
    k = k0
    # k = n - k0 if not has_even_y(R) else k0

    # #### need to update R in case k \neq k0. 
    # #### This is because the y co-ordinate will change now. 
    # #### This was not crucial for normal signing, but it is now as 
    # #### we add Statement to R later on and in preverify, oldR will be 
    # #### recovered using just the x co-ordinate r. The oldR will have 
    # #### the y co-ordinate same as that of recomputed R in this step.
    # R = point_mul(G, k)
    # if not has_even_y(R):
    #     print("check1")


    #### offset R by Statement
    # Statement = lift_x(int_from_bytes(bStatement))
    Statement = point_from_bytes(bStatement)
    # if not has_even_y(Statement):
    #     print("check2")

    newR = point_add(R, Statement)
    # if not has_even_y(newR):
    #     print("check3")
        # k = n - k0
        # R = point_mul(G, k)
        # newR = point_add(R, Statement)
        # if not has_even_y(newR):
        #     print("  SO SAD!!!")

    #### use newR instead of R
    e = int_from_bytes(tagged_hash("BIP0340/challenge", bytes_from_point(newR) + pubkey + msg)) % n
    presig = bytes_from_point(R) + bytes_from_int((k + e * d) % n)
    debug_print_vars(settings.DEBUG)
    #### change to preverify from verify
    if not as_preverify(msg, pubkey, presig, bStatement):
        raise RuntimeError('The created pre-signature does not pass pre-verification.')
    return presig

def as_preverify(msg: bytes, pubkey: bytes, presig: bytes, bStatement: bytes) -> bool:
    if len(pubkey) != 64:
        raise ValueError('The public key must be a 64-byte array.')
    if len(presig) != 96:
        raise ValueError('The pre-signature must be a 96-byte array.')
    if len(bStatement) != 64:
        raise ValueError('The adaptor statement must be a 64-byte array.')
    # public key in Point notation
    P = point_from_bytes(pubkey)
    # P = lift_x(int_from_bytes(pubkey))
    if not is_point_on_curve(P):
        print('as_preverify: The public key must be a point on the elliptic curve.')
        return False

    r = point_from_bytes(presig[0:64])
    if not is_point_on_curve(r):
        print('as_preverify: The first component of pre-signature must be a point on the elliptic curve.')
        return False

    s = int_from_bytes(presig[64:96])
    if (P is None) or (x(r) >= p) or (s >= n):
        debug_print_vars(settings.DEBUG)
        return False

    #### use newR for hash computation
    Statement = point_from_bytes(bStatement)
    # Statement = lift_x(int_from_bytes(bStatement))
    # oldR = lift_x(r)
    # newR = point_add(oldR, Statement)
    newR = point_add(r, Statement)
    # if not has_even_y(newR):
    #     print("changing R")
    #     k = n - k0
    #     R = point_mul(G, k)
    #     newR = point_add(R, Statement)

    e = int_from_bytes(tagged_hash("BIP0340/challenge", bytes_from_point(newR) + pubkey + msg)) % n

    R = point_add(point_mul(G, s), point_mul(P, n - e))
    if (R is None) or (R != r):
    # if (R is None) or (not has_even_y(R)) or (x(R) != r):
        debug_print_vars(settings.DEBUG)
        return False
    debug_print_vars(settings.DEBUG)
    return True

def as_adapt(msg: bytes, pubkey: bytes, presig: bytes, bStatement: bytes, witness: int) -> bytes:
    if len(pubkey) != 64:
        raise ValueError('The public key must be a 64-byte array.')
    if len(presig) != 96:
        raise ValueError('The pre-signature must be a 96-byte array.')
    if len(bStatement) != 64:
        raise ValueError('The adaptor statement must be a 64-byte array.')

    if not as_preverify(msg, pubkey, presig, bStatement):
        raise ValueError('The pre-signature must pass pre-verification.')
    if not is_relation_satisfied(bStatement, witness):
        raise ValueError('The statement and witness do not satisfy discrete log relation.')

    # wit1 = 3
    # wit2 = 5
    # wit3 = wit1 + wit2 % n
    # point1 = point_mul(G, wit1)
    # point2 = point_mul(G, wit2)
    # point3 = point_mul(G, wit3)
    # point12 = point_add(point1, point2)

    R = point_from_bytes(presig[0:64])
    # R = lift_x(r)
    # Statement = lift_x(int_from_bytes(bStatement))
    Statement = point_from_bytes(bStatement)
    new_R = point_add(R, Statement)

    s = int_from_bytes(presig[64:96])
    new_s = (s + witness) % n
    sig = bytes_from_point(new_R) + bytes_from_int(new_s)
    debug_print_vars(settings.DEBUG)
    #### change to preverify from verify
    if not schnorr_verify(msg, pubkey, sig):
        raise RuntimeError('The adapted signature does not pass verification for witness: {}'.format(witness))
    return sig

#  return value 0 signifies that extracted witness does not satisfy relation with the statement.
def as_extract(msg: bytes, pubkey: bytes, presig: bytes, sig: bytes, bStatement: bytes) -> int:
    if len(pubkey) != 64:
        raise ValueError('The public key must be a 64-byte array.')
    if len(presig) != 96:
        raise ValueError('The pre-signature must be a 96-byte array.')
    if len(sig) != 96:
        raise ValueError('The signature must be a 96-byte array.')
    if len(bStatement) != 64:
        raise ValueError('The adaptor statement must be a 64-byte array.')

    if not as_preverify(msg, pubkey, presig, bStatement):
        raise ValueError('The pre-signature must pass pre-verification.')
    if not schnorr_verify(msg, pubkey, sig):
        raise ValueError('The signature must pass verification.')

    # r_presig = point_from_bytes(presig[0:64])
    s_presig = int_from_bytes(presig[64:96])
    # r_sig = point_from_bytes(sig[0:64])
    s_sig = int_from_bytes(sig[64:96])

    witness = (s_sig - s_presig) %n
    debug_print_vars(settings.DEBUG)
    if not is_relation_satisfied(bStatement, witness):
        return 0
    return witness

if __name__ == '__main__':
    settings.init()
    ##custom test for pre-sign, pre-verify, adapt, extract 

    # seckey = bytes_from_int(3)
    # msg = bytes_from_int(0)
    # aux_rand = bytes_from_int(0)
    # pubkey = pubkey_gen(seckey)

    count_presign_errors = 0
    count_adapt_errors = 0 
    count_extract_errors = 0
    count_extraction_fail = 0
    total_tests = 10
    for i in range(1, total_tests+1):
        witness = random.randint(1, n-1)
        print("===== testing for witness: {}".format(witness))
        seckey = bytes_from_int(random.randint(1, n-1))
        msg = bytes_from_int(random.randint(1, n-1))
        aux_rand = bytes_from_int(random.randint(1, n-1))

        Statement = point_mul(G, witness)
        # if not has_even_y(Statement):
        #     print("bad check: {}".format(i))
        bStatement = bytes_from_point(Statement)
        pubkey = pubkey_gen(seckey)

        try:
            presig = as_presign(msg, seckey, aux_rand, bStatement)
        except RuntimeError as e:
            print(' * preSign test raised exception:', e)
            count_presign_errors += 1
            continue
        # preverify_output = as_preverify(msg, pubkey, presig, bStatement)
        # if not preverify_output:
        #     print('pre-verification FAILED')
        # print('pre-verification PASSED')
        
        try:
            sig = as_adapt(msg, pubkey, presig, bStatement, witness)
        except RuntimeError as e:
            print(' * Adapt test raised exception:', e)
            count_adapt_errors += 1
            continue
        # verify_output = schnorr_verify(msg, pubkey, sig)
        # if not verify_output:
        #     print('verification FAILED')
        # print('verification PASSED')
        
        try:
            extracted_witness = as_extract(msg, pubkey, presig, sig, bStatement)
        except RuntimeError as e:
            print(' * Extract test raised exception:', e)
            count_extract_errors += 1
        if not (witness == extracted_witness):
            count_extraction_fail += 1
        #     print('Extraction FAILED')
        # print('Extraction PASSED')

    print('total_tests: ', total_tests)
    print('count_presign_errors: ', count_presign_errors)
    print('count_adapt_errors: ', count_adapt_errors)
    print('count_extract_errors: ', count_extract_errors)
    print('count_extraction_fail: ', count_extraction_fail)

