############################################################
#### Description:
# Our implementation of Schnorr signatures. 
# Follows bip-0340/reference.py.

# Author: Nikhil Vanjani
############################################################

from utils import *
import settings

# # Set DEBUG to True to get a detailed debug output including
# # intermediate values during key generation, signing, and
# # verification. This is implemented via calls to the
# # debug_print_vars(settings.DEBUG) function.
# #
# # If you want to print values on an individual basis, use
# # the pretty() function, e.g., print(pretty(foo)).
# DEBUG = False
# PS: DEBUG has been moved to settings.py

def schnorr_sign(msg: bytes, seckey: bytes, aux_rand: bytes) -> bytes:
    # d0 is the secret key, think sk
    d0 = int_from_bytes(seckey)
    if not (1 <= d0 <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    if len(aux_rand) != 32:
        raise ValueError('aux_rand must be 32 bytes instead of %i.' % len(aux_rand))
    # P is the public key corresponding to seckey
    P = point_mul(G, d0)
    assert P is not None
    pubkey = bytes_from_point(P)
    # d is the secret key
    d = d0 
    # d = d0 if has_even_y(P) else n - d0

    t = xor_bytes(bytes_from_int(d), tagged_hash("BIP0340/aux", aux_rand))
    k0 = int_from_bytes(tagged_hash("BIP0340/nonce", t + pubkey + msg)) % n
    if k0 == 0:
        raise RuntimeError('Failure. This happens only with negligible probability.')
    # R = g^{k0} is the elliptic curve point that will be used in the hash computation in e below. 
    R = point_mul(G, k0)
    assert R is not None
    # k denotes the random coins used by Sign algo. Think R = g^k.
    k = k0
    # k = n - k0 if not has_even_y(R) else k0

    e = int_from_bytes(tagged_hash("BIP0340/challenge", bytes_from_point(R) + pubkey + msg)) % n
    sig = bytes_from_point(R) + bytes_from_int((k + e * d) % n)
    debug_print_vars(settings.DEBUG)
    if not schnorr_verify(msg, pubkey, sig):
        raise RuntimeError('The created signature does not pass verification.')
    return sig

def schnorr_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    if len(pubkey) != 64:
        raise ValueError('The public key must be a 64-byte array.')
    if len(sig) != 96:
        raise ValueError('The signature must be a 96-byte array.')
    # public key in Point notation
    P = point_from_bytes(pubkey)
    if not is_point_on_curve(P):
        print('The public key must be a point on the elliptic curve.')
        return False

    r = point_from_bytes(sig[0:64])
    if not is_point_on_curve(r):
        print('The first component of signature must be a point on the elliptic curve.')
        return False

    s = int_from_bytes(sig[64:96])
    # print("check0")
    if (P is None) or (x(r) >= p) or (s >= n):
        debug_print_vars(settings.DEBUG)
        # print("check1")
        return False
    e = int_from_bytes(tagged_hash("BIP0340/challenge", sig[0:64] + pubkey + msg)) % n
    R = point_add(point_mul(G, s), point_mul(P, n - e))
    # if (R is None):
    #     print("check21")
    # if (not has_even_y(R)):
    #     print("check22")
    # if (x(R) != r):
    #     print("check23")
    # if (R is None) or (not has_even_y(R)) or (x(R) != r):
    if (R is None) or (R != r):
        debug_print_vars(settings.DEBUG)
        # print("check2")
        return False
    debug_print_vars(settings.DEBUG)
    return True

if __name__ == '__main__':
    settings.init()
    # test_vectors()

    # ipfelen = 100 
    # msg_bound = 100 
    # f_bound = 30
    # bound = ipfelen * msg_bound * f_bound
    # msg = []
    # f = []
    # max_val = 0
    # for j in range(5000):
    #     actual_val = 0
    #     for i in range(ipfelen):
    #         # msg_i = i+1
    #         # msg_i = random.randint(0, 2)
    #         msg_i = random.randint(0, msg_bound-1)
    #         msg.append(msg_i)
    #         f_i = random.randint(0, f_bound-1)
    #         f.append(f_i)
    #         actual_val = (actual_val + ((msg_i * f_i) %n)) % n
    #     max_val = max(max_val, actual_val)
    #     print('actual_val: {}, atleast 0.3 frac: {}'.format(actual_val, actual_val > 100000))
    # print('bound: {}, max_val: {}'.format(bound, max_val))

    ##custom test for sign, verify, adapt, extract 
    seckey = bytes_from_int(3)
    msg = bytes_from_int(0)
    aux_rand = bytes_from_int(0)
    pubkey = pubkey_gen(seckey)
    test_sig = schnorr_sign(msg, seckey, aux_rand)
    test_verify_output = schnorr_verify(msg, pubkey, test_sig)
    if not test_verify_output:
        print('test verification FAILED')
    print('test verification PASSED')


