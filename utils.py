############################################################
#### Description:
# Utility functions: secp256k1 curve ops, debuggin utils.

# Author: Nikhil Vanjani
############################################################

from typing import Tuple, Optional, Any
import hashlib
import binascii
import random
import time 
import os 
import concurrent.futures
import multiprocessing
import pickle
from math import ceil, sqrt
import sys

import settings
import group_ops

# # Set DEBUG to True to get a detailed debug output including
# # intermediate values during key generation, signing, and
# # verification. This is implemented via calls to the
# # debug_print_vars(settings.DEBUG) function.
# #
# # If you want to print values on an individual basis, use
# # the pretty() function, e.g., print(pretty(foo)).
# DEBUG = False
# PS: DEBUG has been moved to settings.py

# p is the field size. 
# p = 2^{256}− 2^{32} − 977 is prime
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
# n is order of the secp256k1 elliptic curve y^2 = x^3 + 7, 
# ie, it denotes the number of points on the elliptic curve
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Points are tuples of X and Y coordinates and the point at infinity is
# represented by the None keyword.
# G is the generator of the elliptic curve.
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

Point = Tuple[int, int]

LOCAL_OPS = False
OPTIMIZE_MULT = False
# count_add = 0
# count_mul = 0

if OPTIMIZE_MULT:
    two_pow_dict = {}
    tmp = group_ops.point_mul(G, 1)
    two_pow_dict[0] = tmp
    for i in range(1, 256):
        tmp = group_ops.point_add(tmp, tmp)
        two_pow_dict[i] = tmp


# This implementation can be sped up by storing the midstate after hashing
# tag_hash instead of rehashing it all the time.
def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()

def is_infinite(P: Optional[Point]) -> bool:
    return P is None

# returns x coordinate of point P
def x(P: Point) -> int:
    assert not is_infinite(P)
    return P[0]

# returns y coordinate of point P
def y(P: Point) -> int:
    assert not is_infinite(P)
    return P[1]

# performs group operation on two group elements. Think $g^a * g^b = g^{a+b}$
def point_add(P1: Optional[Point], P2: Optional[Point]) -> Optional[Point]:
    if LOCAL_OPS:
        if P1 is None:
            return P2
        if P2 is None:
            return P1
        if (x(P1) == x(P2)) and (y(P1) != y(P2)):
            return None
        if P1 == P2:
            lam = (3 * x(P1) * x(P1) * pow(2 * y(P1), p - 2, p)) % p
        else:
            lam = ((y(P2) - y(P1)) * pow(x(P2) - x(P1), p - 2, p)) % p
        x3 = (lam * lam - x(P1) - x(P2)) % p
        # global count_add
        # count_add += 1
        return (x3, (lam * (x(P1) - x3) - y(P1)) % p)
    else:
        # print('Point_add: P1: {}, P2: {}'.format(P1, P2))

        return group_ops.point_add(P1, P2)

# applies group operation n times on a group element. Think $(g^a)^n = g^{an}$
def point_mul(P: Optional[Point], n: int) -> Optional[Point]:
    # print('Point_mul: P: {}, n: {}'.format(P, n))
    if LOCAL_OPS:
        R = None
        for i in range(256):
            if (n >> i) & 1:
                R = point_add(R, P)
            P = point_add(P, P)
        # global count_mul
        # count_mul += 1
        return R
    elif OPTIMIZE_MULT: 
        # this is 3x faster for uniformly random input n and P=G.
        if P == G:
            # print("P = G")
            R = group_ops.point_mul(G, 0)
            for i in range(256):
                if (n >> i) & 1:
                    R = group_ops.point_add(R, two_pow_dict[i])
            return R
        else:
            return group_ops.point_mul(P, n)
            # # print("P != G")
            # R = group_ops.point_mul(G, 0)
            # for i in range(256):
            #     if (n >> i) & 1:
            #         # print('group_ops.point_add(R, P) with iteration: {}, R: {}, P: {}'.format(i, R, P))
            #         R = group_ops.point_add(R, P)
            #     # print('group_ops.point_add(P, P) with iteration: {},  P: {}'.format(i,P))
            #     if i == 255:
            #         continue
            #     P = group_ops.point_add(P, P)
            # return R
    else: 
        # this is still very slow if input n is uniformly random
        return group_ops.point_mul(P, n)

def point_mul_slow(P: Optional[Point], n: int) -> Optional[Point]:
    return group_ops.point_mul_slow(P, n)

# implements FastMult algorithm from Section 3.2 of https://cseweb.ucsd.edu/~mihir/papers/batch.pdf
## This is tested in ipfe.py in the method ipfe_pubkgen_sequential_fast and turns out this is slower than
## multiplying manually. TODO: Why? 
def point_batch_mul(count: int, P_dict: dict, n_dict: dict) -> Optional[Point]:
    MANUAL_GROUP_OPS = False
    if MANUAL_GROUP_OPS:
        val = group_ops.point_mul(G, 0)
        # print('point_batch_mul: starting val = {}'.format(val))

        for j in reversed(range(256)):
            # print('point_batch_mul: outer loop squaring val = {}'.format(val))
            val = group_ops.point_add(val, val)
            # print('point_batch_mul: outer loop result   val = {}'.format(val))
            for i in range(count):
                if ((n_dict[i] >> j) & 1):
                    # print('point_batch_mul: j = {}, n_dict[{}] = {}'.format(j, i, n_dict[i]))
                    # print('point_batch_mul: Adding val = {} and Points_dict[{}] = {}'.format(val, i, Points_dict[i]))
                    val = group_ops.point_add(val, P_dict[i])
                    # print('point_batch_mul: Add result val = {}'.format(val))
        
        # print('point_batch_mul: final val = {}'.format(val))
        return val
    else:
        # Points_dict = {}
        # for i in range(count):
        #     Points_dict[i] = point_from_bytes(P_dict[i])
        return group_ops.point_batch_mul(count, P_dict, n_dict)

def bytes_from_int(x: int) -> bytes:
    return x.to_bytes(32, byteorder="big")

#### return full 64 bytes representation
def bytes_from_point(P: Point) -> bytes:
    return bytes_from_int(x(P)) + bytes_from_int(y(P))

#### convert 64-byte representation of point to Point tuple
def point_from_bytes(bytesP: bytes) -> Optional[Point]:
    if len(bytesP) != 64:
        raise ValueError('The point must be a 64-byte array.')
    bytesPx = bytesP[0:32]
    bytesPy = bytesP[32:64]
    Px = int_from_bytes(bytesPx)
    Py = int_from_bytes(bytesPy)
    return (Px, Py)

def xor_bytes(b0: bytes, b1: bytes) -> bytes:
    return bytes(x ^ y for (x, y) in zip(b0, b1))

# given the x co-ordinate of the elliptic curve point, 
# computes the y co-ordinate and returns the point (x, y)
#### STOP using this as we will never compress anymore
# def lift_x(x: int) -> Optional[Point]:
#     if x >= p:
#         return None
#     y_sq = (pow(x, 3, p) + 7) % p
#     y = pow(y_sq, (p + 1) // 4, p)
#     if pow(y, 2, p) != y_sq:
#         return None
#     return (x, y if y & 1 == 0 else p-y)

#### check if point is on curve
def is_point_on_curve(P: Point) -> bool:
    if LOCAL_OPS:
        Px = x(P)
        Py = y(P)
        Py_sq = pow(Py, 2, p)
        if Px >= p:
            print("check1")
            debug_print_vars(settings.DEBUG)
            return False
        y_sq = (pow(Px, 3, p) + 7) % p
        # y_local = pow(y_sq, (p + 1) // 4, p)
        # if pow(y_local, 2, p) != y_sq:
        #     print("check2")
        #     debug_print_vars(settings.DEBUG)
        #     return False
        if y_sq != Py_sq:
            print("check3")
            debug_print_vars(settings.DEBUG)
            return False
        return True
    else:
        return group_ops.is_point_on_curve(P)

def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")

def hash_sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

#### STOP using this as we will never compress anymore
# def has_even_y(P: Point) -> bool:
#     assert not is_infinite(P)
#     return y(P) % 2 == 0

# given sk = x, computes pk = g^x
def pubkey_gen(seckey: bytes) -> bytes:
    d0 = int_from_bytes(seckey)
    if not (1 <= d0 <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    P = point_mul(G, d0)
    assert P is not None
    return bytes_from_point(P)

def is_relation_satisfied(bStatement: bytes, witness: int) -> bool:
    if len(bStatement) != 64:
        print('is_relation_satisfied: The adaptor statement must be a 64-byte array.')
        return False
    if not (1 <= witness <= n - 1):
        print('is_relation_satisfied: The witness must be an integer in the range 1..n-1.')
        return False

    Statement = point_from_bytes(bStatement)
    if not is_point_on_curve(Statement):
        print('is_relation_satisfied: The adaptor statement must be a point on the elliptic curve.')
        return False

    P = point_mul(G, witness)
    debug_print_vars(settings.DEBUG)
    assert P is not None
    if not (x(Statement) == x(P)):
        return False 
    # if not ((y(Statement) == y(P)) or (y(Statement) == p-y(P))):
    if not (y(Statement) == y(P)):
        return False 
    return True

def compute_inner_product(x1: list[int], x2: list[int], modulus: int) -> int:
	if len(x1) != len(x2):
		raise ValueError('compute_inner_product: vectors should be of same length. Lengths provided: vector1: {}, vector2: {}'.format(len(x1), len(x2)))
	ret = 0
	for i in range(len(x1)):
		ret = (ret + (x1[i] * x2[i] ) % modulus ) % modulus
	return ret

#### implement the baby step giant step algorithm. 
#### Running time: O(sqrt(bound)), Space: O(sqrt(bound))
def compute_discrete_log(P: Optional[Point], bound: int) -> int:
    m = ceil(sqrt(bound))
    # G_inv = point_mul(G, n-1)
    G_minus_m = point_mul(G, n-m)

    local_dict = {}
    tmp = point_mul(G, 0)
    local_dict[tmp] = 0
    for i in range(1, m+1):
        tmp = point_add(tmp, G)
        local_dict[tmp] = i

    group_elem = P
    for i in range(m+1):
        j = local_dict.get(group_elem)
        if j != None:
            return  i * m + j 
        else:
            group_elem = point_add(group_elem, G_minus_m)
    return -1

#
# The following code is only used for debugging
#
import inspect

def pretty(v: Any) -> Any:
    if isinstance(v, bytes):
        return '0x' + v.hex()
    if isinstance(v, int):
        return pretty(bytes_from_int(v))
    if isinstance(v, tuple):
        return tuple(map(pretty, v))
    return v

def debug_print_vars(debug) -> None:
	if debug:
		current_frame = inspect.currentframe()
		assert current_frame is not None
		frame = current_frame.f_back
		assert frame is not None
		print('   Variables in function ', frame.f_code.co_name, ' at line ', frame.f_lineno, ':', sep='')
		for var_name, var_val in frame.f_locals.items():
			if var_name == 'msg_dict':
				continue
			print('   ' + var_name.rjust(11, ' '), '==', pretty(var_val))

def dict_kv_length(d):
    klen = sum(sys.getsizeof(k) for k in d.keys())
    vlen = sum(sys.getsizeof(v) for v in d.values())
    return klen + vlen

if __name__ == '__main__':

    ops_test = True
    # ops_test = False

    # save_msg_dict_offline = True
    save_msg_dict_offline = False

    dlog_test = False

    batch_test = True

    if save_msg_dict_offline:
        bound = 10000000
        msg_dict = {}
        tmp = point_mul(G, 0)
        msg_dict[tmp] = 0
        dict_st = time.time()
        for i in range(1, bound):
            tmp = point_add(tmp, G)
            msg_dict[tmp] = i
        # print(msg_dict)
        dict_et = time.time()
        dict_time = dict_et - dict_st
        print('DictTime: {}'.format(dict_time))

        with open('msg_dict.pkl', 'wb') as fp:
            pickle.dump(msg_dict, fp)
            print('msg_dict saved successfully to file of bound: {}'.format(bound))


    if ops_test:
        r1 = random.randint(1, n-1)
        r2 = random.randint(1, n-1)

        st = time.time()
        r1p = point_mul(G, r1)
        et = time.time()
        testtime = et - st
        print("Time for point_mul(G, r1) : {}".format(testtime))

        r2p = point_mul(G, r2)

        st = time.time()
        r3p = point_add(r1p, r1p)
        et = time.time()
        testtime = et - st
        print("Time for point_add(r1, r1): {}".format(testtime))

        st = time.time()
        r4p = point_add(r1p, r2p)
        et = time.time()
        testtime = et - st
        print("Time for point_add(r1, r2): {}".format(testtime))

        st = time.time()
        r5p = point_mul(r1p, r2)
        et = time.time()
        testtime = et - st
        print("Time for point_mul(R, r2) : {}".format(testtime))

    if dlog_test:
        bound_power = 12
        # bound = n-1
        for i in range(bound_power):
            bound = 10 ** (i+1)
            s = random.randint(0, bound)
            P = point_mul(G, s)
            st = time.time()
            val = compute_discrete_log(P, bound)
            et = time.time()
            dlog_time = et - st
            print('Discrete log computation time: {}, bound: {}'.format(dlog_time, bound))
            if s != val:
                print('Discrete Log test FAILED: expected_val: {}, computed_val: {}'.format(s, val))

    if batch_test:
        batch_size = 10000
        Points_dict = {}
        n_dict = {}
        # local_N = N
        point_bound = 1000
        scalar_bound = 1000
        total_bound = batch_size * point_bound * scalar_bound
        for i in range(batch_size):
            exp = random.randint(1, point_bound-1)
            Points_dict[i] = point_mul(G, exp)
            # print('Points_dict[{}] = G^{}'.format(i, exp))
            n_dict[i] = random.randint(1, scalar_bound-1)
            # print('n_dict[{}] = {}'.format(i, n_dict[i]))
        # zero = point_mul(G, 0)

        st = time.time()
        batch_val = point_batch_mul(batch_size, Points_dict, n_dict)
        et = time.time()
        testtime = et - st
        print("Time for point_batch_mul(batch_size = {}, ...) : {}".format(batch_size, testtime))

        st = time.time()
        sequential_val = point_mul(G, 0)
        for i in range(batch_size):
            sequential_val = point_add(sequential_val, point_mul(Points_dict[i], n_dict[i]))
            # sequential_val = point_add(sequential_val, point_mul_slow(Points_dict[i], n_dict[i]))
        et = time.time()
        testtime = et - st
        print("Time for {} number of multiply                 : {}".format(batch_size, testtime))

        if sequential_val != batch_val:
            batch_val_dlog = compute_discrete_log(batch_val, total_bound)
            sequential_val_dlog = compute_discrete_log(sequential_val, total_bound)
            print('ERROR: sequential_val (G^{}) != batch_val (G^{})'.format(sequential_val_dlog, batch_val_dlog))
        else:
            print('SUCCESS: sequential_val = batch_val')

