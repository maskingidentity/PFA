############################################################
#### Description:
# Our implementation of group ops. 

# Author: Nikhil Vanjani
############################################################
from typing import Tuple, Optional, Any
from libnum import ecc
import sys
import random
import time 

import secp256k1
import fast_secp256k1

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

# coefficients of equation y^2 = x^3 + ax + b.
# For secp256k1 curve, y^2 = x^3 + 7
a = 0
b = 7
c = ecc.Curve(a, b, p, G)

Point = Tuple[int, int]

USE_SECP256K1_LIB = False
USE_FAST_SECP256K1_LIB = True


def bytes_from_int(x: int) -> bytes:
    return x.to_bytes(32, byteorder="big")

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
    if USE_FAST_SECP256K1_LIB:
        P1_Pt = fast_secp256k1.Point(x(P1), y(P1))
        P2_Pt = fast_secp256k1.Point(x(P2), y(P2))
        res_Pt = P1_Pt.add(P2_Pt)
        return (res_Pt.x, res_Pt.y)
    elif USE_SECP256K1_LIB:
        P1_Pt = secp256k1.Pt(secp256k1.Fq(x(P1)), secp256k1.Fq(y(P1)))
        P2_Pt = secp256k1.Pt(secp256k1.Fq(x(P2)), secp256k1.Fq(y(P2)))
        res_Pt = P1_Pt + P2_Pt
        return (res_Pt.x.x, res_Pt.y.x)
    else:
        return c.add(P1, P2)

# applies group operation n times on a group element. Think $(g^a)^n = g^{an}$
def point_mul(P: Optional[Point], n: int) -> Optional[Point]:
    if USE_FAST_SECP256K1_LIB:
        P_Pt = fast_secp256k1.Point(x(P), y(P))
        res_Pt = P_Pt.multiply(n)
        return (res_Pt.x, res_Pt.y)
    elif USE_SECP256K1_LIB:
        P_Pt = secp256k1.Pt(secp256k1.Fq(x(P)), secp256k1.Fq(y(P)))
        res_Pt = P_Pt * secp256k1.Fr(n)
        return (res_Pt.x.x, res_Pt.y.x)
    else:
        return c.power(P, n)

def point_mul_slow(P: Optional[Point], n: int) -> Optional[Point]:
    if USE_FAST_SECP256K1_LIB:
        P_Pt = fast_secp256k1.Point(x(P), y(P))
        res_Pt = P_Pt.multiply_slow(n)
        return (res_Pt.x, res_Pt.y)

def point_batch_mul(count: int, Points_dict: dict, n_dict: dict) -> Optional[Point]:
    if USE_FAST_SECP256K1_LIB:
        # zero_Pt = fast_secp256k1.Point(0, 0)
        zero_Pt = fast_secp256k1.Point.zero()
        fast_P_dict = {}
        for i in range(count):
            fast_P_dict[i] = fast_secp256k1.Point(x(Points_dict[i]), y(Points_dict[i]))
        res_Pt = zero_Pt.batch_multiply(count, fast_P_dict, n_dict)
        return (res_Pt.x, res_Pt.y)        

#### check if point is on curve
def is_point_on_curve(P: Point) -> bool:
    return c.check(P)

if __name__ == '__main__':

    

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
