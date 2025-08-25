####
# Source: https://github.com/hanabi1224/Programming-Language-Benchmarks/blob/main/bench/algorithm/secp256k1/1.py
####
# ported from 1.ts

import sys
import os
import time 
import random
import concurrent.futures
import multiprocessing as mp

P = 2 ** 256 - 2 ** 32 - 977
N = 2 ** 256 - 432420386565659656852420866394968145599
GX = 55066263022277343669578718895168534326250603453777594175500187360389116729240
GY = 32670510020758816978083085130507043184471273380659243275938904335757337482424
BETA = 0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee
POW_2_128 = 2 ** 128

class JacobianPoint(object):
    def __init__(self, x, y, z):
        self.x = x
        self.y = y
        self.z = z

    def zero():
        return JacobianPoint(0, 1, 0)

    def base():
        return JacobianPoint(GX, GY, 1)

    def from_affine(p):
        return JacobianPoint(p.x, p.y, 1)

    def to_affine(self):
        inv_z = invert(self.z)
        inv_z_pow = inv_z ** 2
        x = mod(self.x * inv_z_pow)
        y = mod(self.y * inv_z * inv_z_pow)
        return Point(x, y)

    def negate(self):
        return JacobianPoint(self.x, mod(-self.y), self.z)

    def double(self):
        x1 = self.x
        y1 = self.y
        z1 = self.z
        a = mod(x1 ** 2)
        b = mod(y1 ** 2)
        c = mod(b ** 2)
        d = mod(2 * (mod(mod((x1 + b) ** 2)) - a - c))
        e = mod(3 * a)
        f = mod(e ** 2)
        x3 = mod(f - 2 * d)
        y3 = mod(e * (d - x3) - 8 * c)
        z3 = mod(2 * y1 * z1)
        return JacobianPoint(x3, y3, z3)

    def add(self, other):
        x1 = self.x
        y1 = self.y
        z1 = self.z
        x2 = other.x
        y2 = other.y
        z2 = other.z
        if x2 == 0 or y2 == 0:
            return self
        if x1 == 0 or y1 == 0:
            return other
        z1z1 = mod(z1 ** 2)
        z2z2 = mod(z2 ** 2)
        u1 = mod(x1 * z2z2)
        u2 = mod(x2 * z1z1)
        s1 = mod(y1 * z2 * z2z2)
        s2 = mod(mod(y2 * z1) * z1z1)
        h = mod(u2 - u1)
        r = mod(s2 - s1)
        if h == 0:
            if r == 0:
                return self.double()
            else:
                return JacobianPoint.zero()
        hh = mod(h ** 2)
        hhh = mod(h * hh)
        v = mod(u1 * hh)
        x3 = mod(r ** 2 - hhh - 2 * v)
        y3 = mod(r * (v - x3) - s1 * hhh)
        z3 = mod(z1 * z2 * h)
        return JacobianPoint(x3, y3, z3)

    def multiply_unsafe(self, n):
        (k1neg, k1, k2neg, k2) = split_scalar_endo(n)
        k1p = JacobianPoint.zero()
        k2p = JacobianPoint.zero()
        d = self
        while k1 > 0 or k2 > 0:
            if k1 & 1:
                k1p = k1p.add(d)
            if k2 & 1:
                k2p = k2p.add(d)
            d = d.double()
            k1 >>= 1
            k2 >>= 1
        if k1neg:
            k1p = k1p.negate()
        if k2neg:
            k2p = k2p.negate()
        k2p = JacobianPoint(mod(k2p.x * BETA), k2p.y, k2p.z)
        return k1p.add(k2p)

    # without using endomorphism
    def multiply_unsafe_slow(self, n):
        p = JacobianPoint.zero()
        d = self
        while n > 0:
            if n & 1:
                p = p.add(d)
            d = d.double()
            n >>= 1
        return p

    ### Note: I do not know if there is a way to fasten up batch_multiply_unsafe using endomorphisms.
    ### The main challenge seems that if in multiply_unsafe k1neg and k2neg are used to 
    ### conditionally negate k1p and k2p, but due to the batch setting, now we have k1neg[i] and k2neg[i] for all i in count.
    ### how to do conditional negations then? 
    ### If there was a way to ensure that k1[i] and k2[i] are never negative, 
    ### then maybe it's possible to use endomorphisms to speed up batch multiplications.
    # def batch_multiply_unsafe_fast(self, count, Jacobian_Points_dict, n_dict):
    #     p1 = self
    #     p2 = self
    #     k1neg = {}
    #     k1 = {}
    #     k2neg = {}
    #     k2 = {}
    #     for i in range(count):
    #         (k1neg[i], k1[i], k2neg[i], k2[i]) = split_scalar_endo(n_dict[i])

    #     # for i in range(count):
    #         # print('batch_multiply_unsafe_slow: n_dict[{}] = {}'.format(i, n_dict[i]))
    #     for j in reversed(range(256)):
    #         p1 = p1.double()
    #         p2 = p2.double()
    #         for i in range(count):                
    #             if ((k1[i] >> j) & 1):
    #                 # print('batch_multiply_unsafe_slow: index j = {} added'.format(j))
    #                 p1 = p1.add(Jacobian_Points_dict[i])
    #             if ((k2[i] >> j) & 1):
    #                 # print('batch_multiply_unsafe_slow: index j = {} added'.format(j))
    #                 p2 = p2.add(Jacobian_Points_dict[i])

    #             # else:
    #                 # print('batch_multiply_unsafe_slow: index j = {} NOT added'.format(j))
    #     return p


    def batch_multiply_unsafe(self, count, Jacobian_Points_dict, n_dict):
        p = self
        # for i in range(count):
            # print('batch_multiply_unsafe_slow: n_dict[{}] = {}'.format(i, n_dict[i]))
        for j in reversed(range(256)):
            p = p.double()
            for i in range(count):                
                if ((n_dict[i] >> j) & 1):
                    # print('batch_multiply_unsafe_slow: index j = {} added'.format(j))
                    p = p.add(Jacobian_Points_dict[i])
                # else:
                    # print('batch_multiply_unsafe_slow: index j = {} NOT added'.format(j))
        return p

    def batch_multiply_parallel_unsafe(self, count, Jacobian_Points_dict, n_dict):

        if count < 100:
            p = self
            return p.batch_multiply_unsafe(count, Jacobian_Points_dict, n_dict)
        else:
            cpu_num = os.cpu_count()
            list_size = cpu_num * 10
            self_list = []
            count_list = []
            Jacobian_Points_dict_list = []
            n_dict_list = []
            chunk_count = count // list_size # computes count / cpu_num and rounds down result to integer
            chunk_remainder = count % list_size
            # print('count                 : {}'.format(count))
            # print('cpu_num               : {}'.format(cpu_num))
            # print('chunk_count           : {}'.format(chunk_count))
            # print('chunk_remainder       : {}'.format(chunk_remainder))
            for i in range(list_size):
                if i == list_size-1:
                    self_list.insert(i, self)
                else:
                    self_list.insert(i, JacobianPoint.zero())

                chunk_size = chunk_count
                if i == list_size-1:
                    chunk_size = chunk_count + chunk_remainder
                count_list.insert(i, chunk_size)

                chunk_points_dict = {}
                chunk_n_dict = {}
                for j in range(chunk_size):
                    chunk_points_dict[j] = Jacobian_Points_dict[i * chunk_count + j]
                    chunk_n_dict[j] = n_dict[i * chunk_count + j]
                Jacobian_Points_dict_list.insert(i, chunk_points_dict)
                n_dict_list.insert(i, chunk_n_dict)

            # print('self_list                : {}'.format(self_list))
            # print('count_list               : {}'.format(count_list))
            # print('Jacobian_Points_dict_list: {}'.format(Jacobian_Points_dict_list))
            # print('n_dict_list              : {}'.format(n_dict_list))
            with concurrent.futures.ProcessPoolExecutor(max_workers = cpu_num, mp_context=mp.get_context('spawn'), max_tasks_per_child = list_size // cpu_num) as executor:
                p_list = list(executor.map(batch_multiply_unsafe_objectless, 
                    self_list,
                    count_list, 
                    Jacobian_Points_dict_list,
                    n_dict_list
                    ))
            ret_val = JacobianPoint.zero()
            for i in range(len(p_list)):
                ret_val = ret_val.add(p_list[i])
            return ret_val

def batch_multiply_unsafe_objectless(my_object, count, Jacobian_Points_dict, n_dict) -> JacobianPoint:
    return my_object.batch_multiply_unsafe(count, Jacobian_Points_dict, n_dict)

class Point(object):
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def zero():
        return Point(0, 0)

    def base():
        return Point(GX, GY)

    def add(self, other):
        return JacobianPoint.from_affine(self).add(JacobianPoint.from_affine(other)).to_affine()

    def multiply(self, scalar):
        return JacobianPoint.from_affine(self).multiply_unsafe(scalar).to_affine()

    def multiply_slow(self, scalar):
        return JacobianPoint.from_affine(self).multiply_unsafe_slow(scalar).to_affine()

    # def batch_multiply_fast(self, count, Points_dict, scalars_dict):
    #     Jacobian_Points_dict = {}
    #     for i in range(count):
    #         Jacobian_Points_dict[i] = JacobianPoint.from_affine(Points_dict[i])
    #     return JacobianPoint.from_affine(self).batch_multiply_unsafe_fast(count, Jacobian_Points_dict, scalars_dict).to_affine()

    def batch_multiply(self, count, Points_dict, scalars_dict):
        Jacobian_Points_dict = {}
        for i in range(count):
            Jacobian_Points_dict[i] = JacobianPoint.from_affine(Points_dict[i])
        # return JacobianPoint.from_affine(self).batch_multiply_unsafe(count, Jacobian_Points_dict, scalars_dict).to_affine()
        return JacobianPoint.from_affine(self).batch_multiply_parallel_unsafe(count, Jacobian_Points_dict, scalars_dict).to_affine()


def mod(a, b=P):
    r = a % b
    if r < 0:
        return r + b
    return r


def invert(number, modulo=P):
    a = mod(number, modulo)
    b = modulo
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q = b // a
        r = b % a
        m = x - u * q
        n = y - v * q
        b, a = a, r
        x, y = u, v
        u, v = m, n
    return mod(x, modulo)


def div_nearest(a, b):
    return (a + b // 2) // b


def split_scalar_endo(k):
    n = N
    a1 = 0x3086d221a7d46bcde86c90e49284eb15
    b1 = -0xe4437ed6010e88286f547fa90abfe4c3
    a2 = 0x114ca50f7a8e2f3f657c1108d9d44cfd8
    b2 = a1
    c1 = div_nearest(b2 * k, n)
    c2 = div_nearest(-b1 * k, n)
    k1 = mod(k - c1 * a1 - c2 * a2, n)
    k2 = mod(-c1 * b1 - c2 * b2, n)
    k1neg = k1 > POW_2_128
    k2neg = k2 > POW_2_128
    if k1neg:
        k1 = n - k1
    if k2neg:
        k2 = n - k2
    return (k1neg, k1, k2neg, k2)


def main():
    n = 1 if len(sys.argv) < 2 else int(sys.argv[1])
    private_key = 0x2DEE927079283C3C4FCA3EF970FF4D38B64592E3FE0AB0DAD9132D70B5BC7693
    point = Point.base()
    for i in range(0, n):
        point = point.multiply(private_key)
    print(f"{point.x:x},{point.y:x}")

    ops_test = True
    batch_test = True

    if ops_test:
        r1 = random.randint(1, N-1)
        r2 = random.randint(1, N-1)

        G = Point.base()
        st = time.time()
        r1p = G.multiply(r1)
        et = time.time()
        testtime = et - st
        print("Time for multiply(G, r1) : {}".format(testtime))

        G = Point.base()
        st = time.time()
        r1p_slow = G.multiply_slow(r1)
        et = time.time()
        testtime = et - st
        print("Time for multiply_slow(G, r1) : {}".format(testtime))

        r2p = G.multiply(r2)

        st = time.time()
        r3p = r1p.add(r1p)
        et = time.time()
        testtime = et - st
        print("Time for add(r1, r1): {}".format(testtime))

        st = time.time()
        r4p = r1p.add(r2p)
        et = time.time()
        testtime = et - st
        print("Time for add(r1, r2): {}".format(testtime))

        st = time.time()
        r5p = r1p.multiply(r2)
        et = time.time()
        testtime = et - st
        print("Time for multiply(R, r2) : {}".format(testtime))

        st = time.time()
        r5p = r1p.multiply_slow(r2)
        et = time.time()
        testtime = et - st
        print("Time for multiply_slow(R, r2) : {}".format(testtime))

    if batch_test:
        batch_size = 1
        Points_dict = {}
        n_dict = {}
        # local_N = N
        local_N = 4
        for i in range(batch_size):
            G = Point.base()
            Points_dict[i] = G.multiply(random.randint(1, local_N-1))
            print('Points_dict[{}] = {}'.format(i, Points_dict[i]))
            n_dict[i] = random.randint(1, local_N-1)
            print('n_dict[{}] = {}'.format(i, n_dict[i]))
        zero = Point.zero()

        st = time.time()
        batch_val = zero.batch_multiply_slow(batch_size, Points_dict, n_dict)
        et = time.time()
        testtime = et - st
        print("Time for batch_multiply_slow(batch_size = {}, ...) : {}".format(batch_size, testtime))

        st = time.time()
        sequential_val = Point.zero()
        for i in range(batch_size):
            sequential_val = sequential_val.add(Points_dict[i].multiply_slow(n_dict[i]))
        et = time.time()
        testtime = et - st
        print("Time for {} number of multiply_slow : {}".format(batch_size, testtime))

        if sequential_val != batch_val:
            print('ERROR: sequential_val != batch_val')
        else:
            print('SUCCESS: sequential_val = batch_val')

if __name__ == '__main__':
    main()