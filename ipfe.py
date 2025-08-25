############################################################
#### Description:
# Our implementation of [ABDP15] Inner Product Functional Encryption.

# Author: Nikhil Vanjani
############################################################

import sys
import time 
import pickle
import random
import multiprocessing as mp

from utils import *
from pke import *
import settings 

# # Set DEBUG to True to get a detailed debug output including
# # intermediate values during key generation, signing, and
# # verification. This is implemented via calls to the
# # debug_print_vars(settings.DEBUG) function.
# #
# # If you want to print values on an individual basis, use
# # the pretty() function, e.g., print(pretty(foo)).
# DEBUG = True
# PS: DEBUG has been moved to settings.py

#### IPFE implementation ===============================================================
def ipfe_setup(ipfelen: int) -> (dict, dict):
    debug_print_vars(settings.DEBUG)
    return pke_setup(ipfelen)

## outputs seckey such that its each co-ordinate is same 
## outputs pubkey such that its each co-ordinate is same 
def ipfe_setup_dummy(ipfelen: int) -> (dict, dict):
    debug_print_vars(settings.DEBUG)
    return pke_setup_dummy(ipfelen)

def ipfe_enc(ipfelen: int, mpk: dict, msg: dict) -> (bytes, dict):
    debug_print_vars(settings.DEBUG)
    return pke_encrypt(ipfelen, mpk, msg)

## Assumes each co-ordinate of pubkey is same 
## Assumes each co-ordinate of msg is same 
def ipfe_enc_dummy(ipfelen: int, mpk: dict, msg: dict) -> (bytes, dict):
    debug_print_vars(settings.DEBUG)
    return pke_encrypt_dummy(ipfelen, mpk, msg)

## Assumes each co-ordinate of pubkey is same 
## Assumes first ipfelen-1 co-ordinates of msg are same and last co-ordinate is zero.
def ipfe_enc_dummy_with_last_zero(ipfelen: int, mpk: dict, msg: dict) -> (bytes, dict):
    debug_print_vars(settings.DEBUG)
    return pke_encrypt_dummy_with_last_zero(ipfelen, mpk, msg)

def ipfe_kgen(ipfelen: int, msk: dict, f: dict) -> int:
    if len(msk) != ipfelen:
        raise ValueError('ipfe_kgen: The msk must be list of length: {}'.format(ipfelen))
    if len(f) != ipfelen:
        raise ValueError('ipfe_kgen: The function must be list of length: {}'.format(ipfelen))
    
    sk_f = 0
    for i in range(ipfelen):
        sk_f = (sk_f + (f[i] * int_from_bytes(msk[i]) ) % n ) % n
    debug_print_vars(settings.DEBUG)
    return sk_f

def ipfe_pubkgen_slow(ipfelen: int, mpk: dict, f: dict) -> bytes:
    # print("PubKGen: check1")
    if len(mpk) != ipfelen:
        raise ValueError('ipfe_kgen: The mpk must be list of length: {}'.format(ipfelen))
    if len(f) != ipfelen:
        raise ValueError('ipfe_kgen: The function must be list of length: {}'.format(ipfelen))

    # num CPUs 
    cpu_num = os.cpu_count()
    # print("PubKGen: check2: cpu_num: {}".format(cpu_num))
    with concurrent.futures.ProcessPoolExecutor(max_workers = cpu_num, mp_context=mp.get_context('spawn'), max_tasks_per_child = ipfelen) as executor:
        pk_intermediates = list(executor.map(point_mul, 
            (point_from_bytes(mpk[i]) for i in range(ipfelen)),
            (f[i] for i in range(ipfelen)),
            ))
    # print("PubKGen: check3")

    pk_f = point_mul(G, 0)
    # print("PubKGen: check4")

    for i in range(ipfelen):
        pk_f = point_add(pk_f, pk_intermediates[i])
    # print("PubKGen: check5")

    debug_print_vars(settings.DEBUG)
    return bytes_from_point(pk_f)

def ipfe_pubkgen_slow_sequential(ipfelen: int, mpk: dict, f: dict) -> bytes:
    # print("PubKGen: check1")
    if len(mpk) != ipfelen:
        raise ValueError('ipfe_kgen: The mpk must be list of length: {}'.format(ipfelen))
    if len(f) != ipfelen:
        raise ValueError('ipfe_kgen: The function must be list of length: {}'.format(ipfelen))

    # # num CPUs 
    # cpu_num = os.cpu_count()
    # # print("PubKGen: check2: cpu_num: {}".format(cpu_num))
    # with concurrent.futures.ProcessPoolExecutor(max_workers = 1, mp_context=mp.get_context('spawn'), max_tasks_per_child = ipfelen) as executor:
    #     pk_intermediates = list(executor.map(point_mul, 
    #         (point_from_bytes(mpk[i]) for i in range(ipfelen)),
    #         (f[i] for i in range(ipfelen)),
    #         ))
    # # print("PubKGen: check3")

    # pk_intermediates = []
    # for i in range(ipfelen):
    #     pk_intermediates.extend(point_mul(point_from_bytes(mpk[i]), f[i]))
    # # print(type(Point(pk_intermediates[0])))

    pk_f = point_mul(G, 0)
    # print("PubKGen: check4")

    for i in range(ipfelen):
        # print('index: {}'.format(i))
        # pk_f = point_add(pk_f, pk_intermediates[i])
        pk_f = point_add(pk_f, point_mul(point_from_bytes(mpk[i]), f[i]))
    # print("PubKGen: check5")

    debug_print_vars(settings.DEBUG)
    return bytes_from_point(pk_f)


def ipfe_pubkgen(ipfelen: int, mpk: dict, f: dict) -> bytes:
    # print("PubKGen: check1")
    if len(mpk) != ipfelen:
        raise ValueError('ipfe_kgen: The mpk must be list of length: {}'.format(ipfelen))
    if len(f) != ipfelen:
        raise ValueError('ipfe_kgen: The function must be list of length: {}'.format(ipfelen))

    Points_mpk = {}
    for i in range(ipfelen):
        Points_mpk[i] = point_from_bytes(mpk[i])
        # print('Points_dict[{}] = {}'.format(i, Points_dict[i]))

    # print('mpk: {}'.format(mpk))
    # print('f: {}'.format(f))
    pk_f = point_batch_mul(ipfelen, Points_mpk, f)

    debug_print_vars(settings.DEBUG)
    return bytes_from_point(pk_f)

# def ipfe_pubkgen_sequential_fast(ipfelen: int, mpk: dict, f: dict) -> bytes:
#     # print("PubKGen: check1")
#     if len(mpk) != ipfelen:
#         raise ValueError('ipfe_kgen: The mpk must be list of length: {}'.format(ipfelen))
#     if len(f) != ipfelen:
#         raise ValueError('ipfe_kgen: The function must be list of length: {}'.format(ipfelen))

#     # num CPUs 
#     cpu_num = os.cpu_count()
#     # print("PubKGen: check2: cpu_num: {}".format(cpu_num))
#     with concurrent.futures.ProcessPoolExecutor(max_workers = cpu_num, mp_context=mp.get_context('spawn'), max_tasks_per_child = ipfelen) as executor:
#         pk_intermediates = list(executor.map(point_batch_mul, 
#             (1 for i in range(ipfelen)),
#             ({0: point_from_bytes(mpk[i])} for i in range(ipfelen)),
#             ({0: f[i]} for i in range(ipfelen)),
#             ))
#     # print("PubKGen: check3")

#     pk_f = point_mul(G, 0)
#     # print("PubKGen: check4")

#     for i in range(ipfelen):
#         pk_f = point_add(pk_f, pk_intermediates[i])
#     # print("PubKGen: check5")

#     debug_print_vars(settings.DEBUG)
#     return bytes_from_point(pk_f)

# def ipfe_dec(ipfelen: int, mpk: list[bytes], f: list[int], sk_f: int, ct0: bytes, ct1: list[bytes], bound: int, msg_dict: dict) -> int:
def ipfe_dec(ipfelen: int, f: dict, sk_f: int, ct0: bytes, ct1: dict, bound: int) -> int:
    ct2 = ipfe_dec_offline(ipfelen, f, ct1)
    # ct2 = ipfe_dec_offline_slow(ipfelen, f, ct1)
    return ipfe_dec_online(sk_f, ct0, ct2, bound)

def ipfe_dec_offline_slow(ipfelen: int, f: dict, ct1: dict) -> bytes:
    # print("Dec offline: check0")
    if len(f) != ipfelen:
        raise ValueError('ipfe_kgen: The function must be list of length: {}'.format(ipfelen))
    if len(ct1) != ipfelen:
        raise ValueError('ipfe_kgen: The ct1 must be list of length: {}'.format(ipfelen))
    # print("Dec offline: check1")

    # num CPUs 
    cpu_num = os.cpu_count()
    # print("Dec offline: check2: cpu_num: {}".format(cpu_num))
    with concurrent.futures.ProcessPoolExecutor(max_workers = cpu_num, mp_context=mp.get_context('spawn'), max_tasks_per_child = ipfelen) as executor:
        ct2_intermediates = list(executor.map(point_mul, 
            (point_from_bytes(ct1[i]) for i in range(ipfelen)),
            (f[i] for i in range(ipfelen)),
            ))
    # print("Dec offline: check3")
    
    ct2 = point_mul(G, 0) 
    for i in range(ipfelen):
        ct2 = point_add(ct2, ct2_intermediates[i])
    # print("Dec offline: check4")

    return bytes_from_point(ct2)

def ipfe_dec_offline(ipfelen: int, f: dict, ct1: dict) -> bytes:
    # print("Dec offline: check0")
    if len(f) != ipfelen:
        raise ValueError('ipfe_kgen: The function must be list of length: {}'.format(ipfelen))
    if len(ct1) != ipfelen:
        raise ValueError('ipfe_kgen: The ct1 must be list of length: {}'.format(ipfelen))
    # print("Dec offline: check1")

    Points_ct1 = {}
    for i in range(ipfelen):
        Points_ct1[i] = point_from_bytes(ct1[i])
        # print('Points_dict[{}] = {}'.format(i, Points_dict[i]))

    # print('mpk: {}'.format(mpk))
    # print('f: {}'.format(f))
    ct2 = point_batch_mul(ipfelen, Points_ct1, f)

    return bytes_from_point(ct2)

def ipfe_dec_online(sk_f: int, ct0: bytes, ct2: bytes, bound: int) -> int:
    ct2_dict = {}
    ct2_dict[0] = (ct2)
    sk_f_dict = {}
    sk_f_dict[0] = bytes_from_int(sk_f)
    debug_print_vars(settings.DEBUG)
    val = pke_decrypt_sequential(1, sk_f_dict, ct0, ct2_dict, bound)
    return val[0]

if __name__ == '__main__':
    settings.init()

    # len_range = (1, 2, 10)
    len_range = (10 ** 2, 10 ** 3, 10 ** 4, 10 ** 5)
    # bound_range = (100, 10000)
    msg_bound = 1000
    f_bound = 1000

    # msg_dict = {}
    # dict_st = time.time()
    # with open('msg_dict.pkl', 'rb') as fp:
    #     msg_dict = pickle.load(fp)
    # tmp = point_mul(G, 0)
    # msg_dict[tmp] = 0
    # for i in range(1, bound):
    #     tmp = point_add(tmp, G)
    #     msg_dict[tmp] = i
    # print(msg_dict)
    # dict_et = time.time()
    # dict_time = dict_et - dict_st
    # print('DictTime: {}'.format(dict_time))

    DUMMY_SETUP_AND_ENC = True
    # DUMMY_SETUP_AND_ENC = False

    if DUMMY_SETUP_AND_ENC:
        for ipfelen in len_range:
            bound = ipfelen * msg_bound * f_bound # 100000
            msg = {}
            f = {}
            actual_val = 0
            dummy_msg = random.randint(0, msg_bound-1)
            for i in range(ipfelen):
                # msg_i = i+1
                # msg_i = random.randint(0, 2)
                msg[i] = dummy_msg
                f_i = random.randint(0, f_bound-1)
                f[i] = f_i
                actual_val = (actual_val + ((dummy_msg * f_i) %n)) % n


            st = time.time()

            setup_st = time.time()
            # (mpk, msk) = ipfe_setup(ipfelen)
            (mpk, msk) = ipfe_setup_dummy(ipfelen)
            setup_et = time.time()
            setup_time = setup_et - setup_st

            try:
                enc_st = time.time()
                # (ct0, ct1) = ipfe_enc(ipfelen, mpk, msg)
                (ct0, ct1) = ipfe_enc_dummy(ipfelen, mpk, msg)
                enc_et = time.time()
                enc_time = enc_et - enc_st
                try:
                    kgen_st = time.time()
                    sk_f = ipfe_kgen(ipfelen, msk, f)
                    kgen_et = time.time()
                    kgen_time = kgen_et - kgen_st

                    try: 
                        pubkgen_st = time.time()
                        # pk_f = ipfe_pubkgen_slow(ipfelen, mpk, f)
                        # pk_f = ipfe_pubkgen_slow_sequential(ipfelen, mpk, f)
                        # pk_f = ipfe_pubkgen_sequential_fast(ipfelen, mpk, f)
                        pk_f = ipfe_pubkgen(ipfelen, mpk, f)
                        pubkgen_et = time.time()
                        pubkgen_time = pubkgen_et - pubkgen_st

                        expected_pk_f = bytes_from_point(point_mul(G, sk_f))
                        if expected_pk_f != pk_f:
                            print('ipfe_pubkgen test FAILED: pk_f: {}, expected_pk_f: {}'.format(pk_f, expected_pk_f))
                    except RuntimeError as e:
                        print(' * ipfe_pubkgen test raised exception:', e)


                    try:
                        dec_off_st = time.time()
                        # ct2 = ipfe_dec_offline_slow(ipfelen, f, ct1)
                        ct2 = ipfe_dec_offline(ipfelen, f, ct1)
                        # val = ipfe_dec(ipfelen, f, sk_f, ct0, ct1, bound)
                        dec_off_et = time.time()
                        dec_off_time = dec_off_et - dec_off_st

                        dec_on_st = time.time()
                        val = ipfe_dec_online(sk_f, ct0, ct2, bound)
                        dec_on_et = time.time()
                        dec_on_time = dec_on_et - dec_on_st

                        # print('msg encrpted: {}'.format(msg))
                        # print('msg decrpted: {}'.format(val))
                        if val != actual_val:
                            print('ipfe_dec test FAILED: val = {}, actual_val = {}'.format(val, actual_val))
                            print('msg = {}'.format(msg))
                            print('f   = {}'.format(f))
                        # else: 
                        #     print('SUCCESS')
                    except RuntimeError as e:
                        print(' * ipfe_dec test raised exception:', e)
                        # print(' * pke_decrypt_check test raised exception:', e)
                except RuntimeError as e:
                    print(' * ipfe_kgen test raised exception:', e)

            except RuntimeError as e:
                print(' * ipfe_enc test raised exception:', e)
            
            et = time.time()
            elapsed_time = et - st 
            print('ipfelen: {} \t bound: {} \t ExecTime: {:.3f} \t SetupTime: {:.3f} \t EncTime: {:.3f} \t KGenTime: {:.3f} \t PubKGenTime: {:.3f} \t DecOffTime: {:.3f} \t DecOnTime: {:.3f}'.format(ipfelen, bound, elapsed_time, setup_time, enc_time, kgen_time, pubkgen_time, dec_off_time, dec_on_time))

    else:
        for ipfelen in len_range:
            bound = ipfelen * msg_bound * f_bound # 100000
            msg = {}
            f = {}
            actual_val = 0
            for i in range(ipfelen):
                # msg_i = i+1
                # msg_i = random.randint(0, 2)
                msg_i = random.randint(0, msg_bound-1)
                msg[i] = msg_i
                f_i = random.randint(0, f_bound-1)
                f[i] = f_i
                actual_val = (actual_val + ((msg_i * f_i) %n)) % n

            
            print('ipfelen       : {}'.format(ipfelen))
            print('sizeof msg_[0]: {}'.format(sys.getsizeof(msg[0])))
            print('sizeof msg    : {}'.format(dict_kv_length(msg)))

            st = time.time()

            setup_st = time.time()
            (mpk, msk) = ipfe_setup(ipfelen)
            # (mpk, msk) = ipfe_setup_dummy(ipfelen)
            setup_et = time.time()
            setup_time = setup_et - setup_st

            try:
                enc_st = time.time()
                (ct0, ct1) = ipfe_enc(ipfelen, mpk, msg)
                # (ct0, ct1) = ipfe_enc_dummy(ipfelen, mpk, msg)
                enc_et = time.time()
                enc_time = enc_et - enc_st
                try:
                    kgen_st = time.time()
                    sk_f = ipfe_kgen(ipfelen, msk, f)
                    kgen_et = time.time()
                    kgen_time = kgen_et - kgen_st

                    try: 
                        pubkgen_st = time.time()
                        # pk_f = ipfe_pubkgen_slow(ipfelen, mpk, f)
                        # pk_f = ipfe_pubkgen_slow_sequential(ipfelen, mpk, f)
                        # pk_f = ipfe_pubkgen_sequential_fast(ipfelen, mpk, f)
                        pk_f = ipfe_pubkgen(ipfelen, mpk, f)
                        pubkgen_et = time.time()
                        pubkgen_time = pubkgen_et - pubkgen_st

                        expected_pk_f = bytes_from_point(point_mul(G, sk_f))
                        if expected_pk_f != pk_f:
                            print('ipfe_pubkgen test FAILED: pk_f: {}, expected_pk_f: {}'.format(pk_f, expected_pk_f))
                    except RuntimeError as e:
                        print(' * ipfe_pubkgen test raised exception:', e)


                    try:
                        dec_off_st = time.time()
                        # ct2 = ipfe_dec_offline_slow(ipfelen, f, ct1)
                        ct2 = ipfe_dec_offline(ipfelen, f, ct1)
                        # val = ipfe_dec(ipfelen, f, sk_f, ct0, ct1, bound)
                        dec_off_et = time.time()
                        dec_off_time = dec_off_et - dec_off_st

                        dec_on_st = time.time()
                        val = ipfe_dec_online(sk_f, ct0, ct2, bound)
                        dec_on_et = time.time()
                        dec_on_time = dec_on_et - dec_on_st

                        # print('msg encrpted: {}'.format(msg))
                        # print('msg decrpted: {}'.format(val))
                        if val != actual_val:
                            print('ipfe_dec test FAILED: val = {}, actual_val = {}'.format(val, actual_val))
                            print('msg = {}'.format(msg))
                            print('f   = {}'.format(f))
                        # else: 
                        #     print('SUCCESS')
                    except RuntimeError as e:
                        print(' * ipfe_dec test raised exception:', e)
                        # print(' * pke_decrypt_check test raised exception:', e)
                except RuntimeError as e:
                    print(' * ipfe_kgen test raised exception:', e)

            except RuntimeError as e:
                print(' * ipfe_enc test raised exception:', e)
            
            et = time.time()
            elapsed_time = et - st 
            print('ipfelen: {} \t bound: {} \t ExecTime: {:.3f} \t SetupTime: {:.3f} \t EncTime: {:.3f} \t KGenTime: {:.3f} \t PubKGenTime: {:.3f} \t DecOffTime: {:.3f} \t DecOnTime: {:.3f}'.format(ipfelen, bound, elapsed_time, setup_time, enc_time, kgen_time, pubkgen_time, dec_off_time, dec_on_time))
