import time
import random
import hashlib
from typing import Dict, Tuple, Any, List, Optional

from adaptors import as_presign, as_preverify, as_adapt, as_extract
from ipfe import ipfe_setup, ipfe_kgen, ipfe_enc, ipfe_dec_offline, ipfe_dec_online, ipfe_pubkgen
from utils import bytes_from_int, int_from_bytes, bytes_from_point, point_from_bytes, G, n, point_mul, point_add, is_point_on_curve, compute_discrete_log
from schnorr import schnorr_verify, schnorr_sign
import settings

settings.init()

"""
PROOF-OF-CONCEPT IMPLEMENTATION NOTICE:
This implementation uses simplified NIZK proofs (hash-based) 
for performance comparison purposes only.
In production, proper zero-knowledge proofs would be required.
"""

def simple_hash_proof(*args):
    """Simple hash-based proof for proof-of-concept"""
    proof_data = "".join(str(arg) for arg in args)
    return hashlib.sha256(proof_data.encode()).digest()

def simple_verification():
    """Simple verification that always succeeds for proof-of-concept"""
    return True

def matrix_det_2x2(matrix):
    return (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % n

def matrix_inv_2x2(matrix, det=None):
    if det is None:
        det = matrix_det_2x2(matrix)
    if det == 0:
        raise ValueError("Matrix is not invertible")
    
    det_inv = pow(det, -1, n)
    
    return [
        [(matrix[1][1] * det_inv) % n, (-matrix[0][1] * det_inv) % n],
        [(-matrix[1][0] * det_inv) % n, (matrix[0][0] * det_inv) % n]
    ]

def measure_time(func_name):
    def decorator(func):
        def wrapper(self, *args, **kwargs):
            start_time = time.time()
            result = func(self, *args, **kwargs)
            end_time = time.time()
            self.times[func_name] = end_time - start_time
            return result
        return wrapper
    return decorator

class FunctionalAdaptorSignatures:
    def __init__(self, security_param=128, vector_dim=100, bound=10000000, input_range=100, func_range=100):
        print("⚠️  PROOF-OF-CONCEPT: Using simplified cryptographic proofs")
        self.security_param = security_param
        self.vector_dim = vector_dim
        self.bound = bound
        self.input_range = input_range
        self.func_range = func_range
        self.times = {}
    
    @measure_time("Setup")
    def setup(self):
        """
        Simplified Setup for proof-of-concept
        Setup(1λ):
        1: Sample crs ← NIZK.Setup(1λ) (simplified)
        2: Sample pp′ ← IPFE.Gen(1λ)
        3: ret pp := (crs, pp′)
        """
        # Simplified CRS generation
        crs = {"security_param": self.security_param, "type": "simplified"}
        
        # Generate IPFE parameters
        ipfe_pp = self.ipfe_gen(self.security_param)
        
        pp = {"security_param": self.security_param, "ipfe": ipfe_pp}
        
        return crs, pp
    
    def ipfe_gen(self, security_param):
        """Generate IPFE parameters"""
        return {"security_param": security_param}
    
    @measure_time("AdGen")
    def adgen(self, pp, X, x):
        """
        Simplified AdGen for proof-of-concept
        AdGen(pp, X, x):
        1: Sample random coins r0, r1
        2: Let (mpk, msk) := IPFE.Setup(pp′, 1ℓ+1; r0)
        3: Sample t ←$ Zℓp, let xe := (xT, 0)T ∈ Zℓ+1p
        4: Let ct := IPFE.Enc(mpk, xe; r1)
        5: Let stmt := (X, pp′, mpk, ct), wit := (r0, r1, x)
        6: Let π ← NIZK.Prove(crs, stmt, wit) (simplified)
        7: ret advt := (mpk, ct, π), st := (msk, t)
        """
        # Sample random values
        r0 = random.randint(1, n-1)
        r1 = random.randint(1, n-1)
        
        # Generate IPFE master keys
        mpk, msk = ipfe_setup(self.vector_dim + 1)
        
        # Sample random vector t
        t = {}
        for i in range(self.vector_dim):
            t[i] = random.randint(1, n-1)
        
        # Create extended vector xe = (x^T, 0)^T
        ex = {}
        for i in range(self.vector_dim):
            ex[i] = x[i]
        ex[self.vector_dim] = 0
        
        # Encrypt
        ct0, ct1 = ipfe_enc(self.vector_dim + 1, mpk, ex)
        ct = {"ct0": ct0, "ct1": ct1}
        
        # Generate simplified zero-knowledge proof
        proof = simple_hash_proof(X, x, mpk, ct, "adgen")
        
        advt = {"mpk": mpk, "ct": ct, "proof": proof}
        st = {"msk": msk, "t": t, "x": x}
        
        return advt, st
    
    @measure_time("AdVerify")
    def adverify(self, pp, X, advt):
        """
        Simplified AdVerify for proof-of-concept
        AdVerify(pp, X, advt):
        1: ret NIZK.Vf(crs, (X, pp′, mpk, ct), π) (simplified)
        """
        # Simplified verification (always succeeds for proof-of-concept)
        return simple_verification()
    
    @measure_time("AuxGen")
    def auxgen(self, advt, st, y):
        """
        Simplified AuxGen for proof-of-concept
        AuxGen(advt, st, y):
        1: Parse advt = (mpk, ct, π), st = (msk, t)
        2: Let ye := (yT, fy(t))T ∈ Zℓ+1p
        3: Let pky := IPFE.PubKGen(mpk, ye)
        4: ret auxy := pky, πy := fy(t)
        """
        mpk = advt["mpk"]
        msk = st["msk"]
        t = st["t"]
        
        # Calculate fy(t) = <y, t>
        fy_t = 0
        for i in range(self.vector_dim):
            fy_t = (fy_t + (y[i] * t[i]) % n) % n
        
        # Create extended vector ye = (y^T, fy(t))^T
        ey = {}
        for i in range(self.vector_dim):
            ey[i] = y[i]
        ey[self.vector_dim] = fy_t
        
        # Generate public key
        pky = ipfe_pubkgen(self.vector_dim + 1, mpk, ey)
        
        return pky, fy_t
    
    @measure_time("AuxVerify")
    def auxverify(self, advt, y, auxy, pi_y):
        """
        Simplified AuxVerify for proof-of-concept
        AuxVerify(advt, y, auxy, πy):
        1: Parse advt = (mpk, ct, π), let ye := (yT, πy)T
        2: ret 1 iff auxy = IPFE.PubKGen(mpk, ye)
        """
        mpk = advt["mpk"]
        
        # Create extended vector ye = (y^T, pi_y)^T
        ey = {}
        for i in range(self.vector_dim):
            ey[i] = y[i]
        ey[self.vector_dim] = pi_y
        
        # Calculate expected public key
        expected_auxy = ipfe_pubkgen(self.vector_dim + 1, mpk, ey)
        
        # Check if keys match
        return auxy == expected_auxy
    
    @measure_time("FPreSign")
    def fpresign(self, advt, sk, m, X, y, auxy):
        """
        FPreSign(advt, sk, m, X, y, auxy):
        1: ret σe ← AS.PreSign(sk, m, auxy)
        """
        # Generate adaptor pre-signature
        sigma_tilde = as_presign(m, sk, bytes_from_int(random.randint(1, n-1)), auxy)
        return sigma_tilde
    
    @measure_time("FPreVerify")
    def fpreverify(self, advt, vk, m, X, y, auxy, pi_y, sigma_tilde):
        """
        FPreVerify(advt, vk, m, X, y, auxy, πy, σe):
        1: ret AuxVerify(advt, y, auxy, πy) ∧ AS.PreVerify(vk, m, auxy, σe)
        """
        # Verify auxiliary information and pre-signature
        if not self.auxverify(advt, y, auxy, pi_y):
            return False
        
        return as_preverify(m, vk, sigma_tilde, auxy)
    
    @measure_time("Adapt")
    def adapt(self, advt, st, vk, m, X, x, y, auxy, sigma_tilde):
        """
        Adapt(advt, st, vk, m, X, x, y, auxy, σe):
        1: Parse advt = (mpk, ct, π), st = (msk, t)
        2: Let ye := (yT, fy(t))T
        3: Let sky := IPFE.KGen(msk, ye)
        4: ret σ := AS.Adapt(vk, m, auxy, sky, σe)
        """
        mpk = advt["mpk"]
        msk = st["msk"]
        t = st["t"]
        
        # Calculate fy(t) = <y, t>
        fy_t = 0
        for i in range(self.vector_dim):
            fy_t = (fy_t + (y[i] * t[i]) % n) % n
        
        # Create extended vector ye = (y^T, fy(t))^T
        ey = {}
        for i in range(self.vector_dim):
            ey[i] = y[i]
        ey[self.vector_dim] = fy_t
        
        # Generate function secret key
        sky = ipfe_kgen(self.vector_dim + 1, msk, ey)
        
        # Adapt signature
        sigma = as_adapt(m, vk, sigma_tilde, auxy, sky)
        
        return sigma
    
    @measure_time("FExt")
    def fext(self, advt, sigma_tilde, sigma, X, y, auxy, m, vk, pi_y):
        """
        FExt(advt, σe, σ, X, y, auxy):
        1: Parse advt = (mpk, ct, π).
        2: Let z := AS.Ext(σe, σ, auxy)
        3: ret v := IPFE.Dec(z, ct)
        """
        # Extract function secret key from signature
        sky = as_extract(m, vk, sigma_tilde, sigma, auxy)
        
        # Parse ciphertext
        ct = advt["ct"]
        ct0 = ct["ct0"]
        ct1 = ct["ct1"]
        
        # Create extended vector ye = (y^T, pi_y)^T
        y_elongated = {}
        for i in range(self.vector_dim):
            y_elongated[i] = y[i]
        y_elongated[self.vector_dim] = pi_y
        
        # Prepare for offline decryption
        ct2 = ipfe_dec_offline(self.vector_dim + 1, y_elongated, ct1)
        
        # Calculate result with online decryption
        result = ipfe_dec_online(sky, ct0, ct2, self.bound)
        
        return result
    
    def run_protocol(self, use_fixed_seed=False, verbose=True):
        """Run the complete FAS protocol"""
        if use_fixed_seed:
            random.seed(42)
        else:
            current_time = int(time.time())
            random.seed(current_time)
        
        print("=== Running Simplified FAS Protocol (Proof-of-Concept) ===\n")
        
        crs, pp = self.setup()
        
        # Generate seller's input
        x = {}
        for i in range(self.vector_dim):
            x[i] = random.randint(1, self.input_range)
        
        print(f"Seller's input vector x: {[x[i] for i in range(min(10, self.vector_dim))]}" + 
              ("..." if self.vector_dim > 10 else ""))
        
        X = bytes_from_point(point_mul(G, sum(x.values()) % n))
        
        # Advertisement phase
        advt, st = self.adgen(pp, X, x)
        
        ad_verified = self.adverify(pp, X, advt)
        if not ad_verified:
            print("Advertisement verification failed!")
            return False
        
        # Generate buyer's function
        y = {}
        for i in range(self.vector_dim):
            y[i] = random.randint(1, self.func_range)
        
        print(f"Buyer's function vector y: {[y[i] for i in range(min(10, self.vector_dim))]}" + 
              ("..." if self.vector_dim > 10 else ""))
        
        # Calculate expected result
        expected = 0
        for i in range(self.vector_dim):
            expected = (expected + (x[i] * y[i]) % n) % n
        
        print(f"Expected inner product <x,y>: {expected}")
        
        # Auxiliary generation and verification
        auxy, pi_y = self.auxgen(advt, st, y)
        
        aux_verified = self.auxverify(advt, y, auxy, pi_y)
        if not aux_verified:
            print("Auxiliary verification failed!")
            return False
        
        # Generate signature keys
        sk = bytes_from_int(random.randint(1, n-1))
        vk = bytes_from_point(point_mul(G, int_from_bytes(sk)))
        
        m = b'fas_payment_transaction'
        
        # Fair exchange protocol
        sigma_tilde = self.fpresign(advt, sk, m, X, y, auxy)
        
        pre_verified = self.fpreverify(advt, vk, m, X, y, auxy, pi_y, sigma_tilde)
        if not pre_verified:
            print("Pre-signature verification failed!")
            return False
        
        sigma = self.adapt(advt, st, vk, m, X, x, y, auxy, sigma_tilde)
        
        sig_verified = schnorr_verify(m, vk, sigma)
        if not sig_verified:
            print("Signature verification failed!")
            return False
        
        # Extract result
        result = self.fext(advt, sigma_tilde, sigma, X, y, auxy, m, vk, pi_y)
        
        print(f"Function evaluation result: {result}")
        
        if result == expected:
            print("✓ Results match! The protocol computed the correct inner product.")
            success = True
        else:
            print("✗ Results do not match! There's an issue with the protocol computation.")
            success = False
        
        # Display timing results
        print("\n=== Execution Times ===")
        total_time = 0
        for step, time_taken in self.times.items():
            print(f"{step.ljust(12)}: {time_taken:.6f} seconds")
            total_time += time_taken
        
        print(f"{'Total'.ljust(12)}: {total_time:.6f} seconds")
        
        # Protocol summary
        print(f"\n=== Protocol Summary ===")
        print(f"Vector dimension: {self.vector_dim}")
        print(f"Input range: [1, {self.input_range}]")
        print(f"Function range: [1, {self.func_range}]")
        print(f"Discrete log bound: {self.bound}")
        print(f"Security level: {self.security_param}-bit (proof-of-concept)")
        
        return success

if __name__ == "__main__":
    # Configuration parameters for fair comparison with PFA
    vector_dim = 100        # Match with PFA
    dlog_bound = 10000000   # Discrete log calculation bound
    input_range = 100       # Input value range (1 to input_range)
    func_range = 100        # Function value range (1 to func_range)
    use_fixed_seed = False  # Set to True for reproducible testing
    
    print("Starting Simplified FAS Protocol Implementation (Proof-of-Concept)")
    print("=" * 70)
    
    fas = FunctionalAdaptorSignatures(
        security_param=128,
        vector_dim=vector_dim,
        bound=dlog_bound,
        input_range=input_range,
        func_range=func_range
    )
    fas.run_protocol(use_fixed_seed)