# utils.py - Utility functions for PFA protocol
import hashlib
import random
from typing import Tuple, Optional

# Elliptic curve parameters (secp256k1)
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)

def mod_inverse(a: int, m: int) -> int:
    """Compute modular inverse using extended Euclidean algorithm"""
    if a < 0:
        a = (a % m + m) % m
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % m

def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean Algorithm"""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def point_add(P: Tuple[int, int], Q: Tuple[int, int]) -> Tuple[int, int]:
    """Add two points on elliptic curve"""
    if P is None:
        return Q
    if Q is None:
        return P
    
    x1, y1 = P
    x2, y2 = Q
    
    if x1 == x2:
        if y1 == y2:
            # Point doubling
            s = (3 * x1 * x1 * mod_inverse(2 * y1, p)) % p
        else:
            return None  # Point at infinity
    else:
        # Point addition
        s = ((y2 - y1) * mod_inverse(x2 - x1, p)) % p
    
    x3 = (s * s - x1 - x2) % p
    y3 = (s * (x1 - x3) - y1) % p
    
    return (x3, y3)

def point_mul(point: Tuple[int, int], scalar: int) -> Tuple[int, int]:
    """Scalar multiplication of point"""
    if scalar == 0:
        return None
    if scalar == 1:
        return point
    
    result = None
    addend = point
    
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    
    return result

def is_point_on_curve(point: Tuple[int, int]) -> bool:
    """Check if point is on the elliptic curve y^2 = x^3 + 7"""
    if point is None:
        return True
    x, y = point
    return (y * y) % p == (x * x * x + 7) % p

def bytes_from_int(x: int) -> bytes:
    """Convert integer to bytes"""
    return x.to_bytes(32, byteorder='big')

def int_from_bytes(b: bytes) -> int:
    """Convert bytes to integer"""
    return int.from_bytes(b, byteorder='big')

def bytes_from_point(point: Tuple[int, int]) -> bytes:
    """Convert point to compressed bytes representation"""
    if point is None:
        return b'\x00' * 33
    x, y = point
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    return prefix + x.to_bytes(32, byteorder='big')

def point_from_bytes(b: bytes) -> Tuple[int, int]:
    """Convert bytes to point (simplified)"""
    if len(b) != 33:
        raise ValueError("Invalid point bytes length")
    
    if b[0] == 0:
        return None
    
    x = int.from_bytes(b[1:], byteorder='big')
    
    # Compute y coordinate from x
    y_squared = (pow(x, 3, p) + 7) % p
    y = pow(y_squared, (p + 1) // 4, p)
    
    if b[0] == 0x03 and y % 2 == 0:
        y = p - y
    elif b[0] == 0x02 and y % 2 == 1:
        y = p - y
    
    return (x, y)

def compute_discrete_log(target: Tuple[int, int], base: Tuple[int, int], bound: int) -> Optional[int]:
    """Compute discrete logarithm using baby-step giant-step (for small bounds)"""
    if target is None:
        return 0
    
    # Baby steps
    baby_steps = {}
    current = None
    
    for i in range(int(bound**0.5) + 1):
        if current == target:
            return i
        baby_steps[current] = i
        current = point_add(current, base)
    
    # Giant steps
    giant_step = point_mul(base, -int(bound**0.5))
    gamma = target
    
    for j in range(int(bound**0.5) + 1):
        if gamma in baby_steps:
            candidate = j * int(bound**0.5) + baby_steps[gamma]
            if candidate < bound:
                return candidate
        gamma = point_add(gamma, giant_step)
    
    return None

# adaptors.py - Adaptor signature functions
def as_presign(message: bytes, secret_key: bytes, randomness: bytes, statement: bytes) -> dict:
    """Generate adaptor pre-signature"""
    # Simplified adaptor pre-signature
    r = int_from_bytes(randomness) % n
    R = point_mul(G, r)
    
    # Hash for challenge
    h = hashlib.sha256(message + bytes_from_point(R) + statement).digest()
    c = int_from_bytes(h) % n
    
    # Pre-signature component
    s = (r + c * int_from_bytes(secret_key)) % n
    
    return {
        'R': R,
        's': s,
        'statement': statement
    }

def as_preverify(message: bytes, public_key: bytes, pre_sig: dict, statement: bytes) -> bool:
    """Verify adaptor pre-signature"""
    try:
        R = pre_sig['R']
        s = pre_sig['s']
        
        # Recompute challenge
        h = hashlib.sha256(message + bytes_from_point(R) + statement).digest()
        c = int_from_bytes(h) % n
        
        # Verify: g^s = R + c*PK
        pk_point = point_from_bytes(public_key)
        left = point_mul(G, s)
        right = point_add(R, point_mul(pk_point, c))
        
        return left == right
    except:
        return False

def as_adapt(message: bytes, vk: bytes, pre_sig: dict, aux: bytes, witness: int) -> dict:
    """Adapt pre-signature to full signature"""
    try:
        R = pre_sig['R']
        s = pre_sig['s']
        
        # Add witness to create valid signature
        s_adapted = (s + witness) % n
        
        return {
            'R': R,
            's': s_adapted
        }
    except:
        return None

def as_extract(message: bytes, vk: bytes, pre_sig: dict, sig: dict, aux: bytes) -> Optional[int]:
    """Extract witness from pre-signature and signature"""
    try:
        s_pre = pre_sig['s']
        s_sig = sig['s']
        
        # Extract witness
        witness = (s_sig - s_pre) % n
        return witness
    except:
        return None

# schnorr.py - Schnorr signature functions
def schnorr_sign(message: bytes, secret_key: bytes) -> dict:
    """Generate Schnorr signature"""
    k = random.randint(1, n-1)
    R = point_mul(G, k)
    
    # Challenge
    h = hashlib.sha256(message + bytes_from_point(R)).digest()
    c = int_from_bytes(h) % n
    
    # Signature
    s = (k + c * int_from_bytes(secret_key)) % n
    
    return {
        'R': R,
        's': s
    }

def schnorr_verify(message: bytes, public_key: bytes, signature: dict) -> bool:
    """Verify Schnorr signature"""
    try:
        R = signature['R']
        s = signature['s']
        
        # Recompute challenge
        h = hashlib.sha256(message + bytes_from_point(R)).digest()
        c = int_from_bytes(h) % n
        
        # Verify: g^s = R + c*PK
        pk_point = point_from_bytes(public_key)
        left = point_mul(G, s)
        right = point_add(R, point_mul(pk_point, c))
        
        return left == right
    except:
        return False

# settings.py - Initialize settings
def init():
    """Initialize global settings"""
    pass

# Test the implementation
if __name__ == "__main__":
    # Test elliptic curve operations
    print("Testing elliptic curve operations...")
    
    # Test point multiplication
    P = point_mul(G, 123)
    print(f"G * 123 = {P}")
    
    # Test point addition
    Q = point_add(P, G)
    print(f"P + G = {Q}")
    
    # Test bytes conversion
    P_bytes = bytes_from_point(P)
    P_recovered = point_from_bytes(P_bytes)
    print(f"Point serialization works: {P == P_recovered}")
    
    # Test adaptor signatures
    print("\nTesting adaptor signatures...")
    sk = bytes_from_int(random.randint(1, n-1))
    pk = bytes_from_point(point_mul(G, int_from_bytes(sk)))
    
    message = b"test message"
    statement = bytes_from_point(point_mul(G, 42))
    randomness = bytes_from_int(random.randint(1, n-1))
    
    # Pre-sign
    pre_sig = as_presign(message, sk, randomness, statement)
    print(f"Pre-signature generated: {pre_sig is not None}")
    
    # Pre-verify
    valid = as_preverify(message, pk, pre_sig, statement)
    print(f"Pre-signature verification: {valid}")
    
    # Adapt
    witness = 42
    sig = as_adapt(message, pk, pre_sig, b"aux", witness)
    print(f"Signature adaptation: {sig is not None}")
    
    # Extract
    extracted = as_extract(message, pk, pre_sig, sig, b"aux")
    print(f"Witness extraction: {extracted == witness}")
    
    print("\nAll tests completed!")