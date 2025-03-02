import math
import random
import secrets
from py_ecc.bls12_381 import G1, curve_order, add, multiply, neg, eq, is_inf, Z1, FQ
from hashlib import sha256
from encryption.keygen import KeyGenerator  # Import KeyGenerator for key generation

# We need to implement our own versions of these functions
def normalize(point):
    """Normalize a point from projective to affine coordinates."""
    if is_inf(point):
        return point
    # For most ECC libraries, this would convert from projective to affine coordinates
    # In py_ecc, points are already in a specific form, so we'll just return them
    return point

def point_to_bytes(point):
    """Convert an elliptic curve point to bytes for hashing."""
    if is_inf(point):
        return b'INFINITY'
    # Convert to string representation for hashing
    return f"{point[0]}:{point[1]}".encode('utf-8')

class DiscreteLog:
    """Class for computing discrete logarithms on elliptic curves using Baby-Step Giant-Step."""

    @staticmethod
    def point_to_bytes(point):
        """Convert an elliptic curve point to bytes for hashing."""
        if is_inf(point):
            return b'INFINITY'
        # Convert to string representation for hashing
        return f"{point[0]}:{point[1]}".encode('utf-8')

    @classmethod
    def baby_step_giant_step(cls, base, target, limit):
        """
        Find x such that base^x = target using the baby-step giant-step algorithm.
        In additive notation: Find x such that x*base = target.

        Args:
            base: The base point (generator)
            target: The target point
            limit: Upper bound for x

        Returns:
            x such that x*base = target, or None if not found in range [0, limit)
        """
        # Handle special cases
        if is_inf(target):
            return 0  # target is identity, so x = 0

        if eq(base, target):
            return 1  # target = base, so x = 1

        # Calculate optimal step size: m = ceil(sqrt(limit))
        m = math.ceil(math.sqrt(limit))

        # BABY STEPS: Compute and store base^j for j in [0, m)
        baby_steps = {}

        # Compute each baby step directly
        for j in range(m):
            # Calculate j*base
            current = multiply(base, j)
            # Hash the point to use as dictionary key
            point_hash = sha256(cls.point_to_bytes(current)).digest()
            # Store j in the baby steps table
            baby_steps[point_hash] = j

        # Precompute the giant step factor: -m*base
        giant_step = multiply(neg(base), m)

        # GIANT STEPS: Check for matches with target + i*(-m*base) for i in [0, m)
        current = target
        for i in range(m):
            # Hash current point for lookup
            point_hash = sha256(cls.point_to_bytes(current)).digest()

            # Check if we have a match in the baby steps table
            if point_hash in baby_steps:
                j = baby_steps[point_hash]
                result = i * m + j

                # Verify the result is correct
                verification = multiply(base, result)
                if eq(verification, target):
                    return result

            # Move to next giant step: current = current + giant_step
            current = add(current, giant_step)

        # No solution found within the range
        return None

class ElGamalEncryption:
    """ElGamal encryption on elliptic curves with discrete log support."""

    def __init__(self, limit=2**16):
        """Initialize with a limit for discrete log operations."""
        self.limit = limit

    def keygen(self, seed=None):
        """Generate a key pair (sk, pk)."""
        if seed is not None:
            random.seed(seed)
            sk = random.randint(1, curve_order - 1)
        else:
            sk = secrets.randbelow(curve_order)
            while sk == 0:
                sk = secrets.randbelow(curve_order)

        pk = multiply(G1, sk)
        return sk, pk

    def encrypt(self, pk, message):
        """
        Encrypt a message (integer < limit) using ElGamal.
        Returns (C, R) where C = pk^r * G1^message, R = G1^r
        """
        if message >= self.limit:
            raise ValueError(f"Message must be < {self.limit}")

        # Generate random ephemeral key
        r = secrets.randbelow(curve_order)
        while r == 0:
            r = secrets.randbelow(curve_order)

        # Compute R = G1^r
        R = multiply(G1, r)

        # Compute S = pk^r
        S = multiply(pk, r)

        # Compute C = S * G1^message
        message_point = multiply(G1, message)
        C = add(S, message_point)

        return (C, R)

    def decrypt(self, sk, ciphertext):
        """
        Decrypt an ElGamal ciphertext (C, R) using secret key sk.
        Returns the original message if within discrete log limit.
        """
        C, R = ciphertext

        # Compute S = R^sk
        S = multiply(R, sk)

        # Compute M' = C - S
        M_prime = add(C, neg(S))

        # Find discrete log M' = message * G1
        message = DiscreteLog.baby_step_giant_step(G1, M_prime, self.limit)

        if message is None:
            raise ValueError(f"Discrete log failed - message may be outside limit ({self.limit})")

        return message