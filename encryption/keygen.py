import random
import secrets
from py_ecc.bls12_381 import G1, curve_order, multiply

class KeyGenerator:
    def __init__(self, seed):
        self.seed = seed
        self.p = curve_order  # order of the BLS12-381 G1 group (a prime)
        self.rng = random.Random(seed)

    def get_random_below(self, n):
        """Helper function to match secrets.randbelow API."""
        return self.rng.randrange(n)

    def generate_keypair(self):
        """Generate a BLS12-381 private key and public key with a given seed."""
        # Choose a random non-zero secret key x in Z_p
        x = self.get_random_below(self.p)
        while x == 0:
            x = self.get_random_below(self.p)

        # Compute public key point y = x * G1
        y = multiply(G1, x)
        return x, y