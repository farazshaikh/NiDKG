"""
This module implements Shamir's Secret Sharing scheme with resharing capabilities.

Classes:
- SharingBuilder: A configuration class for creating shares.
- ReconstructionBuilder: A configuration class for reconstructing the secret from shares.
- SecretSharing: A class to represent the Shamir secret sharing + Resharing scheme.

Functions:
----------
- resharing_test(): Tests the resharing functionality of the SecretSharing class.
- basic_test(): Tests the basic functionality of the SecretSharing class.

Usage:
------
Run the module as a script to execute the basic and resharing tests:
    python ss.py

Example:
# Create a sharing scheme with t=5, n=10
secret_sharing = SecretSharing(SharingBuilder(test_secret, 5, 10, test_prime, seed=42))

# Reconstruct the secret using all shares

# Select a subset of shares equal to the threshold and reconstruct the secret
assert reconstructed_secret_from_threshold == test_secret
"""
from sympy import mod_inverse
from sympy import Integer
from random import randint
from collections import defaultdict
from prettytable import PrettyTable
from random import seed as random_seed
from random import sample
from typing import Dict, Optional
import copy

Prime = Integer("208351617316091241234326746312124448251235562226470491514186331217050270460481")

class SharingBuilder:
    def __init__(self, secret: Integer, threshold: int, num_shares: int, prime: Integer, seed: Optional[int] = None) -> None:
        self.secret = secret
        self.threshold = threshold
        self.num_shares = num_shares
        self.prime = prime
        self.seed = seed

class ReconstructionBuilder:
    def __init__(self, shares: Dict[int, Integer], threshold: int, prime: Integer) -> None:
        # this is explicitly allowed as one can build a new sharing with higher threshold
        # if threshold > len(shares):
        #     raise ValueError("Threshold cannot be greater than the number of shares")
        self.shares = shares
        self.threshold = threshold
        self.num_shares = len(shares)
        self.prime = prime


class SecretSharing:
    """
    A class to handle secret sharing and reconstruction using Shamir's Secret Sharing scheme.

    Attributes:
        shares (Dict[int, Integer]): A dictionary of share indices and their corresponding values.
        threshold (int): The minimum number of shares required to reconstruct the secret.
        num_shares (int): The total number of shares.
        prime (Integer): A prime number used in the calculations.
        secret (Integer): The secret to be shared or reconstructed.

    Methods:
        __init__(config: SharingBuilder | ReconstructionBuilder) -> None:
            Initializes the SecretSharing object with either a SharingBuilder or ReconstructionBuilder configuration.

        display() -> None:
            Displays the shares and the secret in a tabular format.

        _generate_shares(secret: Integer, threshold: int, num_shares: int, prime: Integer, seed: Optional[int] = None) -> None:
            Generates the shares based on the given secret, threshold, number of shares, prime, and optional seed.

        reshare_shares(threshold: int, num_shares: int, seed: Optional[int] = None) -> 'SecretSharing':
            Reshares the existing shares to create new shares with a specified threshold and number of shares.

        select_threshold_shares() -> 'SecretSharing':
            Selects a subset of shares equal to the threshold and returns a new SecretSharing object with these shares.

        reconstruct_secret() -> Integer:
            Reconstructs the secret from the available shares using Lagrange interpolation.
    """
    def __init__(self, config: SharingBuilder | ReconstructionBuilder) -> None:
        if isinstance(config, SharingBuilder):
            self.shares: Dict[int, Integer] = {}
            self.threshold: int = config.threshold
            self.num_shares: int = config.num_shares
            self.prime: Integer = config.prime
            self.secret: Integer = config.secret
            self._generate_shares(config.secret, config.threshold, config.num_shares, config.prime, config.seed)
        elif isinstance(config, ReconstructionBuilder):
            self.shares: Dict[int, Integer] = config.shares
            self.threshold: int = config.threshold
            self.num_shares: int = config.num_shares
            self.prime: Integer = config.prime
            self.secret: Integer = self.reconstruct_secret()
        else:
            raise TypeError("Config must be either SharingBuilder or ReconstructionBuilder")
        if self.threshold > self.num_shares:
            raise ValueError("Threshold cannot be greater than the number of shares")

    def display(self) -> None:
        table = PrettyTable()
        t = self.threshold
        n = self.num_shares
        table.field_names = [f"Share Index {t}/{n}", "Share Value"]
        table.add_row(["SS f(0)",  self.secret])
        for index in sorted(self.shares.keys()):
            table.add_row([f"f({index})", self.shares[index]])
        print(table)

    def _generate_shares(self, secret: Integer, threshold: int, num_shares: int, prime: Integer, seed: Optional[int] = None) -> None:
        """
        Generate shares for the secret.

        Args:
            secret (Integer): The secret to be shared.
            threshold (int): The minimum number of shares required to reconstruct the secret.
            num_shares (int): The total number of shares to generate.
            prime (Integer): The prime modulus for the finite field.
            seed (int, optional): Seed for random number generation.
        """
        if seed is not None:
            random_seed(seed)
        coefficients = [secret] + [Integer(randint(0, prime - 1)) for _ in range(threshold - 1)]
        shares: Dict[int, Integer] = {}

        for x in range(1, num_shares + 1):
            y = Integer(0)
            for i, coeff in enumerate(coefficients):
                y = (y + coeff * (Integer(x) ** i)) % prime
            shares[x] = y

        self.shares = shares
        self.threshold = threshold
        self.num_shares = num_shares
        self.prime = prime
        self.seed = seed
        self.secret = secret

    def reshare_shares(self, threshold, num_shares, seed):
        if self.threshold > len(self.shares):
            raise ValueError("Threshold cannot be greater than the number of shares")
        new_shares = defaultdict(dict)
        for i, (index, share) in enumerate(self.shares.items()):
            sub_shares_obj = SecretSharing(SharingBuilder(share, threshold, num_shares, self.prime, seed))
            for sub_index, sub_share in sub_shares_obj.shares.items():
                new_shares[sub_index][index] = sub_share

        reshared_shares = {}
        for sub_index, sub_shares in new_shares.items():
            temp_secret_sharing = SecretSharing(ReconstructionBuilder(sub_shares, self.threshold, self.prime))
            reshared_shares[sub_index] = temp_secret_sharing.reconstruct_secret()

        return SecretSharing(ReconstructionBuilder(reshared_shares, threshold, self.prime))

    def select_threshold_shares(self):
        shares = self.shares
        threshold = self.threshold
        if threshold > len(shares):
            raise ValueError("Threshold cannot be greater than the number of shares")
        selected_shares = dict(sample(list(shares.items()), threshold))

        new_secret_sharing = copy.deepcopy(self)
        new_secret_sharing.shares = selected_shares
        new_secret_sharing.num_shares = len(selected_shares)
        return new_secret_sharing

    def reconstruct_secret(self):
        shares = self.shares
        prime = self.prime
        if len(shares) < self.threshold:
            raise ValueError("Not enough shares to reconstruct the secret")

        secret = Integer(0)
        for x_j, y_j in shares.items():
            numerator = Integer(1)
            denominator = Integer(1)
            for x_m in shares.keys():
                if x_j != x_m:
                    numerator = (numerator * (-x_m)) % prime
                    denominator = (denominator * (x_j - x_m)) % prime
            lagrange_basis = (numerator * mod_inverse(denominator, prime)) % prime
            secret = (secret + y_j * lagrange_basis) % prime
        return secret