import secrets
from py_ecc.bls12_381 import G1, curve_order, add, multiply, neg
from encryption.bsgs import DiscreteLog
from encryption.chunking import MessageChunker

class EncryptSecretShares:
    """
    Class to encrypt and decrypt secret shares using ElGamal encryption with chunking.
    """

    def __init__(self, B, curve_order):
        """
        Initialize the EncryptSecretShares with chunking parameters.

        Args:
            B (int): The base for chunking.
            curve_order (int): The order of the elliptic curve.
        """
        self.chunker = MessageChunker(B, curve_order)
        self.B = B  # Store B as an instance variable


    def generate_random(self):
        """
        Generate a random value below the curve order that is not zero.

        Returns:
            int: A random value below the curve order and not zero.
        """
        p = curve_order
        r = secrets.randbelow(p)
        while r == 0:
            r = secrets.randbelow(p)
        return r


    def encrypt_share(self, pk, share, r):
        """
        Encrypt a secret share using the provided public key.

        Args:
            pk: The public key for encryption.
            share (int): The secret share to be encrypted.
            r (int): Shared randomness value (caller must provide it).

            We take r as an argument to allow for sharing the same randomness value for multiple encryptions.

        Returns:
            list: A list of (C_j, R_j) tuples representing the ciphertext.
        """
        if r >= curve_order:
            raise ValueError("Shared random value r must be below the curve order.")

        chunks = self.chunker.chunk_message(share)
        ciphertext = []

        R = multiply(G1, r)  # Compute shared R value

        for m_j in chunks:
            part1 = multiply(pk, r)  # y^r
            part2 = multiply(G1, m_j)  # g^m_j
            C_j = add(part1, part2)
            ciphertext.append((C_j, R))

        return ciphertext


    def encrypt_share_distinct_randomness(self, pk, share):
        """
        Encrypt a secret share using the provided public key.
        discrete randomness means that each chunk is encrypted with a different random number.

        Args:
            pk: The public key for encryption.
            share (int): The secret share to be encrypted.

        Returns:
            list: A list of (C_j, R_j) tuples representing the ciphertext.
        """
        chunks = self.chunker.chunk_message(share)
        ciphertext = []
        p = curve_order
        for m_j in chunks:
            r_j = self.generate_random()
            R_j = multiply(G1, r_j)
            part1 = multiply(pk, r_j)
            part2 = multiply(G1, m_j)
            C_j = add(part1, part2)
            ciphertext.append((C_j, R_j))
        return ciphertext

    def decrypt_share(self, sk, ciphertext):
        """
        Decrypt a secret share using the provided secret key.

        Args:
            sk: The secret key for decryption.
            ciphertext (list): The ciphertext to be decrypted.

        Returns:
            int: The decrypted secret share.

        Raises:
            ValueError: If decryption fails due to invalid key or unrecoverable chunks.
        """
        x = sk
        recovered_chunks = []
        for C_j, R_j in ciphertext:
            S = multiply(R_j, x)
            m_j = DiscreteLog.baby_step_giant_step(G1, add(C_j, neg(S)), self.B)

            # Check if discrete log failed (wrong key or other reason)
            if m_j is None:
                raise ValueError(f"Decryption failed: chunk discrete log not found")

            recovered_chunks.append(m_j)

        return self.chunker.reassemble_message(recovered_chunks)



class MultiReceiverEncryptSecretShares:
    """
    Thin wrapper over EncryptSecretShares to handle multi-receiver encryption.
    We take r as an argument to allow for sharing the same randomness value for multiple encryptions.
    Each share and each chunk reuses the same randomness value.
    """

    def __init__(self, encryptor):
        """
        Initialize MultiReceiverEncryptSecretShares with an instance of EncryptSecretShares.

        Args:
            encryptor (EncryptSecretShares): Instance of EncryptSecretShares for single-receiver encryption.
        """
        self.encryptor = encryptor  # Reuse single-receiver encryptor

    def encrypt_shares(self, pk_list, shares, r):
        """
        Encrypt multiple secret shares for multiple recipients efficiently.

        Args:
            pk_list (list): List of public keys for recipients.
            shares (list): List of secret shares (each recipient gets one).
            r (int): Shared randomness value for all encryptions.

        Returns:
            tuple: (R, ciphertext_dict), where:
                - R is the shared randomness component.
                - ciphertext_dict maps recipient index i -> (C_i).
        """
        if len(pk_list) != len(shares):
            raise ValueError("Number of public keys must match number of shares")

        if r >= curve_order or r == 0:
            raise ValueError("Shared random value r must be in range (0, curve_order-1)")

        R = multiply(G1, r)  # Shared randomness component
        ciphertext_dict = {}

        for i, (pk, share) in enumerate(zip(pk_list, shares)):
            ciphertext_dict[i] = self.encryptor.encrypt_share(pk, share, r)  # Reuse single-receiver function

        return R, ciphertext_dict