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

    def encrypt_share(self, pk, share):
        """
        Encrypt a secret share using the provided public key.

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
            r_j = secrets.randbelow(p)
            while r_j == 0:
                r_j = secrets.randbelow(p)
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