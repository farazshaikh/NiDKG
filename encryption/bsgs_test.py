import unittest
import random
from encryption.bsgs import DiscreteLog, ElGamalEncryption, G1, multiply
from encryption.keygen import KeyGenerator

# Define B for the tests
B = 2**16

class TestDiscreteLog(unittest.TestCase):
    def test_baby_step_giant_step(self):
        """Test the baby-step giant-step algorithm for discrete logarithm."""
        base_point = G1
        D_j = (2162907396045674769351232007234347103304821277428318873964222746163066973358299232780236120701433899886933151106798, 
                3422347011584838051406356376779427507368617803535924458791995333969680508164199070583200313433109201924870109116340)
        expected_m_j = 0x5678
        limit = B

        # Compute G1^expected_m_j
        computed_D_j = multiply(G1, expected_m_j)
        # Assert that computed_D_j is indeed D_j
        self.assertEqual(computed_D_j, D_j, f"Point multiplication mismatch: expected {D_j}, got {computed_D_j}")

        computed_m_j = DiscreteLog.baby_step_giant_step(base_point, D_j, limit)
        self.assertEqual(computed_m_j, expected_m_j, f"Discrete log mismatch: expected {expected_m_j}, got {computed_m_j}")

class TestElGamalEncryption(unittest.TestCase):
    def setUp(self):
        self.seed = 42
        self.key_generator = KeyGenerator(self.seed)
        self.sk, self.pk = self.key_generator.generate_keypair()
        self.elgamal = ElGamalEncryption()

    def test_encrypt_decrypt_small_message(self):
        """Test small message encryption/decryption with seeded key."""
        message = 12345
        ciphertext = self.elgamal.encrypt(self.pk, message)
        decrypted = self.elgamal.decrypt(self.sk, ciphertext)
        self.assertEqual(message, decrypted, f"Expected {message}, got {decrypted}")

    def test_multiple_random_messages(self):
        """Test encrypt/decrypt multiple random messages."""
        random.seed(42)
        for i in range(5):
            message = random.randint(1, 2**16 - 1)
            ciphertext = self.elgamal.encrypt(self.pk, message)
            decrypted = self.elgamal.decrypt(self.sk, ciphertext)
            self.assertEqual(decrypted, message, f"Iteration {i}: expected {message}, got {decrypted}")

    def test_decrypt_with_wrong_key(self):
        """Test decrypt with wrong key fails."""
        # Use a different seed for the wrong key
        wrong_key_generator = KeyGenerator(43)
        wrong_sk, _ = wrong_key_generator.generate_keypair()
        message = 42
        ciphertext = self.elgamal.encrypt(self.pk, message)
        with self.assertRaises(ValueError):
            wrong_decrypted = self.elgamal.decrypt(wrong_sk, ciphertext)

    def test_boundary_values(self):
        """Test boundary values."""
        # Very small message
        small_message = 1
        ciphertext = self.elgamal.encrypt(self.pk, small_message)
        decrypted = self.elgamal.decrypt(self.sk, ciphertext)
        self.assertEqual(decrypted, small_message, f"Expected {small_message}, got {decrypted}")

        # Maximum allowed message (just under limit)
        max_message = 2**16 - 1
        ciphertext = self.elgamal.encrypt(self.pk, max_message)
        decrypted = self.elgamal.decrypt(self.sk, ciphertext)
        self.assertEqual(decrypted, max_message, f"Expected {max_message}, got {decrypted}")

    def test_message_too_large(self):
        """Test error on too large message."""
        too_large = 2**16  # Equal to limit
        with self.assertRaises(ValueError):
            self.elgamal.encrypt(self.pk, too_large)

if __name__ == "__main__":
    unittest.main()
