import unittest
import secrets
from encryption.enc_secret_shares import EncryptSecretShares
from encryption.keygen import KeyGenerator
from py_ecc.bls12_381 import curve_order

class TestEncryptSecretShares(unittest.TestCase):

    def setUp(self):
        """Initialize keys before running tests."""
        self.key_generator = KeyGenerator(42)
        self.sk, self.pk = self.key_generator.generate_keypair()
        self.encrypt_secret_shares = EncryptSecretShares(2**16, curve_order)

    def run_encryption_tests(self, encrypt_function):
        """Run a battery of tests with the given encryption function."""
        secret_share = 123456789
        ciphertext = encrypt_function(self.pk, secret_share)
        decrypted_message = self.encrypt_secret_shares.decrypt_share(self.sk, ciphertext)
        self.assertEqual(secret_share, decrypted_message,
                         "Decryption should return the original message")

        msg1 = 42
        msg2 = 987654321
        ciphertext1 = encrypt_function(self.pk, msg1)
        ciphertext2 = encrypt_function(self.pk, msg2)
        self.assertNotEqual(ciphertext1, ciphertext2,
                            "Different messages should produce different ciphertexts")

        ciphertext1 = encrypt_function(self.pk, secret_share)
        ciphertext2 = encrypt_function(self.pk, secret_share)
        self.assertNotEqual(ciphertext1, ciphertext2,
                            "Encryption should be randomized and produce different ciphertexts")

        sk_fake, _ = self.key_generator.generate_keypair()
        ciphertext = encrypt_function(self.pk, secret_share)
        try:
            decrypted_message = self.encrypt_secret_shares.decrypt_share(sk_fake, ciphertext)
            self.assertNotEqual(secret_share, decrypted_message,
                               "Decryption with incorrect key should fail")
        except ValueError:
            pass

        for i in range(5):
            random_share = secrets.randbelow(curve_order)
            ciphertext = encrypt_function(self.pk, random_share)
            decrypted_message = self.encrypt_secret_shares.decrypt_share(self.sk, ciphertext)
            self.assertEqual(random_share, decrypted_message,
                             "Decryption should return the original message")

    def test_encrypt_share_distinct_randomness(self):
        """Test encryption and decryption with distinct randomness."""
        self.run_encryption_tests(self.encrypt_secret_shares.encrypt_share_distinct_randomness)

    def test_encrypt_share(self):
        """Test encryption and decryption with shared randomness."""
        self.run_encryption_tests(lambda pk, share: self.encrypt_secret_shares.encrypt_share(pk, share, self.encrypt_secret_shares.generate_random()))


if __name__ == "__main__":
    unittest.main()