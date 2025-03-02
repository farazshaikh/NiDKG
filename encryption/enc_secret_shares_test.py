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

    def test_encryption_decryption(self):
        """Test that encryption and decryption work correctly."""
        secret_share = 123456789
        ciphertext = self.encrypt_secret_shares.encrypt_share(self.pk, secret_share)
        decrypted_message = self.encrypt_secret_shares.decrypt_share(self.sk, ciphertext)
        self.assertEqual(secret_share, decrypted_message,
                         "Decryption should return the original message")

    def test_different_messages(self):
        """Test encryption of different messages produces different ciphertexts."""
        msg1 = 42
        msg2 = 987654321
        ciphertext1 = self.encrypt_secret_shares.encrypt_share(self.pk, msg1)
        ciphertext2 = self.encrypt_secret_shares.encrypt_share(self.pk, msg2)
        self.assertNotEqual(ciphertext1, ciphertext2,
                            "Different messages should produce different ciphertexts")

    def test_randomized_ciphertext(self):
        """Test that the same message encrypts to different ciphertexts due to randomness."""
        secret_share = 123456789
        ciphertext1 = self.encrypt_secret_shares.encrypt_share(self.pk, secret_share)
        ciphertext2 = self.encrypt_secret_shares.encrypt_share(self.pk, secret_share)
        self.assertNotEqual(ciphertext1, ciphertext2,
                            "Encryption should be randomized and produce different ciphertexts")

    def test_invalid_decryption(self):
        """Test that incorrect secret key fails to decrypt correctly."""
        sk_fake, _ = self.key_generator.generate_keypair()
        secret_share = 123456789
        ciphertext = self.encrypt_secret_shares.encrypt_share(self.pk, secret_share)

        # This will likely raise an exception due to incorrect decryption
        try:
            decrypted_message = self.encrypt_secret_shares.decrypt_share(sk_fake, ciphertext)
            self.assertNotEqual(secret_share, decrypted_message,
                               "Decryption with incorrect key should fail")
        except ValueError:
            # If discrete log fails, that's also an acceptable result
            pass

    def test_correct_random_messages(self):
        """Test correctness on multiple random messages."""
        for i in range(5):
            secret_share = secrets.randbelow(curve_order)
            ciphertext = self.encrypt_secret_shares.encrypt_share(self.pk, secret_share)
            dec_msg = self.encrypt_secret_shares.decrypt_share(self.sk, ciphertext)
            self.assertEqual(
                secret_share, dec_msg,
                f"Decryption mismatch on iteration {i}: expected {secret_share}, got {dec_msg}"
            )

if __name__ == "__main__":
    unittest.main() 