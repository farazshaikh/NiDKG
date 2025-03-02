import unittest
from encryption.keygen import KeyGenerator
from py_ecc.bls12_381 import G1, multiply

class TestKeyGenerator(unittest.TestCase):
    def setUp(self):
        self.seed = 42
        self.key_generator = KeyGenerator(self.seed)

    def test_generate_keypair(self):
        sk, pk = self.key_generator.generate_keypair()
        self.assertIsNotNone(sk)
        self.assertIsNotNone(pk)

    def test_deterministic_keypair(self):
        sk1, pk1 = self.key_generator.generate_keypair()
        sk2, pk2 = KeyGenerator(self.seed).generate_keypair()
        self.assertEqual(sk1, sk2, "Secret keys should be the same for the same seed")
        self.assertEqual(pk1, pk2, "Public keys should be the same for the same seed")

if __name__ == "__main__":
    unittest.main()