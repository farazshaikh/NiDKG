# Unit tests for MessageChunker
import unittest
from encryption.chunking import MessageChunker
from py_ecc.bls12_381 import curve_order
import secrets

class TestMessageChunker(unittest.TestCase):
    def setUp(self):
        self.B = 2**16
        self.curve_order = curve_order
        self.chunker = MessageChunker(self.B, self.curve_order)

    def test_chunk_and_reassemble(self):
        message = 123456789
        chunks = self.chunker.chunk_message(message)
        reassembled_message = self.chunker.reassemble_message(chunks)
        self.assertEqual(message, reassembled_message, f"Expected {message}, got {reassembled_message}")

    def test_chunking_consistency(self):
        for i in range(5):
            message = secrets.randbelow(self.curve_order)
            chunks = self.chunker.chunk_message(message)
            reassembled_message = self.chunker.reassemble_message(chunks)
            self.assertEqual(message, reassembled_message, f"Iteration {i}: expected {message}, got {reassembled_message}")

if __name__ == "__main__":
    unittest.main()