import secrets
import math
from py_ecc.bls12_381 import curve_order

class MessageChunker:
    """
    A class to handle message chunking and reassembly for encryption purposes.

    This class is particularly useful in the context of ElGamal encryption where
    exponent extraction using the Baby-step Giant-step (BSGS) algorithm is required.
    Messages need to be split into chunks for efficient computation and secure transmission.

    Attributes:
        B (int): The base used for chunking the message.
        curve_order (int): The order of the elliptic curve used in encryption.
        m_chunks (int): The number of chunks required to represent a message.
    """

    def __init__(self, B, curve_order):
        """
        Initializes the MessageChunker with a specific base and curve order.

        Args:
            B (int): The base for chunking.
            curve_order (int): The order of the elliptic curve.
        """
        self.B = B
        self.curve_order = curve_order
        self.m_chunks = math.ceil(math.log(curve_order, B))

    def chunk_message(self, m):
        """
        Splits an integer message into base-B chunks.

        Args:
            m (int): The message to be chunked, represented as an integer.

        Returns:
            list: A list of integers representing the chunks of the message.
        """
        chunks = []
        for _ in range(self.m_chunks):
            chunk = m % self.B
            chunks.append(chunk)
            m //= self.B
        return chunks

    def reassemble_message(self, chunks):
        """
        Reassembles a message from its base-B chunks.

        Args:
            chunks (list): A list of integers representing the chunks of the message.

        Returns:
            int: The reassembled message as an integer.
        """
        message = 0
        for j, chunk_value in enumerate(chunks):
            message += chunk_value * (self.B ** j)
        message %= self.curve_order
        return message