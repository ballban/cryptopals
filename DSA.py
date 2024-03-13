import random
import hashlib
from typing import Tuple

class DSA:
    """
    DSA (Digital Signature Algorithm) class for generating and verifying digital signatures.

    Attributes:
        p (int): The prime modulus.
        q (int): The prime divisor of (p-1).
        g (int): The generator.
        x (int): The private key.
        y (int): The public key.

    Methods:
        sign(message: bytes) -> Tuple[int, int]: Generates a digital signature for the given message.
        verify(message: bytes, r: int, s: int) -> bool: Verifies the digital signature for the given message.

    """

    def __init__(self, p, q, g):
        self.p = p
        self.q = q
        self.g = g
        self.x = random.randint(1, q-1)
        self.y = pow(g, self.x, p)

    def sign(self, message: bytes) -> Tuple[int, int]:
        """
        Generates a digital signature for the given message.

        Args:
            message (bytes): The message to be signed.

        Returns:
            Tuple[int, int]: The digital signature (r, s).

        """
        mhash = hashlib.sha1(message).hexdigest()
        H = int(mhash, 16)

        k = random.randint(1, 2 ** 16 - 1)
        r = pow(self.g, k, self.p) % self.q
        s = (pow(k, -1, self.q) * (H + self.x * r)) % self.q
        return (r, s)

    def verify(self, message: bytes, r: int, s: int) -> bool:
        """
        Verifies the digital signature for the given message.

        Args:
            message (bytes): The message to be verified.
            r (int): The first part of the digital signature.
            s (int): The second part of the digital signature.

        Returns:
            bool: True if the signature is valid, False otherwise.

        """
        mhash = hashlib.sha1(message).hexdigest()
        H = int(mhash, 16)

        w = pow(s, -1, self.q)
        u1 = (H * w) % self.q
        u2 = (r * w) % self.q
        v = (pow(self.g, u1, self.p) * pow(self.y, u2, self.p)) % self.p % self.q
        return v == r