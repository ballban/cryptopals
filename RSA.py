from Crypto.Util import number
from utility import *

class RSA:
    """
    RSA class for encryption and decryption using the RSA algorithm.
    """

    def __init__(self) -> None:
        """
        Initializes the RSA object with default values for e, p, q, et, N, and d.
        """
        self.e = 3
        self.p = self.q = self.et = 0

        while self.et % self.e == 0:
            # size = 2048
            size = 512
            self.p = number.getPrime(size)
            self.q = number.getPrime(size)
            self.et = (self.p - 1) * (self.q - 1)

        self.N = self.p * self.q
        self.d = pow(self.e, -1, self.et)

    
    def EGCD(self, a:int, b:int) -> tuple:
        """
        Extended Euclidean Algorithm to find the greatest common divisor (gcd) and the coefficients x and y
        for the equation ax + by = gcd(a, b).

        Args:
            a (int): First integer.
            b (int): Second integer.

        Returns:
            tuple: A tuple containing the gcd, x, and y.
        """
        old_r, r = a, b
        old_s, s = 1, 0
        old_t, t = 0, 1
        while r > 0:
            q = old_r // r
            old_r, r = r, old_r - q * r
            old_s, s = s, old_s - q * s
            old_t, t = t, old_t - q * t
        return old_r, old_s, old_t
    
    def modinv(self, a, m):
        """
        Calculates the modular inverse of a modulo m.

        Args:
            a (int): The integer for which the modular inverse is to be calculated.
            m (int): The modulus.

        Returns:
            int: The modular inverse of a modulo m.

        Raises:
            ValueError: If the modular inverse does not exist.
        """
        g, x, y = self.EGCD(a, m)
        if g != 1:
            raise ValueError('Modular inverse does not exist.')
        else:
            return x % m
    
    def encrypt(self, text:str) -> int:
        """
        Encrypts the given text using RSA encryption.

        Args:
            text (str): The text to be encrypted.

        Returns:
            int: The encrypted ciphertext.
        """
        m = int(text.encode().hex(), 16)
        c = pow(m, self.e, self.N)
        return c

    def decrypt(self, c:int) -> str:
        """
        Decrypts the given ciphertext using RSA decryption.

        Args:
            c (int): The ciphertext to be decrypted.

        Returns:
            str: The decrypted plaintext.
        """
        m = pow(c, self.d, self.N)
        return bytes.fromhex(hex(m)[2:]).decode()
    
    def decrypt_to_int(self, c:int) -> int:
        """
        Decrypts the given ciphertext to an integer using RSA decryption.

        Args:
            c (int): The ciphertext to be decrypted.

        Returns:
            int: The decrypted plaintext as an integer.
        """
        m = pow(c, self.d, self.N)
        return m
    
    def encrypt_for_sig(self, input:int) -> bytes:
        """
        Encrypts the given input for digital signature using RSA encryption.

        Args:
            input (int): The input to be encrypted.

        Returns:
            bytes: The encrypted ciphertext as bytes.
        """
        c = pow(input, self.e, self.N)
        return int_to_bytes(c)

    def decrypt_for_sig(self, input:bytes) -> int:
        """
        Decrypts the given ciphertext for digital signature using RSA decryption.

        Args:
            input (bytes): The ciphertext to be decrypted.

        Returns:
            int: The decrypted plaintext as an integer.
        """
        c = int.from_bytes(input, 'big')
        m = pow(c, self.d, self.N)
        return m