from Crypto.Util import number

class RSA:
    def __init__(self) -> None:
        self.e = 3
        self.p = self.q = self.et = 0

        while self.et % self.e == 0:
            # size = 2048
            size = 1024
            self.p = number.getPrime(size)
            self.q = number.getPrime(size)
            self.et = (self.p - 1) * (self.q - 1)

        self.N = self.p * self.q
        self.d = pow(self.e, -1, self.et)

    
    def EGCD(self, a:int, b:int) -> tuple:
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
        g, x, y = self.EGCD(a, m)
        if g != 1:
            raise ValueError('not available')
        else:
            return x % m
    
    def encrypt(self, text:str) -> int:
        m = int(text.encode().hex(), 16)
        c = pow(m, self.e, self.N)
        return c

    def decript(self, c:int) -> str:
        m = pow(c, self.d, self.N)
        return bytes.fromhex(hex(m)[2:]).decode()