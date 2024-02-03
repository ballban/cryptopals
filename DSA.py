import random
import hashlib

class DSA:
    def __init__(self, p, q, g):
        self.p = p
        self.q = q
        self.g = g
        self.x = random.randint(1, q-1)
        self.y = pow(g, self.x, p)

    def sign(self, message: bytes):
        mhash = hashlib.sha1(message).hexdigest()
        H = int(mhash, 16)

        # k = random.randint(1, self.q-1)
        k = random.randint(1, 2 ** 16 - 1)
        r = pow(self.g, k, self.p) % self.q
        s = (pow(k, -1, self.q) * (H + self.x * r)) % self.q
        return (r, s)

    def verify(self, message: bytes, r, s):
        mhash = hashlib.sha1(message).hexdigest()
        H = int(mhash, 16)

        w = pow(s, -1, self.q)
        u1 = (H * w) % self.q
        u2 = (r * w) % self.q
        v = (pow(self.g, u1, self.p) * pow(self.y, u2, self.p)) % self.p % self.q
        return v == r