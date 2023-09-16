import hashlib
import random


class SRP_server:
    def __init__(self) -> None:
        N_str = '''ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff'''
        self.N = int(N_str.replace('\n', ''), base=16)
        self.g = 2
        self.k = 3
        self.I = 'test@abc.com'
        self.P = 'password'
        # Step 1: Generate salt as random integer
        self.salt = random.randint(2, self.N)
        # Step 2: Generate string xH=SHA256(salt|password)
        xH = hashlib.sha256(str(self.salt).encode() + self.P.encode()).hexdigest()
        # Step 3: Convert xH to integer x somehow (put 0x on hexdigest)
        x = int(xH, 16)
        # Step 4: Generate v=g**x % N
        self.v = pow(self.g, x, self.N)
        # Step 5: Save everything but x, xH
    
    def get_salt_and_B(self):
        self.b = random.randint(2, self.N)
        self.B = self.k*self.v + pow(self.g, self.b, self.N)
        return self.salt, self.B
    
    def validate_K(self, A, HMAC_c):
        uH = hashlib.sha256(str(A).encode() + str(self.B).encode()).hexdigest()
        u = int(uH, 16)
        self.S = pow(A * pow(self.v,u,self.N), self.b, self.N)
        self.K = hashlib.sha256(str(self.S).encode()).hexdigest()
        HMAC = hashlib.sha256((self.K + str(self.salt)).encode()).hexdigest()
        return "ok" if HMAC_c == HMAC else "wrong!"


class SRP_client:
    def __init__(self, N, g, k, I, P) -> None:
        self.N = N
        self.g = g
        self.k = k
        self.I = I
        self.P = P
    
    def generate_A(self):
        self.a = random.randint(2, self.N)
        self.A = pow(self.g, self.a, self.N)
        return self.A
    
    def generate_HMAC(self, salt, B, u=None):
        xH = hashlib.sha256(str(salt).encode() + self.P.encode()).hexdigest()
        x = int(xH, 16)
        if not u:
            uH = hashlib.sha256(str(self.A).encode() + str(B).encode()).hexdigest()
            u = int(uH, 16)

        # Client Side: Send HMAC-SHA256(K, salt)
        if not u:
            self.S = pow(B - self.k * pow(self.g, x, self.N), self.a + u * x, self.N)
        else:
            self.S = pow(B, self.a + u * x, self.N)
        self.K = hashlib.sha256(str(self.S).encode()).hexdigest()
        HMAC = hashlib.sha256((self.K + str(salt)).encode()).hexdigest()
        return HMAC