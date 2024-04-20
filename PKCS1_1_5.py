import RSA
from hashlib import sha1

class PKCS1_1_5:
    def __init__(self) -> None:
        self.rsa = RSA.RSA(1024)
        self.ASN1_prefix = 0x3021300906052B0E03021A05000414
        self.sig_len = 128
        self.N = self.rsa.N
        self.hex_size = 0
    
    def verify(self, sig: int, mHash: bytes):
        '''
        data should be like this
        00h 01h ffh ffh ... ffh ffh 00h ASN.1 GOOP HASH
        '''
        signature = self.rsa.encrypt_for_sig(sig, self.sig_len)
        # signature = b'\x00' + signature
        print('signature', signature)

        assert signature[:2] == b'\x00\x01'
        
        i = 2
        while signature[i] == 255:
            # todo: fix the check
            assert signature[i] == 255
            i += 1
            if i == len(signature):
                break
        
        ASN1 = signature[-20:]
        print('ASN1', ASN1)
        print('mHash', mHash)

        assert ASN1 == mHash
        return True
        
    def sign(self, msg: bytes) -> int:
        mHash = sha1(msg).digest()
        padding = b'\xFF' * (self.sig_len - len(mHash) - 3)
        sig = b'\x00\x01' + padding + b'\x00' + mHash

        print(f'sig before decrypt: {sig}')

        return self.rsa.decrypt_for_sig(sig)
