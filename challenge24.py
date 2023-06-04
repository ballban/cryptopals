import challenge21 as c21
import random
import time
import math
from utility import *

# Step 1
# Create MT19937 stream cipher
def MT19937_key_stream(key: int, length: int) -> bytes:
    key_stream = b''
    MT19937 = c21.MT19937(key)
    for i in range(math.ceil(length / 4)):
        key_stream += MT19937.rand().to_bytes(4, 'little')
    return key_stream

def MT19937_stream_cipher(input: bytes, key: int) -> bytes:
    key_stream = MT19937_key_stream(key, len(input))
    return xor_bytes(input, key_stream)

# Step 2
# Verify step 1 is working properly
def verify_step_1():
    # 16-bit seed
    key = 1991
    
    plain = b'test hello world'
    encrypted = MT19937_stream_cipher(plain, key)
    decrypted = MT19937_stream_cipher(encrypted, key)
    print(f'plain text : {plain}')
    print(f'encrypted text : {encrypted}')
    print(f'decrypted text : {decrypted}')

# Step 3
# encrypt a known plaintext prefixed by a random number of random characters and recover the key from ciphertext
def find_seed(lower_bound, upper_bound, known_plain_text = 'AAAAAAAAAAAAAA') -> int:
    key = random.randint(lower_bound, upper_bound)
    prefix = os.urandom(random.randint(0, 20))
    plain_text = prefix + bytes(known_plain_text, "utf-8")

    encrypted = MT19937_stream_cipher(plain_text, key)

    for i in range(lower_bound, upper_bound):
        decrypted = MT19937_stream_cipher(encrypted, i)

        if known_plain_text in str(decrypted):
            print(f'seed found: {i}')
            return i
    
    print(f"couldn't find the seed")

# Step 4
# Generate a random "password reset token" using MT19937 seeded from the current time.
# Write a function to check if any given password token is actually the product of an MT19937 PRNG seeded with the current time.
def generate_password_reset_token(length: int = 32) -> bytes:
    current_timestamp = int(time.time())
    password_reset_token = MT19937_key_stream(current_timestamp, length)
    return password_reset_token


def check_is_MT19937_product_with_current_time(token: bytes) -> bool:
    lower_bound = 100000
    upper_bound = 100000
    current_timestamp = int(time.time())
    for i in range(current_timestamp - lower_bound, current_timestamp + upper_bound):
        if MT19937_key_stream(i, len(token)) == token:
            print(f'seed found: {i}')
            return True
    
    print(f"couldn't find seed")
    return False