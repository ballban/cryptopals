import challenge16 as c16
import random
from utility import *

key = generate_random_aes_key()
nonce = random.randint(0, 999)

def encrypt_CTR_26(plain_text):
  prefix = "comment1=cooking%20MCs;userdata="
  suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
  new_text = prefix + plain_text + suffix
  encrypt_bytes = exec_CTR(new_text.encode(), key, nonce)
  return encrypt_bytes

def check_admin_26(encrypt_bytes):
  decrypt_bytes = exec_CTR(encrypt_bytes, key, nonce)
  print_bytes(decrypt_bytes)
  return c16.parse_16(decrypt_bytes)