import base64
import requests
from collections import defaultdict
import string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import random


def print_bytes(text_bytes, block_size = 16):
  print([text_bytes[i:i+block_size] for i in range(0, len(text_bytes), block_size)])


def xor_bytes(ba1: bytes, ba2: bytes) -> bytes:
  return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

''' Get text from url '''
def get_txt_from_url(url: str) -> list:
  f = requests.get(url).content.decode('utf-8')
  text_list = f.split('\n')
  return text_list
def get_txt_from_url_b64decode(url: str) -> list:
  text_list = get_txt_from_url(url)
  text_list = [base64.b64decode(x) for x in text_list]
  return text_list

''' Generate a block_size-long key bytes '''
def generate_random_aes_key(block_size = 16) -> bytes:
  return os.urandom(block_size)

''' ECB Encrypt '''
def _encrypt_ECB(text_bytes: bytes, key) -> bytes:
  cipher = AES.new(key, AES.MODE_ECB)
  return cipher.encrypt(text_bytes)
def encrypt_ECB(text_bytes: bytes, key, block_size) -> bytes:
  text_bytes = padding_PKCS7(text_bytes, block_size)
  block_list = [text_bytes[i: i + block_size] for i in range(0, len(text_bytes), block_size)]
  encrypted_bytes = b''
  for block in block_list:
    encrypted_bytes += _encrypt_ECB(block, key)
  return encrypted_bytes

''' ECB Decrypt '''
def decrypt_ECB(encrypted_bytes: bytes, key) -> bytes:
  cipher = AES.new(key, AES.MODE_ECB)
  return cipher.decrypt(encrypted_bytes)

''' PKCS7 Padding '''
def padding_PKCS7(input_bytes: bytes, block_size: int) -> bytes:
  # pad_length = block_size - len(input_bytes) % block_size
  # return input_bytes + pad_length.to_bytes(1, 'big') * pad_length
  return pad(input_bytes, block_size)

''' PKCS7 Unpadding '''
def unpadding_PKCS7(input_bytes: bytes, block_size: int) -> bytes:
  # target_byte = input_bytes[-1]
  # print(f'input_bytes {input_bytes}')
  # if input_bytes[-target_byte:] == target_byte.to_bytes(1, 'big') * target_byte:
  #   return input_bytes[:-target_byte]
  # else:
  #   return input_bytes
  return unpad(input_bytes, block_size)

''' CBC Encrypt '''
def encrypt_CBC(text_bytes: bytes, key: bytes, block_size: int, initialization_vector: bytes):
  text_bytes = padding_PKCS7(text_bytes, block_size)
  block_list = [text_bytes[i: i + block_size] for i in range(0, len(text_bytes), block_size)]
  
  pre_block = initialization_vector
  result = []
  for block in block_list:
    XOR_block = [b1 ^ b2 for b1, b2 in zip(pre_block, block)]
    encrypted_block = _encrypt_ECB(bytes(XOR_block), key)

    pre_block = encrypted_block
    result += encrypted_block
  return bytes(result)

''' CBC Decrypt '''
def decrypt_CBC(text_bytes: bytes, key: bytes, block_size: int, initialization_vector: bytes, is_unpadding: bool = True):
  block_list = [text_bytes[i: i + block_size] for i in range(0, len(text_bytes), block_size)]
  
  pre_block = initialization_vector
  result = []
  for block in block_list:
    decrypted_block = decrypt_ECB(block, key)
    plain_text = [b1 ^ b2 for b1, b2 in zip(pre_block, decrypted_block)]
    #print(bytes(plain_text))

    pre_block = block
    result += plain_text
  return bytes(result) if is_unpadding else unpadding_PKCS7(bytes(result), block_size)

''' CTR encrypt/decrypt '''
def exec_CTR(input_bytes: bytes, key: bytes, nonce: int) -> bytes:
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    block_size = len(key)
    
    block_list = [input_bytes[i:i+block_size] for i in range(0, len(input_bytes), block_size)]
    counter = 0
    result = []
    for block in block_list:
        key_stream = cipher.encrypt(nonce.to_bytes(block_size // 2, 'little') + counter.to_bytes(block_size // 2, 'little'))
        result += [x1 ^ x2 for x1, x2 in zip(key_stream, block)]
        counter += 1
    return bytes(result)