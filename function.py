from collections import defaultdict
import string
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import random
import os
import re
import urllib.parse
import base64


def get_frequency_dic(text):
  fre_bytes = defaultdict(int)
  for i in range(len(text)):
    x = text[i]
    fre_bytes[x] += 1
  return sorted(fre_bytes.items(), key=lambda x:x[1], reverse=True)


def get_score(text):
  score_dic = {"E":11.16,"A":8.50,"R":7.58,"I":7.54,"O":7.16,"T":6.95,"N":6.65,"S":5.74,"L":5.49,"C":4.54,"U":3.63,"D":3.38,"P":3.17,"M":3.01,"H":3.00,"G":2.47,"B":2.07,"F":1.81,"Y":1.78,"W":1.29,"K":1.10,"V":1.01,"X":0.29,"Z":0.27,"J":0.20,"Q":0.20,"e":11.16,"a":8.50,"r":7.58,"i":7.54,"o":7.16,"t":6.95,"n":6.65,"s":5.74,"l":5.49,"c":4.54,"u":3.63,"d":3.38,"p":3.17,"m":3.01,"h":3.00,"g":2.47,"b":2.07,"f":1.81,"y":1.78,"w":1.29,"k":1.10,"v":1.01,"x":0.29,"z":0.27,"j":0.20,"q":0.20," ":18}
  score = 0
  for key, value in get_frequency_dic(text):
    if key in score_dic:
      score += score_dic[key] * value
    elif key not in string.printable:
      score = 0
      break
  return score


def try_decrypt(text):
  if(type(text) == str):
    text_bytes = bytes.fromhex(text)
  else:
    text_bytes = text
  #print(text_bytes)

  keys = range(0, 127)
  scores = defaultdict(int)
  for key in keys:
    decrypt_text = ''
    for i in range(len(text_bytes)):
      x = text_bytes[i]
      decrypt_text += chr(x ^ key)
    scores[key] = get_score(decrypt_text)
  scores = sorted(scores.items(), key=lambda x:x[1], reverse=True)
  #print(scores[:10])

  true_key = scores[0][0]

  result = ''
  for i in range(len(text_bytes)):
      x = text_bytes[i]
      result += chr(x ^ true_key)
  return scores[0][1], result, true_key


def get_txt(url):
  f = requests.get(url).content.decode('utf-8')
  text_list = f.split('\n')
  return text_list


def encrypt(text, key):
  key = key * int(len(text) / len(key) + 1)
  result = b''
  for i in range(len(text)):
    result += (ord(text[i]) ^ ord(key[i])).to_bytes(1, 'big')
  return result


def hamming_distance(text1, text2):
  return sum([bin(x[0] ^ x[1]).count("1") for x in zip(text1, text2)])


def encrypt_ECB(plain_text: bytes, key) -> bytes:
  cipher = AES.new(key, AES.MODE_ECB)
  return cipher.encrypt(plain_text)


def decrypt_ECB(encrypted_bytes: bytes, key) -> bytes:
  cipher = AES.new(key, AES.MODE_ECB)
  return cipher.decrypt(encrypted_bytes)


def padding_PKCS7(input_bytes: bytes, block_size: int):
  # pad_length = block_size - len(input_bytes) % block_size
  # return input_bytes + pad_length.to_bytes(1, 'big') * pad_length
  return pad(input_bytes, block_size)


def unpadding_PKCS7(input_bytes: bytes):
  # target_byte = input_bytes[-1]
  # print(f'input_bytes {input_bytes}')
  # if input_bytes[-target_byte:] == target_byte.to_bytes(1, 'big') * target_byte:
  #   return input_bytes[:-target_byte]
  # else:
  #   return input_bytes
  return unpad(input_bytes, 16)


def encrypt_CBC(text_bytes: bytes, key: bytes, block_size: int, initialization_vector: bytes):
  text_bytes = padding_PKCS7(text_bytes, block_size)
  block_list = [text_bytes[i: i + block_size] for i in range(0, len(text_bytes), block_size)]
  
  pre_block = initialization_vector
  result = []
  for block in block_list:
    XOR_block = [b1 ^ b2 for b1, b2 in zip(pre_block, block)]
    encrypted_block = encrypt_ECB(bytes(XOR_block), key)

    pre_block = encrypted_block
    result += encrypted_block
  return bytes(result)


def decrypt_CBC(text_bytes: bytes, key: bytes, block_size: int, initialization_vector: bytes, is_unpadding: bool = True):
  block_list = [text_bytes[i: i + block_size] for i in range(0, len(text_bytes), block_size)]
  
  pre_block = initialization_vector
  result = []
  for block in block_list:
    decrypted_block = decrypt_ECB(block, key)
    plain_text = [b1 ^ b2 for b1, b2 in zip(pre_block, decrypted_block)]

    pre_block = block
    result += plain_text
  return unpadding_PKCS7(bytes(result)) if is_unpadding else bytes(result)


def encryption_oracle(plain_text: str, block_size: int) -> bytes:
  bytes_text = plain_text.encode()
  random_key = random_aes_key()
  
  append_count = random.randint(5, 10)
  bytes_text = os.urandom(append_count) + bytes_text + os.urandom(append_count)

  encryption_mode = random.randint(0,1)

  if encryption_mode == 0:
    # ECB
    encrypted_bytes = encrypt_ECB(bytes_text, random_key, block_size)
  else:
    # CBC
    encrypted_bytes = encrypt_CBC(bytes_text, random_key, block_size, os.urandom(16))

  return encrypted_bytes, random_key, 'ECB' if encryption_mode == 0 else 'CBC'


def random_aes_key(block_size = 16) -> bytes:
  return os.urandom(block_size)


def routine(input: str):
  result = dict()
  pairs = input.split('&')
  for pair in pairs:
    key, value = pair.split('=')
    result[key] = value
  return result


def profile_for(input: str):
  input = re.sub(r'\&', '', input)
  input = re.sub(r'\=', '', input)
  params = {'email': input, 'uid': 10, 'role': 'user'}
  return urllib.parse.urlencode(params)


def new_oracle(random_prefix: bytes, plain_text = '', random_key = b'', block_size = 16) -> bytes:
  footer_base64 = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
  footer_bytes = base64.b64decode(footer_base64)

  if isinstance(plain_text, str):
    bytes_text = random_prefix + plain_text.encode() + footer_bytes
  else:
    bytes_text = random_prefix + plain_text + footer_bytes

  # ECB
  #print("new_oracle", [bytes_text[x*block_size: (x+1)*block_size] for x in range(len(bytes_text))])
  encrypted_bytes = encrypt_ECB(bytes_text, random_key, block_size)

  return encrypted_bytes

# Step 1
def detect_block_size(plain_text, block_size = 16):
  for i in range(10):
    new_text = 'A' * i + plain_text
    ECB_encrypted_text = new_oracle(new_text)
    print(ECB_encrypted_text)
  return block_size

# Step 2
def detect_ECB_mode(plain_text: str, block_size: int):
  target_index = -1
  encrypted_bytes = new_oracle('A'*256 + plain_text)
  max_chunk = len(encrypted_bytes)//block_size

  for i in range(max_chunk - 1):
    for j in range(i + 1, max_chunk):
      if encrypted_bytes[i*block_size: (i+1)*block_size] == encrypted_bytes[j*block_size: (j+1)*block_size]:
        target_index = i
        break
    if target_index != -1:
      break

  return 'ECB' if target_index != -1 else 'UNKNOWN'

# Step 3,4
def craft_input_dict(header: str, block_size = 16):
  return {new_oracle(header + bytes([i]))[:block_size]: bytes([i]) for i in range(256)}

# Step 5, 6
def match_output(block_size = 16):
  header = b'A' * (block_size - 1)
  result = header

  for x in range(10):
    for i in range(block_size):
      input_dict = craft_input_dict(header)
      key = new_oracle(b'A' * (block_size - 1 - i))[x*block_size:(x+1)*block_size]
      if key in input_dict:
        output = input_dict[key]
      else:
        return result[block_size - 1:]
      result += output
      header = result[-block_size+1:]
  return result[block_size - 1:]


def get_prefix_length(block_size = 16):
  encrypted_btyes_list = []
  for i in range(32):
    encrypted_btyes = new_oracle(b'A' * i)
    print(i, [encrypted_btyes[i*16: (i+1)*16] for i in range(len(encrypted_btyes) // 16 + 1)])
    encrypted_btyes_list.append(encrypted_btyes)

  same_btyes_index = -1
  for j in range(len(encrypted_btyes_list[0])):
    if same_btyes_index != -1:
      break
    for i in range(len(encrypted_btyes_list) - 1):
      #print(encrypted_btyes_list[i][j*block_size: (j+1)*block_size])
      if same_btyes_index == -1:
        if encrypted_btyes_list[i][j*block_size: (j+1)*block_size] == encrypted_btyes_list[i + 1][j*block_size: (j+1)*block_size]:
          if i == 0:
            break
          same_btyes_index = i
  return j, same_btyes_index


def craft_input_dict_14(header: str, prefix_block, prefix_size, block_size = 16):
  input_dict = {new_oracle(b'A' * prefix_size + header + bytes([i]))[prefix_block*block_size:(prefix_block+1)*block_size]: bytes([i]) for i in range(256)}
  return input_dict


def match_output_14(block_size = 16):
  header = b'A' * (block_size - 1)
  result = header
  prefix_block, prefix_size = get_prefix_length()
  print(prefix_block, prefix_size)

  for x in range(10):
    for i in range(block_size):
      input_dict = craft_input_dict_14(header, prefix_block, prefix_size)
      key = new_oracle(b'A' * prefix_size + b'A' * (block_size - 1 - i))[(x+prefix_block)*block_size:(x+prefix_block+1)*block_size]
      #print(input_dict)
      #print(key)
      if key in input_dict:
        output = input_dict[key]
      else:
        return result[block_size - 1:]
      result += output
      header = result[-block_size+1:]
  return result[block_size - 1:]


def check_and_strip_PKCS7(plain_bytes, block_size):
  if len(plain_bytes) % block_size != 0:
    raise Exception('Wrong size!')

  while True:
    if plain_bytes[-1:] == b'\x04':
      plain_bytes = plain_bytes[:-1]
    elif plain_bytes[-1:] not in string.printable.encode():
      raise Exception('Bad padding!')
    else:
      break
  return plain_bytes

# Step 1
def encrypt_CBC_16(plain_text, key, block_size, initialization_vector):
  prefix = "comment1=cooking%20MCs;userdata="
  suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
  new_text = prefix + plain_text + suffix
  encrypt_bytes = encrypt_CBC(new_text.encode(), key, block_size, initialization_vector)
  return encrypt_bytes

# Step 2
def check_admin_16(encrypt_bytes, key, block_size, initialization_vector):
  decrypt_bytes = decrypt_CBC(encrypt_bytes, key, block_size, initialization_vector)
  print_bytes(decrypt_bytes)
  decrypt_bytes = check_and_strip_PKCS7(decrypt_bytes, block_size)
  return parse_16(decrypt_bytes)


def parse_16(decrypt_bytes):
  s = decrypt_bytes.decode('iso-8859-1')
  print(s)
  block_list = s.split(';')
  for block in block_list:
    key, val = block.split('=')
    if key == 'admin':
      return True
  return False


def print_bytes(text_bytes, block_size = 16):
  print([text_bytes[i:i+block_size] for i in range(0, len(text_bytes), block_size)])


def xor_bytes(ba1, ba2):
  return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])
