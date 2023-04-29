from utility import *
import challenge15 as c15

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
  decrypt_bytes = c15.check_and_strip_PKCS7(decrypt_bytes, block_size)
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