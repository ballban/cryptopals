from utility import *

block_size = None
random_key = None

def new_oracle(plain_text: str) -> bytes:
  footer_base64 = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
  footer_bytes = base64.b64decode(footer_base64)

  if isinstance(plain_text, str):
    bytes_text = plain_text.encode() + footer_bytes
  else:
    bytes_text = plain_text + footer_bytes

  # ECB
  #print("new_oracle", [bytes_text[x*block_size: (x+1)*block_size] for x in range(len(bytes_text))])
  encrypted_bytes = encrypt_ECB(bytes_text, random_key, block_size)

  return encrypted_bytes

# Step 1
def detect_block_size(plain_text: str, random_key: bytes, block_size = 16):
  for i in range(10):
    new_text = 'A' * i + plain_text
    ECB_encrypted_text = new_oracle(new_text, random_key, block_size)
    print(ECB_encrypted_text)
  return block_size

# Step 2
def detect_ECB_mode(plain_text: str):
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
def craft_input_dict(header: str):
  return {new_oracle(header + bytes([i]))[:block_size]: bytes([i]) for i in range(256)}

# Step 5, 6
def match_output():
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