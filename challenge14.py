from utility import *

random_prefix = None
block_size = None
random_key = None

def new_oracle(plain_text: str) -> bytes:
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


def get_prefix_length():
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


def craft_input_dict(header: str, prefix_block, prefix_size, block_size = 16):
  input_dict = {new_oracle(b'A' * prefix_size + header + bytes([i]))[prefix_block*block_size:(prefix_block+1)*block_size]: bytes([i]) for i in range(256)}
  return input_dict


def match_output():
  header = b'A' * (block_size - 1)
  result = header
  prefix_block, prefix_size = get_prefix_length()
  print(prefix_block, prefix_size)

  for x in range(10):
    for i in range(block_size):
      input_dict = craft_input_dict(header, prefix_block, prefix_size)
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