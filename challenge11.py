from utility import *

def encryption_oracle(plain_text: str, block_size: int) -> bytes:
  bytes_text = plain_text.encode()
  random_key = generate_random_aes_key()
  
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