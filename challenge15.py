import string

def check_and_strip_PKCS7(plain_bytes, block_size):
  if len(plain_bytes) % block_size != 0:
    raise Exception('Wrong size!')

  while True:
    last_byte = plain_bytes[-1]
    if plain_bytes[-last_byte:] == bytes([last_byte] * last_byte):
      return plain_bytes[:-last_byte]
    elif plain_bytes[-1:] not in string.printable.encode():
      raise Exception(f'Bad padding!:{plain_bytes}')
    else:
      break
  return plain_bytes