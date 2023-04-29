import string

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