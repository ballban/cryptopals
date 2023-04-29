def encrypt(text, key):
  key = key * int(len(text) / len(key) + 1)
  result = b''
  for i in range(len(text)):
    result += (ord(text[i]) ^ ord(key[i])).to_bytes(1, 'big')
  return result