from utility import *

def decrypt_CBC_27(text_bytes: bytes, key: bytes, block_size: int, initialization_vector: bytes, is_unpadding: bool = True):
    decrypt = decrypt_CBC(text_bytes, key, block_size, initialization_vector, True)
    for x in decrypt:
        if x > 127:
          print('eeeeeeeeeeeeeeeeeeeeeeeeeerror')
          break
    return decrypt