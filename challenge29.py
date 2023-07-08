import struct


def MD_padding(message: bytes, extra_len = 0):
    origin_message_len = len(message)
    message += b'\x80'
    mod = len(message) % 64
    if mod > 56:
        message += b'\x00' * (120 - len(message) % 64)
    else:
        message += b'\x00' * (56 - len(message) % 64)
    
    message += struct.pack(b'>Q', (origin_message_len + extra_len) * 8)

    return message