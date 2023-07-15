import struct


def MD_padding(message: bytes, extra_len = 0):
    origin_message_len = len(message)
    message += b'\x80'
    message += b'\x00' * (-(len(message) + 8) % 64)
    message += struct.pack(b'<Q', (origin_message_len + extra_len) * 8)

    return message