import sha1

def MAC(key, message):
    return sha1.sha1(key + message)