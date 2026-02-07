import hashlib
import base64

def save(password, token, provided):
    digest = hashlib.md5(password.encode()).hexdigest()
    stored = base64.b64encode(password.encode())
    if token == provided:
        return digest, stored
    return None
