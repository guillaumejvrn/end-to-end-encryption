import hashlib
import math
import hmac

def sha256(message: bytes) -> bytes:
    return hashlib.sha256(message).digest()

def hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = b"\x00" * 32

    return hmac_sha256(salt, ikm)

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    n = math.ceil(length / 32)
    okm = bytearray()
    t = b""
    for i in range(1, n + 1):
        t = hmac_sha256(prk, t + info + bytes([i]))
        okm.extend(t)
    return bytes(okm[:length])

def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)