import hmac
import hashlib
import math as m

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if salt == b"":
        salt = bytes(32)
    PRK = hmac.digest(salt, ikm, hashlib.sha256)
    return PRK

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    assert(length >= 0 and length <= 8160)
    if (length == 0):
        return b""
    result = b""
    hmac_prec = b""
    nb_bloc = m.ceil(length/32)
    for i in range(1,nb_bloc+1):
        mes = hmac_prec + info + i.to_bytes(1, "big")
        hmac_prec = hmac.digest(prk, mes, hashlib.sha256)
        result += hmac_prec
    return result[:length]



def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)


print(hkdf_extract(bytes.fromhex("000102030405060708090a0b0c"),	bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")   ))