import hmac
import hashlib
import math as m


def sha256(message: bytes) -> bytes:
    return hashlib.sha256(message).digest()


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = bytes(32)
    return hmac_sha256(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    if not (0 <= length <= 8160):
        raise ValueError("length doit être compris entre 0 et 8160 octets")
    if length == 0:
        return b""
    result = bytearray()
    hmac_prec = b""
    nb_bloc = m.ceil(length / 32)
    for i in range(1, nb_bloc + 1):
        mes = hmac_prec + info + i.to_bytes(1, "big")
        hmac_prec = hmac_sha256(prk, mes)
        result.extend(hmac_prec)
    return bytes(result[:length])


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)


if __name__ == "__main__":
    print(
        hkdf_extract(
            bytes.fromhex("000102030405060708090a0b0c"),
            bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
        ).hex()
    )
