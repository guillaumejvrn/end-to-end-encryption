import X25519
import hashlib

def kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    next_ck = X25519.hmac_sha256(ck, b"\x01")
    mk = X25519.hmac_sha256(ck, b"\x02")
    return next_ck, mk


def kdf_rk(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    derived = X25519.hkdf(salt=rk, ikm=dh_out, info=b"WhisperRatchet", length=64)
    next_rk = derived[:32]
    next_ck = derived[32:]
    return next_rk, next_ck