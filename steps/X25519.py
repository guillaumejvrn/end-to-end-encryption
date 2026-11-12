import secrets

P = (1 << 255) - 19
A24 = 121665
BASE_POINT = (9).to_bytes(32, "little")


def _clamp_scalar(k_bytes: bytes) -> int:
    if not isinstance(k_bytes, bytes) or len(k_bytes) != 32:
        raise ValueError("La clé privée X25519 doit faire exactement 32 octets")
    k_list = bytearray(k_bytes)
    k_list[0] &= 248
    k_list[31] &= 127
    k_list[31] |= 64
    return int.from_bytes(k_list, "little")


def _decode_u_coordinate(u_bytes: bytes) -> int:
    if not isinstance(u_bytes, bytes) or len(u_bytes) != 32:
        raise ValueError("La clé publique X25519 doit faire exactement 32 octets")
    u_list = bytearray(u_bytes)
    # RFC 7748 Section 5 : ignorer le bit le plus significatif du dernier octet
    u_list[31] &= 127
    return int.from_bytes(u_list, "little") % P


def _cswap(swap: int, x_2: int, x_3: int) -> tuple[int, int]:
    dummy = swap * (x_2 ^ x_3)
    x_2 ^= dummy
    x_3 ^= dummy
    return x_2, x_3


def x25519(private_key: bytes, public_key: bytes) -> bytes:
    """
    Calcule le secret partagé X25519 (RFC 7748) via l'échelle de Montgomery
    sur la courbe Curve25519 modulo 2^255 - 19.
    """
    k = _clamp_scalar(private_key)
    u = _decode_u_coordinate(public_key)

    x_1 = u
    x_2 = 1
    z_2 = 0
    x_3 = u
    z_3 = 1
    swap = 0

    for t in range(254, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        x_2, x_3 = _cswap(swap, x_2, x_3)
        z_2, z_3 = _cswap(swap, z_2, z_3)
        swap = k_t

        A = (x_2 + z_2) % P
        AA = (A * A) % P
        B = (x_2 - z_2) % P
        BB = (B * B) % P
        E = (AA - BB) % P
        C = (x_3 + z_3) % P
        D = (x_3 - z_3) % P
        DA = (D * A) % P
        CB = (C * B) % P

        x_3 = pow(DA + CB, 2, P)
        z_3 = (x_1 * pow(DA - CB, 2, P)) % P
        x_2 = (AA * BB) % P
        z_2 = (E * (AA + A24 * E)) % P

    x_2, x_3 = _cswap(swap, x_2, x_3)
    z_2, z_3 = _cswap(swap, z_2, z_3)

    res = (x_2 * pow(z_2, P - 2, P)) % P
    return res.to_bytes(32, "little")


def generate_keypair() -> tuple[bytes, bytes]:
    """
    Génère une paire de clés X25519 (clé_privée, clé_publique) de 32 octets chacune.
    """
    private_key = secrets.token_bytes(32)
    public_key = x25519(private_key, BASE_POINT)
    return private_key, public_key
