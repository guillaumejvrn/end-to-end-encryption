import struct
maxi = 4294967295
mini = 0
def encode_header(dh_pub : bytes, pn : int, n : int) -> bytes:
    if (isinstance(dh_pub, bytes)) and (len(dh_pub) == 32):
        if (not isinstance(pn, bool) and isinstance(pn, int) and pn >= mini and pn <= maxi):
            if (not isinstance(n, bool) and isinstance(n, int) and n >= mini and n <= maxi):
                return dh_pub + struct.pack(">II", pn, n)
            raise ValueError("n n'est un entier codé sur 4 bytes")
        raise ValueError("pn n'est un entier codé sur 4 bytes")
    raise ValueError("db_pub n'est pas un bytes de taille 32")


def decode_header(header_bytes: bytes) -> tuple[bytes, int, int]:
    if (isinstance(header_bytes, bytes)) and (len(header_bytes) == 40):
        dh = header_bytes[:32] 
        pn,n = struct.unpack(">II", header_bytes[32:40])
        return (dh,pn,n)
    raise ValueError("header_bytes n'est pas un bytes de taille 40")

