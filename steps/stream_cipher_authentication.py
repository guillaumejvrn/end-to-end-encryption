import hmac
import hashlib
import secrets
import struct
from steps.hkdf import hkdf_expand


def xor_bytes(b1: bytes, b2: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(b1, b2))


def encrypt_symmetric(key: bytes, plaintext: bytes, ad: bytes) -> bytes:
    # Création des subkeys
    enc_key = hkdf_expand(key, b"enc", 32)
    mac_key = hkdf_expand(key, b"mac", 32)

    # Génération du Nonce
    nonce = secrets.token_bytes(12)

    # Initialisation de la liste des blocs du message chiffré
    ciphertext_blocks = []

    # Étape de la création du texte chiffré en utilisant enc_key
    nb_blocks = (len(plaintext) + 31) // 32
    for i in range(nb_blocks):
        chunk = plaintext[i * 32 : (i + 1) * 32]
        counter_bytes = struct.pack(">I", i)
        keystream_block = hmac.new(enc_key, nonce + counter_bytes, hashlib.sha256).digest()
        cipher_chunk = xor_bytes(chunk, keystream_block[: len(chunk)])
        ciphertext_blocks.append(cipher_chunk)

    ciphertext = b"".join(ciphertext_blocks)

    # Création du tag avec mac_key
    htag = hmac.new(mac_key, nonce + ciphertext + ad, hashlib.sha256).digest()
    return nonce + ciphertext + htag


def decrypt_symmetric(key: bytes, bundle: bytes, ad: bytes) -> bytes:
    # Vérification de la taille du bundle
    if len(bundle) < 44:
        raise ValueError("Le paquet reçu est trop court pour être valide")

    # Création des subkeys
    enc_key = hkdf_expand(key, b"enc", 32)
    mac_key = hkdf_expand(key, b"mac", 32)

    # Découpage du paquet brut reçu : nonce + ciphertext + htag
    nonce = bundle[:12]
    htag_received = bundle[-32:]
    p_ciphertext = bundle[12:-32]

    # Vérification du tag d'authentification en temps constant
    htag_computed = hmac.new(mac_key, nonce + p_ciphertext + ad, hashlib.sha256).digest()
    if not hmac.compare_digest(htag_computed, htag_received):
        raise ValueError("Tag ou cipher modifié")

    nb_blocks = (len(p_ciphertext) + 31) // 32
    plaintext_blocks = []
    for i in range(nb_blocks):
        chunk = p_ciphertext[i * 32 : (i + 1) * 32]
        counter_bytes = struct.pack(">I", i)
        keystream_block = hmac.new(enc_key, nonce + counter_bytes, hashlib.sha256).digest()
        plain_chunk = xor_bytes(chunk, keystream_block[: len(chunk)])
        plaintext_blocks.append(plain_chunk)

    return b"".join(plaintext_blocks)
