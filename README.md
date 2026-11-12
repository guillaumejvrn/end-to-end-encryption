# end-to-end-encryption (Double Ratchet en Python)

Implémentation complète de l'algorithme **Double Ratchet** (spécification Signal) en Python avec uniquement la bibliothèque standard (`hashlib`, `hmac`, `secrets`, `struct`).

## Architecture du projet

- `main.py` : Interface en ligne de commande (CLI) interactive et mode démonstration.
- `steps/hkdf.py` : Primitives de hachage et dérivation (`sha256`, `hmac_sha256`, `hkdf_extract`, `hkdf_expand`, `hkdf`).
- `steps/X25519.py` : Échange de clés elliptiques Curve25519 / X25519 (RFC 7748) (`x25519`, `generate_keypair`).
- `steps/KDFRatchets.py` : Cliquets de dérivation de clés (`kdf_ck`, `kdf_rk`).
- `steps/stream_cipher_authentication.py` : Chiffrement par flux authentifié (Encrypt-then-MAC via HMAC-SHA256) (`encrypt_symmetric`, `decrypt_symmetric`).
- `steps/header.py` : Sérialisation et désérialisation des en-têtes de paquets (`encode_header`, `decode_header`).
- `steps/ratchet.py` : Moteur d'état complet `RatchetState` (gestion des cliquets symétriques/asymétriques et des messages hors-ordre `MKSKIPPED`).

## Utilisation en CLI

Lancer la session interactive entre Alice et Bob :
```bash
python3 main.py
```

Lancer la démonstration automatique complète :
```bash
python3 main.py --demo
```
