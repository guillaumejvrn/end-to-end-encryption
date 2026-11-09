import X25519
import hashlib

if __name__ == "__main__":
    test_data = b"Hello Double Ratchet"
    result = X25519.sha256(test_data)
    
    print("Entrée :", test_data)
    print("Empreinte (hex) :", result.hex())
    print("Taille :", len(result), "octets")