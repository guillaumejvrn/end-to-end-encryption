import hmac
import hashlib
import secrets
import struct
from hkdf import hkdf_expand

#fonction xor utile pour les calcul des éléments chiffrés
def xor_bytes(b1: bytes, b2: bytes) -> bytes:
	return bytes(x ^ y for x, y in zip(b1, b2))

def encrypt_symmetric(key: bytes, plaintext: bytes, ad: bytes) -> bytes:
	#création des subkeys
	enc_key = hkdf_expand(key, b"enc", 32)
	mac_key = hkdf_expand(key, b"mac", 32)
	
	#génération du Nonce
	nonce = secrets.token_bytes(12)
	
	#initalisation de la liste des blocs du message chiffré
	ciphertext_blocks = []
	
	#étape de la création du texte chiffré en utilisant enc_key
	
	nb_blocks = (len(plaintext) + 31) // 32 #calcul du nombre de blocs(flux)
	for i in range(nb_blocks):
		#Découpage du plaintext par tranche de 32 bytes
		chunk = plaintext[i*32 : (i+1)*32]
		
		#génération des blocks de masque (keystream par block)
		counter_bytes = struct.pack(">I", i)
		keystream_block = hmac.new(enc_key, nonce + counter_bytes, hashlib.sha256).digest()
		
		#portion de message chiffré obtenu par un XOR entre le chunk et le keystream courant
		cipher_chunk = xor_bytes(chunk, keystream_block[:len(chunk)])
		
		#rajout du morceau chiffré
		ciphertext_blocks.append(cipher_chunk)
		
	#rassemblage de toutes les portions ensemble
	ciphertext = b"".join(ciphertext_blocks)
	
	#création du tag avec mac_key
	htag = hmac.new(mac_key, nonce + ciphertext + ad, hashlib.sha256).digest()
	return nonce + ciphertext + htag

def decrypt_symmetric(key: bytes, bundle: bytes, ad: bytes) -> bytes:
	#vérification de la taille du bundle
	if len(bundle) < 44:
		raise ValueError("Le paquet reçu est trop court pour être valide")
	
	#création des subkeys (ce sont les mêmes car même clés)
	enc_key = hkdf_expand(key, b"enc", 32)
	mac_key = hkdf_expand(key, b"mac", 32)
	
	#découpage du paquet brut reçu : nonce + ciphertext + htag
	nonce = bundle[:12] #car on a pris un nonce de 12 bytes
	htag_received = bundle[-32:] #car hmac-sha256 renvoie un truc de taille 32 bytes
	p_ciphertext = bundle[12:-32] #le reste, donc pseudo-ciphertext
	
	#vérifier d'abord que le htag est bon, en recalculant htag avec les éléments obtenus, avant de poursuivre
	htag_computed = hmac.new(mac_key, nonce + p_ciphertext + ad, hashlib.sha256).digest()
	
	if not hmac.compare_digest(htag_computed, htag_received) :
		raise ValueError("Tag ou cipher modifié")
		
	nb_blocks = (len(p_ciphertext) + 31) // 32 #même formule que dans encrypt car len(p_ciphertext) == len(plaintext)
	plaintext_blocks = []
	#quasiment le même procédé que dans encrypt sauf que ça fait l'inverse
	for i in range(nb_blocks):
		
		chunk = p_ciphertext[i*32 : (i+1)*32]
		
		counter_bytes = struct.pack(">I", i)
		keystream_block = hmac.new(enc_key, nonce + counter_bytes, hashlib.sha256).digest()
		
		plain_chunk = xor_bytes(chunk, keystream_block[:len(chunk)])
		
		plaintext_blocks.append(plain_chunk)
	
	plaintext = b"".join(plaintext_blocks)
	return plaintext
	
if __name__ == "__main__":
	print("Tests")
