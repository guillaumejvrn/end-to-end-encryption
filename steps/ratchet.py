from steps.header import decode_header, encode_header
from steps.KDFRatchets import kdf_ck, kdf_rk
from steps.stream_cipher_authentication import encrypt_symmetric, decrypt_symmetric
from steps.X25519 import x25519, generate_keypair


class RatchetState:
    MAX_SKIP = 100

    def __init__(self):
        self.RK = None
        self.CKs = None
        self.CKr = None
        self.DHs = None
        self.DHr = None
        self.Ns = 0
        self.Nr = 0
        self.PN = 0
        self.MKSKIPPED = {}

    def init_alice(self, shared_key: bytes, bob_dh_pub: bytes):
        # 1. Initialisation de la clé racine
        self.RK = shared_key

        # 2. Génération de la paire de clés DH d'Alice
        self.DHs = generate_keypair()

        # 3. Enregistrement de la clé publique de Bob
        self.DHr = bob_dh_pub

        # 4. Calcul du secret partagé DH
        dh_out = x25519(self.DHs[0], self.DHr)

        # 5. Dérivation des nouvelles clés
        self.RK, self.CKs = kdf_rk(self.RK, dh_out)

    def init_bob(self, shared_key: bytes, bob_dh_pair: tuple[bytes, bytes]):
        # 1. Initialisation de la clé racine
        self.RK = shared_key

        # 2. Enregistrement de la paire DH de Bob
        self.DHs = bob_dh_pair

        # 3. Alice n'a pas encore communiqué sa clé publique
        self.DHr = None

        # 4. Les chaînes seront dérivées lors du premier ratchet
        self.CKs = None
        self.CKr = None

        # 5. Initialisation des compteurs
        self.Ns = 0
        self.Nr = 0
        self.PN = 0

        # 6. Initialisation des clés de messages sautés
        self.MKSKIPPED = {}

    def ratchet_encrypt(self, plaintext: bytes, ad: bytes = b"") -> tuple[bytes, bytes]:
        if self.CKs is None:
            raise RuntimeError("Chaîne d'envoi non initialisée (attendez un premier message).")

        # Dérive une nouvelle clé de chaîne et une clé pour ce message
        self.CKs, MK = kdf_ck(self.CKs)

        # Construit le header avec notre clé publique DH
        header_bytes = encode_header(self.DHs[1], self.PN, self.Ns)

        # Chiffre le message en authentifiant aussi le header
        ciphertext = encrypt_symmetric(MK, plaintext, ad + header_bytes)

        # Passe au numéro de message suivant
        self.Ns += 1

        return header_bytes, ciphertext

    def ratchet_decrypt(self, header_bytes: bytes, ciphertext: bytes, ad: bytes = b"") -> bytes:
        # 1. Décodage du header
        dh_pub, pn, n = decode_header(header_bytes)

        # 2. Vérification des clés de messages déjà sauvegardées
        if (dh_pub, n) in self.MKSKIPPED:
            MK = self.MKSKIPPED.pop((dh_pub, n))
            return decrypt_symmetric(MK, ciphertext, ad + header_bytes)

        # 3. Vérification d'un éventuel changement de clé DH
        if dh_pub != self.DHr:
            # Sauvegarde les clés manquantes de l'ancienne chaîne
            self.skip_message_keys(pn)
            # Effectue le nouveau DH Ratchet
            self.dh_ratchet(dh_pub)

        # 4. Sauvegarde les clés des éventuels messages manquants
        self.skip_message_keys(n)

        # 5. Dérive la clé du message actuel
        self.CKr, MK = kdf_ck(self.CKr)
        self.Nr += 1

        # 6. Déchiffre le message en vérifiant l'authenticité du header
        return decrypt_symmetric(MK, ciphertext, ad + header_bytes)

    def skip_message_keys(self, until: int):
        if self.CKr is None and until > self.Nr:
            raise ValueError("Chaîne de réception non initialisée")

        while self.Nr < until:
            if len(self.MKSKIPPED) >= RatchetState.MAX_SKIP:
                raise Exception("Trop de messages en attente")

            self.CKr, MK = kdf_ck(self.CKr)
            self.MKSKIPPED[(self.DHr, self.Nr)] = MK
            self.Nr += 1

    def dh_ratchet(self, dh_pub: bytes):
        # 1. Mise à jour des compteurs
        self.PN = self.Ns
        self.Ns = 0
        self.Nr = 0

        # 2. Enregistrement de la nouvelle clé publique distante
        self.DHr = dh_pub

        # 3. Renouvellement de la clé racine et de la chaîne de réception
        dh_out = x25519(self.DHs[0], self.DHr)
        self.RK, self.CKr = kdf_rk(self.RK, dh_out)

        # 4. Génération d'une nouvelle paire de clés locale
        self.DHs = generate_keypair()

        # 5. Renouvellement de la clé racine et de la chaîne d'envoi
        dh_out = x25519(self.DHs[0], self.DHr)
        self.RK, self.CKs = kdf_rk(self.RK, dh_out)
