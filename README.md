# Double Ratchet — Implémentation & Démonstrateur Visuel E2EE

Implémentation pédagogique en Python de l'algorithme **Double Ratchet** (protocole Signal) accompagnée d'une **interface graphique interactive (Flet)** permettant de visualiser en temps réel le chiffrement de bout en bout entre **Alice** et **Bob**.

---

## Fonctionnalités principales

### 1. Interface graphique interactive (`gui_flet.py`)
* **Schéma d'architecture temps réel (panneau gauche)** :
  * Diagramme visuel en 10 étapes reliées par des connecteurs dynamiques (`Initialisation X3DH` $\rightarrow$ `Expéditeur` $\rightarrow$ `Réseau` $\rightarrow$ `Destinataire`).
  * Indicateurs d'état en direct sur chaque bloc (**En cours**, **Exécuté**, **Sauté**) avec aperçu des clés dérivées (`RK`, `CKs`, `CKr`, `MK`, `DHs`).
  * **Inspecteur détaillé** : cliquez sur n'importe quel bloc du schéma pour afficher l'explication vulgarisée ainsi que les valeurs hexadécimales complètes en entrée et en sortie.
* **Discussion chiffrée (panneau droit)** :
  * Simulation d'une messagerie instantanée entre **Alice** et **Bob** avec indicateur de statut des paquets (*En cours*, *Retardé*, *Déchiffré*).
* **Modes d'exécution & scénarios réseau** :
  * **Mode Pas à pas** : avancez étape par étape (`Étape suivante`) pour observer chaque opération cryptographique (KDF, encodage d'en-tête, X25519, HMAC) avant la livraison du message.
  * **Mode Instantané** : exécute l'ensemble du cycle d'envoi et de réception d'un seul coup.
  * **Simulation hors-ordre (`Simuler retard` / `Livrer retardé`)** : permet de retenir un paquet sur le réseau, d'envoyer d'autres messages entre-temps, puis de livrer le message retardataire afin de démontrer le mécanisme de sauvegarde des clés sautées (`MKSKIPPED`).

### 2. Briques cryptographiques (`steps/`)
* `steps/X25519.py` : génération de paires de clés et échange Diffie-Hellman sur courbe elliptique **Curve25519**.
* `steps/KDFRatchets.py` : fonctions de dérivation de clés pour la chaîne racine (`kdf_rk`) et les chaînes symétriques (`kdf_ck`) basées sur **HKDF / HMAC-SHA256**.
* `steps/header.py` : sérialisation et désérialisation binaires (40 octets) des en-têtes contenant la clé publique DH courante et les compteurs `PN` et `N`.
* `steps/stream_cipher_authentication.py` : chiffrement authentifié (Nonce aléatoire 12 octets, chiffrement par flux et signature d'intégrité **HMAC-SHA256** couvrant les données associées `AD` et l'en-tête).
* `steps/ratchet.py` : machine à états complète `RatchetState` gérant la *Forward Secrecy*, la *Break-in Recovery* (guérison post-compromission) et le dictionnaire `MKSKIPPED`.

---

## Structure du projet

```text
.
├── gui_flet.py                               # Interface graphique interactive (Flet)
├── steps/
│   ├── X25519.py                             # Échange de clés Curve25519
│   ├── KDFRatchets.py                        # Fonctions KDF (Root & Chain)
│   ├── header.py                             # Encodage / décodage des en-têtes (40B)
│   ├── stream_cipher_authentication.py       # Chiffrement & authentification HMAC
│   └── ratchet.py                            # État et logique du Double Ratchet
└── README.md
```

---

## Installation & Lancement

### Prérequis
* **Python 3.10+**
* Bibliothèques `flet` et `cryptography`

```bash
pip install flet cryptography
```

### Démarrer l'application
Assurez-vous que le fichier principal de l'interface se nomme `gui_flet.py`, puis lancez :

```bash
python3 gui_flet.py
```

---

## Scénarios de démonstration conseillés

1. **Ratchet symétrique simple (*Forward Secrecy*)** :
   * Envoyez deux messages consécutifs depuis **Alice** vers **Bob**.
   * Observez que les blocs `6. Ratchet DH #1` et `7. Ratchet DH #2` sont **sautés** : seule la chaîne d'envoi `CKs` avance, générant une clé `MK` différente à chaque message.
2. **Ratchet asymétrique Diffie-Hellman (*Break-in Recovery*)** :
   * Faites répondre **Bob** à **Alice**.
   * Observez l'activation des blocs `6` et `7` : une nouvelle paire **X25519** est générée et la clé racine `RK` est renouvelée.
3. **Messages désordonnés (`MKSKIPPED`)** :
   * Cliquez sur **Simuler retard** côté Alice pour un premier message, puis envoyez un second message normalement.
   * Observez l'activation du bloc `5. Hors-Ordre` chez Bob qui archive la clé manquante, puis cliquez sur **Livrer retardé** en haut pour déchiffrer le premier message grâce à la clé mise de côté.