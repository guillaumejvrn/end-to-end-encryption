#!/usr/bin/env python3
import argparse
import secrets
import sys
from steps.X25519 import generate_keypair, x25519
from steps.header import decode_header
from steps.ratchet import RatchetState

AD = b"DoubleRatchetCLI-v1"


def _short_hex(data: bytes | None) -> str:
    if data is None:
        return "None"
    return f"{data[:6].hex()}...{data[-4:].hex()}"


def setup_session() -> tuple[RatchetState, RatchetState, bytes]:
    shared_key = secrets.token_bytes(32)
    bob_dh_pair = generate_keypair()

    alice = RatchetState()
    bob = RatchetState()

    alice.init_alice(shared_key, bob_dh_pair[1])
    bob.init_bob(shared_key, bob_dh_pair)
    return alice, bob, shared_key


def send_and_receive(
    sender_name: str,
    receiver_name: str,
    sender: RatchetState,
    receiver: RatchetState,
    text: str,
    deliver: bool = True,
) -> tuple[bytes, bytes] | None:
    try:
        header, ciphertext = sender.ratchet_encrypt(text.encode("utf-8"), AD)
    except RuntimeError as e:
        print(f"[!] Erreur d'envoi ({sender_name}) : {e}")
        return None

    dh_pub, pn, n = decode_header(header)
    print(f"\n[{sender_name} -> {receiver_name}] Paquet chiffré :")
    print(f"  Header     : dh_pub={_short_hex(dh_pub)} | PN={pn} | N={n}")
    print(f"  Ciphertext : {ciphertext.hex()[:64]}... ({len(ciphertext)} octets)")

    if not deliver:
        print(f"  Statut     : EN ATTENTE (paquet retardé sur le réseau)")
        return header, ciphertext

    plaintext = receiver.ratchet_decrypt(header, ciphertext, AD)
    print(f"  Déchiffré  : \"{plaintext.decode('utf-8')}\" (reçu par {receiver_name})")
    return header, ciphertext


def print_status(alice: RatchetState, bob: RatchetState):
    print("\n--- État des Ratchets ---")
    for name, state in [("Alice", alice), ("Bob", bob)]:
        print(f"{name}:")
        print(f"  RK        : {_short_hex(state.RK)}")
        print(f"  DHs (pub) : {_short_hex(state.DHs[1] if state.DHs else None)}")
        print(f"  DHr (pub) : {_short_hex(state.DHr)}")
        print(f"  CKs / CKr : {_short_hex(state.CKs)} / {_short_hex(state.CKr)}")
        print(f"  Compteurs : Ns={state.Ns}, Nr={state.Nr}, PN={state.PN}")
        print(f"  MKSKIPPED : {len(state.MKSKIPPED)} clé(s) en attente")
    print("-------------------------\n")


def run_demo():
    print("=== Démonstration Double Ratchet ===")
    alice, bob, shared_key = setup_session()
    print(f"Secret partagé initial : {_short_hex(shared_key)}")

    # 1. Alice envoie deux messages à Bob
    send_and_receive("Alice", "Bob", alice, bob, "Salut Bob ! Voici le premier message.")
    send_and_receive("Alice", "Bob", alice, bob, "Tout est chiffré de bout en bout.")

    # 2. Bob répond (déclenche un Ratchet DH)
    send_and_receive("Bob", "Alice", bob, alice, "Bien reçu Alice ! Je te réponds avec une nouvelle clé DH.")

    # 3. Simulation de messages hors-ordre (Alice envoie msg #1 retardé, puis msg #2 livré avant)
    print("\n--- Test des messages hors-ordre (MKSKIPPED) ---")
    delayed = send_and_receive(
        "Alice", "Bob", alice, bob, "Message #1 (retardé sur le réseau)", deliver=False
    )
    send_and_receive("Alice", "Bob", alice, bob, "Message #2 (arrivé en avance)")

    if delayed:
        header_d, cipher_d = delayed
        recovered = bob.ratchet_decrypt(header_d, cipher_d, AD)
        print(f"\n[Livraison tardive] Bob déchiffre le message retardé via MKSKIPPED : \"{recovered.decode('utf-8')}\"")

    # 4. Test d'intégrité (altération du ciphertext)
    print("\n--- Test de détection d'altération (HMAC) ---")
    h_test, c_test = alice.ratchet_encrypt(b"Message sensible", AD)
    tampered = bytearray(c_test)
    tampered[15] ^= 0xFF
    try:
        bob.ratchet_decrypt(h_test, bytes(tampered), AD)
    except ValueError as err:
        print(f"[OK] Altération bloquée avec succès : {err}")

    print_status(alice, bob)


def run_interactive():
    alice, bob, shared_key = setup_session()
    delayed_queue: list[tuple[str, str, RatchetState, bytes, bytes]] = []

    print("==================================================")
    print("  Double Ratchet CLI — Session Alice <-> Bob")
    print("==================================================")
    print(f"Secret initial : {_short_hex(shared_key)}")
    print("Commandes disponibles :")
    print("  alice: <texte>        -> Alice envoie un message à Bob")
    print("  bob: <texte>          -> Bob envoie un message à Alice")
    print("  delay alice: <texte>  -> Envoie un message retardé (hors-ordre)")
    print("  delay bob: <texte>    -> Envoie un message retardé (hors-ordre)")
    print("  deliver               -> Livre les messages retardés en attente")
    print("  status                -> Affiche les clés et compteurs internes")
    print("  help                  -> Affiche cette aide")
    print("  quit                  -> Quitter\n")

    while True:
        try:
            raw = input("ratchet> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nFermeture de la session.")
            break

        if not raw:
            continue

        cmd = raw.lower()
        if cmd in ("quit", "exit"):
            print("Fermeture de la session.")
            break
        elif cmd == "help":
            print("  alice: <msg> | bob: <msg> | delay alice: <msg> | delay bob: <msg> | deliver | status | quit")
        elif cmd == "status":
            print_status(alice, bob)
        elif cmd == "deliver":
            if not delayed_queue:
                print("Aucun message retardé en attente.")
                continue
            while delayed_queue:
                s_name, r_name, receiver, h_bytes, c_bytes = delayed_queue.pop(0)
                pt = receiver.ratchet_decrypt(h_bytes, c_bytes, AD)
                print(f"[Livraison tardive {s_name} -> {r_name}] Déchiffré : \"{pt.decode('utf-8')}\"")
        elif cmd.startswith("delay alice:"):
            msg = raw[len("delay alice:") :].strip()
            pkt = send_and_receive("Alice", "Bob", alice, bob, msg, deliver=False)
            if pkt:
                delayed_queue.append(("Alice", "Bob", bob, pkt[0], pkt[1]))
        elif cmd.startswith("delay bob:"):
            msg = raw[len("delay bob:") :].strip()
            pkt = send_and_receive("Bob", "Alice", bob, alice, msg, deliver=False)
            if pkt:
                delayed_queue.append(("Bob", "Alice", alice, pkt[0], pkt[1]))
        elif cmd.startswith("alice:"):
            msg = raw[len("alice:") :].strip()
            send_and_receive("Alice", "Bob", alice, bob, msg, deliver=True)
        elif cmd.startswith("bob:"):
            msg = raw[len("bob:") :].strip()
            send_and_receive("Bob", "Alice", bob, alice, msg, deliver=True)
        else:
            print("Commande inconnue. Utilisez 'alice: <message>', 'bob: <message>' ou 'help'.")


def main():
    parser = argparse.ArgumentParser(
        description="CLI Double Ratchet (chiffrement de bout en bout en Python pur)"
    )
    subparsers = parser.add_subparsers(dest="command")

    parser.add_argument(
        "--demo",
        action="store_true",
        help="Exécute une démonstration complète automatique (Alice/Bob, hors-ordre, intégrité)",
    )
    subparsers.add_parser("chat", help="Lance le mode conversation interactif (par défaut)")
    subparsers.add_parser("keygen", help="Génère une paire de clés X25519 en hexadécimal")

    args = parser.parse_args()

    if args.demo:
        run_demo()
    elif args.command == "keygen":
        sk, pk = generate_keypair()
        print(f"Clé privée (sk)   : {sk.hex()}")
        print(f"Clé publique (pk) : {pk.hex()}")
    else:
        run_interactive()


if __name__ == "__main__":
    main()
