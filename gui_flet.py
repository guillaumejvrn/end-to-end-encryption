#!/usr/bin/env python3
"""
Interface Graphique Pédagogique (Flet) pour l'algorithme Double Ratchet.
Design épuré inspiré d'Apple (macOS / iMessage) :
- Gauche : Schéma visuel interactif en temps réel (cartes minimalistes, lignes fines, palette système).
- Droite : Messagerie style iMessage entre Alice et Bob.
- Haut   : Barre d'outils sobre avec contrôle segmenté (Instantané / Pas à pas).
"""

import secrets
import flet as ft

from steps.X25519 import generate_keypair, x25519
from steps.header import encode_header, decode_header
from steps.KDFRatchets import kdf_ck, kdf_rk
from steps.stream_cipher_authentication import encrypt_symmetric, decrypt_symmetric
from steps.ratchet import RatchetState

# Compatibilité multi-versions Flet (< 0.80 et >= 0.80 / 1.0)
COLORS = getattr(ft, "Colors", getattr(ft, "colors", None))
ICONS = getattr(ft, "Icons", getattr(ft, "icons", None))
BUTTON = getattr(ft, "ElevatedButton", getattr(ft, "Button", None))
PADDING = getattr(ft, "Padding", getattr(ft, "padding", None))
BORDER = getattr(ft, "Border", getattr(ft, "border", None))
ALIGNMENT = getattr(ft, "Alignment", getattr(ft, "alignment", None))
CENTER_ALIGN = getattr(ALIGNMENT, "CENTER", getattr(ALIGNMENT, "center", None))

# Palette Apple HIG (Light Mode)
BG_WINDOW = "#F5F5F7"
BG_CARD = "#FFFFFF"
BG_SUBTLE = "#F2F2F7"
BORDER_HAIRLINE = "#E5E5EA"
BORDER_STRONG = "#D1D1D6"
TEXT_PRIMARY = "#1D1D1F"
TEXT_SECONDARY = "#6E6E73"
TEXT_TERTIARY = "#8E8E93"

ACCENT_BLUE = "#007AFF"
ACCENT_BLUE_SOFT = "#EBF5FF"
ACCENT_INDIGO = "#5856D6"
ACCENT_INDIGO_SOFT = "#F0EFFF"
ACCENT_GREEN = "#34C759"
ACCENT_GREEN_SOFT = "#EAFBF0"
ACCENT_ORANGE = "#FF9500"
ACCENT_ORANGE_SOFT = "#FFF6E6"

AD = b"DoubleRatchetGUI-v2"


def set_btn_label(btn, label: str):
    if hasattr(btn, "text"):
        btn.text = label
    else:
        btn.content = label


def get_icon(name: str, fallback: str = "CIRCLE"):
    if not ICONS:
        return None
    return getattr(ICONS, name, getattr(ICONS, fallback, None))


def short_hex(data: bytes | None, head: int = 5, tail: int = 4) -> str:
    if data is None:
        return "None"
    if len(data) <= head + tail:
        return data.hex()
    return f"{data[:head].hex()}…{data[-tail:].hex()}"


def full_hex(data: bytes | None) -> str:
    if data is None:
        return "Non initialisé"
    return data.hex()


# Définition des 10 étapes du schéma Double Ratchet
STEP_DEFINITIONS = [
    {
        "id": 0,
        "short_title": "0. Initialisation",
        "title": "0. Initialisation X3DH",
        "icon": "KEY",
        "func": "init_alice() / init_bob()",
        "default_actor": "Alice & Bob",
        "default_desc": "RK partagée & 1ère DH",
        "default_vulga": (
            "Avant tout échange, Alice et Bob partagent une Clé Racine initiale (RK) et Bob a publié "
            "sa clé publique X25519. Alice génère sa paire DH et dérive sa première chaîne d'envoi CKs."
        ),
    },
    {
        "id": 1,
        "short_title": "1. KDF Envoi",
        "title": "1. Ratchet Symétrique (Envoi)",
        "icon": "SYNC_ALT",
        "func": "kdf_ck(CKs)",
        "default_actor": "Expéditeur",
        "default_desc": "Dérive MK unique",
        "default_vulga": (
            "L'expéditeur fait avancer sa Clé de Chaîne d'envoi (CKs) via HMAC-SHA256 pour obtenir "
            "une nouvelle CKs et une Clé de Message (MK) à usage unique (Forward Secrecy)."
        ),
    },
    {
        "id": 2,
        "short_title": "2. En-tête",
        "title": "2. Encodage de l'en-tête",
        "icon": "TAG",
        "func": "encode_header(DHs, PN, Ns)",
        "default_actor": "Expéditeur",
        "default_desc": "DHs_pub + PN + N (40 o)",
        "default_vulga": (
            "L'expéditeur assemble l'en-tête de 40 octets : sa clé publique Diffie-Hellman actuelle, "
            "la longueur de la chaîne précédente (PN) et le numéro du message courant (N)."
        ),
    },
    {
        "id": 3,
        "short_title": "3. Chiffrement",
        "title": "3. Chiffrement & Signature HMAC",
        "icon": "LOCK_OUTLINE",
        "func": "encrypt_symmetric(MK, msg)",
        "default_actor": "Expéditeur",
        "default_desc": "Flux XOR + Tag HMAC",
        "default_vulga": (
            "Le texte est chiffré avec la clé MK et un Nonce aléatoire (12 octets), puis signé par "
            "un tag HMAC-SHA256 couvrant également l'en-tête pour garantir son intégrité."
        ),
    },
    {
        "id": 4,
        "short_title": "4. Lecture En-tête",
        "title": "4. Décodage de l'en-tête",
        "icon": "SEARCH",
        "func": "decode_header(header)",
        "default_actor": "Destinataire",
        "default_desc": "Vérifie rotation DH",
        "default_vulga": (
            "Le destinataire extrait la clé publique DH de l'expéditeur et vérifie si elle a changé "
            "depuis le dernier message reçu, ce qui déclenche un Ratchet asymétrique."
        ),
    },
    {
        "id": 5,
        "short_title": "5. Hors-Ordre",
        "title": "5. Gestion des messages sautés",
        "icon": "INVENTORY_2_OUTLINED",
        "func": "skip_message_keys()",
        "default_actor": "Destinataire",
        "default_desc": "Coffre MKSKIPPED",
        "default_vulga": (
            "Si des messages manquent à l'appel ou arrivent en retard, leurs clés MK sont archivées "
            "ou récupérées dans le dictionnaire MKSKIPPED."
        ),
    },
    {
        "id": 6,
        "short_title": "6. Ratchet DH #1",
        "title": "6. Ratchet DH (Réception)",
        "icon": "AUTORENEW",
        "func": "x25519() + kdf_rk()",
        "default_actor": "Destinataire",
        "default_desc": "Renouvelle RK & CKr",
        "default_vulga": (
            "Lors d'un changement de tour de parole, le destinataire combine sa clé privée actuelle "
            "avec la nouvelle clé publique reçue (Curve25519) pour dériver RK et CKr."
        ),
    },
    {
        "id": 7,
        "short_title": "7. Ratchet DH #2",
        "title": "7. Ratchet DH (Nouvelle clé)",
        "icon": "ENHANCED_ENCRYPTION_OUTLINED",
        "func": "generate_keypair() + kdf_rk()",
        "default_actor": "Destinataire",
        "default_desc": "Nouvelle paire DHs & CKs",
        "default_vulga": (
            "Le destinataire génère une nouvelle paire X25519 pour sa future réponse et re-mélange RK "
            "afin de créer sa nouvelle chaîne d'envoi CKs (guérison post-compromission)."
        ),
    },
    {
        "id": 8,
        "short_title": "8. KDF Réception",
        "title": "8. Ratchet Symétrique (Réception)",
        "icon": "SYNC",
        "func": "kdf_ck(CKr)",
        "default_actor": "Destinataire",
        "default_desc": "Retrouve la clé MK",
        "default_vulga": (
            "Le destinataire fait avancer sa chaîne de réception CKr d'un cran via HMAC-SHA256 et "
            "retrouve la clé MK identique à celle utilisée lors de l'envoi."
        ),
    },
    {
        "id": 9,
        "short_title": "9. Déchiffrement",
        "title": "9. Vérification HMAC & Déchiffrement",
        "icon": "LOCK_OPEN_OUTLINED",
        "func": "decrypt_symmetric(MK, paquet)",
        "default_actor": "Destinataire",
        "default_desc": "Validation & texte clair",
        "default_vulga": (
            "Le destinataire vérifie d'abord l'authenticité via HMAC-SHA256, puis déchiffre le message "
            "qui s'affiche en clair dans la conversation."
        ),
    },
]


class StepUpdate:
    """Mise à jour atomique d'une carte du schéma visuel."""

    def __init__(
        self,
        row_id: int,
        status: str,  # "done" | "skipped"
        actor: str,
        live_value: str,
        vulgarisation: str,
        inputs_detail: str,
        outputs_detail: str,
        on_reveal=None,
    ):
        self.row_id = row_id
        self.status = status
        self.actor = actor
        self.live_value = live_value
        self.vulgarisation = vulgarisation
        self.inputs_detail = inputs_detail
        self.outputs_detail = outputs_detail
        self.on_reveal = on_reveal


class DoubleRatchetApp:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "Double Ratchet — Démonstrateur E2EE"
        self.page.window.width = 1440
        self.page.window.height = 900
        self.page.padding = 16
        self.page.theme_mode = ft.ThemeMode.LIGHT
        self.page.bgcolor = BG_WINDOW

        # États cryptographiques
        self.alice: RatchetState = RatchetState()
        self.bob: RatchetState = RatchetState()
        self.shared_key: bytes = b""
        self.bob_initial_dh: tuple[bytes, bytes] = (b"", b"")

        # État des 10 cartes du schéma
        self.row_states: dict[int, dict] = {}
        self.selected_row_id: int = 0
        self.active_row_id: int | None = None

        # État du canal réseau
        self.network_status_text: str = "Canal prêt — En attente d'un message"
        self.network_is_active: bool = False
        self.current_sender: str = "Alice"
        self.current_receiver: str = "Bob"

        # File d'étapes en attente pour le mode pas à pas
        self.pending_updates: list[StepUpdate] = []
        self.delayed_packets: list[dict] = []

        # Mode par défaut : pas à pas
        self.execution_mode: str = "step"

        self._build_ui()
        self._reset_session(initial=True)

    # ------------------------------------------------------------------
    # Initialisation / Réinitialisation de la session et du schéma
    # ------------------------------------------------------------------
    def _init_fixed_nodes(self):
        self.row_states = {}
        for item in STEP_DEFINITIONS:
            rid = item["id"]
            self.row_states[rid] = {
                "id": rid,
                "short_title": item["short_title"],
                "title": item["title"],
                "icon": item["icon"],
                "func": item["func"],
                "status": "pending",
                "actor": item["default_actor"],
                "live_value": item["default_desc"],
                "vulgarisation": item["default_vulga"],
                "inputs_detail": "En attente d'exécution…",
                "outputs_detail": "En attente d'exécution…",
            }

    def _prepare_nodes_for_new_message(self, sender_name: str, receiver_name: str):
        self.current_sender = sender_name
        self.current_receiver = receiver_name
        for item in STEP_DEFINITIONS:
            rid = item["id"]
            if rid == 0:
                continue
            self.row_states[rid]["status"] = "pending"
            self.row_states[rid]["actor"] = sender_name if rid in (1, 2, 3) else receiver_name
            self.row_states[rid]["live_value"] = "En attente"
            self.row_states[rid]["vulgarisation"] = item["default_vulga"]
            self.row_states[rid]["inputs_detail"] = "Pas encore exécutée pour ce message."
            self.row_states[rid]["outputs_detail"] = "Pas encore exécutée pour ce message."
        self.active_row_id = None

    def _reset_session(self, initial: bool = False):
        self.shared_key = secrets.token_bytes(32)
        self.bob_initial_dh = generate_keypair()

        self.alice = RatchetState()
        self.bob = RatchetState()
        self.alice.init_alice(self.shared_key, self.bob_initial_dh[1])
        self.bob.init_bob(self.shared_key, self.bob_initial_dh)

        self.pending_updates.clear()
        self.delayed_packets.clear()
        self._init_fixed_nodes()

        self.current_sender = "Alice"
        self.current_receiver = "Bob"
        self.network_status_text = "Session initialisée — Canal prêt"
        self.network_is_active = False

        # Bloc 0 (Initialisation) actif dès le départ
        self.row_states[0]["status"] = "done"
        self.row_states[0]["actor"] = "Alice & Bob"
        self.row_states[0]["live_value"] = f"RK {short_hex(self.alice.RK)} · CKs {short_hex(self.alice.CKs)}"
        self.row_states[0]["inputs_detail"] = (
            f"Secret partagé (RK) : {full_hex(self.shared_key)}\n"
            f"Clé publique DH Bob : {full_hex(self.bob_initial_dh[1])}"
        )
        self.row_states[0]["outputs_detail"] = (
            f"Alice RK  : {full_hex(self.alice.RK)}\n"
            f"Alice CKs : {full_hex(self.alice.CKs)}\n"
            f"Alice DHs : {full_hex(self.alice.DHs[1])}\n"
            f"Bob RK    : {full_hex(self.bob.RK)}"
        )

        self.selected_row_id = 0
        self.active_row_id = 0

        self.chat_list.controls.clear()
        self.chat_list.controls.append(
            self._make_system_banner(
                f"Session chiffrée initialisée · RK {short_hex(self.shared_key)}"
            )
        )

        self._refresh_all_ui()
        if not initial:
            self._notify("Session réinitialisée.")

    # ------------------------------------------------------------------
    # Construction de l'interface style Apple / macOS
    # ------------------------------------------------------------------
    def _card_shadow(self):
        return ft.BoxShadow(
            spread_radius=0,
            blur_radius=12,
            color="#0D000000",
            offset=ft.Offset(0, 3),
        )

    def _build_ui(self):
        # --- Contrôle segmenté style macOS pour le mode d'exécution ---
        self.seg_instant = ft.Container(
            content=ft.Text("Instantané", size=12, weight=ft.FontWeight.W_500),
            padding=PADDING.symmetric(horizontal=12, vertical=5),
            border_radius=7,
            on_click=lambda _: self._set_mode("instant"),
        )
        self.seg_step = ft.Container(
            content=ft.Text("Pas à pas", size=12, weight=ft.FontWeight.W_500),
            padding=PADDING.symmetric(horizontal=12, vertical=5),
            border_radius=7,
            on_click=lambda _: self._set_mode("step"),
        )
        segmented_control = ft.Container(
            bgcolor=BG_SUBTLE,
            padding=2,
            border_radius=9,
            border=BORDER.all(1, BORDER_HAIRLINE),
            content=ft.Row(spacing=2, controls=[self.seg_instant, self.seg_step]),
        )

        # --- Boutons d'action sobres ---
        self.next_step_btn = BUTTON(
            "Étape suivante",
            icon=get_icon("ARROW_FORWARD_IOS", "SKIP_NEXT"),
            bgcolor=ACCENT_BLUE,
            color=COLORS.WHITE,
            style=ft.ButtonStyle(
                shape=ft.RoundedRectangleBorder(radius=8),
                elevation=0,
            ),
            on_click=self._on_next_step_click,
            disabled=True,
        )

        self.finish_all_btn = ft.OutlinedButton(
            "Terminer",
            style=ft.ButtonStyle(
                shape=ft.RoundedRectangleBorder(radius=8),
                side=ft.BorderSide(1, BORDER_STRONG),
                color=TEXT_PRIMARY,
            ),
            on_click=self._on_finish_all_click,
            disabled=True,
        )

        self.deliver_delayed_btn = ft.OutlinedButton(
            "Livrer retardé (0)",
            style=ft.ButtonStyle(
                shape=ft.RoundedRectangleBorder(radius=8),
                side=ft.BorderSide(1, BORDER_STRONG),
                color=TEXT_PRIMARY,
            ),
            on_click=self._on_deliver_delayed_click,
            disabled=True,
        )

        self.reset_btn = ft.IconButton(
            icon=get_icon("REFRESH"),
            icon_color=TEXT_SECONDARY,
            icon_size=19,
            tooltip="Réinitialiser la session",
            on_click=lambda _: self._reset_session(initial=False),
        )

        self.status_dot = ft.Container(width=8, height=8, border_radius=4, bgcolor=ACCENT_GREEN)
        self.status_label = ft.Text("Synchronisé", size=12, weight=ft.FontWeight.W_500, color=TEXT_SECONDARY)
        status_pill = ft.Container(
            bgcolor=BG_SUBTLE,
            padding=PADDING.symmetric(horizontal=10, vertical=5),
            border_radius=12,
            content=ft.Row(spacing=6, controls=[self.status_dot, self.status_label]),
        )

        top_bar = ft.Container(
            bgcolor=BG_CARD,
            padding=PADDING.symmetric(horizontal=16, vertical=10),
            border_radius=14,
            border=BORDER.all(1, BORDER_HAIRLINE),
            shadow=self._card_shadow(),
            content=ft.Row(
                wrap=True,
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
                    ft.Row(
                        spacing=10,
                        controls=[
                            ft.Container(
                                width=30,
                                height=30,
                                border_radius=8,
                                bgcolor=ACCENT_BLUE,
                                alignment=CENTER_ALIGN,
                                content=ft.Icon(get_icon("LOCK"), color=COLORS.WHITE, size=16),
                            ),
                            ft.Column(
                                spacing=0,
                                controls=[
                                    ft.Text(
                                        "Double Ratchet",
                                        size=15,
                                        weight=ft.FontWeight.W_600,
                                        color=TEXT_PRIMARY,
                                    ),
                                    ft.Text(
                                        "Protocole de chiffrement de bout en bout",
                                        size=11,
                                        color=TEXT_SECONDARY,
                                    ),
                                ],
                            ),
                        ],
                    ),
                    ft.Row(
                        wrap=True,
                        spacing=10,
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        controls=[
                            segmented_control,
                            self.next_step_btn,
                            self.finish_all_btn,
                            self.deliver_delayed_btn,
                            status_pill,
                            self.reset_btn,
                        ],
                    ),
                ],
            ),
        )

        # --- PANNEAU GAUCHE : Schéma visuel épuré + Inspecteur ---
        self.alice_state_text = ft.Text("", size=11, font_family="monospace", color=TEXT_SECONDARY)
        self.bob_state_text = ft.Text("", size=11, font_family="monospace", color=TEXT_SECONDARY)

        actors_header = ft.Row(
            spacing=10,
            controls=[
                ft.Container(
                    expand=True,
                    bgcolor=BG_SUBTLE,
                    padding=10,
                    border_radius=12,
                    border=BORDER.all(1, BORDER_HAIRLINE),
                    content=ft.Row(
                        spacing=10,
                        controls=[
                            ft.Container(
                                width=32,
                                height=32,
                                border_radius=16,
                                bgcolor=ACCENT_BLUE,
                                alignment=CENTER_ALIGN,
                                content=ft.Text("A", size=14, weight=ft.FontWeight.W_600, color=COLORS.WHITE),
                            ),
                            ft.Column(
                                spacing=2,
                                expand=True,
                                controls=[
                                    ft.Text("Alice", size=13, weight=ft.FontWeight.W_600, color=TEXT_PRIMARY),
                                    self.alice_state_text,
                                ],
                            ),
                        ],
                    ),
                ),
                ft.Container(
                    expand=True,
                    bgcolor=BG_SUBTLE,
                    padding=10,
                    border_radius=12,
                    border=BORDER.all(1, BORDER_HAIRLINE),
                    content=ft.Row(
                        spacing=10,
                        controls=[
                            ft.Container(
                                width=32,
                                height=32,
                                border_radius=16,
                                bgcolor=ACCENT_INDIGO,
                                alignment=CENTER_ALIGN,
                                content=ft.Text("B", size=14, weight=ft.FontWeight.W_600, color=COLORS.WHITE),
                            ),
                            ft.Column(
                                spacing=2,
                                expand=True,
                                controls=[
                                    ft.Text("Bob", size=13, weight=ft.FontWeight.W_600, color=TEXT_PRIMARY),
                                    self.bob_state_text,
                                ],
                            ),
                        ],
                    ),
                ),
            ],
        )

        self.schema_container = ft.Column(
            spacing=6,
            scroll=ft.ScrollMode.AUTO,
            expand=True,
        )

        # Inspecteur bas de page style macOS Inspector
        self.detail_title = ft.Text("", size=13, weight=ft.FontWeight.W_600, color=TEXT_PRIMARY)
        self.detail_func = ft.Text("", size=11, font_family="monospace", color=ACCENT_BLUE)
        self.detail_vulgarisation = ft.Text("", size=12, color=TEXT_SECONDARY)
        self.detail_inputs = ft.Text("", size=10.5, font_family="monospace", color=TEXT_PRIMARY, selectable=True)
        self.detail_outputs = ft.Text("", size=10.5, font_family="monospace", color=TEXT_PRIMARY, selectable=True)

        detail_panel = ft.Container(
            bgcolor=BG_SUBTLE,
            padding=12,
            border_radius=12,
            border=BORDER.all(1, BORDER_HAIRLINE),
            height=175,
            content=ft.Column(
                scroll=ft.ScrollMode.AUTO,
                spacing=6,
                controls=[
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[self.detail_title, self.detail_func],
                    ),
                    self.detail_vulgarisation,
                    ft.Row(
                        spacing=8,
                        vertical_alignment=ft.CrossAxisAlignment.START,
                        controls=[
                            ft.Container(
                                expand=True,
                                bgcolor=BG_CARD,
                                padding=8,
                                border_radius=8,
                                border=BORDER.all(1, BORDER_HAIRLINE),
                                content=ft.Column(
                                    spacing=3,
                                    controls=[
                                        ft.Text("ENTRÉES", size=10, weight=ft.FontWeight.W_600, color=TEXT_TERTIARY),
                                        self.detail_inputs,
                                    ],
                                ),
                            ),
                            ft.Container(
                                expand=True,
                                bgcolor=BG_CARD,
                                padding=8,
                                border_radius=8,
                                border=BORDER.all(1, BORDER_HAIRLINE),
                                content=ft.Column(
                                    spacing=3,
                                    controls=[
                                        ft.Text("SORTIES", size=10, weight=ft.FontWeight.W_600, color=TEXT_TERTIARY),
                                        self.detail_outputs,
                                    ],
                                ),
                            ),
                        ],
                    ),
                ],
            ),
        )

        left_pane = ft.Container(
            expand=6,
            bgcolor=BG_CARD,
            padding=14,
            border_radius=16,
            border=BORDER.all(1, BORDER_HAIRLINE),
            shadow=self._card_shadow(),
            content=ft.Column(
                spacing=10,
                controls=[
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Text(
                                "Flux cryptographique",
                                size=14,
                                weight=ft.FontWeight.W_600,
                                color=TEXT_PRIMARY,
                            ),
                            ft.Row(
                                spacing=10,
                                controls=[
                                    self._legend_dot(ACCENT_ORANGE, "En cours"),
                                    self._legend_dot(ACCENT_GREEN, "Exécuté"),
                                    self._legend_dot(BORDER_STRONG, "Sauté"),
                                ],
                            ),
                        ],
                    ),
                    actors_header,
                    self.schema_container,
                    detail_panel,
                ],
            ),
        )

        # --- PANNEAU DROIT : Style iMessage ---
        self.chat_list = ft.ListView(
            expand=True,
            spacing=8,
            auto_scroll=True,
            padding=12,
        )

        self.alice_input = ft.TextField(
            hint_text="Message d'Alice…",
            expand=True,
            dense=True,
            border_radius=18,
            bgcolor=BG_CARD,
            border_color=BORDER_STRONG,
            focused_border_color=ACCENT_BLUE,
            text_size=13,
            content_padding=PADDING.symmetric(horizontal=14, vertical=8),
            on_submit=lambda _: self._handle_send("Alice", "Bob", delayed=False),
        )
        self.bob_input = ft.TextField(
            hint_text="Message de Bob…",
            expand=True,
            dense=True,
            border_radius=18,
            bgcolor=BG_CARD,
            border_color=BORDER_STRONG,
            focused_border_color=ACCENT_INDIGO,
            text_size=13,
            content_padding=PADDING.symmetric(horizontal=14, vertical=8),
            on_submit=lambda _: self._handle_send("Bob", "Alice", delayed=False),
        )

        alice_controls = ft.Container(
            bgcolor=BG_SUBTLE,
            padding=10,
            border_radius=12,
            border=BORDER.all(1, BORDER_HAIRLINE),
            content=ft.Column(
                spacing=6,
                controls=[
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Row(
                                spacing=6,
                                controls=[
                                    ft.Container(width=8, height=8, border_radius=4, bgcolor=ACCENT_BLUE),
                                    ft.Text("Alice", size=12, weight=ft.FontWeight.W_600, color=TEXT_PRIMARY),
                                ],
                            ),
                            ft.TextButton(
                                "Simuler retard",
                                style=ft.ButtonStyle(color=TEXT_SECONDARY, padding=0),
                                on_click=lambda _: self._handle_send("Alice", "Bob", delayed=True),
                            ),
                        ],
                    ),
                    ft.Row(
                        spacing=8,
                        controls=[
                            self.alice_input,
                            ft.IconButton(
                                icon=get_icon("ARROW_UPWARD"),
                                bgcolor=ACCENT_BLUE,
                                icon_color=COLORS.WHITE,
                                icon_size=18,
                                tooltip="Envoyer",
                                on_click=lambda _: self._handle_send("Alice", "Bob", delayed=False),
                            ),
                        ],
                    ),
                ],
            ),
        )

        bob_controls = ft.Container(
            bgcolor=BG_SUBTLE,
            padding=10,
            border_radius=12,
            border=BORDER.all(1, BORDER_HAIRLINE),
            content=ft.Column(
                spacing=6,
                controls=[
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Row(
                                spacing=6,
                                controls=[
                                    ft.Container(width=8, height=8, border_radius=4, bgcolor=ACCENT_INDIGO),
                                    ft.Text("Bob", size=12, weight=ft.FontWeight.W_600, color=TEXT_PRIMARY),
                                ],
                            ),
                            ft.TextButton(
                                "Simuler retard",
                                style=ft.ButtonStyle(color=TEXT_SECONDARY, padding=0),
                                on_click=lambda _: self._handle_send("Bob", "Alice", delayed=True),
                            ),
                        ],
                    ),
                    ft.Row(
                        spacing=8,
                        controls=[
                            self.bob_input,
                            ft.IconButton(
                                icon=get_icon("ARROW_UPWARD"),
                                bgcolor=ACCENT_INDIGO,
                                icon_color=COLORS.WHITE,
                                icon_size=18,
                                tooltip="Envoyer",
                                on_click=lambda _: self._handle_send("Bob", "Alice", delayed=False),
                            ),
                        ],
                    ),
                ],
            ),
        )

        right_pane = ft.Container(
            expand=4,
            bgcolor=BG_CARD,
            padding=14,
            border_radius=16,
            border=BORDER.all(1, BORDER_HAIRLINE),
            shadow=self._card_shadow(),
            content=ft.Column(
                spacing=10,
                controls=[
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Text(
                                "Messages",
                                size=14,
                                weight=ft.FontWeight.W_600,
                                color=TEXT_PRIMARY,
                            ),
                            ft.Row(
                                spacing=4,
                                controls=[
                                    ft.Icon(get_icon("LOCK"), color=TEXT_TERTIARY, size=13),
                                    ft.Text("Chiffré de bout en bout", size=11, color=TEXT_TERTIARY),
                                ],
                            ),
                        ],
                    ),
                    ft.Container(
                        expand=True,
                        bgcolor=BG_WINDOW,
                        border_radius=12,
                        border=BORDER.all(1, BORDER_HAIRLINE),
                        content=self.chat_list,
                    ),
                    alice_controls,
                    bob_controls,
                ],
            ),
        )

        self.page.add(
            ft.Column(
                expand=True,
                spacing=12,
                controls=[
                    top_bar,
                    ft.Row(
                        expand=True,
                        spacing=14,
                        vertical_alignment=ft.CrossAxisAlignment.STRETCH,
                        controls=[left_pane, right_pane],
                    ),
                ],
            )
        )
        self._update_mode_buttons_style()

    def _legend_dot(self, color: str, label: str) -> ft.Control:
        return ft.Row(
            spacing=4,
            controls=[
                ft.Container(width=8, height=8, bgcolor=color, border_radius=4),
                ft.Text(label, size=11, color=TEXT_SECONDARY),
            ],
        )

    # ------------------------------------------------------------------
    # Cartes minimalistes et connecteurs du schéma visuel
    # ------------------------------------------------------------------
    def _build_node_card(self, rid: int, expand: bool = True) -> ft.Control:
        st = self.row_states[rid]
        status = st["status"]
        is_active = rid == self.active_row_id
        is_selected = rid == self.selected_row_id

        if is_active and status == "done":
            bg_color = ACCENT_ORANGE_SOFT
            border_color = ACCENT_ORANGE
            border_width = 1.8
            icon_color = ACCENT_ORANGE
            dot_color = ACCENT_ORANGE
            title_color = TEXT_PRIMARY
            val_color = TEXT_PRIMARY
        elif status == "done":
            bg_color = BG_CARD
            border_color = ACCENT_BLUE if is_selected else ACCENT_GREEN
            border_width = 1.6 if is_selected else 1.2
            icon_color = ACCENT_GREEN
            dot_color = ACCENT_GREEN
            title_color = TEXT_PRIMARY
            val_color = TEXT_PRIMARY
        elif status == "skipped":
            bg_color = BG_SUBTLE
            border_color = ACCENT_BLUE if is_selected else BORDER_HAIRLINE
            border_width = 1.4 if is_selected else 1.0
            icon_color = TEXT_TERTIARY
            dot_color = BORDER_STRONG
            title_color = TEXT_TERTIARY
            val_color = TEXT_TERTIARY
        else:  # pending
            bg_color = BG_CARD
            border_color = ACCENT_BLUE if is_selected else BORDER_HAIRLINE
            border_width = 1.4 if is_selected else 1.0
            icon_color = TEXT_TERTIARY
            dot_color = BORDER_HAIRLINE
            title_color = TEXT_SECONDARY
            val_color = TEXT_TERTIARY

        return ft.Container(
            expand=expand,
            bgcolor=bg_color,
            border=BORDER.all(border_width, border_color),
            border_radius=10,
            padding=PADDING.symmetric(horizontal=9, vertical=7),
            on_click=lambda _, r=rid: self._select_row(r),
            content=ft.Column(
                spacing=3,
                controls=[
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        controls=[
                            ft.Row(
                                spacing=5,
                                controls=[
                                    ft.Icon(get_icon(st["icon"]), color=icon_color, size=14),
                                    ft.Text(
                                        st["short_title"],
                                        size=11.5,
                                        weight=ft.FontWeight.W_600,
                                        color=title_color,
                                    ),
                                ],
                            ),
                            ft.Container(width=7, height=7, border_radius=3.5, bgcolor=dot_color),
                        ],
                    ),
                    ft.Text(
                        st["live_value"],
                        size=10,
                        font_family="monospace",
                        color=val_color,
                        max_lines=1,
                        overflow=ft.TextOverflow.ELLIPSIS,
                    ),
                ],
            ),
        )

    def _arrow_right(self, active: bool = False) -> ft.Control:
        return ft.Icon(
            get_icon("CHEVRON_RIGHT", "ARROW_FORWARD"),
            color=ACCENT_GREEN if active else BORDER_STRONG,
            size=16,
        )

    def _arrow_down(self, active: bool = False, label: str = "") -> ft.Control:
        controls = [
            ft.Icon(
                get_icon("SOUTH", "ARROW_DOWNWARD"),
                color=ACCENT_GREEN if active else BORDER_STRONG,
                size=14,
            )
        ]
        if label:
            controls.append(
                ft.Text(
                    label,
                    size=10.5,
                    color=TEXT_PRIMARY if active else TEXT_TERTIARY,
                )
            )
        return ft.Row(
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=4,
            controls=controls,
        )

    def _rebuild_visual_schema(self):
        s = self.row_states
        sender_accent = ACCENT_BLUE if self.current_sender == "Alice" else ACCENT_INDIGO
        recv_accent = ACCENT_INDIGO if self.current_receiver == "Bob" else ACCENT_BLUE

        # 1. Initialisation
        init_row = ft.Row(controls=[self._build_node_card(0, expand=True)])

        # 2. Zone Expéditeur
        sender_zone = ft.Container(
            bgcolor=BG_SUBTLE,
            border=BORDER.all(1, BORDER_HAIRLINE),
            border_radius=12,
            padding=9,
            content=ft.Column(
                spacing=6,
                controls=[
                    ft.Row(
                        spacing=6,
                        controls=[
                            ft.Container(width=6, height=6, border_radius=3, bgcolor=sender_accent),
                            ft.Text(
                                f"Expéditeur · {self.current_sender}",
                                size=11,
                                weight=ft.FontWeight.W_600,
                                color=TEXT_SECONDARY,
                            ),
                        ],
                    ),
                    ft.Row(
                        spacing=4,
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        controls=[
                            self._build_node_card(1, expand=True),
                            self._arrow_right(s[1]["status"] == "done"),
                            self._build_node_card(2, expand=True),
                            self._arrow_right(s[2]["status"] == "done"),
                            self._build_node_card(3, expand=True),
                        ],
                    ),
                ],
            ),
        )

        # 3. Passerelle réseau sobre
        net_bg = ACCENT_ORANGE_SOFT if self.network_is_active else BG_CARD
        net_border = ACCENT_ORANGE if self.network_is_active else BORDER_HAIRLINE
        net_fg = TEXT_PRIMARY if self.network_is_active else TEXT_SECONDARY

        network_bridge = ft.Container(
            bgcolor=net_bg,
            border=BORDER.all(1, net_border),
            border_radius=20,
            padding=PADDING.symmetric(horizontal=14, vertical=5),
            content=ft.Row(
                alignment=ft.MainAxisAlignment.CENTER,
                spacing=6,
                controls=[
                    ft.Icon(
                        get_icon("SWAP_VERT", "SYNC_ALT"),
                        color=ACCENT_ORANGE if self.network_is_active else TEXT_TERTIARY,
                        size=15,
                    ),
                    ft.Text(self.network_status_text, size=11, weight=ft.FontWeight.W_500, color=net_fg),
                ],
            ),
        )

        # 4. Zone Destinataire
        receiver_zone = ft.Container(
            bgcolor=BG_SUBTLE,
            border=BORDER.all(1, BORDER_HAIRLINE),
            border_radius=12,
            padding=9,
            content=ft.Column(
                spacing=6,
                controls=[
                    ft.Row(
                        spacing=6,
                        controls=[
                            ft.Container(width=6, height=6, border_radius=3, bgcolor=recv_accent),
                            ft.Text(
                                f"Destinataire · {self.current_receiver}",
                                size=11,
                                weight=ft.FontWeight.W_600,
                                color=TEXT_SECONDARY,
                            ),
                        ],
                    ),
                    ft.Row(
                        spacing=4,
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        controls=[
                            self._build_node_card(4, expand=True),
                            self._arrow_right(s[4]["status"] == "done"),
                            self._build_node_card(5, expand=True),
                        ],
                    ),
                    self._arrow_down(
                        s[6]["status"] == "done",
                        label="Rotation Diffie-Hellman (si nouvelle clé DH)",
                    ),
                    ft.Row(
                        spacing=4,
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        controls=[
                            self._build_node_card(6, expand=True),
                            self._arrow_right(s[6]["status"] == "done"),
                            self._build_node_card(7, expand=True),
                        ],
                    ),
                    self._arrow_down(
                        s[8]["status"] == "done",
                        label="Dérivation clé MK & déchiffrement",
                    ),
                    ft.Row(
                        spacing=4,
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        controls=[
                            self._build_node_card(8, expand=True),
                            self._arrow_right(s[8]["status"] == "done"),
                            self._build_node_card(9, expand=True),
                        ],
                    ),
                ],
            ),
        )

        self.schema_container.controls = [
            init_row,
            self._arrow_down(s[1]["status"] == "done"),
            sender_zone,
            network_bridge,
            receiver_zone,
        ]

    # ------------------------------------------------------------------
    # Contrôle segmenté & notifications
    # ------------------------------------------------------------------
    def _set_mode(self, mode: str):
        self.execution_mode = mode
        self._update_mode_buttons_style()
        if mode == "instant" and self.pending_updates:
            self._on_finish_all_click(None)
        else:
            self._refresh_all_ui()

    def _update_mode_buttons_style(self):
        if self.execution_mode == "instant":
            self.seg_instant.bgcolor = BG_CARD
            self.seg_instant.shadow = self._card_shadow()
            self.seg_instant.content.color = TEXT_PRIMARY
            self.seg_step.bgcolor = None
            self.seg_step.shadow = None
            self.seg_step.content.color = TEXT_SECONDARY
        else:
            self.seg_step.bgcolor = BG_CARD
            self.seg_step.shadow = self._card_shadow()
            self.seg_step.content.color = TEXT_PRIMARY
            self.seg_instant.bgcolor = None
            self.seg_instant.shadow = None
            self.seg_instant.content.color = TEXT_SECONDARY

    def _notify(self, text: str):
        snack = ft.SnackBar(ft.Text(text), duration=2200)
        if hasattr(self.page, "open"):
            self.page.open(snack)
        else:
            self.page.snack_bar = snack
            snack.open = True
            self.page.update()

    # ------------------------------------------------------------------
    # Bulles de chat style iMessage
    # ------------------------------------------------------------------
    def _make_system_banner(self, text: str) -> ft.Control:
        return ft.Container(
            alignment=CENTER_ALIGN,
            padding=PADDING.symmetric(vertical=4),
            content=ft.Text(text, size=11, color=TEXT_TERTIARY, text_align=ft.TextAlign.CENTER),
        )

    def _add_chat_bubble(self, sender_name: str, receiver_name: str, text: str, status_label: str, is_transit: bool = False):
        is_alice = sender_name == "Alice"
        if is_transit:
            bubble_bg = ACCENT_ORANGE_SOFT
            text_color = TEXT_PRIMARY
            sub_color = ACCENT_ORANGE
        elif is_alice:
            bubble_bg = ACCENT_BLUE
            text_color = COLORS.WHITE
            sub_color = "#D6EAFF"
        else:
            bubble_bg = "#E9E9EB"
            text_color = TEXT_PRIMARY
            sub_color = TEXT_SECONDARY

        align = ft.MainAxisAlignment.END if is_alice else ft.MainAxisAlignment.START

        bubble = ft.Container(
            width=300,
            bgcolor=bubble_bg,
            border_radius=18,
            padding=PADDING.symmetric(horizontal=14, vertical=9),
            content=ft.Column(
                spacing=3,
                controls=[
                    ft.Text(text, size=13.5, color=text_color),
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Text(f"{sender_name} → {receiver_name}", size=10, color=sub_color),
                            ft.Text(status_label, size=10, color=sub_color),
                        ],
                    ),
                ],
            ),
        )
        row = ft.Row(alignment=align, controls=[bubble])
        self.chat_list.controls.append(row)
        return bubble

    # ------------------------------------------------------------------
    # Logique cryptographique Double Ratchet
    # ------------------------------------------------------------------
    def _handle_send(self, sender_name: str, receiver_name: str, delayed: bool = False):
        if self.pending_updates:
            self._notify("Terminez d'abord le message en cours.")
            return

        input_field = self.alice_input if sender_name == "Alice" else self.bob_input
        text = (input_field.value or "").strip()
        if not text:
            text = f"Bonjour {receiver_name} (#{(self.alice.Ns if sender_name == 'Alice' else self.bob.Ns) + 1})"
        input_field.value = ""

        sender = self.alice if sender_name == "Alice" else self.bob
        receiver = self.bob if sender_name == "Alice" else self.alice

        if sender.CKs is None:
            self._notify(f"{sender_name} doit d'abord recevoir un message.")
            return

        self._prepare_nodes_for_new_message(sender_name, receiver_name)

        plaintext_bytes = text.encode("utf-8")
        updates: list[StepUpdate] = []

        if self.execution_mode == "step" and not delayed:
            bubble_ref = self._add_chat_bubble(
                sender_name,
                receiver_name,
                text,
                "En cours…",
                is_transit=True,
            )
            self.network_status_text = f"Préparation du paquet par {sender_name}…"
            self.network_is_active = True
        elif delayed:
            bubble_ref = self._add_chat_bubble(
                sender_name,
                receiver_name,
                text,
                "Retardé sur le réseau",
                is_transit=True,
            )
            self.network_status_text = f"Paquet de {sender_name} retenu (hors-ordre)"
            self.network_is_active = True
        else:
            bubble_ref = self._add_chat_bubble(
                sender_name,
                receiver_name,
                text,
                "Déchiffré",
                is_transit=False,
            )
            self.network_status_text = f"Livré · {sender_name} → {receiver_name}"
            self.network_is_active = False

        # ÉTAPE 1 : kdf_ck(CKs)
        ck_before = sender.CKs
        ns_before = sender.Ns
        pn_before = sender.PN
        dhs_pub = sender.DHs[1]

        ck_after, mk = kdf_ck(ck_before)
        sender.CKs = ck_after

        updates.append(
            StepUpdate(
                row_id=1,
                status="done",
                actor=sender_name,
                live_value=f"N={ns_before} · MK {short_hex(mk)}",
                vulgarisation=(
                    f"{sender_name} dérive la clé unique MK pour le message N={ns_before} et fait avancer sa "
                    f"chaîne d'envoi CKs via HMAC-SHA256."
                ),
                inputs_detail=f"CKs : {full_hex(ck_before)}\nNs  : {ns_before}",
                outputs_detail=f"CKs' : {full_hex(ck_after)}\nMK   : {full_hex(mk)}",
            )
        )

        # ÉTAPE 2 : encode_header
        header_bytes = encode_header(dhs_pub, pn_before, ns_before)
        updates.append(
            StepUpdate(
                row_id=2,
                status="done",
                actor=sender_name,
                live_value=f"DH {short_hex(dhs_pub)} · PN={pn_before}, N={ns_before}",
                vulgarisation=(
                    f"{sender_name} assemble l'en-tête de 40 octets : sa clé publique DH actuelle, "
                    f"PN={pn_before} et N={ns_before}."
                ),
                inputs_detail=f"DHs_pub : {full_hex(dhs_pub)}\nPN={pn_before}, N={ns_before}",
                outputs_detail=f"Header (40 o) : {full_hex(header_bytes)}",
            )
        )

        # ÉTAPE 3 : encrypt_symmetric
        ciphertext = encrypt_symmetric(mk, plaintext_bytes, AD + header_bytes)
        sender.Ns += 1

        def on_sent_done(s_name=sender_name, r_name=receiver_name, is_del=delayed, size=len(ciphertext)):
            if is_del:
                self.network_status_text = f"Paquet ({size} o) en attente réseau · {s_name} → {r_name}"
                self.network_is_active = True
            else:
                self.network_status_text = f"Paquet chiffré ({size} o) en transit · {s_name} → {r_name}"
                self.network_is_active = True

        updates.append(
            StepUpdate(
                row_id=3,
                status="done",
                actor=sender_name,
                live_value=f"{len(ciphertext)} o · HMAC {short_hex(ciphertext[-32:])}",
                vulgarisation=(
                    f"{sender_name} chiffre le message \"{text}\" avec MK et ajoute une signature HMAC-SHA256."
                ),
                inputs_detail=f'Clair : "{text}"\nMK    : {full_hex(mk)}',
                outputs_detail=(
                    f"Nonce : {full_hex(ciphertext[:12])}\n"
                    f"Data  : {full_hex(ciphertext[12:-32])}\n"
                    f"HMAC  : {full_hex(ciphertext[-32:])}"
                ),
                on_reveal=on_sent_done,
            )
        )

        if delayed:
            self.delayed_packets.append(
                {
                    "sender_name": sender_name,
                    "receiver_name": receiver_name,
                    "receiver": receiver,
                    "header": header_bytes,
                    "ciphertext": ciphertext,
                    "text": text,
                    "bubble": bubble_ref,
                }
            )
            for rid in range(4, 10):
                updates.append(
                    StepUpdate(
                        row_id=rid,
                        status="skipped",
                        actor=receiver_name,
                        live_value="En attente réseau",
                        vulgarisation="Le paquet n'est pas encore arrivé chez le destinataire.",
                        inputs_detail="En attente sur le réseau.",
                        outputs_detail="En attente sur le réseau.",
                    )
                )
        else:
            self._append_receive_updates(
                sender_name=sender_name,
                receiver_name=receiver_name,
                receiver=receiver,
                header_bytes=header_bytes,
                ciphertext=ciphertext,
                bubble_ref=bubble_ref,
                updates=updates,
            )

        if self.execution_mode == "instant":
            for up in updates:
                self._apply_one_update(up)
            self.active_row_id = None
            self.selected_row_id = 9 if not delayed else 3
            if not delayed:
                self.network_status_text = f"Livré & déchiffré · {sender_name} → {receiver_name}"
                self.network_is_active = False
        else:
            self.pending_updates.extend(updates)
            self._reveal_next_update()

        self._refresh_all_ui()

    def _append_receive_updates(
        self,
        sender_name: str,
        receiver_name: str,
        receiver: RatchetState,
        header_bytes: bytes,
        ciphertext: bytes,
        bubble_ref: ft.Container,
        updates: list[StepUpdate],
    ):
        # ÉTAPE 4 : decode_header
        dh_pub, pn, n = decode_header(header_bytes)
        dh_changed = dh_pub != receiver.DHr

        updates.append(
            StepUpdate(
                row_id=4,
                status="done",
                actor=receiver_name,
                live_value=f"N={n} · {'Nouvelle DH' if dh_changed else 'Même DH'}",
                vulgarisation=(
                    f"{receiver_name} lit l'en-tête. "
                    + (
                        f"La clé publique DH de {sender_name} a changé : Ratchet DH requis."
                        if dh_changed
                        else "La clé publique DH est inchangée : pas de rotation asymétrique."
                    )
                ),
                inputs_detail=f"Header : {full_hex(header_bytes)}",
                outputs_detail=f"DH_pub : {full_hex(dh_pub)}\nPN={pn}, N={n} · Changement DH = {dh_changed}",
            )
        )

        # Cas spécial : message retardé retrouvé dans MKSKIPPED
        if (dh_pub, n) in receiver.MKSKIPPED:
            mk_saved = receiver.MKSKIPPED.pop((dh_pub, n))
            plaintext_out = decrypt_symmetric(mk_saved, ciphertext, AD + header_bytes).decode("utf-8")

            updates.append(
                StepUpdate(
                    row_id=5,
                    status="done",
                    actor=receiver_name,
                    live_value=f"MK extraite (N={n})",
                    vulgarisation=(
                        f"{receiver_name} retrouve la clé MK pré-calculée pour ce message retardataire dans MKSKIPPED."
                    ),
                    inputs_detail=f"Clé : (DH={short_hex(dh_pub)}, N={n})",
                    outputs_detail=f"MK : {full_hex(mk_saved)}\nRestant dans coffre : {len(receiver.MKSKIPPED)}",
                )
            )
            for rid in (6, 7, 8):
                updates.append(
                    StepUpdate(
                        row_id=rid,
                        status="skipped",
                        actor=receiver_name,
                        live_value="Clé déjà archivée",
                        vulgarisation="Inutile de recalculer les chaînes : la clé MK était déjà dans MKSKIPPED.",
                        inputs_detail="—",
                        outputs_detail="—",
                    )
                )

            def reveal_delayed(b=bubble_ref, pt=plaintext_out, is_alice=(sender_name == "Alice"), s_name=sender_name, r_name=receiver_name):
                b.bgcolor = ACCENT_BLUE if is_alice else "#E9E9EB"
                b.content.controls[0].color = COLORS.WHITE if is_alice else TEXT_PRIMARY
                sub_c = "#D6EAFF" if is_alice else TEXT_SECONDARY
                b.content.controls[1].controls[0].color = sub_c
                b.content.controls[1].controls[1].color = sub_c
                b.content.controls[1].controls[1].value = "Déchiffré (MKSKIPPED)"
                b.content.controls[0].value = pt
                self.network_status_text = f"Livré (hors-ordre) · {s_name} → {r_name}"
                self.network_is_active = False

            updates.append(
                StepUpdate(
                    row_id=9,
                    status="done",
                    actor=receiver_name,
                    live_value=f'"{plaintext_out}"',
                    vulgarisation=f"Signature HMAC validée et message déchiffré : \"{plaintext_out}\".",
                    inputs_detail=f"MK : {full_hex(mk_saved)}",
                    outputs_detail=f'Clair : "{plaintext_out}"',
                    on_reveal=reveal_delayed,
                )
            )
            return

        # ÉTAPE 5 : skip_message_keys
        skipped_something = False
        skip_summary_parts = []
        skip_in_parts = []
        skip_out_parts = []

        if dh_changed and receiver.Nr < pn:
            nr_start = receiver.Nr
            receiver.skip_message_keys(pn)
            skipped_something = True
            skip_summary_parts.append(f"N={nr_start}..{pn - 1}")
            skip_in_parts.append(f"Ancienne chaîne : Nr={nr_start} < PN={pn}")
            skip_out_parts.append(f"Archivé N={nr_start}..{pn - 1} (coffre={len(receiver.MKSKIPPED)})")

        # ÉTAPES 6 & 7 : Ratchet DH
        if dh_changed:
            rk_before = receiver.RK
            old_dhs_priv, old_dhs_pub = receiver.DHs

            receiver.PN = receiver.Ns
            receiver.Ns = 0
            receiver.Nr = 0
            receiver.DHr = dh_pub

            dh_out_1 = x25519(old_dhs_priv, receiver.DHr)
            rk_mid, ckr_new = kdf_rk(rk_before, dh_out_1)
            receiver.RK = rk_mid
            receiver.CKr = ckr_new

            updates.append(
                StepUpdate(
                    row_id=6,
                    status="done",
                    actor=receiver_name,
                    live_value=f"CKr {short_hex(ckr_new)}",
                    vulgarisation=(
                        f"{receiver_name} calcule X25519 entre sa clé privée actuelle et la nouvelle clé publique de "
                        f"{sender_name}, puis dérive la chaîne de réception CKr."
                    ),
                    inputs_detail=f"RK     : {full_hex(rk_before)}\nDH_pub : {full_hex(dh_pub)}",
                    outputs_detail=f"X25519 : {full_hex(dh_out_1)}\nRK'    : {full_hex(rk_mid)}\nCKr    : {full_hex(ckr_new)}",
                )
            )

            receiver.DHs = generate_keypair()
            dh_out_2 = x25519(receiver.DHs[0], receiver.DHr)
            rk_after, cks_new = kdf_rk(rk_mid, dh_out_2)
            receiver.RK = rk_after
            receiver.CKs = cks_new

            updates.append(
                StepUpdate(
                    row_id=7,
                    status="done",
                    actor=receiver_name,
                    live_value=f"DHs' {short_hex(receiver.DHs[1])}",
                    vulgarisation=(
                        f"{receiver_name} génère une nouvelle paire X25519 locale et re-mélange RK pour préparer "
                        f"sa future chaîne d'envoi CKs."
                    ),
                    inputs_detail=f"RK'         : {full_hex(rk_mid)}\nAncienne DH : {full_hex(old_dhs_pub)}",
                    outputs_detail=f"Nouvelle DH : {full_hex(receiver.DHs[1])}\nRK''        : {full_hex(rk_after)}\nCKs         : {full_hex(cks_new)}",
                )
            )
        else:
            updates.append(
                StepUpdate(
                    row_id=6,
                    status="skipped",
                    actor=receiver_name,
                    live_value="Non requis",
                    vulgarisation="Clé DH identique : conservation de la chaîne CKr actuelle.",
                    inputs_detail="DH_pub == DHr",
                    outputs_detail=f"CKr : {full_hex(receiver.CKr)}",
                )
            )
            updates.append(
                StepUpdate(
                    row_id=7,
                    status="skipped",
                    actor=receiver_name,
                    live_value="Non requis",
                    vulgarisation="Pas de changement de tour de parole.",
                    inputs_detail="DH_pub == DHr",
                    outputs_detail=f"RK : {full_hex(receiver.RK)}",
                )
            )

        if receiver.Nr < n:
            nr_before_skip = receiver.Nr
            receiver.skip_message_keys(n)
            skipped_something = True
            skip_summary_parts.append(f"N={nr_before_skip}..{n - 1}")
            skip_in_parts.append(f"Chaîne courante : Nr={nr_before_skip} < N={n}")
            skip_out_parts.append(f"Archivé N={nr_before_skip}..{n - 1} (coffre={len(receiver.MKSKIPPED)})")

        step5_update = StepUpdate(
            row_id=5,
            status="done" if skipped_something else "skipped",
            actor=receiver_name,
            live_value=(
                f"Archivé {', '.join(skip_summary_parts)}"
                if skipped_something
                else f"Aucun saut (N={n})"
            ),
            vulgarisation=(
                "Des messages manquent à l'appel : leurs clés sont sauvegardées dans MKSKIPPED."
                if skipped_something
                else "Le numéro de message correspond au compteur attendu."
            ),
            inputs_detail="\n".join(skip_in_parts) if skipped_something else f"Nr attendu = {n}",
            outputs_detail="\n".join(skip_out_parts) if skipped_something else f"Coffre MKSKIPPED = {len(receiver.MKSKIPPED)}",
        )
        updates.insert(4, step5_update)

        # ÉTAPE 8 : kdf_ck(CKr)
        ckr_before = receiver.CKr
        nr_curr = receiver.Nr
        ckr_after, mk_recv = kdf_ck(ckr_before)
        receiver.CKr = ckr_after
        receiver.Nr += 1

        updates.append(
            StepUpdate(
                row_id=8,
                status="done",
                actor=receiver_name,
                live_value=f"N={nr_curr} · MK {short_hex(mk_recv)}",
                vulgarisation=(
                    f"{receiver_name} fait avancer sa chaîne de réception CKr et retrouve la clé MK "
                    f"identique à celle utilisée par {sender_name}."
                ),
                inputs_detail=f"CKr : {full_hex(ckr_before)}\nNr  : {nr_curr}",
                outputs_detail=f"CKr' : {full_hex(ckr_after)}\nMK   : {full_hex(mk_recv)}",
            )
        )

        # ÉTAPE 9 : decrypt_symmetric
        plaintext_out = decrypt_symmetric(mk_recv, ciphertext, AD + header_bytes).decode("utf-8")

        def reveal_decrypted(b=bubble_ref, pt=plaintext_out, is_alice=(sender_name == "Alice"), s_name=sender_name, r_name=receiver_name):
            b.bgcolor = ACCENT_BLUE if is_alice else "#E9E9EB"
            b.content.controls[0].color = COLORS.WHITE if is_alice else TEXT_PRIMARY
            sub_c = "#D6EAFF" if is_alice else TEXT_SECONDARY
            b.content.controls[1].controls[0].color = sub_c
            b.content.controls[1].controls[1].color = sub_c
            b.content.controls[1].controls[1].value = "Déchiffré"
            b.content.controls[0].value = pt
            self.network_status_text = f"Livré & déchiffré · {s_name} → {r_name}"
            self.network_is_active = False

        updates.append(
            StepUpdate(
                row_id=9,
                status="done",
                actor=receiver_name,
                live_value=f'"{plaintext_out}"',
                vulgarisation=(
                    f"{receiver_name} valide le tag HMAC-SHA256 et déchiffre le message : \"{plaintext_out}\"."
                ),
                inputs_detail=f"Paquet ({len(ciphertext)} o) : {short_hex(ciphertext, 10, 10)}\nMK : {full_hex(mk_recv)}",
                outputs_detail=f'HMAC  : Valide\nClair : "{plaintext_out}"',
                on_reveal=reveal_decrypted,
            )
        )

    # ------------------------------------------------------------------
    # Exécution incrémentale
    # ------------------------------------------------------------------
    def _apply_one_update(self, up: StepUpdate):
        if up.on_reveal:
            up.on_reveal()
        row = self.row_states[up.row_id]
        row["status"] = up.status
        row["actor"] = up.actor
        row["live_value"] = up.live_value
        row["vulgarisation"] = up.vulgarisation
        row["inputs_detail"] = up.inputs_detail
        row["outputs_detail"] = up.outputs_detail

    def _reveal_next_update(self):
        if not self.pending_updates:
            return
        up = self.pending_updates.pop(0)
        self._apply_one_update(up)
        self.active_row_id = up.row_id
        self.selected_row_id = up.row_id

    def _on_next_step_click(self, _):
        if not self.pending_updates:
            return
        self._reveal_next_update()
        if not self.pending_updates:
            self.active_row_id = None
        self._refresh_all_ui()

    def _on_finish_all_click(self, _):
        while self.pending_updates:
            self._reveal_next_update()
        self.active_row_id = None
        self._refresh_all_ui()

    def _on_deliver_delayed_click(self, _):
        if self.pending_updates:
            self._notify("Terminez d'abord le message en cours.")
            return
        if not self.delayed_packets:
            return

        pkt = self.delayed_packets.pop(0)
        self._prepare_nodes_for_new_message(pkt["sender_name"], pkt["receiver_name"])
        self.network_status_text = f"Livraison retardée · {pkt['sender_name']} → {pkt['receiver_name']}"
        self.network_is_active = True

        updates: list[StepUpdate] = []
        for rid in (1, 2, 3):
            updates.append(
                StepUpdate(
                    row_id=rid,
                    status="skipped",
                    actor=pkt["sender_name"],
                    live_value="Déjà émis",
                    vulgarisation="Les étapes d'envoi ont déjà été exécutées lors de l'émission du paquet.",
                    inputs_detail="Déjà exécuté.",
                    outputs_detail="Déjà exécuté.",
                )
            )

        self._append_receive_updates(
            sender_name=pkt["sender_name"],
            receiver_name=pkt["receiver_name"],
            receiver=pkt["receiver"],
            header_bytes=pkt["header"],
            ciphertext=pkt["ciphertext"],
            bubble_ref=pkt["bubble"],
            updates=updates,
        )

        if self.execution_mode == "instant":
            for up in updates:
                self._apply_one_update(up)
            self.active_row_id = None
            self.selected_row_id = 9
        else:
            for _ in range(3):
                self._apply_one_update(updates.pop(0))
            self.pending_updates.extend(updates)
            self._reveal_next_update()

        self._refresh_all_ui()

    # ------------------------------------------------------------------
    # Rafraîchissement global de l'interface
    # ------------------------------------------------------------------
    def _select_row(self, row_id: int):
        self.selected_row_id = row_id
        self._refresh_detail_panel()
        self._rebuild_visual_schema()
        self.page.update()

    def _refresh_detail_panel(self):
        st = self.row_states.get(self.selected_row_id)
        if not st:
            return
        self.detail_title.value = f"{st['title']} · {st['actor']}"
        self.detail_func.value = st["func"]
        self.detail_vulgarisation.value = st["vulgarisation"]
        self.detail_inputs.value = st["inputs_detail"]
        self.detail_outputs.value = st["outputs_detail"]

    def _refresh_all_ui(self):
        pending_count = len(self.pending_updates)
        self.next_step_btn.disabled = pending_count == 0
        set_btn_label(
            self.next_step_btn,
            f"Étape suivante ({pending_count})" if pending_count > 0 else "Étape suivante",
        )
        self.finish_all_btn.disabled = pending_count == 0

        delayed_count = len(self.delayed_packets)
        self.deliver_delayed_btn.disabled = delayed_count == 0 or pending_count > 0
        set_btn_label(self.deliver_delayed_btn, f"Livrer retardé ({delayed_count})")

        if pending_count > 0:
            self.status_dot.bgcolor = ACCENT_ORANGE
            self.status_label.value = f"{pending_count} étape(s) restante(s)"
        else:
            self.status_dot.bgcolor = ACCENT_GREEN
            self.status_label.value = "Synchronisé"

        self.alice_state_text.value = (
            f"RK {short_hex(self.alice.RK)} · Ns={self.alice.Ns} Nr={self.alice.Nr} PN={self.alice.PN}\n"
            f"CKs {short_hex(self.alice.CKs)} · CKr {short_hex(self.alice.CKr)} · Skip={len(self.alice.MKSKIPPED)}"
        )
        self.bob_state_text.value = (
            f"RK {short_hex(self.bob.RK)} · Ns={self.bob.Ns} Nr={self.bob.Nr} PN={self.bob.PN}\n"
            f"CKs {short_hex(self.bob.CKs)} · CKr {short_hex(self.bob.CKr)} · Skip={len(self.bob.MKSKIPPED)}"
        )

        self._rebuild_visual_schema()
        self._refresh_detail_panel()
        self.page.update()


def main(page: ft.Page):
    DoubleRatchetApp(page)


if __name__ == "__main__":
    if hasattr(ft, "run"):
        ft.run(main)
    else:
        ft.app(target=main)
