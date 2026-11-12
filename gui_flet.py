#!/usr/bin/env python3
"""
Interface Graphique Pédagogique (Flet) pour l'algorithme Double Ratchet.
- Gauche : Tableau FIXE pré-rempli avec toutes les étapes de l'algorithme qui se met à jour en direct.
- Droite : Chat classique entre Alice et Bob.
- Haut   : Contrôles (Mode Tout d'un coup vs Pas à pas, Étape suivante +1, Tout exécuter, Msg retardé, Réinitialiser).
"""

import inspect
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

_DATAROW_PARAMS = inspect.signature(ft.DataRow.__init__).parameters
DATAROW_SELECT_EVENT = "on_select_change" if "on_select_change" in _DATAROW_PARAMS else "on_select_changed"

AD = b"DoubleRatchetGUI-Oral-v1"


def set_btn_label(btn, label: str):
    if hasattr(btn, "text"):
        btn.text = label
    else:
        btn.content = label


def short_hex(data: bytes | None, head: int = 6, tail: int = 4) -> str:
    if data is None:
        return "None"
    if len(data) <= head + tail:
        return data.hex()
    return f"{data[:head].hex()}…{data[-tail:].hex()}"


def full_hex(data: bytes | None) -> str:
    if data is None:
        return "None (non initialisé)"
    return data.hex()


# Définition des 10 lignes fixes du tableau de l'algorithme Double Ratchet
STEP_DEFINITIONS = [
    {
        "id": 0,
        "title": "0. Initialisation session",
        "func": "init_alice() / init_bob()",
        "default_actor": "Alice & Bob",
        "default_desc": "Secret initial RK partagé + 1ère paire DH d'Alice",
        "default_vulga": (
            "Avant tout échange, Alice et Bob partagent une Clé Racine initiale (RK) et Bob a publié "
            "sa clé publique X25519. Alice génère sa propre paire DH et calcule sa première chaîne d'envoi CKs."
        ),
    },
    {
        "id": 1,
        "title": "1. Ratchet Symétrique (Envoi)",
        "func": "kdf_ck(CKs) → (CKs', MK)",
        "default_actor": "Expéditeur",
        "default_desc": "Fait avancer CKs et dérive une clé unique MK",
        "default_vulga": (
            "L'expéditeur passe sa Clé de Chaîne d'envoi (CKs) dans HMAC-SHA256 pour produire deux clés : "
            "la prochaine CKs et une Clé de Message (MK) à usage unique (Forward Secrecy)."
        ),
    },
    {
        "id": 2,
        "title": "2. Construction de l'en-tête",
        "func": "encode_header(DHs, PN, Ns)",
        "default_actor": "Expéditeur",
        "default_desc": "Empaquète clé publique DH + compteurs PN et N (40B)",
        "default_vulga": (
            "L'expéditeur construit l'en-tête de 40 octets contenant sa clé publique Diffie-Hellman actuelle, "
            "la longueur de la chaîne précédente (PN) et le numéro du message courant (N)."
        ),
    },
    {
        "id": 3,
        "title": "3. Chiffrement & Tag HMAC",
        "func": "encrypt_symmetric(MK, msg, AD)",
        "default_actor": "Expéditeur",
        "default_desc": "Chiffre le message (XOR) + authentifie (HMAC-SHA256)",
        "default_vulga": (
            "Avec la clé unique MK, le texte est chiffré par flux avec un Nonce aléatoire (12B), puis signé "
            "par un tag HMAC-SHA256 couvrant aussi l'en-tête pour empêcher toute falsification."
        ),
    },
    {
        "id": 4,
        "title": "4. Réception & Lecture en-tête",
        "func": "decode_header(header)",
        "default_actor": "Destinataire",
        "default_desc": "Extrait DH_pub, PN, N et teste si DH a changé",
        "default_vulga": (
            "Le destinataire lit l'en-tête reçu et compare la clé publique DH de l'expéditeur avec celle "
            "qu'il connaissait : si elle est nouvelle, un Ratchet DH asymétrique est déclenché."
        ),
    },
    {
        "id": 5,
        "title": "5. Gestion Hors-Ordre / Saut",
        "func": "skip_message_keys() / MKSKIPPED",
        "default_actor": "Destinataire",
        "default_desc": "Archive ou récupère les clés des messages retardés",
        "default_vulga": (
            "Si un message arrive en avance ou en retard par rapport au compteur Nr, les clés intermédiaires "
            "sont mises de côté (ou récupérées) dans le dictionnaire MKSKIPPED."
        ),
    },
    {
        "id": 6,
        "title": "6. Ratchet DH #1 (Réception)",
        "func": "x25519() + kdf_rk(RK, dh1)",
        "default_actor": "Destinataire",
        "default_desc": "Renouvelle RK et crée la chaîne de réception CKr",
        "default_vulga": (
            "Lors d'un changement de tour de parole, le destinataire combine sa clé privée actuelle avec la "
            "nouvelle clé publique reçue (Curve25519) pour régénérer la Clé Racine RK et sa chaîne CKr."
        ),
    },
    {
        "id": 7,
        "title": "7. Ratchet DH #2 (Nouvelle clé)",
        "func": "generate_keypair() + kdf_rk()",
        "default_actor": "Destinataire",
        "default_desc": "Génère une nouvelle paire X25519 et prépare CKs",
        "default_vulga": (
            "Le destinataire génère immédiatement une nouvelle paire de clés X25519 pour sa future réponse "
            "et re-mélange RK pour créer sa nouvelle chaîne d'envoi CKs (guérison post-compromission)."
        ),
    },
    {
        "id": 8,
        "title": "8. Ratchet Symétrique (Réception)",
        "func": "kdf_ck(CKr) → (CKr', MK)",
        "default_actor": "Destinataire",
        "default_desc": "Avance CKr et retrouve exactement la même clé MK",
        "default_vulga": (
            "Le destinataire fait avancer sa chaîne de réception d'un cran via HMAC-SHA256 et obtient "
            "la clé MK identique à celle calculée par l'expéditeur à l'étape 1."
        ),
    },
    {
        "id": 9,
        "title": "9. Vérification & Déchiffrement",
        "func": "decrypt_symmetric(MK, paquet)",
        "default_actor": "Destinataire",
        "default_desc": "Vérifie la signature HMAC et affiche le texte en clair",
        "default_vulga": (
            "Le destinataire vérifie d'abord l'authenticité via HMAC-SHA256, puis déchiffre le message "
            "qui apparaît en clair dans la discussion."
        ),
    },
]


class StepUpdate:
    """Action atomique qui met à jour une ligne précise du tableau fixe."""

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
        self.page.title = "Double Ratchet — Tableau Dynamique & Chat E2EE"
        self.page.window.width = 1460
        self.page.window.height = 900
        self.page.padding = 12
        self.page.theme_mode = ft.ThemeMode.LIGHT
        self.page.bgcolor = COLORS.BLUE_GREY_50

        # États cryptographiques
        self.alice: RatchetState = RatchetState()
        self.bob: RatchetState = RatchetState()
        self.shared_key: bytes = b""
        self.bob_initial_dh: tuple[bytes, bytes] = (b"", b"")

        # État des 10 lignes fixes du tableau
        self.row_states: dict[int, dict] = {}
        self.selected_row_id: int = 0
        self.active_row_id: int | None = None

        # File d'étapes en attente pour le mode pas à pas
        self.pending_updates: list[StepUpdate] = []
        self.delayed_packets: list[dict] = []

        # Mode par défaut : pas à pas (incrémentation)
        self.execution_mode: str = "step"

        self._build_ui()
        self._reset_session(initial=True)

    # ------------------------------------------------------------------
    # Initialisation / Réinitialisation de la session et du tableau fixe
    # ------------------------------------------------------------------
    def _init_fixed_rows(self):
        self.row_states = {}
        for item in STEP_DEFINITIONS:
            rid = item["id"]
            self.row_states[rid] = {
                "id": rid,
                "title": item["title"],
                "func": item["func"],
                "status": "pending",  # "pending" | "active" | "done" | "skipped"
                "actor": item["default_actor"],
                "live_value": item["default_desc"],
                "vulgarisation": item["default_vulga"],
                "inputs_detail": "En attente de l'exécution de cette étape…",
                "outputs_detail": "En attente de l'exécution de cette étape…",
            }

    def _prepare_rows_for_new_message(self):
        """Remet les étapes 1..9 à l'état 'En attente' avant de démarrer un nouveau message."""
        for item in STEP_DEFINITIONS:
            rid = item["id"]
            if rid == 0:
                continue
            self.row_states[rid]["status"] = "pending"
            self.row_states[rid]["actor"] = item["default_actor"]
            self.row_states[rid]["live_value"] = "⏳ En attente…"
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
        self._init_fixed_rows()

        # Remplir la ligne 0 (Initialisation) immédiatement
        self.row_states[0]["status"] = "done"
        self.row_states[0]["actor"] = "Alice & Bob"
        self.row_states[0]["live_value"] = (
            f"RK={short_hex(self.alice.RK)} | Alice CKs={short_hex(self.alice.CKs)}"
        )
        self.row_states[0]["inputs_detail"] = (
            f"• Secret partagé (shared_key) : {full_hex(self.shared_key)}\n"
            f"• Clé publique DH initiale Bob : {full_hex(self.bob_initial_dh[1])}"
        )
        self.row_states[0]["outputs_detail"] = (
            f"• Alice RK  : {full_hex(self.alice.RK)}\n"
            f"• Alice CKs : {full_hex(self.alice.CKs)}\n"
            f"• Alice DHs (pub) : {full_hex(self.alice.DHs[1])}\n"
            f"• Bob RK    : {full_hex(self.bob.RK)} (prêt à recevoir)"
        )

        self.selected_row_id = 0
        self.active_row_id = 0

        self.chat_list.controls.clear()
        self.chat_list.controls.append(
            self._make_system_banner(
                f"Session E2EE initialisée (X3DH simulé)\n"
                f"Secret initial RK : {short_hex(self.shared_key)} | Clé DH Bob : {short_hex(self.bob_initial_dh[1])}"
            )
        )

        self._refresh_all_ui()
        if not initial:
            self._notify("Session et tableau réinitialisés avec de nouvelles clés.")

    # ------------------------------------------------------------------
    # Construction de l'interface Flet
    # ------------------------------------------------------------------
    def _build_ui(self):
        # --- Barre supérieure (Contrôles) ---
        self.mode_instant_btn = BUTTON(
            "⚡ Tout d'un coup",
            on_click=lambda _: self._set_mode("instant"),
        )
        self.mode_step_btn = BUTTON(
            "👣 Par incrémentation (Pas à pas)",
            on_click=lambda _: self._set_mode("step"),
        )

        self.next_step_btn = BUTTON(
            "Étape suivante (+1)",
            icon=ICONS.SKIP_NEXT if ICONS else None,
            bgcolor=COLORS.GREEN_700,
            color=COLORS.WHITE,
            on_click=self._on_next_step_click,
            disabled=True,
        )

        self.finish_all_btn = ft.OutlinedButton(
            "Finir le message",
            icon=ICONS.FAST_FORWARD if ICONS else None,
            on_click=self._on_finish_all_click,
            disabled=True,
        )

        self.deliver_delayed_btn = ft.OutlinedButton(
            "Livrer msg retardé (0)",
            icon=ICONS.MARK_EMAIL_UNREAD if ICONS else None,
            on_click=self._on_deliver_delayed_click,
            disabled=True,
        )

        self.reset_btn = ft.OutlinedButton(
            "Réinitialiser",
            icon=ICONS.REFRESH if ICONS else None,
            on_click=lambda _: self._reset_session(initial=False),
        )

        self.status_pill = ft.Container(
            content=ft.Text("Prêt", size=12, weight=ft.FontWeight.BOLD, color=COLORS.WHITE),
            bgcolor=COLORS.BLUE_GREY_700,
            padding=PADDING.symmetric(horizontal=10, vertical=6),
            border_radius=12,
        )

        top_bar = ft.Container(
            bgcolor=COLORS.WHITE,
            padding=12,
            border_radius=10,
            border=BORDER.all(1, COLORS.BLUE_GREY_200),
            content=ft.Row(
                wrap=True,
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
                    ft.Row(
                        spacing=8,
                        controls=[
                            ft.Icon(ICONS.LOCK if ICONS else None, color=COLORS.INDIGO_700, size=24),
                            ft.Text(
                                "Double Ratchet — Tableau d'États en Direct",
                                size=17,
                                weight=ft.FontWeight.BOLD,
                                color=COLORS.BLUE_GREY_900,
                            ),
                        ],
                    ),
                    ft.Row(
                        wrap=True,
                        spacing=8,
                        controls=[
                            self.mode_instant_btn,
                            self.mode_step_btn,
                            ft.VerticalDivider(width=8),
                            self.next_step_btn,
                            self.finish_all_btn,
                            ft.VerticalDivider(width=8),
                            self.deliver_delayed_btn,
                            self.reset_btn,
                            self.status_pill,
                        ],
                    ),
                ],
            ),
        )

        # --- PANNEAU GAUCHE : Tableau fixe pré-rempli + Inspecteur détaillé ---
        self.steps_table = ft.DataTable(
            column_spacing=12,
            heading_row_height=36,
            data_row_min_height=40,
            data_row_max_height=52,
            heading_row_color=COLORS.INDIGO_50,
            border=BORDER.all(1, COLORS.BLUE_GREY_200),
            border_radius=8,
            columns=[
                ft.DataColumn(ft.Text("Étape de l'algorithme", weight=ft.FontWeight.BOLD, size=12)),
                ft.DataColumn(ft.Text("État", weight=ft.FontWeight.BOLD, size=12)),
                ft.DataColumn(ft.Text("Acteur", weight=ft.FontWeight.BOLD, size=12)),
                ft.DataColumn(ft.Text("Fonction Python", weight=ft.FontWeight.BOLD, size=12)),
                ft.DataColumn(ft.Text("Valeurs / Clés mises à jour", weight=ft.FontWeight.BOLD, size=12)),
            ],
            rows=[],
        )

        self.table_scroll_container = ft.ListView(
            expand=True,
            controls=[
                ft.Row(
                    scroll=ft.ScrollMode.AUTO,
                    controls=[self.steps_table],
                )
            ],
        )

        # Inspecteur détaillé en bas à gauche
        self.detail_title = ft.Text(
            "Détail de l'étape sélectionnée",
            size=14,
            weight=ft.FontWeight.BOLD,
            color=COLORS.INDIGO_900,
        )
        self.detail_vulgarisation = ft.Text("", size=12, color=COLORS.BLUE_GREY_900)
        self.detail_inputs = ft.Text("", size=11, font_family="monospace", color=COLORS.BLUE_GREY_800, selectable=True)
        self.detail_outputs = ft.Text("", size=11, font_family="monospace", color=COLORS.TEAL_900, selectable=True)

        detail_panel = ft.Container(
            bgcolor=COLORS.INDIGO_50,
            padding=10,
            border_radius=8,
            border=BORDER.all(1, COLORS.INDIGO_200),
            height=195,
            content=ft.Column(
                scroll=ft.ScrollMode.AUTO,
                spacing=5,
                controls=[
                    self.detail_title,
                    self.detail_vulgarisation,
                    ft.Divider(height=4),
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        vertical_alignment=ft.CrossAxisAlignment.START,
                        controls=[
                            ft.Container(
                                expand=True,
                                bgcolor=COLORS.WHITE,
                                padding=8,
                                border_radius=6,
                                content=ft.Column(
                                    spacing=2,
                                    controls=[
                                        ft.Text("ENTRÉES / AVANT", size=10, weight=ft.FontWeight.BOLD, color=COLORS.BLUE_GREY_600),
                                        self.detail_inputs,
                                    ],
                                ),
                            ),
                            ft.Container(
                                expand=True,
                                bgcolor=COLORS.WHITE,
                                padding=8,
                                border_radius=6,
                                content=ft.Column(
                                    spacing=2,
                                    controls=[
                                        ft.Text("SORTIES / APRÈS", size=10, weight=ft.FontWeight.BOLD, color=COLORS.TEAL_700),
                                        self.detail_outputs,
                                    ],
                                ),
                            ),
                        ],
                    ),
                ],
            ),
        )

        # Bandeaux d'état d'Alice et Bob
        self.alice_state_text = ft.Text("", size=11, font_family="monospace")
        self.bob_state_text = ft.Text("", size=11, font_family="monospace")

        state_summary_bar = ft.Row(
            spacing=8,
            controls=[
                ft.Container(
                    expand=True,
                    bgcolor=COLORS.BLUE_50,
                    padding=8,
                    border_radius=6,
                    border=BORDER.all(1, COLORS.BLUE_200),
                    content=ft.Column(
                        spacing=2,
                        controls=[
                            ft.Text("État courant d'Alice", size=11, weight=ft.FontWeight.BOLD, color=COLORS.BLUE_900),
                            self.alice_state_text,
                        ],
                    ),
                ),
                ft.Container(
                    expand=True,
                    bgcolor=COLORS.PURPLE_50,
                    padding=8,
                    border_radius=6,
                    border=BORDER.all(1, COLORS.PURPLE_200),
                    content=ft.Column(
                        spacing=2,
                        controls=[
                            ft.Text("État courant de Bob", size=11, weight=ft.FontWeight.BOLD, color=COLORS.PURPLE_900),
                            self.bob_state_text,
                        ],
                    ),
                ),
            ],
        )

        left_pane = ft.Container(
            expand=6,
            bgcolor=COLORS.WHITE,
            padding=12,
            border_radius=10,
            border=BORDER.all(1, COLORS.BLUE_GREY_200),
            content=ft.Column(
                spacing=8,
                controls=[
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Text(
                                "Pipeline Double Ratchet (10 étapes fixes)",
                                size=15,
                                weight=ft.FontWeight.BOLD,
                                color=COLORS.BLUE_GREY_900,
                            ),
                            ft.Text(
                                "Cliquez sur une ligne pour inspecter ses clés complètes",
                                size=11,
                                italic=True,
                                color=COLORS.BLUE_GREY_600,
                            ),
                        ],
                    ),
                    state_summary_bar,
                    self.table_scroll_container,
                    detail_panel,
                ],
            ),
        )

        # --- PANNEAU DROIT : Chat classique Alice <-> Bob ---
        self.chat_list = ft.ListView(
            expand=True,
            spacing=10,
            auto_scroll=True,
            padding=10,
        )

        self.alice_input = ft.TextField(
            hint_text="Message d'Alice vers Bob…",
            expand=True,
            dense=True,
            on_submit=lambda _: self._handle_send("Alice", "Bob", delayed=False),
        )
        self.bob_input = ft.TextField(
            hint_text="Message de Bob vers Alice…",
            expand=True,
            dense=True,
            on_submit=lambda _: self._handle_send("Bob", "Alice", delayed=False),
        )

        alice_controls = ft.Container(
            bgcolor=COLORS.BLUE_50,
            padding=8,
            border_radius=8,
            border=BORDER.all(1, COLORS.BLUE_200),
            content=ft.Column(
                spacing=6,
                controls=[
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Text("Alice (Expéditeur gauche)", size=12, weight=ft.FontWeight.BOLD, color=COLORS.BLUE_900),
                            ft.TextButton(
                                "Envoyer en retard (hors-ordre)",
                                on_click=lambda _: self._handle_send("Alice", "Bob", delayed=True),
                            ),
                        ],
                    ),
                    ft.Row(
                        spacing=6,
                        controls=[
                            self.alice_input,
                            BUTTON(
                                "Envoyer",
                                bgcolor=COLORS.BLUE_700,
                                color=COLORS.WHITE,
                                on_click=lambda _: self._handle_send("Alice", "Bob", delayed=False),
                            ),
                        ],
                    ),
                ],
            ),
        )

        bob_controls = ft.Container(
            bgcolor=COLORS.PURPLE_50,
            padding=8,
            border_radius=8,
            border=BORDER.all(1, COLORS.PURPLE_200),
            content=ft.Column(
                spacing=6,
                controls=[
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Text("Bob (Expéditeur droite)", size=12, weight=ft.FontWeight.BOLD, color=COLORS.PURPLE_900),
                            ft.TextButton(
                                "Envoyer en retard (hors-ordre)",
                                on_click=lambda _: self._handle_send("Bob", "Alice", delayed=True),
                            ),
                        ],
                    ),
                    ft.Row(
                        spacing=6,
                        controls=[
                            self.bob_input,
                            BUTTON(
                                "Envoyer",
                                bgcolor=COLORS.PURPLE_700,
                                color=COLORS.WHITE,
                                on_click=lambda _: self._handle_send("Bob", "Alice", delayed=False),
                            ),
                        ],
                    ),
                ],
            ),
        )

        right_pane = ft.Container(
            expand=4,
            bgcolor=COLORS.WHITE,
            padding=12,
            border_radius=10,
            border=BORDER.all(1, COLORS.BLUE_GREY_200),
            content=ft.Column(
                spacing=8,
                controls=[
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Text(
                                "Discussion Chiffrée (Alice ↔ Bob)",
                                size=15,
                                weight=ft.FontWeight.BOLD,
                                color=COLORS.BLUE_GREY_900,
                            ),
                            ft.Row(
                                spacing=4,
                                controls=[
                                    ft.Icon(ICONS.VERIFIED_USER if ICONS else None, color=COLORS.GREEN_700, size=16),
                                    ft.Text("E2EE Actif", size=12, color=COLORS.GREEN_700, weight=ft.FontWeight.BOLD),
                                ],
                            ),
                        ],
                    ),
                    ft.Container(
                        expand=True,
                        bgcolor=COLORS.BLUE_GREY_50,
                        border_radius=8,
                        border=BORDER.all(1, COLORS.BLUE_GREY_200),
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
                spacing=10,
                controls=[
                    top_bar,
                    ft.Row(
                        expand=True,
                        spacing=12,
                        vertical_alignment=ft.CrossAxisAlignment.STRETCH,
                        controls=[left_pane, right_pane],
                    ),
                ],
            )
        )
        self._update_mode_buttons_style()

    # ------------------------------------------------------------------
    # Gestion des modes et notifications
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
            self.mode_instant_btn.bgcolor = COLORS.INDIGO_700
            self.mode_instant_btn.color = COLORS.WHITE
            self.mode_step_btn.bgcolor = COLORS.BLUE_GREY_100
            self.mode_step_btn.color = COLORS.BLUE_GREY_900
        else:
            self.mode_step_btn.bgcolor = COLORS.INDIGO_700
            self.mode_step_btn.color = COLORS.WHITE
            self.mode_instant_btn.bgcolor = COLORS.BLUE_GREY_100
            self.mode_instant_btn.color = COLORS.BLUE_GREY_900

    def _notify(self, text: str):
        snack = ft.SnackBar(ft.Text(text), duration=2500)
        if hasattr(self.page, "open"):
            self.page.open(snack)
        else:
            self.page.snack_bar = snack
            snack.open = True
            self.page.update()

    # ------------------------------------------------------------------
    # Bulles de chat (Droite)
    # ------------------------------------------------------------------
    def _make_system_banner(self, text: str) -> ft.Control:
        return ft.Container(
            alignment=CENTER_ALIGN,
            content=ft.Container(
                bgcolor=COLORS.AMBER_50,
                border=BORDER.all(1, COLORS.AMBER_300),
                border_radius=8,
                padding=8,
                content=ft.Text(text, size=11, color=COLORS.AMBER_900, text_align=ft.TextAlign.CENTER),
            ),
        )

    def _add_chat_bubble(self, sender_name: str, receiver_name: str, text: str, status_label: str, is_transit: bool = False):
        is_alice = sender_name == "Alice"
        bubble_color = COLORS.BLUE_100 if is_alice else COLORS.PURPLE_100
        if is_transit:
            bubble_color = COLORS.ORANGE_100
        border_color = COLORS.BLUE_300 if is_alice else COLORS.PURPLE_300
        if is_transit:
            border_color = COLORS.ORANGE_400

        align = ft.MainAxisAlignment.START if is_alice else ft.MainAxisAlignment.END

        bubble = ft.Container(
            width=330,
            bgcolor=bubble_color,
            border=BORDER.all(1, border_color),
            border_radius=12,
            padding=10,
            content=ft.Column(
                spacing=4,
                controls=[
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Text(
                                f"{sender_name} → {receiver_name}",
                                size=11,
                                weight=ft.FontWeight.BOLD,
                                color=COLORS.BLUE_GREY_900,
                            ),
                            ft.Text(status_label, size=10, italic=True, color=COLORS.BLUE_GREY_700),
                        ],
                    ),
                    ft.Text(text, size=13, color=COLORS.BLACK),
                ],
            ),
        )
        row = ft.Row(alignment=align, controls=[bubble])
        self.chat_list.controls.append(row)
        return bubble

    # ------------------------------------------------------------------
    # Calcul des mises à jour des 10 lignes fixes du tableau
    # ------------------------------------------------------------------
    def _handle_send(self, sender_name: str, receiver_name: str, delayed: bool = False):
        if self.pending_updates:
            self._notify("Terminez d'abord les étapes en cours avec 'Étape suivante (+1)' ou 'Finir le message'.")
            return

        input_field = self.alice_input if sender_name == "Alice" else self.bob_input
        text = (input_field.value or "").strip()
        if not text:
            text = f"Salut {receiver_name} ! (msg #{(self.alice.Ns if sender_name == 'Alice' else self.bob.Ns) + 1})"
        input_field.value = ""

        sender = self.alice if sender_name == "Alice" else self.bob
        receiver = self.bob if sender_name == "Alice" else self.alice

        if sender.CKs is None:
            self._notify(f"{sender_name} doit d'abord recevoir un message avant de pouvoir répondre !")
            return

        # Réinitialise l'affichage des lignes 1..9 pour ce nouveau message
        self._prepare_rows_for_new_message()

        plaintext_bytes = text.encode("utf-8")
        updates: list[StepUpdate] = []

        if self.execution_mode == "step" and not delayed:
            bubble_ref = self._add_chat_bubble(
                sender_name,
                receiver_name,
                f"🔒 [En transit chiffré…] ({text})",
                "En cours d'étape par étape",
                is_transit=True,
            )
        elif delayed:
            bubble_ref = self._add_chat_bubble(
                sender_name,
                receiver_name,
                f'⏳ [Paquet retardé sur le réseau] "{text}"',
                "Hors-ordre (en attente)",
                is_transit=True,
            )
        else:
            bubble_ref = self._add_chat_bubble(
                sender_name,
                receiver_name,
                text,
                "Déchiffré E2EE ✓",
                is_transit=False,
            )

        # ==============================================================
        # ÉTAPE 1 : kdf_ck(CKs)
        # ==============================================================
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
                live_value=f"N={ns_before} | MK={short_hex(mk)} | CKs→{short_hex(ck_after)}",
                vulgarisation=(
                    f"{sender_name} dérive la clé unique MK pour le message N={ns_before} et fait avancer sa "
                    f"chaîne d'envoi CKs via HMAC-SHA256."
                ),
                inputs_detail=f"• CKs avant : {full_hex(ck_before)}\n• Compteur Ns : {ns_before}",
                outputs_detail=f"• Nouvelle CKs : {full_hex(ck_after)}\n• Clé Message MK : {full_hex(mk)}",
            )
        )

        # ==============================================================
        # ÉTAPE 2 : encode_header
        # ==============================================================
        header_bytes = encode_header(dhs_pub, pn_before, ns_before)
        updates.append(
            StepUpdate(
                row_id=2,
                status="done",
                actor=sender_name,
                live_value=f"DHs={short_hex(dhs_pub)} | PN={pn_before} | N={ns_before}",
                vulgarisation=(
                    f"{sender_name} assemble l'en-tête de 40 octets : sa clé publique DH actuelle, "
                    f"PN={pn_before} et N={ns_before}."
                ),
                inputs_detail=f"• DHs pub : {full_hex(dhs_pub)}\n• PN={pn_before}, N={ns_before}",
                outputs_detail=f"• Header (40B) : {full_hex(header_bytes)}",
            )
        )

        # ==============================================================
        # ÉTAPE 3 : encrypt_symmetric
        # ==============================================================
        ciphertext = encrypt_symmetric(mk, plaintext_bytes, AD + header_bytes)
        sender.Ns += 1

        updates.append(
            StepUpdate(
                row_id=3,
                status="done",
                actor=sender_name,
                live_value=f"Paquet={len(ciphertext)}B | Nonce={short_hex(ciphertext[:12])} | HMAC={short_hex(ciphertext[-32:])}",
                vulgarisation=(
                    f"{sender_name} chiffre le texte \"{text}\" avec MK et ajoute une signature HMAC-SHA256 "
                    f"de 32 octets."
                ),
                inputs_detail=f'• Texte clair : "{text}"\n• Clé MK : {full_hex(mk)}',
                outputs_detail=(
                    f"• Nonce (12B) : {full_hex(ciphertext[:12])}\n"
                    f"• Chiffré     : {full_hex(ciphertext[12:-32])}\n"
                    f"• Tag HMAC    : {full_hex(ciphertext[-32:])}"
                ),
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
            # Marque les étapes de réception 4..9 comme non exécutées car paquet bloqué sur le réseau
            for rid in range(4, 10):
                updates.append(
                    StepUpdate(
                        row_id=rid,
                        status="skipped",
                        actor=receiver_name,
                        live_value="⏸ Paquet retenu sur le réseau (cliquez sur 'Livrer msg retardé')",
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
        # ==============================================================
        # ÉTAPE 4 : decode_header
        # ==============================================================
        dh_pub, pn, n = decode_header(header_bytes)
        dh_changed = dh_pub != receiver.DHr

        updates.append(
            StepUpdate(
                row_id=4,
                status="done",
                actor=receiver_name,
                live_value=f"PN={pn}, N={n} | {'🔄 NOUVELLE clé DH !' if dh_changed else '✔ Même clé DH'}",
                vulgarisation=(
                    f"{receiver_name} décode l'en-tête. "
                    + (
                        f"La clé publique DH de {sender_name} a changé : il faut exécuter un Ratchet DH (étapes 6 et 7) !"
                        if dh_changed
                        else f"La clé publique DH est identique à la précédente : pas besoin de Ratchet DH (étapes 6-7 sautées)."
                    )
                ),
                inputs_detail=f"• Header reçu : {full_hex(header_bytes)}",
                outputs_detail=f"• DH_pub : {full_hex(dh_pub)}\n• PN={pn}, N={n} | Changement DH = {dh_changed}",
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
                    live_value=f"📦 Clé MK retrouvée dans MKSKIPPED (N={n}) !",
                    vulgarisation=(
                        f"{receiver_name} retrouve la clé MK pré-calculée pour ce message retardataire dans MKSKIPPED."
                    ),
                    inputs_detail=f"• Clé recherchée : (DH={short_hex(dh_pub)}, N={n})",
                    outputs_detail=f"• MK récupérée : {full_hex(mk_saved)}\n• Reste dans MKSKIPPED : {len(receiver.MKSKIPPED)}",
                )
            )
            for rid in (6, 7, 8):
                updates.append(
                    StepUpdate(
                        row_id=rid,
                        status="skipped",
                        actor=receiver_name,
                        live_value="⏭ Sautée (clé déjà extraite de MKSKIPPED à l'étape 5)",
                        vulgarisation="Inutile de recalculer les chaînes : la clé MK était déjà archivée.",
                        inputs_detail="—",
                        outputs_detail="—",
                    )
                )

            def reveal_delayed(b=bubble_ref, pt=plaintext_out):
                b.bgcolor = COLORS.GREEN_100
                b.border = BORDER.all(1, COLORS.GREEN_400)
                b.content.controls[0].controls[1].value = "Déchiffré via MKSKIPPED ✓"
                b.content.controls[1].value = pt

            updates.append(
                StepUpdate(
                    row_id=9,
                    status="done",
                    actor=receiver_name,
                    live_value=f'HMAC OK ✓ → "{plaintext_out}"',
                    vulgarisation=f"Signature HMAC validée et texte déchiffré : \"{plaintext_out}\".",
                    inputs_detail=f"• MK : {full_hex(mk_saved)}",
                    outputs_detail=f'• Texte déchiffré : "{plaintext_out}"',
                    on_reveal=reveal_delayed,
                )
            )
            return

        # ==============================================================
        # ÉTAPE 5 : skip_message_keys (si saut avant changement DH ou sur chaîne courante)
        # ==============================================================
        skipped_something = False
        skip_summary_parts = []
        skip_in_parts = []
        skip_out_parts = []

        if dh_changed and receiver.Nr < pn:
            nr_start = receiver.Nr
            receiver.skip_message_keys(pn)
            skipped_something = True
            skip_summary_parts.append(f"Ancienne chaîne N={nr_start}..{pn - 1}")
            skip_in_parts.append(f"• Ancienne chaîne : Nr={nr_start} < PN={pn}")
            skip_out_parts.append(f"• Archivé N={nr_start}..{pn - 1} dans MKSKIPPED (total={len(receiver.MKSKIPPED)})")

        # ==============================================================
        # ÉTAPES 6 & 7 : Ratchet DH (si dh_changed)
        # ==============================================================
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
                    live_value=f"RK→{short_hex(rk_mid)} | CKr={short_hex(ckr_new)}",
                    vulgarisation=(
                        f"{receiver_name} calcule X25519 entre sa clé privée actuelle et la nouvelle clé publique de "
                        f"{sender_name}, puis dérive la nouvelle chaîne de réception CKr."
                    ),
                    inputs_detail=f"• RK avant : {full_hex(rk_before)}\n• DH_pub reçue : {full_hex(dh_pub)}",
                    outputs_detail=f"• Secret X25519 #1 : {full_hex(dh_out_1)}\n• RK mid : {full_hex(rk_mid)}\n• Nouvelle CKr : {full_hex(ckr_new)}",
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
                    live_value=f"DHs'={short_hex(receiver.DHs[1])} | RK→{short_hex(rk_after)} | CKs={short_hex(cks_new)}",
                    vulgarisation=(
                        f"{receiver_name} génère une nouvelle paire X25519 locale et re-mélange RK pour préparer "
                        f"sa future chaîne d'envoi CKs."
                    ),
                    inputs_detail=f"• RK mid : {full_hex(rk_mid)}\n• Ancienne DHs pub : {full_hex(old_dhs_pub)}",
                    outputs_detail=f"• Nouvelle DHs pub : {full_hex(receiver.DHs[1])}\n• Nouvelle RK : {full_hex(rk_after)}\n• Nouvelle CKs : {full_hex(cks_new)}",
                )
            )
        else:
            updates.append(
                StepUpdate(
                    row_id=6,
                    status="skipped",
                    actor=receiver_name,
                    live_value="⏭ Non requis (même clé DH que le message précédent)",
                    vulgarisation="Comme l'expéditeur n'a pas changé de clé DH, on conserve la chaîne de réception CKr.",
                    inputs_detail="DH_pub reçue == DHr actuelle",
                    outputs_detail=f"CKr inchangée : {full_hex(receiver.CKr)}",
                )
            )
            updates.append(
                StepUpdate(
                    row_id=7,
                    status="skipped",
                    actor=receiver_name,
                    live_value="⏭ Non requis (pas de renouvellement DH)",
                    vulgarisation="Pas de changement de tour de parole : pas de nouvelle paire DH générée.",
                    inputs_detail="DH_pub reçue == DHr actuelle",
                    outputs_detail=f"RK inchangée : {full_hex(receiver.RK)}",
                )
            )

        # Vérification des messages sautés sur la chaîne courante (Nr < n)
        if receiver.Nr < n:
            nr_before_skip = receiver.Nr
            receiver.skip_message_keys(n)
            skipped_something = True
            skip_summary_parts.append(f"Chaîne courante N={nr_before_skip}..{n - 1}")
            skip_in_parts.append(f"• Chaîne courante : Nr={nr_before_skip} < N={n}")
            skip_out_parts.append(f"• Archivé N={nr_before_skip}..{n - 1} dans MKSKIPPED (total={len(receiver.MKSKIPPED)})")

        # Insérer l'étape 5 juste après l'étape 4 dans l'ordre chronologique
        step5_update = StepUpdate(
            row_id=5,
            status="done" if skipped_something else "skipped",
            actor=receiver_name,
            live_value=(
                f"📦 Archivé : {', '.join(skip_summary_parts)} (total={len(receiver.MKSKIPPED)})"
                if skipped_something
                else f"⏭ Aucun message manquant (Nr={n} attendu == N={n} reçu)"
            ),
            vulgarisation=(
                "Des messages manquent à l'appel : leurs clés sont pré-calculées et sauvegardées dans MKSKIPPED."
                if skipped_something
                else "Le numéro du message reçu correspond exactement au compteur attendu : aucun saut nécessaire."
            ),
            inputs_detail="\n".join(skip_in_parts) if skipped_something else f"• Compteur attendu Nr = {n}",
            outputs_detail="\n".join(skip_out_parts) if skipped_something else f"• Taille MKSKIPPED = {len(receiver.MKSKIPPED)}",
        )
        # Positionner step5 juste après step4 (index 4 dans updates : 0=step1, 1=step2, 2=step3, 3=step4)
        updates.insert(4, step5_update)

        # ==============================================================
        # ÉTAPE 8 : kdf_ck(CKr)
        # ==============================================================
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
                live_value=f"N={nr_curr} | MK={short_hex(mk_recv)} | CKr→{short_hex(ckr_after)}",
                vulgarisation=(
                    f"{receiver_name} fait avancer sa chaîne de réception CKr et retrouve la même clé MK "
                    f"que celle utilisée par {sender_name} à l'étape 1."
                ),
                inputs_detail=f"• CKr avant : {full_hex(ckr_before)}\n• Compteur Nr : {nr_curr}",
                outputs_detail=f"• Nouvelle CKr : {full_hex(ckr_after)}\n• Clé MK retrouvée : {full_hex(mk_recv)}",
            )
        )

        # ==============================================================
        # ÉTAPE 9 : decrypt_symmetric
        # ==============================================================
        plaintext_out = decrypt_symmetric(mk_recv, ciphertext, AD + header_bytes).decode("utf-8")

        def reveal_decrypted(b=bubble_ref, pt=plaintext_out, is_alice=(sender_name == "Alice")):
            b.bgcolor = COLORS.BLUE_100 if is_alice else COLORS.PURPLE_100
            b.border = BORDER.all(1, COLORS.BLUE_300 if is_alice else COLORS.PURPLE_300)
            b.content.controls[0].controls[1].value = "Déchiffré E2EE ✓"
            b.content.controls[1].value = pt

        updates.append(
            StepUpdate(
                row_id=9,
                status="done",
                actor=receiver_name,
                live_value=f'HMAC OK ✓ → "{plaintext_out}"',
                vulgarisation=(
                    f"{receiver_name} valide le tag HMAC-SHA256 et déchiffre le message : \"{plaintext_out}\"."
                ),
                inputs_detail=f"• Paquet ({len(ciphertext)}B) : {short_hex(ciphertext, 10, 10)}\n• Clé MK : {full_hex(mk_recv)}",
                outputs_detail=f'• Signature HMAC : VALIDE ✓\n• Texte en clair : "{plaintext_out}"',
                on_reveal=reveal_decrypted,
            )
        )

    # ------------------------------------------------------------------
    # Exécution incrémentale ligne par ligne sur le tableau fixe
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
            self._notify("Terminez d'abord les étapes en cours avant de livrer le message retardé.")
            return
        if not self.delayed_packets:
            return

        pkt = self.delayed_packets.pop(0)
        self._prepare_rows_for_new_message()

        # Les étapes 1..3 (envoi) ont déjà eu lieu lors de l'envoi retardé
        updates: list[StepUpdate] = []
        for rid in (1, 2, 3):
            updates.append(
                StepUpdate(
                    row_id=rid,
                    status="skipped",
                    actor=pkt["sender_name"],
                    live_value="✔ Déjà envoyé précédemment (paquet en transit)",
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
            # En pas à pas, on marque 1..3 comme déjà faits et on commence directement à l'étape 4 (réception)
            for _ in range(3):
                self._apply_one_update(updates.pop(0))
            self.pending_updates.extend(updates)
            self._reveal_next_update()

        self._refresh_all_ui()

    # ------------------------------------------------------------------
    # Rendu visuel du tableau fixe et du panneau d'inspection
    # ------------------------------------------------------------------
    def _select_row(self, row_id: int):
        self.selected_row_id = row_id
        self._refresh_detail_panel()
        self._refresh_table_rows()
        self.page.update()

    def _make_status_badge(self, status: str, is_active: bool) -> ft.Control:
        if is_active and status == "done":
            return ft.Container(
                bgcolor=COLORS.ORANGE_700,
                padding=PADDING.symmetric(horizontal=8, vertical=3),
                border_radius=6,
                content=ft.Text("▶ EN COURS", color=COLORS.WHITE, size=10, weight=ft.FontWeight.BOLD),
            )
        if status == "done":
            return ft.Container(
                bgcolor=COLORS.GREEN_700,
                padding=PADDING.symmetric(horizontal=8, vertical=3),
                border_radius=6,
                content=ft.Text("✅ Exécuté", color=COLORS.WHITE, size=10, weight=ft.FontWeight.BOLD),
            )
        if status == "skipped":
            return ft.Container(
                bgcolor=COLORS.BLUE_GREY_300,
                padding=PADDING.symmetric(horizontal=8, vertical=3),
                border_radius=6,
                content=ft.Text("⏭ Non requis", color=COLORS.BLUE_GREY_900, size=10, weight=ft.FontWeight.BOLD),
            )
        return ft.Container(
            bgcolor=COLORS.BLUE_GREY_100,
            padding=PADDING.symmetric(horizontal=8, vertical=3),
            border_radius=6,
            content=ft.Text("⏳ En attente", color=COLORS.BLUE_GREY_700, size=10, weight=ft.FontWeight.BOLD),
        )

    def _refresh_table_rows(self):
        rows = []
        for item in STEP_DEFINITIONS:
            rid = item["id"]
            st = self.row_states[rid]
            is_selected = rid == self.selected_row_id
            is_active = rid == self.active_row_id

            row_bg = None
            if is_active:
                row_bg = COLORS.AMBER_50
            elif is_selected:
                row_bg = COLORS.INDIGO_50

            text_color = COLORS.BLUE_GREY_400 if st["status"] in ("pending", "skipped") else COLORS.BLUE_GREY_900

            row_kwargs = {
                "selected": is_selected,
                "color": row_bg,
                DATAROW_SELECT_EVENT: lambda _, r=rid: self._select_row(r),
                "cells": [
                    ft.DataCell(
                        ft.Text(st["title"], size=12, weight=ft.FontWeight.BOLD, color=text_color)
                    ),
                    ft.DataCell(
                        self._make_status_badge(st["status"], is_active)
                    ),
                    ft.DataCell(
                        ft.Text(st["actor"], size=12, weight=ft.FontWeight.W_600, color=text_color)
                    ),
                    ft.DataCell(
                        ft.Text(st["func"], size=11, font_family="monospace", color=COLORS.INDIGO_800 if st["status"] == "done" else text_color)
                    ),
                    ft.DataCell(
                        ft.Text(st["live_value"], size=11, font_family="monospace", color=text_color)
                    ),
                ],
            }
            rows.append(ft.DataRow(**row_kwargs))
        self.steps_table.rows = rows

    def _refresh_detail_panel(self):
        st = self.row_states.get(self.selected_row_id)
        if not st:
            return
        self.detail_title.value = f"{st['title']} ({st['actor']}) — {st['func']}"
        self.detail_vulgarisation.value = st["vulgarisation"]
        self.detail_inputs.value = st["inputs_detail"]
        self.detail_outputs.value = st["outputs_detail"]

    def _refresh_all_ui(self):
        pending_count = len(self.pending_updates)
        self.next_step_btn.disabled = pending_count == 0
        set_btn_label(
            self.next_step_btn,
            f"Étape suivante (+1) [{pending_count} restante{'s' if pending_count > 1 else ''}]"
            if pending_count > 0
            else "Étape suivante (+1)",
        )
        self.finish_all_btn.disabled = pending_count == 0

        delayed_count = len(self.delayed_packets)
        self.deliver_delayed_btn.disabled = delayed_count == 0 or pending_count > 0
        set_btn_label(self.deliver_delayed_btn, f"Livrer msg retardé ({delayed_count})")

        if pending_count > 0:
            self.status_pill.content.value = f"En cours : {pending_count} étape(s) restante(s)"
            self.status_pill.bgcolor = COLORS.ORANGE_700
        else:
            self.status_pill.content.value = "Synchronisé ✓"
            self.status_pill.bgcolor = COLORS.GREEN_700

        self.alice_state_text.value = (
            f"RK={short_hex(self.alice.RK)} | Ns={self.alice.Ns} Nr={self.alice.Nr} PN={self.alice.PN}\n"
            f"CKs={short_hex(self.alice.CKs)} | CKr={short_hex(self.alice.CKr)} | Skip={len(self.alice.MKSKIPPED)}"
        )
        self.bob_state_text.value = (
            f"RK={short_hex(self.bob.RK)} | Ns={self.bob.Ns} Nr={self.bob.Nr} PN={self.bob.PN}\n"
            f"CKs={short_hex(self.bob.CKs)} | CKr={short_hex(self.bob.CKr)} | Skip={len(self.bob.MKSKIPPED)}"
        )

        self._refresh_table_rows()
        self._refresh_detail_panel()
        self.page.update()


def main(page: ft.Page):
    DoubleRatchetApp(page)


if __name__ == "__main__":
    if hasattr(ft, "run"):
        ft.run(main)
    else:
        ft.app(target=main)
