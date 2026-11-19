"""
WhatsApp-Desktop-style login / register screen.

"Find server on LAN" broadcasts a discovery request (common/discovery.py) and fills in
the IP address and port of the server that answers.

Flow when the user presses "Log in" / "Create account":
    1. validate the form (instant feedback, no network needed)
    2. connect + secure handshake          (worker thread - UI stays responsive)
    3. verify the server's key fingerprint  (popup on first connection / if it changed)
    4. LOGIN or REGISTER                    (worker thread)
    5. emit logged_in(client, bridge)  ->  main.py opens the main window
"""

import re
import sqlite3
from functools import partial
from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QAction, QColor, QPainter
from PySide6.QtWidgets import (
    QButtonGroup, QCheckBox, QDialog, QFrame, QHBoxLayout, QLabel, QLineEdit,
    QListWidget, QListWidgetItem, QPushButton, QScrollArea, QSizePolicy, QVBoxLayout, QWidget,
)

from client.gui import icons, palette
from client.gui.bridge import ClientBridge
from client.gui.settings import ClientSettings
from client.gui.widgets.spinner import Spinner
from client.gui.workers import Task
from client.local_store import HISTORY_DIR, LocalStore
from client.network import AuthFailed, ChatClient
from common import discovery
from common.config import Config

USERNAME_RE = re.compile(r"^[a-z0-9_]{3,20}$")
BAND_HEIGHT = 222
CARD_WIDTH = 440


def set_prop(widget: QWidget, name: str, value) -> None:
    """Change a dynamic property and re-apply the stylesheet (e.g. error="true")."""
    widget.setProperty(name, value)
    widget.style().unpolish(widget)
    widget.style().polish(widget)


def role_label(text: str, role: str) -> QLabel:
    label = QLabel(text)
    label.setProperty("role", role)
    return label


# ---------------------------------------------------------------------------
# Small building blocks
# ---------------------------------------------------------------------------
class Field(QWidget):
    """Label + rounded input + inline error message."""

    def __init__(self, label: str, placeholder: str = "", password: bool = False, parent=None):
        super().__init__(parent)
        # Never squash a field below its natural height - the page scrolls instead
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)

        self.label = role_label(label, "field-label")
        self.edit = QLineEdit()
        self.edit.setFixedHeight(40)
        self.edit.setPlaceholderText(placeholder)
        self.error = role_label("", "error")
        self.error.setWordWrap(True)
        self.error.hide()
        layout.addWidget(self.label)
        layout.addWidget(self.edit)
        layout.addWidget(self.error)

        self.edit.textEdited.connect(lambda _: self.set_error(""))
        if password:
            self.edit.setEchoMode(QLineEdit.Password)
            self._eye = QAction(icons.svg_icon(icons.EYE, 20, "#8696A0"), "Show password", self.edit)
            self._eye.triggered.connect(self._toggle_password)
            self.edit.addAction(self._eye, QLineEdit.TrailingPosition)

    def _toggle_password(self) -> None:
        hidden = self.edit.echoMode() == QLineEdit.Password
        self.edit.setEchoMode(QLineEdit.Normal if hidden else QLineEdit.Password)
        self._eye.setIcon(icons.svg_icon(icons.EYE_OFF if hidden else icons.EYE, 20, "#8696A0"))
        self._eye.setToolTip("Hide password" if hidden else "Show password")

    def text(self) -> str:
        return self.edit.text().strip()

    def set_error(self, message: str) -> None:
        self.error.setText(message)
        self.error.setVisible(bool(message))
        set_prop(self.edit, "error", bool(message))


class PrimaryButton(QPushButton):
    """Green pill button that shows a spinner next to its text while busy."""

    def __init__(self, text: str = "", parent=None):
        super().__init__(text, parent)
        self.setObjectName("PrimaryButton")
        self.setCursor(Qt.PointingHandCursor)
        self._spinner = Spinner(self, size=18, color="#FFFFFF")

    def set_busy(self, busy: bool, text: str) -> None:
        self.setEnabled(not busy)
        self.setText(text)
        if busy:
            self._place_spinner()
            self._spinner.start()
        else:
            self._spinner.stop()

    def _place_spinner(self) -> None:
        text_width = self.fontMetrics().horizontalAdvance(self.text())
        x = (self.width() - text_width) // 2 - self._spinner.width() - 10
        self._spinner.move(max(14, x), (self.height() - self._spinner.height()) // 2)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._place_spinner()


class Backdrop(QWidget):
    """
    Page background: grey, with the teal band across the top (WhatsApp Desktop style),
    plus a soft shadow under the card. The shadow is painted here rather than with
    QGraphicsDropShadowEffect, which would re-render the whole card on every
    spinner frame (slow, and it leaves glitches on the inputs).
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.shadow_for: Optional[QWidget] = None

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        colours = palette.current()
        painter.fillRect(self.rect(), QColor(colours.login_bg))
        painter.fillRect(0, 0, self.width(), BAND_HEIGHT, QColor(colours.login_band))
        if self.shadow_for is not None:
            rect = self.shadow_for.geometry().translated(0, 3)
            painter.setPen(Qt.NoPen)
            for spread in range(14, 0, -1):   # stacked translucent layers fade outwards
                painter.setBrush(QColor(11, 20, 26, int(1 + (14 - spread) * 0.3)))
                r = rect.adjusted(-spread, -spread, spread, spread)
                painter.drawRoundedRect(r, 12 + spread, 12 + spread)


# ---------------------------------------------------------------------------
# Fingerprint verification popup
# ---------------------------------------------------------------------------
class FingerprintDialog(QDialog):
    """
    Shows the server's public-key fingerprint so the user can compare it with
    the one printed in the server window. A man-in-the-middle would have to
    use a different key, so the fingerprints would not match.
    """

    def __init__(self, fingerprint: str, key_id: str, host: str, port: int,
                 previous: Optional[str] = None, parent=None):
        super().__init__(parent)
        changed = previous is not None
        self.setObjectName("FingerprintDialog")
        self.setWindowTitle("Server key changed!" if changed else "Verify the server")
        self.setModal(True)
        self.setFixedWidth(500)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 30, 36, 26)
        layout.setSpacing(0)

        icon = QLabel()
        icon.setPixmap(icons.svg_pixmap(icons.WARNING if changed else icons.SHIELD_CHECK, 48,
                                        "#EA0038" if changed else "#00A884"))
        icon.setAlignment(Qt.AlignCenter)
        layout.addWidget(icon)
        layout.addSpacing(12)

        title = QLabel("The server's key has CHANGED" if changed else "Verify the server")
        title.setObjectName("DialogTitle")
        set_prop(title, "danger", changed)
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        layout.addSpacing(10)

        if changed:
            body = (f"The key of <b>{host}:{port}</b> is different from the one you verified before. "
                    "That happens if the server's keys were re-created, <b>or if someone is "
                    "intercepting your connection</b> (a man-in-the-middle attack). "
                    "Only continue if you are sure.")
        else:
            body = (f"This is your first connection to <b>{host}:{port}</b>. Compare this fingerprint "
                    "with the one shown in the server's window. If they match, nobody can "
                    "intercept your connection.")
        text = QLabel(body)
        text.setObjectName("DialogText")
        text.setWordWrap(True)
        text.setAlignment(Qt.AlignCenter)
        layout.addWidget(text)
        layout.addSpacing(18)

        groups = fingerprint.split(" ")
        fp = QLabel("\n".join("   ".join(groups[i:i + 4]) for i in range(0, len(groups), 4)))
        fp.setObjectName("Fingerprint")
        set_prop(fp, "danger", changed)
        fp.setAlignment(Qt.AlignCenter)
        fp.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(fp)
        layout.addSpacing(10)

        info = QLabel(f"Session encrypted with AES-256-GCM  ·  session key id {key_id}")
        info.setObjectName("SessionInfo")
        info.setAlignment(Qt.AlignCenter)
        layout.addWidget(info)
        layout.addSpacing(24)

        buttons = QHBoxLayout()
        buttons.setSpacing(10)
        buttons.addStretch()
        self.cancel_button = QPushButton("Disconnect" if changed else "Cancel")
        self.cancel_button.setObjectName("SecondaryButton")
        self.confirm_button = QPushButton("Trust the new key" if changed else "It matches – connect")
        self.confirm_button.setObjectName("DangerButton" if changed else "PrimaryButton")
        for b in (self.cancel_button, self.confirm_button):
            b.setCursor(Qt.PointingHandCursor)
            buttons.addWidget(b)
        (self.cancel_button if changed else self.confirm_button).setDefault(True)
        self.cancel_button.clicked.connect(self.reject)
        self.confirm_button.clicked.connect(self.accept)
        layout.addLayout(buttons)


# ---------------------------------------------------------------------------
# "Find server on LAN" - choose when more than one server answers
# ---------------------------------------------------------------------------
class ServerPickerDialog(QDialog):
    def __init__(self, servers, parent=None):
        super().__init__(parent)
        self.servers = list(servers)
        self.setObjectName("FingerprintDialog")
        self.setWindowTitle("Servers on this network")
        self.setModal(True)
        self.setFixedWidth(460)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 26, 30, 22)
        layout.setSpacing(0)
        title = QLabel(f"{len(self.servers)} SecureChat servers answered")
        title.setObjectName("DialogTitle")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        layout.addSpacing(8)
        text = QLabel("Pick the one running on your other PC. Its key fingerprint is checked "
                      "again when you connect.")
        text.setObjectName("DialogText")
        text.setWordWrap(True)
        text.setAlignment(Qt.AlignCenter)
        layout.addWidget(text)
        layout.addSpacing(14)

        self.list = QListWidget()
        self.list.setObjectName("ServerPicker")
        for server in self.servers:
            item = QListWidgetItem(f"{server.name}    {server.host}:{server.port}\n"
                                   f"Key  {server.short_fingerprint} …")
            self.list.addItem(item)
        self.list.setCurrentRow(0)
        self.list.ensurePolished()
        rows = sum(self.list.sizeHintForRow(i) for i in range(self.list.count()))
        self.list.setFixedHeight(min(260, rows + 2 * self.list.frameWidth() + 2))
        self.list.itemDoubleClicked.connect(lambda _: self.accept())
        layout.addWidget(self.list)
        layout.addSpacing(18)

        buttons = QHBoxLayout()
        buttons.setSpacing(10)
        buttons.addStretch()
        cancel = QPushButton("Cancel")
        cancel.setObjectName("SecondaryButton")
        use = QPushButton("Use this server")
        use.setObjectName("PrimaryButton")
        for b in (cancel, use):
            b.setCursor(Qt.PointingHandCursor)
            buttons.addWidget(b)
        use.setDefault(True)
        cancel.clicked.connect(self.reject)
        use.clicked.connect(self.accept)
        layout.addLayout(buttons)

    @property
    def selected(self):
        return self.servers[max(0, self.list.currentRow())]


# ---------------------------------------------------------------------------
# Login window
# ---------------------------------------------------------------------------
class LoginWindow(QWidget):
    logged_in = Signal(object, object, object)   # (ChatClient, ClientBridge, LocalStore or None)

    def __init__(self, config: Config, settings: ClientSettings, notice: str = "",
                 host_override: Optional[str] = None, port_override: Optional[int] = None):
        super().__init__()
        self.config = config
        self.settings = settings
        self.client: Optional[ChatClient] = None
        self.bridge: Optional[ClientBridge] = None
        self.history_dir = HISTORY_DIR
        self._mode = "login"
        self._busy = False
        self._handed_over = False
        self._task: Optional[Task] = None

        self.setObjectName("LoginRoot")
        self.setWindowTitle("SecureChat")
        self.resize(1000, 760)
        self.setMinimumSize(520, 480)

        self._build()
        self._load_settings(host_override, port_override)
        self._set_mode("login")
        if notice:
            self._show_general_error(notice)

    # ---------------------------------------------------------------- layout
    def _build(self) -> None:
        # Everything sits in a scroll area, so a short window scrolls instead of squashing the form
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        page = Backdrop()
        scroll.setWidget(page)
        outer.addWidget(scroll)

        root = QVBoxLayout(page)
        root.setContentsMargins(0, 0, 0, 24)
        root.setSpacing(0)

        header = QHBoxLayout()
        header.setContentsMargins(34, 24, 34, 0)
        brand_logo = QLabel()
        brand_logo.setPixmap(icons.svg_pixmap(icons.LOGO, 30))
        brand = QLabel("SECURECHAT")
        brand.setObjectName("BrandName")
        header.addWidget(brand_logo)
        header.addSpacing(10)
        header.addWidget(brand)
        header.addStretch()
        root.addLayout(header)
        root.addSpacing(26)

        centre = QHBoxLayout()
        centre.addStretch()
        card = self._build_card()
        page.shadow_for = card
        centre.addWidget(card)
        centre.addStretch()
        root.addLayout(centre)
        root.addSpacing(18)

        footer = QHBoxLayout()
        footer.addStretch()
        lock = QLabel()
        lock.setPixmap(icons.svg_pixmap(icons.LOCK, 13, "#8696A0"))
        footer_text = QLabel("Your personal messages are protected with AES-256-GCM encryption "
                             "and an RSA-2048 key exchange")
        footer_text.setObjectName("Footer")
        footer.addWidget(lock)
        footer.addSpacing(6)
        footer.addWidget(footer_text)
        footer.addStretch()
        root.addLayout(footer)
        root.addStretch()

    def _build_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("Card")
        card.setFixedWidth(CARD_WIDTH)

        layout = QVBoxLayout(card)
        layout.setContentsMargins(40, 32, 40, 30)
        layout.setSpacing(0)

        logo = QLabel()
        logo.setPixmap(icons.svg_pixmap(icons.LOGO, 64))
        logo.setAlignment(Qt.AlignCenter)
        layout.addWidget(logo)
        layout.addSpacing(12)

        title = QLabel("SecureChat")
        title.setObjectName("Title")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        layout.addSpacing(4)

        tagline_row = QHBoxLayout()
        tagline_row.addStretch()
        tag_lock = QLabel()
        tag_lock.setPixmap(icons.svg_pixmap(icons.LOCK, 12, "#667781"))
        tagline = QLabel("End-to-end encrypted with AES-256")
        tagline.setObjectName("Tagline")
        tagline_row.addWidget(tag_lock)
        tagline_row.addSpacing(5)
        tagline_row.addWidget(tagline)
        tagline_row.addStretch()
        layout.addLayout(tagline_row)
        layout.addSpacing(22)

        # Tabs
        tab_bar = QFrame()
        tab_bar.setObjectName("TabBar")
        tabs = QHBoxLayout(tab_bar)
        tabs.setContentsMargins(0, 0, 0, 0)
        tabs.setSpacing(0)
        self.login_tab = QPushButton("Log in")
        self.register_tab = QPushButton("Create account")
        self._tab_group = QButtonGroup(self)
        for tab in (self.login_tab, self.register_tab):
            tab.setObjectName("TabButton")
            tab.setCheckable(True)
            tab.setCursor(Qt.PointingHandCursor)
            self._tab_group.addButton(tab)
            tabs.addWidget(tab)
        self.login_tab.clicked.connect(lambda: self._set_mode("login"))
        self.register_tab.clicked.connect(lambda: self._set_mode("register"))
        layout.addWidget(tab_bar)
        layout.addSpacing(20)

        # Form
        form = QVBoxLayout()
        form.setSpacing(14)

        self.server_row = QFrame()
        self.server_row.setObjectName("ServerRow")
        server_row = QHBoxLayout(self.server_row)
        server_row.setContentsMargins(12, 6, 6, 6)
        server_icon = QLabel()
        server_icon.setPixmap(icons.svg_pixmap(icons.SERVER, 16, "#8696A0"))
        self.server_text = QLabel()
        self.server_text.setObjectName("ServerText")
        change = QPushButton("Change")
        change.setObjectName("LinkButton")
        change.setCursor(Qt.PointingHandCursor)
        change.clicked.connect(lambda: self._show_server_fields(True))
        server_row.addWidget(server_icon)
        server_row.addSpacing(6)
        server_row.addWidget(self.server_text)
        server_row.addStretch()
        server_row.addWidget(change)
        form.addWidget(self.server_row)

        self.server_fields = QWidget()
        server_column = QVBoxLayout(self.server_fields)
        server_column.setContentsMargins(0, 0, 0, 0)
        server_column.setSpacing(8)
        server_fields = QHBoxLayout()
        server_fields.setSpacing(10)
        self.host = Field("SERVER IP ADDRESS", "e.g. 192.168.1.5")
        self.port = Field("PORT", "5555")
        self.port.setFixedWidth(96)
        server_fields.addWidget(self.host, 1)
        server_fields.addWidget(self.port, 0, Qt.AlignTop)
        server_column.addLayout(server_fields)
        self.find_button = QPushButton("  Find server on LAN")
        self.find_button.setObjectName("SecondaryButton")
        self.find_button.setIcon(icons.svg_icon(icons.SEARCH, 18, "#00A884"))
        self.find_button.setCursor(Qt.PointingHandCursor)
        self.find_button.setToolTip("Look for a SecureChat server on this Wi-Fi / network")
        self.find_button.clicked.connect(self.find_servers)
        server_column.addWidget(self.find_button)
        form.addWidget(self.server_fields)

        self.username = Field("USERNAME", "Your username")
        self.display_name = Field("DISPLAY NAME", "How others will see you (optional)")
        self.password = Field("PASSWORD", "Your password", password=True)
        form.addWidget(self.username)
        form.addWidget(self.display_name)
        form.addWidget(self.password)

        self.remember = QCheckBox("Remember server address")
        self.remember.setCursor(Qt.PointingHandCursor)
        form.addWidget(self.remember)
        layout.addLayout(form)
        layout.addSpacing(14)

        self.general_error = role_label("", "error")
        self.general_error.setWordWrap(True)
        self.general_error.setAlignment(Qt.AlignCenter)
        self.general_error.hide()
        layout.addWidget(self.general_error)

        self.status = role_label("", "status-ok")
        self.status.setAlignment(Qt.AlignCenter)
        self.status.hide()
        layout.addWidget(self.status)
        layout.addSpacing(10)

        self.submit_button = PrimaryButton()
        self.submit_button.clicked.connect(self.submit)
        layout.addWidget(self.submit_button)

        for field in (self.host, self.port, self.username, self.display_name, self.password):
            field.edit.returnPressed.connect(self.submit)
        self.host.edit.textChanged.connect(self._update_server_text)
        self.port.edit.textChanged.connect(self._update_server_text)
        return card

    # ------------------------------------------------------------- state
    def _load_settings(self, host_override, port_override) -> None:
        saved = self.settings.saved_server()
        host, port = saved or (self.config.client_host, self.config.port)
        self.host.edit.setText(host_override or host)
        self.port.edit.setText(str(port_override or port))
        self.remember.setChecked(self.settings.remember_server)
        self._show_server_fields(saved is None and not host_override)
        if self.settings.last_username:
            self.username.edit.setText(self.settings.last_username)
            self.password.edit.setFocus()
        else:
            self.username.edit.setFocus()

    def _update_server_text(self) -> None:
        self.server_text.setText(f"Server   {self.host.text() or '?'}:{self.port.text() or '?'}")

    def _show_server_fields(self, show: bool) -> None:
        self._update_server_text()
        self.server_fields.setVisible(show)
        self.server_row.setVisible(not show)
        if show:
            self.host.edit.setFocus()

    def _set_mode(self, mode: str) -> None:
        self._mode = mode
        register = mode == "register"
        (self.register_tab if register else self.login_tab).setChecked(True)
        self.display_name.setVisible(register)
        self.password.edit.setPlaceholderText(
            "At least 8 characters, with a letter and a number" if register else "Your password")
        self.username.edit.setPlaceholderText(
            "3-20 characters: a-z, 0-9 or _" if register else "Your username")
        self._clear_errors()
        self.submit_button.set_busy(False, "Create account" if register else "Log in")

    def _set_busy(self, busy: bool, text: str = "") -> None:
        self._busy = busy
        for widget in (self.host, self.port, self.username, self.display_name, self.password,
                       self.remember, self.login_tab, self.register_tab, self.server_row, self.find_button):
            widget.setEnabled(not busy)
        idle = "Create account" if self._mode == "register" else "Log in"
        self.submit_button.set_busy(busy, text if busy else idle)

    def _clear_errors(self) -> None:
        for field in (self.host, self.port, self.username, self.display_name, self.password):
            field.set_error("")
        self._show_general_error("")
        self.status.hide()

    def _show_general_error(self, message: str) -> None:
        self.general_error.setText(message)
        self.general_error.setVisible(bool(message))

    def _show_status(self, message: str) -> None:
        self.status.setText(message)
        self.status.setVisible(bool(message))

    # --------------------------------------------------------- validation
    def _validate(self) -> bool:
        ok = True
        register = self._mode == "register"
        if not self.host.text():
            self.host.set_error("Enter the server's IP address")
            ok = False
        try:
            if not 1 <= int(self.port.text()) <= 65535:
                raise ValueError
        except ValueError:
            self.port.set_error("1-65535")
            ok = False
        if not ok:
            self._show_server_fields(True)

        username = self.username.text().lower()
        if not username:
            self.username.set_error("Enter your username")
            ok = False
        elif register and not USERNAME_RE.match(username):
            self.username.set_error("Use 3-20 characters: lowercase letters, digits or _")
            ok = False

        password = self.password.edit.text()
        if not password:
            self.password.set_error("Enter your password")
            ok = False
        elif register and (len(password) < 8 or not any(ch.isalpha() for ch in password)   # any alphabet
                           or not any(ch.isdigit() for ch in password)):
            self.password.set_error("At least 8 characters, with at least one letter and one number")
            ok = False

        if register and len(self.display_name.text()) > 30:
            self.display_name.set_error("At most 30 characters")
            ok = False
        return ok

    # ------------------------------------------------- find server on LAN
    def find_servers(self) -> None:
        if self._busy:
            return
        self._clear_errors()
        self._set_busy(True, "Searching the local network…")
        self._run(lambda: discovery.discover(), self._on_servers_found, self._on_discovery_failed)

    def _on_servers_found(self, servers) -> None:
        self._set_busy(False)
        if not servers:
            self._show_server_fields(True)
            self.host.set_error("No SecureChat server answered. Check that the server is running on the "
                                "same Wi-Fi - some networks block this search, so you may need to type the "
                                "IP address shown in the server window.")
            return
        if len(servers) > 1:
            dialog = ServerPickerDialog(servers, self)
            if dialog.exec() != QDialog.Accepted:
                return
            server = dialog.selected
        else:
            server = servers[0]
        self.host.edit.setText(server.host)
        self.port.edit.setText(str(server.port))
        self._show_server_fields(True)
        self._show_status(f"✓  Found “{server.name}” at {server.host}:{server.port}")
        (self.password if self.username.text() else self.username).edit.setFocus()

    def _on_discovery_failed(self, exc: Exception) -> None:
        self._set_busy(False)
        self._show_server_fields(True)
        self.host.set_error(f"Could not search the network: {exc}")

    # --------------------------------------------------------- the flow
    def submit(self) -> None:
        if self._busy:
            return
        self._clear_errors()
        if not self._validate():
            return

        host, port = self.host.text(), int(self.port.text())
        if self.client and self.client.connected and (self.client.host, self.client.port) == (host, port):
            self._authenticate()      # already connected (e.g. retrying after a wrong password)
            return

        self._drop_client()
        self.client = ChatClient(host, port, heartbeat_interval=self.config.heartbeat_interval)
        self.bridge = ClientBridge(self.client)
        self.bridge.disconnected.connect(self._on_lost_connection)
        self._set_busy(True, "Connecting securely…")
        self._run(self.client.connect, self._on_connected, self._on_connect_failed)

    def _run(self, fn, on_success, on_failure) -> None:
        self._task = Task(fn, self)
        self._task.succeeded.connect(on_success)
        self._task.failed.connect(on_failure)
        self._task.finished.connect(self._task.deleteLater)
        self._task.start()

    def _on_connect_failed(self, exc: Exception) -> None:
        self._drop_client()
        self._set_busy(False)
        self._show_server_fields(True)
        self.host.set_error(str(exc))

    def _on_connected(self, fingerprint: str) -> None:
        if self.client is None:   # connection dropped before this slot ran
            self._set_busy(False)
            self._show_general_error("Lost the connection to the server. Please try again.")
            return
        host, port = self.client.host, self.client.port
        trusted = self.settings.trusted_fingerprint(host, port)
        if trusted == fingerprint:
            self._show_status("✓  Server verified: its key fingerprint matches")
            self._authenticate()
            return

        dialog = FingerprintDialog(fingerprint, self.client.key_fingerprint, host, port,
                                   previous=trusted, parent=self)
        if dialog.exec() == QDialog.Accepted and self.client and self.client.connected:
            self.settings.trust(host, port, fingerprint)
            self.settings.save()
            self._show_status("✓  Server verified")
            self._authenticate()
        else:
            self._drop_client()
            self._set_busy(False)
            self._show_general_error("Not connected: the server's identity was not confirmed.")

    def _authenticate(self) -> None:
        username, password = self.username.text().lower(), self.password.edit.text()
        if self._mode == "register":
            self._set_busy(True, "Creating your account…")
            fn = partial(self.client.register, username, password, self.display_name.text() or None)
        else:
            self._set_busy(True, "Logging in…")
            fn = partial(self.client.login, username, password)
        self._run(fn, self._on_auth_ok, self._on_auth_failed)

    def _on_auth_failed(self, exc: Exception) -> None:
        self._set_busy(False)
        if not isinstance(exc, AuthFailed):
            self._drop_client()
            self._show_general_error(str(exc))
            return
        message = str(exc)
        if "Username" in message or "taken" in message:
            self.username.set_error(message)
        elif "Display name" in message:
            self.display_name.set_error(message)
        else:
            self.password.set_error(message)
        self.password.edit.selectAll()
        self.password.edit.setFocus()

    def _on_auth_ok(self, profile: dict) -> None:
        self.settings.set_server(self.client.host, self.client.port, self.remember.isChecked())
        self.settings.last_username = profile["username"]
        self.settings.save()
        # Open the encrypted local history. Its key is derived from the password the user
        # just typed (PBKDF2); the password itself is not kept anywhere.
        try:
            history = LocalStore.open(profile["username"], self.password.edit.text(),
                                      self.history_dir, reset_if_locked=True)
        except (OSError, sqlite3.Error):
            history = None
        self.password.edit.clear()
        self._handed_over = True
        self.bridge.disconnected.disconnect(self._on_lost_connection)
        self.logged_in.emit(self.client, self.bridge, history)

    def _on_lost_connection(self, reason: str) -> None:
        if self._handed_over:
            return
        self.client = None
        self.bridge = None
        if not self._busy:   # if a request is running, its own failure handler reports it
            self._show_general_error("Lost the connection to the server. Please try again.")

    def _drop_client(self) -> None:
        if self.client:
            self.client.close()
        self.client = None
        self.bridge = None

    def closeEvent(self, event) -> None:
        if self._task is not None:
            try:
                self._task.wait(3000)
            except RuntimeError:   # the task's C++ object was already deleted
                pass
        if not self._handed_over:
            self._drop_client()
        super().closeEvent(event)
