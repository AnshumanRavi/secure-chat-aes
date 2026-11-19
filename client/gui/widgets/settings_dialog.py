"""
Settings, WhatsApp-style: a list on the left (Profile, Privacy, Chats, Notifications,
Security, About) and the selected page on the right. Changes apply immediately.
"""

import time

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup, QCheckBox, QDialog, QFrame, QHBoxLayout, QLabel, QLineEdit, QListWidget,
    QListWidgetItem, QMessageBox, QPlainTextEdit, QPushButton, QRadioButton, QScrollArea,
    QStackedWidget, QVBoxLayout, QWidget,
)

from client.files import human_size
from client.gui import icons, palette
from client.gui.settings import ClientSettings
from client.gui.widgets.avatar import Avatar

PAGES = [("profile", "Profile", icons.ACCOUNT), ("privacy", "Privacy", icons.LOCK),
         ("chats", "Chats", icons.BUBBLE_OUTLINE), ("notifications", "Notifications", icons.BELL),
         ("security", "Security", icons.SHIELD_CHECK), ("about", "About", icons.INFO)]


def _label(text: str, name: str, wrap: bool = False) -> QLabel:
    label = QLabel(text)
    label.setObjectName(name)
    label.setWordWrap(wrap)
    return label


class SettingsDialog(QDialog):
    theme_changed = Signal(str)                 # light | dark | system
    wallpaper_changed = Signal(str, bool)       # preset name, doodles
    preferences_changed = Signal()              # notification / privacy switches
    profile_save_requested = Signal(str, str)   # display name, about
    clear_history_requested = Signal()

    def __init__(self, client, settings: ClientSettings, history=None, message_count: int = 0,
                 start_page: str = "profile", parent=None):
        super().__init__(parent)
        self.client, self.settings, self.history = client, settings, history
        self.message_count = message_count
        self.setObjectName("SettingsDialog")
        self.setWindowTitle("Settings")
        self.resize(860, 620)

        h = QHBoxLayout(self)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        self.nav = QListWidget()
        self.nav.setObjectName("SettingsNav")
        self.nav.setFixedWidth(230)
        self.nav.setIconSize(QSize(22, 22))
        self.pages = QStackedWidget()
        self.pages.setObjectName("SettingsPages")
        self._page_index = {}
        for key, title, svg in PAGES:
            item = QListWidgetItem(icons.svg_icon(svg, 22, palette.theme_icon()), f"  {title}")
            item.setSizeHint(QSize(0, 52))
            self.nav.addItem(item)
            self._page_index[key] = self.pages.count()
            self.pages.addWidget(self._scroll(getattr(self, f"_page_{key}")()))
        self.nav.currentRowChanged.connect(self.pages.setCurrentIndex)
        h.addWidget(self.nav)
        h.addWidget(self.pages, 1)
        self.nav.setCurrentRow(self._page_index.get(start_page, 0))

    # ------------------------------------------------------------ helpers
    @staticmethod
    def _scroll(page: QWidget) -> QScrollArea:
        scroll = QScrollArea()
        scroll.setObjectName("SettingsScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(page)
        return scroll

    @staticmethod
    def _page(title: str):
        page = QWidget()
        page.setObjectName("SettingsPage")
        v = QVBoxLayout(page)
        v.setContentsMargins(28, 24, 28, 24)
        v.setSpacing(14)
        v.addWidget(_label(title, "SettingsHeading"))
        return page, v

    @staticmethod
    def _card():
        card = QFrame()
        card.setObjectName("SettingsCard")
        v = QVBoxLayout(card)
        v.setContentsMargins(20, 16, 20, 16)
        v.setSpacing(8)
        return card, v

    def _switch(self, layout, key: str, text: str, hint: str) -> QCheckBox:
        box = QCheckBox(text)
        box.setChecked(bool(self.settings.get(key)))
        box.setCursor(Qt.PointingHandCursor)
        box.toggled.connect(lambda on, k=key: (self.settings.set(k, on), self.preferences_changed.emit()))
        layout.addWidget(box)
        layout.addWidget(_label(hint, "SettingsHint", wrap=True))
        return box

    # -------------------------------------------------------------- pages
    def _page_profile(self) -> QWidget:
        page, v = self._page("Profile")
        card, c = self._card()
        profile = self.client.profile
        self.profile_avatar = Avatar(110, profile.get("display_name", ""), profile.get("avatar_color", "#00A884"))
        c.addWidget(self.profile_avatar, 0, Qt.AlignHCenter)
        c.addSpacing(8)
        c.addWidget(_label("YOUR NAME", "SettingsLabel"))
        self.name_edit = QLineEdit(profile.get("display_name", ""))
        self.name_edit.setMaxLength(30)
        self.name_edit.setFixedHeight(40)
        c.addWidget(self.name_edit)
        c.addWidget(_label(f"This is not your username (@{profile.get('username')}). "
                           "It is shown to your contacts.", "SettingsHint", wrap=True))
        c.addSpacing(6)
        c.addWidget(_label("ABOUT", "SettingsLabel"))
        self.about_edit = QLineEdit(profile.get("about", ""))
        self.about_edit.setMaxLength(140)
        self.about_edit.setFixedHeight(40)
        c.addWidget(self.about_edit)
        row = QHBoxLayout()
        self.profile_status = _label("", "SettingsHint")
        self.save_profile = QPushButton("Save")
        self.save_profile.setObjectName("PrimaryButton")
        self.save_profile.setCursor(Qt.PointingHandCursor)
        self.save_profile.setEnabled(False)
        self.save_profile.clicked.connect(self._save_profile)
        row.addWidget(self.profile_status, 1)
        row.addWidget(self.save_profile)
        c.addSpacing(6)
        c.addLayout(row)
        for edit in (self.name_edit, self.about_edit):
            edit.textChanged.connect(self._profile_edited)
        v.addWidget(card)
        v.addStretch()
        return page

    def _profile_edited(self) -> None:
        profile = self.client.profile
        changed = (self.name_edit.text().strip() != profile.get("display_name", "")
                   or self.about_edit.text().strip() != profile.get("about", ""))
        self.save_profile.setEnabled(changed and bool(self.name_edit.text().strip()))
        self.profile_status.setText("")

    def _save_profile(self) -> None:
        self.profile_save_requested.emit(self.name_edit.text().strip(), self.about_edit.text().strip())
        self.profile_status.setText("Saving…")
        self.save_profile.setEnabled(False)

    def profile_saved(self, profile: dict) -> None:
        """Called by the main window when the server confirms the new profile."""
        self.profile_avatar.set_person(profile.get("display_name", ""), profile.get("avatar_color", "#00A884"))
        self.profile_status.setText("✓ Saved - your contacts will see the change")

    def _page_privacy(self) -> QWidget:
        page, v = self._page("Privacy")
        card, c = self._card()
        self._switch(c, "read_receipts", "Read receipts",
                     "If turned off, people won't see blue ticks when you read their messages.")
        c.addSpacing(6)
        self._switch(c, "typing_indicator", "Show when I'm typing",
                     "If turned off, others won't see “typing…” while you write a message.")
        v.addWidget(card)
        info, i = self._card()
        i.addWidget(_label("🔒  Your messages are encrypted", "SettingsLabel"))
        i.addWidget(_label("Every message and file is encrypted with AES-256-GCM before it leaves this "
                           "computer, with a fresh session key agreed through RSA-2048 each time you "
                           "connect. Your password is never stored - only a salted PBKDF2 hash on the "
                           "server.", "SettingsHint", wrap=True))
        v.addWidget(info)
        v.addStretch()
        return page

    def _page_chats(self) -> QWidget:
        page, v = self._page("Chats")
        card, c = self._card()
        c.addWidget(_label("THEME", "SettingsLabel"))
        group = QButtonGroup(self)
        current = self.settings.get("theme")
        for value, text in (("light", "Light"), ("dark", "Dark"), ("system", "System default")):
            radio = QRadioButton(text)
            radio.setChecked(value == current)
            radio.setCursor(Qt.PointingHandCursor)
            radio.toggled.connect(lambda on, val=value: on and self._set_theme(val))
            group.addButton(radio)
            c.addWidget(radio)
        v.addWidget(card)

        wall, w = self._card()
        w.addWidget(_label("CHAT WALLPAPER", "SettingsLabel"))
        swatches = QHBoxLayout()
        swatches.setSpacing(10)
        self._swatch_group = QButtonGroup(self)
        self._swatches = {}
        for name, (light, dark) in palette.WALLPAPERS.items():
            swatch = QPushButton()
            swatch.setObjectName("WallpaperSwatch")
            swatch.setCheckable(True)
            swatch.setFixedSize(44, 44)
            swatch.setCursor(Qt.PointingHandCursor)
            swatch.setToolTip(name.title())
            swatch.setChecked(name == self.settings.get("wallpaper"))
            swatch.clicked.connect(lambda _=False, n=name: self._set_wallpaper(n))
            self._swatch_group.addButton(swatch)
            self._swatches[name] = swatch
            swatches.addWidget(swatch)
        swatches.addStretch()
        w.addLayout(swatches)
        self.doodles = QCheckBox("Show doodles on the wallpaper")
        self.doodles.setChecked(bool(self.settings.get("doodles")))
        self.doodles.toggled.connect(lambda _: self._set_wallpaper(self.settings.get("wallpaper")))
        w.addWidget(self.doodles)
        self._paint_swatches()
        v.addWidget(wall)
        v.addStretch()
        return page

    def _paint_swatches(self) -> None:
        for name, swatch in self._swatches.items():
            light, dark = palette.WALLPAPERS[name]
            swatch.setStyleSheet(f"background: {dark if palette.is_dark() else light};")

    def _set_theme(self, value: str) -> None:
        self.settings.set("theme", value)
        self.theme_changed.emit(value)
        self._paint_swatches()

    def _set_wallpaper(self, name: str) -> None:
        self.settings.set("wallpaper", name)
        self.settings.set("doodles", self.doodles.isChecked())
        self.wallpaper_changed.emit(name, self.doodles.isChecked())

    def _page_notifications(self) -> QWidget:
        page, v = self._page("Notifications")
        card, c = self._card()
        self._switch(c, "sound", "Sounds", "Play a sound when a message arrives.")
        c.addSpacing(6)
        self._switch(c, "popups", "Desktop notifications",
                     "Show a Windows notification when a message arrives while SecureChat is in the background.")
        c.addSpacing(6)
        self._switch(c, "previews", "Show message previews",
                     "Show the message text in notifications. Turn off if others can see your screen.")
        v.addWidget(card)
        v.addStretch()
        return page

    def _page_security(self) -> QWidget:
        page, v = self._page("Security")
        card, c = self._card()
        c.addWidget(_label("YOUR CONNECTION", "SettingsLabel"))
        rows = [("Encryption", "AES-256-GCM (confidentiality + integrity)"),
                ("Key exchange", "RSA-2048 with OAEP padding, then HKDF-SHA256"),
                ("Session key id", f"{self.client.key_fingerprint or '-'}   (the key itself is never shown)"),
                ("Server", f"{self.client.host}:{self.client.port}")]
        for name, value in rows:
            c.addWidget(self._info_row(name, value))
        c.addSpacing(4)
        c.addWidget(_label("Server key fingerprint (RSA-2048) - compare it with the server window:",
                           "SettingsHint", wrap=True))
        groups = (self.client.server_fingerprint or "").split(" ")
        fingerprint = QLabel("\n".join("   ".join(groups[i:i + 8]) for i in range(0, len(groups), 8)))
        fingerprint.setObjectName("Fingerprint")
        fingerprint.setTextInteractionFlags(Qt.TextSelectableByMouse)
        c.addWidget(fingerprint)
        v.addWidget(card)

        e2e_card, e = self._card()
        e.addWidget(_label("END-TO-END ENCRYPTION", "SettingsLabel"))
        self._switch(e, "e2e", "End-to-end encrypt my 1-to-1 messages",
                     "Messages are encrypted with a key that only you and the other person can compute "
                     "(ECDH P-256 + AES-256-GCM), on top of the connection encryption. The server only "
                     "relays ciphertext it cannot read. Group chats and files use connection encryption.")
        identity = getattr(self.client, "identity_fingerprint", None)
        e.addWidget(self._info_row("Your identity key", f"ECC P-256 · {identity}" if identity
                                   else "not set up in this session"))
        e.addWidget(_label("Only the public half of this key is sent to the server; the private key is kept "
                           "inside your password-encrypted history on this computer.", "SettingsHint", wrap=True))
        v.addWidget(e2e_card)

        store_card, s = self._card()
        s.addWidget(_label("CHAT HISTORY ON THIS COMPUTER", "SettingsLabel"))
        if self.history is not None:
            s.addWidget(self._info_row("Protection", "AES-256-GCM, key derived from your password with "
                                                     "PBKDF2-HMAC-SHA256 (200,000 rounds, random salt)"))
            s.addWidget(self._info_row("File", str(self.history.path)))
            s.addWidget(self._info_row("Contents", f"{self.history.count()} encrypted messages · "
                                                   f"{human_size(self.history.file_size())}"))
            s.addWidget(_label("Chats are indexed by an HMAC of the contact's name, so the file doesn't "
                               "even reveal who you talk to.", "SettingsHint", wrap=True))
            show = QPushButton("Show what's stored on disk")
            show.setObjectName("SecondaryButton")
            show.setCursor(Qt.PointingHandCursor)
            show.clicked.connect(self._toggle_dump)
            s.addWidget(show, 0, Qt.AlignLeft)
            self.dump = QPlainTextEdit()
            self.dump.setObjectName("RawDump")
            self.dump.setReadOnly(True)
            self.dump.setFixedHeight(170)
            self.dump.hide()
            s.addWidget(self.dump)
        else:
            s.addWidget(_label("History is not being saved in this session.", "SettingsHint"))
        clear = QPushButton("Clear chat history")
        clear.setObjectName("DangerButton")
        clear.setCursor(Qt.PointingHandCursor)
        clear.clicked.connect(self._confirm_clear)
        s.addSpacing(6)
        s.addWidget(clear, 0, Qt.AlignLeft)
        v.addWidget(store_card)
        v.addStretch()
        return page

    @staticmethod
    def _info_row(name: str, value: str) -> QWidget:
        row = QWidget()
        h = QHBoxLayout(row)
        h.setContentsMargins(0, 0, 0, 0)
        n = _label(name, "CryptoName")
        n.setFixedWidth(130)
        val = _label(value, "InfoText", wrap=True)
        val.setTextInteractionFlags(Qt.TextSelectableByMouse)
        h.addWidget(n, 0, Qt.AlignTop)
        h.addWidget(val, 1)
        return row

    def _toggle_dump(self) -> None:
        if self.dump.isVisible():
            self.dump.hide()
            return
        lines = ["What someone who copies the database file would see:", ""]
        for chat_key, ts, blob in self.history.raw_rows(6):
            lines.append(f"chat {chat_key[:12]}…  {time.strftime('%d %b %H:%M', time.localtime(ts))}  "
                         f"{blob[:22].hex()}… ({len(blob)} B)")
        if len(lines) == 2:
            lines.append("(no messages saved yet)")
        self.dump.setPlainText("\n".join(lines))
        self.dump.show()

    def _confirm_clear(self) -> None:
        answer = QMessageBox.question(self, "Clear chat history",
                                      "Delete every message stored on this computer?\n\n"
                                      "This can't be undone. Messages on other people's devices are not affected.")
        if answer == QMessageBox.Yes:
            self.clear_history_requested.emit()

    def _page_about(self) -> QWidget:
        page, v = self._page("About")
        card, c = self._card()
        logo = QLabel()
        logo.setPixmap(icons.svg_pixmap(icons.LOGO, 96))
        logo.setAlignment(Qt.AlignCenter)
        c.addWidget(logo)
        title = _label("SecureChat", "InfoTitle")
        title.setAlignment(Qt.AlignCenter)
        c.addWidget(title)
        subtitle = _label("Version 1.0 · Secure Chat Application using AES Encryption", "SettingsHint")
        subtitle.setAlignment(Qt.AlignCenter)
        c.addWidget(subtitle)
        c.addSpacing(10)
        for name, value in (("Language", "Python 3"), ("Networking", "TCP sockets, one thread per client"),
                            ("Cryptography", "PyCryptodome - AES-256-GCM, RSA-2048-OAEP, HKDF, PBKDF2"),
                            ("Interface", "PySide6 (Qt), styled after WhatsApp Desktop")):
            c.addWidget(self._info_row(name, value))
        v.addWidget(card)
        v.addStretch()
        return page
