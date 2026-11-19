"""
Desktop notifications, notification sound and the tray icon.

* When a message arrives and the window is NOT focused: a Windows notification
  (via the tray icon) with the sender's name and a preview, plus a short sound.
* When the window IS focused but the message is for another chat: just the sound.
* The tray icon and the window title show the total unread count, e.g. "(3) SecureChat".
* Clicking the notification opens that chat.

The sound is a short two-tone "ding" generated in code (no audio file to ship).
"""

import math
import struct
import wave
from pathlib import Path
from typing import Optional

from PySide6.QtCore import QObject, QRectF, Qt, QUrl, Signal
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPixmap
from PySide6.QtWidgets import QMenu, QSystemTrayIcon

from client.gui import icons
from client.gui.theme import ASSETS_DIR

SOUND_PATH = ASSETS_DIR / "notification.wav"
PREVIEW_LENGTH = 80


def ensure_notification_sound(path: Path = SOUND_PATH) -> Path:
    """Create a soft two-note chime (E6 -> A6, 0.28 s) as a 16-bit mono WAV if it doesn't exist."""
    if path.exists():
        return path
    rate = 44100
    samples = []
    for freq, start, length in ((1318.5, 0.0, 0.14), (1760.0, 0.10, 0.18)):
        for i in range(int(rate * length)):
            t = i / rate
            envelope = math.exp(-t * 18) * min(1.0, t * 400)     # quick attack, smooth decay
            index = int((start * rate)) + i
            while len(samples) <= index:
                samples.append(0.0)
            samples[index] += 0.35 * envelope * math.sin(2 * math.pi * freq * t)
    path.parent.mkdir(parents=True, exist_ok=True)
    with wave.open(str(path), "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(rate)
        wav.writeframes(b"".join(struct.pack("<h", int(max(-1, min(1, s)) * 32767)) for s in samples))
    return path


def badge_icon(count: int, size: int = 64) -> QIcon:
    """The app logo with a green unread-count badge (shown in the tray / taskbar)."""
    pixmap = QPixmap(icons.svg_pixmap(icons.LOGO, size))
    if count <= 0:
        return QIcon(pixmap)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    diameter = size * 0.55
    rect = QRectF(size - diameter, 0, diameter, diameter)
    painter.setPen(QColor("#FFFFFF"))
    painter.setBrush(QColor("#EA0038"))
    painter.drawEllipse(rect)
    font = QFont()
    font.setPixelSize(int(diameter * (0.62 if count < 10 else 0.48)))
    font.setBold(True)
    painter.setFont(font)
    painter.drawText(rect, Qt.AlignCenter, str(count) if count < 100 else "99+")
    painter.end()
    return QIcon(pixmap)


class NotificationManager(QObject):
    open_chat_requested = Signal(str)
    show_window_requested = Signal()
    quit_requested = Signal()

    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.title = title
        self.sound_enabled = True
        self.popups_enabled = True       # Settings > Notifications
        self.show_previews = True        # off = "New message" instead of the text
        self.unread = 0
        self.last_notification: Optional[tuple] = None   # (title, text) - handy for tests
        self._last_chat: Optional[str] = None

        self._sound = None
        try:
            from PySide6.QtMultimedia import QSoundEffect
            self._sound = QSoundEffect(self)
            self._sound.setSource(QUrl.fromLocalFile(str(ensure_notification_sound())))
            self._sound.setVolume(0.6)
        except Exception:   # no audio device / multimedia backend - notifications still work
            self._sound = None

        self.tray: Optional[QSystemTrayIcon] = None
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray = QSystemTrayIcon(badge_icon(0), self)
            self.tray.setToolTip(title)
            menu = QMenu()
            menu.addAction("Open SecureChat", self.show_window_requested)
            menu.addSeparator()
            menu.addAction("Quit", self.quit_requested)
            self._menu = menu
            self.tray.setContextMenu(menu)
            self.tray.activated.connect(self._on_activated)
            self.tray.messageClicked.connect(self._on_message_clicked)
            self.tray.show()

    def notify(self, chat_id: str, sender: str, text: str, popup: bool) -> None:
        """popup=True shows a Windows notification; the sound plays either way."""
        preview = " ".join(text.split()) if self.show_previews else "New message"
        if len(preview) > PREVIEW_LENGTH:
            preview = preview[:PREVIEW_LENGTH - 1] + "…"
        self.last_notification = (sender, preview)
        self._last_chat = chat_id
        if popup and self.popups_enabled and self.tray and self.tray.supportsMessages():
            self.tray.showMessage(sender, preview, badge_icon(0), 5000)
        self.play_sound()

    def play_sound(self) -> None:
        if self.sound_enabled and self._sound is not None:
            self._sound.play()

    def set_unread(self, count: int) -> None:
        self.unread = count
        if self.tray:
            self.tray.setIcon(badge_icon(count))
            self.tray.setToolTip(f"{self.title} – {count} unread" if count else self.title)

    def hide(self) -> None:
        if self.tray:
            self.tray.hide()

    def _on_activated(self, reason) -> None:
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self.show_window_requested.emit()

    def _on_message_clicked(self) -> None:
        if self._last_chat:
            self.open_chat_requested.emit(self._last_chat)
