"""
Sends the "typing…" signal without flooding the network.

* The first keystroke sends TYPING(true).
* While you keep typing, TYPING(true) is repeated at most every 2.5 s (a throttle),
  so the other side knows you're still typing.
* 3 s without a keystroke, sending the message, clearing the box or switching
  chats sends TYPING(false).
"""

import time
from typing import Optional

from PySide6.QtCore import QObject, QTimer

from client.network import ClientError

THROTTLE_SECONDS = 2.5
IDLE_MS = 3000


class TypingNotifier(QObject):
    def __init__(self, client, parent=None):
        super().__init__(parent)
        self.client = client
        self.enabled = True              # Settings > Privacy > Typing indicator
        self._chat: Optional[str] = None
        self._active = False
        self._last_sent = 0.0
        self._idle = QTimer(self, singleShot=True, interval=IDLE_MS)
        self._idle.timeout.connect(self.stop)

    def text_edited(self, chat_id: Optional[str], text: str) -> None:
        if not self.enabled or not chat_id or not text.strip():
            self.stop()
            return
        if chat_id != self._chat:
            self.stop()
            self._chat = chat_id
        now = time.monotonic()
        if not self._active or now - self._last_sent >= THROTTLE_SECONDS:
            self._send(True)
            self._active = True
            self._last_sent = now
        self._idle.start()   # restart the 3-second idle countdown

    def stop(self) -> None:
        self._idle.stop()
        if self._active and self._chat:
            self._send(False)
        self._active = False

    def _send(self, typing: bool) -> None:
        try:
            self.client.send_typing(self._chat, typing)
        except ClientError:
            pass   # offline - nothing to tell
