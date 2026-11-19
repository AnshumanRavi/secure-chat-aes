"""
Automatic reconnection after the connection to the server drops.

Each attempt runs on a worker thread: connect -> secure handshake (the server must
present the same key as before) -> resume the session with the single-use token.
Failed attempts are retried with growing delays (1, 2, 4, 8, then every 15 s).

Some failures can't be fixed by retrying, so they stop the loop:
* the resume token was rejected (expired, or already used)  -> back to the login screen
* the server's key changed (possible man-in-the-middle)      -> back to the login screen
"""

from typing import Optional

from PySide6.QtCore import QObject, QTimer, Signal

from client.gui.workers import Task
from client.network import AuthFailed, ChatClient, ServerKeyChanged

RETRY_DELAYS = [1, 2, 4, 8, 15]


class Reconnector(QObject):
    connecting = Signal()               # an attempt has started
    waiting = Signal(int, str)          # seconds until the next attempt, short reason
    reconnected = Signal()
    gave_up = Signal(str)               # unrecoverable - show this message on the login screen

    def __init__(self, client: ChatClient, parent=None):
        super().__init__(parent)
        self.client = client
        self.attempts = 0
        self.active = False
        self._seconds_left = 0
        self._last_reason = ""
        self._task: Optional[Task] = None
        self._countdown = QTimer(self, interval=1000)
        self._countdown.timeout.connect(self._tick)

    def start(self) -> None:
        if self.active:
            return
        self.active = True
        self.attempts = 0
        self.try_now()

    def stop(self) -> None:
        self.active = False
        self._countdown.stop()

    def try_now(self) -> None:
        if not self.active or self._task is not None:   # stopped, or an attempt is already running
            return
        self._countdown.stop()
        self.connecting.emit()
        self._task = Task(self.client.reconnect, self)
        self._task.succeeded.connect(self._on_success)
        self._task.failed.connect(self._on_failure)
        self._task.finished.connect(self._task.deleteLater)
        self._task.start()

    def _on_success(self, _profile) -> None:
        self._task = None     # Qt deletes the finished worker; never touch it again
        if not self.active:
            return
        self.active = False
        self.reconnected.emit()

    def _on_failure(self, exc: Exception) -> None:
        self._task = None
        if not self.active:
            return
        if isinstance(exc, (AuthFailed, ServerKeyChanged)):
            self.active = False
            self.client.close()
            self.gave_up.emit(str(exc))
            return
        self._last_reason = "The server can't be reached" if "No SecureChat server" in str(exc) else ""
        self._seconds_left = RETRY_DELAYS[min(self.attempts, len(RETRY_DELAYS) - 1)]
        self.attempts += 1
        self.waiting.emit(self._seconds_left, self._last_reason)
        self._countdown.start()

    def _tick(self) -> None:
        self._seconds_left -= 1
        if self._seconds_left <= 0:
            self.try_now()
        else:
            self.waiting.emit(self._seconds_left, self._last_reason)
