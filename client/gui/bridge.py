"""
Thread-safe bridge between ChatClient (network threads) and the Qt GUI.

ChatClient fires its events on its receiver thread, but Qt widgets may only be
touched from the GUI thread. Emitting a Qt signal from another thread is safe:
Qt queues it and runs the connected slots on the GUI thread.

Events that arrive before the main window exists (e.g. offline messages
delivered straight after login) are held in a backlog and replayed when the
window calls release(), so nothing is lost.
"""

import threading

from PySide6.QtCore import QObject, Signal

from client.network import ChatClient


class ClientBridge(QObject):
    message = Signal(dict)
    ack = Signal(dict)
    delivered = Signal(dict)
    read = Signal(dict)
    typing = Signal(dict)
    presence = Signal(dict)
    user_list = Signal(list)
    error = Signal(dict)
    security = Signal(str, str)
    disconnected = Signal(str)
    groups = Signal(list)
    group = Signal(dict)
    group_message = Signal(dict)
    file_incoming = Signal(dict)
    file_progress = Signal(str, int, int)
    file_done = Signal(dict)
    profile = Signal(dict)

    _HELD = ("message", "ack", "delivered", "read", "typing", "presence", "user_list", "error", "security",
             "groups", "group", "group_message", "file_incoming", "file_progress", "file_done", "profile")

    def __init__(self, client: ChatClient, parent=None):
        super().__init__(parent)
        self.client = client
        self._lock = threading.Lock()
        self._holding = True
        self._backlog = []
        for name in self._HELD:
            client.on(name, lambda *args, _n=name: self._forward(_n, args))
        client.on("disconnected", self.disconnected.emit)   # never held - the login screen needs it

    def _forward(self, name: str, args: tuple) -> None:
        with self._lock:
            if self._holding:
                self._backlog.append((name, args))
                return
        getattr(self, name).emit(*args)

    def release(self) -> None:
        """Start delivering events; replays everything that arrived before."""
        with self._lock:
            backlog, self._backlog, self._holding = self._backlog, [], False
        for name, args in backlog:
            getattr(self, name).emit(*args)
