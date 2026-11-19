"""
Tests for Prompt 9: resume tokens, automatic reconnect, typing indicator and notifications.

Run with:  pytest tests/test_presence.py -v
"""

import os
import time
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtWidgets import QApplication

from common.config import Config
from client.gui.bridge import ClientBridge
from client.gui.main_window import MainWindow
from client.gui.notifications import badge_icon
from client.gui.theme import load_stylesheet
from client.gui.typing import TypingNotifier
from client.network import AuthFailed, ChatClient, ServerKeyChanged
from server.auth import AuthError, AuthManager
from server.database import Database
from server.security_log import SecurityLog
from server.server import ChatServer

PASSWORD = "Passw0rd!"


@pytest.fixture(scope="module")
def app():
    application = QApplication.instance() or QApplication([])
    application.setStyleSheet(load_stylesheet("light"))
    return application


def pump(ms=50):
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


def wait_until(condition, timeout=8):
    deadline = time.time() + timeout
    while not condition() and time.time() < deadline:
        pump()
    return condition()


def unique(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:5]}"


def new_client(port, name=None, register=True):
    client = ChatClient("127.0.0.1", port, heartbeat_interval=0)
    client.connect()
    if register:
        client.register(name or unique("user"), PASSWORD)
        client.user_list_received.wait(3)
    return client


# ------------------------------------------------------------ resume tokens ---
def test_resume_token_is_single_use_and_bound_to_user():
    auth = AuthManager(Database(":memory:"))
    auth.register("alice", "secret123")
    auth.register("bob", "secret123")

    token, token_hash = auth.issue_resume_token("alice")
    stored = [tuple(row) for row in auth.db._conn.execute("SELECT * FROM sessions")]
    assert token_hash in str(stored) and token not in str(stored)   # only the hash is stored
    assert auth.resume("alice", token)["username"] == "alice"
    with pytest.raises(AuthError):
        auth.resume("alice", token)                       # second use is rejected

    token2, _ = auth.issue_resume_token("alice")
    with pytest.raises(AuthError):
        auth.resume("bob", token2)                        # can't be used for another account


def test_expired_and_revoked_tokens_rejected():
    auth = AuthManager(Database(":memory:"))
    auth.register("alice", "secret123")
    token, token_hash = auth.issue_resume_token("alice")
    auth.revoke(token_hash)
    with pytest.raises(AuthError):
        auth.resume("alice", token)

    token = "expired-token"
    auth.db.store_session(auth._token_hash(token), "alice", time.time() + 0.01)
    time.sleep(0.05)
    with pytest.raises(AuthError):
        auth.resume("alice", token)


def test_client_reconnects_with_token_after_drop(server):
    client = new_client(server.port)
    first_token = client.resume_token
    assert first_token

    client.channel.close()                                 # the connection drops
    profile = client.reconnect()
    assert profile["username"] == client.username
    assert client.resume_token and client.resume_token != first_token   # token was rotated

    # the old token can't be replayed by someone who stole it
    thief = new_client(server.port, register=False)
    thief.username, thief.resume_token = client.username, first_token
    with pytest.raises(AuthFailed, match="expired"):
        thief.resume()
    thief.close()
    client.logout()


def test_logout_revokes_the_token(server):
    client = new_client(server.port)
    token, username = client.resume_token, client.username
    client.logout()
    other = new_client(server.port, register=False)
    other.username, other.resume_token = username, token
    with pytest.raises(AuthFailed):
        other.resume()
    other.close()


def test_reconnect_survives_server_restart_but_not_a_new_server_key(tmp_path):
    def start(keys_dir):
        srv = ChatServer(Config(server_host="127.0.0.1", port=port), keys_dir=keys_dir,
                         db_path=tmp_path / "server.db", log=SecurityLog(tmp_path / "logs", console=False),
                         passphrase="test-passphrase")
        srv.start_in_background()
        return srv

    port = 0
    srv = start(tmp_path / "keys")
    port = srv.port
    client = new_client(port)
    srv.stop()                                             # server goes down...
    srv = start(tmp_path / "keys")                         # ...and comes back (same keys + database)
    assert client.reconnect()["username"] == client.username
    srv.stop()

    impostor = start(tmp_path / "other-keys")              # same address, DIFFERENT key
    with pytest.raises(ServerKeyChanged):
        client.reconnect()
    impostor.stop()


# --------------------------------------------------------- typing indicator ---
class RecordingClient:
    def __init__(self):
        self.calls = []

    def send_typing(self, to, typing):
        self.calls.append((to, typing))


def test_typing_notifier_throttles(app):
    client = RecordingClient()
    notifier = TypingNotifier(client)
    typed = "hello there"
    for i in range(1, len(typed) + 1):
        notifier.text_edited("bob", typed[:i])             # 11 keystrokes...
    assert client.calls == [("bob", True)]                 # ...one TYPING packet
    notifier.text_edited("bob", "")                        # box cleared
    assert client.calls[-1] == ("bob", False)
    notifier.text_edited("bob", "a")
    notifier.text_edited("carol", "b")                     # switching chats stops the old one
    assert client.calls[-3:] == [("bob", True), ("bob", False), ("carol", True)]


def gui_user(server, name):
    client = ChatClient("127.0.0.1", server.port, heartbeat_interval=0)
    bridge = ClientBridge(client)
    client.connect()
    client.register(name, PASSWORD, name.split("_")[0].title())
    client.user_list_received.wait(3)
    window = MainWindow(client, bridge)
    bridge.release()
    window.show()
    return client, window


def test_typing_shows_on_the_other_side(app, server):
    alice, wa = gui_user(server, unique("alice"))
    bob, wb = gui_user(server, unique("bob"))
    assert wait_until(lambda: wa.store.get(bob.username) is not None)
    wa.open_chat(bob.username)
    wb.open_chat(alice.username)

    wa.chat_panel.input_bar.set_text("I'm typing")         # emits text_edited -> TYPING(true)
    assert wait_until(lambda: wb.store.get(alice.username).typing)
    assert wb.chat_panel.status.text() == "typing…"

    wa.chat_panel.input_bar.set_text("")                   # cleared -> TYPING(false)
    assert wait_until(lambda: not wb.store.get(alice.username).typing)
    wa.close()
    wb.close()


# ------------------------------------------------------- notifications ---
def test_notification_and_unread_title(app, server):
    alice, wa = gui_user(server, unique("alice"))
    bob, wb = gui_user(server, unique("bob"))              # Bob's window is in front
    assert wait_until(lambda: wa.store.get(bob.username) is not None)

    wb.store.send_text(alice.username, "Are you coming to the lab?")
    assert wait_until(lambda: wa.notifier.last_notification is not None)
    assert wa.notifier.last_notification == ("Bob", "Are you coming to the lab?")
    assert wa.windowTitle().startswith("(1) ")
    assert wa.notifier.unread == 1
    assert not badge_icon(3).isNull()

    wa.open_chat(bob.username)                             # reading clears the count
    assert wait_until(lambda: not wa.windowTitle().startswith("("))
    wa.close()
    wb.close()


# ------------------------------------------------------ GUI auto-reconnect ---
def test_gui_reconnects_and_resends_pending_messages(app, server):
    alice, wa = gui_user(server, unique("alice"))
    bob, wb = gui_user(server, unique("bob"))
    assert wait_until(lambda: wa.store.get(bob.username) is not None)
    wa.open_chat(bob.username)

    alice.channel.close()                                  # Alice's connection drops
    queued = wa.store.send_text(bob.username, "sent while offline")
    assert queued.status == "pending"

    assert wait_until(lambda: wa.reconnector.attempts >= 0 and alice.connected and
                      not wa.sidebar.banner.isVisible(), timeout=10)
    assert wait_until(lambda: queued.status in ("sent", "delivered", "read"))
    assert wait_until(lambda: any(m.id == queued.id for m in wb.store.get(alice.username).messages))
    received = [m for m in wb.store.get(alice.username).messages if m.id == queued.id]
    assert len(received) == 1 and received[0].text == "sent while offline"
    wa.close()
    wb.close()


def test_banner_appears_while_server_is_down(app, tmp_path):
    srv = ChatServer(Config(server_host="127.0.0.1", port=0), keys_dir=tmp_path / "keys",
                     db_path=tmp_path / "db", log=SecurityLog(tmp_path / "logs", console=False),
                     passphrase="test-passphrase")
    srv.start_in_background()
    client, window = gui_user(srv, unique("alice"))
    srv.stop()                                             # server gone
    assert wait_until(lambda: window.sidebar.banner.isVisible())
    assert wait_until(lambda: window.sidebar.banner.title.text() == "Not connected to the server", timeout=10)
    window.close()
