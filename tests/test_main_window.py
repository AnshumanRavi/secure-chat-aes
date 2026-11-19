"""
Tests for the chat store, the chat list sorting/filtering, and the main window with a real server.

Run with:  pytest tests/test_main_window.py -v
"""

import os
import time
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtWidgets import QApplication

from client.gui.bridge import ClientBridge
from client.gui.chat_store import ChatStore
from client.gui.main_window import MainWindow
from client.gui.theme import load_stylesheet
from client.gui.widgets.chat_list import ChatFilterProxy, ChatIdRole, ChatListModel
from client.network import ChatClient, ClientError

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


def wait_until(condition, timeout=5):
    deadline = time.time() + timeout
    while not condition() and time.time() < deadline:
        pump()
    return condition()


class FakeClient:
    def __init__(self, users, fail=False):
        self.username = "alice"
        self.users = {u["username"]: u for u in users}
        self.sent = []
        self.fail = fail

    def send_message(self, to, text, msg_id=None):
        if self.fail:
            raise ClientError("Not connected")
        self.sent.append((to, text))
        return msg_id or f"m{len(self.sent)}"


USERS = [
    {"username": "alice", "display_name": "Alice", "online": True},
    {"username": "bob", "display_name": "Bob", "online": True, "about": "Hi!"},
    {"username": "carol", "display_name": "Carol", "online": False, "last_seen": 1000.0},
    {"username": "dev", "display_name": "Dev", "online": False},
]


@pytest.fixture
def store(app):
    return ChatStore(FakeClient(USERS))


def incoming(sender, msg_id, text="hello", ts=None):
    return {"type": "CHAT_MSG", "id": msg_id, "from": sender, "to": "alice", "text": text,
            "sent_at": ts or time.time()}


def ordered_ids(proxy):
    return [proxy.index(r, 0).data(ChatIdRole) for r in range(proxy.rowCount())]


# ------------------------------------------------------------- chat store ---
def test_user_list_creates_conversations_except_me(store):
    assert sorted(c.chat_id for c in store.conversations()) == ["bob", "carol", "dev"]
    assert store.get("bob").about == "Hi!" and store.get("carol").last_seen == 1000.0


def test_presence_updates_and_adds_new_users(store):
    store.on_presence({"username": "carol", "online": True})
    assert store.get("carol").online
    store.on_presence({"username": "carol", "online": False, "last_seen": 2000.0})
    assert not store.get("carol").online and store.get("carol").last_seen == 2000.0
    store.on_presence({"username": "erin", "online": True, "user": {"username": "erin", "display_name": "Erin"}})
    assert store.get("erin").title == "Erin"


def test_incoming_message_counts_unread_unless_chat_is_open(store):
    received = []
    store.message_received.connect(lambda chat_id, msg: received.append(chat_id))
    store.on_typing({"from": "bob", "typing": True})
    store.on_message(incoming("bob", "1"))
    store.on_message(incoming("bob", "2"))
    store.on_message(incoming("bob", "2"))              # duplicate id ignored
    assert store.get("bob").unread == 2 and len(store.get("bob").messages) == 2
    assert store.get("bob").typing is False              # a message ends "typing…"
    assert received == ["bob", "bob"]

    store.open_chat("bob")
    assert store.get("bob").unread == 0
    store.on_message(incoming("bob", "3"))
    assert store.get("bob").unread == 0                  # chat is open -> read immediately


def test_outgoing_status_only_moves_forward(store):
    msg = store.send_text("bob", "  hi bob  ")
    assert msg.text == "hi bob" and msg.status == "pending" and store.client.sent == [("bob", "hi bob")]
    store.set_status(msg.id, "sent")
    store.set_status(msg.id, "read")
    store.set_status(msg.id, "delivered")               # late DELIVERED must not undo READ
    assert msg.status == "read"
    assert store.send_text("bob", "   ") is None


def test_offline_messages_stay_pending_and_are_resent(app):
    client = FakeClient(USERS, fail=True)            # the connection is down
    store = ChatStore(client)
    first = store.send_text("bob", "hello")
    second = store.send_text("carol", "are you there?")
    assert first.status == second.status == "pending" and client.sent == []
    assert len(store.pending_messages()) == 2

    client.fail = False                               # reconnected
    assert store.resend_pending() == 2
    assert client.sent == [("bob", "hello"), ("carol", "are you there?")]   # oldest first


def test_typing_indicator_expires(app, store):
    store.on_typing({"from": "bob", "typing": True})
    assert store.get("bob").typing
    store.expire_typing(now=time.monotonic() + 1)     # still within the timeout
    assert store.get("bob").typing
    store.expire_typing(now=time.monotonic() + 10)    # "stopped typing" never arrived
    assert not store.get("bob").typing


# ------------------------------------------------- chat list sort/filter ---
def test_chat_list_sorting_and_filters(store):
    proxy = ChatFilterProxy()
    proxy.setSourceModel(ChatListModel(store))
    proxy.sort(0)
    # no messages yet: online first, then A-Z
    assert ordered_ids(proxy) == ["bob", "carol", "dev"]

    store.on_message(incoming("dev", "d1", "meeting at 5", ts=time.time()))
    store.on_message(incoming("carol", "c1", "notes attached", ts=time.time() - 60))
    assert ordered_ids(proxy) == ["dev", "carol", "bob"]  # newest message first

    proxy.set_chip("unread")
    assert ordered_ids(proxy) == ["dev", "carol"]
    proxy.set_chip("all")
    proxy.set_text("meeting")                              # matches message text
    assert ordered_ids(proxy) == ["dev"]
    proxy.set_text("CAR")                                  # matches name, case-insensitive
    assert ordered_ids(proxy) == ["carol"]
    proxy.set_chip("groups")
    proxy.set_text("")
    assert ordered_ids(proxy) == []


# ------------------------------------------------------- live main window ---
def make_user(server, name, display, bridge=False):
    client = ChatClient("127.0.0.1", server.port, heartbeat_interval=0)
    b = ClientBridge(client) if bridge else None
    client.connect()
    client.register(name, PASSWORD, display)
    client.user_list_received.wait(3)
    return client, b


def test_main_window_shows_online_users_and_new_messages(app, server):
    suffix = uuid.uuid4().hex[:5]
    alice, bridge = make_user(server, f"alice_{suffix}", "Alice", bridge=True)
    bob, _ = make_user(server, f"bob_{suffix}", "Bob")
    window = MainWindow(alice, bridge)
    bridge.release()
    window.show()
    sidebar = window.sidebar

    # Bob appears in the chat list with the online dot
    assert wait_until(lambda: window.store.get(bob.username) and window.store.get(bob.username).online)
    assert bob.username in ordered_ids(sidebar.proxy)

    # A message from Bob: unread badge, top of the list
    bob.send_message(alice.username, "Hi Alice!")
    assert wait_until(lambda: window.store.get(bob.username).unread == 1)
    assert ordered_ids(sidebar.proxy)[0] == bob.username

    # Opening the chat clears the badge and shows "online" in the header
    window.open_chat(bob.username)
    assert window.store.get(bob.username).unread == 0
    assert window.right.currentWidget() is window.chat_panel
    assert window.chat_panel.status.text() == "online"

    # Bob goes offline -> header switches to "last seen today at ..."
    bob.logout()
    assert wait_until(lambda: window.chat_panel.status.text().startswith("last seen today"))

    window.open_chat(None)
    assert window.right.currentWidget() is window.intro
    window.close()
