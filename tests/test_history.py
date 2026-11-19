"""
Tests for Prompt 12: encrypted local history, lazy loading, search, settings, profile and dark mode.

Run with:  pytest tests/test_history.py -v
"""

import os
import sqlite3
import time
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QEventLoop, Qt, QTimer
from PySide6.QtWidgets import QApplication

from client.gui import palette
from client.gui.bridge import ClientBridge
from client.gui.chat_store import HISTORY_PAGE, ChatStore
from client.gui.main_window import MainWindow
from client.gui.settings import ClientSettings
from client.gui.theme import apply_theme, load_stylesheet
from client.gui.widgets.settings_dialog import SettingsDialog
from client.local_store import HistoryLocked, LocalStore
from client.network import ChatClient

PASSWORD = "Passw0rd!"


def unique(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:5]}"


# --------------------------------------------------------------- LocalStore ---
def test_history_file_contains_no_plaintext(tmp_path):
    store = LocalStore.open("alice", PASSWORD, tmp_path)
    store.save_messages([("bob_the_builder", "m1", time.time(), {"text": "exam answers are on page 42"})])
    store.save_chat("bob_the_builder", {"unread": 1, "title": "Bob The Builder"})
    store.close()
    raw = (tmp_path / "alice.db").read_bytes()
    assert b"exam answers" not in raw
    assert b"bob_the_builder" not in raw and b"Bob The Builder" not in raw   # even contacts are hidden
    assert PASSWORD.encode() not in raw


def test_wrong_password_is_refused(tmp_path):
    LocalStore.open("alice", PASSWORD, tmp_path).close()
    with pytest.raises(HistoryLocked):
        LocalStore.open("alice", "WrongPassword9", tmp_path)
    fresh = LocalStore.open("alice", "WrongPassword9", tmp_path, reset_if_locked=True)
    assert fresh.count() == 0
    assert any(p.name.startswith("alice.unreadable-") for p in tmp_path.iterdir())   # old file kept aside


def test_tampered_or_swapped_rows_are_skipped(tmp_path):
    store = LocalStore.open("alice", PASSWORD, tmp_path)
    now = time.time()
    store.save_messages([("bob", "m1", now, {"text": "one"}), ("bob", "m2", now + 1, {"text": "two"}),
                         ("bob", "m3", now + 2, {"text": "three"})])
    store.close()
    conn = sqlite3.connect(tmp_path / "alice.db")
    blob1 = conn.execute("SELECT blob FROM messages WHERE id = 'm1'").fetchone()[0]
    blob2 = bytearray(conn.execute("SELECT blob FROM messages WHERE id = 'm2'").fetchone()[0])
    blob2[20] ^= 1                                                       # flip one bit
    conn.execute("UPDATE messages SET blob = ? WHERE id = 'm2'", (bytes(blob2),))
    conn.execute("UPDATE messages SET blob = ? WHERE id = 'm3'", (blob1,))   # copy m1's ciphertext onto m3
    conn.commit()
    conn.close()
    store = LocalStore.open("alice", PASSWORD, tmp_path)
    assert [p["text"] for _, _, p in store.load("bob")] == ["one"]       # GCM + AAD reject both


def test_paging_and_clear(tmp_path):
    store = LocalStore.open("alice", PASSWORD, tmp_path)
    base = time.time() - 1000
    store.save_messages([("bob", f"m{i}", base + i, {"text": f"msg {i}"}) for i in range(120)])
    newest = store.load("bob", limit=50)
    assert [p["text"] for _, _, p in newest][0] == "msg 70" and len(newest) == 50
    older = store.load("bob", limit=50, before_ts=newest[0][1])
    assert [p["text"] for _, _, p in older][-1] == "msg 69"
    store.clear()
    assert store.count() == 0 and store.chats() == {}


# ------------------------------------------------- chat store + history ---
class FakeClient:
    username = "alice"
    users = {"bob": {"username": "bob", "display_name": "Bob"}}
    groups = {}

    def send_message(self, to, text, msg_id=None):
        return msg_id

    def send_read(self, *args, **kwargs):
        pass


@pytest.fixture(scope="module")
def app():
    application = QApplication.instance() or QApplication([])
    application.setStyleSheet(load_stylesheet("light"))
    return application


def test_lazy_loading_and_search_through_old_history(app, tmp_path):
    history = LocalStore.open("alice", PASSWORD, tmp_path)
    base = time.time() - 10_000
    history.save_messages([("bob", f"m{i}", base + i, {"sender": "bob", "text": f"note {i}"}) for i in range(130)])
    history.save_messages([("bob", "old", base - 5, {"sender": "bob", "text": "the wifi password is hunter2"})])
    history.save_chat("bob", {"unread": 3})

    store = ChatStore(FakeClient(), history=history)
    chat = store.get("bob")
    assert len(chat.messages) == HISTORY_PAGE and chat.unread == 3 and not chat.history_complete
    assert store.load_older("bob") == HISTORY_PAGE
    results = store.search("hunter2")                       # lives on the oldest page
    assert [m.id for m in results] == ["old"] and chat.history_complete
    assert len(chat.messages) == 131


def test_messages_survive_a_restart(app, tmp_path):
    history = LocalStore.open("alice", PASSWORD, tmp_path)
    store = ChatStore(FakeClient(), history=history)
    sent = store.send_text("bob", "see you at the lab")
    store.on_message({"id": "in1", "from": "bob", "text": "bring the slides", "sent_at": time.time()})
    store.set_status(sent.id, "read")
    store.flush()
    history.close()

    reopened = ChatStore(FakeClient(), history=LocalStore.open("alice", PASSWORD, tmp_path))
    messages = reopened.get("bob").messages
    assert [m.text for m in messages] == ["see you at the lab", "bring the slides"]
    assert messages[0].outgoing and messages[0].status == "read"
    assert reopened.get("bob").unread == 1


# ------------------------------------------------------------ live GUI ---
def pump(ms=50):
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


def wait_until(condition, timeout=6):
    deadline = time.time() + timeout
    while not condition() and time.time() < deadline:
        pump()
    return condition()


def gui_user(server, tmp_path, name, history=True):
    client = ChatClient("127.0.0.1", server.port, heartbeat_interval=0)
    bridge = ClientBridge(client)
    client.connect()
    client.register(name, PASSWORD, name.split("_")[0].title())
    client.user_list_received.wait(3)
    store = LocalStore.open(name, PASSWORD, tmp_path) if history else None
    window = MainWindow(client, bridge, history=store, settings=ClientSettings(None))
    bridge.release()
    window.show()
    return client, window


def test_in_chat_and_global_search(app, server, tmp_path):
    alice, wa = gui_user(server, tmp_path, unique("alice"))
    bob, _ = gui_user(server, tmp_path, unique("bob"), history=False)
    for text in ("first draft of the report", "lunch?", "final REPORT attached"):
        bob.send_message(alice.username, text)
    assert wait_until(lambda: wa.store.get(bob.username) and len(wa.store.get(bob.username).messages) == 3)

    wa.open_chat(bob.username)
    wa.chat_panel.open_search("report")
    assert wa.chat_panel.search_count.text() == "1 of 2"
    newest = wa.store.get(bob.username).messages[-1]
    assert wa.chat_panel.messages.row(newest.id).bubble.label.textFormat() == Qt.RichText   # highlighted
    wa.chat_panel._step_search(+1)
    assert wa.chat_panel.search_count.text() == "2 of 2"
    wa.chat_panel.close_search()
    assert wa.chat_panel.messages.row(newest.id).bubble.label.textFormat() == Qt.PlainText

    wa.sidebar.search.setText("lunch")
    wa.sidebar._run_global_search()
    assert wa.sidebar.results.count() == 1 and wa.sidebar.results.isVisible()
    wa.close()


def test_profile_update_reaches_contacts(app, server, tmp_path):
    alice, wa = gui_user(server, tmp_path, unique("alice"))
    bob, wb = gui_user(server, tmp_path, unique("bob"), history=False)
    assert wait_until(lambda: wb.store.get(alice.username) is not None)
    wa._save_profile("Alice in Wonderland", "Studying cryptography 🔐")
    assert wait_until(lambda: alice.profile.get("display_name") == "Alice in Wonderland")
    assert wait_until(lambda: wb.store.get(alice.username).title == "Alice in Wonderland")
    assert wb.store.get(alice.username).about == "Studying cryptography 🔐"
    wa.close()
    wb.close()


def test_settings_dialog_and_dark_mode(app, server, tmp_path):
    alice, wa = gui_user(server, tmp_path, unique("alice"))
    dialog = SettingsDialog(alice, wa.settings, wa.history, parent=wa)
    assert dialog.pages.count() == 6
    dialog._set_theme("dark")                                # what clicking "Dark" does
    wa._apply_theme()
    assert palette.is_dark() and "QLabel#BubbleText" in app.styleSheet()
    assert app.styleSheet().count("#0B141A") > 0             # dark colours are in the stylesheet
    dialog._set_theme("light")
    wa._apply_theme()
    assert not palette.is_dark()
    wa.settings.set("read_receipts", False)
    wa._apply_preferences()
    assert wa.store.send_read_receipts is False
    dialog.close()
    wa.close()
    apply_theme(app, "light")
