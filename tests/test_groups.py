"""
Tests for encrypted group chats (Prompt 10): server routing, receipts, leaving, and the GUI.

Run with:  pytest tests/test_groups.py -v
"""

import os
import time
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtWidgets import QApplication

from client.gui.bridge import ClientBridge
from client.gui.chat_store import ChatStore, group_chat_id
from client.gui.main_window import MainWindow
from client.gui.theme import load_stylesheet
from client.gui.widgets.new_group_dialog import NewGroupDialog
from client.network import ChatClient
from tests.test_integration import EventRecorder

PASSWORD = "Passw0rd!"


def unique(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:5]}"


def user(server, name=None):
    client = ChatClient("127.0.0.1", server.port, heartbeat_interval=0)
    events = EventRecorder(client)
    client.connect()
    client.register(name or unique("user"), PASSWORD)
    client.user_list_received.wait(3)
    return client, events


def make_group(creator, creator_events, members, name="Crypto Team"):
    request_id = creator.create_group(name, [m.username for m in members], "Project group", "#7F66FF")
    created = creator_events.wait("group", lambda m: m.get("request_id") == request_id)
    return created["group"]


# ------------------------------------------------------------------ server ---
def test_create_group_notifies_every_member(server):
    (alice, ae), (bob, be), (carol, ce) = user(server), user(server), user(server)
    group = make_group(alice, ae, [bob, carol])

    assert group["name"] == "Crypto Team" and group["avatar_color"] == "#7F66FF"
    roles = {m["username"]: m["role"] for m in group["members"]}
    assert roles == {alice.username: "admin", bob.username: "member", carol.username: "member"}
    for events in (be, ce):
        event = events.wait("group")
        assert event["type"] == "CREATE_GROUP" and event["actor"] == alice.username
    for c in (alice, bob, carol):
        c.logout()


def test_group_message_fans_out_with_receipts(server):
    (alice, ae), (bob, be), (carol, ce) = user(server), user(server), user(server)
    group = make_group(alice, ae, [bob, carol])

    msg_id = alice.send_group_message(group["group_id"], "Hello team 👋")
    assert ae.wait("ack")["id"] == msg_id
    for events, member in ((be, bob), (ce, carol)):
        received = events.wait("group_message")
        assert received["from"] == alice.username and received["text"] == "Hello team 👋"
        assert received["group_id"] == group["group_id"]
    delivered_by = {ae.wait("delivered")["by"], ae.wait("delivered")["by"]}
    assert delivered_by == {bob.username, carol.username}

    bob.send_read(alice.username, [msg_id], group_id=group["group_id"])
    read = ae.wait("read")
    assert read["by"] == bob.username and read["group_id"] == group["group_id"]
    for c in (alice, bob, carol):
        c.logout()


def test_outsiders_cannot_post(server):
    (alice, ae), (bob, _), (eve, ee) = user(server), user(server), user(server)
    group = make_group(alice, ae, [bob])
    eve.send_group_message(group["group_id"], "let me in")
    assert ee.wait("error")["code"] == "NOT_A_MEMBER"
    for c in (alice, bob, eve):
        c.logout()


def test_offline_member_gets_group_and_messages_later(server):
    (alice, ae), (bob, _) = user(server), user(server)
    bob_name = bob.username
    bob.logout()
    group = make_group(alice, ae, [bob])
    msg_id = alice.send_group_message(group["group_id"], "you were offline")
    ae.wait("ack")

    bob = ChatClient("127.0.0.1", server.port, heartbeat_interval=0)
    be = EventRecorder(bob)
    bob.connect()
    bob.login(bob_name, PASSWORD)
    assert be.wait("group")["group"]["group_id"] == group["group_id"]
    assert be.wait("group_message")["id"] == msg_id
    assert ae.wait("delivered", lambda m: m["id"] == msg_id)["by"] == bob_name
    assert group["group_id"] in bob.groups            # also in the USER_LIST after login
    alice.logout(), bob.logout()


def test_leaving_notifies_members_and_promotes_admin(server):
    (alice, ae), (bob, be), (carol, ce) = user(server), user(server), user(server)
    group = make_group(alice, ae, [bob, carol])
    alice.leave_group(group["group_id"])               # the admin leaves

    for events in (ae, be, ce):
        update = events.wait("group", lambda m: m["type"] == "GROUP_UPDATE")
        assert update["event"] == "left" and update["actor"] == alice.username
    assert update["new_admin"] in (bob.username, carol.username)
    assert alice.username not in [m["username"] for m in update["group"]["members"]]

    alice.send_group_message(group["group_id"], "can I still post?")
    assert ae.wait("error")["code"] == "NOT_A_MEMBER"
    for c in (alice, bob, carol):
        c.logout()


@pytest.mark.parametrize("name,members,code", [
    ("", ["x"], "BAD_GROUP"), ("A" * 41, ["x"], "BAD_GROUP"), ("Team", [], "BAD_GROUP"),
    ("Team", ["nobody_here"], "UNKNOWN_USER"),
])
def test_group_validation(server, name, members, code):
    alice, ae = user(server)
    alice.create_group(name, members or [], "", "#00A884")
    assert ae.wait("error")["code"] == code
    alice.logout()


# ------------------------------------------------- group receipt aggregation ---
class FakeClient:
    username = "alice"
    users, groups = {}, {}

    def send_group_message(self, group_id, text, msg_id=None):
        return msg_id

    def send_message(self, to, text, msg_id=None):
        return msg_id


@pytest.fixture(scope="module")
def app():
    application = QApplication.instance() or QApplication([])
    application.setStyleSheet(load_stylesheet("light"))
    return application


def test_blue_ticks_only_when_everyone_read(app):
    store = ChatStore(FakeClient())
    group = {"group_id": "g1", "name": "Team", "members": [
        {"username": "alice", "role": "admin"}, {"username": "bob", "role": "member"},
        {"username": "carol", "role": "member"}]}
    store.on_groups([group])
    msg = store.send_text(group_chat_id("g1"), "hi all")
    store.set_status(msg.id, "sent")
    assert msg.recipients == ["bob", "carol"]

    store.on_delivered({"id": msg.id, "by": "bob", "group_id": "g1"})
    assert msg.status == "sent"                                   # carol doesn't have it yet
    store.on_delivered({"id": msg.id, "by": "carol", "group_id": "g1"})
    assert msg.status == "delivered"
    store.on_read({"ids": [msg.id], "by": "bob", "group_id": "g1"})
    assert msg.status == "delivered"                              # carol hasn't read it
    # carol leaves without reading -> everyone still in the group has read it
    store.on_group_event({"type": "GROUP_UPDATE", "event": "left", "actor": "carol",
                          "group": dict(group, members=group["members"][:2])})
    assert msg.status == "read"
    assert [m.text for m in store.get(group_chat_id("g1")).messages if m.system] == ["carol left"]


# ------------------------------------------------------------------ GUI ---
def pump(ms=50):
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


def wait_until(condition, timeout=6):
    deadline = time.time() + timeout
    while not condition() and time.time() < deadline:
        pump()
    return condition()


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


def test_new_group_dialog_values(app):
    dialog = NewGroupDialog([{"username": "bob", "display_name": "Bob"},
                             {"username": "carol", "display_name": "Carol"}])
    assert not dialog.create_button.isEnabled()
    dialog.name.setText("Crypto Team")
    dialog._toggle(dialog.members.item(0))
    dialog._pick_colour("#7F66FF")
    assert dialog.create_button.isEnabled()
    assert dialog.values() == {"name": "Crypto Team", "description": "", "avatar_color": "#7F66FF",
                               "members": ["bob"]}


def test_group_chat_in_two_windows(app, server):
    alice, wa = gui_user(server, unique("alice"))
    bob, wb = gui_user(server, unique("bob"))
    assert wait_until(lambda: wa.store.get(bob.username) is not None)

    # Alice creates the group -> it opens for her and appears for Bob
    wa._pending_group_request = wa.store.create_group("Crypto Team", [bob.username], "Demo", "#7F66FF")
    assert wait_until(lambda: wa.store.active_chat and wa.store.active_chat.startswith("g:"))
    chat_id = wa.store.active_chat
    assert wait_until(lambda: wb.store.get(chat_id) is not None)
    bob_chat = wb.store.get(chat_id)
    assert [m.text for m in bob_chat.messages if m.system][-1] == "Alice added you"
    assert "Alice" in wa.chat_panel.status.text() or "Bob" in wa.chat_panel.status.text()

    # Chat in it
    wa.chat_panel.input_bar.set_text("Welcome to the group!")
    wa.chat_panel.input_bar._send()
    sent = wa.store.get(chat_id).messages[-1]
    assert wait_until(lambda: any(m.id == sent.id for m in bob_chat.messages))
    wb.open_chat(chat_id)
    row = wb.chat_panel.messages.row(sent.id)
    assert row.bubble.name_label is not None and row.bubble.name_label.text() == "Alice"
    wb.store.mark_read(chat_id)
    assert wait_until(lambda: sent.status == "read")         # the only other member read it

    # Group info panel + leaving
    wa._show_info()
    assert wa.chat_panel.group_info.isVisible()
    assert wb.store.leave_group(chat_id)
    assert wait_until(lambda: wb.store.get(chat_id).left)
    assert not wb.chat_panel.input_bar.isVisible() and wb.chat_panel.left_notice.isVisible()
    assert wait_until(lambda: any(m.system and m.text == "Bob left" for m in wa.store.get(chat_id).messages))
    wa.close()
    wb.close()
