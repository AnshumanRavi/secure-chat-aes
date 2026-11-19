"""
Tests for the conversation view: bubbles, grouping, date chips, input bar, scrolling,
and real-time chatting between two GUI windows with ticks.

Run with:  pytest tests/test_chat_view.py -v
"""

import os
import time
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QEventLoop, Qt, QTimer
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import QApplication

from client.gui.bridge import ClientBridge
from client.gui.chat_store import Message
from client.gui.main_window import MainWindow
from client.gui.theme import load_stylesheet
from client.gui.widgets.bubble import Bubble, is_jumbo, measure_text
from client.gui.widgets.input_bar import InputBar
from client.gui.widgets.message_info import MessageInfoDialog
from client.gui.widgets.message_view import MessageView
from client.network import ChatClient

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


def msg(msg_id, sender="bob", text="hello", ts=None, outgoing=False, status="received"):
    return Message(id=msg_id, chat_id="bob", sender=sender, text=text, ts=ts or time.time(),
                   outgoing=outgoing, status=status)


# ------------------------------------------------------------------ bubbles ---
def test_time_shares_last_line_when_there_is_room(app):
    bubble = Bubble(msg("1", text="Hi"), tail=True)
    bubble.set_max_width(400)
    label, meta = bubble.label.geometry(), bubble.meta.geometry()
    assert meta.left() > label.left() + 10                  # time sits to the right of the text
    assert abs(meta.bottom() - label.bottom()) < 8          # ...on the same line


def test_time_moves_to_new_line_when_last_line_is_full(app):
    text = "word " * 40
    bubble = Bubble(msg("1", text=text), tail=False)
    bubble.set_max_width(300)
    _, height, last_line = measure_text(text, bubble.label.font(), 300)
    assert bubble.width() <= 300
    assert bubble.meta.geometry().top() >= bubble.label.geometry().bottom() - 4 or \
        last_line + 10 + bubble.meta.width() <= 300 - 25


def test_jumbo_emoji_detection():
    assert is_jumbo("😂") and is_jumbo("🎉🔥") and not is_jumbo("hi 😂") and not is_jumbo("😀" * 4)


def test_grouping_and_date_chips(app):
    view = MessageView()
    view.resize(800, 600)
    yesterday = time.time() - 86400
    view.set_messages([
        msg("1", ts=yesterday), msg("2", ts=yesterday + 5),          # bob, bob  (yesterday)
        msg("3", sender="alice", outgoing=True, status="sent"),       # alice      (today)
        msg("4", sender="alice", outgoing=True, status="sent"),
        msg("5"),                                                     # bob
    ])
    tails = [view.row(i).bubble.tail for i in "12345"]
    assert tails == [True, False, True, False, True]                 # tail only on the first of a group
    chips = [w.label.text() for w in view._widgets if hasattr(w, "label") and not hasattr(w, "bubble")]
    assert chips == ["YESTERDAY", "TODAY"]


def test_new_messages_while_scrolled_up_show_counter(app):
    view = MessageView()
    view.resize(600, 300)
    view.show()
    view.set_messages([msg(str(i), text=f"message {i}") for i in range(30)])
    pump(100)
    view.verticalScrollBar().setValue(0)                              # read old messages
    pump(50)
    view.add_message(msg("new1"))
    view.add_message(msg("new2"))
    pump(50)
    assert view.down_button.isVisible() and view.down_button.badge.text() == "2"
    view.scroll_to_bottom()
    pump(50)
    assert not view.down_button.isVisible()
    view.close()


# ---------------------------------------------------------------- input bar ---
def test_enter_sends_and_shift_enter_adds_line(app):
    bar = InputBar()
    sent = []
    bar.send_requested.connect(sent.append)
    bar.set_text("line 1")
    bar.input.keyPressEvent(QKeyEvent(QKeyEvent.KeyPress, Qt.Key_Return, Qt.ShiftModifier))
    bar.input.insertPlainText("line 2")
    assert bar.text() == "line 1\nline 2" and sent == []
    bar.input.keyPressEvent(QKeyEvent(QKeyEvent.KeyPress, Qt.Key_Return, Qt.NoModifier))
    assert sent == ["line 1\nline 2"] and bar.text() == ""


def test_mic_turns_into_send_button(app):
    bar = InputBar()
    mic = []
    bar.mic_clicked.connect(lambda: mic.append(True))
    bar.action_button.click()
    assert mic == [True] and bar.action_button.toolTip() == "Voice message"
    bar.set_text("hi")
    assert bar.action_button.toolTip() == "Send"


def test_emoji_picker_inserts_and_remembers_recent(app):
    bar = InputBar()
    bar.set_text("Nice ")
    bar.emoji_picker._pick("🎉")
    assert bar.text() == "Nice 🎉"
    assert bar.emoji_picker.recent[0] == "🎉"


# ------------------------------------------------ two live GUI windows ---
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


def test_real_time_chat_with_ticks(app, server):
    suffix = uuid.uuid4().hex[:5]
    alice, wa = gui_user(server, f"alice_{suffix}")
    bob, wb = gui_user(server, f"bob_{suffix}")
    assert wait_until(lambda: wa.store.get(bob.username) is not None)
    wa.open_chat(bob.username)
    wb.open_chat(alice.username)

    # Alice types and presses Enter
    wa.chat_panel.input_bar.set_text("Hello Bob, this is encrypted!")
    wa.chat_panel.input_bar._send()
    sent = wa.store.get(bob.username).messages[-1]
    assert sent.outgoing and wa.chat_panel.messages.row(sent.id) is not None   # bubble shown immediately
    assert sent.frame and b"Hello Bob" not in sent.frame                        # the packet is ciphertext

    # Ticks: delivered (Bob's app received it). If Bob's window is the focused one it may
    # already have been read, which skips straight to blue ticks - both are correct.
    assert wait_until(lambda: sent.status in ("delivered", "read"))
    received = wb.store.get(alice.username).messages[-1]
    assert received.text == "Hello Bob, this is encrypted!"
    assert wb.chat_panel.messages.row(received.id) is not None                  # Bob sees the bubble

    # Bob reads it -> blue ticks for Alice
    wb.store.mark_read(alice.username)
    assert wait_until(lambda: sent.status == "read")
    assert set(sent.status_times) >= {"sent", "delivered", "read"}

    # Message info dialog builds for both directions
    MessageInfoDialog(sent, alice.key_fingerprint, "Bob").close()
    MessageInfoDialog(received, bob.key_fingerprint, "Alice").close()

    # Delete for me removes the bubble but only on Alice's side
    wa.store.delete_message(bob.username, sent.id)
    assert wa.chat_panel.messages.row(sent.id) is None
    assert wb.chat_panel.messages.row(received.id) is not None

    wa.close()
    wb.close()
