"""
Tests for encrypted file sharing (Prompt 11): chunked transfer, SHA-256 verification,
server-side checks, path-traversal protection and the GUI bubbles.

Run with:  pytest tests/test_files.py -v
"""

import hashlib
import os
import time
import uuid
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtGui import QColor, QImage
from PySide6.QtWidgets import QApplication

from client.files import CHUNK_SIZE, human_size, kind_for_path, safe_filename, unique_path
from client.gui.bridge import ClientBridge
from client.gui.main_window import MainWindow
from client.gui.theme import load_stylesheet
from client.gui.widgets.file_bubbles import DocumentBubble, ImageBubble, openable_path
from client.network import ChatClient
from common.protocol import MsgType, b64e
from tests.test_integration import EventRecorder

PASSWORD = "Passw0rd!"


def unique(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:5]}"


def user(server, tmp_path, name=None):
    client = ChatClient("127.0.0.1", server.port, heartbeat_interval=0)
    events = EventRecorder(client)
    name = name or unique("user")
    client.download_dir = tmp_path / f"dl_{name}"
    client.connect()
    client.register(name, PASSWORD)
    client.user_list_received.wait(3)
    return client, events


def raw_transfer(client, to, name, data, sha256=None, chunks=None, order=None):
    """Send FILE_START/CHUNK/END by hand - lets tests misbehave like an attacker would."""
    file_id = uuid.uuid4().hex
    pieces = [data[i:i + CHUNK_SIZE] for i in range(0, len(data), CHUNK_SIZE)]
    client._send({"type": MsgType.FILE_START, "id": file_id, "to": to, "name": name, "size": len(data),
                  "chunks": chunks if chunks is not None else len(pieces), "kind": "document",
                  "sha256": sha256 or hashlib.sha256(data).hexdigest()})
    for index in (order if order is not None else range(len(pieces))):
        client._send({"type": MsgType.FILE_CHUNK, "id": file_id, "index": index, "data": b64e(pieces[index])})
    client._send({"type": MsgType.FILE_END, "id": file_id})
    return file_id


# --------------------------------------------------------------- helpers ---
def test_safe_filename_blocks_path_traversal():
    assert safe_filename("..\\..\\Windows\\System32\\evil.exe") == "evil.exe"
    assert safe_filename("../../etc/passwd") == "passwd"
    assert safe_filename('re:po*rt?.pdf') == "re_po_rt_.pdf"
    assert safe_filename("...") == "file" and safe_filename("") == "file"
    assert len(safe_filename("a" * 400 + ".pdf")) <= 150


def test_unique_path_and_sizes(tmp_path):
    (tmp_path / "report.pdf").write_bytes(b"x")
    assert unique_path(tmp_path, "report.pdf").name == "report (1).pdf"
    assert human_size(512) == "512 B" and human_size(1536) == "1.5 KB" and human_size(5 * 1024 ** 2) == "5.0 MB"
    assert kind_for_path("a.JPG") == "image" and kind_for_path("a.pdf") == "document"


# --------------------------------------------------------- network level ---
def test_file_transfer_is_identical_and_verified(server, tmp_path):
    (alice, _), (bob, be) = user(server, tmp_path), user(server, tmp_path)
    data = os.urandom(3 * CHUNK_SIZE + 1234)              # 4 chunks, last one partial
    source = tmp_path / "lecture notes.pdf"
    source.write_bytes(data)
    progress = []
    result = alice.send_file(source, to=bob.username, progress=lambda done, total: progress.append(done))

    assert progress[-1] == len(data) and len(progress) == 4
    assert result["sha256"] == hashlib.sha256(data).hexdigest() and result["frame"]
    incoming = be.wait("file_incoming")
    assert incoming["name"] == "lecture notes.pdf" and incoming["chunks"] == 4
    done = be.wait("file_done")
    assert done["ok"] and Path(done["path"]).read_bytes() == data
    assert Path(done["path"]).parent == bob.download_dir
    alice.logout(), bob.logout()


def test_sender_gets_ticks_for_files(server, tmp_path):
    (alice, ae), (bob, _) = user(server, tmp_path), user(server, tmp_path)
    source = tmp_path / "a.txt"
    source.write_bytes(b"hello file")
    file_id = alice.send_file(source, to=bob.username)["id"]
    assert ae.wait("ack")["id"] == file_id                 # server has the whole file
    assert ae.wait("delivered")["id"] == file_id           # bob's app has it
    alice.logout(), bob.logout()


def test_tampered_file_is_rejected_and_deleted(server, tmp_path):
    (alice, _), (bob, be) = user(server, tmp_path), user(server, tmp_path)
    data = os.urandom(100_000)
    raw_transfer(alice, bob.username, "contract.pdf", data, sha256=hashlib.sha256(b"something else").hexdigest())
    done = be.wait("file_done")
    assert done["ok"] is False and "SHA-256" in done["error"]
    assert not any(p.is_file() for p in bob.download_dir.iterdir())    # nothing half-written left behind
    assert not any((bob.download_dir / ".partial").iterdir())
    alice.logout(), bob.logout()


def test_malicious_file_name_stays_in_downloads(server, tmp_path):
    (alice, _), (bob, be) = user(server, tmp_path), user(server, tmp_path)
    raw_transfer(alice, bob.username, "..\\..\\..\\evil.bat", b"echo pwned")
    done = be.wait("file_done")
    saved = Path(done["path"])
    assert done["ok"] and saved.name == "evil.bat" and saved.parent == bob.download_dir
    alice.logout(), bob.logout()


@pytest.mark.parametrize("problem", ["too_big", "wrong_chunk_count", "out_of_order"])
def test_server_rejects_bad_transfers(server, tmp_path, problem):
    (alice, ae), (bob, _) = user(server, tmp_path), user(server, tmp_path)
    if problem == "too_big":
        alice._send({"type": MsgType.FILE_START, "id": "big1", "to": bob.username, "name": "huge.iso",
                     "size": 26 * 1024 * 1024, "chunks": 416, "kind": "document", "sha256": "a" * 64})
    elif problem == "wrong_chunk_count":
        raw_transfer(alice, bob.username, "x.bin", os.urandom(1000), chunks=5)
    else:
        raw_transfer(alice, bob.username, "x.bin", os.urandom(3 * CHUNK_SIZE), order=[0, 2, 1])
    assert ae.wait("error")["code"] == "FILE_REJECTED"
    alice.logout(), bob.logout()


def test_offline_recipient_gets_file_later(server, tmp_path):
    (alice, ae), (bob, _) = user(server, tmp_path), user(server, tmp_path)
    bob_name, bob_dir = bob.username, bob.download_dir
    bob.logout()
    data = os.urandom(2 * CHUNK_SIZE + 10)
    source = tmp_path / "while_away.zip"
    source.write_bytes(data)
    file_id = alice.send_file(source, to=bob_name)["id"]
    ae.wait("ack")

    bob = ChatClient("127.0.0.1", server.port, heartbeat_interval=0)
    be = EventRecorder(bob)
    bob.download_dir = bob_dir
    bob.connect()
    bob.login(bob_name, PASSWORD)
    done = be.wait("file_done")
    assert done["ok"] and Path(done["path"]).read_bytes() == data
    assert ae.wait("delivered", lambda m: m["id"] == file_id)["by"] == bob_name
    alice.logout(), bob.logout()


def test_group_file_reaches_every_member(server, tmp_path):
    (alice, ae), (bob, be), (carol, ce) = (user(server, tmp_path) for _ in range(3))
    request = alice.create_group("Files", [bob.username, carol.username])
    group = ae.wait("group", lambda m: m.get("request_id") == request)["group"]
    source = tmp_path / "slides.pptx"
    source.write_bytes(os.urandom(70_000))
    alice.send_file(source, group_id=group["group_id"])
    for events in (be, ce):
        assert events.wait("file_incoming")["group_id"] == group["group_id"]
        assert events.wait("file_done")["ok"]
    for c in (alice, bob, carol):
        c.logout()


# ------------------------------------------------------------------- GUI ---
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


def gui_user(server, tmp_path, name):
    client = ChatClient("127.0.0.1", server.port, heartbeat_interval=0)
    client.download_dir = tmp_path / f"gui_{name}"
    bridge = ClientBridge(client)
    client.connect()
    client.register(name, PASSWORD, name.split("_")[0].title())
    client.user_list_received.wait(3)
    window = MainWindow(client, bridge)
    bridge.release()
    window.show()
    return client, window


def test_send_photo_and_pdf_between_windows(app, server, tmp_path):
    alice, wa = gui_user(server, tmp_path, unique("alice"))
    bob, wb = gui_user(server, tmp_path, unique("bob"))
    assert wait_until(lambda: wa.store.get(bob.username) is not None)
    wa.open_chat(bob.username)
    wb.open_chat(alice.username)

    photo = tmp_path / "photo.png"
    image = QImage(800, 600, QImage.Format_RGB32)
    image.fill(QColor("#53BDEB"))
    image.save(str(photo))
    pdf = tmp_path / "report.pdf"
    pdf.write_bytes(b"%PDF-1.4\n" + os.urandom(200_000))

    sent_photo = wa.store.send_file(bob.username, str(photo))
    sent_pdf = wa.store.send_file(bob.username, str(pdf))
    assert sent_photo.kind == "image" and sent_photo.file["width"] == 800
    assert isinstance(wa.chat_panel.messages.row(sent_photo.id).bubble, ImageBubble)
    assert isinstance(wa.chat_panel.messages.row(sent_pdf.id).bubble, DocumentBubble)

    assert wait_until(lambda: sent_photo.file["state"] == "done" and sent_pdf.file["state"] == "done")
    assert wait_until(lambda: sent_pdf.status in ("sent", "delivered", "read"))
    chat = wb.store.get(alice.username)
    assert wait_until(lambda: sum(1 for m in chat.messages if m.is_file and m.file["state"] == "done") == 2)
    received = {m.kind: m for m in chat.messages if m.is_file}
    assert received["image"].file["thumb"]                         # preview arrived with FILE_START
    assert Path(received["document"].file["path"]).read_bytes() == pdf.read_bytes()
    assert openable_path(received["image"]) and received["image"].file["verified"]
    assert received["document"].preview == "📄 report.pdf"
    wa.close()
    wb.close()
