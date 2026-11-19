"""
LAN discovery: the server answers "Find server on LAN" broadcasts, the login screen fills in
the address. Uses 127.0.0.1 and random ports, so no real network is needed.
"""

import json
import os
import socket
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtWidgets import QApplication, QDialog

from client.gui import login_window as lw
from client.gui.settings import ClientSettings
from client.gui.theme import load_stylesheet
from common import discovery
from common.config import Config

FINGERPRINT = "AB12 CD34 EF56 7890 AB12 CD34 EF56 7890 AB12 CD34 EF56 7890 AB12 CD34 EF56 7890"


@pytest.fixture
def responder():
    r = discovery.DiscoveryResponder(5555, FINGERPRINT, name="server-pc", host="127.0.0.1", port=0).start()
    yield r
    r.stop()


# ----------------------------------------------------------------- protocol
def test_client_finds_the_server(responder):
    found = discovery.discover(timeout=0.5, port=responder.port, targets=["127.0.0.1"])
    assert len(found) == 1
    server = found[0]
    assert (server.host, server.port, server.name, server.fingerprint) == ("127.0.0.1", 5555, "server-pc", FINGERPRINT)
    assert server.short_fingerprint == "AB12 CD34 EF56 7890"


def test_nothing_found_when_no_server_answers():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as unused:
        unused.bind(("127.0.0.1", 0))
        port = unused.getsockname()[1]
    start = time.monotonic()
    assert discovery.discover(timeout=0.3, port=port, targets=["127.0.0.1"]) == []
    assert time.monotonic() - start < 2


def test_responder_ignores_junk_and_never_amplifies(responder):
    request = discovery._request("abc123")
    assert len(request) == discovery.REQUEST_SIZE
    reply = responder.answer(request)
    assert reply is not None and len(reply) <= len(request)          # no amplification
    assert json.loads(reply)["nonce"] == "abc123"
    assert responder.answer(b'{"type": "SECURECHAT_DISCOVER", "v": 1, "nonce": "x"}') is None   # too small
    assert responder.answer(b"x" * 600) is None                                               # not JSON
    wrong = json.dumps({"type": "SOMETHING_ELSE", "v": 1, "nonce": "x", "pad": "." * 600}).encode()
    assert responder.answer(wrong) is None


def test_lan_address_preferred_over_loopback():
    same = dict(port=5555, name="pc", fingerprint=FINGERPRINT)
    servers = [discovery.FoundServer("127.0.0.1", **same), discovery.FoundServer("192.168.1.20", **same),
               discovery.FoundServer("192.168.1.30", 5555, "other", "FF" * 32)]
    result = discovery._prefer_lan_address(servers)
    assert [s.host for s in result] == ["192.168.1.30", "192.168.1.20"]   # sorted by name: "other", "pc"


def test_adapters_have_valid_broadcast_addresses():
    for adapter in discovery.adapters():
        assert not adapter.ip.startswith("127.")
        assert adapter.broadcast.count(".") == 3


def test_chat_server_answers_discovery(tmp_path):
    from server.security_log import SecurityLog
    from server.server import ChatServer
    server = ChatServer(Config(server_host="127.0.0.1", port=0), keys_dir=tmp_path / "keys",
                        db_path=tmp_path / "db.sqlite", log=SecurityLog(tmp_path / "logs", console=False),
                        passphrase="test", lan_discovery=True)
    server.start_in_background()
    try:
        if server._discovery is None:            # UDP 5555 taken (e.g. a real server is running)
            assert "in use" in server._discovery_error
            pytest.skip(server._discovery_error)
        found = discovery.discover(timeout=0.5, targets=["127.0.0.1"])
        assert any(s.port == server.port and s.fingerprint == server.fingerprint for s in found)
    finally:
        server.stop()


# ----------------------------------------------------------------- login screen
@pytest.fixture
def window(tmp_path):
    app = QApplication.instance() or QApplication([])
    app.setStyleSheet(load_stylesheet("light"))
    win = lw.LoginWindow(Config(client_host="127.0.0.1", port=5555), ClientSettings(tmp_path / "settings.json"))
    win.show()
    yield win
    win.close()


def wait_until(condition, timeout=5):
    deadline = time.time() + timeout
    while not condition() and time.time() < deadline:
        loop = QEventLoop()
        QTimer.singleShot(30, loop.quit)
        loop.exec()
    return condition()


def test_find_button_fills_in_the_server(window, monkeypatch):
    found = discovery.FoundServer("192.168.1.20", 5600, "lab-pc", FINGERPRINT)
    monkeypatch.setattr(discovery, "discover", lambda: [found])
    window.find_button.click()
    assert wait_until(lambda: not window._busy)
    assert window.host.text() == "192.168.1.20"
    assert window.port.text() == "5600"
    assert "lab-pc" in window.status.text()
    assert window.server_fields.isVisible()


def test_find_button_reports_when_nothing_answers(window, monkeypatch):
    monkeypatch.setattr(discovery, "discover", lambda: [])
    window.find_button.click()
    assert wait_until(lambda: not window._busy)
    assert "No SecureChat server answered" in window.host.error.text()
    assert window.host.text() == "127.0.0.1"          # unchanged


def test_picker_shown_when_several_servers_answer(window, monkeypatch):
    servers = [discovery.FoundServer("192.168.1.20", 5555, "pc-one", FINGERPRINT),
               discovery.FoundServer("192.168.1.30", 5555, "pc-two", "FF" * 32)]
    monkeypatch.setattr(discovery, "discover", lambda: servers)

    def choose_second(dialog):
        dialog.list.setCurrentRow(1)
        return QDialog.Accepted
    monkeypatch.setattr(lw.ServerPickerDialog, "exec", choose_second)
    window.find_button.click()
    assert wait_until(lambda: not window._busy)
    assert window.host.text() == "192.168.1.30"
