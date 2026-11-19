"""
Tests for optional end-to-end encryption (Prompt 13).

Run with:  pytest tests/test_e2e.py -v
"""

import json
import os
import time
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtWidgets import QApplication

from client.gui.bridge import ClientBridge
from client.gui.main_window import MainWindow
from client.gui.settings import ClientSettings
from client.gui.theme import load_stylesheet
from client.gui.widgets.message_view import E2E_NOTICE, TRANSPORT_NOTICE
from client.local_store import LocalStore
from client.network import E2E_UNREADABLE, ChatClient
from common import crypto_utils as cu
from common import e2e
from common.config import Config
from server.security_log import SecurityLog
from server.server import ChatServer
from tests.test_integration import EventRecorder

PASSWORD = "Passw0rd!"


def unique(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:5]}"


# ------------------------------------------------------------ crypto module ---
def test_both_sides_derive_the_same_key_and_only_they_can_read():
    alice, bob, eve = (e2e.generate_identity() for _ in range(3))
    k_alice = e2e.pair_key(alice, "alice", bob.public_key(), "bob")
    k_bob = e2e.pair_key(bob, "bob", alice.public_key(), "alice")
    k_eve = e2e.pair_key(eve, "eve", bob.public_key(), "bob")
    assert k_alice == k_bob and k_alice != k_eve

    sealed = e2e.seal(k_alice, "alice", "bob", "m1", "meet at 5")
    assert e2e.open_sealed(k_bob, "alice", "bob", "m1", sealed) == "meet at 5"
    with pytest.raises(e2e.E2EError):
        e2e.open_sealed(k_eve, "alice", "bob", "m1", sealed)          # wrong key
    with pytest.raises(e2e.E2EError):
        e2e.open_sealed(k_bob, "alice", "carol", "m1", sealed)        # re-addressed by the server
    with pytest.raises(e2e.E2EError):
        e2e.open_sealed(k_bob, "alice", "bob", "m2", sealed)          # replayed under another id


def test_security_code_is_symmetric_and_detects_a_swapped_key():
    alice, bob, mitm = (e2e.generate_identity() for _ in range(3))
    code_on_alice = e2e.security_code("alice", e2e.export_public(alice), "bob", e2e.export_public(bob))
    code_on_bob = e2e.security_code("bob", e2e.export_public(bob), "alice", e2e.export_public(alice))
    assert code_on_alice == code_on_bob
    assert len(code_on_alice.replace(" ", "")) == 60 and len(code_on_alice.split(" ")) == 12
    # a server that hands Alice its own key instead of Bob's produces a different code
    assert e2e.security_code("alice", e2e.export_public(alice), "bob", e2e.export_public(mitm)) != code_on_alice
    assert e2e.code_grid(code_on_alice) == e2e.code_grid(code_on_bob)


def test_only_public_p256_keys_are_accepted():
    key = e2e.generate_identity()
    assert e2e.import_public(e2e.export_public(key)) == key.public_key()
    with pytest.raises(e2e.E2EError):
        e2e.import_public(key.export_key(format="PEM"))             # a PRIVATE key
    with pytest.raises(e2e.E2EError):
        e2e.import_public("not a key")


def test_identity_key_is_stored_encrypted_in_the_history(tmp_path):
    store = LocalStore.open("alice", PASSWORD, tmp_path)
    key = store.identity_key()
    store.close()
    reopened = LocalStore.open("alice", PASSWORD, tmp_path)
    assert reopened.identity_key() == key                            # same key after a restart
    assert e2e.export_private(key) not in (tmp_path / "alice.db").read_bytes()


# ---------------------------------------------------------- with a server ---
class CapturingLog(SecurityLog):
    def __init__(self, folder):
        super().__init__(folder, console=False)
        self.events = []

    def event(self, kind, message, *args, **kwargs):
        self.events.append((kind, message))
        super().event(kind, message, *args, **kwargs)


@pytest.fixture
def demo_server(tmp_path):
    log = CapturingLog(tmp_path / "logs")
    srv = ChatServer(Config(server_host="127.0.0.1", port=0), keys_dir=tmp_path / "keys",
                     db_path=tmp_path / "server.db", log=log, passphrase="test-passphrase", show_bodies=True)
    srv.start_in_background()
    yield srv
    srv.stop()


def e2e_user(server, with_key=True):
    client = ChatClient("127.0.0.1", server.port, heartbeat_interval=0)
    events = EventRecorder(client)
    client.connect()
    client.register(unique("user"), PASSWORD)
    client.user_list_received.wait(3)
    if with_key:
        client.e2e_key = e2e.generate_identity()
        client.publish_identity_key()
    return client, events


def wait_for(condition, timeout=5):
    deadline = time.time() + timeout
    while not condition() and time.time() < deadline:
        time.sleep(0.02)
    return condition()


def test_server_relays_only_ciphertext_it_cannot_read(demo_server):
    (alice, _), (bob, be) = e2e_user(demo_server), e2e_user(demo_server)
    assert wait_for(lambda: alice.can_e2e(bob.username) and bob.can_e2e(alice.username))

    alice.send_message(bob.username, "the vault code is 4711")
    received = be.wait("message")
    assert received["text"] == "the vault code is 4711" and received["e2e"]["ct"]

    e2e_lines = [m for kind, m in demo_server.log.events if kind == "E2E"]
    assert e2e_lines and "[E2E ciphertext]" in e2e_lines[-1]
    assert not any("4711" in m for _, m in demo_server.log.events)   # the server never saw it
    alice.logout(), bob.logout()


def test_without_e2e_the_server_could_read_it(demo_server):
    (alice, _), (bob, be) = e2e_user(demo_server), e2e_user(demo_server)
    assert wait_for(lambda: alice.can_e2e(bob.username))
    alice.e2e_enabled = False                                      # Settings > Security > E2E off
    alice.send_message(bob.username, "plain transport message")
    assert be.wait("message")["text"] == "plain transport message"
    assert any(kind == "PLAINTEXT" and "plain transport message" in m for kind, m in demo_server.log.events)
    alice.logout(), bob.logout()


def test_compromised_server_with_all_its_keys_still_cannot_read(demo_server):
    (alice, _), (bob, _) = e2e_user(demo_server), e2e_user(demo_server)
    assert wait_for(lambda: alice.can_e2e(bob.username))
    bob_name = bob.username
    bob.logout()
    alice.send_message(bob_name, "salary details: confidential")
    assert wait_for(lambda: demo_server.db.count_offline(bob_name) == 1)

    # An attacker who stole the server's storage key decrypts the offline queue...
    _, blob = demo_server.db.fetch_offline(bob_name)[0]
    stored = json.loads(cu.aes_decrypt(demo_server._storage_key, blob, b"offline|" + bob_name.encode()))
    # ...and still only finds the end-to-end ciphertext
    assert "text" not in stored and stored["e2e"]["ct"]
    assert "salary" not in json.dumps(stored)
    alice.logout()


def test_falls_back_to_transport_encryption_for_contacts_without_a_key(demo_server):
    (alice, _), (cli_user, ce) = e2e_user(demo_server), e2e_user(demo_server, with_key=False)
    assert not alice.can_e2e(cli_user.username)
    alice.send_message(cli_user.username, "hello terminal user")
    assert ce.wait("message")["text"] == "hello terminal user"
    assert alice.last_message_e2e is None
    alice.logout(), cli_user.logout()


def test_client_without_e2e_support_sees_a_placeholder(demo_server):
    (alice, _), (bob, _) = e2e_user(demo_server), e2e_user(demo_server)
    assert wait_for(lambda: alice.can_e2e(bob.username))
    bob.e2e_key = None                                             # like the terminal client
    events = EventRecorder(bob)
    alice.send_message(bob.username, "secret")
    assert events.wait("message")["text"] == E2E_UNREADABLE
    alice.logout(), bob.logout()


def test_bad_identity_key_rejected(demo_server):
    alice, ae = e2e_user(demo_server, with_key=False)
    alice._send({"type": "PUBLISH_KEY", "public_key": "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"})
    assert ae.wait("error")["code"] == "BAD_KEY"
    alice.logout()


# -------------------------------------------------------------------- GUI ---
@pytest.fixture(scope="module")
def app():
    application = QApplication.instance() or QApplication([])
    application.setStyleSheet(load_stylesheet("light"))
    return application


def pump(ms=50):
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


def wait_until(condition, timeout=6):
    deadline = time.time() + timeout
    while not condition() and time.time() < deadline:
        pump()
    return condition()


def gui_user(server, tmp_path, name):
    client = ChatClient("127.0.0.1", server.port, heartbeat_interval=0)
    bridge = ClientBridge(client)
    client.connect()
    client.register(name, PASSWORD, name.split("_")[0].title())
    client.user_list_received.wait(3)
    window = MainWindow(client, bridge, history=LocalStore.open(name, PASSWORD, tmp_path),
                        settings=ClientSettings(None))
    bridge.release()
    window.show()
    return client, window


def test_gui_e2e_chat_notice_and_key_change_warning(app, server, tmp_path):
    alice, wa = gui_user(server, tmp_path, unique("alice"))
    bob, wb = gui_user(server, tmp_path, unique("bob"))
    assert wait_until(lambda: wa.store.e2e_active(bob.username) and wb.store.e2e_active(alice.username))

    wa.open_chat(bob.username)
    assert wa.chat_panel.messages.notice.label.text() == E2E_NOTICE
    sent = wa.store.send_text(bob.username, "end-to-end hello")
    assert sent.e2e and sent.e2e_sealed and b"end-to-end hello" not in sent.frame
    assert wait_until(lambda: any(m.text == "end-to-end hello" and m.e2e
                                  for m in wb.store.get(alice.username).messages))

    # turning E2E off changes the notice and the next message is transport-only
    wa.settings.set("e2e", False)
    wa._apply_preferences()
    assert wa.chat_panel.messages.notice.label.text() == TRANSPORT_NOTICE
    assert not wa.store.send_text(bob.username, "transport only").e2e
    wa.settings.set("e2e", True)
    wa._apply_preferences()

    # Bob gets a new identity key (e.g. reinstalled) -> yellow warning for Alice
    wa.store.set_verified(bob.username, True)
    bob.e2e_key = e2e.generate_identity()
    bob.publish_identity_key()
    assert wait_until(lambda: any(m.kind == "security" for m in wa.store.get(bob.username).messages))
    assert wa.store.get(bob.username).verified is False
    # ...and messages with the NEW key still decrypt on both sides
    wb.store.send_text(alice.username, "sent with my new key")
    assert wait_until(lambda: any(m.text == "sent with my new key" and m.e2e
                                  for m in wa.store.get(bob.username).messages))
    wa.close()
    wb.close()
