"""
The security demos are also tests: every attack must be detected or blocked.

Run with:  pytest tests/test_security_demos.py -v
"""

import pytest

from security_demo import bruteforce_login_test, replay_test, run_all, tamper_test
from security_demo.demo_utils import entropy, utf8_attempt
from security_demo.insecure_chat import InsecureServer, run_demo
from security_demo.sniffer_proxy import MitmProxy


@pytest.fixture(autouse=True)
def fast(monkeypatch):
    # the demos pause between steps for the audience; tests don't need that
    for module in (tamper_test, replay_test, bruteforce_login_test):
        monkeypatch.setattr(module, "pause", lambda *a, **k: None)


def test_eavesdropping_is_blocked():
    assert run_all.eavesdropping_demo() is True


def test_tampering_is_detected():
    assert tamper_test.run() is True


def test_replay_is_rejected():
    assert replay_test.run() is True


def test_bruteforce_is_locked_out():
    assert bruteforce_login_test.run() is True


def test_insecure_chat_leaks_through_the_proxy():
    server = InsecureServer(port=0, host="127.0.0.1", verbose=False).start_in_background()
    proxy = MitmProxy(("127.0.0.1", server.port), listen_port=0, framed=False).start()
    run_demo("127.0.0.1", proxy.port)
    captured = b"".join(body for conn in proxy.connections for _, _, body in conn.history)
    assert b"my bank PIN is 4711" in captured
    proxy.stop()
    server.stop()


def test_helpers():
    assert entropy(bytes(range(256))) == pytest.approx(8.0)
    assert entropy(b"aaaa") == 0
    assert utf8_attempt(b"hello world")[0] is True
    assert utf8_attempt(bytes([0x8F, 0x00, 0xFF, 0x13]))[0] is False
