"""
GUI tests for the login screen, run without showing a window (Qt "offscreen" platform).

Run with:  pytest tests/test_gui_login.py -v
"""

import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtWidgets import QApplication, QDialog

from client.gui import login_window as lw
from client.gui.settings import ClientSettings
from client.gui.theme import load_stylesheet
from common.config import Config


@pytest.fixture(scope="module")
def app():
    application = QApplication.instance() or QApplication([])
    application.setStyleSheet(load_stylesheet("light"))
    return application


def pump(ms=50):
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


def wait_until(condition, timeout=10):
    deadline = time.time() + timeout
    while not condition() and time.time() < deadline:
        pump()
    return condition()


@pytest.fixture
def window(app, server, tmp_path):
    win = lw.LoginWindow(Config(client_host="127.0.0.1", port=server.port),
                         ClientSettings(tmp_path / "settings.json"))
    win.result = {}
    win.history_dir = tmp_path / "history"           # keep test history out of the project folder
    win.logged_in.connect(lambda client, bridge, history: win.result.update(client=client, bridge=bridge,
                                                                            history=history))
    win.show()
    yield win
    if "client" in win.result:
        win.result["client"].logout()
    win.close()


@pytest.fixture
def answer_dialog(monkeypatch):
    """Replace the fingerprint popup with an automatic answer; records what it was shown."""
    shown = []

    def install(accept: bool):
        def fake_exec(dialog):
            shown.append(dialog.windowTitle())
            return QDialog.Accepted if accept else QDialog.Rejected
        monkeypatch.setattr(lw.FingerprintDialog, "exec", fake_exec)
        return shown
    return install


def fill(win, username, password, display=""):
    win.username.edit.setText(username)
    win.password.edit.setText(password)
    win.display_name.edit.setText(display)


# ----------------------------------------------------------------- tests ---
def test_validation_errors_shown_without_connecting(window):
    window.register_tab.click()
    fill(window, "A!", "short")
    window.submit()
    assert window.username.error.isVisible()
    assert window.password.error.isVisible()
    assert window.client is None          # nothing was sent to the network


def test_register_flow_with_fingerprint_check(window, server, answer_dialog):
    shown = answer_dialog(accept=True)
    window.register_tab.click()
    fill(window, "gui_alice", "Passw0rd1", "Alice GUI")
    window.submit()
    assert wait_until(lambda: "client" in window.result)
    assert shown == ["Verify the server"]               # first connection -> popup
    assert window.result["client"].profile["display_name"] == "Alice GUI"
    assert window.settings.trusted_fingerprint("127.0.0.1", server.port) == server.fingerprint


def test_known_server_skips_popup_and_wrong_password_shows_error(window, server, answer_dialog):
    shown = answer_dialog(accept=True)
    window.settings.trust("127.0.0.1", server.port, server.fingerprint)
    fill(window, "gui_alice", "WrongPass9")
    window.submit()
    assert wait_until(lambda: window.password.error.isVisible())
    assert "Invalid username or password" in window.password.error.text()
    assert shown == []                                   # fingerprint matched -> no popup
    assert window.status.isVisible() and "verified" in window.status.text()

    fill(window, "gui_alice", "Passw0rd1")               # retry on the same connection
    window.submit()
    assert wait_until(lambda: "client" in window.result)


def test_rejecting_fingerprint_does_not_log_in(window, answer_dialog):
    answer_dialog(accept=False)
    fill(window, "gui_alice", "Passw0rd1")
    window.submit()
    assert wait_until(lambda: window.general_error.isVisible())
    assert "not confirmed" in window.general_error.text()
    assert window.client is None and "client" not in window.result


def test_changed_fingerprint_shows_warning(window, server, answer_dialog):
    shown = answer_dialog(accept=False)
    window.settings.trust("127.0.0.1", server.port, "0000 1111 2222 3333")
    fill(window, "gui_alice", "Passw0rd1")
    window.submit()
    assert wait_until(lambda: bool(shown))
    assert shown == ["Server key changed!"]


def test_unreachable_server_shows_error_on_server_field(window):
    window.host.edit.setText("127.0.0.1")
    window.port.edit.setText("1")
    fill(window, "gui_alice", "Passw0rd1")
    window.submit()
    assert wait_until(lambda: window.host.error.isVisible(), timeout=15)
    assert window.server_fields.isVisible()
    assert not window._busy
