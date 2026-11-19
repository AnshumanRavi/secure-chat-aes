"""
Create the screenshots in docs/screenshots/ from the REAL application.

    python -m docs.tools.make_screenshots

A throwaway server is started, a few users chat with each other (text, a group, a photo
and a PDF), and every window/dialog is rendered off-screen at 2x resolution. Console
screenshots (server window, packet sniffer, attack scorecard) are real program output,
drawn as terminal images.
"""

import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

os.environ["QT_QPA_PLATFORM"] = "offscreen"
os.environ.setdefault("QT_QPA_FONTDIR", "C:/Windows/Fonts")
os.environ["QT_SCALE_FACTOR"] = "2"                 # crisp images for print

from PySide6.QtCore import QEventLoop, QRectF, Qt, QTimer
from PySide6.QtGui import QColor, QFont, QFontMetrics, QImage, QPainter, QPainterPath, QPdfWriter
from PySide6.QtWidgets import QApplication

from client.gui.bridge import ClientBridge
from client.gui.chat_store import group_chat_id
from client.gui.login_window import FingerprintDialog, LoginWindow
from client.gui.main_window import MainWindow
from client.gui.media import image_size, make_thumbnail
from client.gui.settings import ClientSettings
from client.gui.theme import apply_theme
from client.gui.widgets.message_info import MessageInfoDialog
from client.gui.widgets.security_code import SecurityCodeDialog
from client.gui.widgets.settings_dialog import SettingsDialog
from client.local_store import LocalStore
from client.network import ChatClient
from common import e2e
from common.config import PROJECT_ROOT, Config
from common.discovery import FoundServer
from server.security_log import SecurityLog
from server.server import ChatServer

OUT = PROJECT_ROOT / "docs" / "screenshots"
PASSWORD = "Passw0rd2026"
ANSI = re.compile(r"\x1b\[[0-9;]*m")


# ------------------------------------------------------------------ helpers
def pump(ms: int = 40) -> None:
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


def wait_until(condition, timeout: float = 8) -> bool:
    deadline = time.time() + timeout
    while not condition() and time.time() < deadline:
        pump()
    return bool(condition())


def settle(ms: int = 400) -> None:
    for _ in range(ms // 40):
        pump()


def grab(widget, name: str) -> None:
    widget.repaint()
    settle(300)
    widget.grab().save(str(OUT / f"{name}.png"))
    print(f"  saved docs/screenshots/{name}.png")


def headless_user(server, tmp: Path, name: str, display: str, about: str = "") -> ChatClient:
    client = ChatClient("127.0.0.1", server.port, heartbeat_interval=0)
    client.download_dir = tmp / f"dl_{name}"
    client.connect()
    client.register(name, PASSWORD, display)
    client.user_list_received.wait(3)
    client.e2e_key = e2e.generate_identity()
    client.publish_identity_key()
    if about:
        client.update_profile(about=about)
    return client


def make_pdf(path: Path) -> None:
    writer = QPdfWriter(str(path))
    painter = QPainter(writer)
    painter.setFont(QFont("Segoe UI", 14))
    painter.drawText(400, 600, "AES-GCM notes - Applied Cryptography")
    painter.end()


# ------------------------------------------------------------------ console images
def render_console(lines, name: str, title: str, width_chars: int = 92) -> None:
    """Draw program output as a dark terminal window (colours by line meaning)."""
    lines = list(lines)
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    font = QFont("Consolas", 11)
    metrics = QFontMetrics(font)
    scale, pad, bar = 2, 18, 34
    line_h = metrics.height() + 2
    width = metrics.horizontalAdvance("M") * width_chars + 2 * pad
    height = bar + pad * 2 + line_h * len(lines)
    image = QImage(width * scale, height * scale, QImage.Format_ARGB32)
    image.fill(Qt.transparent)
    p = QPainter(image)
    p.setRenderHint(QPainter.Antialiasing)
    p.scale(scale, scale)
    frame = QPainterPath()
    frame.addRoundedRect(QRectF(0, 0, width, height), 10, 10)
    p.fillPath(frame, QColor("#0d1117"))
    top = QPainterPath()
    top.addRoundedRect(QRectF(0, 0, width, bar + 10), 10, 10)
    p.fillPath(top, QColor("#1f2630"))
    p.fillRect(QRectF(0, bar, width, 10), QColor("#0d1117"))
    for i, colour in enumerate(("#ff5f56", "#ffbd2e", "#27c93f")):
        p.setBrush(QColor(colour))
        p.setPen(Qt.NoPen)
        p.drawEllipse(QRectF(14 + i * 20, bar / 2 - 6, 12, 12))
    p.setPen(QColor("#9aa4b2"))
    p.setFont(QFont("Segoe UI", 10))
    p.drawText(QRectF(0, 0, width, bar), Qt.AlignCenter, title)
    p.setFont(font)
    y = bar + pad + metrics.ascent()
    for line in lines:
        text = line.rstrip()
        colour = "#c9d1d9"
        if any(k in text for k in ("BLOCKED", "✓", "unreadable", "Listening", "should connect")):
            colour = "#3fb950"
        if any(k in text for k in ("READABLE", "ATTACK ", "✗", "☠", "TAMPER", "REPLAY", "readable?!")):
            colour = "#f85149"
        if text.strip().startswith(("═", "+", "|  SecureChat", "STEP", "▶")):
            colour = "#58a6ff"
        if re.match(r"^\s+[0-9a-f]{4}\s", text):
            colour = "#d2a8ff"                       # hex dump
        if "Entropy" in text or "UTF-8" in text:
            colour = "#e3b341" if "READABLE" not in text else "#f85149"
        if "BLOCKED" in text:
            colour = "#3fb950"                       # a blocked attack is good news
        p.setPen(QColor(colour))
        p.drawText(pad, y, text[:width_chars])
        y += line_h
    p.end()
    image.save(str(OUT / f"{name}.png"))
    print(f"  saved docs/screenshots/{name}.png")


def run_output(args, env=None, timeout=120) -> str:
    result = subprocess.run([sys.executable, *args], cwd=PROJECT_ROOT, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=timeout,
                            env=dict(os.environ, PYTHONIOENCODING="utf-8", **(env or {})))
    return ANSI.sub("", result.stdout)


def console_shots(tmp: Path) -> None:
    print("Console screenshots")
    out = run_output(["-m", "security_demo.run_all"]).splitlines()
    end = next(i for i, l in enumerate(out) if "TAMPER TEST" in l) - 1
    secure = [l for l in out[:end]]
    # SecureChat part of the eavesdropping demo: from the start to the insecure step
    split = next(i for i, l in enumerate(secure) if "STEP 2" in l or "insecure" in l.lower() and "STEP" in l)
    render_console(secure[:split][:34], "10_sniffer", "Attacker's proxy - SecureChat traffic")
    render_console(secure[split - 1:][:30], "11_insecure_sniffer", "Attacker's proxy - insecure plain-text chat")
    start = next(i for i, l in enumerate(out) if "SECURITY SCORECARD" in l) - 1
    render_console(out[start:start + 9], "12_scorecard", "python -m security_demo.run_all", 104)

    # the server window: start it in a subprocess, let one client chat, capture what it prints
    keys = tmp / "console_keys"
    proc = subprocess.Popen([sys.executable, "-u", "-m", "server.server", "--port", "5589", "--keys-dir", str(keys),
                             "--db", str(tmp / "console.db"), "--no-discovery"], cwd=PROJECT_ROOT,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                            errors="replace",
                            env=dict(os.environ, PYTHONIOENCODING="utf-8", SECURECHAT_KEY_PASSPHRASE="demo-pass"))
    try:
        for _ in range(40):
            try:
                a = ChatClient("127.0.0.1", 5589, heartbeat_interval=0)
                a.connect()
                break
            except Exception:
                time.sleep(0.25)
        a.register("anshuman", PASSWORD, "Anshuman Ravi")
        b = ChatClient("127.0.0.1", 5589, heartbeat_interval=0)
        b.connect()
        b.register("priya", PASSWORD, "Priya Sharma")
        time.sleep(0.3)
        a.send_message("priya", "Hi Priya, this message is AES-256-GCM encrypted")
        time.sleep(0.6)
        a.logout()
        b.logout()
        time.sleep(0.4)
    finally:
        proc.terminate()
        text, _ = proc.communicate(timeout=10)
    lines = [l for l in ANSI.sub("", text).splitlines() if l.strip()]
    start = next(i for i, l in enumerate(lines) if l.startswith("+"))
    # the banner, then the interesting events: connect, handshake, login and one chat message relayed
    boring = ("USER_LIST", "PRESENCE", "AUTH_OK", "IN REGISTER", "REGISTER  ", "LOGOUT", "DISCONNECT", "STOP")
    lines = [l for l in lines[start:] if not any(b in l for b in boring)][:34]
    render_console(lines, "03_server_console", "run_server.bat - SecureChat Server", 112)


# ------------------------------------------------------------------ GUI
def gui_shots(tmp: Path) -> None:
    app = QApplication.instance() or QApplication([])
    app.setFont(QFont("Segoe UI", 10))
    apply_theme(app, "light")

    server = ChatServer(Config(server_host="127.0.0.1", port=0), keys_dir=tmp / "keys", db_path=tmp / "server.db",
                        log=SecurityLog(tmp / "logs", console=False), passphrase="screenshots")
    server.start_in_background()

    print("Login screens")
    login = LoginWindow(Config(client_host="", port=5555), ClientSettings(tmp / "login.json"))
    login.resize(1000, 820)
    login.show()
    login.username.edit.setText("anshuman")
    login._on_servers_found([FoundServer("192.168.1.20", 5555, "ANSHUMAN-LAPTOP", server.fingerprint)])
    grab(login, "01_login")
    login.close()

    priya = headless_user(server, tmp, "priya", "Priya Sharma", "Busy with assignments 📚")
    rahul = headless_user(server, tmp, "rahul", "Rahul Verma", "At the library")
    neha = headless_user(server, tmp, "neha", "Neha Gupta")

    client = ChatClient("127.0.0.1", server.port, heartbeat_interval=0)
    client.download_dir = tmp / "dl_anshuman"
    bridge = ClientBridge(client)
    client.connect()

    dialog = FingerprintDialog(server.fingerprint, client.key_fingerprint, "192.168.1.20", 5555)
    dialog.show()
    settle()
    dialog.adjustSize()                          # exec() would size it to fit the whole fingerprint
    grab(dialog, "02_fingerprint")
    dialog.close()

    client.register("anshuman", PASSWORD, "Anshuman Ravi")
    client.user_list_received.wait(3)
    history = LocalStore.open("anshuman", PASSWORD, tmp / "history")
    settings = ClientSettings(None)
    win = MainWindow(client, bridge, history=history, settings=settings)
    bridge.release()
    win.resize(1240, 800)
    win.show()
    wait_until(lambda: all(win.store.get(u) for u in ("priya", "rahul", "neha")))
    wait_until(lambda: client.can_e2e("priya"))
    store = win.store

    print("Conversations")
    priya.send_message("anshuman", "Hey Anshuman! Did you finish the AES-GCM part of the project? 🔐")
    wait_until(lambda: len(store.get("priya").messages) >= 1)
    settle()
    store.send_text("priya", "Yes! Every message is now encrypted with AES-256-GCM 😄")
    store.send_text("priya", "The server window only ever shows random-looking bytes.")
    settle()
    priya.send_message("anshuman", "Nice. And what stops someone from replaying an old packet?")
    wait_until(lambda: len(store.get("priya").messages) >= 4)
    store.send_text("priya", "Sequence numbers + timestamps inside the encrypted payload - replayed "
                             "packets are rejected ✅")
    settle()
    win.open_chat("priya")
    mine = [m.id for m in store.get("priya").messages if m.outgoing]
    wait_until(lambda: all(store._by_id[i].status in ("delivered", "read") for i in mine))
    priya.send_read("anshuman", mine)
    wait_until(lambda: all(store._by_id[i].status == "read" for i in mine))
    rahul.send_message("anshuman", "Are we presenting on Friday?")
    neha.send_message("anshuman", "Can you share the performance graphs?")
    wait_until(lambda: store.get("neha").messages and store.get("rahul").messages)
    settle()
    priya.send_typing("anshuman", True)
    wait_until(lambda: store.get("priya").typing)
    win.open_chat("priya")
    grab(win, "04_main_window")

    print("Group chat")
    client.create_group("Applied Crypto Project", ["priya", "rahul", "neha"], "NIT Patna · CSE 1")
    wait_until(lambda: any(g["name"] == "Applied Crypto Project" for g in priya.groups.values()))
    group_id = next(g["group_id"] for g in priya.groups.values() if g["name"] == "Applied Crypto Project")
    wait_until(lambda: store.get(group_chat_id(group_id)) is not None)
    chat_id = group_chat_id(group_id)
    priya.send_group_message(group_id, "I'll prepare the slides on RSA-OAEP and HKDF")
    rahul.send_group_message(group_id, "I'll run the network benchmark on both laptops 💻")
    wait_until(lambda: len(store.get(chat_id).messages) >= 2)
    msg = store.send_text(chat_id, "Great - the security scorecard shows every attack blocked 🎉")
    settle()
    for member in (priya, rahul, neha):
        member.send_read("anshuman", [msg.id], group_id=group_id)
    wait_until(lambda: store._by_id[msg.id].status == "read")
    neha.send_group_message(group_id, "Perfect, see you all in the lab!")
    wait_until(lambda: len(store.get(chat_id).messages) >= 4)
    win.open_chat(chat_id)
    grab(win, "06_group_chat")

    print("Files")
    photo = PROJECT_ROOT / "performance" / "graphs" / "aes_throughput_by_mode.png"
    width, height = image_size(photo)
    priya.send_message("anshuman", "Here are the throughput graphs from my laptop")
    priya.send_file(photo, to="anshuman", kind="image", thumb=make_thumbnail(photo), width=width, height=height)
    notes = tmp / "AES-GCM notes.pdf"
    make_pdf(notes)
    priya.send_file(notes, to="anshuman", kind="document")
    wait_until(lambda: sum(1 for m in store.get("priya").messages if m.file and m.file.get("state") == "done") >= 2,
               15)
    store.send_text("priya", "Got both - SHA-256 verified 👍")
    priya.send_typing("anshuman", False)
    win.open_chat("priya")
    settle(800)
    grab(win, "07_file_sharing")

    print("Dialogs")
    text_msg = next(m for m in store.get("priya").messages if m.outgoing and "replayed" in (m.text or ""))
    info = MessageInfoDialog(text_msg, client.key_fingerprint, "Priya Sharma", win, name_of=store.display_name)
    info.show()
    grab(info, "08_message_info")
    info.close()
    my_pem = e2e.export_public(client.e2e_key)
    code = SecurityCodeDialog(client.username, my_pem, "priya", "Priya Sharma", client.peer_identity("priya"), False,
                              e2e_on=True, parent=win)
    code.show()
    grab(code, "09_security_code")
    code.close()
    settings_dialog = SettingsDialog(client, settings, history, start_page="security", parent=win)
    settings_dialog.show()
    grab(settings_dialog, "14_settings_security")
    settings_dialog.close()

    print("Dark mode")
    settings.set("theme", "dark")
    win._apply_theme()
    win.open_chat("priya")
    settle(600)
    grab(win, "05_dark_mode")

    for c in (priya, rahul, neha, client):
        c.logout()
    win.close()
    server.stop()


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="securechat-shots-"))
    gui_shots(tmp)
    console_shots(tmp)
    sys.stdout.flush()
    os._exit(0)          # skip Python's teardown of the off-screen Qt objects (it can crash on exit)


if __name__ == "__main__":
    main()
