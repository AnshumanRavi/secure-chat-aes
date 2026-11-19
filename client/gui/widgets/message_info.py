"""
"Message info" dialog: delivery times, plus the real encrypted packet that carried the message.

The packet is what actually crossed the network between this computer and the
server - shown here so the demo can prove that only ciphertext is transmitted.
Layout of an AES-256-GCM packet:  nonce (12 bytes) || ciphertext || tag (16 bytes)
"""

import base64
from datetime import datetime
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication, QDialog, QFrame, QGridLayout, QHBoxLayout, QLabel, QPushButton, QVBoxLayout,
)

from client.files import CHUNK_SIZE, human_size
from client.gui import icons
from client.gui.chat_store import Message
from client.gui.widgets.chat_list import status_pixmap

NONCE, TAG = 12, 16


def _when(ts: Optional[float]) -> str:
    return datetime.fromtimestamp(ts).strftime("%d %b %Y, %I:%M:%S %p") if ts else "—"


def _hex(data: bytes, limit: int = 16) -> str:
    """Hex in groups of 2 bytes; long values are shortened with '…' (Copy gives the full packet)."""
    text = data[:limit].hex().upper()
    grouped = " ".join(text[i:i + 4] for i in range(0, len(text), 4))
    return grouped + (" …" if len(data) > limit else "")


class MessageInfoDialog(QDialog):
    def __init__(self, msg: Message, session_key_id: str, peer_title: str, parent=None, name_of=None):
        super().__init__(parent)
        self.setObjectName("InfoDialog")
        self.setWindowTitle("Message info")
        self.setMinimumWidth(560)
        self.msg = msg

        v = QVBoxLayout(self)
        v.setContentsMargins(28, 24, 28, 22)
        v.setSpacing(0)

        title = QLabel("Message info")
        title.setObjectName("DialogTitle")
        v.addWidget(title)
        v.addSpacing(14)

        text = msg.preview
        if msg.is_file:
            text += f"  ({human_size(msg.file['size'])})"
        preview = QLabel(text if len(text) < 300 else text[:300] + "…")
        preview.setObjectName("InfoPreviewOut" if msg.outgoing else "InfoPreviewIn")
        preview.setWordWrap(True)
        preview.setTextInteractionFlags(Qt.TextSelectableByMouse)
        v.addWidget(preview)
        v.addSpacing(16)

        # --- delivery timeline
        times = QGridLayout()
        times.setHorizontalSpacing(12)
        times.setVerticalSpacing(8)
        if msg.outgoing and msg.recipients:      # group: blue ticks only once everyone has read it
            rows = [("read", "Read by everyone"), ("delivered", "Delivered to everyone"), ("sent", "Sent to server")]
        elif msg.outgoing:
            rows = [("read", f"Read by {peer_title}"), ("delivered", "Delivered"), ("sent", "Sent to server")]
        else:
            rows = [("received", f"Received from {peer_title}")]
        for i, (status, label) in enumerate(rows):
            icon = QLabel()
            if msg.outgoing:
                icon.setPixmap(status_pixmap(status, 18))
            name = QLabel(label)
            name.setObjectName("InfoLabel")
            value = QLabel(_when(msg.status_times.get(status)))
            value.setObjectName("InfoValue")
            times.addWidget(icon, i, 0)
            times.addWidget(name, i, 1)
            times.addWidget(value, i, 2, Qt.AlignRight)
        times.setColumnStretch(1, 1)
        v.addLayout(times)

        if msg.outgoing and msg.recipients:      # per-member progress in a group
            name_of = name_of or (lambda username: username)
            read = [name_of(u) for u in msg.recipients if u in msg.read_by]
            delivered = [name_of(u) for u in msg.recipients if u in msg.delivered_by and u not in msg.read_by]
            waiting = [name_of(u) for u in msg.recipients if u not in msg.delivered_by]
            v.addSpacing(10)
            for label, names in (("Read by", read), ("Delivered to", delivered), ("Not delivered yet", waiting)):
                if names:
                    line = QLabel(f"<b>{label}:</b> {', '.join(names)}")
                    line.setObjectName("InfoValue")
                    line.setWordWrap(True)
                    v.addWidget(line)
        v.addSpacing(18)

        # --- layer 1: end-to-end (only for E2E messages)
        if msg.e2e and msg.e2e_sealed:
            try:
                inner = base64.b64decode(msg.e2e_sealed)
            except ValueError:
                inner = b""
            e2e_box = QFrame()
            e2e_box.setObjectName("CryptoBox")
            e = QVBoxLayout(e2e_box)
            e.setContentsMargins(16, 14, 16, 14)
            e.setSpacing(6)
            title_row = QHBoxLayout()
            shield = QLabel()
            shield.setPixmap(icons.svg_pixmap(icons.SHIELD_CHECK, 15, "#008069"))
            title_label = QLabel("Layer 1 - End-to-end encryption (the server can't read this)")
            title_label.setObjectName("CryptoHeading")
            title_row.addWidget(shield)
            title_row.addWidget(title_label)
            title_row.addStretch()
            e.addLayout(title_row)
            grid = QGridLayout()
            grid.setHorizontalSpacing(14)
            grid.setVerticalSpacing(6)
            rows = [("Key agreement", "ECDH P-256 + HKDF-SHA256 (only you two)"),
                    ("Cipher", "AES-256-GCM, bound to sender+recipient+id")]
            if len(inner) > NONCE + TAG:
                rows += [("Nonce (96-bit)", _hex(inner[:NONCE])),
                         (f"Ciphertext ({len(inner) - NONCE - TAG} B)", _hex(inner[NONCE:-TAG])),
                         ("Auth tag (128-bit)", _hex(inner[-TAG:]))]
            for i, (name, value) in enumerate(rows):
                n, val = QLabel(name), QLabel(value)
                n.setObjectName("CryptoName")
                val.setObjectName("CryptoValue")
                for label in (n, val):
                    label.ensurePolished()
                    label.setMinimumHeight(label.fontMetrics().height() + 4)
                grid.addWidget(n, i, 0, Qt.AlignTop)
                grid.addWidget(val, i, 1)
            grid.setColumnStretch(1, 1)
            e.addLayout(grid)
            v.addWidget(e2e_box)
            v.addSpacing(10)

        # --- encryption details (transport layer)
        box = QFrame()
        box.setObjectName("CryptoBox")
        b = QVBoxLayout(box)
        b.setContentsMargins(16, 14, 16, 14)
        b.setSpacing(6)
        heading = QHBoxLayout()
        lock = QLabel()
        lock.setPixmap(icons.svg_pixmap(icons.LOCK, 15, "#008069"))
        heading_text = QLabel("Layer 2 - Transport packet on the wire" if msg.e2e else "Encrypted packet on the wire")
        heading_text.setObjectName("CryptoHeading")
        heading.addWidget(lock)
        heading.addWidget(heading_text)
        heading.addStretch()
        b.addLayout(heading)

        frame = msg.frame
        if frame and len(frame) > NONCE + TAG:
            fields = [
                ("Algorithm", "AES-256-GCM (authenticated encryption)"),
                ("Session key id", session_key_id or "—"),
                ("Packet size", f"{len(frame)} bytes"),
                ("Nonce (96-bit)", _hex(frame[:NONCE])),
                (f"Ciphertext ({len(frame) - NONCE - TAG} B)", _hex(frame[NONCE:-TAG])),
                ("Auth tag (128-bit)", _hex(frame[-TAG:])),
            ]
            if msg.is_file:
                chunks = -(-msg.file["size"] // CHUNK_SIZE)
                sha = msg.file.get("sha256") or ""
                verified = " ✓ verified" if msg.file.get("verified") else ""
                fields.insert(3, ("Shown packet", "FILE_START (file details + SHA-256)"))
                fields.append(("File chunks", f"{chunks} × separately encrypted 64 KB packets"))
                if sha:
                    fields.append(("File SHA-256", f"{sha[:32]}…{verified}"))
            grid = QGridLayout()
            grid.setHorizontalSpacing(14)
            grid.setVerticalSpacing(6)
            for i, (name, value) in enumerate(fields):
                n = QLabel(name)
                n.setObjectName("CryptoName")
                val = QLabel(value)
                val.setObjectName("CryptoValue")
                val.setTextInteractionFlags(Qt.TextSelectableByMouse)
                for label in (n, val):   # never let the wrapped note below squeeze these rows
                    label.ensurePolished()
                    label.setMinimumHeight(label.fontMetrics().height() + 4)
                grid.addWidget(n, i, 0, Qt.AlignTop)
                grid.addWidget(val, i, 1)
            grid.setColumnStretch(1, 1)
            b.addLayout(grid)
            direction = "from your computer to the server" if msg.outgoing else "from the server to your computer"
            note = QLabel(f"This is the exact packet that carried this message {direction}. "
                          "Each connection has its own session key, so the same message looks "
                          "completely different on every hop. Changing a single bit would make "
                          "the GCM tag check fail and the packet would be rejected.")
        else:
            note = QLabel("The encrypted packet for this message is not available.")
        note.setObjectName("CryptoNote")
        note.setWordWrap(True)
        b.addWidget(note)
        v.addWidget(box)
        v.addSpacing(18)

        buttons = QHBoxLayout()
        buttons.addStretch()
        if frame:
            copy = QPushButton("Copy packet hex")
            copy.setObjectName("SecondaryButton")
            copy.setCursor(Qt.PointingHandCursor)
            copy.clicked.connect(lambda: QApplication.clipboard().setText(frame.hex()))
            buttons.addWidget(copy)
        close = QPushButton("Close")
        close.setObjectName("PrimaryButton")
        close.setCursor(Qt.PointingHandCursor)
        close.setDefault(True)
        close.clicked.connect(self.accept)
        buttons.addWidget(close)
        v.addLayout(buttons)
