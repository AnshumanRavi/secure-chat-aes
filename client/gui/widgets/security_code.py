"""
"Verify security code" screen (like WhatsApp's): a QR-like pattern and a 60-digit number,
both computed from YOUR public identity key and your CONTACT's.

Both people see exactly the same code. Compare them side by side or read the number
out over a call: if they match, nobody (not even the server, which hands out the
public keys) has swapped in a key of its own, so the chat really is end-to-end.
"""

from typing import Optional

from PySide6.QtCore import QRectF, Qt, Signal
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from common import e2e


class CodeGrid(QWidget):
    """Draws the QR-like pattern, with QR-style finder squares in three corners."""

    def __init__(self, code: str, parent=None):
        super().__init__(parent)
        self.grid = e2e.code_grid(code)
        self.setFixedSize(200, 200)

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor("#FFFFFF"))
        n = len(self.grid)
        cell = (self.width() - 16) / n
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor("#111B21"))
        finders = {(0, 0), (0, n - 7), (n - 7, 0)}

        def in_finder(r, c):
            return any(fr <= r < fr + 7 and fc <= c < fc + 7 for fr, fc in finders)

        for r in range(n):
            for c in range(n):
                if self.grid[r][c] and not in_finder(r, c):
                    painter.drawRect(QRectF(8 + c * cell, 8 + r * cell, cell + 0.3, cell + 0.3))
        for fr, fc in finders:                       # the three big squares make it look like a QR code
            for size, colour in ((7, "#111B21"), (5, "#FFFFFF"), (3, "#111B21")):
                offset = (7 - size) / 2
                painter.setBrush(QColor(colour))
                painter.drawRect(QRectF(8 + (fc + offset) * cell, 8 + (fr + offset) * cell, size * cell, size * cell))


class SecurityCodeDialog(QDialog):
    verified_changed = Signal(bool)

    def __init__(self, my_username: str, my_public_pem: Optional[str], contact_username: str,
                 contact_title: str, contact_pem: Optional[str], verified: bool,
                 e2e_on: bool = True, parent=None):
        super().__init__(parent)
        self.setObjectName("InfoDialog")
        self.setWindowTitle("Verify security code")
        self.setMinimumWidth(500)
        self.verified = verified

        v = QVBoxLayout(self)
        v.setContentsMargins(32, 26, 32, 24)
        v.setSpacing(10)
        title = QLabel("Verify security code")
        title.setObjectName("DialogTitle")
        v.addWidget(title)

        if not (my_public_pem and contact_pem):
            text = QLabel(f"{contact_title} hasn't set up end-to-end encryption yet (they need to log in "
                          "with the SecureChat desktop app). Until then, your messages are protected by "
                          "AES-256-GCM between each of you and the server, but the server can read them.")
            text.setObjectName("DialogText")
            text.setWordWrap(True)
            v.addWidget(text)
        else:
            code = e2e.security_code(my_username, my_public_pem, contact_username, contact_pem)
            row = QHBoxLayout()
            row.addStretch()
            row.addWidget(CodeGrid(code))
            row.addStretch()
            v.addLayout(row)
            groups = code.split(" ")
            digits = QLabel("\n".join("    ".join(groups[i:i + 4]) for i in range(0, 12, 4)))
            digits.setObjectName("SecurityDigits")
            digits.setAlignment(Qt.AlignCenter)
            digits.setTextInteractionFlags(Qt.TextSelectableByMouse)
            v.addWidget(digits)
            explanation = QLabel(
                f"To verify that messages with <b>{contact_title}</b> are end-to-end encrypted, compare this "
                f"code with the one on their screen - side by side, or read it out over a call. "
                f"Both of you see the same code. If it matches, the SecureChat server can't read your "
                f"messages or pretend to be either of you.")
            explanation.setObjectName("DialogText")
            explanation.setWordWrap(True)
            explanation.setFixedWidth(436)
            explanation.ensurePolished()          # wrapped labels report a 1-line minimum; give the real one
            explanation.setMinimumHeight(explanation.heightForWidth(436))
            v.addWidget(explanation)
            keys = QLabel(f"Your key  {e2e.fingerprint(my_public_pem)}<br>"
                          f"{contact_title}'s key  {e2e.fingerprint(contact_pem)}")
            keys.setObjectName("SessionInfo")
            v.addWidget(keys)
            if not e2e_on:
                off = QLabel("End-to-end encryption is turned OFF in your settings, so new messages "
                             "you send use transport encryption only.")
                off.setObjectName("DialogText")
                off.setWordWrap(True)
                v.addWidget(off)
            self.status = QLabel()
            self.status.setObjectName("VerifiedLabel")
            v.addWidget(self.status)

        buttons = QHBoxLayout()
        buttons.addStretch()
        if my_public_pem and contact_pem:
            self.toggle = QPushButton()
            self.toggle.setObjectName("SecondaryButton")
            self.toggle.setCursor(Qt.PointingHandCursor)
            self.toggle.clicked.connect(self._toggle_verified)
            buttons.addWidget(self.toggle)
            self._refresh()
        close = QPushButton("Close")
        close.setObjectName("PrimaryButton")
        close.setCursor(Qt.PointingHandCursor)
        close.setDefault(True)
        close.clicked.connect(self.accept)
        buttons.addWidget(close)
        v.addLayout(buttons)
        v.setSizeConstraint(QVBoxLayout.SetMinimumSize)   # never squeeze the grid into the digits

    def _refresh(self) -> None:
        self.toggle.setText("Clear verification" if self.verified else "Mark as verified")
        self.status.setText("✓ You verified this security code" if self.verified else "")

    def _toggle_verified(self) -> None:
        self.verified = not self.verified
        self._refresh()
        self.verified_changed.emit(self.verified)
