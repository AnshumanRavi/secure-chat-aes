"""
"Group info" panel that slides in from the right of the chat (like WhatsApp Desktop):
big group avatar, name, description, members (with a "Group admin" badge) and "Leave group".
"""

from typing import Callable, Optional

from PySide6.QtCore import QEasingCurve, QPoint, QPropertyAnimation, Qt, Signal
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QPushButton, QScrollArea, QSizePolicy, QVBoxLayout, QWidget,
)

from client.gui import icons
from client.gui.chat_store import Conversation
from client.gui.widgets.avatar import Avatar
from client.gui.widgets.sidebar import icon_button

PANEL_WIDTH = 380


class MemberRow(QFrame):
    def __init__(self, display: str, real_name: str, subtitle: str, colour: str, admin: bool, parent=None):
        super().__init__(parent)
        self.setObjectName("MemberRow")
        h = QHBoxLayout(self)
        h.setContentsMargins(24, 10, 20, 10)
        h.setSpacing(14)
        avatar = Avatar(40, real_name, colour)   # initials of the real name, even for "You"
        h.addWidget(avatar)
        texts = QVBoxLayout()
        texts.setSpacing(1)
        name = QLabel(display)
        name.setObjectName("MemberName")
        about = QLabel(subtitle)
        about.setObjectName("MemberAbout")
        for label in (name, about):   # let long text be cut off instead of pushing the badge out
            label.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        texts.addWidget(name)
        texts.addWidget(about)
        h.addLayout(texts, 1)
        if admin:
            badge = QLabel("Group admin")
            badge.setObjectName("AdminBadge")
            h.addWidget(badge, 0, Qt.AlignVCenter)


class GroupInfoPanel(QFrame):
    closed = Signal()
    leave_requested = Signal(str)   # chat_id

    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self.setObjectName("GroupInfo")
        self.setFixedWidth(PANEL_WIDTH)
        self.chat: Optional[Conversation] = None
        self._animation = QPropertyAnimation(self, b"pos", self)
        self._animation.setDuration(220)
        self._animation.setEasingCurve(QEasingCurve.OutCubic)
        self._animation.finished.connect(self._on_animation_finished)
        self._hide_after = False

        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        header = QFrame()
        header.setObjectName("PanelHeader")
        header.setFixedHeight(60)
        h = QHBoxLayout(header)
        h.setContentsMargins(12, 0, 16, 0)
        close = icon_button(icons.CLOSE, "Close", None, 22)
        close.clicked.connect(self.slide_out)
        title = QLabel("Group info")
        title.setObjectName("ChatTitle")
        h.addWidget(close)
        h.addSpacing(18)
        h.addWidget(title)
        h.addStretch()
        v.addWidget(header)

        scroll = QScrollArea()
        scroll.setObjectName("GroupInfoScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.body = QWidget()
        self.body.setObjectName("GroupInfoBody")
        self.body_layout = QVBoxLayout(self.body)
        self.body_layout.setContentsMargins(0, 0, 0, 0)
        self.body_layout.setSpacing(10)
        scroll.setWidget(self.body)
        v.addWidget(scroll, 1)
        self.hide()

    # ----------------------------------------------------------- contents
    def set_group(self, chat: Conversation, me: str, name_of: Callable[[str], str],
                  about_of: Callable[[str], str], colour_of: Callable[[str], str],
                  real_name_of_me: str = "") -> None:
        self.chat = chat
        real_name_of_me = real_name_of_me or me
        layout = self.body_layout
        while layout.count():
            item = layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        # --- card: avatar, name, member count, description
        card = QFrame()
        card.setObjectName("InfoCard")
        c = QVBoxLayout(card)
        c.setContentsMargins(24, 28, 24, 22)
        c.setSpacing(6)
        avatar = Avatar(160, chat.title, chat.avatar_color)
        avatar.set_person(chat.title, chat.avatar_color, group=True)
        c.addWidget(avatar, 0, Qt.AlignHCenter)
        c.addSpacing(8)
        name = QLabel(chat.title)
        name.setObjectName("InfoTitle")
        name.setAlignment(Qt.AlignCenter)
        name.setWordWrap(True)
        c.addWidget(name)
        count = QLabel(f"Group · {len(chat.members)} member{'s' if len(chat.members) != 1 else ''}")
        count.setObjectName("InfoSubtitle")
        count.setAlignment(Qt.AlignCenter)
        c.addWidget(count)
        layout.addWidget(card)

        if chat.about:
            description = QFrame()
            description.setObjectName("InfoCard")
            d = QVBoxLayout(description)
            d.setContentsMargins(24, 14, 24, 16)
            heading = QLabel("Description")
            heading.setObjectName("InfoSection")
            text = QLabel(chat.about)
            text.setObjectName("InfoText")
            text.setWordWrap(True)
            d.addWidget(heading)
            d.addWidget(text)
            layout.addWidget(description)

        # --- members: me first, then admins, then A-Z
        members_card = QFrame()
        members_card.setObjectName("InfoCard")
        m = QVBoxLayout(members_card)
        m.setContentsMargins(0, 14, 0, 8)
        m.setSpacing(0)
        heading = QLabel(f"{len(chat.members)} members")
        heading.setObjectName("InfoSection")
        heading.setContentsMargins(24, 0, 24, 6)
        m.addWidget(heading)
        ordered = sorted(chat.members, key=lambda x: (x["username"] != me, x["role"] != "admin",
                                                      name_of(x["username"]).lower()))
        for member in ordered:
            username = member["username"]
            m.addWidget(MemberRow("You" if username == me else name_of(username),
                                  name_of(username) if username != me else real_name_of_me,
                                  about_of(username), colour_of(username), member["role"] == "admin"))
        layout.addWidget(members_card)

        # --- leave
        actions = QFrame()
        actions.setObjectName("InfoCard")
        a = QVBoxLayout(actions)
        a.setContentsMargins(12, 6, 12, 6)
        if chat.left:
            note = QLabel("You're no longer a member of this group")
            note.setObjectName("InfoSubtitle")
            note.setContentsMargins(12, 10, 12, 10)
            a.addWidget(note)
        else:
            leave = QPushButton("  Leave group")
            leave.setObjectName("DangerLink")
            leave.setIcon(icons.svg_icon(icons.LOGOUT, 22, "#EA0038"))
            leave.setCursor(Qt.PointingHandCursor)
            leave.clicked.connect(lambda: self.leave_requested.emit(chat.chat_id))
            a.addWidget(leave, 0, Qt.AlignLeft)
        layout.addWidget(actions)
        layout.addStretch()

    # ------------------------------------------------------------ sliding
    def place(self) -> None:
        """Keep the panel glued to the right edge when the window is resized."""
        parent = self.parentWidget()
        self.setFixedHeight(parent.height())
        if self.isVisible() and self._animation.state() != QPropertyAnimation.Running:
            self.move(parent.width() - self.width(), 0)

    def slide_in(self) -> None:
        parent = self.parentWidget()
        self.setFixedHeight(parent.height())
        self.move(parent.width(), 0)
        self.show()
        self.raise_()
        self._animate(QPoint(parent.width() - self.width(), 0))

    def slide_out(self) -> None:
        if not self.isVisible():
            return
        self._animate(QPoint(self.parentWidget().width(), 0), hide_after=True)

    def _animate(self, end: QPoint, hide_after: bool = False) -> None:
        self._animation.stop()
        self._hide_after = hide_after
        self._animation.setStartValue(self.pos())
        self._animation.setEndValue(end)
        self._animation.start()

    def _on_animation_finished(self) -> None:
        if self._hide_after:
            self.hide()
            self.closed.emit()
