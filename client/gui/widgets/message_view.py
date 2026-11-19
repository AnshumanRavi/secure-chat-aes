"""
The scrolling conversation: encryption notice, date chips and message bubbles on the doodle wallpaper.

Scrolling behaviour (like WhatsApp):
* while you are at the bottom, new messages keep the view pinned to the bottom
* if you scrolled up to read history, new incoming messages don't yank you down;
  a round "↓" button appears with a green count of new messages instead
* sending a message always jumps to the bottom
"""

from datetime import datetime
from typing import Callable, Dict, List, Optional

from PySide6.QtCore import QPoint, QSize, Qt, Signal
from PySide6.QtGui import QPainter
from PySide6.QtWidgets import QFrame, QLabel, QPushButton, QScrollArea, QVBoxLayout, QWidget

from client.formatting import format_date_chip
from client.gui import icons, palette
from client.gui.chat_store import Message
from client.gui.widgets.bubble import CentredChip, MessageRow
from client.gui.widgets.wallpaper import wallpaper_tile

ENCRYPTION_NOTICE = ("🔒 Messages are encrypted with AES-256-GCM. "
                     "No one outside this chat can read them.")
E2E_NOTICE = ("🔒 Messages are end-to-end encrypted. No one outside of this chat, not even the "
              "SecureChat server, can read them. Click to verify.")
TRANSPORT_NOTICE = ("🔒 Messages are encrypted with AES-256-GCM between you and the server. "
                    "End-to-end encryption is off for this chat. Click to learn more.")
BUBBLE_WIDTH_RATIO = 0.65
AT_BOTTOM_SLACK = 40   # px - "close enough" to the bottom


class ScrollDownButton(QPushButton):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("ScrollDownButton")
        self.setFixedSize(42, 42)
        self.setCursor(Qt.PointingHandCursor)
        self._svg, self._icon_px, self._fixed_colour = icons.CHEVRON_DOWN, 26, None   # re-coloured with the theme
        self.setIcon(icons.svg_icon(icons.CHEVRON_DOWN, 26, palette.theme_icon()))
        self.setIconSize(QSize(26, 26))
        self.setToolTip("Scroll to bottom")
        self.badge = QLabel(self.parentWidget())
        self.badge.setObjectName("ScrollBadge")
        self.badge.setAlignment(Qt.AlignCenter)
        self.badge.hide()

    def set_count(self, count: int) -> None:
        self.badge.setText(str(count) if count < 100 else "99+")
        self.badge.adjustSize()
        self.badge.setFixedSize(max(20, self.badge.width()), 20)
        self.badge.setVisible(count > 0 and self.isVisible())
        self._place_badge()

    def _place_badge(self) -> None:
        self.badge.move(self.x() - 4, self.y() - 8)
        self.badge.raise_()

    def moveEvent(self, event) -> None:
        super().moveEvent(event)
        self._place_badge()

    def setVisible(self, visible: bool) -> None:
        super().setVisible(visible)
        if not visible:
            self.badge.hide()


class MessageView(QScrollArea):
    menu_requested = Signal(object, QPoint)   # Message, global position
    open_requested = Signal(object)           # Message - a photo or document was clicked
    reached_top = Signal()                    # scrolled to the top: time to load older history
    security_clicked = Signal()               # the encryption notice or a "security code changed" chip

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("MessageView")
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self.container = QWidget()
        self.container.setObjectName("MessageContainer")
        self.vbox = QVBoxLayout(self.container)
        self.vbox.setSpacing(0)
        self.vbox.addStretch(1)                               # few messages -> they sit at the bottom
        self.notice = CentredChip(ENCRYPTION_NOTICE, "EncryptionNotice", top_margin=4, clickable=True)
        self.notice.clicked.connect(self.security_clicked)
        self.vbox.addWidget(self.notice)
        self.setWidget(self.container)

        self._rows: Dict[str, MessageRow] = {}
        self._widgets: List[QWidget] = []                    # everything after the notice, in order
        self._last: Optional[Message] = None
        self.group_mode = False                              # show sender names above bubbles
        self.name_of: Callable[[str], str] = lambda username: username
        self._stick_to_bottom = True
        self._new_count = 0
        self._side_margin = 60
        self._keep_distance: Optional[int] = None   # px from the bottom to restore after a rebuild
        self._highlight = ("", None)                # (search query, current message id)

        self.down_button = ScrollDownButton(self)
        self.down_button.clicked.connect(self.scroll_to_bottom)
        self.down_button.hide()

        bar = self.verticalScrollBar()
        bar.rangeChanged.connect(self._on_range_changed)
        bar.valueChanged.connect(self._on_scrolled)

    # ------------------------------------------------------------- painting
    def paintEvent(self, event) -> None:
        painter = QPainter(self.viewport())
        colour, doodles = palette.wallpaper()
        tile = wallpaper_tile(background=colour, doodles=doodles, dark=palette.is_dark())
        # anchor the pattern to the content, so it scrolls along with the messages
        offset = QPoint(0, self.verticalScrollBar().value() % tile.height())
        painter.drawTiledPixmap(self.viewport().rect(), tile, offset)

    # --------------------------------------------------------------- layout
    def _bubble_max_width(self) -> int:
        return max(220, int((self.viewport().width() - 2 * self._side_margin) * BUBBLE_WIDTH_RATIO))

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._side_margin = int(min(80, max(16, self.width() * 0.06)))
        self.vbox.setContentsMargins(self._side_margin, 8, self._side_margin, 12)
        width = self._bubble_max_width()
        for row in self._rows.values():
            row.bubble.set_max_width(width)
        self.down_button.move(self.width() - self.down_button.width() - 22,
                              self.height() - self.down_button.height() - 16)

    # ------------------------------------------------------------- messages
    def clear(self) -> None:
        for widget in self._widgets:
            self.vbox.removeWidget(widget)
            widget.deleteLater()
        self._widgets.clear()
        self._rows.clear()
        self._last = None
        self._new_count = 0

    def set_messages(self, messages: List[Message], keep_position: bool = False) -> None:
        """Show these messages. keep_position=True (after loading older history above)
        keeps the same messages on screen instead of jumping."""
        bar = self.verticalScrollBar()
        if keep_position:
            self._stick_to_bottom = False
            self._keep_distance = bar.maximum() - bar.value()
        self.setUpdatesEnabled(False)
        self.clear()
        for msg in messages:
            self._append(msg)
        self.setUpdatesEnabled(True)
        if not keep_position:
            self.scroll_to_bottom()
        if self._highlight[0]:
            self.highlight(*self._highlight)

    def highlight(self, query: str, current_id: Optional[str] = None) -> None:
        """Highlight search matches in all text bubbles; scroll the current match into view."""
        self._highlight = (query, current_id)
        for msg_id, row in self._rows.items():
            if hasattr(row.bubble, "highlight"):
                row.bubble.highlight(query, msg_id == current_id)
        if current_id:
            self.scroll_to_message(current_id)

    def scroll_to_message(self, msg_id: str) -> None:
        row = self._rows.get(msg_id)
        if row is not None:
            self._stick_to_bottom = False
            self.container.adjustSize()
            self.ensureWidgetVisible(row, 0, max(60, self.viewport().height() // 3))

    def add_message(self, msg: Message) -> None:
        if msg.id in self._rows:
            return
        self._append(msg)
        if msg.system:
            return
        if msg.outgoing:
            self.scroll_to_bottom()
        elif not self._stick_to_bottom:
            self._new_count += 1
            self.down_button.set_count(self._new_count)

    def update_message(self, msg: Message) -> None:
        row = self._rows.get(msg.id)
        if row:
            row.bubble.refresh_status()

    def row(self, msg_id: str) -> Optional[MessageRow]:
        return self._rows.get(msg_id)

    def _append(self, msg: Message) -> None:
        previous = self._last
        new_day = previous is None or \
            datetime.fromtimestamp(previous.ts).date() != datetime.fromtimestamp(msg.ts).date()
        if new_day:
            chip = CentredChip(format_date_chip(msg.ts), "DateChip")
            self.vbox.addWidget(chip)
            self._widgets.append(chip)
        if msg.system:                                        # "Bob left", "You created group …"
            security = msg.kind == "security"                 # "Bob's security code changed"
            chip = CentredChip(("🔐 " if security else "") + msg.text,
                               "SecurityChip" if security else "SystemChip", top_margin=10, clickable=security)
            if security:
                chip.clicked.connect(self.security_clicked)
            self.vbox.addWidget(chip)
            self._widgets.append(chip)
            self._last = msg
            return
        first_in_group = new_day or previous.system or previous.sender != msg.sender
        show_name = self.group_mode and first_in_group and not msg.outgoing
        row = MessageRow(msg, first_in_group, self.name_of(msg.sender) if show_name else "")
        row.bubble.set_max_width(self._bubble_max_width())
        row.bubble.menu_requested.connect(self.menu_requested)
        row.bubble.open_requested.connect(self.open_requested)
        self.vbox.addWidget(row)
        self._widgets.append(row)
        self._rows[msg.id] = row
        self._last = msg

    # ------------------------------------------------------------- scrolling
    def _is_at_bottom(self) -> bool:
        bar = self.verticalScrollBar()
        return bar.value() >= bar.maximum() - AT_BOTTOM_SLACK

    def _on_range_changed(self, _minimum: int, maximum: int) -> None:
        if self._keep_distance is not None:            # older messages were added above
            self.verticalScrollBar().setValue(maximum - self._keep_distance)
            self._keep_distance = None
        elif self._stick_to_bottom:
            self.verticalScrollBar().setValue(maximum)

    def _on_scrolled(self, value: int) -> None:
        if value == 0 and self.verticalScrollBar().maximum() > 0 and self._keep_distance is None:
            self.reached_top.emit()
        self._stick_to_bottom = self._is_at_bottom()
        if self._stick_to_bottom:
            self._new_count = 0
        self.down_button.setVisible(not self._stick_to_bottom)
        self.down_button.set_count(self._new_count)
        if self.down_button.isVisible():
            self.down_button.raise_()

    def scroll_to_bottom(self) -> None:
        self._stick_to_bottom = True
        self._new_count = 0
        bar = self.verticalScrollBar()
        bar.setValue(bar.maximum())
        self.down_button.hide()
