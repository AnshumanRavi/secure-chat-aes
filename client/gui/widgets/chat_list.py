"""
The chat list in the sidebar (model + filter/sort proxy + painter), WhatsApp style.

    ChatListModel     one row per conversation in the ChatStore
    ChatFilterProxy   search box + filter chips, and sorting (latest message first)
    ChatListDelegate  paints each row: avatar, name, time, preview with ticks, unread badge
"""

from typing import Optional

from PySide6.QtCore import QAbstractListModel, QModelIndex, QRectF, QSize, QSortFilterProxyModel, Qt
from PySide6.QtGui import QColor, QFont, QFontMetrics, QPainter
from PySide6.QtWidgets import QAbstractItemView, QListView, QStyle, QStyledItemDelegate

from client.formatting import format_chat_time
from client.gui import icons, palette
from client.gui.chat_store import ChatStore, Conversation
from client.gui.widgets.avatar import paint_avatar

ConversationRole = Qt.UserRole + 1
ChatIdRole = Qt.UserRole + 2

ROW_HEIGHT = 72
AVATAR_SIZE = 49

# status -> (icon, colour) for the ticks next to my own messages
STATUS_ICONS = {
    "pending":   (icons.CLOCK, "#8696A0"),
    "sent":      (icons.TICK, "#8696A0"),
    "delivered": (icons.DOUBLE_TICK, "#8696A0"),
    "read":      (icons.DOUBLE_TICK, "#53BDEB"),
    "failed":    (icons.WARNING, "#EA0038"),
}


def status_pixmap(status: str, size: int = 16):
    svg, colour = STATUS_ICONS.get(status, STATUS_ICONS["pending"])
    return icons.svg_pixmap(svg, size, colour)


class ChatListModel(QAbstractListModel):
    def __init__(self, store: ChatStore, parent=None):
        super().__init__(parent)
        self.store = store
        self._ids = [c.chat_id for c in store.conversations()]
        store.conversation_added.connect(self._on_added)
        store.conversation_changed.connect(self._on_changed)

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._ids)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):
        if not index.isValid():
            return None
        chat_id = self._ids[index.row()]
        if role == Qt.DisplayRole:
            return self.store.get(chat_id).title
        if role == ConversationRole:
            return self.store.get(chat_id)
        if role == ChatIdRole:
            return chat_id
        return None

    def index_of(self, chat_id: str) -> QModelIndex:
        return self.index(self._ids.index(chat_id)) if chat_id in self._ids else QModelIndex()

    def _on_added(self, chat_id: str) -> None:
        if chat_id not in self._ids:
            self.beginInsertRows(QModelIndex(), len(self._ids), len(self._ids))
            self._ids.append(chat_id)
            self.endInsertRows()

    def _on_changed(self, chat_id: str) -> None:
        index = self.index_of(chat_id)
        if index.isValid():
            self.dataChanged.emit(index, index)   # proxy re-sorts and re-filters automatically


class ChatFilterProxy(QSortFilterProxyModel):
    """Filters by search text and chip (all / unread / groups); sorts newest chat first."""

    def __init__(self, contacts_mode: bool = False, parent=None):
        super().__init__(parent)
        self.contacts_mode = contacts_mode
        self.active_chat: Optional[str] = None
        self._text = ""
        self._chip = "all"
        self.setDynamicSortFilter(True)

    def set_text(self, text: str) -> None:
        self._text = text.strip().lower()
        self.invalidate()

    def set_chip(self, chip: str) -> None:
        self._chip = chip
        self.invalidate()

    def filterAcceptsRow(self, row: int, parent: QModelIndex) -> bool:
        chat: Conversation = self.sourceModel().index(row, 0, parent).data(ConversationRole)
        if self.contacts_mode and chat.is_group:    # "New chat" lists people, not groups
            return False
        if self._chip == "unread" and not chat.unread and chat.chat_id != self.active_chat:
            return False
        if self._chip == "groups" and chat.kind != "group":
            return False
        if self._text:
            haystack = f"{chat.title} {chat.chat_id}".lower()
            if not self.contacts_mode and chat.last_message:
                haystack += " " + chat.last_message.preview.lower()
            return self._text in haystack
        return True

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
        a: Conversation = left.data(ConversationRole)
        b: Conversation = right.data(ConversationRole)
        if self.contacts_mode:
            return a.title.lower() < b.title.lower()
        # newest message first; chats without messages: online people first, then A-Z
        return (-a.last_activity, not a.online, a.title.lower()) < (-b.last_activity, not b.online, b.title.lower())


class ChatListDelegate(QStyledItemDelegate):
    def __init__(self, contacts_mode: bool = False, name_of=None, parent=None):
        super().__init__(parent)
        self.contacts_mode = contacts_mode
        self.name_of = name_of or (lambda username: username)   # username -> short display name

    def sizeHint(self, option, index) -> QSize:
        return QSize(option.rect.width(), ROW_HEIGHT)

    @staticmethod
    def _font(base: QFont, px: int, bold: bool = False) -> QFont:
        font = QFont(base)
        font.setPixelSize(px)
        font.setWeight(QFont.DemiBold if bold else QFont.Normal)
        return font

    def paint(self, painter: QPainter, option, index: QModelIndex) -> None:
        chat: Conversation = index.data(ConversationRole)
        if chat is None:
            return
        r = option.rect
        selected = bool(option.state & QStyle.State_Selected)
        hovered = bool(option.state & QStyle.State_MouseOver)
        colours = palette.current()
        background = colours.row_selected if selected else colours.row_hover if hovered else colours.sidebar

        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setRenderHint(QPainter.TextAntialiasing)
        painter.fillRect(r, QColor(background))

        avatar = QRectF(r.left() + 13, r.top() + (ROW_HEIGHT - AVATAR_SIZE) / 2, AVATAR_SIZE, AVATAR_SIZE)
        paint_avatar(painter, avatar, chat.title, chat.avatar_color, chat.online and not chat.is_group,
                     ring_color=background, group=chat.is_group)

        x = r.left() + 77
        right = r.right() - 15
        width = right - x
        if not (selected or hovered):
            painter.setPen(QColor(colours.divider))
            painter.drawLine(x, r.bottom(), r.right(), r.bottom())

        # --- first line: name ............................ time
        top = r.top() + 13
        last = chat.last_message
        time_text = "" if self.contacts_mode or last is None else format_chat_time(last.ts)
        time_font = self._font(option.font, 12)
        time_width = QFontMetrics(time_font).horizontalAdvance(time_text)
        painter.setFont(time_font)
        painter.setPen(QColor(colours.accent if chat.unread else colours.text_secondary))
        painter.drawText(QRectF(right - time_width, top, time_width, 24), Qt.AlignRight | Qt.AlignVCenter, time_text)

        name_font = self._font(option.font, 16, bold=bool(chat.unread) and not self.contacts_mode)
        name_width = width - time_width - 8
        painter.setFont(name_font)
        painter.setPen(QColor(colours.text))
        painter.drawText(QRectF(x, top, name_width, 24), Qt.AlignLeft | Qt.AlignVCenter,
                         QFontMetrics(name_font).elidedText(chat.title, Qt.ElideRight, int(name_width)))

        # --- second line: [ticks] preview ................ (unread badge)
        y2 = top + 26
        available = width
        if chat.unread and not self.contacts_mode:
            badge_font = self._font(option.font, 12, bold=True)
            count = str(chat.unread) if chat.unread < 100 else "99+"
            badge_width = max(20, QFontMetrics(badge_font).horizontalAdvance(count) + 12)
            badge = QRectF(right - badge_width, y2 + 1, badge_width, 20)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(colours.badge))
            painter.drawRoundedRect(badge, 10, 10)
            painter.setFont(badge_font)
            painter.setPen(QColor(colours.badge_text))
            painter.drawText(badge, Qt.AlignCenter, count)
            available -= badge_width + 8

        px = x
        preview_colour = colours.text_secondary
        if self.contacts_mode:
            preview = chat.about
        elif chat.typing:
            preview, preview_colour = "typing…", colours.accent
        elif last is not None and last.system:
            preview, preview_colour = last.text, colours.text_muted
        elif last is not None:
            if last.outgoing:
                painter.drawPixmap(int(px), int(y2 + 3), status_pixmap(last.status, 16))
                px += 20
                available -= 20
            preview = " ".join(last.preview.split())
            if chat.is_group and not last.outgoing:      # "Bob: see you at 5"
                preview = f"{self.name_of(last.sender)}: {preview}"
            if chat.unread:
                preview_colour = colours.text
        else:
            preview, preview_colour = chat.about or "Say hi 👋", colours.text_muted

        preview_font = self._font(option.font, 14)
        preview_font.setItalic(chat.typing and not self.contacts_mode)
        painter.setFont(preview_font)
        painter.setPen(QColor(preview_colour))
        painter.drawText(QRectF(px, y2, available, 22), Qt.AlignLeft | Qt.AlignVCenter,
                         QFontMetrics(preview_font).elidedText(preview, Qt.ElideRight, int(available)))
        painter.restore()


class ChatListView(QListView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("ChatList")
        self.setMouseTracking(True)
        self.viewport().setAttribute(Qt.WA_Hover)
        self.setUniformItemSizes(True)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setFocusPolicy(Qt.NoFocus)
        self.setCursor(Qt.PointingHandCursor)
