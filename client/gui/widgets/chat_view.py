"""
Right-hand pane.

IntroPanel  shown when no chat is open ("SecureChat for Windows", like WhatsApp's intro screen)
ChatPanel   header (avatar, name, online / last seen / typing…, search, menu),
            the conversation (MessageView) and the input bar
"""

from pathlib import Path
from typing import Callable, Dict, Optional

from PySide6.QtCore import QPoint, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QMenu, QVBoxLayout, QWidget

from client.formatting import format_last_seen
from client.gui import icons, palette
from client.gui.chat_store import Conversation
from client.gui.widgets.avatar import Avatar
from client.gui.widgets.group_info import GroupInfoPanel
from client.gui.widgets.input_bar import InputBar
from client.gui.widgets.message_view import E2E_NOTICE, ENCRYPTION_NOTICE, TRANSPORT_NOTICE, MessageView
from client.gui.widgets.sidebar import icon_button, search_box, themed_icon


class IntroPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("IntroPanel")
        v = QVBoxLayout(self)
        v.setContentsMargins(40, 0, 40, 34)
        v.addStretch(3)

        art = QLabel()
        art.setPixmap(icons.svg_pixmap(icons.INTRO_ART, 320))
        art.setAlignment(Qt.AlignCenter)
        v.addWidget(art)
        v.addSpacing(24)

        title = QLabel("SecureChat for Windows")
        title.setObjectName("IntroTitle")
        title.setAlignment(Qt.AlignCenter)
        v.addWidget(title)
        v.addSpacing(14)

        text = QLabel("Send and receive messages securely. Every message is encrypted with\n"
                      "AES-256-GCM before it leaves your computer, using a session key\n"
                      "exchanged with RSA-2048.")
        text.setObjectName("IntroText")
        text.setAlignment(Qt.AlignCenter)
        v.addWidget(text)
        v.addStretch(4)

        footer = QHBoxLayout()
        footer.addStretch()
        lock = QLabel()
        lock.setPixmap(icons.svg_pixmap(icons.LOCK, 13, "#8696A0"))
        note = QLabel("Your messages are end-to-end encrypted")
        note.setObjectName("IntroFooter")
        footer.addWidget(lock)
        footer.addSpacing(6)
        footer.addWidget(note)
        footer.addStretch()
        v.addLayout(footer)

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor(palette.current().intro_bg))
        painter.fillRect(0, self.height() - 6, self.width(), 6, QColor(palette.current().badge))


class ClickableHeader(QFrame):
    clicked = Signal()

    def mouseReleaseEvent(self, event) -> None:
        if event.button() == Qt.LeftButton:
            self.clicked.emit()
        super().mouseReleaseEvent(event)


class ChatPanel(QWidget):
    close_requested = Signal()
    info_requested = Signal()
    files_dropped = Signal(list)    # local file paths dragged onto the chat
    security_requested = Signal()   # show the "Verify security code" screen

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("ChatPanel")
        self.chat: Optional[Conversation] = None
        self.me = ""
        self.name_of: Callable[[str], str] = lambda username: username
        self._drafts: Dict[str, str] = {}   # unsent text per chat, like WhatsApp

        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        header = ClickableHeader()
        header.setObjectName("PanelHeader")
        header.setFixedHeight(60)
        header.setCursor(Qt.PointingHandCursor)
        header.setToolTip("Click for info")
        header.clicked.connect(self.info_requested)
        h = QHBoxLayout(header)
        h.setContentsMargins(16, 0, 10, 0)
        h.setSpacing(4)
        self.avatar = Avatar(40)
        names = QVBoxLayout()
        names.setSpacing(0)
        names.setContentsMargins(0, 0, 0, 0)
        self.title = QLabel()
        self.title.setObjectName("ChatTitle")
        self.status = QLabel()
        self.status.setObjectName("ChatStatus")
        names.addStretch()
        names.addWidget(self.title)
        names.addWidget(self.status)
        names.addStretch()
        search = icon_button(icons.SEARCH, "Search messages")
        search.clicked.connect(lambda: self.open_search())
        self.menu_button = icon_button(icons.MORE_VERT, "Menu")
        self.menu_button.clicked.connect(self._show_menu)
        h.addWidget(self.avatar)
        h.addSpacing(12)
        h.addLayout(names, 1)
        h.addWidget(search)
        h.addWidget(self.menu_button)
        v.addWidget(header)

        # in-chat search bar (hidden until the 🔍 button is clicked)
        self.search_bar = QFrame()
        self.search_bar.setObjectName("ChatSearchBar")
        s = QHBoxLayout(self.search_bar)
        s.setContentsMargins(14, 8, 10, 8)
        s.setSpacing(4)
        self.search_box = search_box("Search messages in this chat")
        self.search_count = QLabel()
        self.search_count.setObjectName("SearchCount")
        self.search_count.setAlignment(Qt.AlignCenter)
        older = icon_button(icons.CHEVRON_UP, "Older match (Enter)")
        newer = icon_button(icons.CHEVRON_DOWN, "Newer match (Shift+Enter)")
        close_search = icon_button(icons.CLOSE, "Close search (Esc)")
        older.clicked.connect(lambda: self._step_search(+1))
        newer.clicked.connect(lambda: self._step_search(-1))
        close_search.clicked.connect(self.close_search)
        s.addWidget(self.search_box, 1)
        s.addWidget(self.search_count)
        for button in (older, newer, close_search):
            s.addWidget(button)
        self.search_bar.hide()
        v.addWidget(self.search_bar)
        self._search_timer = QTimer(self, singleShot=True, interval=220)
        self._search_timer.timeout.connect(self._run_search)
        self.search_box.textChanged.connect(lambda _: self._search_timer.start())
        self.search_box.returnPressed.connect(lambda: self._step_search(+1))
        self.search_provider: Optional[Callable] = None   # (query, chat_id) -> [Message], newest first
        self.older_provider: Optional[Callable] = None    # (chat_id) -> number of older messages loaded
        self._results = []
        self._result_index = 0

        self.messages = MessageView()
        self.messages.reached_top.connect(self._load_older)
        self.messages.security_clicked.connect(self.security_requested)
        self.e2e_provider: Optional[Callable] = None      # (chat) -> True if E2E is active for it
        v.addWidget(self.messages, 1)
        self.input_bar = InputBar()
        v.addWidget(self.input_bar)
        self.left_notice = QLabel("You can't send messages to this group because you're no longer a member.")
        self.left_notice.setObjectName("LeftNotice")
        self.left_notice.setAlignment(Qt.AlignCenter)
        self.left_notice.hide()
        v.addWidget(self.left_notice)

        self.group_info = GroupInfoPanel(self)   # slides in over the right side

        # drag & drop files onto the chat to send them
        self.setAcceptDrops(True)
        self.drop_overlay = QLabel("Drop files here to send them\n🔒 encrypted with AES-256-GCM", self)
        self.drop_overlay.setObjectName("DropOverlay")
        self.drop_overlay.setAlignment(Qt.AlignCenter)
        self.drop_overlay.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.drop_overlay.hide()

        # "last seen today at ..." changes with time, so refresh the header every minute
        self._clock = QTimer(self, interval=60_000)
        self._clock.timeout.connect(self.refresh)
        self._clock.start()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self.group_info.place()

    # ------------------------------------------------------------ drag & drop
    @staticmethod
    def _local_files(event):
        urls = event.mimeData().urls() if event.mimeData().hasUrls() else []
        paths = [u.toLocalFile() for u in urls if u.isLocalFile()]
        return [p for p in paths if Path(p).is_file()]

    def dragEnterEvent(self, event) -> None:
        if self.chat is not None and not self.chat.left and self._local_files(event):
            event.acceptProposedAction()
            area = self.messages.geometry()
            self.drop_overlay.setGeometry(area.adjusted(16, 16, -16, -16))
            self.drop_overlay.show()
            self.drop_overlay.raise_()

    def dragMoveEvent(self, event) -> None:
        event.acceptProposedAction()

    def dragLeaveEvent(self, event) -> None:
        self.drop_overlay.hide()

    def dropEvent(self, event) -> None:
        self.drop_overlay.hide()
        files = self._local_files(event)
        if files:
            event.acceptProposedAction()
            self.files_dropped.emit(files)

    def _show_menu(self) -> None:
        menu = QMenu(self)
        is_group = self.chat is not None and self.chat.is_group
        menu.addAction(themed_icon(icons.INFO, 18), "Group info" if is_group else "Contact info",
                       self.info_requested)
        if not is_group:
            menu.addAction(themed_icon(icons.SHIELD_CHECK, 18), "Verify security code", self.security_requested)
        menu.addAction(themed_icon(icons.CLOSE, 18), "Close chat", self.close_requested)
        b = self.menu_button
        menu.exec(b.mapToGlobal(QPoint(b.width() - menu.sizeHint().width(), b.height() + 4)))

    def set_conversation(self, chat: Conversation) -> None:
        if self.chat is not None:
            self._drafts[self.chat.chat_id] = self.input_bar.text()
        switching = self.chat is not chat
        self.chat = chat
        self.refresh()
        if switching:
            self.close_search()
            self.group_info.hide()
            self.messages.group_mode = chat.is_group
            self.messages.name_of = self.name_of
            self.messages.set_messages(chat.messages)
            self.input_bar.set_text(self._drafts.pop(chat.chat_id, ""))
        self.input_bar.focus()

    def reload_messages(self, keep_position: bool = False) -> None:
        if self.chat:
            self.messages.set_messages(self.chat.messages, keep_position)

    # ----------------------------------------------------- history & search
    def _load_older(self) -> None:
        """Scrolled to the top: pull the previous page from the encrypted local history."""
        if self.chat and self.older_provider and self.older_provider(self.chat.chat_id):
            self.reload_messages(keep_position=True)

    def open_search(self, query: str = "", jump_to: Optional[str] = None) -> None:
        self.search_bar.show()
        self.search_box.setFocus()
        if query:
            self.search_box.blockSignals(True)
            self.search_box.setText(query)
            self.search_box.blockSignals(False)
            self._run_search(jump_to)

    def close_search(self) -> None:
        if self.search_bar.isVisible():
            self.search_bar.hide()
            self.search_box.blockSignals(True)
            self.search_box.clear()
            self.search_box.blockSignals(False)
        self._results = []
        self.messages.highlight("")
        self.input_bar.focus()

    def _run_search(self, jump_to: Optional[str] = None) -> None:
        query = self.search_box.text().strip()
        if not (self.chat and self.search_provider and query):
            self._results = []
            self.search_count.setText("")
            self.messages.highlight("")
            return
        loaded = len(self.chat.messages)
        self._results = self.search_provider(query, self.chat.chat_id)
        if len(self.chat.messages) != loaded:             # the search pulled in older history
            self.reload_messages(keep_position=True)
        ids = [m.id for m in self._results]
        self._result_index = ids.index(jump_to) if jump_to in ids else 0
        self._show_result()

    def _step_search(self, step: int) -> None:
        if self._results:
            self._result_index = (self._result_index + step) % len(self._results)
            self._show_result()

    def _show_result(self) -> None:
        query = self.search_box.text().strip()
        if not self._results:
            self.search_count.setText("No results")
            self.messages.highlight(query)
            return
        self.search_count.setText(f"{self._result_index + 1} of {len(self._results)}")
        self.messages.highlight(query, self._results[self._result_index].id)

    def keyPressEvent(self, event) -> None:
        if event.key() == Qt.Key_Escape and self.search_bar.isVisible():
            self.close_search()
            return
        super().keyPressEvent(event)

    def refresh(self) -> None:
        chat = self.chat
        if chat is None:
            return
        self.avatar.set_person(chat.title, chat.avatar_color, group=chat.is_group)
        self.title.setText(chat.title)
        if chat.is_group:                       # "Alice, Bob, Carol, You" like WhatsApp
            others = sorted((self.name_of(u) for u in chat.member_names() if u != self.me), key=str.lower)
            names = ", ".join(others + (["You"] if not chat.left else []))
            text = self.status.fontMetrics().elidedText(names, Qt.ElideRight, 480)
            typing = False
        elif chat.typing:
            text, typing = "typing…", True
        else:
            text, typing = format_last_seen(chat.online, chat.last_seen), False
            if text == "offline":
                text = f"@{chat.chat_id}"
        self.input_bar.setVisible(not chat.left)
        self.left_notice.setVisible(chat.left)
        self.status.setText(text)
        if chat.is_group:
            notice = ENCRYPTION_NOTICE
        elif self.e2e_provider is not None and self.e2e_provider(chat):
            notice = E2E_NOTICE
        else:
            notice = TRANSPORT_NOTICE
        if self.messages.notice.label.text() != notice:
            self.messages.notice.set_text(notice)
        self.status.setProperty("typing", typing)
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)
