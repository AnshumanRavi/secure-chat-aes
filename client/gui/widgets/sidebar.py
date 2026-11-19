"""
Left sidebar, WhatsApp Desktop style.

Page 1 - Chats:     header (avatar, "Chats", new chat / new group / menu), search box,
                    filter chips (All | Unread | Groups), chat list
Page 2 - New chat:  green header with a back arrow, search, every contact on the server
"""

import html
import re
from typing import Optional

from PySide6.QtCore import QModelIndex, QPoint, QSize, Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QAbstractItemView, QButtonGroup, QFrame, QHBoxLayout, QLabel, QLineEdit, QListWidget,
    QListWidgetItem, QMenu, QPushButton, QSizePolicy, QStackedWidget, QVBoxLayout, QWidget,
)

from client.formatting import format_chat_time

from client.gui import icons
from client.gui.chat_store import ChatStore
from client.gui.palette import theme_icon
from client.gui.widgets.avatar import Avatar
from client.gui.widgets.banner import ConnectionBanner
from client.gui.widgets.chat_list import (
    ChatFilterProxy, ChatIdRole, ChatListDelegate, ChatListModel, ChatListView,
)

def themed_icon(svg: str, size: int = 22):
    """An icon in the current theme's grey (dark grey in light mode, light grey in dark mode)."""
    return icons.svg_icon(svg, size, theme_icon())


def icon_button(svg: str, tooltip: str, colour: Optional[str] = None, size: int = 22) -> QPushButton:
    """Round icon button. colour=None follows the theme and is re-coloured when it changes."""
    button = QPushButton()
    button.setObjectName("IconButton")
    button._svg, button._icon_px, button._fixed_colour = svg, size, colour
    button.setIcon(icons.svg_icon(svg, size, colour or theme_icon()))
    button.setIconSize(QSize(size, size))
    button.setToolTip(tooltip)
    button.setCursor(Qt.PointingHandCursor)
    button.setFixedSize(40, 40)
    return button


def set_button_svg(button: QPushButton, svg: str) -> None:
    button._svg = svg
    button.setIcon(icons.svg_icon(svg, button._icon_px, button._fixed_colour or theme_icon()))


def refresh_themed_icons(widgets) -> None:
    """After a theme change: re-colour every icon_button that follows the theme."""
    for widget in widgets:
        if isinstance(widget, QPushButton) and getattr(widget, "_svg", None) and not widget._fixed_colour:
            widget.setIcon(icons.svg_icon(widget._svg, widget._icon_px, theme_icon()))


def search_box(placeholder: str) -> QLineEdit:
    box = QLineEdit()
    box.setObjectName("SearchBox")
    box.setPlaceholderText(placeholder)
    box.setClearButtonEnabled(True)
    box.addAction(icons.svg_icon(icons.SEARCH, 18, "#8696A0"), QLineEdit.LeadingPosition)
    box.setFixedHeight(36)
    return box


class SearchResultRow(QWidget):
    """One global-search hit: chat name + time, then the message with the match in bold."""

    def __init__(self, title: str, msg, query: str, first_name, parent=None):
        super().__init__(parent)
        v = QVBoxLayout(self)
        v.setContentsMargins(20, 8, 16, 8)
        v.setSpacing(2)
        top = QHBoxLayout()
        name = QLabel(title)
        name.setObjectName("ResultTitle")
        when = QLabel(format_chat_time(msg.ts))
        when.setObjectName("ResultTime")
        top.addWidget(name, 1)
        top.addWidget(when)
        v.addLayout(top)

        text = " ".join((msg.text or msg.preview).split())
        at = text.lower().find(query.lower())
        start = max(0, at - 25) if at >= 0 else 0
        excerpt = ("…" if start else "") + text[start:start + 90]
        prefix = "You: " if msg.outgoing else (f"{first_name(msg.sender)}: " if msg.chat_id.startswith("g:") else "")
        pattern = re.compile(re.escape(query), re.IGNORECASE)
        body = pattern.sub(lambda m: f"<b>{m.group(0)}</b>", html.escape(excerpt)) if query else html.escape(excerpt)
        snippet = QLabel(html.escape(prefix) + body)
        snippet.setObjectName("ResultSnippet")
        snippet.setTextFormat(Qt.RichText)
        snippet.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        v.addWidget(snippet)
        for label in (name, when, snippet):
            label.setAttribute(Qt.WA_TransparentForMouseEvents)


class Sidebar(QWidget):
    chat_selected = Signal(str)
    message_selected = Signal(str, str, str)   # chat_id, message id, search text
    new_group_requested = Signal()
    settings_requested = Signal()
    dark_mode_requested = Signal()
    logout_requested = Signal()

    def __init__(self, store: ChatStore, profile: dict, parent=None):
        super().__init__(parent)
        self.setObjectName("Sidebar")
        self.store = store
        self.setMinimumWidth(300)

        self.model = ChatListModel(store, self)
        self.proxy = ChatFilterProxy(parent=self)
        self.proxy.setSourceModel(self.model)
        self.proxy.sort(0)
        self.contacts_proxy = ChatFilterProxy(contacts_mode=True, parent=self)
        self.contacts_proxy.setSourceModel(self.model)
        self.contacts_proxy.sort(0)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.pages = QStackedWidget()
        self.pages.addWidget(self._build_chats_page(profile))
        self.pages.addWidget(self._build_new_chat_page())
        layout.addWidget(self.pages)

    # ---------------------------------------------------------- chats page
    def _build_chats_page(self, profile: dict) -> QWidget:
        page = QWidget()
        page.setObjectName("SidebarPage")
        v = QVBoxLayout(page)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        header = QFrame()
        header.setObjectName("PanelHeader")
        header.setFixedHeight(60)
        h = QHBoxLayout(header)
        h.setContentsMargins(16, 0, 10, 0)
        h.setSpacing(4)
        self.my_avatar = Avatar(40, profile.get("display_name", "?"), profile.get("avatar_color", "#00A884"))
        self.my_avatar.setToolTip(f"{profile.get('display_name')}  (@{profile.get('username')})")
        title = QLabel("Chats")
        title.setObjectName("SidebarTitle")
        new_chat = icon_button(icons.NEW_CHAT, "New chat")
        new_chat.clicked.connect(self.show_new_chat)
        new_group = icon_button(icons.NEW_GROUP, "New group")
        new_group.clicked.connect(self.new_group_requested)
        self.menu_button = icon_button(icons.MORE_VERT, "Menu")
        self.menu_button.clicked.connect(self._show_menu)
        h.addWidget(self.my_avatar)
        h.addSpacing(12)
        h.addWidget(title)
        h.addStretch()
        for b in (new_chat, new_group, self.menu_button):
            h.addWidget(b)
        v.addWidget(header)

        self.banner = ConnectionBanner()      # yellow "Connecting…" bar, hidden while online
        v.addWidget(self.banner)

        search_row = QFrame()
        search_row.setObjectName("SearchRow")
        s = QHBoxLayout(search_row)
        s.setContentsMargins(12, 8, 12, 6)
        self.search = search_box("Search or start new chat")
        self.search.textChanged.connect(self._on_search)
        s.addWidget(self.search)
        v.addWidget(search_row)

        chips_row = QFrame()
        chips_row.setObjectName("SearchRow")
        c = QHBoxLayout(chips_row)
        c.setContentsMargins(12, 2, 12, 8)
        c.setSpacing(8)
        self._chip_group = QButtonGroup(self)
        for key, text in (("all", "All"), ("unread", "Unread"), ("groups", "Groups")):
            chip = QPushButton(text)
            chip.setObjectName("Chip")
            chip.setCheckable(True)
            chip.setCursor(Qt.PointingHandCursor)
            chip.setChecked(key == "all")
            chip.clicked.connect(lambda _=False, k=key: self._on_chip(k))
            self._chip_group.addButton(chip)
            c.addWidget(chip)
        c.addStretch()
        v.addWidget(chips_row)

        self.list_view = ChatListView()
        self.list_view.setModel(self.proxy)
        self.list_view.setItemDelegate(ChatListDelegate(name_of=self.store.first_name, parent=self.list_view))
        self.list_view.clicked.connect(self._on_clicked)
        v.addWidget(self.list_view, 1)

        self.empty_label = QLabel()
        self.empty_label.setProperty("role", "empty-state")
        self.empty_label.setAlignment(Qt.AlignHCenter | Qt.AlignTop)
        self.empty_label.setWordWrap(True)
        v.addWidget(self.empty_label, 1)

        # global search: messages from every chat that contain the search text
        self.results_label = QLabel("MESSAGES")
        self.results_label.setObjectName("SectionLabel")
        self.results = QListWidget()
        self.results.setObjectName("SearchResults")
        self.results.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.results.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.results.itemClicked.connect(self._on_result_clicked)
        self.results.setCursor(Qt.PointingHandCursor)
        for widget in (self.results_label, self.results):
            widget.hide()
        v.addWidget(self.results_label)
        v.addWidget(self.results, 2)
        self._global_timer = QTimer(self, singleShot=True, interval=250)
        self._global_timer.timeout.connect(self._run_global_search)
        for signal in (self.proxy.rowsInserted, self.proxy.rowsRemoved, self.proxy.modelReset,
                       self.proxy.layoutChanged):
            signal.connect(self._update_empty_state)
        self._chip = "all"
        self._update_empty_state()
        return page

    def _show_menu(self) -> None:
        menu = QMenu(self)
        menu.addAction(themed_icon(icons.NEW_GROUP, 18), "New group", self.new_group_requested)
        menu.addAction(themed_icon(icons.SETTINGS, 18), "Settings", self.settings_requested)
        menu.addAction(themed_icon(icons.DARK_MODE, 18), "Dark mode", self.dark_mode_requested)
        menu.addSeparator()
        menu.addAction(themed_icon(icons.LOGOUT, 18), "Log out", self.logout_requested)
        button = self.menu_button
        menu.exec(button.mapToGlobal(QPoint(button.width() - menu.sizeHint().width(), button.height() + 4)))

    def _on_search(self, text: str) -> None:
        self.proxy.set_text(text)
        self._after_filter()
        self._global_timer.start()

    def _run_global_search(self) -> None:
        query = self.search.text().strip()
        self.results.clear()
        matches = self.store.search(query) if len(query) >= 2 else []
        for msg in matches[:50]:
            chat = self.store.get(msg.chat_id)
            item = QListWidgetItem()
            item.setData(Qt.UserRole, (msg.chat_id, msg.id))
            item.setSizeHint(QSize(0, 66))
            self.results.addItem(item)
            self.results.setItemWidget(item, SearchResultRow(chat.title if chat else msg.chat_id, msg, query,
                                                             self.store.first_name))
        searching = bool(matches)
        self.results_label.setVisible(searching)
        self.results.setVisible(searching)
        # while message results are shown, keep the matching chats compact (at most 3 rows)
        rows = self.proxy.rowCount()
        self.list_view.setMaximumHeight(min(rows, 3) * 72 + 2 if searching else 16777215)
        self._update_empty_state()

    def _on_result_clicked(self, item: QListWidgetItem) -> None:
        chat_id, msg_id = item.data(Qt.UserRole)
        self.message_selected.emit(chat_id, msg_id, self.search.text().strip())

    def _on_chip(self, chip: str) -> None:
        self._chip = chip
        self.proxy.set_chip(chip)
        self._after_filter()

    def _after_filter(self) -> None:
        self._update_empty_state()
        self.select_chat(self.proxy.active_chat)   # re-filtering drops the highlight; restore it

    def _update_empty_state(self, *_) -> None:
        empty = self.proxy.rowCount() == 0
        if empty:
            if self.search.text().strip():
                text = f"No chats or contacts found for “{self.search.text().strip()}”"
            elif self._chip == "unread":
                text = "No unread chats.\nYou're all caught up! 🎉"
            elif self._chip == "groups":
                text = "No groups yet.\nCreate one with the 👥 button above."
            else:
                text = "No one else is on this server yet.\nRegister a second account to start chatting."
            self.empty_label.setText(text)
        has_results = self.results.isVisible() if hasattr(self, "results") else False
        self.list_view.setVisible(not empty)
        self.empty_label.setVisible(empty and not has_results)

    def _on_clicked(self, index: QModelIndex) -> None:
        self.chat_selected.emit(index.data(ChatIdRole))

    def select_chat(self, chat_id: Optional[str]) -> None:
        """Highlight a chat in the list (or clear the highlight)."""
        self.proxy.active_chat = chat_id
        if chat_id is None:
            self.list_view.clearSelection()
            return
        index = self.proxy.mapFromSource(self.model.index_of(chat_id))
        if index.isValid():
            self.list_view.setCurrentIndex(index)
            self.list_view.scrollTo(index)

    # ------------------------------------------------------- new chat page
    def _build_new_chat_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("SidebarPage")
        v = QVBoxLayout(page)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        header = QFrame()
        header.setObjectName("NewChatHeader")
        header.setFixedHeight(108)
        h = QHBoxLayout(header)
        h.setContentsMargins(14, 0, 20, 16)
        back = icon_button(icons.BACK, "Back", "#FFFFFF", 24)
        back.setObjectName("IconButtonOnColour")
        back.clicked.connect(self.show_chats)
        title = QLabel("New chat")
        title.setObjectName("NewChatTitle")
        h.addWidget(back, 0, Qt.AlignBottom)
        h.addSpacing(16)
        h.addWidget(title, 0, Qt.AlignBottom)
        h.addStretch()
        v.addWidget(header)

        search_row = QFrame()
        search_row.setObjectName("SearchRow")
        s = QHBoxLayout(search_row)
        s.setContentsMargins(12, 8, 12, 8)
        self.contact_search = search_box("Search name or username")
        self.contact_search.textChanged.connect(self.contacts_proxy.set_text)
        s.addWidget(self.contact_search)
        v.addWidget(search_row)

        section = QLabel("CONTACTS ON THIS SERVER")
        section.setObjectName("SectionLabel")
        v.addWidget(section)

        contacts = ChatListView()
        contacts.setModel(self.contacts_proxy)
        contacts.setItemDelegate(ChatListDelegate(contacts_mode=True, parent=contacts))
        contacts.clicked.connect(self._on_contact_clicked)
        v.addWidget(contacts, 1)
        return page

    def show_new_chat(self) -> None:
        self.contact_search.clear()
        self.pages.setCurrentIndex(1)
        self.contact_search.setFocus()

    def show_chats(self) -> None:
        self.pages.setCurrentIndex(0)

    def _on_contact_clicked(self, index: QModelIndex) -> None:
        chat_id = index.data(ChatIdRole)
        self.show_chats()
        self.search.clear()
        self.chat_selected.emit(chat_id)
