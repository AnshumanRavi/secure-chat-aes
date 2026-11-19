"""Emoji picker popup (opens above the 😊 button): category tabs on top, a grid of emoji below."""

from typing import Dict, List

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QButtonGroup, QFrame, QGridLayout, QHBoxLayout, QLabel, QPushButton, QScrollArea,
    QVBoxLayout, QWidget,
)

from client.gui.emoji_data import CATEGORIES

COLUMNS = 9
MAX_RECENT = 27
EMOJI_FONT = "Segoe UI Emoji"


class EmojiPicker(QFrame):
    emoji_selected = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent, Qt.Popup | Qt.FramelessWindowHint)
        self.setObjectName("EmojiPicker")
        self.setFixedSize(9 * 40 + 34, 380)
        self.recent: List[str] = []
        self._categories = [("recent", "🕘", "Recently used", self.recent)] + CATEGORIES
        self._tabs: Dict[str, QPushButton] = {}

        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        tab_bar = QFrame()
        tab_bar.setObjectName("EmojiTabBar")
        tabs = QHBoxLayout(tab_bar)
        tabs.setContentsMargins(8, 6, 8, 0)
        tabs.setSpacing(0)
        group = QButtonGroup(self)
        tab_font = QFont(EMOJI_FONT)
        tab_font.setPixelSize(18)
        for key, icon, title, _ in self._categories:
            tab = QPushButton(icon)
            tab.setObjectName("EmojiTab")
            tab.setFont(tab_font)
            tab.setCheckable(True)
            tab.setToolTip(title)
            tab.setCursor(Qt.PointingHandCursor)
            tab.clicked.connect(lambda _=False, k=key: self.show_category(k))
            group.addButton(tab)
            tabs.addWidget(tab)
            self._tabs[key] = tab
        v.addWidget(tab_bar)

        self.title = QLabel()
        self.title.setObjectName("EmojiCategoryTitle")
        v.addWidget(self.title)

        self.scroll = QScrollArea()
        self.scroll.setObjectName("EmojiScroll")
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.NoFrame)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        v.addWidget(self.scroll, 1)

        self._emoji_font = QFont(EMOJI_FONT)
        self._emoji_font.setPixelSize(24)
        self.show_category("smileys")

    def show_category(self, key: str) -> None:
        _, _, title, emoji_list = next(c for c in self._categories if c[0] == key)
        self._tabs[key].setChecked(True)
        self.title.setText(title.upper())

        grid_widget = QWidget()
        grid_widget.setObjectName("EmojiGrid")
        grid = QGridLayout(grid_widget)
        grid.setContentsMargins(10, 0, 10, 10)
        grid.setSpacing(0)
        if not emoji_list:
            empty = QLabel("Emoji you use will show up here")
            empty.setProperty("role", "hint")
            grid.addWidget(empty, 0, 0)
        for i, item in enumerate(emoji_list):
            button = QPushButton(item)
            button.setObjectName("EmojiButton")
            button.setFont(self._emoji_font)
            button.setFixedSize(40, 40)
            button.setCursor(Qt.PointingHandCursor)
            button.clicked.connect(lambda _=False, e=item: self._pick(e))
            grid.addWidget(button, i // COLUMNS, i % COLUMNS)
        grid.setRowStretch(grid.rowCount(), 1)
        self.scroll.setWidget(grid_widget)

    def _pick(self, item: str) -> None:
        if item in self.recent:
            self.recent.remove(item)
        self.recent.insert(0, item)
        del self.recent[MAX_RECENT:]
        self.emoji_selected.emit(item)

    def popup_above(self, anchor: QWidget) -> None:
        """Open just above the input bar, aligned with its left edge."""
        top_left = anchor.mapToGlobal(QPoint(0, 0))
        self.move(top_left.x() + 8, top_left.y() - self.height() - 6)
        self.show()
