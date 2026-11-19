"""
The message input bar: 😊 emoji, 📎 attach (photo or document), a growing text box,
and a button that shows 🎤 when the box is empty and ➤ send once you type.

Enter sends, Shift+Enter starts a new line.
"""

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtGui import QFontMetrics
from PySide6.QtWidgets import QFrame, QHBoxLayout, QMenu, QPlainTextEdit

from client.gui import icons
from client.gui.widgets.emoji_picker import EmojiPicker
from client.gui.widgets.sidebar import icon_button, set_button_svg

MAX_VISIBLE_LINES = 6
BOX_PADDING = 20          # top + bottom padding inside the text box (see light.qss)


class MessageInput(QPlainTextEdit):
    submit = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("MessageInput")
        self.setPlaceholderText("Type a message")
        self.setTabChangesFocus(True)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.setFrameShape(QFrame.NoFrame)
        self.document().setDocumentMargin(0)
        self.document().documentLayout().documentSizeChanged.connect(self._fit_height)
        self._fit_height()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._fit_height()   # the stylesheet font is only applied once the widget is shown

    def keyPressEvent(self, event) -> None:
        if event.key() in (Qt.Key_Return, Qt.Key_Enter) and not event.modifiers() & Qt.ShiftModifier:
            self.submit.emit()
            return
        super().keyPressEvent(event)

    def _fit_height(self, *_) -> None:
        # QPlainTextEdit measures its document in lines, so convert lines -> pixels
        lines = max(1, int(self.document().documentLayout().documentSize().height()))
        line_height = QFontMetrics(self.font()).lineSpacing()
        self.setFixedHeight(min(lines, MAX_VISIBLE_LINES) * line_height + BOX_PADDING + 2)


class InputBar(QFrame):
    send_requested = Signal(str)
    text_edited = Signal(str)       # used for the "typing…" indicator (Prompt 9)
    mic_clicked = Signal()
    attach_requested = Signal(str)  # "image" or "document"

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("InputBar")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 9, 14, 9)
        layout.setSpacing(6)

        self.emoji_button = icon_button(icons.EMOJI, "Emoji", None, 26)
        self.emoji_button.setFixedSize(42, 42)
        self.emoji_button.clicked.connect(self._toggle_emoji)
        self.attach_button = icon_button(icons.ATTACH, "Attach", None, 24)
        self.attach_button.setFixedSize(42, 42)
        self.attach_button.clicked.connect(self._show_attach_menu)
        self.input = MessageInput()
        self.action_button = icon_button(icons.MIC, "Voice message", None, 26)
        self.action_button.setFixedSize(42, 42)
        self.action_button.clicked.connect(self._on_action)

        for widget in (self.emoji_button, self.attach_button):
            layout.addWidget(widget, 0, Qt.AlignBottom)
        layout.addWidget(self.input, 1, Qt.AlignBottom)
        layout.addWidget(self.action_button, 0, Qt.AlignBottom)

        self.emoji_picker = EmojiPicker(self)
        self.emoji_picker.emoji_selected.connect(self.insert_text)

        self.input.submit.connect(self._send)
        self.input.textChanged.connect(self._on_text_changed)
        self._showing_send = False

    # ---------------------------------------------------------------- text
    def text(self) -> str:
        return self.input.toPlainText()

    def set_text(self, text: str) -> None:
        self.input.setPlainText(text)
        cursor = self.input.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self.input.setTextCursor(cursor)

    def insert_text(self, text: str) -> None:
        self.input.insertPlainText(text)
        self.input.setFocus()

    def focus(self) -> None:
        self.input.setFocus()

    # -------------------------------------------------------------- actions
    def _on_text_changed(self) -> None:
        has_text = bool(self.text().strip())
        if has_text != self._showing_send:          # swap 🎤 <-> ➤
            self._showing_send = has_text
            set_button_svg(self.action_button, icons.SEND if has_text else icons.MIC)
            self.action_button.setToolTip("Send" if has_text else "Voice message")
        self.text_edited.emit(self.text())

    def _on_action(self) -> None:
        if self._showing_send:
            self._send()
        else:
            self.mic_clicked.emit()

    def _send(self) -> None:
        text = self.text()
        if text.strip():
            self.send_requested.emit(text)
            self.input.clear()

    def _show_attach_menu(self) -> None:
        menu = QMenu(self)
        menu.setObjectName("AttachMenu")
        menu.addAction(icons.svg_icon(icons.IMAGE, 20, "#007BFC"), "Photos & images",
                       lambda: self.attach_requested.emit("image"))
        menu.addAction(icons.svg_icon(icons.DOCUMENT, 20, "#7F66FF"), "Document",
                       lambda: self.attach_requested.emit("document"))
        button = self.attach_button
        menu.exec(button.mapToGlobal(QPoint(0, -menu.sizeHint().height() - 6)))

    def _toggle_emoji(self) -> None:
        if self.emoji_picker.isVisible():
            self.emoji_picker.hide()
        else:
            self.emoji_picker.popup_above(self)
