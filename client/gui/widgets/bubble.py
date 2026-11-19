"""
Message bubbles, WhatsApp style.

Layout trick (the same one WhatsApp uses): the time + ticks sit at the bottom
right of the bubble. If the last line of text has room for them, they share
that line; otherwise the bubble grows by one line to fit them.
"""

import html
import math
import re
from typing import Optional

import emoji
from PySide6.QtCore import QPoint, QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QFont, QFontMetrics, QPainter, QPainterPath, QTextDocument
from PySide6.QtWidgets import QHBoxLayout, QLabel, QSizePolicy, QWidget

from client.formatting import format_time
from client.gui.chat_store import Message
from client.gui import icons, palette
from client.gui.widgets.avatar import sender_colour
from client.gui.widgets.chat_list import STATUS_ICONS, status_pixmap

# bubble colours come from client/gui/palette.py (light or dark theme)

PAD_LEFT, PAD_RIGHT, PAD_TOP, PAD_BOTTOM = 9, 8, 6, 7
TAIL = 8            # how far the tail sticks out of the bubble
RADIUS = 7.5
META_GAP = 10       # space between the text and the time
TEXT_PX = 14
JUMBO_PX = 34       # a message of only 1-3 emoji is shown big, like WhatsApp

ZERO_WIDTH_SPACE = chr(0x200B)   # invisible; lets Qt wrap inside long words
_LONG_WORD = re.compile(r"\S{24,}")


def display_text(text: str) -> str:
    """Let very long words (URLs, hashes) wrap by inserting zero-width spaces."""
    return _LONG_WORD.sub(lambda m: ZERO_WIDTH_SPACE.join(m.group(0)[i:i + 20]
                                                   for i in range(0, len(m.group(0)), 20)), text)


def is_jumbo(text: str) -> bool:
    stripped = text.strip()
    return bool(stripped) and emoji.purely_emoji(stripped) and emoji.emoji_count(stripped) <= 3


def measure_text(text: str, font: QFont, max_width: int):
    """Lay the text out like the label will. Returns (width, height, last_line_width)."""
    doc = QTextDocument()
    doc.setDefaultFont(font)
    doc.setDocumentMargin(0)
    doc.setPlainText(text)
    doc.setTextWidth(max_width)
    doc.documentLayout().documentSize()     # forces the layout to run before we read the lines
    layout = doc.lastBlock().layout()
    last_line = layout.lineAt(layout.lineCount() - 1)
    return math.ceil(doc.idealWidth()), math.ceil(doc.size().height()), last_line.naturalTextWidth()


class BubbleMeta(QWidget):
    """'10:42 PM ✓✓' in the bottom-right corner of a bubble."""

    TICK = 16

    def __init__(self, msg: Message, parent=None, light: bool = False):
        super().__init__(parent)
        self.msg = msg
        self.light = light          # white text, drawn on top of a photo
        self.font_ = QFont(self.font())
        self.font_.setPixelSize(11)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.setFixedSize(self.sizeHint())

    def sizeHint(self):
        width = QFontMetrics(self.font_).horizontalAdvance(format_time(self.msg.ts))
        if self.msg.outgoing:
            width += 3 + self.TICK
        return QSize(width, 16)

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.TextAntialiasing)
        painter.setFont(self.font_)
        text = format_time(self.msg.ts)
        text_width = QFontMetrics(self.font_).horizontalAdvance(text)
        if self.light:
            painter.setPen(QColor(0, 0, 0, 90))      # soft shadow keeps white text readable on photos
            painter.drawText(QRectF(0, 1, text_width, 16), Qt.AlignLeft | Qt.AlignVCenter, text)
        painter.setPen(QColor("#FFFFFF" if self.light else palette.current().meta))
        painter.drawText(QRectF(0, 0, text_width, 16), Qt.AlignLeft | Qt.AlignVCenter, text)
        if self.msg.outgoing:
            status = self.msg.status
            if self.light and status in ("sent", "delivered"):   # grey ticks would vanish on a photo
                svg, _ = STATUS_ICONS[status]
                painter.drawPixmap(text_width + 3, 0, icons.svg_pixmap(svg, self.TICK, "#FFFFFF"))
            else:
                painter.drawPixmap(text_width + 3, 0, status_pixmap(status, self.TICK))


class BubbleBase(QWidget):
    """
    Shared by all bubble types (text, image, document): the rounded shape with the
    WhatsApp tail, the 1px shadow, the optional sender name (groups) and the
    right-click menu. Subclasses implement _relayout() and set _body_x / _body_w.
    """

    menu_requested = Signal(object, QPoint)   # Message, global position
    open_requested = Signal(object)           # Message - a file/photo bubble was clicked

    def __init__(self, msg: Message, tail: bool, sender_name: str = "", parent=None):
        super().__init__(parent)
        self.msg = msg
        self.tail = tail
        self._max_width = 420
        self._body_x = 0
        self._body_w = 0
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

        # In groups, the first bubble of a run shows who sent it, in that person's colour
        self.name_label: Optional[QLabel] = None
        if sender_name:
            self.name_label = QLabel(sender_name, self)
            self.name_label.setObjectName("SenderName")
            self.name_label.setStyleSheet(f"color: {sender_colour(msg.sender)};")

    def _name_size(self, max_width: int):
        if self.name_label is None:
            return 0, 0
        self.name_label.ensurePolished()
        return min(max_width, self.name_label.sizeHint().width()), self.name_label.sizeHint().height() + 1

    def set_max_width(self, width: int) -> None:
        if width != self._max_width:
            self._max_width = width
            self._relayout()

    def _relayout(self) -> None:
        raise NotImplementedError

    def refresh_status(self) -> None:
        self.update()
        for child in self.findChildren(BubbleMeta):
            child.update()

    # --------------------------------------------------------------- painting
    def _shape(self) -> QPainterPath:
        x0, w, h = self._body_x, self._body_w, self.height()
        body = QPainterPath()
        body.addRoundedRect(QRectF(x0, 0, w, h), RADIUS, RADIUS)
        if not self.tail:
            return body
        tail = QPainterPath()
        if self.msg.outgoing:                       # tail on the top right
            right = x0 + w
            tail.addRect(QRectF(right - RADIUS, 0, RADIUS, RADIUS))   # square off that corner
            tail.moveTo(right, 0)
            tail.lineTo(right + TAIL - 2, 0)
            tail.quadTo(right + TAIL, 0, right + TAIL - 1.5, 2)
            tail.lineTo(right, 12)
            tail.closeSubpath()
        else:                                       # tail on the top left
            tail.addRect(QRectF(x0, 0, RADIUS, RADIUS))
            tail.moveTo(x0, 0)
            tail.lineTo(x0 - TAIL + 2, 0)
            tail.quadTo(x0 - TAIL, 0, x0 - TAIL + 1.5, 2)
            tail.lineTo(x0, 12)
            tail.closeSubpath()
        return body.united(tail)

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(Qt.NoPen)
        shape = self._shape()
        colours = palette.current()
        painter.setBrush(QColor(*colours.bubble_shadow))     # 1px shadow under the bubble
        painter.drawPath(shape.translated(0, 1))
        painter.setBrush(QColor(colours.bubble_out if self.msg.outgoing else colours.bubble_in))
        painter.drawPath(shape)
        self.paint_content(painter)

    def paint_content(self, painter: QPainter) -> None:
        """Hook for image/document bubbles to draw on top of the bubble background."""

    def contextMenuEvent(self, event) -> None:
        self.menu_requested.emit(self.msg, event.globalPos())


class Bubble(BubbleBase):
    """A text message bubble."""

    def __init__(self, msg: Message, tail: bool, sender_name: str = "", parent=None):
        super().__init__(msg, tail, sender_name, parent)

        self._plain = display_text(msg.text)
        self.label = QLabel(self._plain, self)
        self.label.setObjectName("BubbleText")
        self.label.setTextFormat(Qt.PlainText)
        self.label.setWordWrap(True)
        self.label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.label.setContextMenuPolicy(Qt.NoContextMenu)   # right-click goes to the bubble's menu
        self.label.setCursor(Qt.IBeamCursor)
        font = QFont(self.label.font())
        font.setPixelSize(JUMBO_PX if is_jumbo(msg.text) else TEXT_PX)
        self.label.setFont(font)

        self.meta = BubbleMeta(msg, self)
        self._relayout()

    def _relayout(self) -> None:
        inner_max = max(80, self._max_width - TAIL - PAD_LEFT - PAD_RIGHT)
        text_w, text_h, last_line = measure_text(self._plain, self.label.font(), inner_max)
        meta_w, meta_h = self.meta.width(), self.meta.height()
        name_w, name_h = self._name_size(inner_max)

        if last_line + META_GAP + meta_w <= inner_max:     # time fits on the last line
            content_w = max(text_w, math.ceil(last_line) + META_GAP + meta_w, name_w)
            content_h = max(text_h, meta_h)
        else:                                              # time goes on its own line
            content_w = max(text_w, meta_w, name_w)
            content_h = text_h + meta_h - 2
        meta_y = PAD_TOP + name_h + content_h - meta_h + 3

        self._body_w = content_w + PAD_LEFT + PAD_RIGHT
        body_h = name_h + content_h + PAD_TOP + PAD_BOTTOM
        self._body_x = TAIL if not self.msg.outgoing else 0
        self.setFixedSize(self._body_w + TAIL, body_h)
        if self.name_label is not None:
            self.name_label.setGeometry(self._body_x + PAD_LEFT, PAD_TOP - 1, name_w, name_h)
        self.label.setGeometry(self._body_x + PAD_LEFT, PAD_TOP + name_h, text_w + 2, text_h)
        self.meta.move(self._body_x + self._body_w - PAD_RIGHT - meta_w + 2, meta_y)

    def highlight(self, query: str = "", current: bool = False) -> None:
        """Mark search matches in yellow (the current match in orange). Empty query = plain text."""
        if not query or query.lower() not in self._plain.lower():
            self.label.setTextFormat(Qt.PlainText)
            self.label.setText(self._plain)
            return
        colour = "#FF9F1A" if current else "#FFD279"
        pattern = re.compile(re.escape(query), re.IGNORECASE)
        parts, last = [], 0
        for match in pattern.finditer(self._plain):
            parts.append(html.escape(self._plain[last:match.start()]))
            parts.append(f'<span style="background:{colour}; color:#111B21;">{html.escape(match.group(0))}</span>')
            last = match.end()
        parts.append(html.escape(self._plain[last:]))
        # same wrapping as plain text: keep spaces and line breaks
        self.label.setTextFormat(Qt.RichText)
        self.label.setText('<span style="white-space:pre-wrap;">' + "".join(parts) + "</span>")


class MessageRow(QWidget):
    """One line in the conversation: a bubble pushed to the left (incoming) or right (outgoing)."""

    def __init__(self, msg: Message, first_in_group: bool, sender_name: str = "", parent=None):
        super().__init__(parent)
        self.msg = msg
        if msg.kind in ("image", "document"):
            from client.gui.widgets.file_bubbles import make_file_bubble   # avoids a circular import
            self.bubble = make_file_bubble(msg, first_in_group, sender_name)
        else:
            self.bubble = Bubble(msg, tail=first_in_group, sender_name=sender_name)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 12 if first_in_group else 2, 0, 0)
        if msg.outgoing:
            layout.addStretch()
            layout.addWidget(self.bubble)
        else:
            layout.addWidget(self.bubble)
            layout.addStretch()


class CentredChip(QWidget):
    """A centred label chip: date separators ('TODAY'), system messages and the encryption notice."""

    clicked = Signal()

    def __init__(self, text: str, object_name: str, top_margin: int = 12, parent=None, clickable: bool = False):
        super().__init__(parent)
        self._clickable = clickable
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, top_margin, 0, 0)
        self.label = QLabel(text)
        self.label.setObjectName(object_name)
        self.label.setWordWrap(True)
        self.label.setAlignment(Qt.AlignCenter)
        self.set_text(text)
        if clickable:
            self.label.setCursor(Qt.PointingHandCursor)
        layout.addStretch()
        layout.addWidget(self.label)
        layout.addStretch()

    def set_text(self, text: str) -> None:
        self.label.setText(text)
        self.label.ensurePolished()   # apply the stylesheet font before measuring
        natural = self.label.fontMetrics().horizontalAdvance(text) + 26   # + horizontal padding
        self.label.setFixedWidth(min(540, natural))

    def mouseReleaseEvent(self, event) -> None:
        if self._clickable and event.button() == Qt.LeftButton and \
                self.label.geometry().contains(event.position().toPoint()):
            self.clicked.emit()
        super().mouseReleaseEvent(event)
