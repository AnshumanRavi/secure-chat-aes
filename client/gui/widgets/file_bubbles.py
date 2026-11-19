"""
Bubbles for shared files, WhatsApp style.

ImageBubble     the photo fills the bubble (3 px border), the time sits on the photo in white,
                a progress ring covers it while it uploads/downloads; click to view full size.
DocumentBubble  a file card: coloured icon with the extension, file name, "1.2 MB · PDF",
                a progress ring while transferring, then an "open" button.
"""

from pathlib import Path
from typing import Optional

from PySide6.QtCore import QRect, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QFontMetrics, QLinearGradient, QPainter, QPainterPath, QPen, QPixmap
from PySide6.QtWidgets import QWidget

from client.files import human_size
from client.gui import icons, palette
from client.gui.chat_store import Message
from client.gui.media import doc_colour, extension, pixmap_from_bytes, scaled_image
from client.gui.widgets.bubble import TAIL, BubbleBase, BubbleMeta

IMAGE_PAD = 3
MAX_IMAGE_WIDTH = 330
MAX_IMAGE_HEIGHT = 340
MIN_IMAGE_WIDTH = 160
MIN_IMAGE_HEIGHT = 110
DOC_WIDTH = 300
CARD_HEIGHT = 62


def transferring(msg: Message) -> bool:
    return msg.file["state"] in ("uploading", "downloading")


def openable_path(msg: Message) -> Optional[str]:
    path = msg.file.get("path")
    if path and msg.file["state"] != "failed" and (msg.outgoing or msg.file["state"] == "done"):
        return path if Path(path).exists() else None
    return None


class ProgressRing(QWidget):
    """Circular progress indicator with an up/down arrow in the middle."""

    def __init__(self, parent, size: int, dark: bool, upload: bool):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.dark, self.upload, self.value = dark, upload, 0.0

    def set_value(self, value: float) -> None:
        self.value = max(0.0, min(1.0, value))
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = QRectF(self.rect()).adjusted(3, 3, -3, -3)
        if self.dark:
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(11, 20, 26, 120))
            painter.drawEllipse(QRectF(self.rect()))
        track, arc = (QColor(255, 255, 255, 70), QColor("#FFFFFF")) if self.dark else \
            (QColor(palette.current().ring_track), QColor(palette.current().accent))
        pen = QPen(track, 3)
        painter.setPen(pen)
        painter.setBrush(Qt.NoBrush)
        painter.drawEllipse(rect)
        pen.setColor(arc)
        pen.setCapStyle(Qt.RoundCap)
        painter.setPen(pen)
        painter.drawArc(rect, 90 * 16, -int(max(0.03, self.value) * 360 * 16))
        size = int(self.width() * 0.42)
        arrow = icons.svg_pixmap(icons.ARROW_UP if self.upload else icons.ARROW_DOWN, size,
                                 "#FFFFFF" if self.dark else "#00A884")
        painter.drawPixmap((self.width() - size) // 2, (self.height() - size) // 2, arrow)


class ImageBubble(BubbleBase):
    def __init__(self, msg: Message, tail: bool, sender_name: str = "", parent=None):
        super().__init__(msg, tail, sender_name, parent)
        self.meta = BubbleMeta(msg, self, light=True)
        self.ring = ProgressRing(self, 54, dark=True, upload=msg.outgoing)
        self.setCursor(Qt.PointingHandCursor)
        self.setToolTip(msg.file["name"])
        self._thumb: Optional[QPixmap] = None
        self._image_rect = QRect()
        self._relayout()
        self.refresh_status()

    def _image_box(self):
        available = max(MIN_IMAGE_WIDTH, min(MAX_IMAGE_WIDTH, self._max_width - TAIL - 2 * IMAGE_PAD))
        width, height = self.msg.file.get("width") or 0, self.msg.file.get("height") or 0
        if not (width and height):
            width, height = 4, 3
        scale = min(available / width, MAX_IMAGE_HEIGHT / height)
        return (int(max(MIN_IMAGE_WIDTH, min(available, width * scale))),
                int(max(MIN_IMAGE_HEIGHT, min(MAX_IMAGE_HEIGHT, height * scale))))

    def _relayout(self) -> None:
        image_w, image_h = self._image_box()
        self._body_x = TAIL if not self.msg.outgoing else 0
        name_w, name_h = self._name_size(image_w - 6)
        top = IMAGE_PAD + (name_h + 3 if name_h else 0)
        self._body_w = image_w + 2 * IMAGE_PAD
        self.setFixedSize(self._body_w + TAIL, top + image_h + IMAGE_PAD)
        self._image_rect = QRect(self._body_x + IMAGE_PAD, top, image_w, image_h)
        if self.name_label is not None:
            self.name_label.setGeometry(self._body_x + 8, 4, name_w, name_h)
        r = self._image_rect
        self.meta.move(r.right() - self.meta.width() - 6, r.bottom() - self.meta.height() - 4)
        self.ring.move(r.center().x() - self.ring.width() // 2, r.center().y() - self.ring.height() // 2)

    def _pixmap(self) -> Optional[QPixmap]:
        path = openable_path(self.msg)
        if path:
            return scaled_image(path, self._image_rect.width(), self._image_rect.height())
        if self.msg.file.get("thumb"):
            if self._thumb is None:
                self._thumb = pixmap_from_bytes(self.msg.file["thumb"])
            return self._thumb
        return None

    def paint_content(self, painter: QPainter) -> None:
        r = QRectF(self._image_rect)
        clip = QPainterPath()
        clip.addRoundedRect(r, 6, 6)
        painter.save()
        painter.setClipPath(clip)
        pixmap = self._pixmap()
        if pixmap is not None and not pixmap.isNull():
            # "cover" fit: scale to fill the box, crop the overflow evenly
            pw, ph = pixmap.width(), pixmap.height()
            scale = max(r.width() / pw, r.height() / ph)
            sw, sh = r.width() / scale, r.height() / scale
            painter.drawPixmap(r, pixmap, QRectF((pw - sw) / 2, (ph - sh) / 2, sw, sh))
        else:
            painter.fillRect(r, QColor(palette.current().placeholder))
            icon = icons.svg_pixmap(icons.IMAGE, 48, "#FFFFFF")
            painter.drawPixmap(int(r.center().x() - 24), int(r.center().y() - 24), icon)
        if transferring(self.msg):
            painter.fillRect(r, QColor(11, 20, 26, 50))
        shade = QLinearGradient(0, r.bottom() - 30, 0, r.bottom())   # keeps the white time readable
        shade.setColorAt(0, QColor(0, 0, 0, 0))
        shade.setColorAt(1, QColor(0, 0, 0, 90))
        painter.fillRect(QRectF(r.left(), r.bottom() - 30, r.width(), 30), shade)
        painter.restore()
        if self.msg.file["state"] == "failed":
            icon = icons.svg_pixmap(icons.WARNING, 40, "#EA0038")
            painter.drawPixmap(int(r.center().x() - 20), int(r.center().y() - 20), icon)

    def refresh_status(self) -> None:
        self.ring.setVisible(transferring(self.msg))
        self.ring.set_value(self.msg.file.get("progress", 0))
        if self.msg.file["state"] == "failed":
            self.setToolTip(self.msg.file.get("error", "Failed"))
        super().refresh_status()

    def mouseReleaseEvent(self, event) -> None:
        if event.button() == Qt.LeftButton and openable_path(self.msg):
            self.open_requested.emit(self.msg)
        super().mouseReleaseEvent(event)


class DocumentBubble(BubbleBase):
    def __init__(self, msg: Message, tail: bool, sender_name: str = "", parent=None):
        super().__init__(msg, tail, sender_name, parent)
        self.meta = BubbleMeta(msg, self)
        self.ring = ProgressRing(self, 36, dark=False, upload=msg.outgoing)
        self.setCursor(Qt.PointingHandCursor)
        self._card = QRect()
        self._relayout()
        self.refresh_status()

    def _relayout(self) -> None:
        width = max(220, min(DOC_WIDTH, self._max_width - TAIL - 12))
        self._body_x = TAIL if not self.msg.outgoing else 0
        name_w, name_h = self._name_size(width)
        top = 6 + (name_h + 2 if name_h else 0)
        self._body_w = width + 12
        self._card = QRect(self._body_x + 6, top, width, CARD_HEIGHT)
        meta_y = top + CARD_HEIGHT + 4
        self.setFixedSize(self._body_w + TAIL, meta_y + self.meta.height() + 5)
        if self.name_label is not None:
            self.name_label.setGeometry(self._body_x + 9, 4, name_w, name_h)
        self.meta.move(self._body_x + self._body_w - 8 - self.meta.width(), meta_y)
        self.ring.move(self._card.right() - 12 - self.ring.width(),
                       self._card.center().y() - self.ring.height() // 2 + 1)

    @staticmethod
    def _font(base: QFont, px: int, bold: bool = False) -> QFont:
        font = QFont(base)
        font.setPixelSize(px)
        font.setWeight(QFont.DemiBold if bold else QFont.Normal)
        return font

    def paint_content(self, painter: QPainter) -> None:
        card = QRectF(self._card)
        painter.setPen(Qt.NoPen)
        colours = palette.current()
        painter.setBrush(QColor(*(colours.card_out if self.msg.outgoing else colours.card_in)))
        painter.drawRoundedRect(card, 6, 6)

        # file-type icon: a page with a folded corner and the extension
        ext = extension(self.msg.file["name"])[:4].upper() or "FILE"
        icon = QRectF(card.left() + 12, card.center().y() - 19, 30, 38)
        page = QPainterPath()
        page.moveTo(icon.left(), icon.top() + 2)
        page.lineTo(icon.right() - 9, icon.top())
        page.lineTo(icon.right(), icon.top() + 9)
        page.lineTo(icon.right(), icon.bottom())
        page.lineTo(icon.left(), icon.bottom())
        page.closeSubpath()
        painter.setBrush(QColor(doc_colour(self.msg.file["name"])))
        painter.drawPath(page)
        painter.setBrush(QColor(255, 255, 255, 110))
        corner = QPainterPath()
        corner.moveTo(icon.right() - 9, icon.top())
        corner.lineTo(icon.right() - 9, icon.top() + 9)
        corner.lineTo(icon.right(), icon.top() + 9)
        corner.closeSubpath()
        painter.drawPath(corner)
        painter.setPen(QColor("#FFFFFF"))
        painter.setFont(self._font(self.font(), 8, bold=True))
        painter.drawText(QRectF(icon.left(), icon.bottom() - 15, icon.width(), 12), Qt.AlignCenter, ext)

        # name and details
        text_left = icon.right() + 12
        text_width = card.right() - 54 - text_left
        name_font = self._font(self.font(), 14)
        painter.setFont(name_font)
        painter.setPen(QColor(colours.text))
        name = QFontMetrics(name_font).elidedText(self.msg.file["name"], Qt.ElideMiddle, int(text_width))
        painter.drawText(QRectF(text_left, card.top() + 10, text_width, 20), Qt.AlignLeft | Qt.AlignVCenter, name)

        detail_font = self._font(self.font(), 12)
        painter.setFont(detail_font)
        if self.msg.file["state"] == "failed":
            painter.setPen(QColor("#EA0038"))
            detail = self.msg.file.get("error", "Failed")
        else:
            painter.setPen(QColor(colours.text_secondary))
            detail = f"{human_size(self.msg.file['size'])} · {ext}"
            if transferring(self.msg):
                done = int(self.msg.file["size"] * self.msg.file.get("progress", 0))
                detail = f"{human_size(done)} of {human_size(self.msg.file['size'])}"
        detail = QFontMetrics(detail_font).elidedText(detail, Qt.ElideRight, int(text_width))
        painter.drawText(QRectF(text_left, card.top() + 32, text_width, 18), Qt.AlignLeft | Qt.AlignVCenter, detail)

        # right side: progress ring (separate widget) / open / failed
        if not transferring(self.msg):
            svg, colour = (icons.WARNING, "#EA0038") if self.msg.file["state"] == "failed" else \
                (icons.OPEN_EXTERNAL, colours.icon)
            pixmap = icons.svg_pixmap(svg, 22, colour)
            painter.drawPixmap(int(card.right() - 12 - 30), int(card.center().y() - 11), pixmap)

    def refresh_status(self) -> None:
        self.ring.setVisible(transferring(self.msg))
        self.ring.set_value(self.msg.file.get("progress", 0))
        self.setToolTip(self.msg.file.get("error", "") if self.msg.file["state"] == "failed"
                        else f"{self.msg.file['name']} - click to open")
        super().refresh_status()

    def mouseReleaseEvent(self, event) -> None:
        if event.button() == Qt.LeftButton and self._card.contains(event.position().toPoint()) \
                and openable_path(self.msg):
            self.open_requested.emit(self.msg)
        super().mouseReleaseEvent(event)


def make_file_bubble(msg: Message, tail: bool, sender_name: str = "") -> BubbleBase:
    if msg.kind == "image":
        return ImageBubble(msg, tail, sender_name)
    return DocumentBubble(msg, tail, sender_name)
