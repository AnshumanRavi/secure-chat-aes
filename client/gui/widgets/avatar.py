"""Round avatars with initials on a coloured background (WhatsApp shows a photo or a silhouette)."""

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter
from PySide6.QtWidgets import QWidget

from typing import Optional

from client.formatting import initials
from client.gui import icons, palette

ONLINE_GREEN = "#25D366"

# WhatsApp gives every group member's name its own colour; pick one per username, always the same
SENDER_COLOURS = ["#E542A3", "#1F7AEC", "#FA6533", "#029D00", "#7F66FF", "#C4532D",
                  "#008069", "#A62C71", "#B38400", "#0D8C80", "#D6224B", "#5E47DE"]


def sender_colour(username: str) -> str:
    # a fixed checksum (not hash(), which changes between runs) keeps the colour stable
    return SENDER_COLOURS[sum(map(ord, username)) % len(SENDER_COLOURS)]


def paint_avatar(painter: QPainter, rect: QRectF, name: str, color: str,
                 online: bool = False, ring_color: Optional[str] = None, group: bool = False) -> None:
    """Draw a circular avatar into rect: initials, or a people icon for groups.
    With online=True add the green presence dot (ring_color = the background behind it)."""
    ring_color = ring_color or palette.current().sidebar
    painter.save()
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setPen(Qt.NoPen)
    painter.setBrush(QColor(color))
    painter.drawEllipse(rect)

    if group:
        size = int(rect.height() * 0.56)
        icon = icons.svg_pixmap(icons.GROUP, size, "#FFFFFF")
        painter.drawPixmap(int(rect.center().x() - size / 2), int(rect.center().y() - size / 2), icon)
    else:
        font = QFont(painter.font())
        font.setPixelSize(max(10, int(rect.height() * 0.38)))
        font.setWeight(QFont.DemiBold)
        painter.setFont(font)
        painter.setPen(QColor("#FFFFFF"))
        painter.drawText(rect, Qt.AlignCenter, initials(name))

    if online:
        d = max(10.0, rect.height() * 0.26)
        dot = QRectF(rect.right() - d + 1, rect.bottom() - d + 1, d, d)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(ring_color))
        painter.drawEllipse(dot)
        painter.setBrush(QColor(ONLINE_GREEN))
        painter.drawEllipse(dot.adjusted(2, 2, -2, -2))
    painter.restore()


class Avatar(QWidget):
    def __init__(self, size: int = 40, name: str = "", color: str = "#00A884",
                 ring_color: Optional[str] = None, parent=None):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self._name, self._color, self._online, self._ring = name, color, False, ring_color
        self._group = False

    def set_person(self, name: str, color: str, online: bool = False, group: bool = False) -> None:
        self._name, self._color, self._online, self._group = name, color, online, group
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        paint_avatar(painter, QRectF(self.rect()), self._name, self._color, self._online,
                     self._ring or palette.current().panel, group=self._group)
