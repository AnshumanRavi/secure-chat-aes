"""A small rotating loading spinner (like the one WhatsApp shows while connecting)."""

from PySide6.QtCore import QRectF, Qt, QTimer
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import QWidget


class Spinner(QWidget):
    def __init__(self, parent=None, size: int = 20, color: str = "#FFFFFF", line_width: float = 2.5):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self._color = QColor(color)
        self._line_width = line_width
        self._angle = 0
        self._timer = QTimer(self, interval=16)
        self._timer.timeout.connect(self._tick)
        self.hide()

    def start(self) -> None:
        self.show()
        self._timer.start()

    def stop(self) -> None:
        self._timer.stop()
        self.hide()

    def _tick(self) -> None:
        self._angle = (self._angle + 8) % 360
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        pen = QPen(self._color, self._line_width)
        pen.setCapStyle(Qt.RoundCap)
        painter.setPen(pen)
        inset = self._line_width / 2 + 0.5
        rect = QRectF(inset, inset, self.width() - 2 * inset, self.height() - 2 * inset)
        painter.drawArc(rect, -self._angle * 16, 270 * 16)   # a 3/4 circle that rotates
