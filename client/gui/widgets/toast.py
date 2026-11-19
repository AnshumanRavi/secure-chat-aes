"""A small dark message that fades in at the bottom of a window, then fades out."""

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, Qt, QTimer
from PySide6.QtWidgets import QGraphicsOpacityEffect, QLabel, QWidget


class Toast(QLabel):
    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self.setObjectName("Toast")
        self.setAlignment(Qt.AlignCenter)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self._effect = QGraphicsOpacityEffect(self)
        self._effect.setOpacity(0.0)
        self.setGraphicsEffect(self._effect)
        self._fade = QPropertyAnimation(self._effect, b"opacity", self)
        self._fade.setDuration(180)
        self._fade.setEasingCurve(QEasingCurve.OutCubic)
        self._timer = QTimer(self, singleShot=True)
        self._timer.timeout.connect(lambda: self._animate(0.0))
        self._fade.finished.connect(lambda: self._effect.opacity() == 0 and self.hide())
        self.hide()

    def show_message(self, text: str, msecs: int = 2600) -> None:
        self.setText(text)
        self.adjustSize()
        parent = self.parentWidget()
        self.move((parent.width() - self.width()) // 2, parent.height() - self.height() - 36)
        self.raise_()
        self.show()
        self._animate(1.0)
        self._timer.start(msecs)

    def _animate(self, target: float) -> None:
        self._fade.stop()
        self._fade.setStartValue(self._effect.opacity())
        self._fade.setEndValue(target)
        self._fade.start()
