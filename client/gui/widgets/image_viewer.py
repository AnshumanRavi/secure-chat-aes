"""Full-size image viewer (opens when you click a photo), dark like WhatsApp's media viewer."""

from pathlib import Path

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QImageReader, QPixmap
from PySide6.QtWidgets import QDialog, QFrame, QHBoxLayout, QLabel, QPushButton, QVBoxLayout

from client.gui import icons
from client.gui.media import open_file, show_in_folder


class ImageViewer(QDialog):
    def __init__(self, path: str, title: str, subtitle: str = "", parent=None):
        super().__init__(parent)
        self.setObjectName("ImageViewer")
        self.setWindowTitle(Path(path).name)
        self.path = path
        reader = QImageReader(path)
        reader.setAutoTransform(True)
        self._pixmap = QPixmap.fromImage(reader.read())

        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        bar = QFrame()
        bar.setObjectName("ViewerBar")
        bar.setFixedHeight(58)
        h = QHBoxLayout(bar)
        h.setContentsMargins(18, 0, 10, 0)
        texts = QVBoxLayout()
        texts.setSpacing(0)
        name = QLabel(title)
        name.setObjectName("ViewerTitle")
        sub = QLabel(subtitle)
        sub.setObjectName("ViewerSubtitle")
        texts.addStretch()
        texts.addWidget(name)
        texts.addWidget(sub)
        texts.addStretch()
        h.addLayout(texts, 1)
        for svg, tip, action in ((icons.FOLDER, "Show in folder", lambda: show_in_folder(path)),
                                 (icons.OPEN_EXTERNAL, "Open with another app", lambda: open_file(path)),
                                 (icons.CLOSE, "Close (Esc)", self.accept)):
            button = QPushButton()
            button.setObjectName("ViewerButton")
            button.setIcon(icons.svg_icon(svg, 22, "#E9EDEF"))
            button.setIconSize(QSize(22, 22))
            button.setFixedSize(40, 40)
            button.setToolTip(tip)
            button.setCursor(Qt.PointingHandCursor)
            button.clicked.connect(action)
            h.addWidget(button)
        v.addWidget(bar)

        self.image = QLabel()
        self.image.setAlignment(Qt.AlignCenter)
        self.image.setMinimumSize(200, 200)
        v.addWidget(self.image, 1)

        if parent is not None:
            self.resize(int(parent.width() * 0.9), int(parent.height() * 0.9))
        else:
            self.resize(1000, 720)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if not self._pixmap.isNull():
            available = self.image.size() - QSize(40, 40)
            ratio = self.devicePixelRatioF()
            scaled = self._pixmap.scaled(available * ratio, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            scaled.setDevicePixelRatio(ratio)
            self.image.setPixmap(scaled)
