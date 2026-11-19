"""Yellow banner at the top of the sidebar while the connection to the server is down."""

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QVBoxLayout

from client.gui import icons
from client.gui.widgets.spinner import Spinner


class ConnectionBanner(QFrame):
    retry_clicked = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("ConnectionBanner")
        h = QHBoxLayout(self)
        h.setContentsMargins(16, 12, 14, 12)
        h.setSpacing(14)

        circle = QLabel()
        circle.setObjectName("BannerIcon")
        circle.setFixedSize(44, 44)
        circle.setAlignment(Qt.AlignCenter)
        circle.setPixmap(icons.svg_pixmap(icons.WIFI_OFF, 22, "#FFFFFF"))
        h.addWidget(circle, 0, Qt.AlignTop)

        texts = QVBoxLayout()
        texts.setSpacing(2)
        self.title = QLabel()
        self.title.setObjectName("BannerTitle")
        self.subtitle = QLabel()
        self.subtitle.setObjectName("BannerText")
        self.subtitle.setWordWrap(True)
        self.retry = QPushButton("Retry now")
        self.retry.setObjectName("LinkButton")
        self.retry.setCursor(Qt.PointingHandCursor)
        self.retry.clicked.connect(self.retry_clicked)
        texts.addWidget(self.title)
        texts.addWidget(self.subtitle)
        texts.addWidget(self.retry, 0, Qt.AlignLeft)
        h.addLayout(texts, 1)

        self.spinner = Spinner(self, size=20, color="#54656F")
        h.addWidget(self.spinner, 0, Qt.AlignTop)
        self.hide()

    def show_connecting(self) -> None:
        self.title.setText("Connecting…")
        self.subtitle.setText("Messages you send will be delivered when the connection is back.")
        self.retry.hide()
        self.spinner.start()
        self.show()

    def show_waiting(self, seconds: int, reason: str = "") -> None:
        self.title.setText("Not connected to the server")
        detail = f"{reason}. " if reason else ""
        self.subtitle.setText(f"{detail}Retrying in {seconds} s.")
        self.retry.show()
        self.spinner.stop()
        self.show()

    def dismiss(self) -> None:
        self.spinner.stop()
        self.hide()
