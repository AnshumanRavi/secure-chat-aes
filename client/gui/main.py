"""
SecureChat desktop app.

    python -m client.gui.main                       # server address from config.json / saved settings
    python -m client.gui.main --host 192.168.1.5    # pre-fill another server
"""

import sys

from PySide6.QtCore import QObject
from PySide6.QtGui import QFont, QIcon
from PySide6.QtWidgets import QApplication

from client.gui import icons
from client.gui.login_window import LoginWindow
from client.gui.main_window import MainWindow
from client.gui.settings import ClientSettings
from client.gui.theme import apply_theme
from common.config import build_arg_parser, load_config


class AppController(QObject):
    """Switches between the login screen and the main window."""

    def __init__(self, config, settings: ClientSettings, host_override=None, port_override=None):
        super().__init__()
        self.config = config
        self.settings = settings
        self._overrides = (host_override, port_override)
        self.login_window = None
        self.main_window = None

    def show_login(self, notice: str = "") -> None:
        self.login_window = LoginWindow(self.config, self.settings, notice, *self._overrides)
        self.login_window.logged_in.connect(self.show_main)
        if self.main_window:
            self.login_window.setGeometry(self.main_window.geometry())
        self.login_window.show()
        self._overrides = (None, None)   # only pre-fill from the command line the first time

    def show_main(self, client, bridge, history=None) -> None:
        self.main_window = MainWindow(client, bridge, history=history, settings=self.settings)
        self.main_window.logout_requested.connect(self._logout)
        self.main_window.session_ended.connect(self._session_ended)
        self.main_window.setGeometry(self.login_window.geometry())
        self.main_window.show()
        self.login_window.close()
        bridge.release()   # deliver anything that arrived during login (e.g. offline messages)

    def _logout(self) -> None:
        self.main_window.client.logout()
        self.show_login()
        self.main_window.close()

    def _session_ended(self, reason: str) -> None:
        self.main_window.client.close()
        self.show_login(f"Disconnected: {reason}")
        self.main_window.close()

    def apply_theme(self) -> None:
        apply_theme(QApplication.instance(), self.settings.get("theme"),
                    self.settings.get("wallpaper"), bool(self.settings.get("doodles")))


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    args, _ = build_arg_parser("SecureChat").parse_known_args(argv)
    config = load_config(argv, role="client")

    app = QApplication(sys.argv[:1])
    app.setApplicationName("SecureChat")
    app.setWindowIcon(QIcon(icons.svg_pixmap(icons.LOGO, 64)))
    app.setFont(QFont("Segoe UI", 10))

    controller = AppController(config, ClientSettings(), args.host, args.port)
    controller.apply_theme()
    # "System default" theme: follow Windows when it switches between light and dark
    try:
        app.styleHints().colorSchemeChanged.connect(
            lambda _: controller.settings.get("theme") == "system" and controller.apply_theme())
    except AttributeError:
        pass
    controller.show_login()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
