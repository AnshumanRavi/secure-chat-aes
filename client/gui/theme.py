"""
Loads the Qt stylesheets in client/gui/styles/ and switches between light and dark at runtime.

    light theme = light.qss
    dark theme  = light.qss + dark.qss  (dark.qss only overrides colours)
"""

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication

from client.gui import palette

GUI_DIR = Path(__file__).resolve().parent
STYLES_DIR = GUI_DIR / "styles"
ASSETS_DIR = GUI_DIR / "assets"


def _read(name: str) -> str:
    # %ASSETS% -> absolute path, because Qt resolves url(...) relative to the working directory
    return (STYLES_DIR / f"{name}.qss").read_text(encoding="utf-8").replace("%ASSETS%", ASSETS_DIR.as_posix())


def load_stylesheet(name: str = "light") -> str:
    qss = _read("light")
    if name == "dark":
        qss += "\n" + _read("dark")
    return qss


def system_is_dark() -> bool:
    app = QGuiApplication.instance()
    try:
        return app is not None and app.styleHints().colorScheme() == Qt.ColorScheme.Dark
    except AttributeError:   # Qt older than 6.5 has no colorScheme()
        return False


def resolve(choice: str) -> str:
    """'light' / 'dark' / 'system' -> 'light' or 'dark'."""
    if choice == "system":
        return "dark" if system_is_dark() else "light"
    return "dark" if choice == "dark" else "light"


def apply_theme(app, choice: str = "light", wallpaper: str = "default", doodles: bool = True) -> str:
    """Switch the whole app to a theme right now. Returns the theme actually used."""
    name = resolve(choice)
    palette.set_palette(name)
    palette.set_wallpaper(wallpaper, doodles)
    app.setStyleSheet(load_stylesheet(name))
    from client.gui.widgets.sidebar import refresh_themed_icons   # imported late: avoids a cycle
    widgets = app.allWidgets()
    refresh_themed_icons(widgets)
    for widget in widgets:
        widget.update()
    return name
