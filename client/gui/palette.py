"""
Colours used by custom-painted widgets (chat list rows, bubbles, wallpaper, avatars...).

Widgets styled by Qt stylesheets get their colours from styles/light.qss and
styles/dark.qss. Widgets that paint themselves read the CURRENT palette from here
every time they paint, so switching theme at runtime just means: swap the palette,
swap the stylesheet, repaint.
"""

from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass(frozen=True)
class Palette:
    name: str
    panel: str               # headers, input bar
    sidebar: str             # sidebar / chat list background
    row_hover: str
    row_selected: str
    divider: str
    text: str
    text_secondary: str
    text_muted: str
    accent: str
    badge: str
    badge_text: str
    icon: str                # grey icons
    bubble_out: str
    bubble_in: str
    bubble_shadow: Tuple[int, int, int, int]
    meta: str                # time inside bubbles
    card_in: Tuple[int, int, int, int]    # document card tint (incoming bubble)
    card_out: Tuple[int, int, int, int]   # document card tint (outgoing bubble)
    ring_track: str
    placeholder: str         # image placeholder
    doodle: str
    doodle_opacity: float
    intro_bg: str
    login_bg: str
    login_band: str


LIGHT = Palette(
    name="light", panel="#F0F2F5", sidebar="#FFFFFF", row_hover="#F5F6F6", row_selected="#F0F2F5",
    divider="#E9EDEF", text="#111B21", text_secondary="#667781", text_muted="#8696A0", accent="#00A884",
    badge="#25D366", badge_text="#FFFFFF", icon="#54656F", bubble_out="#D9FDD3", bubble_in="#FFFFFF",
    bubble_shadow=(11, 20, 26, 33), meta="#667781", card_in=(11, 20, 26, 15), card_out=(0, 60, 30, 18),
    ring_track="#D1D7DB", placeholder="#D1D7DB", doodle="#4A3B2A", doodle_opacity=0.05,
    intro_bg="#F0F2F5", login_bg="#F0F2F5", login_band="#00A884",
)

DARK = Palette(
    name="dark", panel="#202C33", sidebar="#111B21", row_hover="#202C33", row_selected="#2A3942",
    divider="#222D34", text="#E9EDEF", text_secondary="#8696A0", text_muted="#667781", accent="#00A884",
    badge="#00A884", badge_text="#111B21", icon="#AEBAC1", bubble_out="#005C4B", bubble_in="#202C33",
    bubble_shadow=(0, 0, 0, 60), meta="#A4B1B9", card_in=(255, 255, 255, 12), card_out=(0, 0, 0, 40),
    ring_track="#3B4A54", placeholder="#2A3942", doodle="#FFFFFF", doodle_opacity=0.035,
    intro_bg="#222E35", login_bg="#111B21", login_band="#00A884",
)

# Chat wallpaper presets: name -> (light colour, dark colour)
WALLPAPERS: Dict[str, Tuple[str, str]] = {
    "default": ("#EFEAE2", "#0B141A"),
    "mint": ("#D7F2E3", "#0D2620"),
    "sky": ("#D8E9F5", "#0E1E2B"),
    "lavender": ("#E5DFF5", "#1A1630"),
    "rose": ("#F5DCE2", "#2B1219"),
    "sand": ("#F1E5CF", "#251E12"),
    "slate": ("#DCE1E4", "#151B1F"),
}

_state = {"palette": LIGHT, "wallpaper": "default", "doodles": True}


def current() -> Palette:
    return _state["palette"]


def set_palette(name: str) -> None:
    _state["palette"] = DARK if name == "dark" else LIGHT


def is_dark() -> bool:
    return current().name == "dark"


def set_wallpaper(name: str, doodles: bool = True) -> None:
    _state["wallpaper"] = name if name in WALLPAPERS else "default"
    _state["doodles"] = doodles


def wallpaper() -> Tuple[str, bool]:
    """(background colour for the current theme, show doodles?)"""
    light, dark = WALLPAPERS[_state["wallpaper"]]
    return (dark if is_dark() else light), _state["doodles"]


def theme_icon() -> str:
    return current().icon
