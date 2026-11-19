"""
Client settings saved in client_settings.json (git-ignored).

Also stores the fingerprints of servers the user has verified ("trust on first
use", the same model SSH uses): the first connection to a server shows its
fingerprint for the user to check; afterwards a matching fingerprint is
accepted silently, and a CHANGED fingerprint triggers a man-in-the-middle warning.
"""

import json
from pathlib import Path
from typing import Optional

from common.config import PROJECT_ROOT

SETTINGS_PATH = PROJECT_ROOT / "client_settings.json"


DEFAULTS = {
    "theme": "light",            # light | dark | system
    "wallpaper": "default",      # see palette.WALLPAPERS
    "doodles": True,
    "sound": True,
    "popups": True,              # Windows notifications
    "previews": True,            # show message text in notifications
    "read_receipts": True,       # send READ (blue ticks)
    "typing_indicator": True,    # send TYPING
    "e2e": True,                 # end-to-end encrypt 1-to-1 messages
}


class ClientSettings:
    def __init__(self, path: Optional[Path] = SETTINGS_PATH):
        """path=None keeps settings in memory only (used by tests)."""
        self.path = Path(path) if path else None
        try:
            self.data = json.loads(self.path.read_text(encoding="utf-8")) if self.path else {}
        except (OSError, ValueError):
            self.data = {}
        self.data.setdefault("known_servers", {})

    def save(self) -> None:
        if self.path is None:
            return
        try:
            self.path.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
        except OSError:
            pass   # settings are a convenience; never crash because of them

    # ------------------------------------------------------- preferences
    def get(self, key: str):
        return self.data.get(key, DEFAULTS.get(key))

    def set(self, key: str, value) -> None:
        self.data[key] = value
        self.save()

    # ------------------------------------------------------- server address
    @property
    def remember_server(self) -> bool:
        return bool(self.data.get("remember_server", True))

    def saved_server(self) -> Optional[tuple]:
        if self.remember_server and self.data.get("server_host"):
            return self.data["server_host"], int(self.data.get("server_port", 5555))
        return None

    def set_server(self, host: str, port: int, remember: bool) -> None:
        self.data["remember_server"] = remember
        if remember:
            self.data["server_host"], self.data["server_port"] = host, port
        else:
            self.data.pop("server_host", None)
            self.data.pop("server_port", None)

    # ------------------------------------------------------------ username
    @property
    def last_username(self) -> str:
        return self.data.get("last_username", "")

    @last_username.setter
    def last_username(self, value: str) -> None:
        self.data["last_username"] = value

    # ------------------------------------------------- trusted fingerprints
    def trusted_fingerprint(self, host: str, port: int) -> Optional[str]:
        return self.data["known_servers"].get(f"{host}:{port}")

    def trust(self, host: str, port: int, fingerprint: str) -> None:
        self.data["known_servers"][f"{host}:{port}"] = fingerprint
