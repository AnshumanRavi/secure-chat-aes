"""
Configuration loader for SecureChat.

Settings are read from config.json in the project root. Any setting that is
missing from the file falls back to the defaults below, and --host / --port
given on the command line override the file.

Usage:
    from common.config import load_config
    cfg = load_config()                 # reads config.json + CLI args
    print(cfg.server_host, cfg.port)
"""

import argparse
import json
import sys
from dataclasses import asdict, dataclass, fields
from pathlib import Path

if getattr(sys, "frozen", False):
    # Standalone .exe built with PyInstaller (packaging/securechat.spec): keep keys, the database,
    # logs, settings and config.json next to the .exe - not in the temporary unpack folder
    PROJECT_ROOT = Path(sys.executable).resolve().parent
else:
    PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "config.json"


@dataclass
class Config:
    server_host: str = "0.0.0.0"          # interface the server listens on (all interfaces)
    client_host: str = "127.0.0.1"        # server address the client connects to
    port: int = 5555
    max_message_size: int = 1024 * 1024   # largest allowed network frame (bytes)
    max_file_size: int = 25 * 1024 * 1024 # largest file that can be shared (bytes)
    session_timeout: int = 300            # seconds of silence before a session is dropped
    heartbeat_interval: int = 30          # seconds between PING messages
    max_clock_skew: int = 60              # seconds a message timestamp may differ (replay check)

    def to_dict(self) -> dict:
        return asdict(self)


def _read_file(path: Path) -> dict:
    """Return the settings in a JSON file, keeping only keys Config knows about."""
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    known = {f.name for f in fields(Config)}
    return {k: v for k, v in data.items() if k in known}


def build_arg_parser(description: str = "SecureChat") -> argparse.ArgumentParser:
    """Argument parser with the shared --host / --port / --config options."""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--host", help="Server IP (client) or bind address (server)")
    parser.add_argument("--port", type=int, help="TCP port")
    parser.add_argument("--config", default=str(CONFIG_PATH), help="Path to config.json")
    return parser


def load_config(argv=None, role: str = "client") -> Config:
    """
    Load the configuration.

    role: "server" makes --host override server_host; "client" makes it
          override client_host.
    argv: list of CLI arguments (None = use sys.argv). Unknown arguments are
          ignored so each program can add its own options.
    """
    args, _ = build_arg_parser().parse_known_args(argv)
    cfg = Config(**_read_file(Path(args.config)))

    if args.host:
        if role == "server":
            cfg.server_host = args.host
        else:
            cfg.client_host = args.host
    if args.port:
        cfg.port = args.port
    return cfg


if __name__ == "__main__":
    print(json.dumps(load_config().to_dict(), indent=2))
