"""Entry point of SecureChatServer.exe (PyInstaller needs a script, not `python -m server.server`)."""

import sys

from server.server import main

if __name__ == "__main__":
    sys.exit(main())
