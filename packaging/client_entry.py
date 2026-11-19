"""Entry point of SecureChat.exe (PyInstaller needs a script, not `python -m client.gui.main`)."""

import sys

from client.gui.main import main

if __name__ == "__main__":
    sys.exit(main())
