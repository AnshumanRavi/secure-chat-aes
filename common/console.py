"""Terminal helpers shared by the server log and the CLI client: ANSI colours on Windows."""

import os
import sys

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
GREY = "\033[90m"


def enable_ansi() -> bool:
    """Turn on ANSI colour codes in the Windows console. Returns True if colours work."""
    if not sys.stdout.isatty():
        return False
    if os.name != "nt":
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)                       # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return True
    except (AttributeError, OSError):
        return False


class Painter:
    """paint(GREEN, "text") -> coloured text, or plain text if the terminal has no colours."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled and enable_ansi()

    def __call__(self, colour: str, text: str) -> str:
        return f"{colour}{text}{RESET}" if self.enabled else text
