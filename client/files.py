"""File-sharing helpers shared by the network client and the GUI (no Qt here)."""

import mimetypes
import re
import unicodedata
from pathlib import Path

CHUNK_SIZE = 64 * 1024                  # every chunk is its own AES-GCM packet
MAX_FILE_SIZE = 25 * 1024 * 1024        # 25 MB, same limit as the server
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}

_UNSAFE = re.compile(r'[\\/:*?"<>|\x00-\x1f]')
# Names Windows reserves for devices - "CON.txt" can't be created as a normal file
_WINDOWS_DEVICES = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                    *(f"LPT{i}" for i in range(1, 10))}


def kind_for_path(path) -> str:
    return "image" if Path(path).suffix.lower() in IMAGE_EXTENSIONS else "document"


def mime_type(path) -> str:
    return mimetypes.guess_type(str(path))[0] or "application/octet-stream"


def human_size(size: int) -> str:
    """1536 -> '1.5 KB'."""
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def safe_filename(name: str) -> str:
    """
    Clean a file name that came from the network before saving it.

    Without this, a malicious sender could
      * name a file "..\\..\\Windows\\evil.exe" and make the receiver write outside the
        downloads folder (path traversal);
      * hide the real extension with an invisible right-to-left override:
        "photo\\u202egpj.exe" is displayed as "photoexe.jpg" (extension spoofing);
      * use a Windows device name such as "CON" or "NUL.txt".
    """
    # Unicode "format" characters (category Cf) are invisible: RTL/LTR overrides, zero-width ...
    name = "".join(ch for ch in str(name) if unicodedata.category(ch) != "Cf")
    name = Path(name.replace("\\", "/")).name                # drop any directory part
    name = _UNSAFE.sub("_", name).strip(" .")
    if not name or set(name) == {"_"}:
        name = "file"
    if name.split(".")[0].upper() in _WINDOWS_DEVICES:
        name = "_" + name
    stem, dot, ext = name.rpartition(".")
    if dot and len(name) > 150:
        name = stem[:140] + "." + ext[:9]
    return name[:150]


def unique_path(folder: Path, name: str) -> Path:
    """downloads/report.pdf, or report (1).pdf if that already exists."""
    candidate = folder / name
    stem, suffix = candidate.stem, candidate.suffix
    counter = 1
    while candidate.exists():
        candidate = folder / f"{stem} ({counter}){suffix}"
        counter += 1
    return candidate
