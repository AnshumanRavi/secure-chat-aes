"""Qt helpers for images and files: thumbnails, scaled previews, opening files."""

import os
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Optional, Tuple

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, Qt, QUrl
from PySide6.QtGui import QDesktopServices, QImage, QImageReader, QPixmap

THUMBNAIL_MAX = 320          # px, longest side of the preview sent with an image
THUMBNAIL_QUALITY = 60       # JPEG quality - small, the real image follows

# colours for document icons, like WhatsApp's file cards
DOC_COLOURS = {
    "pdf": "#E5252A", "doc": "#2A5699", "docx": "#2A5699", "txt": "#8696A0", "rtf": "#2A5699",
    "xls": "#207245", "xlsx": "#207245", "csv": "#207245", "ppt": "#D24726", "pptx": "#D24726",
    "zip": "#F5A623", "rar": "#F5A623", "7z": "#F5A623", "py": "#7F66FF", "js": "#7F66FF",
    "json": "#7F66FF", "html": "#7F66FF", "mp3": "#E542A3", "wav": "#E542A3", "mp4": "#1F7AEC",
}


def extension(name: str) -> str:
    return Path(name).suffix.lstrip(".").lower()


def doc_colour(name: str) -> str:
    return DOC_COLOURS.get(extension(name), "#54656F")


def _reader(path) -> QImageReader:
    reader = QImageReader(str(path))
    reader.setAutoTransform(True)          # respect the phone camera's EXIF rotation
    return reader


def image_size(path) -> Tuple[int, int]:
    image = _reader(path).read()
    return (image.width(), image.height()) if not image.isNull() else (0, 0)


def make_thumbnail(path) -> Optional[bytes]:
    """Small JPEG preview sent in FILE_START, so the receiver sees the photo straight away."""
    image = _reader(path).read()
    if image.isNull():
        return None
    image = image.scaled(THUMBNAIL_MAX, THUMBNAIL_MAX, Qt.KeepAspectRatio, Qt.SmoothTransformation)
    data = QByteArray()
    buffer = QBuffer(data)
    buffer.open(QIODevice.WriteOnly)
    image.save(buffer, "JPEG", THUMBNAIL_QUALITY)
    return bytes(data)


def pixmap_from_bytes(data: bytes) -> QPixmap:
    pixmap = QPixmap()
    pixmap.loadFromData(data)
    return pixmap


@lru_cache(maxsize=64)
def scaled_image(path: str, width: int, height: int) -> QPixmap:
    """Load an image file scaled to cover width x height (2x for sharp high-DPI display)."""
    image: QImage = _reader(path).read()
    if image.isNull():
        return QPixmap()
    image = image.scaled(width * 2, height * 2, Qt.KeepAspectRatioByExpanding, Qt.SmoothTransformation)
    pixmap = QPixmap.fromImage(image)
    pixmap.setDevicePixelRatio(2)
    return pixmap


def open_file(path) -> None:
    QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))


def show_in_folder(path) -> None:
    path = Path(path)
    if os.name == "nt":
        subprocess.Popen(["explorer", f"/select,{path}"])
    else:
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path.parent)))
