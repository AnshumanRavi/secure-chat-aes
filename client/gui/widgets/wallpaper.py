"""
WhatsApp-style chat wallpaper: a background colour with faint doodles, generated in code.

A square tile is drawn once (doodles at jittered grid positions with random
rotation) and then repeated. Doodles that cross an edge are also drawn on the
opposite side, so the tile repeats seamlessly. Tiles are cached per colour/theme.
"""

import random
from functools import lru_cache

from PySide6.QtCore import QPointF
from PySide6.QtGui import QColor, QPainter, QPixmap

from client.gui import icons
from client.gui.palette import DARK, LIGHT

DOODLES = [icons.LOCK, icons.KEY, icons.BUBBLE_OUTLINE, icons.SHIELD_CHECK, icons.HEART,
           icons.STAR, icons.EMOJI, icons.MUSIC, icons.SEND, icons.ATTACH]


@lru_cache(maxsize=16)
def wallpaper_tile(background: str = "#EFEAE2", doodles: bool = True, dark: bool = False,
                   size: int = 360, seed: int = 7) -> QPixmap:
    rng = random.Random(seed)
    tile = QPixmap(size, size)
    tile.fill(QColor(background))
    if not doodles:
        return tile
    colours = DARK if dark else LIGHT
    painter = QPainter(tile)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setRenderHint(QPainter.SmoothPixmapTransform)
    painter.setOpacity(colours.doodle_opacity)

    cells = 6
    step = size / cells
    for row in range(cells):
        for col in range(cells):
            svg = rng.choice(DOODLES)
            doodle_size = rng.randint(20, 30)
            pixmap = icons.svg_pixmap(svg, doodle_size, colours.doodle)
            x = col * step + rng.uniform(0.15, 0.85) * step
            y = row * step + rng.uniform(0.15, 0.85) * step
            angle = rng.uniform(-35, 35)
            for dx in (-size, 0, size):          # wrap around the edges for seamless tiling
                for dy in (-size, 0, size):
                    painter.save()
                    painter.translate(QPointF(x + dx, y + dy))
                    painter.rotate(angle)
                    painter.drawPixmap(QPointF(-doodle_size / 2, -doodle_size / 2), pixmap)
                    painter.restore()
    painter.end()
    return tile
