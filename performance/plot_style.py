"""
One consistent, print-friendly look for every benchmark graph.

Colour rules (validated with the data-viz palette checker for colour-blind safety):
* Each AES mode always has the SAME colour in every chart (colour follows the entity).
* Lines also get distinct marker shapes and a direct label at their end, so they can be
  told apart in black-and-white print too (two of the colours are light on white).
* Ordered values (128 < 192 < 256-bit keys) use light-to-dark steps of one hue.
* Never two y-axes on one chart - different measures get their own panel.
"""

import logging
from pathlib import Path
from typing import Dict, List, Sequence

import matplotlib

matplotlib.use("Agg")             # render to files, no window needed
# the fallback font has no "semibold" weight; matplotlib uses bold instead - no need to warn
logging.getLogger("matplotlib.font_manager").setLevel(logging.ERROR)
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

# --- palette (light mode, white paper) --------------------------------------------
INK = "#0b0b0b"          # titles
INK_2 = "#52514e"        # labels, legends
MUTED = "#898781"        # tick labels
GRID = "#e1e0d9"         # hairline grid
BASELINE = "#c3c2b7"     # axis lines

# categorical slots 1-4, fixed order: GCM, CBC+HMAC, CTR, ECB
MODE_COLOURS = {"GCM": "#2a78d6", "CBC+HMAC": "#eb6834", "CTR": "#1baf7a", "ECB": "#eda100"}
MODE_MARKERS = {"GCM": "o", "CBC+HMAC": "s", "CTR": "^", "ECB": "D"}
MODE_LABELS = {"GCM": "AES-GCM", "CBC+HMAC": "AES-CBC + HMAC", "CTR": "AES-CTR", "ECB": "AES-ECB (insecure)"}
# ordinal: one blue hue, light -> dark
KEY_COLOURS = {128: "#86b6ef", 192: "#2a78d6", 256: "#104281"}
SINGLE = "#2a78d6"       # a chart with one series
# network benchmark: the two systems being compared (categorical slots 1-2)
SYSTEM_COLOURS = {"secure": "#2a78d6", "plain": "#eb6834"}
SYSTEM_MARKERS = {"secure": "o", "plain": "s"}
SYSTEM_LABELS = {"secure": "SecureChat (AES-256-GCM)", "plain": "Plaintext chat (insecure)"}


def apply_style() -> None:
    plt.rcParams.update({
        "figure.facecolor": "white", "axes.facecolor": "white", "savefig.facecolor": "white",
        "font.family": ["Segoe UI", "DejaVu Sans"], "font.size": 10,
        "axes.edgecolor": BASELINE, "axes.linewidth": 0.8, "axes.labelcolor": INK_2,
        "axes.titlesize": 12.5, "axes.titleweight": "semibold", "axes.titlecolor": INK,
        "axes.titlepad": 10, "axes.labelsize": 10,
        "axes.spines.top": False, "axes.spines.right": False,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6, "grid.linestyle": "-",
        "axes.axisbelow": True,
        "xtick.color": MUTED, "ytick.color": MUTED, "xtick.labelcolor": INK_2, "ytick.labelcolor": INK_2,
        "xtick.major.size": 0, "ytick.major.size": 0, "xtick.minor.size": 0, "ytick.minor.size": 0,
        "legend.frameon": False, "legend.fontsize": 9, "legend.labelcolor": INK_2,
        "lines.linewidth": 1.6, "lines.markersize": 5.5,
        "figure.dpi": 100, "savefig.dpi": 300, "savefig.bbox": "tight", "savefig.pad_inches": 0.15,
    })


def size_label(size: float) -> str:
    """1024 -> '1 KB', 1048576 -> '1 MB'."""
    size = int(size)
    if size >= 2 ** 20 and size % 2 ** 20 == 0:
        return f"{size // 2 ** 20} MB"
    if size >= 1024 and size % 1024 == 0:
        return f"{size // 1024} KB"
    return f"{size} B"


def use_size_axis(ax, sizes: Sequence[int]) -> None:
    """Log-scale x axis with ticks exactly at the tested message sizes."""
    ax.set_xscale("log", base=2)
    ax.set_xticks(list(sizes))
    ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: size_label(v)))
    ax.xaxis.set_minor_locator(matplotlib.ticker.NullLocator())
    ax.set_xlabel("Message size (log scale)")


def plain_number_axis(ax, axis: str = "y") -> None:
    """Show 0.1 / 10 / 1,000 instead of 10^-1 / 10^1 / 10^3 on log axes."""
    def fmt(v, _):
        if v >= 1:
            return f"{v:,.0f}"
        return f"{v:g}"
    getattr(ax, f"{axis}axis").set_major_formatter(FuncFormatter(fmt))


def label_line_ends(ax, items: List[Dict], log_y: bool = True, min_gap: float = 0.07) -> None:
    """
    Write each series' name just right of its last point (direct labels), nudging
    labels apart vertically so they never overlap. items: [{"x", "y", "text"}].
    Text uses the label ink - the coloured line next to it carries the identity.
    """
    import math
    ymin, ymax = ax.get_ylim()
    if log_y:
        lo, hi = math.log10(ymin), math.log10(ymax)
        to_frac = lambda y: (math.log10(y) - lo) / (hi - lo)
        to_data = lambda f: 10 ** (lo + f * (hi - lo))
    else:
        to_frac = lambda y: (y - ymin) / (ymax - ymin)
        to_data = lambda f: ymin + f * (ymax - ymin)
    # Sort bottom-to-top and group labels that would overlap; each group is spaced
    # min_gap apart and centred on the average of its points, so labels stay next to their lines.
    placed = sorted(({**item, "frac": to_frac(item["y"])} for item in items), key=lambda i: i["frac"])
    groups: List[List[Dict]] = []
    start = lambda g: sum(i["frac"] for i in g) / len(g) - (len(g) - 1) * min_gap / 2
    for item in placed:
        groups.append([item])
        while len(groups) > 1 and start(groups[-1]) < start(groups[-2]) + len(groups[-2]) * min_gap:
            groups[-2:] = [groups[-2] + groups[-1]]
    for group in groups:
        first = start(group)
        for n, item in enumerate(group):
            ax.annotate(item["text"], xy=(item["x"], to_data(first + n * min_gap)), xycoords="data",
                        xytext=(10, 0), textcoords="offset points", color=INK_2, fontsize=8.5,
                        va="center", annotation_clip=False)


def save(fig, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path)
    plt.close(fig)
    return path
