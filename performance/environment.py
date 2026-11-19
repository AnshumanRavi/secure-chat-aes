"""
Record the test environment (CPU, RAM, OS, Python and library versions) next to the results,
so the numbers in the report can be reproduced and compared.

    python -m performance.environment          # print it
"""

import json
import os
import platform
import sys
import time
from pathlib import Path

import psutil


def cpu_name() -> str:
    """The marketing name of the CPU, e.g. 'Intel(R) Core(TM) Ultra 7 155H'."""
    if os.name == "nt":
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
            return winreg.QueryValueEx(key, "ProcessorNameString")[0].strip()
        except OSError:
            pass
    return platform.processor() or platform.machine()


def collect() -> dict:
    import Crypto
    import matplotlib
    try:
        import PySide6
        pyside = PySide6.__version__
    except ImportError:
        pyside = "not installed"
    return {
        "date": time.strftime("%Y-%m-%d %H:%M"),
        "cpu": cpu_name(),
        "cpu_cores_physical": psutil.cpu_count(logical=False),
        "cpu_cores_logical": psutil.cpu_count(logical=True),
        "ram_gb": round(psutil.virtual_memory().total / 2 ** 30, 1),
        "os": platform.platform(),
        "python": sys.version.split()[0],
        "pycryptodome": Crypto.__version__,
        "pyside6": pyside,
        "matplotlib": matplotlib.__version__,
    }


def save(path: Path) -> dict:
    info = collect()
    Path(path).write_text(json.dumps(info, indent=2), encoding="utf-8")
    return info


if __name__ == "__main__":
    print(json.dumps(collect(), indent=2))
