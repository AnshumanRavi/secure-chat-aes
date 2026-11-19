# PyInstaller build of SecureChat - two standalone Windows programs, no Python needed:
#
#     .venv\Scripts\python -m pip install -r requirements-build.txt
#     .venv\Scripts\pyinstaller packaging\securechat.spec --noconfirm
#
# Result (copy a whole folder to the other PC, e.g. as a zip):
#     dist\SecureChat\SecureChat.exe               the chat app (no console window)
#     dist\SecureChatServer\SecureChatServer.exe   the server (console window)
#
# Keys, the database, logs, chat history and settings are created NEXT TO the .exe
# (see PROJECT_ROOT in common/config.py), so each folder is self-contained.

import os
import shutil

from PyInstaller.utils.hooks import collect_data_files

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))

client_data = [
    (os.path.join(ROOT, "client", "gui", "styles"), os.path.join("client", "gui", "styles")),
    (os.path.join(ROOT, "client", "gui", "assets"), os.path.join("client", "gui", "assets")),
] + collect_data_files("emoji")

# Libraries the other program needs but this one doesn't - keeps the folders smaller
NOT_IN_CLIENT = ["matplotlib", "numpy", "pytest", "tkinter", "performance", "security_demo", "tests"]
NOT_IN_SERVER = NOT_IN_CLIENT + ["PySide6", "shiboken6", "emoji"]

client_a = Analysis([os.path.join(SPECPATH, "client_entry.py")], pathex=[ROOT], datas=client_data,
                    excludes=NOT_IN_CLIENT)
client_pyz = PYZ(client_a.pure)
client_exe = EXE(client_pyz, client_a.scripts, [], exclude_binaries=True, name="SecureChat",
                 console=False, upx=False)
COLLECT(client_exe, client_a.binaries, client_a.datas, name="SecureChat", upx=False)

server_a = Analysis([os.path.join(SPECPATH, "server_entry.py")], pathex=[ROOT], excludes=NOT_IN_SERVER)
server_pyz = PYZ(server_a.pure)
server_exe = EXE(server_pyz, server_a.scripts, [], exclude_binaries=True, name="SecureChatServer",
                 console=True, upx=False)
COLLECT(server_exe, server_a.binaries, server_a.datas, name="SecureChatServer", upx=False)

# config.json is read from next to the .exe, so a user can edit the port without rebuilding
for folder in ("SecureChat", "SecureChatServer"):
    shutil.copy(os.path.join(ROOT, "config.json"), os.path.join(DISTPATH, folder, "config.json"))
