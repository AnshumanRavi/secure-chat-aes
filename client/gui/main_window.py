"""
Main window, WhatsApp Desktop layout:

    +-------------------+--------------------------------------+
    | Sidebar (~30 %)   | IntroPanel   (no chat open)          |
    |  header, search,  |   - or -                             |
    |  chips, chat list | ChatPanel    (header + messages)     |
    +-------------------+--------------------------------------+
"""

from pathlib import Path
from typing import Optional

from PySide6.QtCore import QEvent, QPoint, Qt, QTimer, Signal
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QHBoxLayout, QMenu, QMessageBox, QSplitter, QStackedWidget, QWidget,
)

from client.files import MAX_FILE_SIZE, human_size
from client.formatting import format_time
from client.gui import icons
from client.gui.bridge import ClientBridge
from client.gui.media import open_file, show_in_folder
from client.gui.widgets.file_bubbles import openable_path
from client.gui.widgets.image_viewer import ImageViewer
from client.gui.widgets.security_code import SecurityCodeDialog
from client.gui.widgets.settings_dialog import SettingsDialog
from common import e2e
from client.gui import palette
from client.gui.settings import ClientSettings
from client.gui.theme import apply_theme
from client.local_store import LocalStore
from client.network import ClientError
from client.gui.chat_store import ChatStore, Message
from client.gui.notifications import NotificationManager
from client.gui.reconnect import Reconnector
from client.gui.typing import TypingNotifier
from client.gui.widgets.chat_view import ChatPanel, IntroPanel
from client.gui.widgets.message_info import MessageInfoDialog
from client.gui.widgets.new_group_dialog import NewGroupDialog
from client.gui.widgets.sidebar import Sidebar, themed_icon
from client.gui.widgets.toast import Toast
from client.network import ChatClient


class MainWindow(QWidget):
    logout_requested = Signal()
    session_ended = Signal(str)   # connection lost / kicked; argument = reason

    def __init__(self, client: ChatClient, bridge: ClientBridge, history: Optional[LocalStore] = None,
                 settings: Optional[ClientSettings] = None):
        super().__init__()
        self.client = client
        self.bridge = bridge
        self.history = history                       # encrypted local history (None = not saved)
        self.settings = settings or ClientSettings(None)
        self._closing_on_purpose = False
        self._kicked_reason: Optional[str] = None
        self._settings_dialog: Optional[SettingsDialog] = None
        profile = client.profile

        self.setObjectName("MainWindow")
        self._base_title = f"SecureChat – {profile['display_name']}"
        self.setWindowTitle(self._base_title)
        self.setMinimumSize(820, 560)

        # End-to-end identity key: kept inside the password-encrypted history so it survives
        # restarts (without a history it lives in memory for this session only).
        # Only its PUBLIC half is sent to the server.
        client.e2e_key = history.identity_key() if history is not None else e2e.generate_identity()
        client.e2e_enabled = bool(self.settings.get("e2e"))
        try:
            client.publish_identity_key()
        except ClientError:
            pass

        self.store = ChatStore(client, bridge, self, history=history)
        self.sidebar = Sidebar(self.store, profile)
        self.intro = IntroPanel()
        self.chat_panel = ChatPanel()
        self.right = QStackedWidget()
        self.right.addWidget(self.intro)
        self.right.addWidget(self.chat_panel)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setObjectName("MainSplitter")
        splitter.setHandleWidth(1)
        splitter.setChildrenCollapsible(False)
        splitter.addWidget(self.sidebar)
        splitter.addWidget(self.right)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 7)
        splitter.setSizes([340, 800])
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(splitter)

        self.toast = Toast(self)

        self.sidebar.chat_selected.connect(self.open_chat)
        self.sidebar.logout_requested.connect(self._logout)
        self.sidebar.new_group_requested.connect(self._new_group)
        self.sidebar.settings_requested.connect(self.open_settings)
        self.sidebar.dark_mode_requested.connect(self._toggle_dark_mode)
        self.sidebar.message_selected.connect(self._jump_to_message)
        self.chat_panel.close_requested.connect(lambda: self.open_chat(None))
        self.chat_panel.search_provider = lambda query, chat_id: self.store.search(query, chat_id)
        self.chat_panel.older_provider = self.store.load_older
        self.chat_panel.info_requested.connect(self._show_info)
        self.chat_panel.e2e_provider = lambda chat: self.store.e2e_active(chat.chat_id)
        self.chat_panel.security_requested.connect(self._show_security_code)
        self.chat_panel.me = self.store.me
        self.chat_panel.name_of = self.store.display_name
        self.chat_panel.group_info.leave_requested.connect(self._leave_group)
        self.store.group_created.connect(self._on_group_created)
        self._pending_group_request: Optional[str] = None
        self.chat_panel.input_bar.send_requested.connect(self._send)
        self.chat_panel.input_bar.mic_clicked.connect(
            lambda: self.toast.show_message("Voice messages aren't supported - type a message instead"))
        self.chat_panel.messages.menu_requested.connect(self._show_message_menu)
        self.chat_panel.messages.open_requested.connect(self._open_file)
        self.chat_panel.input_bar.attach_requested.connect(self._pick_files)
        self.chat_panel.files_dropped.connect(lambda paths: self._send_files(paths))
        self.store.upload_error.connect(lambda text: self.toast.show_message(text, 4000))
        self.store.conversation_changed.connect(self._on_conversation_changed)
        self.store.message_added.connect(self._on_message_added)
        self.store.message_updated.connect(self._on_message_updated)
        self.store.message_removed.connect(self._on_message_removed)
        self.store.message_received.connect(self._on_message_received)

        # "typing…" sent to the other person while we type
        self.typing = TypingNotifier(client, self)
        self.chat_panel.input_bar.text_edited.connect(
            lambda text: self.typing.text_edited(self.store.active_chat, text))

        # tray icon, Windows notifications, sound, unread count
        self.notifier = NotificationManager(self._base_title, self)
        self.notifier.open_chat_requested.connect(self._open_from_notification)
        self.notifier.show_window_requested.connect(self._bring_to_front)
        self.notifier.quit_requested.connect(self.close)

        # automatic reconnection with the yellow banner
        self.reconnector = Reconnector(client, self)
        self.reconnector.connecting.connect(self.sidebar.banner.show_connecting)
        self.reconnector.waiting.connect(self.sidebar.banner.show_waiting)
        self.reconnector.reconnected.connect(self._on_reconnected)
        self.reconnector.gave_up.connect(self._end_session)
        self.sidebar.banner.retry_clicked.connect(self.reconnector.try_now)

        bridge.disconnected.connect(self._on_disconnected)
        bridge.error.connect(self._on_error)
        bridge.security.connect(lambda kind, text: self.toast.show_message(f"⚠ Security: {text}", 4000))
        bridge.profile.connect(self._on_profile_saved)

        self._apply_preferences()
        if self.store.pending_messages():          # written while offline in a previous session
            QTimer.singleShot(0, self.store.resend_pending)

        QShortcut(QKeySequence(Qt.Key_Escape), self, activated=lambda: self.open_chat(None))

    # ---------------------------------------------------------------- chats
    def open_chat(self, chat_id: Optional[str]) -> None:
        if chat_id != self.store.active_chat:
            self.typing.stop()            # leaving a chat = stopped typing there
        self.store.open_chat(chat_id)
        self.sidebar.select_chat(chat_id)
        chat = self.store.get(chat_id) if chat_id else None
        if chat is None:
            self.right.setCurrentWidget(self.intro)
            return
        self.chat_panel.set_conversation(chat)
        self.right.setCurrentWidget(self.chat_panel)
        self._mark_read_if_visible()

    def _send(self, text: str) -> None:
        if self.store.active_chat:
            self.typing.stop()
            self.store.send_text(self.store.active_chat, text)

    def _on_conversation_changed(self, chat_id: str) -> None:
        if chat_id == self.store.active_chat:
            self.chat_panel.refresh()
            if self.chat_panel.group_info.isVisible():
                self._fill_group_info()           # e.g. someone just left
        self._update_unread()

    # ------------------------------------------------------- settings / theme
    def _apply_preferences(self) -> None:
        s = self.settings
        self.notifier.sound_enabled = bool(s.get("sound"))
        self.notifier.popups_enabled = bool(s.get("popups"))
        self.notifier.show_previews = bool(s.get("previews"))
        self.store.send_read_receipts = bool(s.get("read_receipts"))
        self.typing.enabled = bool(s.get("typing_indicator"))
        self.client.e2e_enabled = bool(s.get("e2e"))
        self.chat_panel.refresh()                 # the encryption notice depends on the E2E switch

    def _show_security_code(self) -> None:
        chat = self.chat_panel.chat
        if chat is None or chat.is_group:
            self.toast.show_message("Group chats are protected by AES-256-GCM connection encryption", 3500)
            return
        my_pem = e2e.export_public(self.client.e2e_key) if self.client.e2e_key is not None else None
        dialog = SecurityCodeDialog(self.client.username, my_pem, chat.chat_id, chat.title,
                                    self.client.peer_identity(chat.chat_id), chat.verified,
                                    e2e_on=self.client.e2e_enabled, parent=self)
        dialog.verified_changed.connect(lambda verified: self.store.set_verified(chat.chat_id, verified))
        dialog.exec()

    def open_settings(self, page: str = "profile") -> None:
        dialog = SettingsDialog(self.client, self.settings, self.history, start_page=page, parent=self)
        dialog.theme_changed.connect(lambda _: self._apply_theme())
        dialog.wallpaper_changed.connect(lambda *_: self._apply_theme())
        dialog.preferences_changed.connect(self._apply_preferences)
        dialog.profile_save_requested.connect(self._save_profile)
        dialog.clear_history_requested.connect(self._clear_history)
        self._settings_dialog = dialog
        dialog.exec()
        self._settings_dialog = None

    def _apply_theme(self) -> None:
        apply_theme(QApplication.instance(), self.settings.get("theme"),
                    self.settings.get("wallpaper"), bool(self.settings.get("doodles")))

    def _toggle_dark_mode(self) -> None:
        self.settings.set("theme", "light" if palette.is_dark() else "dark")
        self._apply_theme()

    def _save_profile(self, display_name: str, about: str) -> None:
        try:
            self.client.update_profile(display_name=display_name, about=about)
        except ClientError as exc:
            self.toast.show_message(f"Couldn't save: {exc}")

    def _on_profile_saved(self, profile: dict) -> None:
        self.sidebar.my_avatar.set_person(profile.get("display_name", ""), profile.get("avatar_color", "#00A884"))
        self.sidebar.my_avatar.setToolTip(f"{profile.get('display_name')}  (@{profile.get('username')})")
        self._base_title = f"SecureChat – {profile.get('display_name')}"
        self._update_unread()
        if self._settings_dialog is not None:
            self._settings_dialog.profile_saved(profile)

    def _clear_history(self) -> None:
        self.store.clear_history()
        self.chat_panel.reload_messages()
        self.toast.show_message("Chat history deleted from this computer")

    def _jump_to_message(self, chat_id: str, msg_id: str, query: str) -> None:
        """A global-search result was clicked: open the chat and highlight that message."""
        self.open_chat(chat_id)
        self.chat_panel.open_search(query, jump_to=msg_id)

    # ---------------------------------------------------------------- groups
    def _new_group(self) -> None:
        contacts = [{"username": c.chat_id, "display_name": c.title, "about": c.about}
                    for c in self.store.conversations() if not c.is_group]
        if not contacts:
            self.toast.show_message("There's nobody else on this server to add yet")
            return
        dialog = NewGroupDialog(contacts, self)
        if dialog.exec() != NewGroupDialog.Accepted:
            return
        values = dialog.values()
        self._pending_group_request = self.store.create_group(
            values["name"], values["members"], values["description"], values["avatar_color"])
        if self._pending_group_request is None:
            self.toast.show_message("You're offline - try again when you're connected")

    def _on_group_created(self, chat_id: str, request_id: str) -> None:
        if request_id == self._pending_group_request:     # the group I just created: open it
            self._pending_group_request = None
            self.open_chat(chat_id)

    def _about_of(self, username: str) -> str:
        if username == self.store.me:
            return self.client.profile.get("about", "")
        chat = self.store.get(username)
        return chat.about if chat else ""

    def _colour_of(self, username: str) -> str:
        if username == self.store.me:
            return self.client.profile.get("avatar_color", "#00A884")
        chat = self.store.get(username)
        return chat.avatar_color if chat else "#8696A0"

    def _fill_group_info(self) -> None:
        chat = self.chat_panel.chat
        if chat and chat.is_group:
            self.chat_panel.group_info.set_group(chat, self.store.me, self.store.display_name,
                                                 self._about_of, self._colour_of,
                                                 real_name_of_me=self.client.profile.get("display_name", ""))

    def _show_info(self) -> None:
        chat = self.chat_panel.chat
        if chat is None:
            return
        if chat.is_group:
            self._fill_group_info()
            self.chat_panel.group_info.slide_in()
        else:
            self._show_contact_info()

    def _leave_group(self, chat_id: str) -> None:
        chat = self.store.get(chat_id)
        answer = QMessageBox.question(self, "Leave group", f"Leave “{chat.title}”?\n\n"
                                      "You won't receive its messages any more.")
        if answer != QMessageBox.Yes:
            return
        if not self.store.leave_group(chat_id):
            self.toast.show_message("You're offline - try again when you're connected")

    # -------------------------------------------------------- notifications
    def _update_unread(self) -> None:
        total = sum(chat.unread for chat in self.store.conversations())
        self.setWindowTitle(f"({total}) {self._base_title}" if total else self._base_title)
        if total != self.notifier.unread:
            self.notifier.set_unread(total)

    def _on_message_received(self, chat_id: str, msg: Message) -> None:
        focused = self.isActiveWindow() and not self.isMinimized()
        if focused and chat_id == self.store.active_chat:
            return                        # you're looking at it - no need to notify
        chat = self.store.get(chat_id)
        text = f"{self.store.first_name(msg.sender)}: {msg.preview}" if chat and chat.is_group else msg.preview
        # Window in the background: Windows notification + sound. Focused but another chat: sound only.
        self.notifier.notify(chat_id, chat.title if chat else chat_id, text, popup=not focused)

    def _bring_to_front(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _open_from_notification(self, chat_id: str) -> None:
        self._bring_to_front()
        self.open_chat(chat_id)

    def _on_message_added(self, chat_id: str, msg: Message) -> None:
        if chat_id == self.store.active_chat:
            self.chat_panel.messages.add_message(msg)
            if not msg.outgoing:
                self._mark_read_if_visible()

    def _on_message_updated(self, chat_id: str, msg: Message) -> None:
        if chat_id == self.store.active_chat:
            self.chat_panel.messages.update_message(msg)

    def _on_message_removed(self, chat_id: str, _msg_id: str) -> None:
        if chat_id == self.store.active_chat:
            self.chat_panel.reload_messages()

    # -------------------------------------------------------- read receipts
    def _mark_read_if_visible(self) -> None:
        """Blue ticks only once the chat is really in front of the user (open + window focused)."""
        if self.store.active_chat and self.isActiveWindow() and not self.isMinimized():
            self.store.mark_read(self.store.active_chat)

    def changeEvent(self, event) -> None:
        super().changeEvent(event)
        if event.type() == QEvent.ActivationChange:
            self._mark_read_if_visible()

    # --------------------------------------------------------- message menu
    def _show_message_menu(self, msg: Message, pos: QPoint) -> None:
        menu = QMenu(self)
        if msg.is_file:
            path = openable_path(msg)
            open_action = menu.addAction(themed_icon(icons.OPEN_EXTERNAL, 18), "Open",
                                         lambda: self._open_file(msg))
            folder_action = menu.addAction(themed_icon(icons.FOLDER, 18), "Show in folder",
                                           lambda: show_in_folder(path))
            open_action.setEnabled(bool(path))
            folder_action.setEnabled(bool(path))
        else:
            menu.addAction(themed_icon(icons.COPY, 18), "Copy", lambda: self._copy(msg))
        menu.addAction(themed_icon(icons.INFO, 18), "Message info", lambda: self._message_info(msg))
        menu.addSeparator()
        menu.addAction(themed_icon(icons.DELETE, 18), "Delete for me",
                       lambda: self.store.delete_message(msg.chat_id, msg.id))
        menu.exec(pos)

    def _copy(self, msg: Message) -> None:
        row = self.chat_panel.messages.row(msg.id)
        selected = row.bubble.label.selectedText() if row else ""
        # remove the zero-width spaces added for wrapping; Qt reports line breaks as U+2029
        text = selected.replace(chr(0x200B), "").replace(chr(0x2029), chr(10)) if selected else msg.text
        QApplication.clipboard().setText(text)
        self.toast.show_message("Message copied", 1500)

    # ------------------------------------------------------------------ files
    def _pick_files(self, kind: str) -> None:
        if not self.store.active_chat:
            return
        if kind == "image":
            caption, filters = "Send photos", "Images (*.png *.jpg *.jpeg *.gif *.bmp *.webp)"
        else:
            caption, filters = "Send documents", "All files (*.*)"
        paths, _ = QFileDialog.getOpenFileNames(self, caption, str(Path.home()), filters)
        if paths:
            self._send_files(paths, kind)

    def _send_files(self, paths, kind: Optional[str] = None) -> None:
        chat_id = self.store.active_chat
        if not chat_id:
            return
        for path in paths:
            size = Path(path).stat().st_size
            if size == 0:
                self.toast.show_message(f"{Path(path).name} is empty")
            elif size > MAX_FILE_SIZE:
                self.toast.show_message(f"{Path(path).name} is {human_size(size)} - the limit is "
                                        f"{human_size(MAX_FILE_SIZE)}", 4000)
            elif not self.client.connected:
                self.toast.show_message("You're offline - files can be sent once you're connected")
                return
            else:
                self.store.send_file(chat_id, path, kind if kind == "document" else None)

    def _open_file(self, msg: Message) -> None:
        path = openable_path(msg)
        if not path:
            return
        if msg.kind == "image":
            sender = "You" if msg.outgoing else self.store.display_name(msg.sender)
            ImageViewer(path, sender, f"{format_time(msg.ts)} · {msg.file['name']}", self).exec()
        else:
            open_file(path)

    def _message_info(self, msg: Message) -> None:
        chat = self.store.get(msg.chat_id)
        MessageInfoDialog(msg, self.client.key_fingerprint, chat.title if chat else msg.chat_id, self,
                          name_of=self.store.display_name).exec()

    def _show_contact_info(self) -> None:
        chat = self.chat_panel.chat
        if chat:
            self.toast.show_message(f"{chat.title}  ·  @{chat.chat_id}  ·  “{chat.about}”", 3500)

    # ----------------------------------------------------- connection / session
    def _on_error(self, message: dict) -> None:
        code = message.get("code")
        if code == "SESSION_REPLACED":            # same account logged in elsewhere - don't fight it
            self._kicked_reason = message.get("message", "You logged in from another device")
            self._end_session(self._kicked_reason)
        elif code == "SERVER_SHUTDOWN":           # the disconnect that follows triggers a reconnect
            self.toast.show_message("The server is restarting…")
        else:
            self.toast.show_message(message.get("message", "Something went wrong"))

    def _on_disconnected(self, reason: str) -> None:
        if self._closing_on_purpose:
            return
        if self._kicked_reason:
            self._end_session(self._kicked_reason)
            return
        self.store.connection_lost()
        self.typing.stop()
        self.reconnector.start()

    def _on_reconnected(self) -> None:
        self.sidebar.banner.dismiss()
        try:
            self.client.publish_identity_key()   # harmless if the server already has it
        except ClientError:
            pass
        resent = self.store.resend_pending()
        self.toast.show_message("Back online" + (f" · {resent} queued message(s) sent" if resent else ""))
        self._mark_read_if_visible()

    def _shutdown(self) -> None:
        self.reconnector.stop()
        self.typing.stop()
        self.notifier.hide()
        self.store.flush()                     # write the last changes to the encrypted history
        if self.history is not None:
            self.history.close()
            self.history = self.store.history = None

    def _end_session(self, reason: str) -> None:
        if self._closing_on_purpose:
            return
        self._closing_on_purpose = True
        self._shutdown()
        self.session_ended.emit(reason)

    def _logout(self) -> None:
        self._closing_on_purpose = True
        self._shutdown()
        self.logout_requested.emit()

    def closeEvent(self, event) -> None:
        if not self._closing_on_purpose:      # window closed with the X button
            self._closing_on_purpose = True
            self._shutdown()
            self.client.logout()
        super().closeEvent(event)
