"""'New group' dialog: name, description, avatar colour, and members picked with checkboxes + search."""

from typing import List

from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import (
    QButtonGroup, QDialog, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QPushButton, QVBoxLayout,
)

from client.gui.widgets.avatar import Avatar
from client.gui.widgets.sidebar import search_box

GROUP_COLOURS = ["#00A884", "#53BDEB", "#7F66FF", "#E26AB6", "#F15C6D", "#FF7F50", "#FFBC38", "#3BA55C"]
MAX_NAME = 40


class NewGroupDialog(QDialog):
    def __init__(self, contacts: List[dict], parent=None):
        """contacts: [{"username", "display_name", "about"}] - everyone except me."""
        super().__init__(parent)
        self.setObjectName("InfoDialog")
        self.setWindowTitle("New group")
        self.setMinimumSize(460, 640)
        self.colour = GROUP_COLOURS[0]

        v = QVBoxLayout(self)
        v.setContentsMargins(28, 24, 28, 22)
        v.setSpacing(10)

        title = QLabel("New group")
        title.setObjectName("DialogTitle")
        v.addWidget(title)

        # --- avatar preview + colour swatches
        top = QHBoxLayout()
        top.setSpacing(16)
        self.preview = Avatar(64, "", self.colour)
        self.preview.set_person("", self.colour, group=True)
        top.addWidget(self.preview)
        swatches = QHBoxLayout()
        swatches.setSpacing(6)
        group = QButtonGroup(self)
        for colour in GROUP_COLOURS:
            swatch = QPushButton()
            swatch.setObjectName("Swatch")
            swatch.setCheckable(True)
            swatch.setChecked(colour == self.colour)
            swatch.setFixedSize(QSize(26, 26))
            swatch.setCursor(Qt.PointingHandCursor)
            swatch.setToolTip(colour)
            swatch.setStyleSheet(f"background: {colour};")
            swatch.clicked.connect(lambda _=False, c=colour: self._pick_colour(c))
            group.addButton(swatch)
            swatches.addWidget(swatch)
        swatch_box = QVBoxLayout()
        colour_label = QLabel("GROUP ICON COLOUR")
        colour_label.setProperty("role", "field-label")
        swatch_box.addWidget(colour_label)
        swatch_box.addLayout(swatches)
        top.addLayout(swatch_box)
        top.addStretch()
        v.addLayout(top)

        self.name = QLineEdit()
        self.name.setPlaceholderText("Group name (required)")
        self.name.setMaxLength(MAX_NAME)
        self.name.setFixedHeight(40)
        self.description = QLineEdit()
        self.description.setPlaceholderText("Description (optional)")
        self.description.setMaxLength(200)
        self.description.setFixedHeight(40)
        v.addWidget(self.name)
        v.addWidget(self.description)

        members_label = QLabel("ADD MEMBERS")
        members_label.setProperty("role", "field-label")
        v.addSpacing(4)
        v.addWidget(members_label)
        self.search = search_box("Search name or username")
        self.search.textChanged.connect(self._filter)
        v.addWidget(self.search)

        self.members = QListWidget()
        self.members.setObjectName("MemberPicker")
        for contact in sorted(contacts, key=lambda c: c.get("display_name", c["username"]).lower()):
            item = QListWidgetItem(f"{contact.get('display_name') or contact['username']}   "
                                   f"@{contact['username']}")
            item.setData(Qt.UserRole, contact["username"])
            # the checkbox is drawn, but clicks are handled by _toggle (anywhere on the row)
            item.setFlags(item.flags() & ~Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Unchecked)
            self.members.addItem(item)
        self.members.itemChanged.connect(self._update_state)
        self.members.itemClicked.connect(self._toggle)
        v.addWidget(self.members, 1)

        self.selected_label = QLabel()
        self.selected_label.setProperty("role", "hint")
        v.addWidget(self.selected_label)

        buttons = QHBoxLayout()
        buttons.addStretch()
        cancel = QPushButton("Cancel")
        cancel.setObjectName("SecondaryButton")
        cancel.clicked.connect(self.reject)
        self.create_button = QPushButton("Create group")
        self.create_button.setObjectName("PrimaryButton")
        self.create_button.clicked.connect(self.accept)
        for b in (cancel, self.create_button):
            b.setCursor(Qt.PointingHandCursor)
            buttons.addWidget(b)
        v.addLayout(buttons)

        self.name.textChanged.connect(self._update_state)
        self._update_state()
        self.name.setFocus()

    def _pick_colour(self, colour: str) -> None:
        self.colour = colour
        self.preview.set_person("", colour, group=True)

    def _toggle(self, item: QListWidgetItem) -> None:
        item.setCheckState(Qt.Unchecked if item.checkState() == Qt.Checked else Qt.Checked)

    def _filter(self, text: str) -> None:
        text = text.strip().lower()
        for i in range(self.members.count()):
            item = self.members.item(i)
            item.setHidden(bool(text) and text not in item.text().lower())

    def selected_members(self) -> List[str]:
        return [self.members.item(i).data(Qt.UserRole) for i in range(self.members.count())
                if self.members.item(i).checkState() == Qt.Checked]

    def _update_state(self, *_) -> None:
        count = len(self.selected_members())
        self.selected_label.setText(f"{count} selected" if count else "Pick at least one member")
        self.create_button.setEnabled(bool(self.name.text().strip()) and count > 0)

    def values(self) -> dict:
        return {"name": self.name.text().strip(), "description": self.description.text().strip(),
                "avatar_color": self.colour, "members": self.selected_members()}
