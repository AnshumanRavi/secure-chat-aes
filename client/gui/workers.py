"""Run blocking work (connecting, logging in) off the GUI thread so the window never freezes."""

from typing import Callable

from PySide6.QtCore import QThread, Signal


class Task(QThread):
    """
    Runs fn() on a worker thread.

        task = Task(client.connect)
        task.succeeded.connect(on_ok)      # on_ok(result) runs on the GUI thread
        task.failed.connect(on_error)      # on_error(exception) runs on the GUI thread
        task.start()
    """

    succeeded = Signal(object)
    failed = Signal(object)

    def __init__(self, fn: Callable, parent=None):
        super().__init__(parent)
        self._fn = fn

    def run(self) -> None:
        try:
            result = self._fn()
        except Exception as exc:   # report every failure back to the GUI
            self.failed.emit(exc)
        else:
            self.succeeded.emit(result)
