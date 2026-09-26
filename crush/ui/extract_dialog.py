# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Extract a VFS member to disk behind a progress dialog, with a temp-space check.

Opening a member of an archive or disk image in another window (or in an
external app) needs it as a real file. That copy takes as long as the
member is big -- about a minute for 17 GB -- so it runs on a worker thread
behind a determinate progress dialog with a Cancel button, in bounded memory.
The destination is checked for free space first, and a RAM-backed temp
directory (tmpfs) is called out, because "spilling to disk" there would just
fill memory.
"""
from __future__ import annotations

import hashlib
import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import QEventLoop, QObject, QSettings, QThread, Qt, Signal
from PySide6.QtWidgets import QFileDialog, QMessageBox, QProgressDialog, QWidget

from crush.core import tempdir
from crush.core.vfs import VFS, VFSNode
from crush.core.vfs_stream import CopyCancelledError, HashingWriter, copy_stream
from crush.ui.log_scope import window_log_scope
from crush.ui.i18n import translate

TEMP_DIR_SETTING = "log_temp_dir"

_PROGRESS_STEPS = 1000
_PROGRESS_INTERVAL = 0.1  # seconds between UI updates


def format_size(size: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    value = float(size)
    unit_index = 0
    while value >= 1024 and unit_index < len(units) - 1:
        value /= 1024
        unit_index += 1
    if unit_index == 0:
        return f"{int(value)} {units[unit_index]}"
    return f"{value:.1f} {units[unit_index]}"


def apply_saved_temp_dir(settings: QSettings) -> None:
    tempdir.configure(settings.value(TEMP_DIR_SETTING, "", type=str))


def choose_temp_directory(parent: QWidget, settings: QSettings) -> bool:
    """Let the user pick a temp directory and persist it; False if cancelled."""
    start = str(tempdir.root())
    chosen = QFileDialog.getExistingDirectory(
        parent, translate("ExtractDialog", "Choose temp directory"), start
    )
    if not chosen:
        return False
    settings.setValue(TEMP_DIR_SETTING, chosen)
    tempdir.configure(chosen)
    return True


def confirm_temp_space(parent: QWidget, settings: QSettings, needed: int, what: str) -> bool:
    """True when it is fine to write *needed* bytes to the temp directory.

    Blocks on too little free space and asks before filling RAM-backed
    storage; in both cases the user can pick another directory on the spot.
    """
    while True:
        try:
            check = tempdir.check_space(needed)
        except OSError as exc:
            QMessageBox.critical(
                parent,
                translate("ExtractDialog", "Temp directory unusable"),
                translate(
                    "ExtractDialog",
                    "The temp directory {path} cannot be used:\n{exc}\n\n"
                    "Set another one under Tools → Temp Directory…",
                ).format(path=tempdir.root(), exc=exc),
            )
            return False

        if check.enough_space and not check.ram_warning:
            return True

        box = QMessageBox(parent)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle(translate("ExtractDialog", "Temp directory"))
        if not check.enough_space:
            box.setText(
                translate(
                    "ExtractDialog",
                    "Not enough free space in the temp directory\n{location}\n\n"
                    "Extracting {what} needs {needed}, "
                    "but only {free} is free.",
                ).format(
                    location=check.location,
                    what=what,
                    needed=format_size(check.needed),
                    free=format_size(check.free),
                )
            )
            proceed = None
        else:
            avail = (
                translate("ExtractDialog", " ({available} available)").format(
                    available=format_size(check.ram_available)
                )
                if check.ram_available is not None
                else ""
            )
            box.setText(
                translate(
                    "ExtractDialog",
                    "The temp directory\n{location}\nis RAM-backed (tmpfs), so extracting "
                    "{what} will use about {needed} of memory{available}.\n\n"
                    "A different directory on disk is safer.",
                ).format(
                    location=check.location,
                    what=what,
                    needed=format_size(check.needed),
                    available=avail,
                )
            )
            proceed = box.addButton(
                translate("ExtractDialog", "Continue anyway"),
                QMessageBox.ButtonRole.DestructiveRole,
            )
        choose = box.addButton(
            translate("ExtractDialog", "Choose directory…"), QMessageBox.ButtonRole.AcceptRole
        )
        cancel = box.addButton(QMessageBox.StandardButton.Cancel)
        box.setDefaultButton(cancel)
        box.exec()
        clicked = box.clickedButton()
        if proceed is not None and clicked is proceed:
            return True
        if clicked is choose:
            if choose_temp_directory(parent, settings):
                continue
            return False
        return False


@dataclass
class CopyOutcome:
    status: str  # "ok", "cancelled" or "failed"
    message: str = ""
    sha256: str = ""
    bytes_copied: int = 0


class _CopyWorker(QObject):
    progress = Signal(int, object, object)  # permille, bytes done, bytes total
    finished = Signal(object)  # bytes copied, sha256 hex or ""
    failed = Signal(str)
    cancelled = Signal()

    def __init__(
        self,
        vfs: VFS,
        node: VFSNode,
        dest: Path,
        want_hash: bool,
        cancel: threading.Event,
        window_id: str | None,
    ) -> None:
        super().__init__()
        self._vfs = vfs
        self._node = node
        self._dest = dest
        self._want_hash = want_hash
        self._cancel = cancel
        self._window_id = window_id

    def run(self) -> None:
        with window_log_scope(self._window_id):
            self._run()

    def _run(self) -> None:
        total = self._node.size
        last_emit = 0.0

        def report(done: int, _total: int | None) -> None:
            nonlocal last_emit
            now = time.monotonic()
            if now - last_emit < _PROGRESS_INTERVAL:
                return
            last_emit = now
            permille = min(_PROGRESS_STEPS, done * _PROGRESS_STEPS // total) if total else 0
            self.progress.emit(permille, done, total)

        try:
            hasher = hashlib.sha256() if self._want_hash else None
            with self._vfs.open(self._node) as src, open(self._dest, "wb") as dst:
                sink = HashingWriter(dst, hasher) if hasher is not None else dst
                copied = copy_stream(
                    src,
                    sink,  # type: ignore[arg-type]
                    total=total,
                    progress=report,
                    cancelled=self._cancel.is_set,
                )
        except CopyCancelledError:
            self.cancelled.emit()
            return
        except Exception as exc:  # noqa: BLE001 - reported to the caller, not swallowed
            self.failed.emit(str(exc))
            return
        self.finished.emit((copied, hasher.hexdigest() if hasher is not None else ""))


class _CopyController(QObject):
    """Lives on the UI thread so the worker's signals reach it through the UI
    thread's event loop (see busy_dialog._BusyController)."""

    def __init__(self, parent: QWidget, dialog: QProgressDialog, loop: QEventLoop, name: str) -> None:
        super().__init__(parent)
        self._dialog = dialog
        self._loop = loop
        self._name = name
        self.outcome = CopyOutcome(status="failed", message="Copy did not finish")

    def on_progress(self, permille: int, done: object, total: object) -> None:
        self._dialog.setValue(permille)
        if isinstance(done, int) and isinstance(total, int) and total:
            self._dialog.setLabelText(
                translate("ExtractDialog", "Extracting {name}\n{done} of {total}").format(
                    name=self._name, done=format_size(done), total=format_size(total)
                )
            )

    def on_finished(self, result: object) -> None:
        copied, digest = result  # type: ignore[misc]
        self.outcome = CopyOutcome(status="ok", sha256=digest, bytes_copied=copied)
        self._loop.quit()

    def on_failed(self, message: str) -> None:
        self.outcome = CopyOutcome(status="failed", message=message)
        self._loop.quit()

    def on_cancelled(self) -> None:
        self.outcome = CopyOutcome(status="cancelled")
        self._loop.quit()


def copy_node_with_progress(
    parent: QWidget,
    vfs: VFS,
    node: VFSNode,
    dest: Path,
    *,
    title: str,
    want_hash: bool = False,
    window_id: str | None = None,
) -> CopyOutcome:
    """Copy one VFS member to *dest* behind a modal progress dialog.

    Runs a nested event loop, so the caller stays synchronous while the UI
    keeps repainting. A partially written *dest* is removed on cancel or
    failure.
    """
    cancel = threading.Event()
    dialog = QProgressDialog(
        translate("ExtractDialog", "Extracting {name}").format(name=node.name),
        translate("ExtractDialog", "Cancel"),
        0,
        _PROGRESS_STEPS,
        parent,
    )
    dialog.setWindowTitle(title)
    dialog.setWindowModality(Qt.WindowModality.ApplicationModal)
    dialog.setMinimumDuration(0)
    dialog.setAutoClose(False)
    dialog.setAutoReset(False)
    dialog.setValue(0)
    dialog.canceled.connect(cancel.set)

    loop = QEventLoop(parent)
    thread = QThread(parent)
    worker = _CopyWorker(vfs, node, dest, want_hash, cancel, window_id)
    controller = _CopyController(parent, dialog, loop, node.name)
    worker.moveToThread(thread)
    thread.started.connect(worker.run)
    worker.progress.connect(controller.on_progress)
    worker.finished.connect(controller.on_finished)
    worker.failed.connect(controller.on_failed)
    worker.cancelled.connect(controller.on_cancelled)

    thread.start()
    dialog.show()
    loop.exec()
    thread.quit()
    thread.wait()
    dialog.close()
    dialog.deleteLater()
    worker.deleteLater()
    thread.deleteLater()
    controller.deleteLater()

    outcome = controller.outcome
    if outcome.status != "ok":
        try:
            dest.unlink(missing_ok=True)
        except OSError:
            logging.getLogger("crush").warning("Could not remove partial file %s", dest)
    return outcome
