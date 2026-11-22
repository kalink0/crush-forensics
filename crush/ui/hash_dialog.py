# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Compute Hash: hash entries the analyst picked, behind a progress dialog,
and show the result.

The algorithm is the analyst's choice (MD5, SHA-1, SHA-256 or all three, in
one read pass). A folder is hashed file by file, all the way down. Every
value goes to the window's hash store (shown in the Properties panel) and
to the log; the result dialog lists each entry with its outcome -- an entry
that couldn't be read, or a folder that couldn't be listed, is a row with
the reason, and a cancelled run says it is incomplete.
"""
from __future__ import annotations

import csv
import hashlib
import io
import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from PySide6.QtCore import (
    QAbstractTableModel,
    QEventLoop,
    QModelIndex,
    QObject,
    QPersistentModelIndex,
    QThread,
    Qt,
    Signal,
)
from PySide6.QtGui import QAction, QGuiApplication
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHeaderView,
    QLabel,
    QMenu,
    QMessageBox,
    QProgressDialog,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from crush.core.hashing import (
    ALGORITHMS,
    DISPLAY_NAMES,
    HashCancelled,
    HashReadError,
    HashStore,
    hash_node,
    iter_files,
)
from crush.core.issues import render_value
from crush.core.vfs import VFS, VFSNode, has_no_content
from crush.ui.extract_dialog import format_size
from crush.ui.i18n import translate
from crush.ui.log_scope import window_log_scope

_PROGRESS_STEPS = 1000
_PROGRESS_INTERVAL = 0.1  # seconds between UI updates
_logger = logging.getLogger(__name__)

# Outcomes of one row (plain facts; the dialog words them).
OK = "ok"
NOT_READ = "not_read"
NO_CONTENT = "no_content"  # the entry's status says no content is read or stored
FOLDER = "folder"


def add_hash_actions(menu: QMenu) -> dict[QAction, tuple[str, ...]]:
    """Fill *menu* with one action per algorithm and "All"; returns each
    action's algorithms."""
    actions: dict[QAction, tuple[str, ...]] = {}
    for alg in ALGORITHMS:
        actions[menu.addAction(DISPLAY_NAMES[alg])] = (alg,)  # i18n: keep -- algorithm name
    menu.addSeparator()
    actions[menu.addAction(translate("HashDialog", "All"))] = ALGORITHMS
    return actions


def add_hash_menu(menu: QMenu, title: str | None = None) -> dict[QAction, tuple[str, ...]]:
    """A "Compute Hash" submenu in *menu*; see add_hash_actions. The
    submenu is parented to *menu*, so it lives as long as *menu* does, not
    only as long as this call holds a reference to it."""
    sub = QMenu(title or translate("HashDialog", "Compute Hash"), menu)
    menu.addMenu(sub)
    return add_hash_actions(sub)


@dataclass
class HashRow:
    node: VFSNode
    vfs: VFS
    outcome: str  # OK, NOT_READ, NO_CONTENT or FOLDER
    source: str = ""  # the source the entry belongs to (paths are relative to it)
    digests: dict[str, bytes] = field(default_factory=dict)
    bytes_read: int | None = None
    reason: str = ""  # why it was not read
    # The store holds another value for this entry, computed earlier.
    differs: bool = False


@dataclass
class HashRun:
    algorithms: tuple[str, ...]
    rows: list[HashRow]
    files_total: int
    cancelled: bool = False
    failed: str = ""  # the run itself broke off (not one entry)


class _HashWorker(QObject):
    progress = Signal(object, object, object, object)  # files done/total, bytes done/total
    finished = Signal(object)  # HashRun

    def __init__(
        self,
        entries: list[tuple[VFSNode, VFS]],
        algorithms: tuple[str, ...],
        store: HashStore,
        cancel: threading.Event,
        window_id: str | None,
        source_names: dict[int, str] | None = None,
    ) -> None:
        super().__init__()
        self._entries = entries
        self._algorithms = algorithms
        self._store = store
        self._cancel = cancel
        self._window_id = window_id
        self._source_names = source_names or {}

    def _source(self, vfs: VFS) -> str:
        return self._source_names.get(id(vfs)) or vfs.root().name

    def run(self) -> None:
        with window_log_scope(self._window_id):
            self._run()

    def _run(self) -> None:
        rows: list[HashRow] = []
        seen: set[int] = set()
        files_total = 0
        bytes_total = 0
        files_done = 0
        bytes_before = 0
        last_emit = 0.0
        run = HashRun(self._algorithms, rows, 0)
        try:
            # A file selected along with its folder is hashed once.
            nodes: list[tuple[VFSNode, VFS]] = []
            for top, vfs in self._entries:
                for node in iter_files(top):
                    if id(node) in seen:
                        continue
                    seen.add(id(node))
                    nodes.append((node, vfs))
                    if not node.is_dir:
                        files_total += 1
                        bytes_total += node.size
            run.files_total = files_total

            def report(done_in_file: int) -> None:
                nonlocal last_emit
                now = time.monotonic()
                if now - last_emit < _PROGRESS_INTERVAL:
                    return
                last_emit = now
                self.progress.emit(files_done, files_total, bytes_before + done_in_file, bytes_total)

            for node, vfs in nodes:
                if self._cancel.is_set():
                    raise HashCancelled()
                source = self._source(vfs)
                if node.is_dir:
                    rows.append(HashRow(node, vfs, FOLDER, source))
                    continue
                if has_no_content(node):
                    rows.append(HashRow(node, vfs, NO_CONTENT, source))
                    _logger.info(
                        "HASH not computed, no content is read or stored: %s (%s)",
                        node.path, node.status,
                    )
                    files_done += 1
                    bytes_before += node.size
                    continue
                try:
                    digests, read = hash_node(
                        vfs, node, self._algorithms, cancelled=self._cancel.is_set, progress=report
                    )
                except HashReadError as exc:
                    rows.append(HashRow(node, vfs, NOT_READ, source, reason=str(exc)))
                    _logger.warning("HASH not computed, could not be read: %s: %s", node.path, exc)
                else:
                    self._store.record(vfs, node, digests)
                    known = self._store.get(vfs, node)
                    differs = any(len(known.get(alg, [])) > 1 for alg in digests)
                    rows.append(HashRow(node, vfs, OK, source, digests, read, differs=differs))
                    _logger.info(
                        "HASH %s  size=%d  path=%s",
                        "  ".join(f"{alg}={digests[alg].hex()}" for alg in self._algorithms),
                        read, node.path,
                    )
                    if differs:
                        _logger.warning(
                            "HASH differs from a value computed earlier for this entry: %s",
                            node.path,
                        )
                files_done += 1
                bytes_before += node.size
        except HashCancelled:
            run.cancelled = True
            _logger.warning(
                "HASH cancelled by the analyst: %d of %d file(s) hashed",
                sum(1 for r in rows if r.outcome == OK), files_total,
            )
        except Exception as exc:  # noqa: BLE001 -- reported, the rows so far kept
            run.failed = str(exc)
            _logger.error("HASH run failed: %s", exc)
        self.finished.emit(run)


class _HashController(QObject):
    """Lives on the UI thread (see extract_dialog._CopyController)."""

    def __init__(self, parent: QWidget, dialog: QProgressDialog, loop: QEventLoop) -> None:
        super().__init__(parent)
        self._dialog = dialog
        self._loop = loop
        self.run: HashRun | None = None

    def on_progress(
        self, files_done: object, files_total: object, bytes_done: object, bytes_total: object,
    ) -> None:
        assert isinstance(files_done, int) and isinstance(files_total, int)
        assert isinstance(bytes_done, int) and isinstance(bytes_total, int)
        if bytes_total:
            self._dialog.setValue(min(_PROGRESS_STEPS, bytes_done * _PROGRESS_STEPS // bytes_total))
        self._dialog.setLabelText(
            translate(
                "HashDialog", "Hashing file {done} of {total}\n{bytes_done} of {bytes_total}"
            ).format(
                done=f"{min(files_done + 1, files_total):,}",
                total=f"{files_total:,}",
                bytes_done=format_size(bytes_done),
                bytes_total=format_size(bytes_total),
            )
        )

    def on_finished(self, run: object) -> None:
        assert isinstance(run, HashRun)
        self.run = run
        self._loop.quit()


def compute_hashes_with_progress(
    parent: QWidget,
    entries: list[tuple[VFSNode, VFS]],
    algorithms: tuple[str, ...],
    store: HashStore,
    window_id: str | None = None,
    source_names: dict[int, str] | None = None,
) -> HashRun:
    """Hash *entries* (folders all the way down) behind a modal progress
    dialog with Cancel; the UI keeps repainting (nested event loop).
    *source_names*: id(vfs) -> what the source was opened from, for the
    Source column (else the source's root name)."""
    cancel = threading.Event()
    dialog = QProgressDialog(
        translate("HashDialog", "Hashing…"),
        translate("HashDialog", "Cancel"),
        0,
        _PROGRESS_STEPS,
        parent,
    )
    dialog.setWindowTitle(translate("HashDialog", "Compute Hash"))
    dialog.setWindowModality(Qt.WindowModality.ApplicationModal)
    dialog.setMinimumDuration(0)
    dialog.setAutoClose(False)
    dialog.setAutoReset(False)
    dialog.setValue(0)
    dialog.canceled.connect(cancel.set)

    loop = QEventLoop(parent)
    thread = QThread(parent)
    worker = _HashWorker(entries, algorithms, store, cancel, window_id, source_names)
    controller = _HashController(parent, dialog, loop)
    worker.moveToThread(thread)
    thread.started.connect(worker.run)
    worker.progress.connect(controller.on_progress)
    worker.finished.connect(controller.on_finished)

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
    assert controller.run is not None
    return controller.run


def content_note() -> str:
    """What a computed hash covers -- the same words in the dialog and the
    Properties panel."""
    return translate(
        "HashDialog",
        "Computed over the entry's content as Crush reads it "
        "(for an archive member: its unpacked content).",
    )


def outcome_text(row: HashRow) -> str:
    if row.outcome == OK:
        if row.differs:
            return translate("HashDialog", "Hashed — differs from a value computed earlier")
        return translate("HashDialog", "Hashed")
    if row.outcome == NOT_READ:
        return translate("HashDialog", "Not hashed: could not be read: {reason}").format(
            reason=row.reason
        )
    if row.outcome == NO_CONTENT:
        return translate("HashDialog", "Not hashed: no content read (see Entry status)")
    return translate("HashDialog", "Folder with an entry status: see Entry status")


def entry_status_text(row: HashRow) -> str:
    return render_value(row.node.status, localized=True) if row.node.status else ""


class HashResultModel(QAbstractTableModel):
    """Rows of a run; hex is formatted when shown (a run may hold millions)."""

    def __init__(self, run: HashRun, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._run = run
        self._headers = [
            translate("HashDialog", "Source"),
            translate("HashDialog", "Path"),
            translate("HashDialog", "Bytes read"),
            *(DISPLAY_NAMES[alg] for alg in run.algorithms),  # i18n: keep -- algorithm names
            translate("HashDialog", "Result"),
            translate("HashDialog", "Entry status"),
        ]

    def rowCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:  # noqa: B008, N802
        return 0 if parent.isValid() else len(self._run.rows)

    def columnCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:  # noqa: B008, N802
        return 0 if parent.isValid() else len(self._headers)

    def headerData(  # noqa: N802
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self._headers[section]
        return None

    def data(
        self, index: QModelIndex | QPersistentModelIndex, role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if not index.isValid() or role not in (
            Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole,
        ):
            return None
        return self.cells(self._run.rows[index.row()])[index.column()]

    def cells(self, row: HashRow) -> list[str]:
        return [
            row.source,
            row.node.path,
            f"{row.bytes_read:,}" if row.bytes_read is not None else "",
            *(row.digests[alg].hex() if alg in row.digests else "" for alg in self._run.algorithms),
            outcome_text(row),
            entry_status_text(row),
        ]

    @property
    def headers(self) -> list[str]:
        return list(self._headers)


def summary_lines(run: HashRun) -> list[str]:
    hashed = sum(1 for r in run.rows if r.outcome == OK)
    not_read = sum(1 for r in run.rows if r.outcome == NOT_READ)
    folders = sum(1 for r in run.rows if r.outcome == FOLDER)
    lines = [
        translate("HashDialog", "{hashed} of {total} files hashed.").format(
            hashed=f"{hashed:,}", total=f"{run.files_total:,}"
        )
    ]
    if not_read:
        lines.append(translate("HashDialog", "{n} could not be read.").format(n=f"{not_read:,}"))
    no_content = sum(1 for r in run.rows if r.outcome == NO_CONTENT)
    if no_content:
        lines.append(translate(
            "HashDialog", "{n} not hashed: no content is read or stored for them (see Entry status)."
        ).format(n=f"{no_content:,}"))
    if folders:
        lines.append(translate(
            "HashDialog",
            "{n} folder(s) with an entry status (for one that couldn't be listed, "
            "its files are missing here).",
        ).format(n=f"{folders:,}"))
    differs = sum(1 for r in run.rows if r.differs)
    if differs:
        lines.append(translate(
            "HashDialog", "{n} differ from a value computed earlier for the same entry."
        ).format(n=f"{differs:,}"))
    if run.cancelled:
        lines.append(translate(
            "HashDialog", "Hashing was cancelled: this list is incomplete."
        ))
    if run.failed:
        lines.append(translate(
            "HashDialog", "Hashing stopped on an error: this list is incomplete. {error}"
        ).format(error=run.failed))
    return lines


def export_text(model: HashResultModel, run: HashRun, fmt: str) -> str:
    """The run as tab-separated text ("txt") or CSV ("csv"); the summary
    first, as # lines, so the file alone says what is missing."""
    out = io.StringIO()
    for line in summary_lines(run):
        out.write(f"# {line}\n")
    out.write(f"# {content_note()}\n")
    if fmt == "csv":
        writer = csv.writer(out, lineterminator="\n")
        writer.writerow(model.headers)
        for row in run.rows:
            writer.writerow(model.cells(row))
    else:
        out.write("\t".join(model.headers) + "\n")
        for row in run.rows:
            out.write("\t".join(model.cells(row)) + "\n")
    return out.getvalue()


class HashResultDialog(QDialog):
    def __init__(self, run: HashRun, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(translate("HashDialog", "Computed Hashes"))
        self.resize(1100, 420)
        self._run = run
        layout = QVBoxLayout(self)

        summary = QLabel("\n".join(summary_lines(run)))
        summary.setTextFormat(Qt.TextFormat.PlainText)
        summary.setWordWrap(True)
        summary.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        incomplete = run.cancelled or bool(run.failed)
        if incomplete or any(r.outcome != OK or r.differs for r in run.rows):
            summary.setStyleSheet("color: #b02a37; font-weight: bold;")
        layout.addWidget(summary)

        note = QLabel(content_note())
        note.setTextFormat(Qt.TextFormat.PlainText)
        note.setWordWrap(True)
        note.setStyleSheet("color: gray; font-size: 10px; font-style: italic;")
        layout.addWidget(note)

        self.model = HashResultModel(run, self)
        self.table = QTableView(self)
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        # Fixed widths, not ResizeToContents: that measures every row.
        metrics = self.table.fontMetrics()
        self.table.setColumnWidth(0, 220)
        self.table.setColumnWidth(1, 380)
        self.table.setColumnWidth(2, metrics.horizontalAdvance("0" * 16))
        for i, alg in enumerate(run.algorithms, start=3):
            hex_chars = 2 * hashlib.new(alg).digest_size
            self.table.setColumnWidth(i, metrics.horizontalAdvance("f" * (hex_chars + 2)))
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._on_context_menu)
        layout.addWidget(self.table)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, self)
        copy_btn = buttons.addButton(
            translate("HashDialog", "Copy All"), QDialogButtonBox.ButtonRole.ActionRole
        )
        save_btn = buttons.addButton(
            translate("HashDialog", "Save As…"), QDialogButtonBox.ButtonRole.ActionRole
        )
        copy_btn.clicked.connect(self.copy_all)
        save_btn.clicked.connect(self.save_as)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _on_context_menu(self, pos: Any) -> None:
        index = self.table.indexAt(pos)
        if not index.isValid():
            return
        menu, actions = self.cell_menu(index)
        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        if chosen in actions:
            actions[chosen]()
        menu.deleteLater()

    def cell_menu(
        self, index: QModelIndex | QPersistentModelIndex,
    ) -> tuple[QMenu, dict[QAction, Any]]:
        """Copy cell / row / selection, as in the table viewers. The cell's
        own text is copied (a full hash, a full path), not what fits the
        column."""
        menu = QMenu(self)
        row = self._run.rows[index.row()]
        actions: dict[QAction, Any] = {
            menu.addAction(translate("HashDialog", "Copy cell")): lambda: self._copy(
                self.model.cells(row)[index.column()]
            ),
            menu.addAction(translate("HashDialog", "Copy row (TSV)")): lambda: self._copy(
                "\t".join(self.model.cells(row))
            ),
            menu.addAction(translate("HashDialog", "Copy selection (TSV)")): self._copy_selection,
        }
        return menu, actions

    def _copy_selection(self) -> None:
        rows = sorted({i.row() for i in self.table.selectionModel().selectedIndexes()})
        if not rows:
            return

        def build() -> str:
            return "\n".join("\t".join(self.model.cells(self._run.rows[r])) for r in rows)

        if len(rows) < 10_000:
            self._copy(build())
            return
        from crush.ui.busy_dialog import busy_call

        self._copy(str(busy_call(self, translate("HashDialog", "Preparing the list…"), build)))

    @staticmethod
    def _copy(text: str) -> None:
        QGuiApplication.clipboard().setText(text)

    def _text(self, fmt: str) -> str:
        if len(self._run.rows) < 10_000:
            return export_text(self.model, self._run, fmt)
        from crush.ui.busy_dialog import busy_call

        return str(busy_call(
            self, translate("HashDialog", "Preparing the list…"),
            lambda: export_text(self.model, self._run, fmt),
        ))

    def copy_all(self) -> None:
        QGuiApplication.clipboard().setText(self._text("txt"))

    def save_as(self) -> None:
        csv_filter = translate("HashDialog", "CSV (*.csv)")
        txt_filter = translate("HashDialog", "Tab-separated text (*.txt)")
        path, chosen = QFileDialog.getSaveFileName(
            self, translate("HashDialog", "Save Hashes"), "crush-hashes.csv",
            f"{csv_filter};;{txt_filter}",
        )
        if not path:
            return
        fmt = "txt" if chosen == txt_filter else "csv"
        try:
            Path(path).write_text(self._text(fmt), encoding="utf-8")
        except OSError as exc:
            QMessageBox.warning(
                self, translate("HashDialog", "Save Hashes"),
                translate("HashDialog", "The list could not be saved:\n{error}").format(error=exc),
            )
            return
        _logger.info("HASH list saved: %s", path)
