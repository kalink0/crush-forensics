# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Compute Hash: hashing, the per-window store, the result rows and the
Properties panel's computed-hash rows."""
from __future__ import annotations

import hashlib
import threading
from pathlib import Path
from typing import IO

import pytest

from crush.core.hashing import (
    ALGORITHMS,
    HashCancelled,
    HashReadError,
    HashStore,
    hash_node,
    iter_files,
)
from crush.core.issues import ParseIssue
from crush.core.session import Session
from crush.core.vfs import DirectoryVFS, VFSNode


def _child(vfs: DirectoryVFS, name: str) -> VFSNode:
    return next(n for n in vfs.root().children if n.name == name)


class _FailingVFS(DirectoryVFS):
    """Reading *fail_name* breaks off, as a damaged member would."""

    fail_name = "bad.bin"

    def open(self, node: VFSNode) -> IO[bytes]:
        if node.name == self.fail_name:
            raise OSError("simulated read error")
        return super().open(node)


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    (tmp_path / "a.txt").write_bytes(b"alpha")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.txt").write_bytes(b"beta" * 1000)
    return tmp_path


# --- hashing ---------------------------------------------------------------

def test_hash_node_matches_hashlib_for_every_algorithm(tree: Path) -> None:
    vfs = DirectoryVFS(tree)
    digests, read = hash_node(vfs, _child(vfs, "a.txt"), ALGORITHMS)
    assert read == 5
    for alg in ALGORITHMS:
        assert digests[alg] == hashlib.new(alg, b"alpha").digest()


def test_hash_node_only_the_chosen_algorithm(tree: Path) -> None:
    vfs = DirectoryVFS(tree)
    digests, _ = hash_node(vfs, _child(vfs, "a.txt"), ("sha1",))
    assert set(digests) == {"sha1"}


def test_read_error_gives_no_digest(tree: Path) -> None:
    (tree / "bad.bin").write_bytes(b"x")
    vfs = _FailingVFS(tree)
    with pytest.raises(HashReadError, match="simulated"):
        hash_node(vfs, _child(vfs, "bad.bin"), ALGORITHMS)


def test_cancel_stops_hashing(tree: Path) -> None:
    vfs = DirectoryVFS(tree)
    with pytest.raises(HashCancelled):
        hash_node(vfs, _child(vfs, "a.txt"), ALGORITHMS, cancelled=lambda: True)


def test_iter_files_walks_down_and_keeps_folders_with_a_status() -> None:
    f1 = VFSNode("f1", "/d/f1", False)
    f2 = VFSNode("f2", "/d/e/f2", False)
    unlisted = VFSNode("u", "/d/u", True, status=ParseIssue("entry.folder_unlisted", detail="x"))
    inner = VFSNode("e", "/d/e", True, children=[f2])
    top = VFSNode("d", "/d", True, children=[f1, inner, unlisted])
    assert [n.name for n in iter_files(top)] == ["f1", "f2", "u"]
    assert [n.name for n in iter_files(f1)] == ["f1"]


# --- store -----------------------------------------------------------------

def test_store_keeps_values_per_entry_not_per_path(tree: Path) -> None:
    vfs = DirectoryVFS(tree)
    first = VFSNode("x", "/same", False)
    second = VFSNode("x", "/same", False)  # a second entry stored under the same path
    store = HashStore()
    store.record(vfs, first, {"md5": b"\x01" * 16})
    assert store.get(vfs, first) == {"md5": [b"\x01" * 16]}
    assert store.get(vfs, second) == {}


def test_store_adds_algorithms_and_keeps_a_differing_value(tree: Path) -> None:
    vfs = DirectoryVFS(tree)
    node = _child(vfs, "a.txt")
    store = HashStore()
    store.record(vfs, node, {"sha256": b"\x02" * 32})
    store.record(vfs, node, {"md5": b"\x03" * 16})
    store.record(vfs, node, {"sha256": b"\x02" * 32})  # same value again: no second entry
    assert store.get(vfs, node) == {"md5": [b"\x03" * 16], "sha256": [b"\x02" * 32]}
    store.record(vfs, node, {"sha256": b"\x04" * 32})
    assert store.get(vfs, node)["sha256"] == [b"\x02" * 32, b"\x04" * 32]


def test_store_is_thread_safe(tree: Path) -> None:
    vfs = DirectoryVFS(tree)
    nodes = [VFSNode(f"n{i}", f"/n{i}", False) for i in range(2000)]
    store = HashStore()

    def work(part: list[VFSNode]) -> None:
        for n in part:
            store.record(vfs, n, {"sha1": hashlib.sha1(n.path.encode()).digest()})

    threads = [threading.Thread(target=work, args=(nodes[i::4],)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(
        store.get(vfs, n) == {"sha1": [hashlib.sha1(n.path.encode()).digest()]} for n in nodes
    )


def test_session_forgets_a_sources_hashes_when_closed_or_replaced(tree: Path) -> None:
    session = Session()
    vfs = session.add_source(tree)
    node = _child(vfs, "a.txt")
    session.hashes.record(vfs, node, {"md5": b"\x00" * 16})
    new = session.add_source(tree)
    new_node = _child(new, "a.txt")
    session.hashes.record(new, new_node, {"md5": b"\x00" * 16})

    session.replace_source(vfs, DirectoryVFS(tree))
    assert session.hashes.get(vfs, node) == {}
    assert session.hashes.get(new, new_node) != {}

    session.remove_source(new)
    assert session.hashes.get(new, new_node) == {}
    session.close()


def test_session_detach_drops_the_hashes(tree: Path) -> None:
    session = Session()
    vfs = session.add_source(tree)
    node = _child(vfs, "a.txt")
    session.hashes.record(vfs, node, {"md5": b"\x00" * 16})
    session.detach_source(vfs)
    assert session.hashes.get(vfs, node) == {}
    session.close()


# --- a run: rows and their outcome --------------------------------------------

def _run(entries: list, algorithms: tuple[str, ...], store: HashStore, cancel: bool = False):  # noqa: ANN202
    from crush.ui.hash_dialog import _HashWorker

    event = threading.Event()
    if cancel:
        event.set()
    worker = _HashWorker(entries, algorithms, store, event, None)
    got: list = []
    worker.finished.connect(got.append)
    worker._run()
    worker.deleteLater()
    return got[0]


def test_run_hashes_a_folder_down_and_records_every_file(qapp, tree: Path) -> None:
    from crush.ui.hash_dialog import OK

    vfs = DirectoryVFS(tree)
    store = HashStore()
    run = _run([(vfs.root(), vfs)], ("md5",), store)
    assert run.files_total == 2
    assert not run.cancelled
    paths = {Path(r.node.path).name: r for r in run.rows}
    assert set(paths) == {"a.txt", "b.txt"}
    assert all(r.outcome == OK for r in run.rows)
    b = paths["b.txt"]
    assert b.digests["md5"] == hashlib.md5(b"beta" * 1000).digest()
    assert b.bytes_read == 4000
    assert store.get(vfs, b.node) == {"md5": [b.digests["md5"]]}


def test_run_lists_an_unreadable_file_with_its_reason(qapp, tree: Path) -> None:
    from crush.ui.hash_dialog import NOT_READ, outcome_text

    (tree / "bad.bin").write_bytes(b"x")
    vfs = _FailingVFS(tree)
    store = HashStore()
    run = _run([(vfs.root(), vfs)], ALGORITHMS, store)
    bad = next(r for r in run.rows if r.node.name == "bad.bin")
    assert bad.outcome == NOT_READ
    assert bad.digests == {}
    assert "simulated read error" in outcome_text(bad)
    assert store.get(vfs, bad.node) == {}


def test_run_hashes_a_file_selected_with_its_folder_once(qapp, tree: Path) -> None:
    vfs = DirectoryVFS(tree)
    sub = _child(vfs, "sub")
    run = _run([(sub, vfs), (sub.children[0], vfs)], ("sha1",), HashStore())
    assert run.files_total == 1
    assert len(run.rows) == 1


def test_run_marks_a_value_that_differs_from_an_earlier_one(qapp, tree: Path) -> None:
    from crush.ui.hash_dialog import outcome_text, summary_lines

    vfs = DirectoryVFS(tree)
    node = _child(vfs, "a.txt")
    store = HashStore()
    store.record(vfs, node, {"sha256": b"\xff" * 32})  # e.g. the file changed on disk since
    run = _run([(node, vfs)], ("sha256",), store)
    assert run.rows[0].differs
    assert "differs" in outcome_text(run.rows[0])
    assert any("differ" in line for line in summary_lines(run))
    assert len(store.get(vfs, node)["sha256"]) == 2


def test_cancelled_run_says_it_is_incomplete_in_the_saved_list(qapp, tree: Path) -> None:
    from crush.ui.hash_dialog import HashResultModel, export_text

    vfs = DirectoryVFS(tree)
    run = _run([(vfs.root(), vfs)], ALGORITHMS, HashStore(), cancel=True)
    assert run.cancelled
    assert run.rows == []
    for fmt in ("csv", "txt"):
        text = export_text(HashResultModel(run), run, fmt)
        assert "0 of 2 files hashed" in text
        assert "incomplete" in text


def test_saved_list_has_one_column_per_chosen_algorithm(qapp, tree: Path) -> None:
    from crush.ui.hash_dialog import HashResultModel, export_text

    vfs = DirectoryVFS(tree)
    run = _run([(_child(vfs, "a.txt"), vfs)], ("md5", "sha256"), HashStore())
    lines = [ln for ln in export_text(HashResultModel(run), run, "txt").splitlines()
             if not ln.startswith("#")]
    header, row = lines[0].split("\t"), lines[1].split("\t")
    assert header[2:4] == ["MD5", "SHA-256"]
    assert row[2] == hashlib.md5(b"alpha").hexdigest()
    assert row[3] == hashlib.sha256(b"alpha").hexdigest()


def test_progress_path_runs_on_a_worker_thread_and_returns(qapp, widgets, tree: Path) -> None:
    from PySide6.QtWidgets import QWidget

    from crush.ui.hash_dialog import HashResultDialog, compute_hashes_with_progress

    vfs = DirectoryVFS(tree)
    store = HashStore()
    parent = widgets(QWidget())
    run = compute_hashes_with_progress(parent, [(vfs.root(), vfs)], ("sha256",), store)
    assert run.files_total == 2 and len(run.rows) == 2
    dialog = widgets(HashResultDialog(run, parent))
    assert dialog.model.rowCount() == 2


# --- menus and the Properties panel ------------------------------------------------

def test_hash_menu_offers_each_algorithm_and_all(qapp, widgets) -> None:
    from PySide6.QtWidgets import QMenu

    from crush.ui.hash_dialog import add_hash_menu

    menu = widgets(QMenu())
    actions = add_hash_menu(menu)
    assert [(a.text(), algs) for a, algs in actions.items()] == [
        ("MD5", ("md5",)), ("SHA-1", ("sha1",)), ("SHA-256", ("sha256",)), ("All", ALGORITHMS),
    ]


def _labels(panel) -> list[str]:  # noqa: ANN001
    from PySide6.QtWidgets import QFormLayout, QLabel

    out = []
    for row in range(panel._layout.rowCount()):
        for role in (
            QFormLayout.ItemRole.LabelRole, QFormLayout.ItemRole.FieldRole,
            QFormLayout.ItemRole.SpanningRole,
        ):
            item = panel._layout.itemAt(row, role)
            if item is not None and isinstance(item.widget(), QLabel):
                out.append(item.widget().text())
    return out


def test_panel_shows_computed_hashes_and_the_button_without_a_format(
    qapp, widgets, tree: Path,
) -> None:
    from PySide6.QtWidgets import QPushButton

    from crush.ui.props_panel import PropertiesPanel

    vfs = DirectoryVFS(tree)
    node = _child(vfs, "a.txt")
    store = HashStore()
    panel = widgets(PropertiesPanel())
    panel.set_hash_lookup(store.get)
    panel.update_properties(node, {"Type": "File"}, vfs)
    buttons = [b.text() for b in panel.findChildren(QPushButton)]
    assert "Compute Hash…" in buttons
    assert "Open Format Info…" not in buttons
    assert not any("(computed)" in t for t in _labels(panel))

    store.record(vfs, node, {"md5": hashlib.md5(b"alpha").digest()})
    panel.refresh_hashes()
    labels = _labels(panel)
    assert "MD5 (computed):" in labels
    assert hashlib.md5(b"alpha").hexdigest() in labels
    assert not any("SHA-256" in t for t in labels)


def test_panel_shows_both_values_when_they_differ(qapp, widgets, tree: Path) -> None:
    from crush.ui.props_panel import PropertiesPanel

    vfs = DirectoryVFS(tree)
    node = _child(vfs, "a.txt")
    store = HashStore()
    store.record(vfs, node, {"sha256": b"\x01" * 32})
    store.record(vfs, node, {"sha256": b"\x02" * 32})
    panel = widgets(PropertiesPanel())
    panel.set_hash_lookup(store.get)
    panel.update_properties(node, {}, vfs)
    labels = _labels(panel)
    assert f"{'01' * 32}\n{'02' * 32}" in labels
    assert any("Different values were computed" in t for t in labels)


def test_panel_hash_button_requests_the_chosen_algorithm(qapp, widgets, tree: Path) -> None:
    from PySide6.QtWidgets import QPushButton

    from crush.ui.props_panel import PropertiesPanel

    vfs = DirectoryVFS(tree)
    node = _child(vfs, "a.txt")
    panel = widgets(PropertiesPanel())
    got: list = []
    panel.hash_requested.connect(lambda n, v, algs: got.append((n, v, algs)))
    panel.update_properties(node, {}, vfs)
    button = next(b for b in panel.findChildren(QPushButton) if b.text() == "Compute Hash…")
    sha1 = next(a for a in button.menu().actions() if a.text() == "SHA-1")
    sha1.trigger()
    assert got == [(node, vfs, ("sha1",))]


# --- integrity hashes go to the store ----------------------------------------------

def test_export_with_integrity_keeps_the_sha256(qapp, tree: Path, tmp_path_factory) -> None:
    from crush.ui.main_window import _ExportWorker

    vfs = DirectoryVFS(tree)
    node = _child(vfs, "a.txt")
    store = HashStore()
    dest = tmp_path_factory.mktemp("out")
    worker = _ExportWorker(vfs, node, str(dest), True, hashes=store)
    worker._run()
    worker.deleteLater()
    assert store.get(vfs, node) == {"sha256": [hashlib.sha256(b"alpha").digest()]}
