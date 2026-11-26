# SPDX-License-Identifier: Apache-2.0
"""Export to a ZIP archive (right-click -> Export to ZIP…): into a new
archive, added to one that exists, or replacing it.

The archive is written beside its target and moved into place only when
complete, so a cancel or an error never leaves a half archive under its
name, nor changes an archive being added to.
"""
from __future__ import annotations

import hashlib
import io
import zipfile
from pathlib import Path
from typing import IO, Any

import pytest
from PySide6.QtCore import QItemSelectionModel
from PySide6.QtWidgets import QMessageBox

from crush.core.vfs import VFS, DirectoryVFS, VFSNode
from crush.core.zip_writer import ZipOptions
from crush.ui.fs_panel import _ROLE_NODE, FilesystemPanel
from crush.ui.main_window import (
    MainWindow,
    ZipSourceItem,
    _zip_item,
    _ExportZipWorker,
    _unique_arcname,
    _zip_time,
)


def _source(tmp_path: Path) -> DirectoryVFS:
    src = tmp_path / "case"
    (src / "sub").mkdir(parents=True)
    (src / "empty").mkdir()
    (src / "a.txt").write_bytes(b"alpha")
    (src / "sub" / "b.bin").write_bytes(b"\x00\x01\x02" * 1000)
    return DirectoryVFS(src)


def _run(worker: _ExportZipWorker) -> list[tuple[Any, ...]]:
    seen: list[tuple[Any, ...]] = []
    worker.finished.connect(lambda *a: seen.append(("finished", *a)))
    worker.failed.connect(lambda *a: seen.append(("failed", *a)))
    worker.cancelled.connect(lambda *a: seen.append(("cancelled", *a)))
    worker.run()
    return seen


def _child(node: VFSNode, name: str) -> VFSNode:
    return next(c for c in node.children if c.name == name)


def _choose_in_dialog(
    monkeypatch: Any, path: Path, options: ZipOptions | None = None
) -> None:
    """The ZIP export dialog answered with *path* and *options*."""
    monkeypatch.setattr(
        MainWindow, "_zip_export_dialog",
        lambda self, default_name, items: (path, options or ZipOptions()),
    )


def _no_partials(folder: Path) -> bool:
    return not list(folder.glob("*.crush-partial"))


@pytest.mark.parametrize("integrity", [True, False])
def test_folder_into_a_new_archive(qapp: Any, tmp_path: Path, integrity: bool) -> None:
    vfs = _source(tmp_path)
    out = tmp_path / "out.zip"

    seen = _run(_ExportZipWorker([_zip_item(vfs.root(), vfs)], str(out), "new", integrity))

    assert seen == [("finished", str(out), 0)]
    with zipfile.ZipFile(out) as zf:
        assert zf.testzip() is None
        names = set(zf.namelist())
        assert {"case/", "case/a.txt", "case/sub/", "case/sub/b.bin", "case/empty/"} <= names
        assert zf.read("case/a.txt") == b"alpha"
        assert zf.read("case/sub/b.bin") == b"\x00\x01\x02" * 1000
        assert not any("crush-export-" in name for name in names)  # only the files; lists beside
    beside = tmp_path / "out.zip.crush-export-hashes.txt"
    if integrity:
        hashes = beside.read_text(encoding="utf-8")
        digest = hashlib.sha256(b"alpha").hexdigest()
        assert f"{digest}  5  case/a.txt" in hashes.splitlines()
        archive = hashlib.sha256(out.read_bytes()).hexdigest()
        assert f"# archive sha256={archive}  size={out.stat().st_size}  out.zip" in hashes
    else:
        assert not beside.exists()
    assert _no_partials(tmp_path)


def test_single_file_into_a_new_archive(qapp: Any, tmp_path: Path) -> None:
    vfs = _source(tmp_path)
    out = tmp_path / "one.zip"

    seen = _run(_ExportZipWorker([_zip_item(_child(vfs.root(), "a.txt"), vfs)], str(out), "new", True))

    assert seen == [("finished", str(out), 0)]
    with zipfile.ZipFile(out) as zf:
        assert sorted(zf.namelist()) == ["a.txt"]
        assert zf.read("a.txt") == b"alpha"
    assert (tmp_path / "one.zip.crush-export-hashes.txt").is_file()


def test_add_keeps_existing_entries_and_numbers_a_clash(qapp: Any, tmp_path: Path) -> None:
    vfs = _source(tmp_path)
    out = tmp_path / "out.zip"
    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr("earlier.txt", b"keep me")
        zf.writestr("case/old.txt", b"older export")

    seen = _run(_ExportZipWorker([_zip_item(vfs.root(), vfs)], str(out), "add", False))

    assert seen == [("finished", str(out), 0)]
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
        assert len(names) == len(set(names))  # no duplicate entries
        assert zf.read("earlier.txt") == b"keep me"
        assert zf.read("case/old.txt") == b"older export"
        assert zf.read("case (2)/a.txt") == b"alpha"
        assert not any("crush-export-" in name for name in names)
    renames = (tmp_path / "out.zip.crush-export-renames.txt").read_text(encoding="utf-8")
    assert f"{vfs.root().path}\t->\tcase (2)" in renames
    assert renames.startswith("# Crush ZIP export ")


def test_adding_the_same_file_twice(qapp: Any, tmp_path: Path) -> None:
    vfs = _source(tmp_path)
    a = _child(vfs.root(), "a.txt")
    out = tmp_path / "out.zip"

    assert _run(_ExportZipWorker([_zip_item(a, vfs)], str(out), "new", True))[0][0] == "finished"
    assert _run(_ExportZipWorker([_zip_item(a, vfs)], str(out), "add", True))[0][0] == "finished"

    with zipfile.ZipFile(out) as zf:
        assert set(zf.namelist()) == {"a.txt", "a (2).txt"}
        assert zf.read("a (2).txt") == b"alpha"
    hashes = (tmp_path / "out.zip.crush-export-hashes.txt").read_text(encoding="utf-8")
    first, second = hashes.split("\n\n")  # one section per export, the earlier kept
    assert "written to out.zip" in first and "  a.txt" in first
    assert "added to out.zip" in second and "  a (2).txt" in second
    assert "the one below is of the archive now" in second
    archive = hashlib.sha256(out.read_bytes()).hexdigest()
    assert archive not in first and f"archive sha256={archive}" in second


def test_replace_writes_a_new_archive(qapp: Any, tmp_path: Path) -> None:
    vfs = _source(tmp_path)
    out = tmp_path / "out.zip"
    out.write_bytes(b"not a zip at all")

    seen = _run(_ExportZipWorker([_zip_item(_child(vfs.root(), "a.txt"), vfs)], str(out), "replace", False))

    assert seen == [("finished", str(out), 0)]
    with zipfile.ZipFile(out) as zf:
        assert zf.namelist() == ["a.txt"]


class _FailingRead(io.BytesIO):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self._given = False

    def read(self, size: int | None = -1) -> bytes:
        if self._given:
            raise OSError("only 4 of 9 bytes can be read")
        self._given = True
        return super().read(size)


class _OneUnreadable(DirectoryVFS):
    def open(self, node: VFSNode) -> IO[bytes]:
        if node.name == "bad.bin":
            return _FailingRead(b"part")
        return super().open(node)


def test_an_unreadable_file_is_left_out_and_listed(qapp: Any, tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "bad.bin").write_bytes(b"part-and-rest")
    (src / "good.txt").write_bytes(b"good")
    vfs = _OneUnreadable(src)
    out = tmp_path / "out.zip"

    seen = _run(_ExportZipWorker([_zip_item(vfs.root(), vfs)], str(out), "new", True))

    assert seen == [("finished", str(out), 1)]
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
        assert "src/bad.bin" not in names  # no entry holding part of the file
        assert zf.read("src/good.txt") == b"good"
        assert set(names) == {"src/", "src/good.txt"}
    failed = (tmp_path / "out.zip.crush-export-failed.txt").read_text(encoding="utf-8")
    assert "bad.bin\tonly 4 of 9 bytes can be read" in failed
    hashes = (tmp_path / "out.zip.crush-export-hashes.txt").read_text(encoding="utf-8")
    assert "# not exported: 1 (see out.zip.crush-export-failed.txt)" in hashes


def test_a_single_unreadable_file_fails_and_writes_nothing(qapp: Any, tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "bad.bin").write_bytes(b"part-and-rest")
    vfs = _OneUnreadable(src)
    dest = tmp_path / "dest"
    dest.mkdir()
    out = dest / "out.zip"

    seen = _run(_ExportZipWorker([_zip_item(_child(vfs.root(), "bad.bin"), vfs)], str(out), "new", True))

    assert len(seen) == 1 and seen[0][0] == "failed"
    assert "could not be read and was not exported" in seen[0][1]
    assert list(dest.iterdir()) == []


@pytest.mark.parametrize("mode", ["new", "add", "replace"])
def test_cancel_leaves_the_target_as_it_was(qapp: Any, tmp_path: Path, mode: str) -> None:
    vfs = _source(tmp_path)
    out = tmp_path / "out.zip"
    before = b""
    if mode != "new":
        with zipfile.ZipFile(out, "w") as zf:
            zf.writestr("earlier.txt", b"keep me")
        before = out.read_bytes()
    worker = _ExportZipWorker([_zip_item(vfs.root(), vfs)], str(out), mode, True)  # type: ignore[arg-type]
    worker.cancel()

    seen = _run(worker)

    assert seen == [("cancelled", str(out), mode)]
    if mode == "new":
        assert not out.exists()
    else:
        assert out.read_bytes() == before
    assert _no_partials(tmp_path)


class _MemoryVFS(VFS):
    """A source held in memory, not on the host filesystem: it can hold names
    the host can't, such as "a:b.txt" on Windows (where the colon would name
    an NTFS alternate data stream). Evidence names often aren't valid host
    names either. *files* maps a name to its bytes, all under the root."""

    def __init__(self, root_name: str, files: dict[str, bytes]) -> None:
        self._contents = {f"/{root_name}/{name}": data for name, data in files.items()}
        children = [
            VFSNode(name=name, path=f"/{root_name}/{name}", is_dir=False, size=len(data))
            for name, data in files.items()
        ]
        self._root = VFSNode(name=root_name, path=f"/{root_name}", is_dir=True, children=children)

    def root(self) -> VFSNode:
        return self._root

    def read(self, node: VFSNode) -> bytes:
        return self._contents[node.path]

    def open(self, node: VFSNode) -> IO[bytes]:
        return io.BytesIO(self._contents[node.path])

    def file_count(self, node: VFSNode) -> int:
        return len(node.children) if node.is_dir else 1

    def total_size(self, node: VFSNode) -> int:
        return sum(c.size for c in node.children) if node.is_dir else node.size


def test_windows_unsafe_names_are_sanitized_and_recorded(qapp: Any, tmp_path: Path) -> None:
    vfs = _MemoryVFS("src", {"a:b.txt": b"x"})
    out = tmp_path / "out.zip"

    _run(_ExportZipWorker([_zip_item(vfs.root(), vfs)], str(out), "new", False))

    with zipfile.ZipFile(out) as zf:
        assert zf.read("src/a_b.txt") == b"x"
    renames = (tmp_path / "out.zip.crush-export-renames.txt").read_text(encoding="utf-8")
    assert "/src/a:b.txt\t->\tsrc/a_b.txt" in renames


def test_unique_arcname() -> None:
    taken = {"a.txt", "dir/", "dir/x", "nested.d/f.txt"}
    assert _unique_arcname("b.txt", taken, False) == "b.txt"
    assert _unique_arcname("a.txt", taken, False) == "a (2).txt"
    assert _unique_arcname("dir", taken, True) == "dir (2)"
    assert _unique_arcname("nested.d/f.txt", taken, False) == "nested.d/f (2).txt"
    assert _unique_arcname("a.txt", taken | {"a (2).txt"}, False) == "a (3).txt"


def test_zip_time_says_where_it_comes_from() -> None:
    own = _zip_time(1_700_000_001.5)
    assert own.kind == "source"
    assert own.date_time == (2023, 11, 14, 22, 13, 20)  # 2-second steps: 21 -> 20
    assert own.source == "2023-11-14T22:13:21.5Z"
    assert own.extra[:4] == b"\x55\x54\x05\x00"

    early = _zip_time(-1.5)  # 1969-12-31T23:59:58.5Z: before 1980, pre-1970 too
    assert early.kind == "clamped" and early.date_time == (1980, 1, 1, 0, 0, 0)
    assert early.source == "1969-12-31T23:59:58.5Z"
    assert int.from_bytes(early.extra[5:], "little", signed=True) == -2  # exact second
    late = _zip_time(2**31 + 10.0)  # 2038, beyond the extended timestamp
    assert late.kind == "source" and late.extra == b""
    beyond = _zip_time(5_000_000_000.0)  # 2128
    assert beyond.kind == "clamped" and beyond.date_time == (2107, 12, 31, 23, 59, 58)

    for missing, source in ((None, "-"), (float("nan"), "not convertible: nan"),
                            (1e300, "not convertible: 1e+300")):
        none = _zip_time(missing)
        assert none.kind == "none" and none.source == source
        assert none.date_time == (1980, 1, 1, 0, 0, 0) and none.extra == b""


def test_menu_flow_asks_before_adding_to_an_existing_archive(
    qapp: Any, qtbot: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    vfs = _source(tmp_path)
    out = tmp_path / "out.zip"
    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr("earlier.txt", b"keep me")
    _choose_in_dialog(monkeypatch, out)
    asked: list[str] = []

    def fake_exec(box: QMessageBox) -> int:
        asked.append(box.text())
        add = next(b for b in box.buttons() if box.buttonRole(b) == QMessageBox.ButtonRole.AcceptRole)
        add.click()
        return 0

    monkeypatch.setattr(QMessageBox, "exec", fake_exec)
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.No)

    win = MainWindow()
    try:
        win._export_node_zip(vfs.root(), vfs)
        assert len(asked) == 1 and str(out) in asked[0]
        qtbot.waitUntil(lambda: not win._thread_is_running(win._export_thread), timeout=10_000)
        qapp.processEvents()
    finally:
        win.close()
    with zipfile.ZipFile(out) as zf:
        assert zf.read("earlier.txt") == b"keep me"
        assert zf.read("case/a.txt") == b"alpha"


def test_menu_flow_adds_the_zip_suffix(
    qapp: Any, qtbot: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    vfs = _source(tmp_path)
    from crush.ui.zip_export_dialog import with_zip_suffix

    _choose_in_dialog(monkeypatch, with_zip_suffix(str(tmp_path / "evidence")))
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.No)

    win = MainWindow()
    try:
        win._export_node_zip(vfs.root(), vfs)
        qtbot.waitUntil(lambda: not win._thread_is_running(win._export_thread), timeout=10_000)
        qapp.processEvents()
    finally:
        win.close()
    assert zipfile.is_zipfile(tmp_path / "evidence.zip")


# -- Several selected entries (tree multi-selection) ----------------------------------


def _deep_source(tmp_path: Path) -> DirectoryVFS:
    src = tmp_path / "case"
    (src / "private" / "var" / "mobile").mkdir(parents=True)
    (src / "private" / "var" / "logs").mkdir(parents=True)
    (src / "private" / "var" / "mobile" / "a.db").write_bytes(b"db")
    (src / "private" / "var" / "logs" / "x.log").write_bytes(b"log")
    (src / "top.txt").write_bytes(b"top")
    return DirectoryVFS(src)


def _chain(vfs: DirectoryVFS, *names: str) -> ZipSourceItem:
    """The entry at *names* below the source's root, with its source path."""
    chain = [vfs.root()]
    for name in names:
        chain.append(_child(chain[-1], name))
    return FilesystemPanel._zip_item_from_chain(chain[-1], vfs, chain)


_WITH_PATH = ZipOptions(source_path=True)


def test_selection_keeps_each_path_from_the_source_root(qapp: Any, tmp_path: Path) -> None:
    vfs = _deep_source(tmp_path)
    items = [
        _chain(vfs, "private", "var", "mobile", "a.db"),  # a file, deep down
        _chain(vfs, "private", "var", "logs"),  # a folder, a level higher
        _chain(vfs, "top.txt"),  # a file at the top
    ]
    out = tmp_path / "sel.zip"

    seen = _run(_ExportZipWorker(items, str(out), "new", True, options=_WITH_PATH))

    assert seen == [("finished", str(out), 0)]
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
        assert len(names) == len(set(names))
        assert set(names) == {
            "private/", "private/var/", "private/var/mobile/",
            "private/var/mobile/a.db",
            "private/var/logs/", "private/var/logs/x.log",
            "top.txt",
        }
        assert zf.read("private/var/mobile/a.db") == b"db"
    hashes = (tmp_path / "sel.zip.crush-export-hashes.txt").read_text(encoding="utf-8")
    assert "private/var/logs/x.log" in hashes and "  top.txt" in hashes


def test_selection_added_twice_shares_folders_and_numbers_only_the_entries(
    qapp: Any, tmp_path: Path
) -> None:
    vfs = _deep_source(tmp_path)
    items = [_chain(vfs, "private", "var", "mobile", "a.db"), _chain(vfs, "top.txt")]
    out = tmp_path / "sel.zip"

    _run(_ExportZipWorker(items, str(out), "new", True, options=_WITH_PATH))
    seen = _run(_ExportZipWorker(items, str(out), "add", True, options=_WITH_PATH))

    assert seen == [("finished", str(out), 0)]
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
        assert len(names) == len(set(names))
        assert names.count("private/var/mobile/") == 1  # the folders are shared
        assert zf.read("private/var/mobile/a (2).db") == b"db"
        assert zf.read("top (2).txt") == b"top"


def test_selection_lists_an_unreadable_file_without_failing(qapp: Any, tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "bad.bin").write_bytes(b"part-and-rest")
    (src / "good.txt").write_bytes(b"good")
    vfs = _OneUnreadable(src)
    items = [_zip_item(c, vfs) for c in vfs.root().children]
    out = tmp_path / "sel.zip"

    seen = _run(_ExportZipWorker(items, str(out), "new", False, options=_WITH_PATH))

    assert seen == [("finished", str(out), 1)]
    with zipfile.ZipFile(out) as zf:
        assert "bad.bin" not in zf.namelist()
        assert zf.read("good.txt") == b"good"
    failed = (tmp_path / "sel.zip.crush-export-failed.txt").read_text(encoding="utf-8")
    assert "bad.bin\tonly 4 of 9" in failed


def test_tree_selection_collects_chains_and_drops_what_a_folder_brings(
    qapp: Any, qtbot: Any, tmp_path: Path
) -> None:
    vfs = _deep_source(tmp_path)
    win = MainWindow()
    panel = win._fs_panel
    try:
        panel.load_vfs(vfs)

        def child_item(parent: Any, name: str) -> Any:
            panel._ensure_children_loaded(parent, parent.data(_ROLE_NODE), vfs)

            def find() -> Any:
                for r in range(parent.rowCount()):
                    child = parent.child(r, 0)
                    if child is not None and child.text() == name:
                        return child
                return None

            qtbot.waitUntil(lambda: find() is not None, timeout=5_000)
            return find()

        def select(*names: str) -> None:
            item = panel._model.item(0, 0)
            for name in names:
                item = child_item(item, name)
            panel._tree.selectionModel().select(
                panel._proxy.mapFromSource(item.index()),
                QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows,
            )

        select("private", "var", "logs")
        select("private", "var", "logs", "x.log")  # inside a selected folder
        select("private", "var", "mobile", "a.db")

        items = panel._collect_tree_selected_items()
    finally:
        win.close()
        qapp.processEvents()

    paths = sorted(
        "/".join([source, *(name for name, _m in folders), node.name])
        for node, _v, source, folders in items
    )
    assert paths == ["case/private/var/logs", "case/private/var/mobile/a.db"]


def test_selection_from_several_sources_keeps_each_source_name(
    qapp: Any, tmp_path: Path
) -> None:
    one = _deep_source(tmp_path / "one")
    two_dir = tmp_path / "two" / "phone"
    two_dir.mkdir(parents=True)
    (two_dir / "top.txt").write_bytes(b"other")
    two = DirectoryVFS(two_dir)
    items = [_chain(one, "top.txt"), _chain(two, "top.txt")]
    out = tmp_path / "sel.zip"

    _run(_ExportZipWorker(items, str(out), "new", False, options=_WITH_PATH))

    with zipfile.ZipFile(out) as zf:
        assert zf.read("case/top.txt") == b"top"  # several sources: their names first
        assert zf.read("phone/top.txt") == b"other"


def test_selection_replace_swaps_the_entries_and_keeps_the_rest(
    qapp: Any, tmp_path: Path
) -> None:
    vfs = _deep_source(tmp_path)
    out = tmp_path / "sel.zip"
    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr("earlier.txt", b"keep me")
        zf.writestr("top.txt", b"old top")
        zf.writestr("private/var/logs/stale.log", b"gone with the folder")
        zf.writestr("private/var/other.txt", b"beside, kept")
    items = [_chain(vfs, "top.txt"), _chain(vfs, "private", "var", "logs")]

    seen = _run(_ExportZipWorker(
        items, str(out), "add", False, on_clash="replace", options=_WITH_PATH
    ))

    assert seen == [("finished", str(out), 0)]
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
        assert len(names) == len(set(names))
        assert zf.read("earlier.txt") == b"keep me"
        assert zf.read("private/var/other.txt") == b"beside, kept"
        assert zf.read("top.txt") == b"top"
        assert zf.read("private/var/logs/x.log") == b"log"
        assert "private/var/logs/stale.log" not in names
        assert not any("(2)" in name for name in names)


def test_single_replace_swaps_the_file_and_appends_to_the_list(
    qapp: Any, tmp_path: Path
) -> None:
    vfs = _source(tmp_path)
    a = _child(vfs.root(), "a.txt")
    out = tmp_path / "out.zip"
    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr("a.txt", b"old")
        zf.writestr("b.txt", b"keep")
    beside = tmp_path / "out.zip.crush-export-hashes.txt"
    beside.write_text("# earlier list\n", encoding="utf-8")

    _run(_ExportZipWorker([_zip_item(a, vfs)], str(out), "add", True, on_clash="replace"))

    with zipfile.ZipFile(out) as zf:
        assert sorted(zf.namelist()) == ["a.txt", "b.txt"]
        assert zf.read("a.txt") == b"alpha"
    hashes = beside.read_text(encoding="utf-8")
    assert hashes.startswith("# earlier list\n")
    assert "# replaced in the archive: a.txt" in hashes
    assert hashlib.sha256(b"alpha").hexdigest() in hashes


def test_without_integrity_a_list_beside_is_kept_honest(qapp: Any, tmp_path: Path) -> None:
    vfs = _source(tmp_path)
    a = _child(vfs.root(), "a.txt")
    out = tmp_path / "out.zip"
    beside = tmp_path / "out.zip.crush-export-hashes.txt"
    _run(_ExportZipWorker([_zip_item(a, vfs)], str(out), "new", True))
    assert beside.is_file()

    _run(_ExportZipWorker([_zip_item(a, vfs)], str(out), "add", False))
    assert "without integrity mode: not hashed" in beside.read_text(encoding="utf-8")

    _run(_ExportZipWorker([_zip_item(a, vfs)], str(out), "replace", False))
    assert not beside.exists()  # it described the archive replaced


def test_cancelled_replace_leaves_the_archive_unchanged(qapp: Any, tmp_path: Path) -> None:
    vfs = _source(tmp_path)
    out = tmp_path / "out.zip"
    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr("case/a.txt", b"old")
    before = out.read_bytes()
    worker = _ExportZipWorker([_zip_item(vfs.root(), vfs)], str(out), "add", False, on_clash="replace")
    worker.cancel()

    assert _run(worker) == [("cancelled", str(out), "add")]
    assert out.read_bytes() == before
    assert _no_partials(tmp_path)


@pytest.mark.parametrize("answer, expected", [("Replace", "alpha"), ("Add Beside", "old")])
def test_menu_flow_asks_replace_or_beside_when_an_entry_is_there(
    qapp: Any, qtbot: Any, tmp_path: Path, monkeypatch: Any, answer: str, expected: str
) -> None:
    vfs = _source(tmp_path)
    out = tmp_path / "out.zip"
    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr("case/a.txt", b"old")
    _choose_in_dialog(monkeypatch, out)
    asked: list[str] = []

    def fake_exec(box: QMessageBox) -> int:
        asked.append(box.text())
        labels = {b.text(): b for b in box.buttons()}
        (labels["Add to Archive"] if len(asked) == 1 else labels[answer]).click()
        return 0

    monkeypatch.setattr(QMessageBox, "exec", fake_exec)
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.No)

    win = MainWindow()
    try:
        win._export_node_zip(vfs.root(), vfs)
        assert len(asked) == 2 and "already in the archive" in asked[1]
        qtbot.waitUntil(lambda: not win._thread_is_running(win._export_thread), timeout=10_000)
        qapp.processEvents()
    finally:
        win.close()
    with zipfile.ZipFile(out) as zf:
        assert zf.read("case/a.txt") == (b"alpha" if answer == "Replace" else b"old")
        if answer == "Add Beside":
            assert zf.read("case (2)/a.txt") == b"alpha"


def test_lists_beside_are_appended_when_adding_and_replaced_with_the_archive(
    qapp: Any, tmp_path: Path
) -> None:
    vfs = _MemoryVFS("src", {"a:b.txt": b"x", "plain.txt": b"y"})
    odd = _child(vfs.root(), "a:b.txt")
    plain = _child(vfs.root(), "plain.txt")
    out = tmp_path / "out.zip"
    renames = tmp_path / "out.zip.crush-export-renames.txt"

    _run(_ExportZipWorker([_zip_item(odd, vfs)], str(out), "new", False))
    _run(_ExportZipWorker([_zip_item(odd, vfs)], str(out), "add", False))
    text = renames.read_text(encoding="utf-8")
    assert text.count("# Crush ZIP export ") == 2  # one section per export
    assert "->\ta_b.txt" in text and "->\ta_b (2).txt" in text

    _run(_ExportZipWorker([_zip_item(plain, vfs)], str(out), "add", False))
    assert renames.read_text(encoding="utf-8") == text  # nothing renamed: left as it was

    _run(_ExportZipWorker([_zip_item(plain, vfs)], str(out), "replace", False))
    assert not renames.exists()  # it listed the archive replaced
