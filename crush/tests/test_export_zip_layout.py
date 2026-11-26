# SPDX-License-Identifier: Apache-2.0
"""ZIP export structure: an entry at the top under its own name, or under its
source path; a folder's contents in their structure, or all its files
straight into it with clashing names numbered."""
from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

from PySide6.QtWidgets import QMessageBox

from crush.core.vfs import DirectoryVFS, VFSNode
from crush.core.zip_writer import ZipOptions
from crush.ui.fs_panel import FilesystemPanel
from crush.ui.main_window import MainWindow, ZipSourceItem, _ExportZipWorker
from crush.ui.zip_export_dialog import ZipExportDialog


def _source(tmp_path: Path) -> DirectoryVFS:
    www = tmp_path / "case" / "var" / "www"
    (www / "css").mkdir(parents=True)
    (www / "img" / "old").mkdir(parents=True)
    (www / "empty").mkdir()
    (www / "index.html").write_bytes(b"index")
    (www / "css" / "style.css").write_bytes(b"css")
    (www / "img" / "style.css").write_bytes(b"other css")  # same name, another folder
    (www / "img" / "old" / "style.css").write_bytes(b"oldest css")
    return DirectoryVFS(tmp_path / "case")


def _item(vfs: DirectoryVFS, *names: str) -> ZipSourceItem:
    chain = [vfs.root()]
    for name in names:
        chain.append(next(c for c in chain[-1].children if c.name == name))
    return FilesystemPanel._zip_item_from_chain(chain[-1], vfs, chain)


def _export(tmp_path: Path, items: list[ZipSourceItem], **options: Any) -> dict[str, bytes]:
    out = tmp_path / "out.zip"
    seen: list[Any] = []
    worker = _ExportZipWorker(items, str(out), "new", True, options=ZipOptions(**options))
    worker.finished.connect(lambda *a: seen.append(a))
    worker.failed.connect(lambda *a: seen.append(("failed", *a)))
    worker.run()
    assert seen == [(str(out), 0)]
    with zipfile.ZipFile(out) as zf:
        return {name: zf.read(name) for name in zf.namelist()}


def _content(entries: dict[str, bytes]) -> set[str]:
    assert not any("crush-export-" in name for name in entries)  # lists go beside it
    return set(entries)


def test_a_file_alone(qapp: Any, tmp_path: Path) -> None:
    vfs = _source(tmp_path)
    entries = _export(tmp_path, [_item(vfs, "var", "www", "index.html")])
    assert _content(entries) == {"index.html"}


def test_a_file_with_its_source_path(qapp: Any, tmp_path: Path) -> None:
    vfs = _source(tmp_path)
    entries = _export(tmp_path, [_item(vfs, "var", "www", "index.html")], source_path=True)
    assert _content(entries) == {"var/", "var/www/", "var/www/index.html"}
    assert entries["var/www/index.html"] == b"index"


def test_a_folder_alone_in_its_structure(qapp: Any, tmp_path: Path) -> None:
    vfs = _source(tmp_path)
    entries = _export(tmp_path, [_item(vfs, "var", "www")])
    assert _content(entries) == {
        "www/", "www/index.html", "www/css/", "www/css/style.css",
        "www/img/", "www/img/style.css", "www/img/old/", "www/img/old/style.css", "www/empty/",
    }


def test_a_folder_with_its_source_path(qapp: Any, tmp_path: Path) -> None:
    vfs = _source(tmp_path)
    entries = _export(tmp_path, [_item(vfs, "var", "www")], source_path=True)
    assert "var/www/css/style.css" in entries and "var/" in entries
    assert not any(name.startswith("www/") for name in entries)


def test_a_folder_flattened_numbers_clashing_names_and_lists_them(
    qapp: Any, tmp_path: Path
) -> None:
    vfs = _source(tmp_path)
    entries = _export(tmp_path, [_item(vfs, "var", "www")], flatten=True)
    assert _content(entries) == {
        "www/", "www/index.html", "www/style.css", "www/style (2).css", "www/style (3).css",
    }
    assert sorted(
        entries[n] for n in ("www/style.css", "www/style (2).css", "www/style (3).css")
    ) == [b"css", b"oldest css", b"other css"]
    renames = (tmp_path / "out.zip.crush-export-renames.txt").read_text(encoding="utf-8")
    assert renames.count("->\twww/style (") == 2
    root = str(tmp_path / "case" / "var" / "www")
    assert any(line.startswith(root) for line in renames.splitlines())
    hashes = (tmp_path / "out.zip.crush-export-hashes.txt").read_text(encoding="utf-8")
    assert "www/style (3).css" in hashes


def test_a_folder_flattened_with_its_source_path(qapp: Any, tmp_path: Path) -> None:
    vfs = _source(tmp_path)
    entries = _export(tmp_path, [_item(vfs, "var", "www")], source_path=True, flatten=True)
    assert {"var/www/index.html", "var/www/style (3).css"} <= _content(entries)
    assert "var/www/css/" not in entries


def test_flatten_leaves_files_selected_alone_as_they_are(qapp: Any, tmp_path: Path) -> None:
    vfs = _source(tmp_path)
    entries = _export(
        tmp_path,
        [_item(vfs, "var", "www", "img"), _item(vfs, "var", "www", "index.html")],
        flatten=True,
    )
    assert _content(entries) == {"img/", "img/style.css", "img/style (2).css", "index.html"}


def test_search_result_takes_its_source_path_from_the_sources_nodes(
    qapp: Any, tmp_path: Path
) -> None:
    vfs = _source(tmp_path)
    var = vfs.root().children[0]
    www = var.children[0]
    node = next(c for c in www.children if c.name == "index.html")
    win = MainWindow()
    try:
        item = win._fs_panel._zip_item_from_search(node, vfs)
        assert item == _item(vfs, "var", "www", "index.html")  # the same as from the tree
        assert item[3] == [("var", var.modified), ("www", www.modified)]
        assert var.modified is not None
        stray = VFSNode(name="gone.txt", path="/nowhere/gone.txt", is_dir=False)
        assert win._fs_panel._zip_item_from_search(stray, vfs)[3] == []
    finally:
        win.close()


# -- dialog -----------------------------------------------------------------------------


def test_dialog_structure_choices_and_preview(qapp: Any) -> None:
    dialog = ZipExportDialog(None, "x.zip", example=(["var", "www"], "www", True))
    try:
        assert dialog.preview_path() == "www/subfolder/file"
        assert not dialog.options().source_path and not dialog.options().flatten
        dialog._with_path.setChecked(True)
        dialog._flatten.setChecked(True)
        assert dialog.preview_path() == "var/www/www/file"
        assert "var/www/www/file" in dialog._preview.text()
        options = dialog.options()
        assert options.source_path and options.flatten
        again = ZipExportDialog(None, "x.zip", ZipExportDialog.remembered(options))
        assert again._with_path.isChecked() and again._flatten.isChecked()
        again.deleteLater()
    finally:
        dialog.deleteLater()


def test_dialog_without_folders_offers_no_flatten(qapp: Any) -> None:
    dialog = ZipExportDialog(
        None, "x.zip", ZipOptions(flatten=True),
        example=(["var", "www"], "index.html", False), has_folder=False,
    )
    try:
        assert not dialog._flatten.isEnabled()
        assert not dialog.options().flatten
        assert dialog.preview_path() == "index.html"
    finally:
        dialog.deleteLater()


def test_flow_checks_clashes_where_the_chosen_structure_puts_entries(
    qapp: Any, qtbot: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    vfs = _source(tmp_path)
    out = tmp_path / "out.zip"
    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr("var/www/index.html", b"old")
    monkeypatch.setattr(
        MainWindow, "_zip_export_dialog",
        lambda self, default_name, items: (out, ZipOptions(source_path=True)),
    )
    asked: list[str] = []

    def fake_exec(box: QMessageBox) -> int:
        asked.append(box.text())
        labels = {b.text(): b for b in box.buttons()}
        (labels["Add to Archive"] if len(asked) == 1 else labels["Replace"]).click()
        return 0

    monkeypatch.setattr(QMessageBox, "exec", fake_exec)
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.No)
    win = MainWindow()
    try:
        win._export_selection_zip([_item(vfs, "var", "www", "index.html")])
        assert len(asked) == 2 and "already in the archive" in asked[1]
        qtbot.waitUntil(lambda: not win._thread_is_running(win._export_thread), timeout=10_000)
        qapp.processEvents()
    finally:
        win.close()
    with zipfile.ZipFile(out) as zf:
        assert zf.read("var/www/index.html") == b"index"




def test_integrity_hashes_go_to_the_store_and_empty_content_isnt_hashed(
    qapp: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    from crush.core.hashing import HashStore
    from crush.ui import main_window

    vfs = _source(tmp_path)
    store = HashStore()
    item = _item(vfs, "var", "www", "index.html")
    out = tmp_path / "out.zip"
    _ExportZipWorker([item], str(out), "new", True, hashes=store).run()
    assert store.get(vfs, item[0]).get("sha256")  # recorded for the Properties panel

    monkeypatch.setattr(main_window, "has_no_content", lambda node: True)
    out2 = tmp_path / "out2.zip"
    _ExportZipWorker([item], str(out2), "new", True).run()
    hashes = (tmp_path / "out2.zip.crush-export-hashes.txt").read_text(encoding="utf-8")
    assert "not hashed: no content read" in hashes


# -- entry times -------------------------------------------------------------------------


def _times(tmp_path: Path) -> dict[str, tuple[str, str, str]]:
    """The times list beside out.zip: path in the archive -> (kind, source, stored)."""
    text = (tmp_path / "out.zip.crush-export-times.txt").read_text(encoding="utf-8")
    rows = [line.split("\t") for line in text.splitlines() if not line.startswith("#")]
    return {path: (kind, source, stored) for kind, source, stored, path in rows}


def test_every_entry_says_where_its_time_comes_from(qapp: Any, tmp_path: Path) -> None:
    import os

    vfs = _source(tmp_path)
    www = tmp_path / "case" / "var" / "www"
    os.utime(www / "index.html", (0, 1_700_000_000))
    os.utime(www / "css" / "style.css", (0, 100_000_000))  # 1973: before ZIP's first year
    vfs = DirectoryVFS(tmp_path / "case")

    entries = _export(tmp_path, [_item(vfs, "var", "www")], source_path=True)

    times = _times(tmp_path)
    assert set(times) == set(_content(entries))  # every entry written, folders too
    assert times["var/www/index.html"] == (
        "source", "2023-11-14T22:13:20Z", "2023-11-14 22:13:20"
    )
    assert times["var/www/css/style.css"] == (
        "clamped", "1973-03-03T09:46:40Z", "1980-01-01 00:00:00"
    )
    with zipfile.ZipFile(tmp_path / "out.zip") as zf:
        assert zf.getinfo("var/www/index.html").date_time == (2023, 11, 14, 22, 13, 20)
        assert zf.getinfo("var/www/css/style.css").date_time == (1980, 1, 1, 0, 0, 0)


def test_no_time_gets_the_placeholder_never_the_export_time(qapp: Any, tmp_path: Path) -> None:
    from crush.tests.test_export_zip import _MemoryVFS
    from crush.ui.main_window import _zip_item

    vfs = _MemoryVFS("phone", {"notes.txt": b"n"})  # its nodes carry no time
    entries = _export(tmp_path, [_zip_item(vfs.root(), vfs)])

    assert _times(tmp_path) == {
        "phone/": ("none", "-", "1980-01-01 00:00:00"),
        "phone/notes.txt": ("none", "-", "1980-01-01 00:00:00"),
    }
    with zipfile.ZipFile(tmp_path / "out.zip") as zf:
        for info in zf.infolist():
            assert info.date_time == (1980, 1, 1, 0, 0, 0)
            assert b"UT" not in info.extra  # no extended timestamp to read as real
    assert set(entries) == {"phone/", "phone/notes.txt"}


def test_several_sources_their_folder_has_the_roots_own_time(qapp: Any, tmp_path: Path) -> None:
    import os

    one = _source(tmp_path / "one")
    two_dir = tmp_path / "two" / "phone"
    two_dir.mkdir(parents=True)
    (two_dir / "x.txt").write_bytes(b"x")
    os.utime(tmp_path / "one" / "case", (0, 1_600_000_000))
    os.utime(two_dir, (0, 1_650_000_000))
    one, two = DirectoryVFS(tmp_path / "one" / "case"), DirectoryVFS(two_dir)

    _export(
        tmp_path,
        [_item(one, "var", "www", "index.html"), _item(two, "x.txt")],
        source_path=True,
    )

    times = _times(tmp_path)
    assert times["case/"][:2] == ("source", "2020-09-13T12:26:40Z")
    assert times["phone/"][:2] == ("source", "2022-04-15T05:20:00Z")


# -- several sources of the same name ---------------------------------------------------


def _userdata(tmp_path: Path, where: str, name: str, content: bytes) -> DirectoryVFS:
    root = tmp_path / where / name
    (root / "media").mkdir(parents=True)
    (root / "media" / "x.jpg").write_bytes(content)
    return DirectoryVFS(root)


def test_sources_with_the_same_name_get_their_own_folders(qapp: Any, tmp_path: Path) -> None:
    first = _userdata(tmp_path, "phone-a", "userdata", b"A")
    second = _userdata(tmp_path, "phone-b", "userdata", b"B")
    third = _userdata(tmp_path, "phone-c", "UserData", b"C")  # one folder on Windows too
    out = tmp_path / "out.zip"
    worker = _ExportZipWorker(
        [_item(v, "media", "x.jpg") for v in (first, second, third)], str(out), "new", False,
        options=ZipOptions(source_path=True),
        source_labels={id(first): "/cases/a.zip", id(second): "/cases/b.zip"},
    )
    worker.run()

    with zipfile.ZipFile(out) as zf:
        assert zf.read("userdata/media/x.jpg") == b"A"
        assert zf.read("userdata (2)/media/x.jpg") == b"B"
        assert zf.read("UserData (3)/media/x.jpg") == b"C"
        assert not any("x (2)" in name for name in zf.namelist())  # nothing numbered inside
    sources = (tmp_path / "out.zip.crush-export-sources.txt").read_text(encoding="utf-8")
    assert "userdata/\t/cases/a.zip" in sources
    assert "userdata (2)/\t/cases/b.zip" in sources
    assert "UserData (3)/\tUserData" in sources  # no label known: the root's name
    assert not (tmp_path / "out.zip.crush-export-renames.txt").exists()


def test_one_source_writes_no_source_list(qapp: Any, tmp_path: Path) -> None:
    vfs = _source(tmp_path)
    _export(tmp_path, [_item(vfs, "var", "www", "index.html")], source_path=True)
    assert not (tmp_path / "out.zip.crush-export-sources.txt").exists()


def test_flow_labels_sources_with_what_they_were_opened_from(
    qapp: Any, qtbot: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    first = _userdata(tmp_path, "phone-a", "userdata", b"A")
    second = _userdata(tmp_path, "phone-b", "userdata", b"B")
    out = tmp_path / "out.zip"
    monkeypatch.setattr(
        MainWindow, "_zip_export_dialog",
        lambda self, default_name, items: (out, ZipOptions(source_path=True)),
    )
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.No)
    win = MainWindow()
    try:
        win.session.add_source_vfs(first, tmp_path / "phone-a" / "userdata")
        win.session.add_source_vfs(second, tmp_path / "phone-b" / "userdata")
        win._export_selection_zip([_item(first, "media", "x.jpg"), _item(second, "media", "x.jpg")])
        qtbot.waitUntil(lambda: not win._thread_is_running(win._export_thread), timeout=10_000)
        qapp.processEvents()
    finally:
        win.close()
    sources = (tmp_path / "out.zip.crush-export-sources.txt").read_text(encoding="utf-8")
    assert f"userdata (2)/\t{tmp_path / 'phone-b' / 'userdata'}" in sources
