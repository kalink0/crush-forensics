# SPDX-License-Identifier: Apache-2.0
"""ZIP export structure: an entry at the top under its own name, or under its
source path; a folder's contents in their structure, or all its files
straight into it with clashing names numbered."""
from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

from PySide6.QtWidgets import QMessageBox

from crush.core.vfs import DirectoryVFS
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
    return {name for name in entries if not name.startswith("crush-export-")}


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
    renames = entries["crush-export-renames.txt"].decode()
    assert renames.count("->\twww/style (") == 2
    root = str(tmp_path / "case" / "var" / "www")
    assert any(line.startswith(root) for line in renames.splitlines())
    hashes = entries["crush-export-hashes.txt"].decode()
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


def test_search_result_takes_its_source_path_from_the_result_path(tmp_path: Path) -> None:
    vfs = _source(tmp_path)
    node = next(c for c in vfs.root().children[0].children[0].children if c.name == "index.html")
    item = FilesystemPanel._zip_item_from_virtual_path(node, vfs, "/var/www/index.html")
    assert item[2] == "case"
    assert item[3] == [("var", None), ("www", None)]


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
    with zipfile.ZipFile(out2) as zf:
        assert "not hashed: no content read" in zf.read("crush-export-hashes.txt").decode()
