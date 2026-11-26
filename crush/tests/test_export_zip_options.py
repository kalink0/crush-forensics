# SPDX-License-Identifier: Apache-2.0
"""ZIP export options: compression method and level, an AES-256 password,
splitting into parts (`.zip.001` ...), and copying an archive's entries over
unchanged when entries are replaced -- crush.core.zip_writer, the export
worker that uses it, and the dialog that asks for them."""
from __future__ import annotations

import io
import os
import zipfile
from pathlib import Path
from typing import Any

import pyzipper
import pytest
from PySide6.QtWidgets import QMessageBox

from crush.core import zip_writer
from crush.core.vfs import DirectoryVFS
from crush.core.zip_writer import SplitWriter, ZipOptions, existing_parts, part_path
from crush.ui.main_window import MainWindow, _ExportZipWorker, _zip_item
from crush.ui.zip_export_dialog import ZipExportDialog, with_zip_suffix


def _source(tmp_path: Path) -> DirectoryVFS:
    src = tmp_path / "case"
    (src / "sub").mkdir(parents=True, exist_ok=True)
    (src / "a.txt").write_bytes(b"alpha " * 5000)
    (src / "sub" / "r.bin").write_bytes(os.urandom(250_000))
    return DirectoryVFS(src)


def _run(worker: _ExportZipWorker) -> list[tuple[Any, ...]]:
    seen: list[tuple[Any, ...]] = []
    worker.finished.connect(lambda *a: seen.append(("finished", *a)))
    worker.failed.connect(lambda *a: seen.append(("failed", *a)))
    worker.cancelled.connect(lambda *a: seen.append(("cancelled", *a)))
    worker.run()
    return seen


def _export(tmp_path: Path, out: Path, mode: str = "new", **options: Any) -> list[tuple[Any, ...]]:
    vfs = _source(tmp_path)
    on_clash = options.pop("on_clash", "number")
    return _run(_ExportZipWorker(
        [_zip_item(vfs.root(), vfs)], str(out), mode, True,  # type: ignore[arg-type]
        on_clash=on_clash, options=ZipOptions(**options),
    ))


# -- options ---------------------------------------------------------------------------


def test_options_validate_and_never_show_the_password() -> None:
    options = ZipOptions(method="deflate", level=9, password="s3cret", split_size=10**9)
    assert "s3cret" not in repr(options)
    assert "s3cret" not in options.describe()
    assert options.describe() == (
        "deflate level 9, AES-256 encrypted, split into parts of 1000000000 B, at the top"
    )
    assert ZipOptions().effective_level == 6
    assert ZipOptions(method="lzma").effective_level is None
    for bad in (
        {"method": "zstd"}, {"method": "lzma", "level": 5}, {"level": 10},
        {"password": ""}, {"split_size": 10},
    ):
        with pytest.raises(ValueError):
            ZipOptions(**bad)


@pytest.mark.parametrize("method, compress_type", [
    ("stored", zipfile.ZIP_STORED),
    ("deflate", zipfile.ZIP_DEFLATED),
    ("bzip2", zipfile.ZIP_BZIP2),
    ("lzma", zipfile.ZIP_LZMA),
])
def test_each_compression_method(
    qapp: Any, tmp_path: Path, method: str, compress_type: int
) -> None:
    out = tmp_path / "out.zip"

    assert _export(tmp_path, out, method=method)[0][0] == "finished"

    with zipfile.ZipFile(out) as zf:
        assert zf.testzip() is None
        assert zf.getinfo("case/a.txt").compress_type == compress_type
        assert zf.read("case/a.txt") == b"alpha " * 5000


def test_level_changes_the_size(qapp: Any, tmp_path: Path) -> None:
    fast, small = tmp_path / "fast.zip", tmp_path / "small.zip"
    _export(tmp_path, fast, method="deflate", level=1)
    _export(tmp_path, small, method="deflate", level=9)
    with zipfile.ZipFile(fast) as f, zipfile.ZipFile(small) as s:
        assert s.getinfo("case/a.txt").compress_size <= f.getinfo("case/a.txt").compress_size


# -- password --------------------------------------------------------------------------


def test_password_encrypts_files_with_aes_and_leaves_folders_open(
    qapp: Any, tmp_path: Path
) -> None:
    out = tmp_path / "out.zip"

    assert _export(tmp_path, out, password="geheim")[0][0] == "finished"

    with pyzipper.AESZipFile(out) as zf:
        infos = {i.filename: i for i in zf.infolist()}
        assert not infos["case/"].flag_bits & 0x1
        assert infos["case/a.txt"].flag_bits & 0x1
        assert infos["case/a.txt"].wz_aes_strength == 3  # 256-bit key
        with pytest.raises(RuntimeError):
            zf.read("case/a.txt")  # no password
        zf.setpassword(b"wrong")
        with pytest.raises(RuntimeError):
            zf.read("case/a.txt")
        zf.setpassword(b"geheim")
        assert zf.read("case/a.txt") == b"alpha " * 5000
        assert zf.read("case/sub/r.bin") == (tmp_path / "case" / "sub" / "r.bin").read_bytes()


def test_password_never_reaches_the_log(
    qapp: Any, tmp_path: Path, caplog: Any
) -> None:
    caplog.set_level("DEBUG")
    _export(tmp_path, tmp_path / "out.zip", password="do-not-log-me")
    assert "do-not-log-me" not in caplog.text
    assert "AES-256 encrypted" in caplog.text


def test_replace_in_an_encrypted_archive_needs_no_password(qapp: Any, tmp_path: Path) -> None:
    out = tmp_path / "out.zip"
    with pyzipper.AESZipFile(
        out, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
    ) as zf:
        zf.setpassword(b"other")
        zf.writestr("keep.txt", b"theirs, encrypted")
        zf.writestr("case/a.txt", b"old")
    with zipfile.ZipFile(out) as zf:
        keep = zf.getinfo("keep.txt")
    raw_before = out.read_bytes()[keep.header_offset:keep.header_offset + 30 + keep.compress_size]

    seen = _export(tmp_path, out, "add", on_clash="replace")

    assert seen[0][0] == "finished"
    with pyzipper.AESZipFile(out) as zf:
        zf.setpassword(b"other")
        assert zf.read("keep.txt") == b"theirs, encrypted"  # copied as stored
        assert zf.read("case/a.txt") == b"alpha " * 5000
        moved = zf.getinfo("keep.txt")
    data = out.read_bytes()
    assert raw_before in data[moved.header_offset:]


def test_copied_entries_keep_their_central_extra_fields(tmp_path: Path) -> None:
    src = tmp_path / "src.zip"
    info = zipfile.ZipInfo("x.txt", date_time=(2020, 1, 2, 3, 4, 6))
    info.extra = b"\x55\x54\x05\x00\x01\x00\x00\x00\x5e"  # extended timestamp
    with zipfile.ZipFile(src, "w") as zf:
        zf.writestr(info, b"x")
    out = tmp_path / "out.zip"

    with zip_writer.open_archive(out, "w") as zf:
        zip_writer.copy_entries_raw(src, zf, lambda name: False, lambda: None)

    with zipfile.ZipFile(out) as zf:
        assert zf.getinfo("x.txt").extra == info.extra
        assert zf.read("x.txt") == b"x"


# -- split -----------------------------------------------------------------------------


def test_split_writer_seeks_back_across_parts(tmp_path: Path) -> None:
    writer = SplitWriter(lambda n: tmp_path / f"p.{n:03d}", 10)
    writer.write(b"0123456789abcdefghij-tail")
    writer.seek(8)
    writer.write(b"XYZ")  # spans parts 1 and 2
    writer.seek(0, os.SEEK_END)
    writer.write(b"!")
    parts = writer.parts()
    writer.close()
    assert [p.name for p in parts] == ["p.001", "p.002", "p.003"]
    assert b"".join(p.read_bytes() for p in parts) == b"01234567XYZbcdefghij-tail!"
    assert [p.stat().st_size for p in parts] == [10, 10, 6]


def test_split_writer_with_many_parts_keeps_few_open(tmp_path: Path) -> None:
    writer = SplitWriter(lambda n: tmp_path / f"p.{n:03d}", 4)
    payload = bytes(range(256)) * 4
    writer.write(payload)
    writer.seek(1)
    writer.write(b"\xff")  # back into the first part, long closed
    parts = writer.parts()
    writer.close()
    assert len(parts) == 256
    joined = b"".join(p.read_bytes() for p in parts)
    assert joined == payload[:1] + b"\xff" + payload[2:]


def test_split_archive_parts_join_into_the_archive(qapp: Any, tmp_path: Path) -> None:
    out = tmp_path / "out.zip"

    seen = _export(tmp_path, out, method="stored", split_size=100_000)

    assert seen == [("finished", str(part_path(out, 1)), 0)]
    parts = existing_parts(out)
    assert [p.name for p in parts] == ["out.zip.001", "out.zip.002", "out.zip.003"]
    assert all(p.stat().st_size == 100_000 for p in parts[:-1])
    assert not out.exists()
    joined = b"".join(p.read_bytes() for p in parts)
    with zipfile.ZipFile(io.BytesIO(joined)) as zf:
        assert zf.testzip() is None
        assert zf.read("case/a.txt") == b"alpha " * 5000
    assert not list(tmp_path.glob("*.crush-partial"))


def test_split_and_encrypted(qapp: Any, tmp_path: Path) -> None:
    out = tmp_path / "out.zip"
    _export(tmp_path, out, password="pw", split_size=100_000)
    joined = b"".join(p.read_bytes() for p in existing_parts(out))
    with pyzipper.AESZipFile(io.BytesIO(joined)) as zf:
        zf.setpassword(b"pw")
        assert zf.read("case/a.txt") == b"alpha " * 5000


def test_resplit_removes_stale_parts(qapp: Any, tmp_path: Path) -> None:
    out = tmp_path / "out.zip"
    _export(tmp_path, out, method="stored", split_size=100_000)
    assert len(existing_parts(out)) == 3

    _export(tmp_path, out, "replace", method="stored", split_size=1_000_000)

    assert [p.name for p in existing_parts(out)] == ["out.zip.001"]


def test_cancelled_split_leaves_nothing(qapp: Any, tmp_path: Path) -> None:
    vfs = _source(tmp_path)
    out = tmp_path / "out.zip"
    worker = _ExportZipWorker(
        [_zip_item(vfs.root(), vfs)], str(out), "new", False,
        options=ZipOptions(split_size=100_000),
    )
    worker.cancel()

    assert _run(worker) == [("cancelled", str(out), "new")]
    assert existing_parts(out) == []
    assert not [p for p in tmp_path.iterdir() if p.name != "case"]


def test_a_split_archive_cant_be_added_to(qapp: Any, tmp_path: Path) -> None:
    vfs = _source(tmp_path)
    with pytest.raises(ValueError):
        _ExportZipWorker(
            [_zip_item(vfs.root(), vfs)], str(tmp_path / "o.zip"), "add", False,
            options=ZipOptions(split_size=100_000),
        )


def test_existing_parts_only_counts_numbered_parts(tmp_path: Path) -> None:
    out = tmp_path / "x.zip"
    for name in ("x.zip.001", "x.zip.002", "x.zip.010", "x.zip.bak", "x.zip.01", "y.zip.001"):
        (tmp_path / name).write_bytes(b"")
    assert [p.name for p in existing_parts(out)] == ["x.zip.001", "x.zip.002", "x.zip.010"]


# -- dialog and flow -------------------------------------------------------------------


def test_dialog_turns_its_fields_into_options(qapp: Any, tmp_path: Path) -> None:
    dialog = ZipExportDialog(None, str(tmp_path / "out"))
    try:
        assert dialog.archive_path() == tmp_path / "out.zip"
        assert dialog.options() == ZipOptions(level=6)  # deflate 6, no password, one file
        dialog._method.setCurrentIndex(dialog._method.findData("bzip2"))
        assert dialog._level.value() == 9
        dialog._level.setValue(3)
        dialog._encrypt.setChecked(True)
        dialog._password.setText("pw")
        dialog._split.setChecked(True)
        dialog._split_size.setValue(700)
        dialog._split_unit.setCurrentIndex(dialog._split_unit.findData("MB"))
        options = dialog.options()
        assert options == ZipOptions("bzip2", 3, "pw", 700_000_000)
        remembered = ZipExportDialog.remembered(options)
        assert remembered.password is None and remembered.method == "bzip2"

        again = ZipExportDialog(None, "x.zip", remembered)
        assert again.options() == remembered
        assert again._password.text() == ""
        again.deleteLater()
    finally:
        dialog.deleteLater()


def test_dialog_refuses_mismatched_passwords(
    qapp: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    warned: list[str] = []
    monkeypatch.setattr(QMessageBox, "warning", lambda _p, _t, text, *a: warned.append(text))
    dialog = ZipExportDialog(None, str(tmp_path / "out.zip"))
    try:
        dialog._encrypt.setChecked(True)
        dialog._password.setText("one")
        dialog._confirm.setText("two")
        dialog._accept()
        assert dialog.result() != dialog.DialogCode.Accepted
        assert warned == ["The passwords don't match."]
        dialog._confirm.setText("one")
        dialog._accept()
        assert dialog.result() == dialog.DialogCode.Accepted
    finally:
        dialog.deleteLater()


def test_with_zip_suffix() -> None:
    assert with_zip_suffix("/a/b") == Path("/a/b.zip")
    assert with_zip_suffix("/a/b.ZIP") == Path("/a/b.ZIP")
    assert with_zip_suffix("/a/b.tar") == Path("/a/b.tar.zip")


@pytest.mark.parametrize("answer", [QMessageBox.StandardButton.Yes, QMessageBox.StandardButton.No])
def test_flow_asks_before_replacing_parts(
    qapp: Any, qtbot: Any, tmp_path: Path, monkeypatch: Any, answer: Any
) -> None:
    vfs = _source(tmp_path)
    out = tmp_path / "out.zip"
    for n in (1, 2):
        part_path(out, n).write_bytes(b"old part")
    options = ZipOptions(method="stored", split_size=10**6)
    monkeypatch.setattr(
        MainWindow, "_zip_export_dialog", lambda self, default_name, items: (out, options)
    )
    asked: list[str] = []

    def question(_parent: Any, _title: str, text: str, *_a: Any) -> Any:
        asked.append(text)  # then "Open location?" after the export: no
        return answer if len(asked) == 1 else QMessageBox.StandardButton.No

    monkeypatch.setattr(QMessageBox, "question", question)

    win = MainWindow()
    try:
        win._export_node_zip(vfs.root(), vfs)
        if answer == QMessageBox.StandardButton.Yes:
            qtbot.waitUntil(
                lambda: not win._thread_is_running(win._export_thread), timeout=10_000
            )
            qapp.processEvents()
    finally:
        win.close()
    assert "2 parts" in asked[0]  # (a later question: open the location)
    if answer == QMessageBox.StandardButton.Yes:
        assert [p.name for p in existing_parts(out)] == ["out.zip.001"]
        with zipfile.ZipFile(part_path(out, 1)) as zf:
            assert zf.read("case/a.txt") == b"alpha " * 5000
    else:
        assert part_path(out, 2).read_bytes() == b"old part"


def test_split_archive_hash_list_names_each_part(qapp: Any, tmp_path: Path) -> None:
    import hashlib

    out = tmp_path / "out.zip"
    _export(tmp_path, out, method="stored", split_size=100_000)

    assert not (tmp_path / "out.zip.crush-export-hashes.txt").exists()  # not the unsplit one's
    hashes = (tmp_path / "out.zip.split.crush-export-hashes.txt").read_text(encoding="utf-8")
    parts = existing_parts(out)
    for part in parts:
        digest = hashlib.sha256(part.read_bytes()).hexdigest()
        assert f"# part sha256={digest}  size={part.stat().st_size}  {part.name}" in hashes
    whole = hashlib.sha256(b"".join(p.read_bytes() for p in parts)).hexdigest()
    assert f"# archive sha256={whole}" in hashes and "put together" in hashes
    assert "split into parts of 100000 B" in hashes


def test_split_and_unsplit_archives_keep_their_own_lists(qapp: Any, tmp_path: Path) -> None:
    out = tmp_path / "out.zip"
    _export(tmp_path, out)  # unsplit, integrity on
    unsplit = (tmp_path / "out.zip.crush-export-hashes.txt").read_text(encoding="utf-8")

    _export(tmp_path, out, "replace", method="stored", split_size=100_000)
    _export(tmp_path, out, "replace", method="stored", split_size=1_000_000)  # re-split

    assert (tmp_path / "out.zip.crush-export-hashes.txt").read_text(encoding="utf-8") == unsplit
    assert (tmp_path / "out.zip.split.crush-export-hashes.txt").is_file()
    assert (tmp_path / "out.zip.split.crush-export-times.txt").is_file()
    assert out.is_file()  # the unsplit archive itself is left alone too
