# SPDX-License-Identifier: Apache-2.0
"""Export of a file whose bytes can't be read from the evidence.

The read error can come after the last bytes that could be read (a raw
image's length check runs once the reader is done), so the partial copy
was left under the file's own name, and the first such file ended the whole
export. Now that file is left out, nothing stays under its name, the export
goes on, and crush-export-failed.txt lists it with the reason.
"""
from __future__ import annotations

import io
from pathlib import Path
from typing import IO, Any

import pytest

from crush.core.vfs import DirectoryVFS, VFSNode
from crush.ui.main_window import _ExportMultiWorker, _ExportWorker


class _FailingRead(io.BytesIO):
    """Gives its bytes, then fails the read that would have ended it."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self._given = False

    def read(self, size: int | None = -1) -> bytes:
        if self._given:
            raise OSError("only 4 of 9 bytes can be read: the reader gave no reason")
        self._given = True
        return super().read(size)


class _OneUnreadable(DirectoryVFS):
    def open(self, node: VFSNode) -> IO[bytes]:
        if node.name == "bad.bin":
            return _FailingRead(b"part")
        return super().open(node)


def _source(tmp_path: Path) -> _OneUnreadable:
    src = tmp_path / "src"
    src.mkdir()
    (src / "bad.bin").write_bytes(b"part-and-rest")
    (src / "good.txt").write_bytes(b"good")
    return _OneUnreadable(src)


def _run(worker: Any) -> list[tuple[Any, ...]]:
    seen: list[tuple[Any, ...]] = []
    worker.finished.connect(lambda *a: seen.append(("finished", *a)))
    worker.failed.connect(lambda *a: seen.append(("failed", *a)))
    worker.run()
    return seen


@pytest.mark.parametrize("integrity", [True, False])
def test_tree_export_leaves_out_an_unreadable_file_and_lists_it(
    qapp: Any, tmp_path: Path, integrity: bool
) -> None:
    vfs = _source(tmp_path)
    root = vfs.root()
    dest = tmp_path / "dest"
    target = dest / root.name
    target.mkdir(parents=True)
    (target / "bad.bin").write_bytes(b"from an earlier export")

    seen = _run(_ExportWorker(vfs, root, str(dest), integrity))

    assert seen == [("finished", str(target), 1)]
    assert not (target / "bad.bin").exists()
    assert (target / "good.txt").read_bytes() == b"good"
    failed = (target / "crush-export-failed.txt").read_text(encoding="utf-8")
    bad = next(c for c in root.children if c.name == "bad.bin")
    assert f"{bad.path}\tonly 4 of 9 bytes can be read" in failed
    hashes = target / "crush-export-hashes.txt"
    if integrity:
        assert "good.txt" in hashes.read_text(encoding="utf-8")
        assert "bad.bin" not in hashes.read_text(encoding="utf-8")
    else:
        assert not hashes.exists()


def test_single_file_export_of_an_unreadable_file_leaves_nothing(qapp: Any, tmp_path: Path) -> None:
    vfs = _source(tmp_path)
    bad = next(c for c in vfs.root().children if c.name == "bad.bin")
    dest = tmp_path / "dest"
    dest.mkdir()

    seen = _run(_ExportWorker(vfs, bad, str(dest), True))

    assert seen == [("finished", str(dest / "bad.bin"), 1)]
    assert not (dest / "bad.bin").exists()
    assert "only 4 of 9 bytes" in (dest / "crush-export-failed.txt").read_text(encoding="utf-8")


def test_filtered_export_leaves_out_an_unreadable_file_and_lists_it(
    qapp: Any, tmp_path: Path
) -> None:
    vfs = _source(tmp_path)
    entries = [(c, vfs, f"src/{c.name}") for c in vfs.root().children]
    dest = tmp_path / "dest"
    dest.mkdir()

    seen = _run(_ExportMultiWorker(entries, str(dest), True, "*"))

    (export_root,) = dest.glob("crush-export-*")
    assert seen == [("finished", str(export_root), 1)]
    assert not (export_root / "src" / "bad.bin").exists()
    assert (export_root / "src" / "good.txt").read_bytes() == b"good"
    assert "src/bad.bin\tonly 4 of 9 bytes" in (
        export_root / "crush-export-failed.txt").read_text(encoding="utf-8")
    hashes = (export_root / "crush-export-hashes.txt").read_text(encoding="utf-8")
    assert "# files: 1" in hashes and "# not exported: 1 (see crush-export-failed.txt)" in hashes


def test_a_write_error_still_ends_the_export(qapp: Any, tmp_path: Path, monkeypatch: Any) -> None:
    """Only the evidence's read errors are per file: a copy that can't be
    written (a full disk) ends the export as before, leaving nothing."""
    vfs = _source(tmp_path)
    good = next(c for c in vfs.root().children if c.name == "good.txt")
    dest = tmp_path / "dest"
    dest.mkdir()

    real_open = open

    class _Full(io.RawIOBase):
        def writable(self) -> bool:
            return True

        def write(self, b: Any) -> int:
            raise OSError(28, "No space left on device")

    def fake_open(path: Any, mode: str = "r", *a: Any, **k: Any) -> Any:
        if str(path).endswith("good.txt") and "w" in mode:
            real_open(path, mode, *a, **k).close()
            return _Full()
        return real_open(path, mode, *a, **k)

    monkeypatch.setattr("builtins.open", fake_open)
    seen = _run(_ExportWorker(vfs, good, str(dest), True))

    assert seen and seen[0][0] == "failed" and "No space left" in seen[0][1]
    assert not (dest / "good.txt").exists()
