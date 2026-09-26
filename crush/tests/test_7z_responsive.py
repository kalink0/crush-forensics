# SPDX-License-Identifier: Apache-2.0
"""A large 7z must never freeze the window: type labels are read in one
background pass that keeps only each entry's head, a single peek stops
extracting once its bytes are in, the UI thread only uses what is already
at hand, and an entry opened from the tree is extracted once, ahead, off
the UI thread. The same for compressed TARs and large gzip members; sources
read in place (plain TAR, small gzip) need none of it."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import py7zr
import pytest

import crush.core.vfs as vfs_module
from crush.core.vfs import DirectoryVFS, SevenZipVFS, VFSNode

_SIZES = {"a.bin": 3 << 20, "b.bin": 5 << 20, "c.bin": 2 << 20, "empty.bin": 0, "tiny.txt": 7}


def _content(name: str, size: int) -> bytes:
    head = (name.encode() * 64)[:64]
    return (head + bytes(size))[:size]


@pytest.fixture
def solid_7z(tmp_path: Path) -> Path:
    src = tmp_path / "src"
    (src / "dir").mkdir(parents=True)
    for name, size in _SIZES.items():
        (src / "dir" / name).write_bytes(_content(name, size))
    arc = tmp_path / "solid.7z"
    with py7zr.SevenZipFile(arc, "w") as z:
        z.writeall(src / "dir", "dir")
    return arc


def _node(vfs: SevenZipVFS, name: str) -> VFSNode:
    folder = next(c for c in vfs.root().children if c.name == "dir")
    return next(c for c in folder.children if c.name == name)


class _CountingSpy:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.whole = 0
        real = vfs_module._make_7z_sequence_factory

        def _spy(spool: bool) -> Any:
            self.whole += 1
            return real(spool)

        monkeypatch.setattr(vfs_module, "_make_7z_sequence_factory", _spy)


def test_peek_reads_only_the_head(solid_7z: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    vfs = SevenZipVFS(solid_7z)
    try:
        spy = _CountingSpy(monkeypatch)
        for name, size in _SIZES.items():
            node = _node(vfs, name)
            assert vfs.peek(node, 2048) == _content(name, size)[:2048]
        assert spy.whole == 0, "a peek must not extract (or spool) whole entries"
    finally:
        vfs.close()


def test_peek_if_cached_never_extracts(solid_7z: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    vfs = SevenZipVFS(solid_7z)
    try:
        node = _node(vfs, "b.bin")
        calls: list[Any] = []
        monkeypatch.setattr(vfs, "_extract", lambda *a, **k: calls.append(a))
        assert vfs.peek_if_cached(node, 2048) is None
        assert calls == []
    finally:
        vfs.close()


def test_prefetch_heads_fills_every_head_in_one_pass(
    solid_7z: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vfs = SevenZipVFS(solid_7z)
    try:
        passes: list[Any] = []
        real = vfs._extract
        monkeypatch.setattr(vfs, "_extract", lambda t, f: (passes.append(t), real(t, f)))
        assert vfs.prefetch_heads() is True
        assert len(passes) == 1
        for name, size in _SIZES.items():
            assert vfs.peek_if_cached(_node(vfs, name), 2048) == _content(name, size)[:2048]
    finally:
        vfs.close()


def test_head_pass_steps_aside_for_a_foreground_read(solid_7z: Path) -> None:
    """While a read waits for (or holds) the archive, the background head
    pass doesn't start another extraction; it finishes once the read is done."""
    import threading
    import time

    vfs = SevenZipVFS(solid_7z)
    try:
        vfs._foreground = 1  # a foreground read is waiting
        result: dict[str, bool] = {}
        worker = threading.Thread(target=lambda: result.setdefault("ok", vfs.prefetch_heads()))
        worker.start()
        time.sleep(0.3)
        assert vfs._head_cache == {}, "the pass must wait while a read is pending"
        vfs._foreground = 0
        worker.join(timeout=30)
        assert result == {"ok": True}
        assert all(vfs.peek_if_cached(_node(vfs, n), 2048) is not None for n in _SIZES)
    finally:
        vfs.close()


def test_every_entry_knows_its_solid_block(solid_7z: Path) -> None:
    vfs = SevenZipVFS(solid_7z)
    try:
        assert set(vfs._entry_block) == set(vfs._entry_names)
        assert any(block is not None for block in vfs._entry_block.values())
    finally:
        vfs.close()


def test_prefetch_heads_can_be_cancelled(solid_7z: Path) -> None:
    vfs = SevenZipVFS(solid_7z)
    try:
        assert vfs.prefetch_heads(cancelled=lambda: True) is False
        # still fully usable afterwards
        assert vfs.read(_node(vfs, "tiny.txt")) == _content("tiny.txt", 7)
    finally:
        vfs.close()


def test_prepared_large_entry_is_not_extracted_again(
    solid_7z: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(vfs_module, "STREAM_THRESHOLD", 1 << 20)
    vfs = SevenZipVFS(solid_7z)
    try:
        node = _node(vfs, "b.bin")
        assert vfs.needs_prepare(node)
        vfs.prepare(node)
        assert not vfs.needs_prepare(node)
        spy = _CountingSpy(monkeypatch)
        expected = _content("b.bin", _SIZES["b.bin"])
        with vfs.open(node) as a, vfs.open(node) as b:  # independent positions
            a.seek(100)
            assert b.read(10) == expected[:10]
            assert a.read(10) == expected[100:110]
        with vfs.open(node) as c:
            assert c.read() == expected
        assert vfs.read(node) == expected
        assert vfs.peek_if_cached(node, 2048) == expected[:2048]
        assert spy.whole == 0
        # preparing another large entry replaces it; a reader still open keeps working
        keep = vfs.open(node)
        vfs.prepare(_node(vfs, "a.bin"))
        assert vfs.needs_prepare(node)
        assert keep.read(5) == expected[:5]
        keep.close()
    finally:
        vfs.close()


def test_prepare_small_entry_fills_read_cache(solid_7z: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    vfs = SevenZipVFS(solid_7z)
    try:
        node = _node(vfs, "c.bin")
        vfs.prepare(node)
        calls: list[Any] = []
        monkeypatch.setattr(vfs, "_extract", lambda *a, **k: calls.append(a))
        assert vfs.read(node) == _content("c.bin", _SIZES["c.bin"])
        assert calls == []
    finally:
        vfs.close()


def test_folder_files_need_no_preparation(tmp_path: Path) -> None:
    (tmp_path / "x.bin").write_bytes(b"hello")
    vfs = DirectoryVFS(tmp_path)
    node = vfs.root().children[0]
    assert vfs.peek_if_cached(node, 3) == b"hel"
    assert not vfs.needs_prepare(node)


def test_type_column_never_extracts_on_the_ui_thread(
    qapp: Any, solid_7z: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Uncached entries get a pending label instead of a peek on the UI
    thread; once their heads are in, the label resolves."""
    from crush.ui.fs_panel import _TYPE_PENDING
    from crush.ui.main_window import MainWindow

    vfs = SevenZipVFS(solid_7z)
    win = MainWindow()
    try:
        panel = win._fs_panel
        node = _node(vfs, "a.bin")

        def _no_peek(*_a: Any, **_k: Any) -> bytes:
            raise AssertionError("UI-thread type label must not peek a 7z")

        monkeypatch.setattr(vfs, "peek", _no_peek)
        assert panel._detect_type_label(node, vfs, wait=False) is None
        monkeypatch.undo()
        vfs.prefetch_heads()
        assert panel._detect_type_label(node, vfs, wait=False) not in (None, _TYPE_PENDING)
    finally:
        win.close()
        vfs.close()


def test_large_archive_prescan_uses_the_head_pass(
    solid_7z: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(vfs_module, "_SEVENZIP_PREFETCH_SIZE_LIMIT", 1)
    vfs = SevenZipVFS(solid_7z)
    try:
        assert vfs.prefetch_all() is False
        assert vfs.prefetch_heads() is True
        assert all(
            vfs.peek_if_cached(_node(vfs, n), 2048) is not None for n in _SIZES
        )
    finally:
        vfs.close()


def _tar(tmp_path: Path, mode: str, suffix: str) -> tuple[Path, dict[str, bytes]]:
    import tarfile

    data = {f"m{i}.bin": _content(f"m{i}.bin", 200_000 + i) for i in range(3)}
    arc = tmp_path / f"t{suffix}"
    with tarfile.open(arc, mode) as tf:
        for name, blob in data.items():
            (tmp_path / name).write_bytes(blob)
            tf.add(tmp_path / name, arcname=name)
    return arc, data


def test_plain_sources_read_heads_directly(tmp_path: Path) -> None:
    """Sources read in place give their heads at once: no pending type
    label and no "please wait" dialog when opening."""
    import gzip

    from crush.core.vfs import GzipVFS, TarVFS

    arc, data = _tar(tmp_path, "w", ".tar")
    tar = TarVFS(arc)
    try:
        for node in tar.root().children:
            assert tar.peek_if_cached(node, 16) == data[node.name][:16]
            assert not tar.needs_prepare(node)
    finally:
        tar.close()
    gz = tmp_path / "one.log.gz"
    gz.write_bytes(gzip.compress(b"line one\n" * 10))
    gvfs = GzipVFS(gz)
    member = gvfs.root().children[0]
    assert gvfs.peek_if_cached(member, 4) == b"line"
    assert not gvfs.needs_prepare(member)


def test_compressed_tar_member_is_prepared_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from crush.core.vfs import TarVFS

    monkeypatch.setattr(vfs_module, "STREAM_THRESHOLD", 100_000)
    arc, data = _tar(tmp_path, "w:gz", ".tar.gz")
    tar = TarVFS(arc)
    try:
        small_first, big = tar.root().children[0], tar.root().children[2]
        assert tar.needs_prepare(big)
        tar.prepare(big)
        assert not tar.needs_prepare(big)
        extracted: list[Any] = []
        real = tar._tf.extractfile
        monkeypatch.setattr(tar._tf, "extractfile", lambda m: (extracted.append(m), real(m))[1])
        with tar.open(big) as a, tar.open(big) as b:
            a.seek(50)
            assert b.read(8) == data[big.name][:8]
            assert a.read(8) == data[big.name][50:58]
        assert tar.read(big) == data[big.name]
        assert extracted == [], "a prepared member must not be decompressed again"
        tar.prepare(small_first)  # replaces the staged member
        assert tar.needs_prepare(big)
    finally:
        tar.close()


def test_large_gzip_member_is_prepared_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import gzip

    from crush.core.vfs import GzipVFS

    monkeypatch.setattr(vfs_module, "STREAM_THRESHOLD", 1000)
    payload = _content("big.log", 50_000)
    gz = tmp_path / "big.log.gz"
    gz.write_bytes(gzip.compress(payload))
    gvfs = GzipVFS(gz)
    member = gvfs.root().children[0]
    assert gvfs.needs_prepare(member)
    gvfs.prepare(member)
    assert not gvfs.needs_prepare(member)
    monkeypatch.setattr(gzip, "open", lambda *a, **k: pytest.fail("decompressed again"))
    assert gvfs.read(member) == payload
    with gvfs.open(member) as f:
        f.seek(10)
        assert f.read(5) == payload[10:15]


def test_random_data_heads_match(tmp_path: Path) -> None:
    """Heads of incompressible entries, several solid-block chunks long."""
    src = tmp_path / "src"
    src.mkdir()
    data = {f"r{i}.bin": os.urandom(300_000 + i) for i in range(4)}
    for name, blob in data.items():
        (src / name).write_bytes(blob)
    arc = tmp_path / "rand.7z"
    with py7zr.SevenZipFile(arc, "w") as z:
        z.writeall(src, "src")
    vfs = SevenZipVFS(arc)
    try:
        folder = vfs.root().children[0]
        for node in folder.children:
            assert vfs.peek(node, 4096) == data[node.name][:4096]
    finally:
        vfs.close()
