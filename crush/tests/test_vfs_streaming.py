# SPDX-License-Identifier: Apache-2.0
"""Streaming VFS access: large archive members must not be buffered whole.

VFS.open() used to be `BytesIO(self.read(node))` for every archive backend,
so opening (or hex-viewing, or materializing) a 17 GB TAR inside a ZIP tried
to decompress all of it into RAM. These tests pin the replacement: members
above STREAM_THRESHOLD come back as real streams with bounded memory, while
their bytes stay identical to read().

STREAM_THRESHOLD is lowered per test so the streaming path can be exercised
with small fixtures.
"""
from __future__ import annotations

import gzip
import io
import random
import tarfile
import threading
import tracemalloc
import zipfile
import zlib
from pathlib import Path

import pytest

from crush.core.vfs import (
    AndroidBackupVFS,
    GzipVFS,
    SevenZipVFS,
    TarVFS,
    VFSNode,
    ZipVFS,
    open_vfs,
)
from crush.core.vfs_stream import (
    CopyCancelledError,
    HashingWriter,
    IterStream,
    buffered,
    copy_stream,
)


@pytest.fixture(autouse=True)
def _low_threshold(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("crush.core.vfs.STREAM_THRESHOLD", 1024)


def _blob(size: int, seed: int = 1) -> bytes:
    return random.Random(seed).randbytes(size)


def _node(vfs: ZipVFS | TarVFS | GzipVFS | SevenZipVFS, name: str) -> VFSNode:
    stack = [vfs.root()]
    while stack:
        cur = stack.pop()
        if not cur.is_dir and cur.name == name:
            return cur
        stack.extend(cur.children)
    raise AssertionError(f"{name} not in tree")


# ---------------------------------------------------------------------------
# ZIP
# ---------------------------------------------------------------------------


@pytest.fixture
def zip_path(tmp_path: Path) -> Path:
    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.bin", _blob(300_000))
        zf.writestr("small.txt", b"tiny")
    return path


def test_zip_large_member_is_a_stream_with_identical_bytes(zip_path: Path) -> None:
    data = _blob(300_000)
    vfs = ZipVFS(zip_path)
    node = _node(vfs, "big.bin")
    with vfs.open(node) as f:
        assert not isinstance(f, io.BytesIO)
        assert f.read(100) == data[:100]
        f.seek(250_000)
        assert f.read(50) == data[250_000:250_050]
        f.seek(0)
        assert f.read() == data
    assert vfs.read(node) == data
    vfs.close()


def test_zip_small_member_keeps_bytesio(zip_path: Path) -> None:
    vfs = ZipVFS(zip_path)
    with vfs.open(_node(vfs, "small.txt")) as f:
        assert isinstance(f, io.BytesIO)
        assert f.read() == b"tiny"
    vfs.close()


def test_zip_two_streams_read_independently_across_threads(zip_path: Path) -> None:
    data = _blob(300_000)
    vfs = ZipVFS(zip_path)
    node = _node(vfs, "big.bin")
    errors: list[str] = []

    def reader(offset: int) -> None:
        try:
            with vfs.open(node) as f:
                f.seek(offset)
                got = b""
                while len(got) < 100_000:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    got += chunk
                if got != data[offset : offset + len(got)]:
                    errors.append(f"mismatch at {offset}")
        except Exception as exc:  # noqa: BLE001
            errors.append(repr(exc))

    threads = [threading.Thread(target=reader, args=(off,)) for off in (0, 50_000, 120_000, 200_000)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    vfs.close()


def test_zip_open_of_huge_member_uses_bounded_memory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("crush.core.vfs.STREAM_THRESHOLD", 1024 * 1024)
    path = tmp_path / "zeros.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("zeros.bin", b"\x00" * (40 * 1024 * 1024))
    vfs = ZipVFS(path)
    node = _node(vfs, "zeros.bin")
    tracemalloc.start()
    try:
        with vfs.open(node) as f:
            head = f.read(4096)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert head == b"\x00" * 4096
    assert peak < 10 * 1024 * 1024  # the old BytesIO path peaked above 40 MB
    vfs.close()


@pytest.mark.parametrize("fixture_name", ["legacy_encrypted_zip_fixture", "aes_encrypted_zip_fixture"])
def test_zip_encrypted_member_streams_with_password(
    request: pytest.FixtureRequest, fixture_name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = request.getfixturevalue(fixture_name)
    monkeypatch.setattr("crush.core.vfs.STREAM_THRESHOLD", 0)
    vfs = ZipVFS(path, password="secret123")
    node = next(c for c in vfs.root().children if c.name == "sample.db")
    with vfs.open(node) as f:
        assert not isinstance(f, io.BytesIO)
        assert f.read() == b"SQLite format 3\x00"
    vfs.close()


# ---------------------------------------------------------------------------
# TAR
# ---------------------------------------------------------------------------


def _make_tar(path: Path, mode: str) -> bytes:
    data = _blob(300_000, seed=2)
    with tarfile.open(path, mode) as tf:  # type: ignore[call-overload]
        info = tarfile.TarInfo("dir/big.bin")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
        small = tarfile.TarInfo("dir/small.txt")
        small.size = 4
        tf.addfile(small, io.BytesIO(b"tiny"))
    return data


@pytest.mark.parametrize("name,mode", [("a.tar", "w"), ("a.tar.gz", "w:gz"), ("a.tar.xz", "w:xz")])
def test_tar_large_member_streams_and_peeks(tmp_path: Path, name: str, mode: str) -> None:
    data = _make_tar(tmp_path / name, mode)
    vfs = TarVFS(tmp_path / name)
    node = _node(vfs, "big.bin")
    assert vfs.peek(node, 16) == data[:16]
    with vfs.open(node) as f:
        assert not isinstance(f, io.BytesIO)
        assert f.read(64) == data[:64]
        f.seek(200_000)
        assert f.read(10) == data[200_000:200_010]
        f.seek(0)
        assert f.read() == data
    with vfs.open(_node(vfs, "small.txt")) as f:
        assert isinstance(f, io.BytesIO)
    vfs.close()


def test_tar_peek_does_not_read_whole_member(tmp_path: Path) -> None:
    path = tmp_path / "zeros.tar"
    with tarfile.open(path, "w") as tf:
        info = tarfile.TarInfo("zeros.bin")
        info.size = 30 * 1024 * 1024
        tf.addfile(info, io.BytesIO(b"\x00" * info.size))
    vfs = TarVFS(path)
    node = _node(vfs, "zeros.bin")
    tracemalloc.start()
    try:
        head = vfs.peek(node, 32)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert head == b"\x00" * 32
    assert peak < 5 * 1024 * 1024
    vfs.close()


# ---------------------------------------------------------------------------
# gzip
# ---------------------------------------------------------------------------


def test_gzip_large_member_is_not_held_in_memory(tmp_path: Path) -> None:
    data = _blob(300_000, seed=3)
    path = tmp_path / "big.log.gz"
    path.write_bytes(gzip.compress(data))
    vfs = GzipVFS(path)
    node = vfs.root().children[0]
    assert node.size == len(data)
    assert vfs.total_size(vfs.root()) == len(data)
    assert vfs._data is None
    with vfs.open(node) as f:
        assert not isinstance(f, io.BytesIO)
        assert f.read(50) == data[:50]
        f.seek(100_000)
        assert f.read(50) == data[100_000:100_050]
    assert vfs.read(node) == data


def test_gzip_small_member_stays_cached(tmp_path: Path) -> None:
    path = tmp_path / "s.log.gz"
    path.write_bytes(gzip.compress(b"hello"))
    vfs = GzipVFS(path)
    assert vfs._data == b"hello"
    assert vfs.read(vfs.root().children[0]) == b"hello"


# ---------------------------------------------------------------------------
# 7z
# ---------------------------------------------------------------------------


def test_sevenzip_large_member_is_staged_on_disk_not_cached(tmp_path: Path) -> None:
    import py7zr

    data = _blob(200_000, seed=4)
    path = tmp_path / "a.7z"
    with py7zr.SevenZipFile(path, "w") as z:
        z.writestr(data, "big.bin")
        z.writestr(b"tiny", "a.txt")
    vfs = SevenZipVFS(path)
    node = _node(vfs, "big.bin")
    with vfs.open(node) as f:
        assert not isinstance(f, io.BytesIO)
        assert f.read() == data
    assert "big.bin" not in vfs._read_cache
    assert vfs.read(node) == data
    assert "big.bin" not in vfs._read_cache
    vfs.close()


# ---------------------------------------------------------------------------
# Android backup (.ab)
# ---------------------------------------------------------------------------


def test_android_backup_payload_is_spooled_and_streams(tmp_path: Path) -> None:
    data = _blob(3 * 1024 * 1024 + 123, seed=5)
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tf:
        info = tarfile.TarInfo("apps/x/big.bin")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    path = tmp_path / "b.ab"
    path.write_bytes(b"ANDROID BACKUP\n5\n1\nnone\n" + zlib.compress(tar_buf.getvalue()))

    vfs = AndroidBackupVFS(path)
    node = _node(vfs, "big.bin")
    assert not isinstance(vfs._spool, io.BytesIO)
    with vfs.open(node) as f:
        assert f.read() == data
    vfs.close()
    assert vfs._spool.closed


def test_android_backup_decrypt_stream_matches_one_shot() -> None:
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    from crush.core import android_backup_crypto as crypto

    key, iv = _blob(32, 6), _blob(16, 7)
    for length in (0, 1, 15, 16, 17, 100, 4095):
        plain = _blob(length, length)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plain) + padder.finalize()
        enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        cipher = enc.update(padded) + enc.finalize()
        assert crypto.decrypt_payload(key, iv, cipher) == plain
        for step in (1, 7, 16, 1000, len(cipher) or 1):
            chunks = [cipher[i : i + step] for i in range(0, len(cipher), step)]
            assert b"".join(crypto.decrypt_payload_stream(key, iv, chunks)) == plain


def test_ios_decrypt_stream_matches_one_shot_and_rejects_bad_padding() -> None:
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    from crush.core import ios_keybag
    from crush.core.passwords import WrongPasswordError

    key = _blob(32, 8)
    plain = _blob(5000, 9)
    padder = padding.PKCS7(128).padder()
    enc = Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16)).encryptor()
    cipher = enc.update(padder.update(plain) + padder.finalize()) + enc.finalize()
    assert ios_keybag.aes_cbc_decrypt_and_unpad(key, cipher) == plain
    chunks = [cipher[i : i + 333] for i in range(0, len(cipher), 333)]
    assert b"".join(ios_keybag.aes_cbc_decrypt_stream(key, chunks)) == plain
    with pytest.raises(WrongPasswordError):
        b"".join(ios_keybag.aes_cbc_decrypt_stream(_blob(32, 10), chunks))


# ---------------------------------------------------------------------------
# Stream primitives
# ---------------------------------------------------------------------------


def _chunker(data: bytes, step: int = 7):  # noqa: ANN202
    def make():  # noqa: ANN202
        return iter([data[i : i + step] for i in range(0, len(data), step)])

    return make


def test_iter_stream_sequential_and_seeking() -> None:
    data = _blob(1000, seed=11)
    f = buffered(IterStream(_chunker(data), len(data)), buffer_size=64)
    assert f.read(10) == data[:10]
    f.seek(500)
    assert f.read(20) == data[500:520]
    f.seek(5)  # backwards restarts the generator
    assert f.read(5) == data[5:10]
    f.seek(-10, io.SEEK_END)
    assert f.read() == data[-10:]
    f.seek(0)
    assert f.read() == data


def test_copy_stream_progress_and_cancel() -> None:
    data = _blob(10_000, seed=12)
    dst = io.BytesIO()
    seen: list[int] = []
    n = copy_stream(io.BytesIO(data), dst, total=len(data), progress=lambda d, t: seen.append(d), chunk_size=3000)
    assert n == len(data) and dst.getvalue() == data
    assert seen == [3000, 6000, 9000, 10_000]

    calls = {"n": 0}

    def cancelled() -> bool:
        calls["n"] += 1
        return calls["n"] > 2

    with pytest.raises(CopyCancelledError):
        copy_stream(io.BytesIO(data), io.BytesIO(), cancelled=cancelled, chunk_size=1000)


def test_hashing_writer_hashes_what_it_forwards() -> None:
    import hashlib

    data = _blob(5000, seed=13)
    dst = io.BytesIO()
    hasher = hashlib.sha256()
    copy_stream(io.BytesIO(data), HashingWriter(dst, hasher), chunk_size=999)  # type: ignore[arg-type]
    assert dst.getvalue() == data
    assert hasher.hexdigest() == hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# End to end: a ZIP inside a ZIP, opened as its own source after extraction
# ---------------------------------------------------------------------------


def test_nested_zip_member_copies_out_and_opens_as_a_source(tmp_path: Path) -> None:
    inner = tmp_path / "inner.zip"
    inner_data = _blob(200_000, seed=14)
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("deep/file.bin", inner_data)
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(inner, "wrapped/inner.zip")

    outer_vfs = ZipVFS(outer)
    inner_node = _node(outer_vfs, "inner.zip")
    extracted = tmp_path / "extracted.zip"
    with outer_vfs.open(inner_node) as src, open(extracted, "wb") as dst:
        copy_stream(src, dst)

    inner_vfs = open_vfs(extracted)
    assert isinstance(inner_vfs, ZipVFS)
    assert inner_vfs.read(_node(inner_vfs, "file.bin")) == inner_data
    inner_vfs.close()
    outer_vfs.close()


def test_compressed_tar_peek_is_served_from_the_open_pass(tmp_path: Path) -> None:
    """A compressed tar has no index: reaching a member decompresses
    everything before it. peek() -- called per visible file by the tree's
    type detection, on the UI thread -- must therefore not touch the archive
    at all; the first bytes are kept during the one pass that builds the tree."""
    path = tmp_path / "heads.tar.gz"
    big = _blob(100_000, seed=30)
    small = b"tiny file"
    with tarfile.open(path, "w:gz") as tf:
        for name, data in (("d/big.bin", big), ("d/small.txt", small), ("d/empty", b"")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    vfs = TarVFS(path)

    def boom(*_a: object, **_k: object) -> None:
        raise AssertionError("peek reached into the compressed archive")

    vfs._tf.extractfile = boom  # type: ignore[method-assign,assignment]
    big_n, small_n, empty_n = (_node(vfs, n) for n in ("big.bin", "small.txt", "empty"))
    assert vfs.peek(big_n, 32) == big[:32]
    assert vfs.peek(big_n, 2048) == big[:2048]
    assert vfs.peek(small_n, 2048) == small  # whole file cached, so any n is answered
    assert vfs.peek(small_n, 5) == small[:5]
    assert vfs.peek(empty_n, 32) == b""


def test_compressed_tar_peek_beyond_the_cache_still_reads_the_real_bytes(tmp_path: Path) -> None:
    path = tmp_path / "long.tar.gz"
    data = _blob(50_000, seed=31)
    with tarfile.open(path, "w:gz") as tf:
        info = tarfile.TarInfo("big.bin")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    vfs = TarVFS(path)
    assert vfs.peek(_node(vfs, "big.bin"), 10_000) == data[:10_000]  # more than the cached head
    vfs.close()


def test_plain_tar_keeps_no_head_cache(tmp_path: Path) -> None:
    path = tmp_path / "plain.tar"
    with tarfile.open(path, "w") as tf:
        info = tarfile.TarInfo("f.bin")
        info.size = 4
        tf.addfile(info, io.BytesIO(b"abcd"))
    vfs = TarVFS(path)
    assert vfs._head_cache == {}
    assert vfs.peek(_node(vfs, "f.bin"), 4) == b"abcd"
    vfs.close()
