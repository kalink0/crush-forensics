"""Archives, backups and disk images are opened by their content, not
their name (open_vfs): ZIP, 7z, TAR (plain, bzip2, xz), a ZIP after
leading bytes, and a file named like an archive that isn't one."""
from __future__ import annotations

import bz2
import io
import lzma
import tarfile
import zipfile
from pathlib import Path

import pytest

from crush.core.vfs import (
    DirectoryVFS,
    FileVFS,
    SevenZipVFS,
    TarVFS,
    ZipVFS,
    archive_kind,
    open_vfs,
    zip_leading_bytes,
)


def _zip_bytes() -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr("inner/hello.txt", "hi")
    return out.getvalue()


def _tar_bytes() -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as tf:
        data = b"hi"
        info = tarfile.TarInfo("hello.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return out.getvalue()


def _names(vfs: object) -> set[str]:
    root = vfs.root()  # type: ignore[attr-defined]
    return {c.name for c in root.children}


# -- archive_kind -------------------------------------------------------------

def test_archive_kind_from_first_bytes() -> None:
    assert archive_kind(_zip_bytes()[:512]) == "zip"
    assert archive_kind(b"PK\x05\x06" + bytes(18)) == "zip"  # empty archive
    assert archive_kind(b"7z\xbc\xaf\x27\x1c" + bytes(26)) == "7z"
    assert archive_kind(_tar_bytes()[:512]) == "tar"
    assert archive_kind(b"\x1f\x8b\x08" + bytes(10)) == "gzip"
    assert archive_kind(b"ANDROID BACKUP\n5\n1\nnone\n") == "android_backup"
    assert archive_kind(b"BZh91AY&SY") is None  # only decompressing tells
    assert archive_kind(bytes(512)) is None


# -- open_vfs by content --------------------------------------------------------

@pytest.mark.parametrize("name", ["inner.bin", "no_extension", "app.apk", "report.docx"])
def test_zip_opens_as_zip_whatever_its_name(tmp_path: Path, name: str) -> None:
    path = tmp_path / name
    path.write_bytes(_zip_bytes())
    vfs = open_vfs(path)
    assert isinstance(vfs, ZipVFS)
    assert _names(vfs) == {"inner"}
    assert str(vfs.fallback_note) == ""
    vfs.close()


def test_7z_opens_as_7z_whatever_its_name(tmp_path: Path) -> None:
    py7zr = pytest.importorskip("py7zr")
    path = tmp_path / "archive.dat"
    with py7zr.SevenZipFile(path, "w") as zf:
        zf.writestr(b"hi", "hello.txt")
    vfs = open_vfs(path)
    assert isinstance(vfs, SevenZipVFS)
    assert _names(vfs) == {"hello.txt"}
    vfs.close()


@pytest.mark.parametrize("compress", [None, bz2.compress, lzma.compress])
def test_tar_opens_as_tar_whatever_its_name(tmp_path: Path, compress: object) -> None:
    data = _tar_bytes()
    if compress is not None:
        data = compress(data)  # type: ignore[operator]
    path = tmp_path / "blob"
    path.write_bytes(data)
    vfs = open_vfs(path)
    assert isinstance(vfs, TarVFS)
    assert _names(vfs) == {"hello.txt"}
    vfs.close()


@pytest.mark.parametrize(
    ("name", "note"),
    [
        ("fake.zip", "Named .zip, but no ZIP signature found"),
        ("fake.7z", "Named .7z, but no 7z signature found"),
        ("fake.gz", "Named .gz, but no gzip signature found"),
    ],
)
def test_named_archive_without_signature_opens_as_file_with_note(
    tmp_path: Path, name: str, note: str,
) -> None:
    path = tmp_path / name
    path.write_bytes(b"just some text, not an archive")
    vfs = open_vfs(path)
    assert isinstance(vfs, FileVFS)
    assert str(vfs.fallback_note) == note


def test_named_tar_that_isnt_one_says_so(tmp_path: Path) -> None:
    path = tmp_path / "fake.tar.gz"
    path.write_bytes(b"just some text, not an archive")
    vfs = open_vfs(path)
    assert isinstance(vfs, FileVFS)
    assert str(vfs.fallback_note).startswith("Named .tar.gz, but not opened as TAR — ")
    assert "Named .gz" not in str(vfs.fallback_note)  # one note, not a second one for .gz


def test_zip_signature_but_unreadable_archive_says_so(tmp_path: Path) -> None:
    path = tmp_path / "broken.zip"
    path.write_bytes(b"PK\x03\x04" + bytes(60))
    vfs = open_vfs(path)
    assert isinstance(vfs, FileVFS)
    assert str(vfs.fallback_note).startswith("ZIP signature found, but not opened as ZIP — ")


# -- ZIP after leading bytes ------------------------------------------------------

def test_zip_after_leading_bytes_is_noted_not_routed(tmp_path: Path) -> None:
    path = tmp_path / "photo.jpg"
    path.write_bytes(b"\xff\xd8\xff" + bytes(97) + _zip_bytes())
    assert zip_leading_bytes(path) == 100

    vfs = open_vfs(path)
    assert isinstance(vfs, FileVFS)
    assert str(vfs.fallback_note) == (
        "Contains a ZIP archive after 100 leading bytes — "
        "right-click → Open in New Window to browse it"
    )


def test_zip_after_leading_bytes_opens_on_explicit_request(tmp_path: Path) -> None:
    path = tmp_path / "photo.jpg"
    path.write_bytes(b"\xff\xd8\xff" + bytes(97) + _zip_bytes())
    vfs = open_vfs(path, embedded_zip=True)
    assert isinstance(vfs, ZipVFS)
    assert _names(vfs) == {"inner"}
    assert str(vfs.fallback_note) == "ZIP archive opened after 100 leading bytes"
    vfs.close()


def test_plain_zip_has_no_leading_bytes(tmp_path: Path) -> None:
    path = tmp_path / "a.zip"
    path.write_bytes(_zip_bytes())
    assert zip_leading_bytes(path) is None


# -- UI hints (status bar, large-file dialog) --------------------------------------

def test_member_zip_hint_by_content_not_name(tmp_path: Path) -> None:
    from crush.ui.main_window import _can_open_as_source, _open_as_source_hint

    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as zf:
        zf.writestr("inner.bin", _zip_bytes())
        zf.writestr("fake.zip", b"not a zip")
    vfs = ZipVFS(outer)
    nodes = {c.name: c for c in vfs.root().children}

    assert _can_open_as_source(nodes["inner.bin"], vfs) is True
    assert _open_as_source_hint(nodes["inner.bin"], vfs, probe_archive=False)
    assert _can_open_as_source(nodes["fake.zip"], vfs) is None
    assert _open_as_source_hint(nodes["fake.zip"], vfs, probe_archive=False) == ""
    vfs.close()


def test_on_disk_file_with_leading_zip_gets_hint(tmp_path: Path) -> None:
    from crush.ui.main_window import _can_open_as_source, _open_as_source_hint

    (tmp_path / "setup.exe").write_bytes(b"MZ" + bytes(98) + _zip_bytes())
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "setup.exe")
    assert _can_open_as_source(node, vfs) is True
    assert "after 100 leading bytes" in _open_as_source_hint(node, vfs, probe_archive=False)
