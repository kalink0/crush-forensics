# SPDX-License-Identifier: Apache-2.0
"""The pyzipper internals crush.core.zip_writer and the ZIP export rely on.

pyzipper is capped in pyproject.toml because of these. Each test names one
internal and checks it is still there and still behaves as the code expects,
so a new pyzipper release that changes one fails here, by name, rather than
writing a broken archive. Raise the cap only once these and the ZIP export
tests pass with the new release.
"""
from __future__ import annotations

import inspect
import io
import zipfile
from pathlib import Path

import pyzipper
from pyzipper.zipfile_aes import AESZipInfo

from crush.core import zip_writer


def test_strip_extra_fields_keeps_what_follows_a_stripped_field() -> None:
    # Our own: pyzipper's _strip_extra drops every field after one stripped
    # at the start, which would lose a large entry's timestamp (ZIP64 first).
    zip64 = b"\x01\x00\x08\x00" + b"\x00" * 8
    timestamp = b"\x55\x54\x05\x00\x01\x00\x00\x00\x00"
    aes = b"\x01\x99\x07\x00\x02\x00AE\x03\x08\x00"
    assert zip_writer.strip_extra_fields(zip64 + timestamp, (0x0001,)) == timestamp
    assert zip_writer.strip_extra_fields(timestamp + aes, (0x9901,)) == timestamp
    assert zip_writer.strip_extra_fields(zip64 + timestamp + aes, (0x0001, 0x9901)) == timestamp
    assert zip_writer.strip_extra_fields(timestamp, (0x0001,)) == timestamp
    assert zip_writer.strip_extra_fields(b"", (0x0001,)) == b""
    assert zip_writer.strip_extra_fields(timestamp + b"\x00\x00", (0x0001,)) == timestamp + b"\x00\x00"


def test_a_timestamp_after_a_zip64_field_reaches_the_central_directory(
    tmp_path: Path,
) -> None:
    # A large entry's extras, read back from an archive, start with its
    # ZIP64 field; the raw copy writes them out again. The timestamp after
    # it must survive -- with pyzipper's _strip_extra it was dropped.
    timestamp = b"\x55\x54\x05\x00\x01\x00\x00\x00\x5e"
    out = tmp_path / "x.zip"
    info = zip_writer.new_info("big.bin", (2020, 1, 2, 3, 4, 6))
    info.extra = b"\x01\x00\x08\x00" + b"\x00" * 8 + timestamp
    with zip_writer.open_archive(out, "w") as zf:
        zf.writestr(info, b"x")
    with zipfile.ZipFile(out) as zf:
        assert zf.getinfo("big.bin").extra == timestamp
        assert zf.read("big.bin") == b"x"


def test_encode_central_directory_takes_the_extra_data_to_write() -> None:
    parameters = inspect.signature(AESZipInfo.encode_central_directory).parameters
    assert "extra_data" in parameters
    assert parameters["extra_data"].kind is inspect.Parameter.KEYWORD_ONLY


def test_an_entrys_own_extras_reach_the_central_directory(tmp_path: Path) -> None:
    out = tmp_path / "x.zip"
    info = zip_writer.new_info("x.txt", (2020, 1, 2, 3, 4, 6))
    info.extra = b"\x55\x54\x05\x00\x01\x00\x00\x00\x5e"
    with zip_writer.open_archive(out, "w") as zf:
        zf.writestr(info, b"x")
    with zipfile.ZipFile(out) as zf:  # read back with the standard library
        assert zf.getinfo("x.txt").extra == info.extra


def test_an_open_archive_exposes_what_the_raw_copy_appends_to(tmp_path: Path) -> None:
    with zip_writer.open_archive(tmp_path / "x.zip", "w") as zf:
        zf.writestr("a.txt", b"a")
        assert hasattr(zf, "fp") and zf.fp.tell() == zf.start_dir
        assert isinstance(zf.filelist, list) and isinstance(zf.NameToInfo, dict)
        assert zf.NameToInfo["a.txt"] is zf.filelist[0]
        assert zf._didModify is True
        assert zf.getinfo("a.txt").header_offset == 0


def test_raw_copy_keeps_an_encrypted_entry_byte_for_byte(tmp_path: Path) -> None:
    src = tmp_path / "src.zip"
    with pyzipper.AESZipFile(src, "w", encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(b"pw")
        zf.writestr("secret.txt", b"secret")
        zf.writestr("drop.txt", b"drop")
    out = tmp_path / "out.zip"
    with zip_writer.open_archive(out, "w") as zf:
        skipped = zip_writer.copy_entries_raw(
            src, zf, lambda name: name == "drop.txt", lambda: None
        )
        zf.writestr("new.txt", b"new")
    assert skipped == ["drop.txt"]
    with pyzipper.AESZipFile(out) as zf:
        zf.setpassword(b"pw")
        assert zf.namelist() == ["secret.txt", "new.txt"]
        assert zf.read("secret.txt") == b"secret"
        assert zf.testzip() is None


def test_password_and_encryption_can_be_set_aside_for_an_entry(tmp_path: Path) -> None:
    out = tmp_path / "x.zip"
    with zip_writer.open_archive(out, "w", zip_writer.ZipOptions(password="pw")) as zf:
        assert zf.pwd == b"pw" and zf.encryption is not None
        encryption, password = zf.encryption, zf.pwd
        zf.encryption, zf.pwd = None, None
        zf.writestr("folder/", b"")
        zf.encryption, zf.pwd = encryption, password
        zf.writestr("folder/file.txt", b"f")
    with pyzipper.AESZipFile(out) as zf:
        flags = {i.filename: i.flag_bits & 0x1 for i in zf.infolist()}
    assert flags == {"folder/": 0, "folder/file.txt": 1}


def test_an_entrys_compression_level_is_used(tmp_path: Path) -> None:
    assert "_compresslevel" in AESZipInfo.__slots__ or hasattr(
        AESZipInfo("x"), "_compresslevel"
    )
    data = bytes(range(256)) * 400
    sizes = {}
    for level in (1, 9):
        buffer = io.BytesIO()
        with zip_writer.open_archive(buffer, "w") as zf:
            info = zip_writer.new_info("x.bin", (2020, 1, 1, 0, 0, 0))
            info.compress_type = pyzipper.ZIP_DEFLATED
            info._compresslevel = level
            with zf.open(info, "w") as dst:
                dst.write(data)
        with zipfile.ZipFile(buffer) as zf:
            assert zf.read("x.bin") == data
            sizes[level] = zf.getinfo("x.bin").compress_size
    assert sizes[9] <= sizes[1]


def test_the_installed_version_is_within_the_cap() -> None:
    from importlib.metadata import version

    major, minor = (int(part) for part in version("pyzipper").split(".")[:2])
    assert (0, 3) <= (major, minor) < (0, 5)
