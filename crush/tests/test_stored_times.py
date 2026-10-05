# SPDX-License-Identifier: Apache-2.0
"""Timestamps as a source stores them (issue #139).

A ZIP's DOS date/time and a FAT/exFAT directory entry hold a wall-clock
reading with no time zone: shown as stored, never converted, so the value
never depends on the machine Crush runs on. ZIP extra fields hold instants
(UTC), each shown with the field it comes from. A folder with no record of
its own has no time.
"""
from __future__ import annotations

import gzip
import io
import struct
import tarfile
import time
import zipfile
from pathlib import Path

import pytest
from PySide6.QtWidgets import QLabel

from crush.core.stored_times import (
    ACCESSED,
    BIRTH,
    MODIFIED,
    StoredTime,
    dos_words,
    zip_extra_times,
)
from crush.core.vfs import SevenZipVFS, TarVFS, VFSNode, ZipVFS, open_vfs
from crush.tests.conftest import FIXTURES_DIR

_NOON = (2024, 5, 1, 12, 0, 0)
_MT, _AT, _CT = 1_714_564_800, 1_714_568_400, 1_714_478_400  # 2024-05-01 12:00 UTC etc.


def _filetime(unix: int) -> int:
    return (unix + 11_644_473_600) * 10_000_000


def _ut_local(flags: int, *times: int) -> bytes:
    return struct.pack(f"<HHB{len(times)}i", 0x5455, 1 + 4 * len(times), flags, *times)


def _ntfs(m: int, a: int, c: int) -> bytes:
    return struct.pack("<HHIHH3Q", 0x000A, 32, 0, 1, 24, _filetime(m), _filetime(a), _filetime(c))


def _child(node: VFSNode, name: str) -> VFSNode:
    return next(c for c in node.children if c.name == name)


def _zip(path: Path, members: list[tuple[zipfile.ZipInfo, bytes]]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for info, data in members:
            zf.writestr(info, data)
    return path


def _info(name: str, date_time: tuple[int, ...] = _NOON, extra: bytes = b"") -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=date_time)  # type: ignore[arg-type]
    info.extra = extra
    return info


def _times(times: list[StoredTime] | object, kind: str) -> list[StoredTime]:
    assert isinstance(times, list)
    return [t for t in times if t.kind == kind]


class TestDosDateTime:
    @pytest.mark.forensic(
        category="Completeness",
        subject="ZIP archive",
        desc="A ZIP member with an invalid DOS date must not stop the archive from opening; "
             "the member shows its stored date as not valid, the others keep theirs",
    )
    def test_invalid_date_keeps_archive_open(self, tmp_path: Path) -> None:
        path = _zip(tmp_path / "zero-date.zip", [
            (_info("a.txt", (1980, 0, 0, 0, 0, 0)), b"a"),
            (_info("b.txt"), b"b"),
        ])
        vfs = open_vfs(path)
        assert isinstance(vfs, ZipVFS)
        assert not vfs.fallback_note
        a = _child(vfs.root(), "a.txt")
        (dos,) = a.stored_times
        assert dos.reading == "1980-00-00 00:00:00"
        assert dos.note is not None and dos.note.code == "time.dos_invalid"
        assert dos.note.params == {"date": "0x0000", "time": "0x0000"}
        assert vfs.read(a) == b"a"
        (b_dos,) = _child(vfs.root(), "b.txt").stored_times
        assert b_dos.reading == "2024-05-01 12:00:00" and b_dos.note is None

    def test_calendar_check_not_just_field_ranges(self, tmp_path: Path) -> None:
        """February 30 fits the DOS bit fields but is no date."""
        vfs = open_vfs(_zip(tmp_path / "feb30.zip", [(_info("x", (2023, 2, 30, 10, 0, 0)), b"")]))
        (dos,) = _child(vfs.root(), "x").stored_times
        assert dos.reading == "2023-02-30 10:00:00"
        assert dos.note is not None and dos.note.code == "time.dos_invalid"

    def test_stored_words_round_trip(self) -> None:
        assert dos_words((2024, 5, 1, 12, 0, 0)) == ((44 << 9) | (5 << 5) | 1, 12 << 11)

    @pytest.mark.forensic(
        category="Known-output Verification",
        subject="ZIP archive",
        desc="The pyaff4 container (every member stored with month 0) opens as a ZIP",
    )
    def test_real_pyaff4_container_opens_as_zip(self) -> None:
        vfs = open_vfs(FIXTURES_DIR / "acquisition" / "pyaff4-zlib.aff4")
        assert isinstance(vfs, ZipVFS)
        notes = [
            t.note.code for n in _walk(vfs.root()) for t in n.stored_times if t.note is not None
        ]
        assert notes and set(notes) == {"time.dos_invalid"}

    @pytest.mark.forensic(
        category="Reproducibility",
        subject="ZIP archive",
        desc="A ZIP DOS time is shown the same on every analysis machine, whatever its time zone",
    )
    @pytest.mark.skipif(not hasattr(time, "tzset"), reason="time.tzset is Unix-only")
    @pytest.mark.parametrize("tz", ["UTC", "Europe/Berlin", "America/New_York", "Pacific/Kiritimati"])
    def test_independent_of_analysis_time_zone(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tz: str
    ) -> None:
        path = _zip(tmp_path / "noon.zip", [(_info("noon.txt"), b"x")])
        monkeypatch.setenv("TZ", tz)
        time.tzset()
        try:
            node = _child(open_vfs(path).root(), "noon.txt")
        finally:
            monkeypatch.undo()
            time.tzset()
        assert node.modified == 0.0  # no instant: a DOS time has no zone
        assert [t.reading for t in node.stored_times] == ["2024-05-01 12:00:00"]


def _walk(node: VFSNode) -> list[VFSNode]:
    out = [node]
    for c in node.children:
        out.extend(_walk(c))
    return out


class TestZipExtraFields:
    def test_central_ut_holds_modified_only(self) -> None:
        """Central UT: the flags announce the local header's times; only the
        modification time follows."""
        central = struct.pack("<HHBi", 0x5455, 5, 0b111, _MT)
        (t,) = zip_extra_times(central, local=False)
        assert (t.kind, t.utc) == (MODIFIED, float(_MT))
        assert t.source.params["id"] == "0x5455"

    def test_central_ut_without_time(self) -> None:
        assert zip_extra_times(struct.pack("<HHB", 0x5455, 1, 0b001), local=False) == []

    def test_local_ut_in_flag_order(self) -> None:
        times = zip_extra_times(_ut_local(0b101, _MT, _CT), local=True)
        assert [(t.kind, t.utc) for t in times] == [(MODIFIED, float(_MT)), (BIRTH, float(_CT))]

    def test_ut_is_signed(self) -> None:
        (t,) = zip_extra_times(_ut_local(0b001, -1), local=True)
        assert t.utc == -1.0

    def test_ntfs(self) -> None:
        times = zip_extra_times(_ntfs(_MT, _AT, _CT), local=False)
        assert [(t.kind, t.utc) for t in times] == [
            (MODIFIED, float(_MT)), (ACCESSED, float(_AT)), (BIRTH, float(_CT)),
        ]

    @pytest.mark.parametrize("field_id", [0x5855, 0x000D])
    def test_unix_fields_access_then_modified(self, field_id: int) -> None:
        data = struct.pack("<HHiiHH", field_id, 12, _AT, _MT, 501, 20)
        times = zip_extra_times(data, local=True)
        assert [(t.kind, t.utc) for t in times] == [(MODIFIED, float(_MT)), (ACCESSED, float(_AT))]
        assert times[0].source.params["id"] == f"0x{field_id:04X}"

    def test_too_short_field_is_said(self) -> None:
        (t,) = zip_extra_times(struct.pack("<HHi", 0x5855, 4, _AT), local=True)
        assert t.utc is None and not t.reading
        assert t.note is not None and t.note.code == "time.zip_extra_short"

    def test_fields_without_times_are_skipped(self) -> None:
        uid_gid = struct.pack("<HHBBIBI", 0x7875, 11, 1, 4, 501, 4, 20)
        assert zip_extra_times(uid_gid + _ut_local(0b001, _MT), local=True)[0].utc == _MT

    def test_member_shows_every_source(self, tmp_path: Path) -> None:
        path = _zip(tmp_path / "x.zip", [
            (_info("a.txt", extra=_ut_local(0b111, _MT, _AT, _CT) + _ntfs(_MT + 1, _AT, _CT)), b"a"),
        ])
        vfs = open_vfs(path)
        node = _child(vfs.root(), "a.txt")
        assert node.modified == float(_MT)  # the first stored instant
        mods = _times(node.stored_times, MODIFIED)
        assert [(t.source.code, t.utc, t.reading) for t in mods] == [
            ("time.zip_dos_central", None, "2024-05-01 12:00:00"),
            ("time.zip_extra_central", float(_MT), ""),
            ("time.zip_extra_central", float(_MT + 1), ""),
        ]

    def test_local_header_adds_what_central_lacks(self, tmp_path: Path) -> None:
        """Info-ZIP keeps access and creation time only in the local
        header: read when asked, added once; a time the central record
        already has is not repeated."""
        local_ut = _ut_local(0b111, _MT, _AT, _CT)
        path = _zip(tmp_path / "x.zip", [(_info("a.txt", extra=local_ut), b"a")])
        # Give the central record the central UT layout (modified time only).
        data = path.read_bytes()
        cd = data.index(b"PK\x01\x02")
        data = data[:cd] + data[cd:].replace(local_ut, struct.pack("<HHBi", 0x5455, 5, 0b111, _MT)
                                             + struct.pack("<HH", 0xCAFE, 4) + b"\0" * 4)
        path.write_bytes(data)

        vfs = open_vfs(path)
        node = _child(vfs.root(), "a.txt")
        assert [t.kind for t in node.stored_times] == [MODIFIED, MODIFIED]
        times = vfs.stored_times(node)
        assert isinstance(times, list)
        assert [(t.kind, t.source.code) for t in times] == [
            (MODIFIED, "time.zip_dos_central"),
            (MODIFIED, "time.zip_extra_central"),
            (ACCESSED, "time.zip_extra_local"),
            (BIRTH, "time.zip_extra_local"),
        ]

    def test_differing_local_dos_time_is_shown(self, tmp_path: Path) -> None:
        path = _zip(tmp_path / "x.zip", [(_info("a.txt"), b"a")])
        data = bytearray(path.read_bytes())
        struct.pack_into("<H", data, 10, 13 << 11)  # local header: 13:00:00
        path.write_bytes(bytes(data))
        vfs = open_vfs(path)
        times = vfs.stored_times(_child(vfs.root(), "a.txt"))
        assert isinstance(times, list)
        assert [(t.source.code, t.reading) for t in times] == [
            ("time.zip_dos_central", "2024-05-01 12:00:00"),
            ("time.zip_dos_local", "2024-05-01 13:00:00"),
        ]

    def test_missing_local_header_is_said(self, tmp_path: Path) -> None:
        path = _zip(tmp_path / "x.zip", [(_info("a.txt"), b"a")])
        vfs = open_vfs(path)
        node = _child(vfs.root(), "a.txt")
        # Rewrite after opening: the central directory still points here.
        data = bytearray(path.read_bytes())
        data[0:4] = b"XXXX"
        path.write_bytes(bytes(data))
        times = vfs.stored_times(node)
        assert not isinstance(times, list)
        assert times.code == "time.zip_local_missing"
        assert node.stored_times  # the central record's times stay


class TestFolderTimes:
    """A folder with no record of its own has no time; its own record gives
    it one, even when it comes after a member inside it."""

    def test_zip(self, tmp_path: Path) -> None:
        path = _zip(tmp_path / "x.zip", [
            (_info("implied/a.txt"), b"a"),
            (_info("late/b.txt"), b"b"),
            (_info("late/", (2023, 1, 2, 3, 4, 6)), b""),
        ])
        root = open_vfs(path).root()
        assert _child(root, "implied").stored_times == []
        late = _child(root, "late")
        assert [t.reading for t in late.stored_times] == ["2023-01-02 03:04:06"]

    def _tar(self, path: Path) -> Path:
        with tarfile.open(path, "w") as tf:
            for name, mtime, is_dir in (("implied/a.txt", 1000, False), ("late/b.txt", 2000, False),
                                        ("late", 3000, True)):
                ti = tarfile.TarInfo(name)
                ti.mtime = mtime
                if is_dir:
                    ti.type = tarfile.DIRTYPE
                tf.addfile(ti, None if is_dir else io.BytesIO(b""))
        return path

    def test_tar(self, tmp_path: Path) -> None:
        vfs = open_vfs(self._tar(tmp_path / "x.tar"))
        assert isinstance(vfs, TarVFS)
        root = vfs.root()
        assert _child(root, "implied").modified == 0.0
        assert _child(root, "late").modified == 3000.0
        assert _child(_child(root, "implied"), "a.txt").modified == 1000.0

    def test_sevenzip(self, tmp_path: Path) -> None:
        import py7zr

        path = tmp_path / "x.7z"
        with py7zr.SevenZipFile(path, "w") as zf:
            zf.writestr(b"a", "implied/a.txt")
        vfs = open_vfs(path)
        assert isinstance(vfs, SevenZipVFS)
        root = vfs.root()
        assert _child(root, "implied").modified == 0.0
        assert _child(_child(root, "implied"), "a.txt").modified != 0.0

    def test_sevenzip_entry_without_time_stays_without(self, tmp_path: Path) -> None:
        """py7zr's list() hands an entry with no stored time the previous
        entry's time."""
        import py7zr

        path = tmp_path / "x.7z"
        with py7zr.SevenZipFile(path, "w") as zf:
            zf.writestr(b"one", "first.txt")
            zf.writestr(b"two", "second.txt")
            for f in zf.files:
                if f.filename == "second.txt":
                    f._file_info.pop("lastwritetime", None)
        root = open_vfs(path).root()
        assert _child(root, "first.txt").modified != 0.0
        assert _child(root, "second.txt").modified == 0.0


class TestFatReadings:
    @pytest.mark.forensic(
        category="Known-output Verification",
        subject="FAT32",
        desc="FAT32 entries show their stored date/time as stored, with no time zone",
    )
    def test_fat32(self, tmp_path: Path) -> None:
        node = self._live(tmp_path, "raw_fat32_deleted.img.gz", "a.bin")
        assert node.modified == 0.0
        assert [(t.kind, t.reading, t.note) for t in node.stored_times] == [
            (MODIFIED, "2026-09-11 01:01:24", None),
            (ACCESSED, "2026-09-11", None),  # FAT stores the access date only
            (BIRTH, "2026-09-11 01:01:24.94", None),
        ]
        assert {t.source.code for t in node.stored_times} == {"time.fat_entry"}

    @pytest.mark.forensic(
        category="Known-output Verification",
        subject="exFAT",
        desc="exFAT entries show their stored date/time as stored, with the stored UTC offset "
             "shown and not applied",
    )
    def test_exfat_offset_shown_not_applied(self, tmp_path: Path) -> None:
        node = self._live(tmp_path, "raw_exfat_deleted.img.gz", "a.bin")
        assert node.modified == 0.0
        assert [(t.kind, t.reading) for t in node.stored_times] == [
            (MODIFIED, "2026-09-11 09:01:29.36"),
            (ACCESSED, "2026-09-11 09:01:28"),
            (BIRTH, "2026-09-11 09:01:29.36"),
        ]
        for t in node.stored_times:
            assert t.source.code == "time.exfat_entry"
            assert t.note is not None and t.note.code == "time.offset_not_applied"
            assert t.note.params == {"offset": "+04:00"}

    @staticmethod
    def _live(tmp_path: Path, fixture: str, name: str) -> VFSNode:
        dst = tmp_path / fixture[:-3]
        dst.write_bytes(gzip.decompress((FIXTURES_DIR / fixture).read_bytes()))
        vfs = open_vfs(dst, as_disk_image=True)
        try:
            return _child(vfs.root().children[0], name)
        finally:
            vfs.close()


class TestDisplay:
    def _rows(self, panel) -> list[tuple[str, str]]:
        from PySide6.QtWidgets import QFormLayout

        rows = []
        for i in range(panel._layout.rowCount()):
            label = panel._layout.itemAt(i, QFormLayout.ItemRole.LabelRole)
            field = panel._layout.itemAt(i, QFormLayout.ItemRole.FieldRole)
            if label is not None and field is not None and isinstance(field.widget(), QLabel):
                rows.append((label.widget().text(), field.widget().text()))
        return rows

    def test_properties_show_reading_and_source(self, qapp, tmp_path: Path) -> None:
        from crush.ui.props_panel import PropertiesPanel

        path = _zip(tmp_path / "x.zip", [
            (_info("a.txt", (1980, 0, 0, 0, 0, 0), extra=_ut_local(0b001, _MT)), b"a"),
        ])
        vfs = open_vfs(path)
        panel = PropertiesPanel()
        panel.update_properties(_child(vfs.root(), "a.txt"), {}, vfs)
        rows = self._rows(panel)
        assert (
            "Modified (as stored, no time zone):",
            "1980-00-00 00:00:00 — ZIP DOS date/time (central directory); "
            "not a valid date/time; stored words: date 0x0000, time 0x0000",
        ) in rows
        assert (
            "Modified (UTC):",
            "2024-05-01 12:00:00 UTC — ZIP extra field Info-ZIP extended timestamp "
            "(0x5455, central directory)",
        ) in rows
        assert ("Accessed:", "—") in rows

    def test_search_column_marks_reading(self, qapp, tmp_path: Path) -> None:
        from crush.ui.search_panel import SearchPanel

        vfs = open_vfs(_zip(tmp_path / "x.zip", [(_info("a.txt"), b"a")]))
        panel = SearchPanel()
        panel._vfs = vfs
        panel._populate([_child(vfs.root(), "a.txt")])
        assert panel._model.item(0, 4).text() == "2024-05-01 12:00:00 (as stored, no time zone)"
