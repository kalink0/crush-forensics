# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Timestamps as a source stores them -- no Qt dependency.

A VFSNode's modified/accessed/changed/birth floats hold instants (Unix
seconds, UTC). Not every source stores an instant: a ZIP's DOS date/time
and a FAT/exFAT directory entry hold a wall-clock reading with no time
zone, and a ZIP member may carry several timestamps from different extra
fields at once. StoredTime keeps each of them as stored, with where it
came from, so nothing has to pick one or put a zone on a reading.

ZIP layouts are decoded from PKWARE APPNOTE 6.3.10 (4.4.6, 4.5.5, 4.5.7)
and Info-ZIP's extrafld.txt (0x5455, 0x5855).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime
from typing import IO

from crush.core.issues import ParseIssue

MODIFIED, ACCESSED, CHANGED, BIRTH = "modified", "accessed", "changed", "birth"
KINDS = (MODIFIED, ACCESSED, CHANGED, BIRTH)

_WIN_EPOCH_OFFSET = 11_644_473_600  # seconds from 1601-01-01 to 1970-01-01


@dataclass(frozen=True)
class StoredTime:
    """One timestamp of an entry, as its source stores it.

    One of *utc* (an instant: Unix seconds, UTC) and *reading* (a
    wall-clock reading as text, with no time zone) is set -- neither only
    when the field holding it is too short, and *note* says so. *source*
    says where it is stored; *note* what else the analyst must know about
    it (not a valid date, a UTC offset stored beside it ...).
    """

    kind: str
    source: ParseIssue
    utc: float | None = None
    reading: str = ""
    note: ParseIssue | None = None


def filetime_to_unix(ft: int) -> float:
    """A Windows FILETIME (100 ns units since 1601-01-01, UTC) as Unix seconds."""
    return ft / 10_000_000 - _WIN_EPOCH_OFFSET


def first_instant(times: list[StoredTime], kind: str = MODIFIED) -> float:
    """The first instant of *kind* in *times*, in stored order, or 0.0 (the
    VFSNode value for "none")."""
    for t in times:
        if t.kind == kind and t.utc is not None:
            return t.utc
    return 0.0


# -- ZIP: DOS date/time (APPNOTE 4.4.6) ------------------------------------

def dos_words(date_time: tuple[int, int, int, int, int, int]) -> tuple[int, int]:
    """The stored 16-bit (date, time) words behind zipfile's date_time tuple
    (its fields are plain bit slices of the two words, so this is exact)."""
    year, month, day, hour, minute, second = date_time
    date = ((year - 1980) << 9) | (month << 5) | day
    time_ = (hour << 11) | (minute << 5) | (second // 2)
    return date, time_


def dos_stored_time(
    date_time: tuple[int, int, int, int, int, int], source: ParseIssue
) -> StoredTime:
    """A ZIP member's DOS date/time: a reading with no time zone.

    Shown as stored, never converted. A value that is not a calendar date
    or time of day (month 0, February 30, hour 24 ...) still shows its
    fields and stored words, with a note saying so.
    """
    year, month, day, hour, minute, second = date_time
    reading = f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}"
    try:
        datetime(year, month, day, hour, minute, second)
    except ValueError:
        date, time_ = dos_words(date_time)
        note = ParseIssue("time.dos_invalid", {"date": f"0x{date:04X}", "time": f"0x{time_:04X}"})
        return StoredTime(MODIFIED, source, reading=reading, note=note)
    return StoredTime(MODIFIED, source, reading=reading)


# -- ZIP: extra fields ---------------------------------------------------------

EXTRA_UT = 0x5455     # Info-ZIP extended timestamp
EXTRA_UX = 0x5855     # Info-ZIP Unix, type 1 (obsolete, still written)
EXTRA_NTFS = 0x000A   # PKWARE NTFS
EXTRA_UNIX = 0x000D   # PKWARE Unix

_FIELD_NAMES = {
    EXTRA_UT: "Info-ZIP extended timestamp",
    EXTRA_UX: "Info-ZIP Unix (type 1)",
    EXTRA_NTFS: "NTFS",
    EXTRA_UNIX: "PKWARE Unix",
}


def _source(field_id: int, local: bool) -> ParseIssue:
    code = "time.zip_extra_local" if local else "time.zip_extra_central"
    return ParseIssue(code, {"name": _FIELD_NAMES[field_id], "id": f"0x{field_id:04X}"})


def _malformed(field_id: int, local: bool, size: int) -> StoredTime:
    """A time-bearing field too short for its own layout: said, not dropped."""
    return StoredTime(
        MODIFIED, _source(field_id, local),
        note=ParseIssue("time.zip_extra_short", {"size": size}),
    )


def _unix_times(data: bytes, field_id: int, local: bool) -> list[StoredTime]:
    """0x5855 and 0x000d: AcTime, ModTime (signed 32-bit, UTC), then
    fields with no time in them."""
    if len(data) < 8:
        return [_malformed(field_id, local, len(data))]
    atime, mtime = struct.unpack_from("<ii", data, 0)
    src = _source(field_id, local)
    return [
        StoredTime(MODIFIED, src, utc=float(mtime)),
        StoredTime(ACCESSED, src, utc=float(atime)),
    ]


def _ut_times(data: bytes, local: bool) -> list[StoredTime]:
    """0x5455: a flags byte, then the times its low three bits announce, in
    the order modified, accessed, created (signed 32-bit, UTC).

    The flags describe the LOCAL header; the central header holds the
    modification time only, or no time at all.
    """
    if not data:
        return [_malformed(EXTRA_UT, local, 0)]
    flags = data[0]
    src = _source(EXTRA_UT, local)
    if not local:
        # TSize says whether the modification time follows.
        if len(data) < 5:
            return []
        (value,) = struct.unpack_from("<i", data, 1)
        return [StoredTime(MODIFIED, src, utc=float(value))]
    out: list[StoredTime] = []
    pos = 1
    for bit, kind in ((0, MODIFIED), (1, ACCESSED), (2, BIRTH)):
        if not flags & (1 << bit):
            continue
        if pos + 4 > len(data):
            out.append(StoredTime(kind, src, note=ParseIssue("time.zip_extra_short",
                                                             {"size": len(data)})))
            break
        (value,) = struct.unpack_from("<i", data, pos)
        out.append(StoredTime(kind, src, utc=float(value)))
        pos += 4
    return out


def _ntfs_times(data: bytes, local: bool) -> list[StoredTime]:
    """0x000a: 4 reserved bytes, then tagged attributes; tag 1 holds Mtime,
    Atime, Ctime (creation) as FILETIME, UTC."""
    src = _source(EXTRA_NTFS, local)
    out: list[StoredTime] = []
    pos = 4
    while pos + 4 <= len(data):
        tag, size = struct.unpack_from("<HH", data, pos)
        pos += 4
        body = data[pos:pos + size]
        pos += size
        if tag != 0x0001:
            continue
        if len(body) < 24:
            out.append(StoredTime(MODIFIED, src, note=ParseIssue("time.zip_extra_short",
                                                                 {"size": len(body)})))
            continue
        for kind, ft in zip((MODIFIED, ACCESSED, BIRTH), struct.unpack_from("<QQQ", body, 0)):
            out.append(StoredTime(kind, src, utc=filetime_to_unix(ft)))
    return out


def zip_extra_times(extra: bytes, *, local: bool) -> list[StoredTime]:
    """Every timestamp in a ZIP extra-field block, in stored order.

    Fields without times are skipped; a block that runs past the end of
    *extra* ends the walk (the rest is not a field).
    """
    out: list[StoredTime] = []
    pos = 0
    while pos + 4 <= len(extra):
        field_id, size = struct.unpack_from("<HH", extra, pos)
        data = extra[pos + 4:pos + 4 + size]
        pos += 4 + size
        if len(data) < size:
            break
        if field_id == EXTRA_UT:
            out.extend(_ut_times(data, local))
        elif field_id in (EXTRA_UX, EXTRA_UNIX):
            out.extend(_unix_times(data, field_id, local))
        elif field_id == EXTRA_NTFS:
            out.extend(_ntfs_times(data, local))
    return out


def zip_central_times(
    date_time: tuple[int, int, int, int, int, int], extra: bytes
) -> list[StoredTime]:
    """A member's times from its central directory record."""
    dos = dos_stored_time(date_time, ParseIssue("time.zip_dos_central"))
    return [dos, *zip_extra_times(extra, local=False)]


_LOCAL_HEADER = struct.Struct("<4s5H3I2H")
_LOCAL_SIGNATURE = b"PK\x03\x04"


def zip_local_times(f: IO[bytes], header_offset: int) -> list[StoredTime] | ParseIssue:
    """A member's times from its local file header (APPNOTE 4.3.7), or why
    it couldn't be read."""
    f.seek(header_offset)
    head = f.read(_LOCAL_HEADER.size)
    if len(head) < _LOCAL_HEADER.size or head[:4] != _LOCAL_SIGNATURE:
        return ParseIssue("time.zip_local_missing", {"offset": f"{header_offset:,}"})
    fields = _LOCAL_HEADER.unpack(head)
    time_, date = fields[4], fields[5]
    name_len, extra_len = fields[9], fields[10]
    f.seek(header_offset + _LOCAL_HEADER.size + name_len)
    extra = f.read(extra_len)
    date_time = (
        1980 + (date >> 9), (date >> 5) & 0x0F, date & 0x1F,
        time_ >> 11, (time_ >> 5) & 0x3F, (time_ & 0x1F) * 2,
    )
    dos = dos_stored_time(date_time, ParseIssue("time.zip_dos_local"))
    return [dos, *zip_extra_times(extra, local=True)]


def merge_local(central: list[StoredTime], local: list[StoredTime]) -> list[StoredTime]:
    """Central times, plus each local time that says something the central
    record doesn't (a time it lacks, or a different value for one it has)."""
    def key(t: StoredTime) -> tuple[str, str, float | None, str]:
        name = str(t.source.params.get("id", "dos"))
        return t.kind, name, t.utc, t.reading

    seen = {key(t) for t in central}
    return [*central, *(t for t in local if key(t) not in seen)]


# -- FAT / exFAT directory entries (readings from qnxprobe) ---------------------

def fat_stored_times(recorded: dict[str, str], *, exfat: bool) -> list[StoredTime]:
    """The readings qnxprobe's listdir_records() returns for one entry.

    FAT and exFAT store a wall-clock reading and no zone. exFAT also stores
    a UTC offset beside each stamp; it is shown and not applied (as
    qnxprobe does). FAT's last-access field is a date with no time.
    """
    src = ParseIssue("time.exfat_entry" if exfat else "time.fat_entry")
    out: list[StoredTime] = []
    for key, kind in (("modified", MODIFIED), ("accessed", ACCESSED),
                      ("accessed date", ACCESSED), ("created", BIRTH)):
        reading = recorded.get(key, "")
        if not reading:
            continue
        offset = recorded.get(f"{key} utc offset", "")
        note = ParseIssue("time.offset_not_applied", {"offset": offset}) if offset else None
        out.append(StoredTime(kind, src, reading=reading, note=note))
    return out
