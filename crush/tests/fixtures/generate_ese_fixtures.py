# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Generate the synthetic ESE (Extensible Storage Engine) fixtures for Crush tests.

Windows only: the databases are written by the operating system's own ESE engine
(esent.dll) through its documented C API, so the bytes on disk are exactly what
ESE writes -- no sample data from a real system is used. The values put in are
also written to ``<name>.expected.json``: that JSON is the ground truth the
parser is checked against, independent of the parser itself.

Two databases, the same content in each:

Stored gzip-compressed (ESE preallocates the file, mostly zeros):

- ese_alltypes_8k.edb.gz: 8 KiB pages (the "small page" format: page tag flags in
  the tag, 13-bit offsets, 40-byte page header).
- ese_alltypes_32k.edb.gz: 32 KiB pages (the "large page" format of Windows 7 and
  later: flags in the node, 15-bit offsets, 80-byte page header).

Each holds:

- ``AllTypes``: one column of every type ESE has (fixed, variable and tagged),
  NULLs, multi-valued columns (two values and more than two), a long value too
  big to stay in the record (separated into the long-value tree), and compressed
  columns (on current Windows: 7-bit and LZ4).
- ``ManyRows``: 600 rows, enough for a B+-tree with branch pages.

To regenerate (on Windows):

    python crush/tests/fixtures/generate_ese_fixtures.py

Then update ``checksums.json`` with the new files' SHA-256 digests.
"""
from __future__ import annotations

import ctypes
import gzip
import hashlib
import json
import shutil
import struct
import subprocess
import sys
import tempfile
import uuid
from ctypes import POINTER, byref, c_char_p, c_size_t, c_ulong, c_void_p
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

OUT_DIR = Path(__file__).resolve().parent

# esent.h
JET_paramSystemPath = 0
JET_paramTempPath = 1
JET_paramLogFilePath = 2
JET_paramBaseName = 3
JET_paramRecovery = 34
JET_paramDatabasePageSize = 64

JET_coltypBit = 1
JET_coltypUnsignedByte = 2
JET_coltypShort = 3
JET_coltypLong = 4
JET_coltypCurrency = 5
JET_coltypIEEESingle = 6
JET_coltypIEEEDouble = 7
JET_coltypDateTime = 8
JET_coltypBinary = 9
JET_coltypText = 10
JET_coltypLongBinary = 11
JET_coltypLongText = 12
JET_coltypUnsignedLong = 14
JET_coltypLongLong = 15
JET_coltypGUID = 16
JET_coltypUnsignedShort = 17

JET_bitColumnFixed = 0x1
JET_bitColumnTagged = 0x2
JET_bitColumnMultiValued = 0x400
JET_bitColumnCompressed = 0x80000

JET_bitIndexPrimary = 0x2
JET_bitIndexUnique = 0x1
JET_prepInsert = 0

CP_UNICODE = 1200
CP_WESTERN = 1252

JET_API_PTR = c_size_t


class JET_COLUMNDEF(ctypes.Structure):
    _fields_ = [
        ("cbStruct", c_ulong),
        ("columnid", c_ulong),
        ("coltyp", c_ulong),
        ("wCountry", ctypes.c_ushort),
        ("langid", ctypes.c_ushort),
        ("cp", ctypes.c_ushort),
        ("wCollate", ctypes.c_ushort),
        ("cbMax", c_ulong),
        ("grbit", c_ulong),
    ]


class JET_SETINFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", c_ulong),
        ("ibLongValue", c_ulong),
        ("itagSequence", c_ulong),
    ]


def _det_bytes(seed: str, n: int) -> bytes:
    """n deterministic, incompressible bytes."""
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hashlib.sha256(f"{seed}:{i}".encode()).digest()
        i += 1
    return bytes(out[:n])


def _ole_date(dt: datetime) -> float:
    """JET_coltypDateTime: days since 1899-12-30 as an IEEE double."""
    return (dt - datetime(1899, 12, 30)) / timedelta(days=1)


# (name, coltyp, cbMax, grbit, codepage)
ALLTYPES_COLUMNS: list[tuple[str, int, int, int, int]] = [
    ("Id", JET_coltypLong, 0, JET_bitColumnFixed, 0),
    ("BitCol", JET_coltypBit, 0, JET_bitColumnFixed, 0),
    ("ByteCol", JET_coltypUnsignedByte, 0, JET_bitColumnFixed, 0),
    ("ShortCol", JET_coltypShort, 0, JET_bitColumnFixed, 0),
    ("CurrencyCol", JET_coltypCurrency, 0, JET_bitColumnFixed, 0),
    ("SingleCol", JET_coltypIEEESingle, 0, JET_bitColumnFixed, 0),
    ("DoubleCol", JET_coltypIEEEDouble, 0, JET_bitColumnFixed, 0),
    ("DateTimeCol", JET_coltypDateTime, 0, JET_bitColumnFixed, 0),
    ("ULongCol", JET_coltypUnsignedLong, 0, JET_bitColumnFixed, 0),
    ("LongLongCol", JET_coltypLongLong, 0, JET_bitColumnFixed, 0),
    ("GuidCol", JET_coltypGUID, 0, JET_bitColumnFixed, 0),
    ("UShortCol", JET_coltypUnsignedShort, 0, JET_bitColumnFixed, 0),
    ("FixedBinCol", JET_coltypBinary, 6, JET_bitColumnFixed, 0),
    ("BinCol", JET_coltypBinary, 255, 0, 0),
    ("TextUnicodeCol", JET_coltypText, 255, 0, CP_UNICODE),
    ("TextAnsiCol", JET_coltypText, 255, 0, CP_WESTERN),
    ("TaggedLongCol", JET_coltypLong, 0, JET_bitColumnTagged, 0),
    ("LongBinCol", JET_coltypLongBinary, 0, JET_bitColumnTagged, 0),
    ("LongTextCol", JET_coltypLongText, 0, JET_bitColumnTagged, CP_UNICODE),
    (
        "CompressedTextCol", JET_coltypLongText, 0,
        JET_bitColumnTagged | JET_bitColumnCompressed, CP_UNICODE,
    ),
    (
        "CompressedAnsiCol", JET_coltypLongText, 0,
        JET_bitColumnTagged | JET_bitColumnCompressed, CP_WESTERN,
    ),
    (
        "MultiLongCol", JET_coltypLong, 0,
        JET_bitColumnTagged | JET_bitColumnMultiValued, 0,
    ),
    (
        "MultiTextCol", JET_coltypText, 255,
        JET_bitColumnTagged | JET_bitColumnMultiValued, CP_UNICODE,
    ),
]

_SENTENCE = "The quick brown fox jumps over the lazy dog. "


def alltypes_rows() -> list[dict[str, Any]]:
    """The rows put into AllTypes, as Python values (None = not set)."""
    return [
        {
            "Id": 1, "BitCol": True, "ByteCol": 255, "ShortCol": -1234,
            "CurrencyCol": -9_000_000_000_000, "SingleCol": 1.5, "DoubleCol": -2.25,
            "DateTimeCol": datetime(2024, 2, 29, 13, 37, 42),
            "ULongCol": 4_000_000_000, "LongLongCol": -(2**62),
            "GuidCol": uuid.UUID("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"),
            "UShortCol": 65_000, "FixedBinCol": b"\x01\x02\x03\x04\x05\x06",
            "BinCol": b"\xde\xad\xbe\xef", "TextUnicodeCol": "Grüße, 世界",
            "TextAnsiCol": "café", "TaggedLongCol": 42,
            "LongBinCol": _det_bytes("lv", 20_000),
            "LongTextCol": "short tagged text",
            "CompressedTextCol": _SENTENCE * 400,
            "CompressedAnsiCol": "seven bit ascii only " * 10,
            "MultiLongCol": [10, 20, 30], "MultiTextCol": ["alpha", "beta"],
        },
        {
            "Id": 2, "BitCol": False, "ByteCol": 0, "ShortCol": 0,
            "CurrencyCol": 0, "SingleCol": 0.0, "DoubleCol": 0.0,
            "DateTimeCol": datetime(1999, 12, 31, 23, 59, 59),
            "ULongCol": 0, "LongLongCol": 0,
            "GuidCol": uuid.UUID("00000000-0000-0000-0000-000000000001"),
            "UShortCol": 0, "FixedBinCol": b"\x00" * 6,
            "BinCol": b"", "TextUnicodeCol": "", "TextAnsiCol": None,
            "TaggedLongCol": None, "LongBinCol": b"small long binary",
            "LongTextCol": None, "CompressedTextCol": "tiny",
            "CompressedAnsiCol": None,
            "MultiLongCol": [7], "MultiTextCol": ["one", "two", "three"],
        },
        {
            # Only the key set: every other column NULL.
            "Id": 3, "BitCol": None, "ByteCol": None, "ShortCol": None,
            "CurrencyCol": None, "SingleCol": None, "DoubleCol": None,
            "DateTimeCol": None, "ULongCol": None, "LongLongCol": None,
            "GuidCol": None, "UShortCol": None, "FixedBinCol": None,
            "BinCol": None, "TextUnicodeCol": None, "TextAnsiCol": None,
            "TaggedLongCol": None, "LongBinCol": None, "LongTextCol": None,
            "CompressedTextCol": None, "CompressedAnsiCol": None,
            "MultiLongCol": None, "MultiTextCol": None,
        },
    ]


def manyrows_rows() -> list[dict[str, Any]]:
    return [
        {"Id": i, "Name": f"row {i:04d}", "Payload": _det_bytes(f"row{i}", 200)}
        for i in range(1, 601)
    ]


def _encode(coltyp: int, cp: int, value: Any) -> bytes:
    if coltyp == JET_coltypBit:
        return b"\xff" if value else b"\x00"
    if coltyp == JET_coltypUnsignedByte:
        return struct.pack("<B", value)
    if coltyp == JET_coltypShort:
        return struct.pack("<h", value)
    if coltyp == JET_coltypUnsignedShort:
        return struct.pack("<H", value)
    if coltyp == JET_coltypLong:
        return struct.pack("<i", value)
    if coltyp == JET_coltypUnsignedLong:
        return struct.pack("<I", value)
    if coltyp in (JET_coltypCurrency, JET_coltypLongLong):
        return struct.pack("<q", value)
    if coltyp == JET_coltypIEEESingle:
        return struct.pack("<f", value)
    if coltyp == JET_coltypIEEEDouble:
        return struct.pack("<d", value)
    if coltyp == JET_coltypDateTime:
        return struct.pack("<d", _ole_date(value))
    if coltyp == JET_coltypGUID:
        return value.bytes_le
    if coltyp in (JET_coltypText, JET_coltypLongText):
        return value.encode("utf-16-le" if cp == CP_UNICODE else "cp1252")
    return bytes(value)


def _expected(value: Any) -> Any:
    """A value as the expected JSON records it."""
    if isinstance(value, str) and len(value) > 256:
        return {"sha256_utf8": hashlib.sha256(value.encode()).hexdigest(), "length": len(value)}
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, bytes):
        return {"sha256": hashlib.sha256(value).hexdigest(), "size": len(value)}
    if isinstance(value, list):
        return [_expected(v) for v in value]
    raise TypeError(type(value))


class _Jet:
    def __init__(self) -> None:
        self.dll = ctypes.WinDLL("esent.dll")

    def __call__(self, name: str, *args: Any) -> None:
        err = getattr(self.dll, name)(*args)
        if err < 0:
            raise RuntimeError(f"{name} failed: JET error {err}")


def _build(path: Path, page_size: int) -> None:
    """Write one database (runs in its own process: the page size is per process)."""
    jet = _Jet()
    work = path.parent
    inst = JET_API_PTR()
    # Global (process-wide) parameter: set before any instance exists.
    jet("JetSetSystemParameterA", None, JET_API_PTR(0),
        c_ulong(JET_paramDatabasePageSize), JET_API_PTR(page_size), None)
    jet("JetCreateInstanceA", byref(inst), c_char_p(b"crushfixture"))
    for pid, sval in (
        (JET_paramSystemPath, str(work) + "\\"),
        (JET_paramTempPath, str(work) + "\\"),
        (JET_paramLogFilePath, str(work) + "\\"),
        (JET_paramBaseName, "edb"),
        (JET_paramRecovery, "Off"),
    ):
        jet("JetSetSystemParameterA", byref(inst), JET_API_PTR(0), c_ulong(pid),
            JET_API_PTR(0), c_char_p(sval.encode()))
    jet("JetInit", byref(inst))
    ses = JET_API_PTR()
    jet("JetBeginSessionA", inst, byref(ses), None, None)
    dbid = c_ulong()
    jet("JetCreateDatabaseA", ses, c_char_p(str(path).encode()), None, byref(dbid), c_ulong(0))

    def create_table(name: str, cols: list[tuple[str, int, int, int, int]]) -> tuple[
        JET_API_PTR, dict[str, int]
    ]:
        tid = JET_API_PTR()
        jet("JetBeginTransaction", ses)
        jet("JetCreateTableA", ses, dbid, c_char_p(name.encode()), c_ulong(0),
            c_ulong(100), byref(tid))
        ids: dict[str, int] = {}
        for cname, coltyp, cb_max, grbit, cp in cols:
            cd = JET_COLUMNDEF(
                cbStruct=ctypes.sizeof(JET_COLUMNDEF), coltyp=coltyp, cp=cp,
                cbMax=cb_max, grbit=grbit,
            )
            cid = c_ulong()
            jet("JetAddColumnA", ses, tid, c_char_p(cname.encode()), byref(cd), None,
                c_ulong(0), byref(cid))
            ids[cname] = cid.value
        key = b"+Id\x00\x00"
        jet("JetCreateIndexA", ses, tid, c_char_p(b"PrimaryKey"),
            c_ulong(JET_bitIndexPrimary | JET_bitIndexUnique), c_char_p(key),
            c_ulong(len(key)), c_ulong(100))
        jet("JetCommitTransaction", ses, c_ulong(0))
        return tid, ids

    def insert(tid: JET_API_PTR, ids: dict[str, int],
               cols: list[tuple[str, int, int, int, int]], row: dict[str, Any]) -> None:
        jet("JetPrepareUpdate", ses, tid, c_ulong(JET_prepInsert))
        for cname, coltyp, _cb, grbit, cp in cols:
            value = row.get(cname)
            if value is None:
                continue
            values = value if isinstance(value, list) else [value]
            for v in values:
                data = _encode(coltyp, cp, v)
                setinfo = JET_SETINFO(cbStruct=ctypes.sizeof(JET_SETINFO), itagSequence=0)
                buf = ctypes.create_string_buffer(data, len(data) or 1)
                # cbData 0 with JET_bitSetZeroLength (0x20) sets an empty value
                grbit_set = 0x20 if not data else 0
                jet("JetSetColumn", ses, tid, c_ulong(ids[cname]), buf, c_ulong(len(data)),
                    c_ulong(grbit_set), byref(setinfo) if grbit & JET_bitColumnMultiValued
                    else None)
        jet("JetUpdate", ses, tid, None, c_ulong(0), None)

    tid, ids = create_table("AllTypes", ALLTYPES_COLUMNS)
    jet("JetBeginTransaction", ses)
    for row in alltypes_rows():
        insert(tid, ids, ALLTYPES_COLUMNS, row)
    jet("JetCommitTransaction", ses, c_ulong(0))
    jet("JetCloseTable", ses, tid)

    many_cols = [
        ("Id", JET_coltypLong, 0, JET_bitColumnFixed, 0),
        ("Name", JET_coltypText, 64, 0, CP_UNICODE),
        ("Payload", JET_coltypLongBinary, 0, JET_bitColumnTagged, 0),
    ]
    tid, ids = create_table("ManyRows", many_cols)
    jet("JetBeginTransaction", ses)
    for row in manyrows_rows():
        insert(tid, ids, many_cols, row)
    jet("JetCommitTransaction", ses, c_ulong(0))
    jet("JetCloseTable", ses, tid)

    jet("JetCloseDatabase", ses, dbid, c_ulong(0))
    jet("JetDetachDatabaseA", ses, c_char_p(str(path).encode()))
    jet("JetEndSession", ses, c_ulong(0))
    jet("JetTerm", inst)


# Declare argtypes the calls above rely on (pointer-sized handles on x64).
def _main_build(path: str, page_size: int) -> None:
    dll = ctypes.WinDLL("esent.dll")
    dll.JetSetSystemParameterA.argtypes = [
        POINTER(JET_API_PTR), JET_API_PTR, c_ulong, JET_API_PTR, c_char_p,
    ]
    dll.JetSetColumn.argtypes = [
        JET_API_PTR, JET_API_PTR, c_ulong, c_void_p, c_ulong, c_ulong, c_void_p,
    ]
    _build(Path(path), page_size)


def rows_digest_text(rows: list[dict[str, Any]]) -> str:
    """Canonical text of a list of expected rows, for a digest."""
    return json.dumps(rows, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _expected_json() -> dict[str, Any]:
    return {
        "AllTypes": {
            "columns": [c[0] for c in ALLTYPES_COLUMNS],
            "rows": [{k: _expected(v) for k, v in r.items()} for r in alltypes_rows()],
        },
        "ManyRows": {
            "columns": ["Id", "Name", "Payload"],
            "row_count": len(manyrows_rows()),
            # SHA-256 of rows_digest_text() over the rows as this JSON records them.
            "rows_sha256": hashlib.sha256(rows_digest_text(
                [{k: _expected(v) for k, v in r.items()} for r in manyrows_rows()]
            ).encode()).hexdigest(),
        },
    }


def main() -> None:
    if len(sys.argv) == 4 and sys.argv[1] == "--build":
        _main_build(sys.argv[2], int(sys.argv[3]))
        return
    if sys.platform != "win32":
        sys.exit("needs Windows (esent.dll)")
    for page_size, name in ((8192, "ese_alltypes_8k.edb"), (32768, "ese_alltypes_32k.edb")):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / name
            # The page size is fixed for the process once ESE is initialised.
            subprocess.run(
                [sys.executable, __file__, "--build", str(db), str(page_size)], check=True,
            )
            # Fixed mtime and no file name in the gzip header: same input, same bytes.
            with open(db, "rb") as src, open(OUT_DIR / f"{name}.gz", "wb") as raw,                     gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as dst:
                shutil.copyfileobj(src, dst)
        print(f"wrote {name}.gz")
    expected = OUT_DIR / "ese_alltypes.expected.json"
    expected.write_text(json.dumps(_expected_json(), indent=1, ensure_ascii=False) + "\n",
                        encoding="utf-8")
    print(f"wrote {expected.name}")


if __name__ == "__main__":
    main()
