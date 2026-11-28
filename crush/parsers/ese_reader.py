# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Reader for ESE (Extensible Storage Engine, "JET Blue") database files:
SRUDB.dat, Windows.edb, WebCacheV01.dat, ntds.dit, Exchange .edb, ...

Pure Python, read-only, no Qt: reads pages from a seekable stream on
demand, so a multi-GB database is never loaded into memory at once.

Structure is decoded from what the format declares, never guessed:

- The file header, page header and page-tag layout, node flags, record
  layout (fixed / variable / tagged columns), tagged-column header bits,
  multi-values, long-value keys and long-value roots follow Microsoft's
  open-source ESE engine (github.com/microsoft/Extensible-Storage-Engine,
  MIT licence: cpage.hxx, node.hxx, rec.hxx, tagfld.hxx, lv.hxx,
  compression.cxx) and the libyal/libesedb format documentation.
- Column types, codepages and fixed-column record offsets come from the
  database's own catalog (MSysObjects, B+-tree rooted at page 4).
- Compression is identified by the scheme stored in the value's first
  byte (bits 3-7); a long-value chunk is compressed when it is shorter than
  its place in the value says it must be (ESE's own FLVCompressedChunk rule).

What is not decoded is reported as a ParseIssue and the raw bytes are kept,
never silently dropped. Not covered: transaction logs (.log) of a dirty
database, page checksums, encrypted values, the Xpress9/Xpress10
compression schemes (Exchange), and the pre-Windows-XP-SP3 tagged-column
format (format revision < 9).
"""
from __future__ import annotations

import struct
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import IO, Any

from crush.core.issues import ParseIssue
from crush.core.block_compression import (
    BlockCompressionError,
    lz4_block_decompress,
    lz77_decompress,
)

ESE_SIGNATURE = b"\xef\xcd\xab\x89"

# File header
_STATE_NAMES = {
    1: "Just created",
    2: "Dirty shutdown",
    3: "Clean shutdown",
    4: "Being converted",
    5: "Force detach",
}

# Page flags (cpage.hxx)
PAGE_ROOT = 0x0001
PAGE_LEAF = 0x0002
PAGE_PARENT = 0x0004
PAGE_EMPTY = 0x0008
PAGE_SPACE_TREE = 0x0020
PAGE_INDEX = 0x0040
PAGE_LONG_VALUE = 0x0080
PAGE_NEW_RECORD_FORMAT = 0x2000

# Node flags (node.hxx)
NODE_VERSION = 0x01
NODE_DELETED = 0x02
NODE_PREFIX_COMPRESSED = 0x04

# Root page of the catalog (MSysObjects), fixed by ESE.
CATALOG_FDP_PAGE = 4

# Catalog record types
CAT_TABLE = 1
CAT_COLUMN = 2
CAT_INDEX = 3
CAT_LONG_VALUE = 4
CAT_CALLBACK = 5

# Column types (JET_coltyp*)
COLTYP_BIT = 1
COLTYP_UNSIGNED_BYTE = 2
COLTYP_SHORT = 3
COLTYP_LONG = 4
COLTYP_CURRENCY = 5
COLTYP_IEEE_SINGLE = 6
COLTYP_IEEE_DOUBLE = 7
COLTYP_DATETIME = 8
COLTYP_BINARY = 9
COLTYP_TEXT = 10
COLTYP_LONG_BINARY = 11
COLTYP_LONG_TEXT = 12
COLTYP_SLV = 13
COLTYP_UNSIGNED_LONG = 14
COLTYP_LONG_LONG = 15
COLTYP_GUID = 16
COLTYP_UNSIGNED_SHORT = 17

COLTYP_NAMES = {
    0: "Nil",
    COLTYP_BIT: "Bit",
    COLTYP_UNSIGNED_BYTE: "UnsignedByte",
    COLTYP_SHORT: "Short",
    COLTYP_LONG: "Long",
    COLTYP_CURRENCY: "Currency",
    COLTYP_IEEE_SINGLE: "IEEESingle",
    COLTYP_IEEE_DOUBLE: "IEEEDouble",
    COLTYP_DATETIME: "DateTime",
    COLTYP_BINARY: "Binary",
    COLTYP_TEXT: "Text",
    COLTYP_LONG_BINARY: "LongBinary",
    COLTYP_LONG_TEXT: "LongText",
    COLTYP_SLV: "SLV",
    COLTYP_UNSIGNED_LONG: "UnsignedLong",
    COLTYP_LONG_LONG: "LongLong",
    COLTYP_GUID: "GUID",
    COLTYP_UNSIGNED_SHORT: "UnsignedShort",
}

# Fixed sizes of the numeric column types; Binary/Text fixed columns take
# their size from the catalog.
_FIXED_SIZE = {
    COLTYP_BIT: 1,
    COLTYP_UNSIGNED_BYTE: 1,
    COLTYP_SHORT: 2,
    COLTYP_LONG: 4,
    COLTYP_CURRENCY: 8,
    COLTYP_IEEE_SINGLE: 4,
    COLTYP_IEEE_DOUBLE: 8,
    COLTYP_DATETIME: 8,
    COLTYP_UNSIGNED_LONG: 4,
    COLTYP_LONG_LONG: 8,
    COLTYP_GUID: 16,
    COLTYP_UNSIGNED_SHORT: 2,
}

_TEXT_TYPES = (COLTYP_TEXT, COLTYP_LONG_TEXT)

# Codepages ESE declares for text columns.
_CODEPAGES = {1200: "utf-16-le", 1252: "cp1252", 20127: "ascii", 65001: "utf-8"}

# Tagged column header byte (tagfld.hxx TAGFLD_HEADER)
TAG_LONG_VALUE = 0x01
TAG_COMPRESSED = 0x02
TAG_SEPARATED = 0x04
TAG_MULTI_VALUES = 0x08
TAG_TWO_VALUES = 0x10
TAG_NULL = 0x20
TAG_ENCRYPTED = 0x40

# Compression schemes (compression.cxx), stored in bits 3-7 of the first byte.
COMPRESS_7BIT_ASCII = 1
COMPRESS_7BIT_UNICODE = 2
COMPRESS_XPRESS = 3
COMPRESS_SCRUB = 4
COMPRESS_LZ4 = 7
_COMPRESSION_NAMES = {5: "Xpress9", 6: "Xpress10"}

# Column flags as the catalog stores them: ESE's persisted FIELDFLAG values
# (tdb.hxx ffield*), not the JET_bitColumn* API bits.
FIELD_MULTI_VALUED = 0x0008
FIELD_DEFAULT = 0x0010
FIELD_COMPRESSED = 0x1000
FIELD_ENCRYPTED = 0x2000

_OLE_EPOCH = datetime(1899, 12, 30)


class EseError(ValueError):
    """The file is not an ESE database Crush can read."""

    def __init__(self, issue: ParseIssue) -> None:
        super().__init__(str(issue))
        self.issue = issue


# -- File header --------------------------------------------------------------

def _log_time(raw: bytes) -> str | None:
    """JET_LOGTIME (seconds, minutes, hours, day, month, year-1900) as ISO
    text, local time of the system that wrote it; None when unset."""
    sec, minute, hour, day, month, year = raw[:6]
    if not any(raw[:6]):
        return None
    try:
        return datetime(1900 + year, month, day, hour, minute, sec).isoformat()
    except ValueError:
        return f"(invalid: {raw[:6].hex()})"


@dataclass
class EseHeader:
    format_version: int
    format_revision: int
    file_type: int
    db_state: int
    page_size: int
    creation_time: str | None
    consistent_time: str | None
    attach_time: str | None
    detach_time: str | None
    os_version: str
    creation_format: str

    @property
    def state_name(self) -> str:
        return _STATE_NAMES.get(self.db_state, f"Unknown ({self.db_state})")

    @property
    def format_text(self) -> str:
        return f"0x{self.format_version:x}, revision 0x{self.format_revision:x}"


def parse_header(raw: bytes) -> EseHeader:
    """Decode the database file header (first page, at least 668 bytes)."""
    if len(raw) < 668 or raw[4:8] != ESE_SIGNATURE:
        raise EseError(ParseIssue("ese.not_ese"))

    def u32(off: int) -> int:
        value: int = struct.unpack_from("<I", raw, off)[0]
        return value

    page_size = u32(236) or 4096
    if page_size not in (2048, 4096, 8192, 16384, 32768):
        raise EseError(ParseIssue("ese.bad_page_size", {"size": page_size}))
    return EseHeader(
        format_version=u32(8),
        format_revision=u32(232),
        file_type=u32(12),
        db_state=u32(52),
        page_size=page_size,
        creation_time=_log_time(raw[28:36]),
        consistent_time=_log_time(raw[64:72]),
        attach_time=_log_time(raw[72:80]),
        detach_time=_log_time(raw[88:96]),
        os_version=f"{u32(216)}.{u32(220)} build {u32(224)} SP {u32(228)}",
        creation_format=f"0x{u32(340):x}, revision 0x{u32(344):x}",
    )


# -- Pages --------------------------------------------------------------------

@dataclass
class Node:
    """One page tag's value (a B+-tree node)."""
    page: int
    tag: int
    flags: int
    key: bytes
    data: bytes
    offset: int  # file offset of the node data (after its key)


@dataclass
class Page:
    number: int
    flags: int
    fdp_objid: int
    prev: int
    next: int
    nodes: list[Node]
    reserved: int = 1  # leading tags that are page headers, not nodes

    @property
    def is_leaf(self) -> bool:
        return bool(self.flags & PAGE_LEAF)


class EseFile:
    """Page-level access to an ESE database on a seekable binary stream."""

    def __init__(self, stream: IO[bytes], file_size: int) -> None:
        self._f = stream
        self.file_size = file_size
        stream.seek(0)
        self.header = parse_header(stream.read(4096))
        if self.header.file_type != 0:
            raise EseError(ParseIssue("ese.streaming_file"))
        self.page_size = self.header.page_size
        # Pages over 8 KiB use the "large page" format (Windows 7 and later).
        self.small_pages = self.page_size <= 8192
        self.page_header_size = 40 if self.small_pages else 80
        self.page_count = max(0, file_size // self.page_size - 1)

    def read_page(self, pgno: int) -> Page:
        """Read page *pgno* and split it into its nodes. Raises EseError for
        a page outside the file or one whose tags don't fit the page."""
        if pgno < 1 or pgno > self.page_count:
            raise EseError(ParseIssue("ese.page_out_of_range", {"page": pgno}))
        base = (pgno + 1) * self.page_size
        self._f.seek(base)
        raw = self._f.read(self.page_size)
        if len(raw) != self.page_size:
            raise EseError(ParseIssue("ese.page_out_of_range", {"page": pgno}))
        prev, nxt, objid = struct.unpack_from("<III", raw, 16)
        itag_state = struct.unpack_from("<H", raw, 34)[0]
        flags = struct.unpack_from("<I", raw, 36)[0]
        if self.header.format_revision >= 0x122 or itag_state & 0x7000:
            tag_count = itag_state & 0x0FFF
            reserved = (itag_state >> 12) & 0x7 or 1
        else:
            tag_count = itag_state
            reserved = 1
        hdr = self.page_header_size
        mask = 0x1FFF if self.small_pages else 0x7FFF
        nodes: list[Node] = []
        for itag in range(tag_count):
            tag_off = self.page_size - 4 * (itag + 1)
            if tag_off < hdr:
                raise EseError(ParseIssue("ese.bad_page_tags", {"page": pgno}))
            cb_raw, ib_raw = struct.unpack_from("<HH", raw, tag_off)
            cb = cb_raw & mask
            ib = ib_raw & mask
            start = hdr + ib
            if start + cb > self.page_size:
                raise EseError(ParseIssue("ese.bad_page_tags", {"page": pgno}))
            value = raw[start:start + cb]
            if itag < reserved:
                # External header: the page's common key prefix (or, on a
                # root page, the space header). Kept as a node with no key.
                nodes.append(Node(pgno, itag, 0, b"", value, base + start))
                continue
            if self.small_pages:
                node_flags = (ib_raw >> 13) & 0x7
            else:
                node_flags = (struct.unpack_from("<H", value, 0)[0] >> 13) & 0x7 if cb >= 2 else 0
            nodes.append(self._split_node(pgno, itag, node_flags, value, base + start, nodes))
        return Page(pgno, flags, objid, prev, nxt, nodes, min(reserved, len(nodes)))

    @staticmethod
    def _split_node(
        pgno: int, itag: int, flags: int, value: bytes, offset: int, nodes: list[Node]
    ) -> Node:
        pos = 0
        prefix = b""
        if flags & NODE_PREFIX_COMPRESSED:
            cb_prefix = struct.unpack_from("<H", value, 0)[0] & 0x1FFF
            pos = 2
            header = nodes[0].data if nodes else b""
            prefix = header[:cb_prefix]
        if pos + 2 > len(value):
            raise EseError(ParseIssue("ese.bad_node", {"page": pgno, "tag": itag}))
        cb_suffix = struct.unpack_from("<H", value, pos)[0] & 0x1FFF
        pos += 2
        if pos + cb_suffix > len(value):
            raise EseError(ParseIssue("ese.bad_node", {"page": pgno, "tag": itag}))
        key = prefix + value[pos:pos + cb_suffix]
        pos += cb_suffix
        return Node(pgno, itag, flags, key, value[pos:], offset + pos)

    def iter_leaf_nodes(self, root: int, problems: list[ParseIssue]) -> Iterator[Node]:
        """Every leaf node of the B+-tree rooted at page *root*, in key order.
        A page that can't be read is reported in *problems* and skipped."""
        seen: set[int] = set()
        stack = [root]
        while stack:
            pgno = stack.pop()
            if pgno in seen:
                problems.append(ParseIssue("ese.page_loop", {"page": pgno}))
                continue
            seen.add(pgno)
            try:
                page = self.read_page(pgno)
            except EseError as exc:
                problems.append(exc.issue)
                continue
            body = page.nodes[page.reserved:]
            if page.is_leaf:
                yield from body
                continue
            children = []
            for node in body:
                if len(node.data) < 4:
                    problems.append(ParseIssue("ese.bad_node", {"page": pgno, "tag": node.tag}))
                    continue
                children.append(struct.unpack_from("<I", node.data, 0)[0])
            stack.extend(reversed(children))


# -- Catalog ------------------------------------------------------------------

@dataclass
class Column:
    id: int
    name: str
    coltyp: int
    size: int  # catalog SpaceUsage: max size in bytes (fixed size for fixed Binary/Text)
    flags: int
    codepage: int
    record_offset: int  # offset of a fixed column in the record
    default: bytes | None = None
    from_template: bool = False

    @property
    def type_name(self) -> str:
        return COLTYP_NAMES.get(self.coltyp, f"Unknown ({self.coltyp})")

    @property
    def fixed_size(self) -> int:
        return _FIXED_SIZE.get(self.coltyp, self.size)


@dataclass
class Table:
    objid: int
    name: str
    fdp: int
    template_name: str | None = None
    columns: dict[int, Column] = field(default_factory=dict)
    template_tagged: dict[int, Column] = field(default_factory=dict)
    lv_fdp: int | None = None
    flags: int = 0

    def ordered_columns(self) -> list[Column]:
        return [self.columns[k] for k in sorted(self.columns)]


def _catalog_table() -> Table:
    """The catalog's own definition (MSysObjects), needed to read the catalog."""
    fixed = [
        (1, "ObjidTable", COLTYP_LONG), (2, "Type", COLTYP_SHORT),
        (3, "Id", COLTYP_LONG), (4, "ColtypOrPgnoFDP", COLTYP_LONG),
        (5, "SpaceUsage", COLTYP_LONG), (6, "Flags", COLTYP_LONG),
        (7, "PagesOrLocale", COLTYP_LONG), (8, "RootFlag", COLTYP_BIT),
        (9, "RecordOffset", COLTYP_SHORT), (10, "LCMapFlags", COLTYP_LONG),
        (11, "KeyMost", COLTYP_SHORT), (12, "LVChunkMax", COLTYP_LONG),
    ]
    table = Table(objid=2, name="MSysObjects", fdp=CATALOG_FDP_PAGE)
    offset = 4
    for cid, name, coltyp in fixed:
        table.columns[cid] = Column(cid, name, coltyp, _FIXED_SIZE[coltyp], 1, 0, offset)
        offset += _FIXED_SIZE[coltyp]
    for cid, name, coltyp in (
        (128, "Name", COLTYP_TEXT), (129, "Stats", COLTYP_BINARY),
        (130, "TemplateTable", COLTYP_TEXT), (131, "DefaultValue", COLTYP_BINARY),
        (132, "KeyFldIDs", COLTYP_BINARY), (133, "VarSegMac", COLTYP_BINARY),
        (134, "ConditionalColumns", COLTYP_BINARY), (135, "TupleLimits", COLTYP_BINARY),
        (136, "Version", COLTYP_BINARY), (137, "SortID", COLTYP_BINARY),
    ):
        table.columns[cid] = Column(cid, name, coltyp, 255, 0, 1252, 0)
    for cid, name in (
        (256, "CallbackData"), (257, "CallbackDependencies"), (258, "SeparateLV"),
        (259, "SpaceHints"), (260, "SpaceDeferredLVHints"), (261, "LocaleName"),
    ):
        table.columns[cid] = Column(cid, name, COLTYP_LONG_BINARY, 0, 2, 0, 0)
    return table


# -- Values -------------------------------------------------------------------

@dataclass
class Record:
    """One table row as stored in a leaf node."""
    page: int
    tag: int
    deleted: bool
    values: dict[int, Any]


class _Undecoded:
    """Marker for a value that could not be decoded: raw bytes + why."""

    __slots__ = ("raw", "issue")

    def __init__(self, raw: bytes, issue: ParseIssue) -> None:
        self.raw = raw
        self.issue = issue


def ole_date_text(value: float) -> str | None:
    """A JET_coltypDateTime value (OLE Automation date: days since
    1899-12-30) as ISO text, rounded to the millisecond; None if out of range."""
    whole = int(value)
    frac = abs(value - whole)
    try:
        dt = _OLE_EPOCH + timedelta(days=whole) + timedelta(milliseconds=round(frac * 86_400_000))
    except OverflowError:
        return None
    return dt.isoformat(timespec="milliseconds" if dt.microsecond else "seconds")


def decompress(data: bytes) -> bytes:
    """Decompress an ESE-compressed value or long-value chunk. Raises
    EseError naming the scheme when it isn't supported or the data is bad."""
    if not data:
        raise EseError(ParseIssue("ese.decompress_failed", detail="empty value"))
    scheme = data[0] >> 3
    if scheme in (COMPRESS_7BIT_ASCII, COMPRESS_7BIT_UNICODE):
        final_bits = (data[0] & 0x7) + 1
        total_bits = (len(data) - 2) * 8 + final_bits
        if len(data) < 2 or total_bits % 7:
            raise EseError(ParseIssue("ese.decompress_failed", detail="bad 7-bit length"))
        count = total_bits // 7
        bits = int.from_bytes(data[1:], "little")
        chars = bytes((bits >> (7 * i)) & 0x7F for i in range(count))
        if scheme == COMPRESS_7BIT_ASCII:
            return chars
        return b"".join(bytes((c, 0)) for c in chars)
    if scheme in (COMPRESS_XPRESS, COMPRESS_LZ4):
        # 1-byte scheme, 2-byte uncompressed size, then the compressed block
        # (compression.cxx: Xpress legacy header, Lz4Header).
        if len(data) < 3:
            raise EseError(ParseIssue("ese.decompress_failed", detail="header cut off"))
        size = struct.unpack_from("<H", data, 1)[0]
        decode = lz77_decompress if scheme == COMPRESS_XPRESS else lz4_block_decompress
        try:
            return decode(data[3:], size)
        except BlockCompressionError as exc:
            raise EseError(ParseIssue("ese.decompress_failed", detail=str(exc))) from exc
    if scheme == COMPRESS_SCRUB:
        raise EseError(ParseIssue("ese.scrubbed"))
    name = _COMPRESSION_NAMES.get(scheme, f"0x{scheme:x}")
    raise EseError(ParseIssue("ese.compression_unsupported", {"scheme": name}))


class _PartialText:
    """Text whose last character is incomplete: (text before it, all raw
    bytes) as shown, plus why the end was left out."""

    __slots__ = ("value", "issue")

    def __init__(self, value: tuple[str, bytes], issue: ParseIssue) -> None:
        self.value = value
        self.issue = issue


# Longest incomplete character at the end of a value: a UTF-8 sequence missing
# its last byte (3), or a UTF-16 surrogate pair missing its low half plus an
# odd byte (3).
_MAX_CUT_TAIL = 3
_CUT_REASONS = ("truncated data", "unexpected end of data")


def _text_cut_at_end(
    raw: bytes, encoding: str, exc: UnicodeDecodeError, codepage: int,
) -> _PartialText | None:
    """A value valid up to an incomplete last character -- an odd-sized fixed
    Unicode column, or text cut at a byte limit inside a surrogate pair (as
    Windows Search does) -- is shown up to there. Invalid bytes anywhere
    else keep the whole value undecoded."""
    tail = len(raw) - exc.start
    if exc.end != len(raw) or tail > _MAX_CUT_TAIL or exc.reason not in _CUT_REASONS:
        return None
    try:
        text = raw[:exc.start].decode(encoding)
    except UnicodeDecodeError:
        return None
    return _PartialText((text, raw), ParseIssue(
        "ese.text_cut", {"codepage": codepage, "count": tail, "hex": raw[exc.start:].hex(" ")},
    ))


def _decode_typed(col: Column, raw: bytes) -> Any:
    """Bytes of one value -> Python value by the column's declared type."""
    t = col.coltyp
    try:
        if t == COLTYP_BIT:
            return raw[0] != 0
        if t == COLTYP_UNSIGNED_BYTE:
            return raw[0]
        if t == COLTYP_SHORT:
            return struct.unpack("<h", raw[:2])[0]
        if t == COLTYP_UNSIGNED_SHORT:
            return struct.unpack("<H", raw[:2])[0]
        if t == COLTYP_LONG:
            return struct.unpack("<i", raw[:4])[0]
        if t == COLTYP_UNSIGNED_LONG:
            return struct.unpack("<I", raw[:4])[0]
        if t in (COLTYP_CURRENCY, COLTYP_LONG_LONG):
            return struct.unpack("<q", raw[:8])[0]
        if t == COLTYP_IEEE_SINGLE:
            return struct.unpack("<f", raw[:4])[0]
        if t == COLTYP_IEEE_DOUBLE:
            return struct.unpack("<d", raw[:8])[0]
        if t == COLTYP_DATETIME:
            value = struct.unpack("<d", raw[:8])[0]
            text = ole_date_text(value)
            if text is None:
                return _Undecoded(raw, ParseIssue("ese.date_out_of_range", {"value": value}))
            return (text, raw[:8])
        if t == COLTYP_GUID:
            return (str(uuid.UUID(bytes_le=raw[:16])), raw[:16])
    except (struct.error, IndexError, ValueError):
        return _Undecoded(raw, ParseIssue(
            "ese.value_too_short", {"type": col.type_name, "size": len(raw)},
        ))
    if t in _TEXT_TYPES:
        encoding = _CODEPAGES.get(col.codepage)
        if encoding is None:
            return _Undecoded(raw, ParseIssue("ese.codepage_unsupported", {"codepage": col.codepage}))
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError as exc:
            partial = _text_cut_at_end(raw, encoding, exc, col.codepage)
            if partial is not None:
                return partial
            return _Undecoded(raw, ParseIssue(
                "ese.text_decode_failed", {"codepage": col.codepage}, detail=str(exc),
            ))
    return raw  # Binary, LongBinary, SLV, Nil


# -- Database -----------------------------------------------------------------

class EseDatabase:
    """Catalog and records of an ESE database."""

    def __init__(self, stream: IO[bytes], file_size: int) -> None:
        self.file = EseFile(stream, file_size)
        self.header = self.file.header
        self.catalog_problems: list[ParseIssue] = []
        self.tables: list[Table] = self._read_catalog()
        # lv tree FDP -> {lid: (declared size, {offset: chunk bytes})}
        self._lv_cache: dict[int, dict[int, tuple[int | None, dict[int, bytes]]]] = {}

    # catalog

    def _read_catalog(self) -> list[Table]:
        catalog = _catalog_table()
        tables: dict[int, Table] = {}
        order: list[int] = []
        for record in self.iter_records(catalog, self.catalog_problems):
            if record.deleted:
                continue
            v = record.values
            objid, ctype, name = v.get(1), v.get(2), v.get(128)
            if not isinstance(objid, int) or not isinstance(ctype, int) or not isinstance(name, str):
                continue
            if ctype == CAT_TABLE:
                fdp = v.get(4)
                template = v.get(130)
                tables[objid] = Table(
                    objid=objid, name=name, fdp=fdp if isinstance(fdp, int) else 0,
                    template_name=template if isinstance(template, str) and template else None,
                    flags=_int(v.get(6)),
                )
                order.append(objid)
            elif ctype == CAT_COLUMN and objid in tables:
                cid = v.get(3)
                if not isinstance(cid, int):
                    continue
                default = v.get(131)
                tables[objid].columns[cid] = Column(
                    id=cid, name=name, coltyp=_int(v.get(4)), size=_int(v.get(5)),
                    flags=_int(v.get(6)), codepage=_int(v.get(7)),
                    record_offset=_int(v.get(9)),
                    default=default if isinstance(default, bytes) and default else None,
                )
            elif ctype == CAT_LONG_VALUE and objid in tables:
                fdp = v.get(4)
                if isinstance(fdp, int):
                    tables[objid].lv_fdp = fdp
        by_name = {t.name: t for t in tables.values()}
        for table in tables.values():
            if table.template_name:
                self._apply_template(table, by_name.get(table.template_name))
        return [tables[o] for o in order]

    def _apply_template(self, table: Table, template: Table | None) -> None:
        if template is None:
            self.catalog_problems.append(ParseIssue(
                "ese.template_missing", {"table": table.name, "template": table.template_name},
            ))
            return
        for cid, col in template.columns.items():
            copy = Column(**{**col.__dict__, "from_template": True})
            if cid >= 256:
                # Template tagged columns are told apart by the TAGFLD's
                # "derived" bit, not by id: they can share ids with the
                # table's own tagged columns.
                table.template_tagged[cid] = copy
            elif cid not in table.columns:
                table.columns[cid] = copy

    def table_columns(self, table: Table) -> list[Column]:
        """Columns in display order: the template's tagged columns first
        (they come first in the record too), then the table's own."""
        own = table.ordered_columns()
        fixed_var = [c for c in own if c.id < 256]
        tagged = [c for c in own if c.id >= 256]
        return fixed_var + [table.template_tagged[k] for k in sorted(table.template_tagged)] + tagged

    # records

    def iter_records(self, table: Table, problems: list[ParseIssue]) -> Iterator[Record]:
        """Every record of *table*'s B+-tree, deleted-flagged nodes included."""
        if table.fdp <= 0:
            problems.append(ParseIssue("ese.no_fdp", {"table": table.name}))
            return
        for node in self.file.iter_leaf_nodes(table.fdp, problems):
            values = self._decode_record(table, node.data)
            yield Record(node.page, node.tag, bool(node.flags & NODE_DELETED), values)

    def _decode_record(self, table: Table, rec: bytes) -> dict[int, Any]:
        """{column id (template tagged ids as -id): value}. A column absent
        from the record is None; one that can't be decoded is _Undecoded."""
        out: dict[int, Any] = {}
        if len(rec) < 4:
            return out
        last_fixed, last_var, end_fixed = struct.unpack_from("<BBH", rec, 0)
        # Fixed columns
        n_fixed = last_fixed
        null_bitmap_len = (n_fixed + 7) // 8
        bitmap_start = end_fixed - null_bitmap_len
        for cid, col in table.columns.items():
            if not 1 <= cid <= 127:
                continue
            if cid > last_fixed:
                out[cid] = self._default(col)
                continue
            bit_index = cid - 1
            byte = bitmap_start + bit_index // 8
            if 0 <= byte < len(rec) and rec[byte] & (1 << (bit_index % 8)):
                out[cid] = None
                continue
            start = col.record_offset
            size = col.fixed_size
            if start < 4 or start + size > len(rec):
                out[cid] = _Undecoded(rec[start:start + size], ParseIssue(
                    "ese.fixed_out_of_record", {"column": col.name},
                ))
                continue
            out[cid] = _decode_typed(col, rec[start:start + size])
        # Variable columns
        n_var = last_var - 127 if last_var >= 128 else 0
        offsets_start = end_fixed
        var_data = offsets_start + 2 * n_var
        prev_end = 0
        var_ends: list[tuple[int, bool]] = []
        for i in range(n_var):
            if offsets_start + 2 * i + 2 > len(rec):
                break
            raw_end = struct.unpack_from("<H", rec, offsets_start + 2 * i)[0]
            var_ends.append((raw_end & 0x7FFF, bool(raw_end & 0x8000)))
        for cid, col in table.columns.items():
            if not 128 <= cid <= 255:
                continue
            idx = cid - 128
            if idx >= len(var_ends):
                out[cid] = self._default(col)
                continue
            end, is_null = var_ends[idx]
            start = var_ends[idx - 1][0] if idx else 0
            if is_null:
                out[cid] = None
                continue
            raw = rec[var_data + start:var_data + end]
            out[cid] = _decode_typed(col, raw)
        if var_ends:
            prev_end = var_ends[-1][0]
        # Tagged columns
        tagged_start = var_data + prev_end
        if tagged_start < len(rec):
            self._decode_tagged(table, rec[tagged_start:], out)
        for cid, col in table.columns.items():
            if cid >= 256 and cid not in out:
                out[cid] = self._default(col)
        for cid in table.template_tagged:
            out.setdefault(-cid, None)
        return out

    @staticmethod
    def _default(col: Column) -> Any:
        """A column the record doesn't store has the catalog's default value
        (what ESE itself returns for it), or is NULL."""
        if col.default is None or not col.flags & FIELD_DEFAULT:
            return None
        return _decode_typed(col, col.default)

    def _decode_tagged(self, table: Table, data: bytes, out: dict[int, Any]) -> None:
        small = self.file.small_pages
        mask = 0x1FFF if small else 0x7FFF
        if len(data) < 4:
            return
        first_ib = struct.unpack_from("<H", data, 2)[0] & mask
        count = first_ib // 4
        entries = []
        for i in range(count):
            if 4 * i + 4 > len(data):
                break
            fid, ib_raw = struct.unpack_from("<HH", data, 4 * i)
            entries.append((fid, ib_raw))
        for i, (fid, ib_raw) in enumerate(entries):
            start = ib_raw & mask
            end = (entries[i + 1][1] & mask) if i + 1 < len(entries) else len(data)
            derived = bool(ib_raw & 0x8000)
            if derived:
                col = table.template_tagged.get(fid)
                key = -fid
            else:
                col = table.columns.get(fid)
                key = fid
            raw = data[start:end]
            if col is None:
                out[key] = _Undecoded(raw, ParseIssue("ese.unknown_column", {"id": fid}))
                continue
            if small and ib_raw & 0x2000:
                out[key] = None
                continue
            header = 0
            if not small or ib_raw & 0x4000:
                if not raw:
                    out[key] = None
                    continue
                header, raw = raw[0], raw[1:]
            value = self._decode_tagged_value(table, col, header, raw)
            if col.flags & FIELD_MULTI_VALUED and value is not None and not isinstance(value, list):
                # One value of a multi-valued column is stored as a plain
                # single value; show it the same way as two or more.
                value = [value]
            out[key] = value

    def _decode_tagged_value(self, table: Table, col: Column, header: int, raw: bytes) -> Any:
        if header & TAG_NULL:
            return None
        if header & TAG_ENCRYPTED:
            return _Undecoded(raw, ParseIssue("ese.encrypted"))
        compressed = bool(header & TAG_COMPRESSED)
        if header & TAG_TWO_VALUES:
            if not raw:
                return _Undecoded(raw, ParseIssue("ese.bad_multi_value", {"column": col.name}))
            cb_first = raw[0]
            parts = [(raw[1:1 + cb_first], False), (raw[1 + cb_first:], False)]
            return [
                self._single(table, col, part, separated, compressed and i == 0)
                for i, (part, separated) in enumerate(parts)
            ]
        if header & TAG_MULTI_VALUES:
            if len(raw) < 2:
                return _Undecoded(raw, ParseIssue("ese.bad_multi_value", {"column": col.name}))
            first = struct.unpack_from("<H", raw, 0)[0] & 0x7FFF
            n = first // 2
            offs = [struct.unpack_from("<H", raw, 2 * k)[0] for k in range(n)]
            values = []
            for k, off_raw in enumerate(offs):
                s = off_raw & 0x7FFF
                e = (offs[k + 1] & 0x7FFF) if k + 1 < n else len(raw)
                values.append(self._single(
                    table, col, raw[s:e], bool(off_raw & 0x8000), compressed and k == 0,
                ))
            return values
        return self._single(table, col, raw, bool(header & TAG_SEPARATED), compressed)

    def _single(
        self, table: Table, col: Column, raw: bytes, separated: bool, compressed: bool
    ) -> Any:
        if separated:
            lv = self._long_value(table, raw)
            if isinstance(lv, _Undecoded):
                return lv
            raw = lv
        elif compressed:
            try:
                raw = decompress(raw)
            except EseError as exc:
                return _Undecoded(raw, exc.issue)
        return _decode_typed(col, raw)

    # long values

    def _long_value(self, table: Table, ref: bytes) -> bytes | _Undecoded:
        if len(ref) not in (4, 8):
            return _Undecoded(ref, ParseIssue("ese.bad_lv_reference", {"size": len(ref)}))
        lid = int.from_bytes(ref, "little")
        if table.lv_fdp is None:
            return _Undecoded(ref, ParseIssue("ese.lv_missing", {"lid": lid}))
        store = self._lv_store(table.lv_fdp)
        entry = store.get(lid)
        if entry is None:
            return _Undecoded(ref, ParseIssue("ese.lv_missing", {"lid": lid}))
        size, chunks = entry
        offsets = sorted(chunks)
        if size is None:
            return _Undecoded(ref, ParseIssue("ese.lv_no_root", {"lid": lid}))
        chunk_most = offsets[1] - offsets[0] if len(offsets) > 1 else size
        out = bytearray()
        for off in offsets:
            chunk = chunks[off]
            if off != len(out):
                return _Undecoded(ref, ParseIssue("ese.lv_gap", {"lid": lid, "offset": off}))
            expected = min(chunk_most, size - off)
            if len(chunk) < expected:
                try:
                    chunk = decompress(chunk)
                except EseError as exc:
                    return _Undecoded(ref, exc.issue)
            out += chunk
        if len(out) != size:
            return _Undecoded(ref, ParseIssue(
                "ese.lv_size_mismatch", {"lid": lid, "size": size, "actual": len(out)},
            ))
        return bytes(out)

    def _lv_store(self, fdp: int) -> dict[int, tuple[int | None, dict[int, bytes]]]:
        cached = self._lv_cache.get(fdp)
        if cached is not None:
            return cached
        store: dict[int, tuple[int | None, dict[int, bytes]]] = {}
        problems: list[ParseIssue] = []
        for node in self.file.iter_leaf_nodes(fdp, problems):
            if node.flags & NODE_DELETED:
                continue
            key = node.key
            lid64_flag = bool(key[0] & 0x80) if key else False
            if len(key) == 4 or (len(key) == 8 and lid64_flag):
                lid = int.from_bytes(key, "big")
                size = struct.unpack_from("<I", node.data, 4)[0] if len(node.data) >= 8 else None
                _, chunks = store.get(lid, (None, {}))
                store[lid] = (size, chunks)
            elif len(key) in (8, 12):
                lid = int.from_bytes(key[:-4], "big")
                offset = int.from_bytes(key[-4:], "big")
                size, chunks = store.get(lid, (None, {}))
                chunks[offset] = node.data
                store[lid] = (size, chunks)
        self._lv_cache[fdp] = store
        return store


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def is_undecoded(value: Any) -> bool:
    return isinstance(value, _Undecoded)


def undecoded_parts(value: Any) -> tuple[bytes, ParseIssue]:
    assert isinstance(value, _Undecoded)
    return value.raw, value.issue


def is_partial_text(value: Any) -> bool:
    return isinstance(value, _PartialText)


def partial_text_parts(value: Any) -> tuple[tuple[str, bytes], ParseIssue]:
    assert isinstance(value, _PartialText)
    return value.value, value.issue
