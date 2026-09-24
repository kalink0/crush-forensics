# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""SQLite legacy rollback-journal (`-journal`) parser and read-only
post-rollback reconstruction.

A rollback-journal file holds the *pre-transaction* image of every page a
still-open (or crash-interrupted) transaction has touched, so SQLite can
undo an incomplete write on next open. Unlike `-wal` (sqlite_wal.py), where
every committed frame is legitimately part of the database's *current*
state, a rollback journal's page images are the *old*, pre-write content --
mechanically the opposite of "current" unless a rollback is actually
applied.

This module never applies anything to a real file. Every function here is a
pure, read-only transform over bytes already in memory: parsing the journal
into (header, page-record) structures, and -- only for a journal whose magic
and every page checksum validate (see JournalParseResult.mergeable) --
building a byte-exact "what would this database look like after SQLite's
own hot-journal rollback" image purely in memory, for the caller to open via
sqlite3.Connection.deserialize() (never via a file path SQLite's own engine
could auto-detect and silently recover against -- see sqlite_parser.py's
caller for why that distinction matters).

Journal file layout (undocumented by SQLite as a stable/public format, but
stable in practice since the "format 3" journal was introduced; reconstructed
here from SQLite's own pager.c and cross-checked against real journal
samples):

    Offset 0-7:   Magic: d9 d5 05 f9 20 a1 63 d7
    Offset 8-11:  Page-record count (nRec), big-endian u32.
                  0xFFFFFFFF means "unknown" -- scan until the next header
                  or EOF instead of trusting a count.
    Offset 12-15: Checksum nonce (cksumInit), big-endian u32.
    Offset 16-19: Original database size in pages (dbOrigSize), big-endian
                  u32 -- the size to truncate back to on rollback.
    Offset 20-23: Sector size the writer used, big-endian u32. The header is
                  zero-padded out to this many bytes so it starts on a
                  sector boundary.
    Offset 24-27: Database page size, big-endian u32.
    ... zero padding up to `sector size` bytes ...
    Then, repeated `nRec` times (or until EOF/next header if nRec unknown):
        4 bytes  page number, big-endian
        N bytes  page's pre-transaction content (N = page size)
        4 bytes  checksum, big-endian (see _pager_checksum)

A single journal file can hold multiple such header+records segments back
to back (SQLite starts a new header whenever it syncs mid-transaction), each
independently magic-tagged and independently checksummed.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

from crush.core.issues import ParseIssue
from crush.core.sqlite_freeblocks import extract_freeblocks
from crush.core.sqlite_unallocated import extract_unallocated_space
from crush.core.sqlite_wal import PAGE_TYPE_TABLE_LEAF, parse_table_leaf_page

JOURNAL_MAGIC = bytes((0xD9, 0xD5, 0x05, 0xF9, 0x20, 0xA1, 0x63, 0xD7))

_HEADER_FIELDS_SIZE = 28  # magic(8) + nRec(4) + nonce(4) + dbOrigSize(4) + sectorSize(4) + pageSize(4)
_NO_RECORD_COUNT = 0xFFFFFFFF
_MIN_PAGE_SIZE = 512
_MAX_PAGE_SIZE = 65536


def _pager_checksum(nonce: int, page: bytes, page_size: int) -> int:
    """Replicate SQLite pager.c's pager_cksum(): a fast, non-cryptographic
    checksum sampling every 200th byte from the end of the page, seeded with
    the journal header's nonce. Deliberately weak (SQLite only needs it to
    detect a half-written page from a crash mid-write, not to authenticate
    content) -- callers must not treat a valid checksum as proof the page
    wasn't otherwise tampered with, only as proof it wasn't truncated mid
    fwrite() by the same crash that left the journal behind.
    """
    cksum = nonce
    i = page_size - 200
    while i > 0:
        cksum = (cksum + page[i]) & 0xFFFFFFFF
        i -= 200
    return cksum


@dataclass
class JournalHeader:
    offset: int             # absolute file offset this header starts at
    n_rec: int               # 0xFFFFFFFF = unknown, must scan
    nonce: int
    db_orig_size: int        # pages, pre-transaction database size
    sector_size: int
    page_size: int
    records_start: int       # absolute offset of the first page record


@dataclass
class JournalPageRecord:
    segment_index: int
    record_index: int
    page_num: int
    page_offset: int         # absolute offset of this record's page DATA (not its page-number field)
    page_size: int
    data: bytes
    checksum_offset: int     # absolute offset of this record's 4-byte checksum
    checksum_stored: int
    checksum_computed: int
    checksum_valid: bool


@dataclass
class JournalSegment:
    index: int
    header: JournalHeader
    records: list[JournalPageRecord]
    # True only if every record in this segment checksums correctly and, when
    # the header declared a record count, exactly that many were found --
    # i.e. this segment is not the tail end of a journal that a crash cut off
    # mid-write. A segment failing this must never contribute to a rollback
    # reconstruction (see JournalParseResult.mergeable / reconstruct_post_
    # rollback_image), only ever to the raw, fully-labelled record inventory.
    fully_valid: bool


@dataclass
class JournalParseResult:
    segments: list[JournalSegment] = field(default_factory=list)
    trailing_data: bytes | None = None  # unparsed tail (e.g. a super-journal name pointer); best-effort, not decoded
    trailing_offset: int = 0
    page_size: int = 0
    # True only if there is at least one segment and every segment is
    # fully_valid -- the single gate reconstruct_post_rollback_image() and
    # every caller that would merge journal content into a "current" view
    # must check before doing so (ground rule: never present a guess as
    # ground truth -- see MEMORY feedback_forensic_cleanliness).
    mergeable: bool = False
    error: ParseIssue | None = None


def parse_rollback_journal(data: bytes) -> JournalParseResult:
    """Parse a rollback-journal file's bytes into header+record segments.

    Never raises on malformed input -- an unparseable file simply yields no
    segments and JournalParseResult.error explains why (e.g. a zeroed/
    invalidated header, which is exactly what a *stale* PERSIST-mode journal
    looks like: SQLite keeps the file around after every commit but zeroes
    its header so it's recognized as "not hot" on next open).
    """
    segments: list[JournalSegment] = []
    offset = 0
    seg_index = 0

    while offset + 8 <= len(data) and data[offset:offset + 8] == JOURNAL_MAGIC:
        header = _parse_header(data, offset)
        if header is None:
            break

        records: list[JournalPageRecord] = []
        pos = header.records_start
        record_size = 4 + header.page_size + 4
        want = None if header.n_rec == _NO_RECORD_COUNT else header.n_rec
        rec_index = 0

        while pos + record_size <= len(data):
            if want is not None and rec_index >= want:
                break
            if want is None and data[pos:pos + 8] == JOURNAL_MAGIC:
                break  # next header segment starts here

            page_num = struct.unpack_from(">I", data, pos)[0]
            page_data_start = pos + 4
            page_data = bytes(data[page_data_start:page_data_start + header.page_size])
            checksum_off = page_data_start + header.page_size
            checksum_stored = struct.unpack_from(">I", data, checksum_off)[0]
            checksum_computed = _pager_checksum(header.nonce, page_data, header.page_size)

            records.append(JournalPageRecord(
                segment_index=seg_index,
                record_index=rec_index,
                page_num=page_num,
                page_offset=page_data_start,
                page_size=header.page_size,
                data=page_data,
                checksum_offset=checksum_off,
                checksum_stored=checksum_stored,
                checksum_computed=checksum_computed,
                checksum_valid=checksum_computed == checksum_stored,
            ))
            pos += record_size
            rec_index += 1

        fully_valid = (
            bool(records)
            and all(r.checksum_valid for r in records)
            and (want is None or len(records) == want)
        )
        segments.append(JournalSegment(
            index=seg_index, header=header, records=records, fully_valid=fully_valid,
        ))
        offset = pos
        seg_index += 1

    trailing = data[offset:] if offset < len(data) else None
    page_size = segments[0].header.page_size if segments else 0
    mergeable = bool(segments) and all(s.fully_valid for s in segments)
    error = None
    if not segments:
        error = ParseIssue("sqlite_journal.no_valid_header")

    return JournalParseResult(
        segments=segments,
        trailing_data=trailing,
        trailing_offset=offset,
        page_size=page_size,
        mergeable=mergeable,
        error=error,
    )


def _parse_header(data: bytes, offset: int) -> JournalHeader | None:
    if offset + _HEADER_FIELDS_SIZE > len(data) or data[offset:offset + 8] != JOURNAL_MAGIC:
        return None

    n_rec        = struct.unpack_from(">I", data, offset + 8)[0]
    nonce        = struct.unpack_from(">I", data, offset + 12)[0]
    db_orig_size = struct.unpack_from(">I", data, offset + 16)[0]
    sector_size  = struct.unpack_from(">I", data, offset + 20)[0]
    page_size    = struct.unpack_from(">I", data, offset + 24)[0]

    if page_size < _MIN_PAGE_SIZE or page_size > _MAX_PAGE_SIZE or (page_size & (page_size - 1)) != 0:
        return None  # not a power-of-two SQLite page size -- unparseable, not a plausible header

    # The header is zero-padded out to the sector size on disk. A corrupt or
    # implausible sector_size falls back to the unpadded field size rather
    # than guessing -- misreading this would silently misalign every page
    # record that follows.
    header_size = sector_size if _HEADER_FIELDS_SIZE <= sector_size <= len(data) - offset else _HEADER_FIELDS_SIZE

    return JournalHeader(
        offset=offset,
        n_rec=n_rec,
        nonce=nonce,
        db_orig_size=db_orig_size,
        sector_size=sector_size,
        page_size=page_size,
        records_start=offset + header_size,
    )


def build_journal_page_overlay(result: JournalParseResult) -> dict[int, bytes]:
    """Return {page_num: pre-transaction page bytes}, first-record-wins.

    A page journaled more than once (a later header segment re-journals a
    page a savepoint first dirtied) keeps its *earliest* recorded image --
    the state before any of this transaction's writes, which is what
    rolling all the way back restores. Returns {} unless every segment
    validated (result.mergeable) -- a partially-valid journal must never
    silently contribute a guessed subset of pages.
    """
    if not result.mergeable:
        return {}
    overlay: dict[int, bytes] = {}
    for segment in result.segments:
        for rec in segment.records:
            overlay.setdefault(rec.page_num, rec.data)
    return overlay


def read_db_header_page_size(data: bytes) -> int:
    """Return the page size declared in a SQLite database file's own
    100-byte header (offset 16-17, big-endian u16; the special value 1
    means 65536), or 0 if *data* is too short to contain one.
    """
    if len(data) < 18:
        return 0
    raw = struct.unpack_from(">H", data, 16)[0]
    return 65536 if raw == 1 else raw


def reconstruct_post_rollback_image(
    base_data: bytes,
    page_size: int,
    result: JournalParseResult,
    wal_overlay: dict[int, bytes] | None = None,
) -> bytes | None:
    """Build the byte-exact database image SQLite's own hot-journal rollback
    would produce, entirely in memory -- never writes anything, never reads
    anything beyond the bytes already passed in.

    Layers applied in order (each overriding the previous for any page it
    touches): the base file as given, then *wal_overlay* (committed -wal
    frames -- see sqlite_wal.build_wal_page_overlay(), the legitimately
    "current" layer), then the journal's own pre-transaction pages (the
    layer closest to the actual crash/interruption moment, hence applied
    last). Returns None if *result* isn't mergeable (see
    JournalParseResult.mergeable) or *page_size* is invalid -- callers must
    never fall back to a partial/best-effort reconstruction here.
    """
    if not result.mergeable or page_size <= 0 or not result.segments:
        return None

    # The journal's own declared page size (result.page_size, from its
    # header) must agree with the base database's -- a mismatch means this
    # -journal doesn't actually belong to *this* database (stale/foreign
    # companion), and applying its page-sized records against the wrong
    # stride would silently misalign every subsequent byte. Never guess.
    if result.page_size != page_size:
        return None

    # A rollback journal only ever records the *pre-transaction* content of
    # a page that already existed before the write -- a page the
    # transaction newly allocated is rolled back by truncation alone (see
    # below), never by journaling it. page_num isn't covered by the page
    # checksum (only the page content is), so a record naming a page beyond
    # the pre-transaction size is either corrupt or adversarial input, not
    # a page a real SQLite engine would ever have written here -- reject the
    # whole reconstruction rather than trust an attacker/corruption
    # controlled page number into a multi-gigabyte bytearray.extend().
    orig_pages = result.segments[0].header.db_orig_size or (len(base_data) // page_size)
    for segment in result.segments:
        for rec in segment.records:
            if rec.page_num < 1 or rec.page_num > orig_pages:
                return None

    image = bytearray(base_data)

    def _apply(pn: int, page_bytes: bytes) -> None:
        start = (pn - 1) * page_size
        end = start + page_size
        if end > len(image):
            image.extend(b"\x00" * (end - len(image)))
        image[start:end] = page_bytes

    if wal_overlay:
        for pn, page_bytes in wal_overlay.items():
            if pn >= 1 and len(page_bytes) == page_size:
                _apply(pn, page_bytes)

    for pn, page_bytes in build_journal_page_overlay(result).items():
        if pn >= 1:
            _apply(pn, page_bytes)

    # Truncate back to the size the database had before this transaction
    # began, if the transaction had grown the file (dbOrigSize is 0 when a
    # transaction never changed the page count).
    orig_pages = result.segments[0].header.db_orig_size
    if orig_pages > 0:
        target_len = orig_pages * page_size
        if target_len < len(image):
            del image[target_len:]

    # This reconstruction is a complete, self-contained image -- clear any
    # WAL-mode version flag (header offsets 18/19) so nothing that later
    # opens it goes looking for a nonexistent -wal companion. Same fix as
    # vfs.py's _clear_wal_header_flag(), applied here for the same reason.
    if len(image) >= 20 and image[18] == 2 and image[19] == 2:
        image[18] = 1
        image[19] = 1
    if len(image) >= 32 and page_size:
        struct.pack_into(">I", image, 28, len(image) // page_size)

    return bytes(image)


@dataclass
class JournalRow:
    """One recovered entity from a journal page image -- a live table-leaf
    cell, a deleted row still sitting in a freeblock, or non-zero
    unallocated-space slack. *file_offset*/*byte_length* are this row's own
    exact bytes' location within the journal file itself (not the database),
    giving every entry direct hex provenance regardless of whether the
    journal turned out to be mergeable into a reconstructed "current" view.
    """
    segment_index: int
    record_index: int
    page_num: int
    kind: str  # "Live cell" | "Freeblock (deleted)" | "Unallocated slack"
    rowid: int | None
    values: list[Any] | None
    raw: bytes | None
    file_offset: int
    byte_length: int
    checksum_valid: bool


def extract_journal_rows(result: JournalParseResult) -> list[JournalRow]:
    """Decode every live row, deleted-but-recoverable row, and non-zero
    unallocated-space gap out of every page record in *result* -- reusing
    the same page-level decoders sqlite_wal.py/sqlite_freeblocks.py/
    sqlite_unallocated.py already use against live database pages, since a
    journal page record is byte-for-byte the same page format. Each journal
    page image stands on its own (no overflow-chain following across
    records, and no base-database context needed), so this works equally
    for a journal opened standalone (no companion database available) and
    for one opened alongside its database.
    """
    rows: list[JournalRow] = []
    for segment in result.segments:
        for rec in segment.records:
            page = rec.data
            btree_offset = 100 if rec.page_num == 1 else 0
            if len(page) <= btree_offset or page[btree_offset] != PAGE_TYPE_TABLE_LEAF:
                continue

            parsed = parse_table_leaf_page(
                page, page_size=rec.page_size, btree_offset=btree_offset, want_ranges=True,
            )
            if parsed:
                for rowid, values, layout in parsed:
                    cell_start, cell_end = layout.page_local_range
                    rows.append(JournalRow(
                        segment_index=rec.segment_index, record_index=rec.record_index,
                        page_num=rec.page_num, kind="Live cell", rowid=rowid, values=values,
                        raw=None,
                        file_offset=rec.page_offset + cell_start,
                        byte_length=cell_end - cell_start,
                        checksum_valid=rec.checksum_valid,
                    ))

            # Freeblocks/unallocated-space carving assumes offset-0 page
            # headers (see sqlite_freeblocks.py/sqlite_unallocated.py); page
            # 1's is at offset 100, same known limitation those modules
            # already have scanning a live database's own page 1.
            for fb in extract_freeblocks(page):
                # fb["offset"]/["size"] describe the whole freeblock
                # (including its own 4-byte next-pointer+size header);
                # fb["data"] is only the content after that header -- offset
                # the provenance range to match, or a "Locate in Hex" click
                # would highlight 4 bytes of freeblock-list bookkeeping
                # instead of (part of) the recovered row's own bytes.
                content_offset = fb["offset"] + (fb["size"] - len(fb["data"]))
                rows.append(JournalRow(
                    segment_index=rec.segment_index, record_index=rec.record_index,
                    page_num=rec.page_num, kind="Freeblock (deleted)", rowid=None, values=None,
                    raw=fb["data"],
                    file_offset=rec.page_offset + content_offset,
                    byte_length=len(fb["data"]),
                    checksum_valid=rec.checksum_valid,
                ))

            slack = extract_unallocated_space(page)
            if slack is not None:
                rows.append(JournalRow(
                    segment_index=rec.segment_index, record_index=rec.record_index,
                    page_num=rec.page_num, kind="Unallocated slack", rowid=None, values=None,
                    raw=slack["data"],
                    file_offset=rec.page_offset + slack["offset"],
                    byte_length=slack["size"],
                    checksum_valid=rec.checksum_valid,
                ))

    return rows
