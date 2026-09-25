"""SQLite page scans (Freelist Recovery, Freeblocks, Unallocated, WAL,
File Structure) say why a result is empty or partial instead of looking
like "nothing found" (parser-reason audit, part 2g)."""
from __future__ import annotations

import sqlite3
import struct
from pathlib import Path
from typing import Any

from crush.core.issues import ParseIssue
from crush.core.segb_offsets import SegbCellLocator
from crush.core.sqlite_freeblocks import extract_freeblocks, scan_database_freeblocks
from crush.core.sqlite_freelist import carve_freelist_rows, walk_freelist_pages
from crush.core.sqlite_structure import _display_cell_value
from crush.core.sqlite_unallocated import extract_unallocated_space
from crush.core.sqlite_wal import (
    _follow_overflow_chain_ex,
    build_page_table_map,
    parse_table_leaf_page,
)

PAGE = 512


def _codes(problems: list[Any]) -> list[str]:
    return [p.code for p in problems]


def _db(path: Path, pages: dict[int, bytes], count: int, first_trunk: int, freelist_count: int) -> Path:
    """A raw page image: page 1 carries the freelist header fields."""
    header = bytearray(PAGE)
    header[:16] = b"SQLite format 3\x00"
    struct.pack_into(">I", header, 32, first_trunk)
    struct.pack_into(">I", header, 36, freelist_count)
    data = bytearray(bytes(header) + bytes(PAGE * (count - 1)))
    for num, content in pages.items():
        data[(num - 1) * PAGE:(num - 1) * PAGE + len(content)] = content
    path.write_bytes(bytes(data))
    return path


def _trunk(next_trunk: int, leaves: list[int], declared: int | None = None) -> bytes:
    page = bytearray(PAGE)
    struct.pack_into(">II", page, 0, next_trunk, len(leaves) if declared is None else declared)
    for i, leaf in enumerate(leaves):
        struct.pack_into(">I", page, 8 + 4 * i, leaf)
    return bytes(page)


# -- Freelist ---------------------------------------------------------------------

def test_unreadable_file_is_not_an_empty_freelist(tmp_path: Path) -> None:
    problems: list[ParseIssue] = []
    assert walk_freelist_pages(tmp_path / "missing.db", PAGE, None, problems) == []
    assert _codes(problems) == ["sqlite_scan.file_unreadable"]


def test_header_without_freelist_says_so(tmp_path: Path) -> None:
    problems: list[ParseIssue] = []
    walk_freelist_pages(_db(tmp_path / "a.db", {}, 2, 0, 0), PAGE, None, problems)
    assert _codes(problems) == ["freelist.none"]


def test_freelist_cycle_is_reported(tmp_path: Path) -> None:
    path = _db(tmp_path / "a.db", {2: _trunk(2, [3])}, 3, 2, 5)
    problems: list[ParseIssue] = []
    entries = walk_freelist_pages(path, PAGE, None, problems)
    assert [e["page"] for e in entries] == [2, 3]
    assert ParseIssue("freelist.cycle", {"page": 2}) in problems


def test_clamped_leaf_count_is_reported(tmp_path: Path) -> None:
    path = _db(tmp_path / "a.db", {2: _trunk(0, [3], declared=10_000)}, 3, 2, 10_001)
    problems: list[ParseIssue] = []
    walk_freelist_pages(path, PAGE, None, problems)
    fits = (PAGE - 8) // 4
    assert ParseIssue("freelist.leaf_count_clamped", {
        "page": 2, "declared": 10_000, "fits": fits,
    }) in problems


def test_carve_summary_accounts_for_every_walked_page(tmp_path: Path) -> None:
    path = _db(tmp_path / "a.db", {2: _trunk(0, [3])}, 3, 2, 2)
    problems: list[ParseIssue] = []
    entries = walk_freelist_pages(path, PAGE, None, problems)
    carve_freelist_rows(path, PAGE, entries, None, problems)
    summary = next(p for p in problems if p.code == "freelist.summary")
    assert summary.params == {
        "pages": 2, "trunks": 1, "leaves": 1, "carved": 0,
        "empty": 0, "not_leaf": 2, "unreadable": 0,
    }


# -- Freeblocks / unallocated -------------------------------------------------------

def _leaf_page(freeblock: int = 0, cells: int = 0, content_start: int = PAGE) -> bytearray:
    page = bytearray(PAGE)
    page[0] = 0x0D
    struct.pack_into(">HHH", page, 1, freeblock, cells, content_start)
    return page


def test_freeblock_chain_problems_are_reported() -> None:
    page = _leaf_page(freeblock=600)
    problems: list[ParseIssue] = []
    assert extract_freeblocks(bytes(page), problems, 7) == []
    assert problems == [ParseIssue("freeblock.ptr_outside", {"page": 7, "offset": 600})]

    page = _leaf_page(freeblock=100)
    struct.pack_into(">HH", page, 100, 0, 2)
    problems = []
    extract_freeblocks(bytes(page), problems, 7)
    assert _codes(problems) == ["freeblock.too_small"]

    page = _leaf_page(freeblock=500)
    struct.pack_into(">HH", page, 500, 0, 100)
    problems = []
    blocks = extract_freeblocks(bytes(page), problems, 7)
    assert len(blocks) == 1
    assert problems == [ParseIssue("freeblock.overruns_page", {
        "page": 7, "offset": 500, "size": 100, "available": 12,
    })]


def test_bad_content_start_is_not_taken_as_no_gap() -> None:
    page = _leaf_page(content_start=1000)
    problems: list[ParseIssue] = []
    assert extract_unallocated_space(bytes(page), problems, 4) is None
    assert problems == [ParseIssue("unallocated.bad_content_start", {"page": 4, "start": 1000})]


def test_page_scan_reports_unreadable_file_and_short_last_page(tmp_path: Path) -> None:
    problems: list[ParseIssue] = []
    assert scan_database_freeblocks(tmp_path / "missing.db", PAGE, None, problems) == []
    assert _codes(problems) == ["sqlite_scan.file_unreadable"]

    path = tmp_path / "short.db"
    path.write_bytes(bytes(PAGE * 2 + 100))
    problems = []
    scan_database_freeblocks(path, PAGE, None, problems)
    assert problems == [ParseIssue("sqlite_scan.page_short", {
        "page": 3, "size": 100, "page_size": PAGE,
    })]


# -- Leaf-page cells, overflow chains, table attribution ----------------------------

def test_undecodable_cells_are_counted_not_dropped_silently() -> None:
    page = _leaf_page(cells=2, content_start=400)
    struct.pack_into(">HH", page, 8, 0, 9000)  # both pointers invalid
    problems: list[ParseIssue] = []
    assert parse_table_leaf_page(bytes(page), problems=problems, page_num=5) == []
    assert problems == [ParseIssue("sqlite_page.cells_skipped", {"page": 5, "count": 2, "total": 2})]


def test_overflow_chain_is_bounded_by_the_payload_not_a_fixed_page_count() -> None:
    usable = 8  # 4 payload bytes per overflow page
    pages = 12_000  # more than the former fixed 10,000-page cap

    def reader(num: int) -> bytes:
        nxt = num + 1 if num < pages else 0
        return struct.pack(">I", nxt) + b"abcd"

    data, segments = _follow_overflow_chain_ex(1, pages * 4, usable, reader)
    assert len(data) == pages * 4
    assert len(segments) == pages


def test_table_attribution_failure_has_a_reason() -> None:
    conn = sqlite3.connect(":memory:")
    conn.close()
    problems: list[ParseIssue] = []
    assert build_page_table_map(conn, None, PAGE, problems) == {}
    assert _codes(problems) == ["sqlite_wal.table_map_failed"]


# -- File Structure / Locate in Hex --------------------------------------------------

def test_structure_values_are_whole_and_single_line() -> None:
    text = "line1\nline2\t" + "x" * 500 + "\x01"
    shown = _display_cell_value(text)
    assert "\n" not in shown and "\t" not in shown
    assert shown.startswith("line1\\nline2\\t")
    assert shown.endswith("x\\x01")
    assert len(shown) == len(text) + 1 + 1 + 3  # "\n" and "\t" grow by one, "\x01" by three


def test_segb_locator_says_why_a_row_has_no_bytes() -> None:
    locator = SegbCellLocator(file_bytes=bytes(64), version="v2", rows=[["0", "not-an-offset"]])
    assert locator.locate_cell("SEGB", 0, None) is None
    reason = locator.why_not_located("SEGB", 0)
    assert reason is not None and reason.code == "locate.segb_record_offsets"
