# SPDX-License-Identifier: Apache-2.0
"""SQLite file-structure inspection helpers.

The table viewer uses sqlite3 for logical rows. This module reads the file
format directly so a UI can show the physical header/page/cell layout and map
each item back to the bytes that produced it.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from crush.core.sqlite_wal import (
    PAGE_TYPE_INDEX_INTERIOR,
    PAGE_TYPE_INDEX_LEAF,
    PAGE_TYPE_TABLE_INTERIOR,
    PAGE_TYPE_TABLE_LEAF,
    RowByteLayout,
    build_wal_page_index,
    parse_table_leaf_page,
)


@dataclass
class StructureNode:
    label: str
    value: str = ""
    kind: str = ""
    file_kind: str = "base"
    byte_range: tuple[int, int] | None = None
    highlight_ranges: list[tuple[int, int]] = field(default_factory=list)
    children: list["StructureNode"] = field(default_factory=list)


_PAGE_TYPE_NAMES = {
    PAGE_TYPE_TABLE_INTERIOR: "table interior b-tree",
    PAGE_TYPE_TABLE_LEAF: "table leaf b-tree",
    PAGE_TYPE_INDEX_INTERIOR: "index interior b-tree",
    PAGE_TYPE_INDEX_LEAF: "index leaf b-tree",
}

_TEXT_ENCODINGS = {
    1: "UTF-8",
    2: "UTF-16le",
    3: "UTF-16be",
}


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from(">H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


def _header_field(
    data: bytes,
    offset: int,
    size: int,
    label: str,
    description: str = "",
    *,
    transform: Any = None,
) -> StructureNode:
    raw = data[offset:offset + size]
    if size == 1:
        value: Any = raw[0] if raw else 0
    elif size == 2:
        value = _u16(data, offset)
    elif size == 4:
        value = _u32(data, offset)
    else:
        value = raw.hex(" ")
    display = transform(value) if transform is not None else str(value)
    return StructureNode(
        label,
        str(display),
        description,
        byte_range=(offset, offset + size),
    )


def _page_file_location(
    page_num: int,
    page_size: int,
    wal_index: dict[int, tuple[int, bytes]],
) -> tuple[str, int]:
    if page_num in wal_index:
        return "wal", wal_index[page_num][0]
    return "base", (page_num - 1) * page_size


def _read_base_page(fh: Any, page_num: int, page_size: int) -> bytes | None:
    try:
        fh.seek((page_num - 1) * page_size)
        page = fh.read(page_size)
    except OSError:
        return None
    return page if len(page) == page_size else None


def _page_type_name(page: bytes, btree_offset: int) -> str:
    if len(page) <= btree_offset:
        return "unreadable"
    return _PAGE_TYPE_NAMES.get(page[btree_offset], f"unknown 0x{page[btree_offset]:02x}")


def _page_header_size(page_type: int) -> int:
    return 12 if page_type in (PAGE_TYPE_TABLE_INTERIOR, PAGE_TYPE_INDEX_INTERIOR) else 8


def _format_page_value(
    page_num: int,
    page: bytes,
    btree_offset: int,
    allocation: str,
    owner: str,
    file_kind: str,
) -> str:
    type_name = _page_type_name(page, btree_offset)
    cell_count = _u16(page, btree_offset + 3) if len(page) >= btree_offset + 5 else 0
    parts = [allocation, type_name, f"{cell_count} cells"]
    if owner:
        parts.append(owner)
    if file_kind == "wal":
        parts.append("WAL override")
    return "; ".join(parts)


def _make_page_header_nodes(
    page: bytes,
    page_num: int,
    page_size: int,
    btree_offset: int,
    file_kind: str,
    file_offset: int,
) -> list[StructureNode]:
    if len(page) <= btree_offset:
        return []
    page_type = page[btree_offset]
    header_size = _page_header_size(page_type)
    if len(page) < btree_offset + header_size:
        return []
    content_start = _u16(page, btree_offset + 5)
    if content_start == 0 and page_size == 65536:
        content_start_display = "65536"
    else:
        content_start_display = str(content_start)
    children = [
        StructureNode("Page type", _page_type_name(page, btree_offset), "1 byte",
                      file_kind, (file_offset + btree_offset, file_offset + btree_offset + 1)),
        StructureNode("First freeblock", str(_u16(page, btree_offset + 1)), "2 bytes",
                      file_kind, (file_offset + btree_offset + 1, file_offset + btree_offset + 3)),
        StructureNode("Cell count", str(_u16(page, btree_offset + 3)), "2 bytes",
                      file_kind, (file_offset + btree_offset + 3, file_offset + btree_offset + 5)),
        StructureNode("Cell content start", content_start_display, "2 bytes",
                      file_kind, (file_offset + btree_offset + 5, file_offset + btree_offset + 7)),
        StructureNode("Fragmented free bytes", str(page[btree_offset + 7]), "1 byte",
                      file_kind, (file_offset + btree_offset + 7, file_offset + btree_offset + 8)),
    ]
    if header_size == 12:
        children.append(
            StructureNode("Rightmost child page", str(_u32(page, btree_offset + 8)), "4 bytes",
                          file_kind, (file_offset + btree_offset + 8, file_offset + btree_offset + 12))
        )
    return [StructureNode("B-tree page header", "", "", file_kind,
                          (file_offset + btree_offset, file_offset + btree_offset + header_size),
                          children=children)]


def _cell_pointer_nodes(
    page: bytes,
    btree_offset: int,
    header_size: int,
    file_kind: str,
    file_offset: int,
) -> StructureNode | None:
    if len(page) < btree_offset + 5:
        return None
    cell_count = _u16(page, btree_offset + 3)
    ptr_start = btree_offset + header_size
    ptr_end = ptr_start + cell_count * 2
    if ptr_end > len(page):
        return None
    children = []
    for i in range(cell_count):
        off = ptr_start + i * 2
        children.append(
            StructureNode(
                f"Pointer {i}",
                str(_u16(page, off)),
                "cell offset",
                file_kind,
                (file_offset + off, file_offset + off + 2),
            )
        )
    return StructureNode(
        "Cell pointer array",
        f"{cell_count} pointers",
        "",
        file_kind,
        (file_offset + ptr_start, file_offset + ptr_end),
        children=children,
    )


def _cell_nodes(
    page: bytes,
    page_size: int,
    page_num: int,
    btree_offset: int,
    file_kind: str,
    file_offset: int,
    read_page: Any,
    column_names: list[str],
) -> StructureNode | None:
    if len(page) <= btree_offset or page[btree_offset] != PAGE_TYPE_TABLE_LEAF:
        return None
    parsed = parse_table_leaf_page(
        page,
        page_size=page_size,
        overflow_reader=read_page,
        btree_offset=btree_offset,
        want_ranges=True,
    )
    if parsed is None:
        return None
    children = []
    for i, (rowid, values, layout) in enumerate(parsed):
        page_range = (
            file_offset + layout.page_local_range[0],
            file_offset + layout.page_local_range[1],
        )
        item = StructureNode(
            f"Cell {i}",
            f"rowid {rowid}; {len(values)} values",
            "table leaf cell",
            file_kind,
            page_range,
            highlight_ranges=[page_range],
        )
        item.children.extend(_cell_layout_nodes(layout, file_kind, file_offset))
        item.children.insert(
            1,
            StructureNode(
                "Payload size",
                f"{layout.payload_size} B",
                "varint",
                file_kind,
                (file_offset + layout.payload_size_range[0],
                 file_offset + layout.payload_size_range[1]),
            ),
        )
        item.children.insert(
            2,
            StructureNode(
                "RowID",
                str(rowid),
                "varint table b-tree key",
                file_kind,
                (file_offset + layout.rowid_range[0], file_offset + layout.rowid_range[1]),
            ),
        )
        for col, (value, logical_range) in enumerate(zip(values, layout.column_logical_ranges)):
            value_text = _display_cell_value(value)
            physical = _column_physical_ranges(
                logical_range, layout, file_offset, file_kind, page_num, page_size
            )
            column_label = _column_label(col, column_names)
            item.children.append(
                StructureNode(
                    column_label,
                    value_text,
                    type(value).__name__,
                    file_kind,
                    physical[0] if physical else None,
                    highlight_ranges=physical,
                )
            )
        children.append(item)
    return StructureNode("Cells", f"{len(children)} cells", "", file_kind, None, children=children)


def _column_label(col: int, column_names: list[str]) -> str:
    if col < len(column_names):
        return f"Column {col + 1} ({column_names[col]})"
    return f"Column {col + 1}"


def _display_cell_value(value: Any) -> str:
    if isinstance(value, bytes):
        return f"<BLOB {len(value):,} B>"
    text = "" if value is None else str(value)
    return text if len(text) <= 120 else text[:117] + "..."


def _cell_layout_nodes(
    layout: RowByteLayout,
    file_kind: str,
    file_offset: int,
) -> list[StructureNode]:
    payload_start = file_offset + layout.payload_start_in_page
    return [
        StructureNode("Cell local range",
                      f"{layout.page_local_range[0]}-{layout.page_local_range[1]}",
                      "page-relative bytes", file_kind,
                      (file_offset + layout.page_local_range[0],
                       file_offset + layout.page_local_range[1])),
        StructureNode("Inline payload",
                      f"{layout.inline_payload_size} B", "", file_kind,
                      (payload_start, payload_start + layout.inline_payload_size)),
        StructureNode("Overflow segments",
                      str(len(layout.overflow_segments)), "", file_kind, None,
                      children=[
                          StructureNode(f"Overflow page {pn}", f"{size} B used")
                          for pn, size in layout.overflow_segments
                      ]),
    ]


def _column_physical_ranges(
    logical_range: tuple[int, int],
    layout: RowByteLayout,
    file_offset: int,
    file_kind: str,
    page_num: int,
    page_size: int,
) -> list[tuple[int, int]]:
    start, end = logical_range
    ranges: list[tuple[int, int]] = []
    if start < end and start < layout.inline_payload_size:
        seg_end = min(end, layout.inline_payload_size)
        base = file_offset + layout.payload_start_in_page
        ranges.append((base + start, base + seg_end))
    cursor = layout.inline_payload_size
    for overflow_page, taken in layout.overflow_segments:
        seg_start = max(start, cursor)
        seg_end = min(end, cursor + taken)
        if seg_start < seg_end and file_kind == "base":
            overflow_base = (overflow_page - 1) * page_size + 4
            ranges.append((overflow_base + seg_start - cursor, overflow_base + seg_end - cursor))
        cursor += taken
    return ranges


def _freeblock_nodes(page: bytes, btree_offset: int, file_kind: str, file_offset: int) -> StructureNode | None:
    freeblocks = _extract_page_freeblocks(page, btree_offset)
    children = []
    for i, fb in enumerate(freeblocks):
        start = file_offset + fb["offset"]
        end = start + fb["size"]
        children.append(
            StructureNode(
                f"Freeblock {i}",
                f"offset {fb['offset']}; {fb['size']} B",
                "in-page freeblock",
                file_kind,
                (start, end),
            )
        )
    return StructureNode("Freeblocks", f"{len(children)} entries", "", file_kind, None, children=children)


def _unallocated_node(page: bytes, btree_offset: int, file_kind: str, file_offset: int) -> StructureNode | None:
    entry = _extract_page_unallocated_space(page, btree_offset)
    if entry is None:
        return StructureNode("Unallocated area", "none/non-empty bytes not found", "", file_kind)
    start = file_offset + entry["offset"]
    end = start + entry["size"]
    return StructureNode(
        "Unallocated area",
        f"offset {entry['offset']}; {entry['size']} B",
        "gap between pointer array and cell content",
        file_kind,
        (start, end),
    )


def _extract_page_freeblocks(page: bytes, btree_offset: int) -> list[dict[str, Any]]:
    if len(page) < btree_offset + 8 or page[btree_offset] != PAGE_TYPE_TABLE_LEAF:
        return []

    freeblocks: list[dict[str, Any]] = []
    visited: set[int] = set()
    ptr = _u16(page, btree_offset + 1)
    budget = len(page) // 4 + 1

    while ptr and ptr not in visited and budget > 0:
        if ptr + 4 > len(page):
            break
        visited.add(ptr)
        budget -= 1

        next_ptr = _u16(page, ptr)
        size = _u16(page, ptr + 2)
        if size < 4:
            break

        end = min(ptr + size, len(page))
        freeblocks.append({"offset": ptr, "size": end - ptr, "data": bytes(page[ptr + 4:end])})
        ptr = next_ptr

    return freeblocks


def _extract_page_unallocated_space(page: bytes, btree_offset: int) -> dict[str, Any] | None:
    if len(page) < btree_offset + 8 or page[btree_offset] != PAGE_TYPE_TABLE_LEAF:
        return None

    cell_count = _u16(page, btree_offset + 3)
    content_start_raw = _u16(page, btree_offset + 5)
    content_start = content_start_raw if content_start_raw != 0 else 65536
    pointer_array_end = btree_offset + 8 + cell_count * 2

    if pointer_array_end >= content_start or content_start > len(page):
        return None

    data = bytes(page[pointer_array_end:content_start])
    if not any(data):
        return None

    return {"offset": pointer_array_end, "size": len(data), "data": data}


def build_sqlite_structure_tree(
    db_path: Path,
    page_size: int,
    page_table_map: dict[int, str],
    table_columns: dict[str, list[str]],
    freelist_entries: list[dict[str, Any]],
    wal_data: bytes | None = None,
) -> list[StructureNode]:
    """Return top-level structure nodes for a SQLite database file."""
    if page_size <= 0:
        return [StructureNode("SQLite file", "page size unavailable")]

    try:
        file_size = db_path.stat().st_size
    except OSError:
        return [StructureNode("SQLite file", "file unavailable")]

    wal_index = build_wal_page_index(wal_data, page_size)
    page_count = max(file_size // page_size, max(wal_index, default=0))
    freelist_kinds = {int(e["page"]): str(e["kind"]) for e in freelist_entries if "page" in e}

    with open(db_path, "rb") as fh:
        header = fh.read(100)
        roots = [
            StructureNode(
                "SQLite database header",
                f"{len(header)} B",
                "",
                "base",
                (0, min(100, len(header))),
                children=_database_header_nodes(header),
            )
        ]

        pages_node = StructureNode("Pages", f"{page_count:,} pages")

        def read_page(page_num: int) -> bytes | None:
            if page_num in wal_index:
                return wal_index[page_num][1]
            return _read_base_page(fh, page_num, page_size)

        for page_num in range(1, page_count + 1):
            page = read_page(page_num)
            if page is None:
                continue
            page_file_kind, page_file_offset = _page_file_location(page_num, page_size, wal_index)
            if page_num == 1:
                node_file_kind = "base"
                node_file_offset = 0
                detail_file_kind = page_file_kind
                detail_file_offset = page_file_offset
            else:
                node_file_kind = page_file_kind
                node_file_offset = page_file_offset
                detail_file_kind = page_file_kind
                detail_file_offset = page_file_offset
            btree_offset = 100 if page_num == 1 else 0
            owner = page_table_map.get(page_num, "")
            column_names = _column_names_for_page(page_num, owner, table_columns)
            allocation = _allocation_status(page_num, owner, freelist_kinds)
            page_node = StructureNode(
                f"Page {page_num}",
                _format_page_value(page_num, page, btree_offset, allocation, owner, page_file_kind),
                "database page",
                node_file_kind,
                (node_file_offset, node_file_offset + len(page)),
            )
            page_node.children.extend(
                _page_detail_nodes(
                    page,
                    page_num,
                    page_size,
                    btree_offset,
                    detail_file_kind,
                    detail_file_offset,
                    read_page,
                    column_names,
                    page_file_kind != "base",
                )
            )
            pages_node.children.append(page_node)
        roots.append(pages_node)
        return roots


def _database_header_nodes(header: bytes) -> list[StructureNode]:
    if len(header) < 100:
        return [StructureNode("Header", "truncated", byte_range=(0, len(header)))]
    return [
        StructureNode("Magic", header[:16].decode("ascii", errors="replace"), "", "base", (0, 16)),
        _header_field(header, 16, 2, "Page size", "bytes", transform=lambda v: 65536 if v == 1 else v),
        _header_field(header, 18, 1, "File format write version"),
        _header_field(header, 19, 1, "File format read version"),
        _header_field(header, 20, 1, "Reserved bytes per page"),
        _header_field(header, 21, 1, "Max embedded payload fraction"),
        _header_field(header, 22, 1, "Min embedded payload fraction"),
        _header_field(header, 23, 1, "Leaf payload fraction"),
        _header_field(header, 24, 4, "File change counter"),
        _header_field(header, 28, 4, "Database page count"),
        _header_field(header, 32, 4, "First freelist trunk page"),
        _header_field(header, 36, 4, "Freelist page count"),
        _header_field(header, 40, 4, "Schema cookie"),
        _header_field(header, 44, 4, "Schema format number"),
        _header_field(header, 48, 4, "Default page cache size"),
        _header_field(header, 52, 4, "Largest root b-tree page"),
        _header_field(header, 56, 4, "Text encoding", transform=lambda v: f"{v} ({_TEXT_ENCODINGS.get(v, 'unknown')})"),
        _header_field(header, 60, 4, "User version"),
        _header_field(header, 64, 4, "Incremental vacuum mode"),
        _header_field(header, 68, 4, "Application ID"),
        StructureNode("Reserved expansion", header[72:92].hex(" "), "", "base", (72, 92)),
        _header_field(header, 92, 4, "Version-valid-for number"),
        _header_field(header, 96, 4, "SQLite version number"),
    ]


def _allocation_status(page_num: int, owner: str, freelist_kinds: dict[int, str]) -> str:
    if page_num in freelist_kinds:
        return f"freelist {freelist_kinds[page_num]}"
    if owner:
        return "live table b-tree"
    return "unmapped/unknown"


def _column_names_for_page(
    page_num: int,
    owner: str,
    table_columns: dict[str, list[str]],
) -> list[str]:
    if page_num == 1:
        return ["type", "name", "tbl_name", "rootpage", "sql"]
    return table_columns.get(owner, [])


def _page_detail_nodes(
    page: bytes,
    page_num: int,
    page_size: int,
    btree_offset: int,
    file_kind: str,
    file_offset: int,
    read_page: Any,
    column_names: list[str],
    has_wal_override: bool = False,
) -> list[StructureNode]:
    nodes: list[StructureNode] = []
    if page_num == 1:
        nodes.append(StructureNode("Database header area", "100 B", "", "base", (0, 100)))
        if has_wal_override:
            nodes.append(
                StructureNode(
                    "Current page image",
                    "b-tree content is from latest WAL frame",
                    "WAL override",
                    file_kind,
                    (file_offset + btree_offset, file_offset + len(page)),
                )
            )
    if len(page) <= btree_offset:
        return nodes
    page_type = page[btree_offset]
    if page_type not in _PAGE_TYPE_NAMES:
        return nodes
    nodes.extend(_make_page_header_nodes(page, page_num, page_size, btree_offset, file_kind, file_offset))
    header_size = _page_header_size(page_type)
    ptrs = _cell_pointer_nodes(page, btree_offset, header_size, file_kind, file_offset)
    if ptrs is not None:
        nodes.append(ptrs)
    cells = _cell_nodes(
        page, page_size, page_num, btree_offset, file_kind, file_offset, read_page, column_names
    )
    if cells is not None:
        nodes.append(cells)
    freeblocks = _freeblock_nodes(page, btree_offset, file_kind, file_offset)
    if freeblocks is not None:
        nodes.append(freeblocks)
    unallocated = _unallocated_node(page, btree_offset, file_kind, file_offset)
    if unallocated is not None:
        nodes.append(unallocated)
    return nodes
