# SPDX-License-Identifier: Apache-2.0
"""Realm "File Structure" tab: a raw, physical-layout browse of a .realm
file's own array/ref graph (Group top array, free list, per-table Spec and
ClusterTree), independent of the already-decoded logical Tables tab --
explicitly analogous to SQLite Table Viewer's own File Structure tab
(crush/core/sqlite_structure.py), but built directly as a nested dict + a
byte_ranges_by_path map for the generic TreeViewer (crush/viewers/
tree_viewer.py), which already knows how to render that shape with an
embedded, bidirectionally-synced Hex pane (ByteMappedTreeHex) -- the same
mechanism already used for plist/XML and the schema-based Protobuf Viewer.
No new Qt widget or lazy-loading machinery is needed: Realm's ClusterTree is
walked one node per *leaf* (not per row -- a leaf holds up to ~1000 rows),
so even a large table's tree stays small enough to build eagerly, unlike
SQLite's page-per-row-heavy File Structure tab.

All array/ref-graph knowledge is reused from realm_parser.py's public
structural-introspection API (parse_realm_header, extract_free_list,
walk_cluster_leaves, etc.) -- this module only re-derives the reference
chain (Group top array -> table refs -> table top array -> Spec/
ClusterTree), it does not re-implement array decoding.

Byte-range policy: TreeViewer looks up a highlight by the *exact* tree path
clicked (crush/viewers/tree_viewer.py's _apply_byte_range_metadata), with no
built-in fallback to a parent's range. A handful of fields have their own
literal, individually-known byte offsets (the file header's fixed layout) and
get exact per-field ranges; everything else -- a record's descriptive
sub-fields (an "Offset"/"Size" label, a column's type string, a free block's
version) -- is a value *derived from* that record's bytes without its own
separately-tracked offset, so it's tagged with the record's own overall
range via _fill_missing_ranges(). The alternative (leaving those paths
unregistered) means clicking most rows in the tree highlights nothing at
all, which is worse than a range that's real but not maximally granular.
"""
from __future__ import annotations

from typing import Any

from crush.core.issues import ParseIssue
from crush.parsers.realm_parser import (
    REALM_HEADER_SIZE,
    REALM_MIN_CLUSTER_FORMAT_VERSION,
    array_elem_bytes,
    describe_column_type,
    describe_pre_cluster_column_type,
    extract_column_info,
    extract_column_names,
    extract_free_list,
    extract_pre_cluster_spec,
    extract_root_children,
    extract_schema,
    parse_array_header,
    parse_realm_header,
    read_array_ref,
    read_cluster_key_info,
    resolve_pre_cluster_column_refs,
    resolve_streaming_form,
    walk_bplustree_leaves,
    walk_cluster_leaves,
)

# Named slots of the Group top array (group.hpp) that this codebase already
# relies on elsewhere (schema/table-refs extraction, free-list recovery).
# Any other slot still shows up, just without a friendly label -- never
# silently dropped.
_KNOWN_GROUP_CHILDREN = {
    0: "Table names",
    1: "Table refs",
    3: "Free list positions",
    4: "Free list sizes",
    5: "Free list versions",
}

StructureTree = dict[str, Any]
ByteRangesByPath = dict[tuple[str, ...], dict[str, Any]]


def _fill_missing_ranges(
    node: Any, path: tuple[str, ...], byte_range: tuple[int, int], ranges: ByteRangesByPath
) -> None:
    """Register *byte_range* for *path* and every path nested under it that
    doesn't already have a more specific one (checked first, so a range set
    by the caller before this runs -- e.g. one leaf's own precise range --
    is never overwritten by its container's broader one)."""
    ranges.setdefault(path, {"byte_range": byte_range})
    if isinstance(node, dict):
        for key, value in node.items():
            _fill_missing_ranges(value, path + (key,), byte_range, ranges)


def build_realm_structure(data: bytes) -> tuple[StructureTree, ByteRangesByPath]:
    """Return (tree, byte_ranges_by_path) ready for
    TreeViewer(tree, raw=data, byte_ranges_by_path=byte_ranges_by_path)."""
    tree: StructureTree = {}
    ranges: ByteRangesByPath = {}
    file_size = len(data)

    header = parse_realm_header(data)
    if header is None:
        tree["File header"] = ParseIssue("realm_structure.header_not_detected")
        return tree, ranges

    tree["File header"] = {k: str(v) for k, v in header.items()}
    _tag_header_fields(ranges, file_size)

    top_ref0 = int.from_bytes(data[0:8], "little")
    top_ref1 = int.from_bytes(data[8:16], "little")
    fmt0, fmt1 = data[20], data[21]
    active_idx = 1 if (data[23] & 0x01) else 0

    streaming = resolve_streaming_form(data, top_ref0, active_idx)
    if streaming is not None:
        tree["Streaming footer"] = {
            "Resolved top reference": (
                f"{streaming['top_ref']} (0x{streaming['top_ref']:x})"
                if streaming["top_ref"] is not None else ParseIssue("realm_structure.ref_unresolved")
            ),
            "Footer valid": streaming["footer_valid"],
        }
        if file_size >= REALM_HEADER_SIZE + 16:
            footer_range = (file_size - 16, file_size)
            _fill_missing_ranges(tree["Streaming footer"], ("Streaming footer",), footer_range, ranges)
        active_offset = streaming["top_ref"] if streaming["footer_valid"] else None
        active_format = fmt0
    else:
        active_offset = top_ref1 if active_idx == 1 else top_ref0
        active_format = fmt1 if active_idx == 1 else fmt0

    if not active_offset or active_offset <= 0 or active_offset >= file_size:
        tree["Top array (Group)"] = ParseIssue("realm_structure.top_unresolved")
        return tree, ranges

    top_hdr = parse_array_header(data, active_offset)
    if top_hdr is None:
        tree["Top array (Group)"] = ParseIssue("realm_structure.top_unreadable", {"offset": active_offset})
        return tree, ranges

    top_total = top_hdr["Total array bytes"]
    top_range = (active_offset, active_offset + top_total)

    children_dict: dict[str, Any] = {}
    for child in extract_root_children(data, active_offset, file_size):
        idx, off, hdr = child["index"], child["offset"], child.get("array_header")
        label = _KNOWN_GROUP_CHILDREN.get(idx, "unidentified")
        key = f"[{idx}] {label}"
        if hdr is not None:
            total = hdr["Total array bytes"]
            children_dict[key] = {
                "Offset": f"0x{off:x} ({off})",
                "Element count": hdr["Element count (size)"],
                "has_refs": hdr["has_refs"],
                "Total bytes": total,
            }
            _fill_missing_ranges(
                children_dict[key], ("Top array (Group)", "Children", key), (off, off + total), ranges
            )
        else:
            children_dict[key] = f"0x{off:x} ({off}) -- unreadable"
    tree["Top array (Group)"] = {
        "Array header": {k: str(v) for k, v in top_hdr.items()},
        "Children": children_dict,
    }
    _fill_missing_ranges(tree["Top array (Group)"], ("Top array (Group)",), top_range, ranges)

    free_blocks = extract_free_list(data, active_offset, file_size)
    if free_blocks:
        fl_dict: dict[str, Any] = {}
        for i, blk in enumerate(free_blocks):
            off, size = blk["offset"], blk["size"]
            key = f"[{i}] 0x{off:x}"
            fl_dict[key] = {
                "Offset": f"0x{off:x} ({off})",
                "Size": size,
                "Freed at DB version": blk["version"],
            }
            _fill_missing_ranges(fl_dict[key], ("Free list", key), (off, off + size), ranges)
        tree["Free list"] = fl_dict
    else:
        tree["Free list"] = "(empty)"
    # The free list itself isn't one single array (it's 3 parallel Group
    # children) -- the Group's own top array is the closest real,
    # meaningful "this data belongs to" answer for the section label itself.
    _fill_missing_ranges(tree["Free list"], ("Free list",), top_range, ranges)

    schema = extract_schema(data, active_offset, file_size)
    tables_dict: dict[str, Any] = {}
    tables_range = top_range
    if schema and top_hdr["has_refs"] and top_hdr["Element count (size)"] >= 2:
        root_eb = array_elem_bytes(top_hdr)
        table_refs_off = read_array_ref(data, active_offset + 8, 1, root_eb)
        tr_hdr = parse_array_header(data, table_refs_off) if 0 < table_refs_off < file_size else None
        if tr_hdr is not None and tr_hdr["has_refs"]:
            tables_range = (table_refs_off, table_refs_off + tr_hdr["Total array bytes"])
            tr_eb = array_elem_bytes(tr_hdr)
            for t_idx in range(tr_hdr["Element count (size)"]):
                table_name = schema[t_idx] if t_idx < len(schema) else f"table[{t_idx}]"
                table_ref = read_array_ref(data, table_refs_off + 8, t_idx, tr_eb)
                tables_dict[table_name] = _build_table_structure(
                    data, table_ref, active_format, file_size, ranges, ("Tables", table_name)
                )
    tree["Tables"] = tables_dict if tables_dict else "(no schema)"
    # "Tables" itself is the real Table Refs array's own range when resolvable
    # (a genuine array), else falls back to the Group's own range.
    _fill_missing_ranges(tree["Tables"], ("Tables",), tables_range, ranges)

    return tree, ranges


def _tag_header_fields(ranges: ByteRangesByPath, file_size: int) -> None:
    """The 24-byte file header's fields sit at fixed, individually-known
    offsets (unlike everything below the header, which is only known once
    the array graph is walked) -- give each its own exact range."""
    fields: list[tuple[str, int, int]] = [
        ("Top reference 0", 0, 8),
        ("Top reference 1", 8, 8),
        ("Mnemonic", 16, 4),
        ("File format (top ref 0)", 20, 1),
        ("File format (top ref 1)", 21, 1),
        ("Reserved", 22, 1),
        ("Flags", 23, 1),
    ]
    header_end = min(REALM_HEADER_SIZE, file_size)
    ranges[("File header",)] = {"byte_range": (0, header_end)}
    for label, offset, length in fields:
        end = min(offset + length, file_size)
        if offset < end:
            ranges[("File header", label)] = {"byte_range": (offset, end)}
    # "Active top reference" is derived from the Flags byte, not its own field.
    if file_size > 23:
        ranges[("File header", "Active top reference")] = {"byte_range": (23, min(24, file_size))}


def _build_table_structure(
    data: bytes,
    table_ref: int,
    active_format: int,
    file_size: int,
    ranges: ByteRangesByPath,
    path: tuple[str, ...],
) -> Any:
    if table_ref <= 0 or table_ref >= file_size:
        return ParseIssue("realm_structure.table_ref_invalid")

    t_hdr = parse_array_header(data, table_ref)
    if t_hdr is None or not t_hdr["has_refs"]:
        return ParseIssue("realm_structure.table_top_unreadable")

    t_eb = array_elem_bytes(t_hdr)
    t_total = t_hdr["Total array bytes"]
    table_range = (table_ref, table_ref + t_total)

    result: dict[str, Any] = {}

    if active_format < REALM_MIN_CLUSTER_FORMAT_VERSION:
        _build_pre_cluster_table_structure(data, table_ref, t_hdr, t_eb, file_size, ranges, path, result)
    else:
        col_names = extract_column_names(data, table_ref, t_eb, file_size)
        col_info = extract_column_info(data, table_ref, t_eb, file_size) or []
        spec_dict: dict[str, Any] = {}
        for i, name in enumerate(col_names):
            spec_dict[name] = describe_column_type(col_info[i]) if i < len(col_info) else "?"
        result["Spec (columns)"] = spec_dict if spec_dict else ParseIssue("realm_structure.no_columns")

        if t_hdr["Element count (size)"] < 3:
            result["ClusterTree"] = ParseIssue("realm_structure.no_cluster_tree_slot")
        else:
            cluster_root_ref = read_array_ref(data, table_ref + 8, 2, t_eb)
            if cluster_root_ref <= 0 or cluster_root_ref >= file_size:
                result["ClusterTree"] = ParseIssue("realm_structure.cluster_tree_ref_invalid")
            else:
                leaves = walk_cluster_leaves(data, cluster_root_ref, file_size)
                if not leaves:
                    result["ClusterTree"] = "(empty)"
                else:
                    leaves_path = path + ("ClusterTree", f"Leaves ({len(leaves)})")
                    leaves_dict: dict[str, Any] = {}
                    for i, (leaf_ref, key_offset) in enumerate(leaves):
                        leaf_hdr = parse_array_header(data, leaf_ref)
                        key = f"[{i}] 0x{leaf_ref:x}"
                        if leaf_hdr is None:
                            leaves_dict[key] = f"0x{leaf_ref:x} -- unreadable"
                            continue
                        leaf_eb = array_elem_bytes(leaf_hdr)
                        row_count, _local_keys = read_cluster_key_info(data, leaf_ref, leaf_eb, file_size)
                        leaf_total = leaf_hdr["Total array bytes"]
                        leaves_dict[key] = {
                            "Offset": f"0x{leaf_ref:x} ({leaf_ref})",
                            "Row count": row_count if row_count is not None else "?",
                            "Key offset (base ObjKey)": key_offset,
                            "Total bytes": leaf_total,
                        }
                        _fill_missing_ranges(
                            leaves_dict[key], leaves_path + (key,),
                            (leaf_ref, leaf_ref + leaf_total), ranges,
                        )
                    result["ClusterTree"] = {f"Leaves ({len(leaves)})": leaves_dict}

    _fill_missing_ranges(result, path, table_range, ranges)
    return result


def _build_pre_cluster_table_structure(
    data: bytes,
    table_ref: int,
    t_hdr: dict[str, Any],
    t_eb: int,
    file_size: int,
    ranges: ByteRangesByPath,
    path: tuple[str, ...],
    result: dict[str, Any],
) -> None:
    """Pre-format-10 tables (table.hpp @ v5.23.9) have no single Cluster
    tree -- each column is its own independent top-level B+-tree (m_top
    slot 1 = columns ref, one ref per column, resolved via
    resolve_pre_cluster_column_refs). "ClusterTree" here becomes "Column
    B+-Trees": one sub-branch per column, each walked with the same
    generic B+-tree leaf walker used for modern List/Set collections
    (walk_bplustree_leaves works on any BPlusTree<T> root regardless of
    the era or column type it belongs to)."""
    if t_hdr["Element count (size)"] < 2:
        result["Spec (columns)"] = "(table top array is missing its spec/columns slots)"
        result["Column B+-Trees"] = "(unavailable)"
        return

    spec_ref = read_array_ref(data, table_ref + 8, 0, t_eb)
    columns_ref = read_array_ref(data, table_ref + 8, 1, t_eb)
    if not (0 < spec_ref < file_size):
        result["Spec (columns)"] = "Spec reference is invalid or points outside the file"
        result["Column B+-Trees"] = "(unavailable)"
        return

    spec_columns = extract_pre_cluster_spec(data, spec_ref, file_size)
    if not spec_columns:
        result["Spec (columns)"] = ParseIssue("realm_structure.no_columns")
        result["Column B+-Trees"] = "(unavailable)"
        return

    result["Spec (columns)"] = {c["name"]: describe_pre_cluster_column_type(c) for c in spec_columns}

    col_refs = (
        resolve_pre_cluster_column_refs(data, columns_ref, spec_columns, file_size)
        if 0 < columns_ref < file_size else {}
    )
    if not col_refs:
        result["Column B+-Trees"] = "Columns reference is invalid or points outside the file"
        return

    trees_dict: dict[str, Any] = {}
    for col in spec_columns:
        name = col["name"]
        col_ref = col_refs.get(col["col_index"])
        if not col_ref or col_ref <= 0 or col_ref >= file_size:
            trees_dict[name] = "Column reference is invalid or points outside the file"
            continue
        leaves = walk_bplustree_leaves(data, col_ref, file_size)
        if not leaves:
            trees_dict[name] = f"0x{col_ref:x} -- unreadable"
            continue
        leaves_path = path + ("Column B+-Trees", name, f"Leaves ({len(leaves)})")
        leaves_dict: dict[str, Any] = {}
        for i, (leaf_ref, base_index) in enumerate(leaves):
            leaf_hdr = parse_array_header(data, leaf_ref)
            key = f"[{i}] 0x{leaf_ref:x}"
            if leaf_hdr is None:
                leaves_dict[key] = f"0x{leaf_ref:x} -- unreadable"
                continue
            leaf_total = leaf_hdr["Total array bytes"]
            leaves_dict[key] = {
                "Offset": f"0x{leaf_ref:x} ({leaf_ref})",
                "Element count": leaf_hdr["Element count (size)"],
                "Base index": base_index,
                "Total bytes": leaf_total,
            }
            _fill_missing_ranges(
                leaves_dict[key], leaves_path + (key,), (leaf_ref, leaf_ref + leaf_total), ranges
            )
        trees_dict[name] = {f"Leaves ({len(leaves)})": leaves_dict}
    result["Column B+-Trees"] = trees_dict
