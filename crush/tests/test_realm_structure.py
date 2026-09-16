# SPDX-License-Identifier: Apache-2.0
"""Coverage for crush/core/realm_structure.py -- the Realm "File Structure"
tab's tree + byte-range builder, against real fixtures (this project's
synthetic-fixtures-only rule is for hand-built forensic-format edge cases;
these fixtures were already vendored for realm_parser.py's own tests and
this module deliberately reuses them rather than adding new binary blobs).

The core correctness signal used throughout: every byte_range this module
claims for a *live* array must, when sliced out of the real file, start
with Realm's own array-header checksum (b"AAAA") -- proof the offset math
lines up with the actual on-disk array graph, not just plausible-looking
numbers.
"""
from __future__ import annotations

from pathlib import Path

from crush.core.realm_structure import build_realm_structure

_FIXTURES = Path(__file__).parent / "fixtures"
_ARRAY_MAGIC = b"AAAA"


def _load(name: str) -> tuple[dict, dict, bytes]:
    data = (_FIXTURES / name).read_bytes()
    tree, ranges = build_realm_structure(data)
    return tree, ranges, data


def _all_paths(node: object, prefix: tuple[str, ...] = ()) -> list[tuple[str, ...]]:
    """Every path TreeViewer would build for *node*, matching its own
    path convention (crush/viewers/tree_viewer.py's _build_items:
    node_path = parent_path + (str(key),))."""
    paths = [prefix] if prefix else []
    if isinstance(node, dict):
        for key, value in node.items():
            paths.extend(_all_paths(value, prefix + (str(key),)))
    return paths


def test_file_header_is_the_first_24_bytes() -> None:
    tree, ranges, _data = _load("all_types_v24.realm")
    assert isinstance(tree["File header"], dict)
    assert ranges[("File header",)]["byte_range"] == (0, 24)


def test_every_live_array_range_starts_with_the_array_checksum() -> None:
    """Every claimed range except the file header and streaming footer
    (which aren't array-header-shaped) must point at a real array -- proof
    the reference-chain math (Group -> table refs -> table -> Spec/
    ClusterTree) resolves to genuine offsets, not guesses."""
    tree, ranges, data = _load("all_types_v24.realm")
    checked = 0
    for path, meta in ranges.items():
        if path[0] in ("File header", "Streaming footer"):
            continue  # fixed-layout header/footer fields, not array-shaped
        if path[0] == "Free list":
            continue  # freed blocks may be raw heap, not a live array
        start, end = meta["byte_range"]
        assert 0 <= start < end <= len(data), path
        assert data[start:start + 4] == _ARRAY_MAGIC, path
        checked += 1
    assert checked >= 10


def test_top_array_children_are_labeled_where_known() -> None:
    tree, _ranges, _data = _load("all_types_v24.realm")
    children = tree["Top array (Group)"]["Children"]
    assert "[0] Table names" in children
    assert "[1] Table refs" in children
    assert "[3] Free list positions" in children
    assert "[4] Free list sizes" in children
    assert "[5] Free list versions" in children


def test_unknown_top_array_child_is_still_shown_not_dropped() -> None:
    """An unlabeled Group slot must still appear (with a generic label),
    never silently disappear -- see feedback_explicit_unsupported_marking."""
    tree, _ranges, _data = _load("all_types_v24.realm")
    children = tree["Top array (Group)"]["Children"]
    assert any(key.endswith("unidentified") for key in children)


def test_cluster_format_table_shows_real_columns_and_cluster_leaves() -> None:
    tree, ranges, data = _load("all_types_v24.realm")
    table = tree["Tables"]["class_AllTypesRecord"]
    spec = table["Spec (columns)"]
    assert spec["stringCol"] == "string"
    assert spec["uuidCol"] == "uuid"
    assert spec["linkList"] == "link (list)"

    cluster_tree = table["ClusterTree"]
    leaves_key = next(iter(cluster_tree))
    leaves = cluster_tree[leaves_key]
    assert len(leaves) == 1
    leaf = next(iter(leaves.values()))
    assert leaf["Row count"] == 4  # fixture has 4 AllTypesRecord rows

    leaf_path = ("Tables", "class_AllTypesRecord", "ClusterTree", leaves_key, next(iter(leaves)))
    start, end = ranges[leaf_path]["byte_range"]
    assert data[start:start + 4] == _ARRAY_MAGIC


def test_pre_cluster_table_gets_real_columns_and_per_column_bplus_trees() -> None:
    """Pre-format-10 files use a structurally different layout: each column
    is its own independent top-level B+-tree rather than rows grouped into
    Clusters -- "Column B+-Trees" replaces "ClusterTree" for these tables,
    walked with the same generic B+-tree leaf walker used for modern List/
    Set collections."""
    tree, ranges, data = _load("format9_alltypes.realm")
    table = tree["Tables"]["class_AllTypes"]
    spec = table["Spec (columns)"]
    assert spec["col_string_short"] == "string"
    assert spec["col_int"] == "int"

    trees = table["Column B+-Trees"]
    assert isinstance(trees, dict)
    assert set(spec) == set(trees)  # every column gets its own B+-tree entry

    leaves_key = next(iter(trees["col_int"]))
    leaves = trees["col_int"][leaves_key]
    leaf_key = next(iter(leaves))
    assert leaves[leaf_key]["Element count"] > 0

    leaf_path = ("Tables", "class_AllTypes", "Column B+-Trees", "col_int", leaves_key, leaf_key)
    start, end = ranges[leaf_path]["byte_range"]
    assert data[start:start + 4] == _ARRAY_MAGIC


def test_streaming_form_file_gets_a_footer_section() -> None:
    tree, ranges, data = _load("streaming_form.realm")
    assert "Streaming footer" in tree
    start, end = ranges[("Streaming footer",)]["byte_range"]
    assert (start, end) == (len(data) - 16, len(data))
    # The streaming file must still resolve a usable Group top array from
    # the footer's resolved top ref, not fall back to "Unresolved".
    assert isinstance(tree["Top array (Group)"], dict)


def test_every_tree_node_has_a_highlight_range() -> None:
    """Regression test for a real bug: the first cut of this module only
    registered byte_range for a handful of "container" paths, so clicking
    most individual fields in the tree (a column's type string, a free
    block's size, a header's Mnemonic) highlighted nothing in the Hex pane
    at all. Every path TreeViewer can actually render must resolve to a
    real range now, via _fill_missing_ranges()'s container-level fallback."""
    for fixture in ("all_types_v24.realm", "format9_alltypes.realm", "streaming_form.realm"):
        tree, ranges, _data = _load(fixture)
        missing = [p for p in _all_paths(tree) if p not in ranges]
        assert not missing, f"{fixture}: paths with no highlight range: {missing[:5]}"


def test_encrypted_or_undetected_header_marks_unresolved_not_empty() -> None:
    garbage = b"\x00" * 64
    tree, ranges = build_realm_structure(garbage)
    assert tree["File header"] == "Not detected (possibly encrypted or non-standard)"
    assert ranges == {}
