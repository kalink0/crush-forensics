# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for TreeViewer (crush/viewers/tree_viewer.py)."""
from __future__ import annotations

from crush.viewers.tree_viewer import TreeViewer

_UINT64_MAX = (1 << 64) - 1


def _select_only_row(widget: TreeViewer) -> None:
    index = widget._model.index(0, 0)
    widget._tree.setCurrentIndex(index)


def test_scalar_uint64_max_does_not_crash_and_roundtrips(qapp) -> None:
    """A bare int in the uint64 range (e.g. an NSKeyedArchiver UID) must not
    make Qt's QVariant conversion raise OverflowError while building the
    tree, and must still be retrievable afterwards."""
    widget = TreeViewer({"uid": _UINT64_MAX})
    _select_only_row(widget)
    obj, key = widget._current_obj_and_key()
    assert key == "uid"
    assert obj == _UINT64_MAX


def test_dict_containing_uint64_max_does_not_crash_and_roundtrips(qapp) -> None:
    widget = TreeViewer({"outer": {"value": _UINT64_MAX}})
    _select_only_row(widget)
    obj, key = widget._current_obj_and_key()
    assert key == "outer"
    assert obj == {"value": _UINT64_MAX}


def test_list_containing_uint64_max_does_not_crash_and_roundtrips(qapp) -> None:
    widget = TreeViewer({"items": [_UINT64_MAX]})
    _select_only_row(widget)
    obj, key = widget._current_obj_and_key()
    assert key == "items"
    assert obj == [_UINT64_MAX]


def test_optional_hex_view_is_hidden_by_default_and_toggles(qapp) -> None:
    widget = TreeViewer({"value": "decoded"}, raw=b"\x08\x2a")

    assert widget._hex_toggle_btn is not None
    assert widget._hex_toggle_btn.text() == "Show Hex"
    assert widget._mapped_view is not None
    assert not widget._mapped_view.is_hex_visible()

    widget._toggle_hex_view()

    assert widget._hex_toggle_btn.text() == "Hide Hex"
    assert widget._mapped_view.is_hex_visible()


def test_optional_hex_view_can_start_visible(qapp) -> None:
    widget = TreeViewer({"value": "decoded"}, raw=b"\x08\x2a", hex_visible=True)

    assert widget._hex_toggle_btn is not None
    assert widget._hex_toggle_btn.text() == "Hide Hex"
    assert widget._mapped_view is not None
    assert widget._mapped_view.is_hex_visible()


def test_optional_hex_view_uses_tree_path_byte_ranges(qapp) -> None:
    widget = TreeViewer(
        {"value": "decoded"},
        raw=b"\x0a\x07decoded",
        byte_ranges_by_path={
            ("value",): {
                "byte_range": (0, 9),
                "highlight_ranges": [(0, 1), (1, 2), (2, 9)],
            },
        },
    )

    widget._toggle_hex_view()
    widget._tree.setCurrentIndex(widget._model.index(0, 0))

    assert widget._mapped_view is not None
    assert widget._mapped_view.hex_viewer._focus_range == (0, 1)
    assert widget._mapped_view.hex_viewer._focus_ranges == [(0, 1), (1, 2), (2, 9)]


# --- rows built on demand (issue #127) ---

def _child_keys(widget: TreeViewer, index) -> list[str]:
    model = widget._model
    return [model.index(row, 0, index).data() for row in range(model.rowCount(index))]


def _visible(widget: TreeViewer, index) -> bool:
    return not widget._tree.isRowHidden(index.row(), index.parent())


def test_only_the_top_level_is_built_and_expanded_on_open(qapp) -> None:
    widget = TreeViewer({"outer": {"inner": {"leaf": 1}}})
    outer = widget._model.index(0, 0)

    assert widget._tree.isExpanded(outer)
    assert _child_keys(widget, outer) == ["inner"]
    inner = widget._model.index(0, 0, outer)
    assert not widget._tree.isExpanded(inner)
    assert widget._model.rowCount(inner) == 0  # not built yet ...
    assert widget._model.hasChildren(inner)  # ... but shown as expandable


def test_expanding_a_row_builds_its_children(qapp) -> None:
    widget = TreeViewer({"outer": {"inner": {"leaf": 1, "list": [7, 8]}}})
    inner = widget._model.index(0, 0, widget._model.index(0, 0))

    widget._tree.expand(inner)

    assert _child_keys(widget, inner) == ["leaf", "list"]
    assert widget._model.index(0, 1, inner).data() == "1"
    assert widget._model.index(1, 1, inner).data() == "(2 items)"


def test_expand_all_builds_every_row(qapp) -> None:
    widget = TreeViewer({"a": {"b": {"c": {"d": "deep"}}}})

    widget._expand_all()

    idx = widget._model.index(0, 0)
    for key in ("b", "c", "d"):
        idx = widget._model.index(0, 0, idx)
        assert idx.data() == key
    assert idx.siblingAtColumn(1).data() == "deep"


def test_class_metadata_rows_stay_hidden_when_built_on_demand(qapp) -> None:
    obj = {"$class": {"$classname": "NSDate"}, "time": 1.5}
    widget = TreeViewer({"outer": {"date": obj}})
    date = widget._model.index(0, 0, widget._model.index(0, 0))

    widget._tree.expand(date)

    assert date.siblingAtColumn(1).data() == "(1 keys)"
    assert date.siblingAtColumn(2).data() == "NSDate"
    assert _child_keys(widget, date) == ["time"]


def test_filter_finds_a_hit_in_rows_not_built_yet(qapp) -> None:
    widget = TreeViewer({"root": {"a": {"deep": {"x": "needle"}}, "b": {"deep": {"x": "hay"}}}})
    root = widget._model.index(0, 0)
    a = widget._model.index(0, 0, root)
    b = widget._model.index(1, 0, root)
    assert widget._model.rowCount(a) == 0

    widget._apply_filter("NEEDLE")

    deep = widget._model.index(0, 0, a)
    hit = widget._model.index(0, 0, deep)
    assert hit.siblingAtColumn(1).data() == "needle"
    assert _visible(widget, a) and _visible(widget, deep) and _visible(widget, hit)
    assert not _visible(widget, b)
    assert widget._model.rowCount(b) == 0  # no hit there: still not built

    widget._apply_filter("")
    assert _visible(widget, b)


def test_filter_matches_generated_value_text_in_rows_not_built_yet(qapp) -> None:
    widget = TreeViewer({"root": {"a": {"blob": b"\x00" * 3}, "b": {"n": 1}}})

    widget._apply_filter("<blob 3 b>")

    root = widget._model.index(0, 0)
    assert _visible(widget, widget._model.index(0, 0, root))
    assert not _visible(widget, widget._model.index(1, 0, root))


def test_rows_built_while_a_filter_is_active_are_filtered(qapp) -> None:
    widget = TreeViewer({"root": {"match": {"keep": "x", "drop": "y"}}})
    widget._apply_filter("match")
    match = widget._model.index(0, 0, widget._model.index(0, 0))
    assert widget._model.rowCount(match) == 0  # the hit is the row itself

    widget.show()
    widget._tree.expand(match)
    # Hiding rows defers the view's layout; expand() then only records the
    # row and the rows are built by that layout pass, as in the running app.
    qapp.processEvents()

    assert _child_keys(widget, match) == ["keep", "drop"]
    assert not _visible(widget, widget._model.index(0, 0, match))
    assert not _visible(widget, widget._model.index(1, 0, match))


def test_hex_offset_selects_a_row_not_built_yet(qapp) -> None:
    widget = TreeViewer(
        {"outer": {"inner": {"leaf": 42}}},
        raw=bytes(16),
        byte_ranges_by_path={
            ("outer",): {"byte_range": (0, 16)},
            ("outer", "inner"): {"byte_range": (4, 12)},
            ("outer", "inner", "leaf"): {"byte_range": (8, 10)},
        },
    )
    assert widget._mapped_view is not None

    widget._mapped_view._select_deepest_item_for_offset(9)

    current = widget._tree.currentIndex()
    assert current.data() == "leaf"
    assert current.parent().data() == "inner"


def test_tree_text_viewer_builds_the_text_tab_when_first_shown(qapp) -> None:
    from crush.viewers.text_viewer import TextView
    from crush.viewers.tree_text_viewer import TreeTextViewer

    widget = TreeTextViewer({"a": 1}, raw_text=b"<a>1</a>")
    assert widget.findChild(TextView) is None

    widget._tabs.setCurrentIndex(1)

    text_view = widget.findChild(TextView)
    assert text_view is not None
    assert text_view._raw_text == "<a>1</a>"
