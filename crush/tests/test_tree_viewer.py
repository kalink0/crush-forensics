# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for TreeViewer (crush/viewers/tree_viewer.py)."""
from __future__ import annotations

import pytest

from crush.viewers import tree_viewer
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


def _expand(qapp, widget: TreeViewer, index) -> None:
    """Expand as a click does: the view builds the rows in its layout pass."""
    widget.show()
    widget._tree.expand(index)
    qapp.processEvents()


def _visible(widget: TreeViewer, index) -> bool:
    return not widget._tree.isRowHidden(index.row(), index.parent())


@pytest.fixture
def no_initial_expand(monkeypatch: pytest.MonkeyPatch) -> None:
    """Open trees fully collapsed, so every row below the top is unbuilt."""
    monkeypatch.setattr(tree_viewer, "_INITIAL_EXPAND_ROWS", 0)


def test_small_tree_opens_two_levels_expanded(qapp) -> None:
    widget = TreeViewer({"outer": {"inner": {"deeper": {"leaf": 1}}}})
    outer = widget._model.index(0, 0)
    inner = widget._model.index(0, 0, outer)
    deeper = widget._model.index(0, 0, inner)

    assert widget._tree.isExpanded(outer)
    assert widget._tree.isExpanded(inner)
    assert deeper.data() == "deeper"
    assert not widget._tree.isExpanded(deeper)
    assert widget._model.rowCount(deeper) == 0  # not built yet ...
    assert widget._model.hasChildren(deeper)  # ... but shown as expandable


def test_large_top_level_list_opens_collapsed_and_unbuilt(qapp) -> None:
    records = [{"id": i, "v": f"value {i}"} for i in range(tree_viewer._INITIAL_EXPAND_ROWS)]
    widget = TreeViewer(records)

    assert widget._model.rowCount() == len(records)
    first = widget._model.index(0, 0)
    assert not widget._tree.isExpanded(first)
    assert widget._model.rowCount(first) == 0
    assert first.siblingAtColumn(1).data() == "(2 keys)"


def test_second_level_over_the_budget_stays_collapsed(qapp) -> None:
    records = [{"id": i, "v": i} for i in range(tree_viewer._INITIAL_EXPAND_ROWS // 2 + 1)]
    widget = TreeViewer({"records": records})
    top = widget._model.index(0, 0)

    assert widget._tree.isExpanded(top)
    assert widget._model.rowCount(top) == len(records)
    first = widget._model.index(0, 0, top)
    assert not widget._tree.isExpanded(first)
    assert widget._model.rowCount(first) == 0


def test_expanding_a_row_builds_its_children(qapp, no_initial_expand) -> None:
    widget = TreeViewer({"outer": {"inner": {"leaf": 1, "list": [7, 8]}}})
    outer = widget._model.index(0, 0)
    _expand(qapp, widget, outer)
    inner = widget._model.index(0, 0, outer)
    assert widget._model.rowCount(inner) == 0

    _expand(qapp, widget, inner)

    assert _child_keys(widget, inner) == ["leaf", "list"]
    assert widget._model.index(0, 1, inner).data() == "1"
    assert widget._model.index(1, 1, inner).data() == "(2 items)"


def test_expand_all_builds_every_row(qapp, no_initial_expand) -> None:
    widget = TreeViewer({"a": {"b": {"c": {"d": "deep"}}}})

    widget._expand_all()

    idx = widget._model.index(0, 0)
    for key in ("b", "c", "d"):
        idx = widget._model.index(0, 0, idx)
        assert idx.data() == key
    assert idx.siblingAtColumn(1).data() == "deep"


def test_class_metadata_rows_stay_hidden_when_built_on_demand(qapp, no_initial_expand) -> None:
    obj = {"$class": {"$classname": "NSDate"}, "time": 1.5}
    widget = TreeViewer({"outer": {"date": obj}})
    outer = widget._model.index(0, 0)
    _expand(qapp, widget, outer)
    date = widget._model.index(0, 0, outer)

    _expand(qapp, widget, date)

    assert date.siblingAtColumn(1).data() == "(1 keys)"
    assert date.siblingAtColumn(2).data() == "NSDate"
    assert _child_keys(widget, date) == ["time"]


def test_filter_finds_a_hit_in_rows_not_built_yet(qapp, no_initial_expand) -> None:
    widget = TreeViewer({"root": {"a": {"deep": {"x": "needle"}}, "b": {"deep": {"x": "hay"}}}})
    root = widget._model.index(0, 0)
    assert widget._model.rowCount(root) == 0

    widget._apply_filter("NEEDLE")

    a = widget._model.index(0, 0, root)
    b = widget._model.index(1, 0, root)
    deep = widget._model.index(0, 0, a)
    hit = widget._model.index(0, 0, deep)
    assert hit.siblingAtColumn(1).data() == "needle"
    assert _visible(widget, a) and _visible(widget, deep) and _visible(widget, hit)
    assert not _visible(widget, b)
    assert widget._model.rowCount(b) == 0  # no hit there: still not built

    widget._apply_filter("")
    assert _visible(widget, b)


def test_filter_matches_generated_value_text_in_rows_not_built_yet(qapp, no_initial_expand) -> None:
    widget = TreeViewer({"root": {"a": {"blob": b"\x00" * 3}, "b": {"n": 1}}})

    widget._apply_filter("<blob 3 b>")

    root = widget._model.index(0, 0)
    assert _visible(widget, widget._model.index(0, 0, root))
    assert not _visible(widget, widget._model.index(1, 0, root))


def test_rows_built_while_a_filter_is_active_are_filtered(qapp, no_initial_expand) -> None:
    widget = TreeViewer({"root": {"match": {"keep": "x", "drop": "y"}}})
    widget._apply_filter("match")
    root = widget._model.index(0, 0)
    match = widget._model.index(0, 0, root)
    assert widget._model.rowCount(match) == 0  # the hit is the row itself

    _expand(qapp, widget, root)
    _expand(qapp, widget, match)

    assert _child_keys(widget, match) == ["keep", "drop"]
    assert not _visible(widget, widget._model.index(0, 0, match))
    assert not _visible(widget, widget._model.index(1, 0, match))


def test_subtree_search_answers_each_container_once_per_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On the way down to a hit the filter asks again at every level it
    builds; the answers from the first walk are reused, not walked again."""
    inner = {"x": "needle"}
    middle = {"inner": inner}
    outer = {"middle": middle}
    fp = tree_viewer._FilterPass("needle")
    assert tree_viewer._subtree_matches(outer, fp)
    assert fp.seen[id(middle)] and fp.seen[id(inner)]

    def fail(*_args):  # noqa: ANN002, ANN202
        raise AssertionError("walked again")

    monkeypatch.setattr(tree_viewer, "_child_entries", fail)
    assert tree_viewer._subtree_matches(middle, fp)
    assert tree_viewer._subtree_matches(inner, fp)


@pytest.mark.parametrize(
    "translation",
    [
        None,  # UI in English
        {"({count} keys)": "({count} Schlüssel)", "({count} items)": "({count} Einträge)",
         "<BLOB {size:,} B>": "<BLOB {size:,} B>"},
        {"({count} keys)": "({anzahl} Schlüssel)"},  # broken placeholder -> English
    ],
)
def test_filter_sees_the_same_value_text_as_the_cell(
    monkeypatch: pytest.MonkeyPatch, translation: dict[str, str] | None
) -> None:
    """The filter's text for rows not built yet must equal what the Value
    cell will show, in the UI language, or a hit is missed or invented."""
    from crush.viewers import generated_text

    if translation is not None:
        def fake(template: str) -> str:
            return translation.get(template, template)

        monkeypatch.setattr(generated_text, "gen_text", fake)
        monkeypatch.setattr(tree_viewer, "gen_text", fake)

    values = [
        {"a": 1, "$class": {"$classname": "X"}}, [1, 2, 3], b"\x00" * 1234, "text", 42, None,
    ]
    translated: dict[str, str] = {}
    for value in values:
        assert tree_viewer._display_value_text(value, translated) == tree_viewer._value_texts(value)[1]


def test_hex_offset_selects_a_row_not_built_yet(qapp, no_initial_expand) -> None:
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
