# SPDX-License-Identifier: Apache-2.0
"""NSKeyedArchiver object-graph counts (crush/parsers/nska_archive.py), their
Properties rows from the plist parser, and the Tree/Text viewer's Archive tab."""
from __future__ import annotations

import plistlib
from pathlib import Path

import pytest

from crush.core.issues import ParseIssue
from crush.core.vfs import DirectoryVFS
from crush.parsers.nska_archive import archive_stats
from crush.parsers.plist_parser import PlistParser

UID = plistlib.UID


def _archive(objects: list, top: dict | None = None) -> dict:
    return {
        "$archiver": "NSKeyedArchiver",
        "$version": 100000,
        "$top": top if top is not None else {"root": UID(1)},
        "$objects": objects,
    }


def _graph() -> dict:
    """root dict -> two keys -> the same string (shared); two dicts of one
    class (shared class definition); one orphan; one dangling UID."""
    return _archive(
        [
            "$null",
            {"NS.keys": [UID(2), UID(3)], "NS.objects": [UID(4), UID(4)], "$class": UID(5)},
            "a",
            "b",
            "same value",
            {"$classname": "NSDictionary", "$classes": ["NSDictionary", "NSObject"]},
            "orphan",
        ],
        top={"root": UID(1), "extra": UID(99)},
    )


def test_counts_shared_unreachable_and_missing() -> None:
    stats = archive_stats(_graph())

    assert stats is not None
    assert stats.objects == 7
    assert stats.shared == 1  # "same value", referenced twice
    assert stats.shared_classes == 0  # NSDictionary referenced once here
    assert stats.unreachable == 1  # "orphan"
    assert stats.missing_references == 1  # $top["extra"] -> UID 99
    assert stats.top_keys == ("root", "extra")


def test_class_definitions_are_counted_apart_from_data_objects() -> None:
    cls = {"$classname": "NSMutableArray", "$classes": ["NSMutableArray", "NSArray", "NSObject"]}
    archive = _archive([
        "$null",
        {"NS.objects": [UID(2), UID(3)], "$class": UID(4)},
        {"NS.objects": [], "$class": UID(4)},
        {"NS.objects": [], "$class": UID(4)},
        cls,
    ])

    stats = archive_stats(archive)

    assert stats is not None
    assert (stats.shared, stats.shared_classes) == (0, 1)


def test_null_slot_is_neither_shared_nor_unreachable() -> None:
    """Apple's archiver puts "$null" at index 0 and writes every nil as UID 0."""
    archive = _archive(["$null", {"a": UID(0), "b": UID(0)}])
    stats = archive_stats(archive)
    assert stats is not None
    assert (stats.shared, stats.unreachable) == (0, 0)

    unreferenced = archive_stats(_archive(["$null", "root only"]))
    assert unreferenced is not None
    assert unreferenced.unreachable == 0


def test_cycles_terminate_and_count_as_reachable() -> None:
    archive = _archive(["$null", {"next": UID(2)}, {"next": UID(1)}])
    stats = archive_stats(archive)
    assert stats is not None
    assert stats.unreachable == 0
    assert stats.shared == 1  # object 1: from $top and from object 2
    assert stats.has_cycle


def test_cycle_is_found_also_self_reference_and_unreachable() -> None:
    def has_cycle(objects: list) -> bool:
        stats = archive_stats(_archive(objects))
        assert stats is not None
        return stats.has_cycle

    assert has_cycle(["$null", {"self": UID(1)}])
    # Not reachable from $top -- still in the table, still a cycle.
    assert has_cycle(["$null", "root", {"a": UID(3)}, {"b": UID(2)}])


def test_shared_objects_without_a_cycle_are_no_cycle() -> None:
    """Two paths to one object (shared) is a diamond, not a cycle."""
    stats = archive_stats(_graph())
    assert stats is not None and stats.shared == 1
    assert not stats.has_cycle
    diamond = _archive(["$null", {"l": UID(2), "r": UID(3)}, {"x": UID(4)}, {"x": UID(4)}, "leaf"])
    stats = archive_stats(diamond)
    assert stats is not None and not stats.has_cycle


def test_xml_uid_form_is_recognised_exactly() -> None:
    """XML plists write a UID as a dict whose only entry is CF$UID with an
    integer (CoreFoundation's CFPropertyList.c); anything else is data."""
    archive = _archive(
        [
            "$null",
            {"a": {"CF$UID": 2}, "b": {"CF$UID": 3, "other": 1}, "c": {"CF$UID": True}},
            "reached",
            "not reached",
        ],
        top={"root": {"CF$UID": 1}},
    )
    stats = archive_stats(archive)
    assert stats is not None
    assert stats.unreachable == 1  # "not reached": {"CF$UID": 3, ...} is no UID


def test_no_graph_when_objects_or_top_malformed() -> None:
    assert archive_stats({"$archiver": "NSKeyedArchiver", "$objects": {}, "$top": {}}) is None
    assert archive_stats({"$archiver": "NSKeyedArchiver", "$objects": [], "$top": []}) is None


# --- plist parser ---


def _xml(archive: dict) -> bytes:
    """*archive* as an XML plist, UIDs in their XML form {"CF$UID": n}."""
    def convert(value):  # noqa: ANN001, ANN202
        if isinstance(value, UID):
            return {"CF$UID": value.data}
        if isinstance(value, dict):
            return {k: convert(v) for k, v in value.items()}
        if isinstance(value, list):
            return [convert(v) for v in value]
        return value

    return plistlib.dumps(convert(archive), fmt=plistlib.FMT_XML)


def _parse(tmp_path: Path, name: str, payload: bytes):
    (tmp_path / name).write_bytes(payload)
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == name)
    return PlistParser().parse(node, vfs)


def _resolvable_graph() -> dict:
    """_graph() without the dangling UID, so ccl_bplist can resolve it."""
    archive = _graph()
    archive["$top"] = {"root": UID(1), "extra": UID(3)}
    return archive


def test_binary_archive_gets_counts_and_the_archive_for_its_own_tab(tmp_path: Path) -> None:
    archive = _resolvable_graph()
    result = _parse(tmp_path, "a.plist", plistlib.dumps(archive, fmt=plistlib.FMT_BINARY))

    meta = result.metadata
    assert meta["Format"] == "binary (NSKeyedArchiver)"
    assert meta["Objects"] == "7"
    # "same value" (twice from root) and "b" (from root and $top["extra"])
    assert meta["Shared objects"] == ParseIssue("plist.nska_shared", {"count": 2, "classes": 0})
    assert meta["Unreachable objects"] == "1"
    assert meta["Missing references"] == "0"
    assert meta["Top keys"] == "extra, root"  # file order (plistlib writes keys sorted)
    # Decoded shows the resolved root only; the archive tab gets all of it.
    assert result.data == {"a": "same value", "b": "same value"}
    stored = result.viewer_hints["archive"]
    assert sorted(stored["$top"]) == ["extra", "root"]
    assert len(stored["$objects"]) == 7


def test_xml_archive_is_marked_unresolved_and_counted(tmp_path: Path) -> None:
    result = _parse(tmp_path, "a.plist", _xml(_resolvable_graph()))

    meta = result.metadata
    assert meta["Format"] == ParseIssue("plist.format_nska_xml")
    assert meta["Status"] == ParseIssue("plist.nska_xml_unresolved")
    # Same graph, same counts as the binary form.
    assert meta["Shared objects"] == ParseIssue("plist.nska_shared", {"count": 2, "classes": 0})
    assert meta["Unreachable objects"] == "1"
    assert meta["Top keys"] == "extra, root"  # file order (plistlib writes keys sorted)
    # Its own tab too, although Decoded shows the same: always in one place.
    assert result.viewer_hints["archive"] == result.data


def test_failed_resolution_still_counts(tmp_path: Path) -> None:
    archive = _resolvable_graph()
    archive["$version"] = 1  # ccl_bplist resolves $version 100000 only
    result = _parse(tmp_path, "a.plist", plistlib.dumps(archive, fmt=plistlib.FMT_BINARY))

    meta = result.metadata
    assert meta["Status"].code == "plist.nska_failed"
    assert meta["Unreachable objects"] == "1"
    assert result.viewer_hints["archive"] == result.data


def _chat(sender) -> dict:  # noqa: ANN001
    cls = {"$classname": "ChatMessage", "$classes": ["ChatMessage", "NSObject"]}
    return _archive(["$null", {"body": UID(2), "sender": sender, "$class": UID(3)},
                     "see you at 9", cls])


def test_reference_past_the_end_is_not_resolved_but_shown(tmp_path: Path) -> None:
    """ccl_bplist resolves lazily: a dangling UID under root used to pass
    the resolve and fail later, dropping the whole plist to hex."""
    result = _parse(tmp_path, "a.plist", plistlib.dumps(_chat(UID(99)), fmt=plistlib.FMT_BINARY))

    assert result.viewer_type == "tree_text"
    meta = result.metadata
    assert meta["Format"] == ParseIssue("plist.format_nska_unresolved")
    assert meta["Status"] == ParseIssue("plist.nska_missing_refs", {"count": 1})
    assert meta["Missing references"] == "1"
    assert meta["Root class"] == "ChatMessage"
    assert result.data == result.viewer_hints["archive"]  # Decoded shows it as stored


def test_a_failure_while_building_the_views_is_a_failed_resolve(
    tmp_path: Path, monkeypatch
) -> None:  # noqa: ANN001
    """Anything that goes wrong walking the resolved tree is reported as a
    failed resolve, not as a failed plist (hex, counts lost)."""
    from crush.parsers import plist_parser

    original = plist_parser._flatten_text

    def boom_on_the_resolved_tree(data):  # noqa: ANN001, ANN202
        if not plist_parser.is_keyed_archive(data):  # the resolved tree, not the stored archive
            raise IndexError("list index out of range")
        return original(data)

    monkeypatch.setattr(plist_parser, "_flatten_text", boom_on_the_resolved_tree)
    result = _parse(tmp_path, "a.plist", plistlib.dumps(_chat(UID(2)), fmt=plistlib.FMT_BINARY))

    assert result.viewer_type == "tree_text"
    assert result.metadata["Status"].code == "plist.nska_failed"
    assert result.metadata["Objects"] == "4"


def test_root_class_row(tmp_path: Path) -> None:
    from crush.parsers.nska_archive import root_class

    assert root_class(_chat(UID(2))) == "ChatMessage"
    assert root_class(_archive(["$null"], top={"x": UID(0)})) == ParseIssue("plist.nska_root_none")
    assert root_class(_archive(["$null", "text"])) == ParseIssue(
        "plist.nska_root_plain", {"type": "str"}
    )
    assert root_class(_archive(["$null"], top={"root": UID(5)})) == ParseIssue(
        "plist.nska_root_missing"
    )
    # The class definition is there but names no class: not "missing".
    no_name = _archive(["$null", {"$class": UID(2)}, {"$classes": ["X"]}])
    assert root_class(no_name) == ParseIssue("plist.nska_root_no_classname")
    # root stored in $top itself, not referenced.
    assert root_class(_archive(["$null"], top={"root": "inline"})) == ParseIssue(
        "plist.nska_root_plain", {"type": "str"}
    )


def test_cyclic_archive_is_not_resolved_and_says_why(tmp_path: Path) -> None:
    """A parent <-> child cycle used to fail in the Text tab's JSON and read
    "deserialization failed"; it's a valid archive, only not resolvable."""
    cls = {"$classname": "Node", "$classes": ["Node", "NSObject"]}
    archive = _archive(["$null", {"$class": UID(3), "child": UID(2)},
                        {"$class": UID(3), "parent": UID(1)}, cls])
    result = _parse(tmp_path, "a.plist", plistlib.dumps(archive, fmt=plistlib.FMT_BINARY))

    meta = result.metadata
    assert meta["Format"] == ParseIssue("plist.format_nska_unresolved")
    assert meta["Status"] == ParseIssue("plist.nska_cycle")
    assert meta["Root class"] == "Node"
    assert meta["Objects"] == "4"
    assert result.data is result.viewer_hints["archive"]  # Decoded shows it as stored


def test_missing_reference_and_cycle_are_both_named(tmp_path: Path) -> None:
    archive = _archive(["$null", {"self": UID(1), "gone": UID(9)}])
    result = _parse(tmp_path, "a.plist", plistlib.dumps(archive, fmt=plistlib.FMT_BINARY))

    status = result.metadata["Status"]
    assert [issue.code for issue in status] == ["plist.nska_missing_refs", "plist.nska_cycle"]


def test_decoded_top_level_hides_the_root_class_reference(qapp, tmp_path: Path) -> None:  # noqa: ARG001
    from crush.viewers.tree_text_viewer import TreeTextViewer

    result = _parse(tmp_path, "a.plist", plistlib.dumps(_chat(UID(2)), fmt=plistlib.FMT_BINARY))
    viewer = TreeTextViewer(result.data, **result.viewer_hints)
    decoded = viewer._tabs.widget(0)
    keys = [decoded._model.index(r, 0).data() for r in range(decoded._model.rowCount())]
    assert keys == ["body", "sender"]


def test_plain_plist_has_no_archive_rows(tmp_path: Path) -> None:
    result = _parse(tmp_path, "a.plist", plistlib.dumps({"k": 1}, fmt=plistlib.FMT_BINARY))
    assert "Objects" not in result.metadata
    assert "archive" not in result.viewer_hints


def test_empty_top_says_so(tmp_path: Path) -> None:
    result = _parse(tmp_path, "a.plist", _xml(_archive(["$null"], top={})))
    assert result.metadata["Top keys"] == ParseIssue("plist.nska_top_empty")


# --- viewer ---


def _object_table(viewer):  # noqa: ANN001, ANN202
    tabs = viewer._tabs
    return tabs.widget([tabs.tabText(i) for i in range(tabs.count())].index("Stored archive"))


def _rows(tree, index) -> dict[str, object]:  # noqa: ANN001
    """key -> index of each child row of *index*, building it first."""
    item = tree._model.itemFromIndex(index)
    tree._populate_children(item)
    model = tree._model
    return {model.index(r, 0, index).data(): model.index(r, 0, index) for r in range(model.rowCount(index))}


def test_object_table_keeps_class_references_and_definitions(qapp) -> None:  # noqa: ARG001
    """The stored view shows $class on every object and $classname/$classes
    in each class definition -- the resolved tree hides them as metadata."""
    from crush.viewers.tree_text_viewer import TreeTextViewer

    archive = _archive([
        "$null",
        {"NS.string": "hello", "$class": UID(2)},
        {"$classname": "NSString", "$classes": ["NSString", "NSObject"]},
    ])
    viewer = TreeTextViewer({"decoded": 1}, raw_text="", archive=archive)
    tree = _object_table(viewer)
    top = {tree._model.index(r, 0).data(): tree._model.index(r, 0)
           for r in range(tree._model.rowCount())}

    objects = _rows(tree, top["$objects"])
    assert set(_rows(tree, objects["1"])) == {"NS.string", "$class"}
    definition = _rows(tree, objects["2"])
    assert set(definition) == {"$classname", "$classes"}
    assert definition["$classname"].siblingAtColumn(1).data() == "NSString"
    assert objects["2"].siblingAtColumn(1).data() == "(2 keys)"

    tree._apply_filter("nsstring")  # the filter sees those rows too
    assert not tree._tree.isRowHidden(objects["2"].row(), objects["2"].parent())


def test_unresolved_archive_keeps_class_rows_in_decoded_too(qapp, tmp_path: Path) -> None:  # noqa: ARG001
    """An XML archive isn't resolved: Decoded shows the stored archive, so it
    must be as complete as the Stored archive tab."""
    from crush.viewers.tree_text_viewer import TreeTextViewer

    archive = _archive([
        "$null",
        {"NS.string": "hello", "$class": UID(2)},
        {"$classname": "NSString", "$classes": ["NSString", "NSObject"]},
    ])
    result = _parse(tmp_path, "a.plist", _xml(archive))
    viewer = TreeTextViewer(result.data, **result.viewer_hints)
    decoded = viewer._tabs.widget(0)
    top = {decoded._model.index(r, 0).data(): decoded._model.index(r, 0)
           for r in range(decoded._model.rowCount())}
    objects = _rows(decoded, top["$objects"])
    assert set(_rows(decoded, objects["1"])) == {"NS.string", "$class"}


def test_decoded_tree_still_hides_class_metadata(qapp) -> None:  # noqa: ARG001
    from crush.viewers.tree_viewer import TreeViewer

    tree = TreeViewer({"obj": {"a": 1, "$class": {"$classname": "NSDate"}}}, fold_class_meta=True)
    obj = tree._model.index(0, 0)
    assert set(_rows(tree, obj)) == {"a"}
    assert obj.siblingAtColumn(2).data() == "NSDate"


def test_resolved_archive_folds_class_metadata_in_decoded(qapp, tmp_path: Path) -> None:  # noqa: ARG001
    from crush.viewers.tree_text_viewer import TreeTextViewer

    # A root object of an app's own class keeps its $class after resolving.
    archive = _archive([
        "$null",
        {"$class": UID(2), "body": "hi"},
        {"$classname": "ChatMessage", "$classes": ["ChatMessage", "NSObject"]},
    ])
    result = _parse(tmp_path, "a.bplist", plistlib.dumps(archive, fmt=plistlib.FMT_BINARY))
    assert result.metadata["Format"] == "binary (NSKeyedArchiver)"
    viewer = TreeTextViewer(result.data, **result.viewer_hints)
    decoded = viewer._tabs.widget(0)
    top = [decoded._model.index(r, 0).data() for r in range(decoded._model.rowCount())]
    assert top == ["body"]


def test_class_meta_keys_are_ordinary_data_outside_a_resolved_archive(qapp, tmp_path: Path) -> None:  # noqa: ARG001
    """JSON, XML or a plain plist may hold keys named $class / $classes /
    $classname: they're data there and must be shown, counted and typed as
    such -- only a tree resolved from an NSKeyedArchiver archive folds them."""
    from crush.viewers.tree_text_viewer import TreeTextViewer
    from crush.viewers.tree_viewer import TreeViewer

    data = {"$class": "Evidence", "id": 7, "nested": {"$classname": "X", "$class": {"$classname": "Y"}, "v": 1}}
    plain = TreeViewer(data)
    top = {plain._model.index(r, 0).data(): plain._model.index(r, 0) for r in range(plain._model.rowCount())}
    assert set(top) == {"$class", "id", "nested"}
    nested = top["nested"]
    assert set(_rows(plain, nested)) == {"$classname", "$class", "v"}
    assert nested.siblingAtColumn(1).data() == "(3 keys)"
    assert nested.siblingAtColumn(2).data() == "dict"  # no class name taken from data

    plain._apply_filter("evidence")
    assert not plain._tree.isRowHidden(top["$class"].row(), top["$class"].parent())

    result = _parse(tmp_path, "plain.plist", plistlib.dumps(data, fmt=plistlib.FMT_BINARY))
    assert "archive" not in result.viewer_hints
    viewer = TreeTextViewer(result.data, **result.viewer_hints)
    decoded = viewer._tabs.widget(0)
    assert "$class" in [decoded._model.index(r, 0).data() for r in range(decoded._model.rowCount())]


# --- BLOB Inspector: same view as a plist file ---


@pytest.fixture
def blob_panel():  # noqa: ANN201
    """A _BlobPanel for *data*, deleted at the end of the test: left to the
    garbage collector, a panel's pending signals reached a later test."""
    import shiboken6

    from crush.viewers.blob_inspector import _BlobPanel

    panels: list = []

    def make(data: bytes):  # noqa: ANN202
        panels.append(_BlobPanel(data))
        return panels[-1]

    yield make
    for panel in panels:
        shiboken6.delete(panel)


def _plist_page_tabs(panel) -> list[str]:  # noqa: ANN001
    tabs = panel._plist_view._tabs
    return [tabs.tabText(i) for i in range(tabs.count())]


def _summary_lines(panel) -> list[str]:  # noqa: ANN001
    """The summary above the Plist page as the user reads it, line by line."""
    from PySide6.QtGui import QTextDocument

    doc = QTextDocument()
    doc.setHtml(panel._plist_summary.text())
    return doc.toPlainText().replace(" ", "\n").splitlines()


def test_blob_inspector_shows_an_archive_like_a_plist_file(qapp, blob_panel) -> None:  # noqa: ARG001, ANN001
    panel = blob_panel(plistlib.dumps(_resolvable_graph(), fmt=plistlib.FMT_BINARY))
    panel._select_format("Plist / bplist")

    assert panel._stack.currentWidget() is panel._plist_page
    assert _plist_page_tabs(panel) == ["Decoded", "Stored archive", "Text"]
    first, counts = _summary_lines(panel)
    assert first == "Format: binary (NSKeyedArchiver)"
    for part in ("Objects: 7", "Unreachable objects: 1",
                 "Shared objects: 2 (plus 0 class definitions)", "Top keys: extra, root"):
        assert part in counts
    assert "<b>Format:</b>" in panel._plist_summary.text()
    # Copy keeps taking the interpretation's text.
    assert panel._viewer.toPlainText() == panel._cached_results["Plist / bplist"]


def test_blob_inspector_states_a_failed_resolution(qapp, blob_panel) -> None:  # noqa: ARG001, ANN001
    archive = _resolvable_graph()
    archive["$version"] = 1
    panel = blob_panel(plistlib.dumps(archive, fmt=plistlib.FMT_BINARY))
    panel._select_format("Plist / bplist")

    first, _counts = _summary_lines(panel)
    assert first.startswith("Format: ") and "Status: NSKeyedArchiver deserialization failed" in first
    assert "Stored archive" in _plist_page_tabs(panel)


def test_blob_inspector_summary_shows_file_values_as_text(qapp, blob_panel) -> None:  # noqa: ARG001, ANN001
    """Values come from the blob: markup in them is shown, not rendered."""
    archive = _archive(["$null", "x"], top={"root": UID(1), "<i>k</i>": UID(1)})
    panel = blob_panel(plistlib.dumps(archive, fmt=plistlib.FMT_BINARY))
    panel._select_format("Plist / bplist")

    _first, counts = _summary_lines(panel)
    assert "Top keys: <i>k</i>, root" in counts


def test_blob_inspector_plain_plist_gets_the_tree_without_archive_rows(qapp, blob_panel) -> None:  # noqa: ARG001, ANN001
    panel = blob_panel(plistlib.dumps({"k": 1}, fmt=plistlib.FMT_BINARY))
    panel._select_format("Plist / bplist")

    assert panel._stack.currentWidget() is panel._plist_page
    assert _plist_page_tabs(panel) == ["Decoded", "Text"]
    assert _summary_lines(panel) == ["Format: binary"]  # one line: no archive counts


def test_viewer_adds_the_archive_tab_only_when_given(qapp) -> None:  # noqa: ARG001
    from crush.viewers.tree_text_viewer import TreeTextViewer

    with_archive = TreeTextViewer({"a": 1}, raw_text="", archive=_graph())
    labels = [with_archive._tabs.tabText(i) for i in range(with_archive._tabs.count())]
    assert labels == ["Decoded", "Stored archive", "Text"]

    without = TreeTextViewer({"a": 1}, raw_text="")
    assert [without._tabs.tabText(i) for i in range(without._tabs.count())] == ["Decoded", "Text"]
