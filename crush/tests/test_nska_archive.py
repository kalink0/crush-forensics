# SPDX-License-Identifier: Apache-2.0
"""NSKeyedArchiver object-graph counts (crush/parsers/nska_archive.py), their
Properties rows from the plist parser, and the Tree/Text viewer's Archive tab."""
from __future__ import annotations

import plistlib
from pathlib import Path

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
    archive = _graph()
    archive["$version"] = 1  # ccl_bplist resolves $version 100000 only
    result = _parse(tmp_path, "a.plist", plistlib.dumps(archive, fmt=plistlib.FMT_BINARY))

    meta = result.metadata
    assert meta["Status"].code == "plist.nska_failed"
    assert meta["Missing references"] == "1"
    assert result.viewer_hints["archive"] == result.data


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
    return tabs.widget([tabs.tabText(i) for i in range(tabs.count())].index("Object table"))


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
    must be as complete as the Object table."""
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

    tree = TreeViewer({"obj": {"a": 1, "$class": {"$classname": "NSDate"}}})
    obj = tree._model.index(0, 0)
    assert set(_rows(tree, obj)) == {"a"}
    assert obj.siblingAtColumn(2).data() == "NSDate"


def test_viewer_adds_the_archive_tab_only_when_given(qapp) -> None:  # noqa: ARG001
    from crush.viewers.tree_text_viewer import TreeTextViewer

    with_archive = TreeTextViewer({"a": 1}, raw_text="", archive=_graph())
    labels = [with_archive._tabs.tabText(i) for i in range(with_archive._tabs.count())]
    assert labels == ["Decoded", "Object table", "Text"]

    without = TreeTextViewer({"a": 1}, raw_text="")
    assert [without._tabs.tabText(i) for i in range(without._tabs.count())] == ["Decoded", "Text"]
