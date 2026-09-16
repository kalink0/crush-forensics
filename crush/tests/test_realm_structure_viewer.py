# SPDX-License-Identifier: Apache-2.0
"""End-to-end regression coverage for the Realm "File Structure" tab
(crush/core/realm_structure.py), verifying the wiring through the actual
RealmViewer -> TreeViewer -> ByteMappedTreeHex widget chain (not just the
tree/byte-range builder in isolation, see test_realm_structure.py) --
mirrors test_realm_hex_provenance.py's/test_segb_hex_provenance.py's
approach of confirming real bytes are highlighted, not just that the
widget gets constructed.
"""
from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QTabWidget

from crush.core.vfs import DirectoryVFS
from crush.parsers.realm_parser import RealmParser
from crush.viewers.realm_viewer import RealmViewer
from crush.viewers.tree_viewer import TreeViewer

_FIXTURES = Path(__file__).parent / "fixtures"


def _open_structure_tab(qapp, fixture_name: str) -> tuple[TreeViewer, bytes]:  # noqa: ARG001
    fixture = _FIXTURES / fixture_name
    vfs = DirectoryVFS(fixture.parent)
    root = vfs.root()
    node = next(c for c in root.children if c.name == fixture.name)
    result = RealmParser().parse(node, vfs)

    viewer = RealmViewer(result.data)
    tabs = viewer.findChild(QTabWidget)
    assert tabs is not None
    structure_tab = next(
        tabs.widget(i) for i in range(tabs.count()) if tabs.tabText(i) == "File Structure"
    )
    assert isinstance(structure_tab, TreeViewer)
    tabs.setCurrentWidget(structure_tab)
    viewer.show()
    return structure_tab, fixture.read_bytes()


def test_file_structure_tab_uses_the_real_file_bytes(qapp) -> None:
    tv, raw = _open_structure_tab(qapp, "all_types_v24.realm")
    assert tv._raw == raw


def test_selecting_file_header_highlights_the_first_24_bytes(qapp) -> None:
    tv, _raw = _open_structure_tab(qapp, "all_types_v24.realm")
    tv._toggle_hex_view()
    tv._tree.setCurrentIndex(tv._model.index(0, 0))  # "File header" is the first root row

    assert tv._model.index(0, 0).data() == "File header"
    assert tv._mapped_view is not None
    assert tv._mapped_view.hex_viewer._focus_range == (0, 24)


def test_selecting_a_cluster_leaf_highlights_a_real_array(qapp) -> None:
    tv, raw = _open_structure_tab(qapp, "all_types_v24.realm")
    tv._toggle_hex_view()

    # Tables -> class_AllTypesRecord -> ClusterTree -> Leaves (1) -> [0] ...
    tables_idx = tv._model.index(3, 0)
    assert tv._model.data(tables_idx) == "Tables"
    tv._tree.expand(tables_idx)
    table_idx = None
    for row in range(tv._model.rowCount(tables_idx)):
        idx = tv._model.index(row, 0, tables_idx)
        if tv._model.data(idx) == "class_AllTypesRecord":
            table_idx = idx
            break
    assert table_idx is not None
    tv._tree.expand(table_idx)
    cluster_idx = None
    for row in range(tv._model.rowCount(table_idx)):
        idx = tv._model.index(row, 0, table_idx)
        if tv._model.data(idx) == "ClusterTree":
            cluster_idx = idx
            break
    assert cluster_idx is not None
    tv._tree.expand(cluster_idx)
    leaves_idx = tv._model.index(0, 0, cluster_idx)
    tv._tree.expand(leaves_idx)
    leaf_idx = tv._model.index(0, 0, leaves_idx)

    tv._tree.setCurrentIndex(leaf_idx)

    assert tv._mapped_view is not None
    start, end = tv._mapped_view.hex_viewer._focus_range
    assert raw[start:start + 4] == b"AAAA"
