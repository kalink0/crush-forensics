# SPDX-License-Identifier: Apache-2.0
"""iOS App / AppGroup container folders (GUID names) shown by the
identifier in their mobile container manager metadata plist."""
from __future__ import annotations

import plistlib
import time
from pathlib import Path
from typing import Any

import pytest

from crush.core import ios_containers
from crush.core.session import Session
from crush.core.vfs import DirectoryVFS, VFSNode

APP_GUID = "0A1B2C3D-0000-4000-8000-000000000001"
GROUP_GUID = "0A1B2C3D-0000-4000-8000-000000000002"
OTHER_GUID = "0A1B2C3D-0000-4000-8000-000000000003"


def _container(base: Path, guid: str, identifier: str | None, binary: bool = True) -> None:
    folder = base / guid
    (folder / "Documents").mkdir(parents=True)
    if identifier is not None:
        data = {ios_containers.IDENTIFIER_KEY: identifier, "MCMMetadataContentClass": 2}
        fmt = plistlib.FMT_BINARY if binary else plistlib.FMT_XML
        (folder / ios_containers.METADATA_PLIST).write_bytes(plistlib.dumps(data, fmt=fmt))


def _device(tmp_path: Path) -> Path:
    root = tmp_path / "device"
    apps = root / "private/var/mobile/Containers/Data/Application"
    groups = root / "private/var/mobile/Containers/Shared/AppGroup"
    _container(apps, APP_GUID, "com.example.app")
    _container(groups, GROUP_GUID, "group.com.example.shared", binary=False)
    # Not a container: right name, wrong place.
    _container(root / "private/var/mobile/Other", OTHER_GUID, "com.example.elsewhere")
    return root


def _find(node: VFSNode, name: str) -> VFSNode:
    if node.name == name:
        return node
    for child in node.children:
        try:
            return _find(child, name)
        except LookupError:
            pass
    raise LookupError(name)


def test_identifiers_of_app_and_app_group_containers(tmp_path: Path) -> None:
    vfs = DirectoryVFS(_device(tmp_path))
    root = vfs.root()
    assert ios_containers.read_identifier(_find(root, APP_GUID), vfs) == "com.example.app"
    assert (
        ios_containers.read_identifier(_find(root, GROUP_GUID), vfs)
        == "group.com.example.shared"
    )
    assert not ios_containers.is_container(_find(root, OTHER_GUID))
    assert ios_containers.read_identifier(_find(root, OTHER_GUID), vfs) is None


@pytest.mark.parametrize("content", [b"not a plist", plistlib.dumps({"Other": "x"})])
def test_no_identifier_from_a_bad_plist(tmp_path: Path, content: bytes) -> None:
    folder = tmp_path / "Containers/Data/Application" / APP_GUID
    folder.mkdir(parents=True)
    (folder / ios_containers.METADATA_PLIST).write_bytes(content)
    vfs = DirectoryVFS(tmp_path)
    node = _find(vfs.root(), APP_GUID)
    assert ios_containers.is_container(node)
    assert ios_containers.read_identifier(node, vfs) is None


def _wait(qapp: Any, condition: Any) -> None:
    deadline = time.monotonic() + 5
    while not condition() and time.monotonic() < deadline:
        qapp.processEvents()
        time.sleep(0.02)


def _tree_item(panel: Any, vfs: DirectoryVFS, node: VFSNode) -> Any:
    """The tree's name item of *node*, its folders loaded on the way."""
    from crush.ui.fs_panel import _ROLE_NODE

    item = panel._model.item(0, 0)
    for path_node in panel._build_node_path(node, vfs)[1:]:
        while panel._build_queue:  # folders expanded (the root) load in ticks
            panel._process_build_queue()
        panel._load_children_sync(item, item.data(_ROLE_NODE), vfs)
        item = next(
            item.child(r, 0) for r in range(item.rowCount())
            if item.child(r, 0).data(_ROLE_NODE) is path_node
        )
    return item


def test_tree_shows_identifier_and_toggles_back(qapp: Any, widgets: Any, tmp_path: Path) -> None:
    from crush.ui.fs_panel import FilesystemPanel

    panel = widgets(FilesystemPanel(Session()))
    vfs = DirectoryVFS(_device(tmp_path))
    panel.load_vfs(vfs)
    app = _tree_item(panel, vfs, _find(vfs.root(), APP_GUID))
    other = _tree_item(panel, vfs, _find(vfs.root(), OTHER_GUID))

    _wait(qapp, lambda: app.text() != APP_GUID)
    assert app.text() == "com.example.app"
    assert APP_GUID in app.toolTip()
    assert app.font().italic()
    assert other.text() == OTHER_GUID

    panel.set_show_container_names(False)
    assert app.text() == APP_GUID
    assert not app.font().italic()

    panel.set_show_container_names(True)
    assert app.text() == "com.example.app"


def test_folders_loaded_with_names_off_keep_guid_until_turned_on(
    qapp: Any, widgets: Any, tmp_path: Path
) -> None:
    from crush.ui.fs_panel import FilesystemPanel

    panel = widgets(FilesystemPanel(Session()))
    panel.set_show_container_names(False)
    vfs = DirectoryVFS(_device(tmp_path))
    panel.load_vfs(vfs)
    group = _tree_item(panel, vfs, _find(vfs.root(), GROUP_GUID))
    qapp.processEvents()
    assert group.text() == GROUP_GUID

    panel.set_show_container_names(True)
    _wait(qapp, lambda: group.text() != GROUP_GUID)
    assert group.text() == "group.com.example.shared"


def test_name_filter_matches_identifier(widgets: Any, qapp: Any, tmp_path: Path) -> None:
    from crush.ui.fs_panel import FilesystemPanel

    panel = widgets(FilesystemPanel(Session()))
    vfs = DirectoryVFS(_device(tmp_path))
    tokens = {"name": "example.app"}

    results: list[dict] = []
    panel._collect_matches(vfs.root(), vfs, tokens, "", results, panel._search_gen, True)
    assert [r["node"].name for r in results] == [APP_GUID]
    assert results[0]["identifier"] == "com.example.app"

    results = []
    panel._collect_matches(vfs.root(), vfs, tokens, "", results, panel._search_gen, False)
    assert results == []
