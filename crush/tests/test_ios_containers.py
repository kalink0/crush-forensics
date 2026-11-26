# SPDX-License-Identifier: Apache-2.0
"""iOS container folders (GUID names) shown by the identifier in their
mobile container manager metadata plist."""
from __future__ import annotations

import plistlib
import time
from pathlib import Path
from typing import Any

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel

from crush.core import ios_containers
from crush.core.issues import ParseIssue
from crush.core.session import Session
from crush.core.vfs import DirectoryVFS, VFSNode

APP_GUID = "0A1B2C3D-0000-4000-8000-000000000001"
GROUP_GUID = "0A1B2C3D-0000-4000-8000-000000000002"
PLUGIN_GUID = "0A1B2C3D-0000-4000-8000-000000000003"
SYSTEM_GUID = "0A1B2C3D-0000-4000-8000-000000000004"
PLAIN_GUID = "0A1B2C3D-0000-4000-8000-000000000005"


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
    _container(
        root / "private/var/mobile/Containers/Data/PluginKitPlugin",
        PLUGIN_GUID, "com.example.app.widget",
    )
    _container(
        root / "private/var/containers/Shared/SystemGroup",
        SYSTEM_GUID, "systemgroup.com.apple.example",
    )
    # Not a container: a GUID folder without the metadata plist.
    _container(apps, PLAIN_GUID, None)
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


@pytest.mark.parametrize("guid, identifier", [
    (APP_GUID, "com.example.app"),
    (GROUP_GUID, "group.com.example.shared"),
    (PLUGIN_GUID, "com.example.app.widget"),
    (SYSTEM_GUID, "systemgroup.com.apple.example"),
])
def test_identifier_of_any_folder_holding_the_metadata_plist(
    tmp_path: Path, guid: str, identifier: str
) -> None:
    vfs = DirectoryVFS(_device(tmp_path))
    node = _find(vfs.root(), guid)
    assert ios_containers.is_container(node)
    assert ios_containers.read_identifier(node, vfs) == identifier


def test_folder_without_metadata_plist_is_no_container(tmp_path: Path) -> None:
    vfs = DirectoryVFS(_device(tmp_path))
    node = _find(vfs.root(), PLAIN_GUID)
    assert not ios_containers.is_container(node)
    assert ios_containers.read_identifier(node, vfs) is None


def _one_container(tmp_path: Path, content: bytes) -> tuple[DirectoryVFS, VFSNode]:
    folder = tmp_path / "Containers/Data/Application" / APP_GUID
    folder.mkdir(parents=True)
    (folder / ios_containers.METADATA_PLIST).write_bytes(content)
    vfs = DirectoryVFS(tmp_path)
    return vfs, _find(vfs.root(), APP_GUID)


@pytest.mark.parametrize("content, code", [
    (b"not a plist", "ios_container.not_a_plist"),
    (plistlib.dumps({"Other": "x"}), "ios_container.no_identifier"),
    (plistlib.dumps({ios_containers.IDENTIFIER_KEY: ""}), "ios_container.no_identifier"),
    (plistlib.dumps({ios_containers.IDENTIFIER_KEY: 7}), "ios_container.no_identifier"),
    (plistlib.dumps(["com.example.app"]), "ios_container.no_identifier"),
])
def test_bad_plist_says_why_there_is_no_identifier(
    tmp_path: Path, content: bytes, code: str
) -> None:
    vfs, node = _one_container(tmp_path, content)
    assert ios_containers.is_container(node)
    result = ios_containers.read_identifier(node, vfs)
    assert isinstance(result, ParseIssue)
    assert result.code == code


def test_plist_over_the_size_limit_is_not_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = plistlib.dumps({ios_containers.IDENTIFIER_KEY: "com.example.app"})
    vfs, node = _one_container(tmp_path, content)
    monkeypatch.setattr(ios_containers, "MAX_PLIST_SIZE", len(content))
    assert ios_containers.read_identifier(node, vfs) == "com.example.app"

    monkeypatch.setattr(ios_containers, "MAX_PLIST_SIZE", len(content) - 1)
    result = ios_containers.read_identifier(node, vfs)
    assert isinstance(result, ParseIssue)
    assert result.code == "ios_container.plist_too_large"
    assert f"{len(content):,} bytes" in str(result)


def test_read_error_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    vfs, node = _one_container(tmp_path, plistlib.dumps({ios_containers.IDENTIFIER_KEY: "x"}))

    def failing_read(*_args: Any, **_kwargs: Any) -> bytes:
        raise OSError("sector 42 unreadable")

    monkeypatch.setattr(vfs, "read", failing_read)
    result = ios_containers.read_identifier(node, vfs)
    assert isinstance(result, ParseIssue)
    assert result.code == "ios_container.read_failed"
    assert "sector 42 unreadable" in str(result)


def _field(panel: Any, label: str) -> QLabel | None:
    """The value label of the Properties row *label*, None when there is none."""
    from PySide6.QtWidgets import QFormLayout

    for row in range(panel._layout.rowCount()):
        item = panel._layout.itemAt(row, QFormLayout.ItemRole.LabelRole)
        if item is not None and isinstance(item.widget(), QLabel) and item.widget().text() == label:
            return panel._layout.itemAt(row, QFormLayout.ItemRole.FieldRole).widget()
    return None


def _row(panel: Any, label: str) -> str | None:
    field = _field(panel, label)
    return None if field is None else field.text()


def test_properties_show_container_identifier(qapp: Any, widgets: Any, tmp_path: Path) -> None:
    from crush.ui.props_panel import PropertiesPanel

    vfs = DirectoryVFS(_device(tmp_path))
    panel = widgets(PropertiesPanel())
    panel.update_properties(_find(vfs.root(), PLUGIN_GUID), {}, vfs)
    assert _row(panel, "Container Identifier:") == "com.example.app.widget"

    panel.update_properties(_find(vfs.root(), PLAIN_GUID), {}, vfs)
    assert _row(panel, "Container Identifier:") is None


def test_properties_say_why_a_container_has_no_identifier(
    qapp: Any, widgets: Any, tmp_path: Path
) -> None:
    from crush.ui.props_panel import PropertiesPanel

    vfs, node = _one_container(tmp_path, plistlib.dumps({"Other": "x"}))
    panel = widgets(PropertiesPanel())
    panel.update_properties(node, {}, vfs)
    assert _row(panel, "Container Identifier:") == str(
        ParseIssue("ios_container.no_identifier", {"key": ios_containers.IDENTIFIER_KEY})
    )


def test_properties_show_identifier_as_plain_text(
    qapp: Any, widgets: Any, tmp_path: Path
) -> None:
    from crush.ui.props_panel import PropertiesPanel

    identifier = "<b>com.example</b>"
    vfs, node = _one_container(
        tmp_path, plistlib.dumps({ios_containers.IDENTIFIER_KEY: identifier})
    )
    panel = widgets(PropertiesPanel())
    panel.update_properties(node, {}, vfs)
    field = _field(panel, "Container Identifier:")
    assert field is not None
    assert field.text() == identifier
    assert field.textFormat() == Qt.TextFormat.PlainText


def test_worker_takes_an_item_put_while_its_thread_ends() -> None:
    """An item put just as the idle thread gives up still runs (the old
    is_alive() check could leave it in the queue)."""
    import queue

    from crush.ui.fs_panel import _OnDemandWorker

    done: list[int] = []
    worker: _OnDemandWorker[int] = _OnDemandWorker(done.append, None, idle=0.01)

    class RacingQueue(queue.SimpleQueue):
        """The second get() times out just as another item is put."""

        calls = 0

        def get(self, block: bool = True, timeout: float | None = None) -> int:
            RacingQueue.calls += 1
            if RacingQueue.calls == 2:
                worker.put(1)  # the thread still runs: put() starts none
                raise queue.Empty
            return super().get(block, timeout)

    worker._queue = RacingQueue()
    worker.put(0)
    deadline = time.monotonic() + 5
    while len(done) < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert done == [0, 1]


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
    plugin = _tree_item(panel, vfs, _find(vfs.root(), PLUGIN_GUID))
    plain = _tree_item(panel, vfs, _find(vfs.root(), PLAIN_GUID))

    _wait(qapp, lambda: app.text() != APP_GUID and plugin.text() != PLUGIN_GUID)
    assert app.text() == "com.example.app"
    assert APP_GUID in app.toolTip()
    assert app.font().italic()
    assert plugin.text() == "com.example.app.widget"
    assert plain.text() == PLAIN_GUID

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
    tokens = {"name": "example.shared"}

    results: list[dict] = []
    panel._collect_matches(vfs.root(), vfs, tokens, "", results, panel._search_gen, True)
    assert [r["node"].name for r in results] == [GROUP_GUID]
    assert results[0]["identifier"] == "group.com.example.shared"

    results = []
    panel._collect_matches(vfs.root(), vfs, tokens, "", results, panel._search_gen, False)
    assert results == []


def test_search_reads_each_container_plist_once(
    widgets: Any, qapp: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from crush.ui.fs_panel import FilesystemPanel

    panel = widgets(FilesystemPanel(Session()))
    vfs = DirectoryVFS(_device(tmp_path))
    reads: list[str] = []
    real_read = ios_containers.read_identifier

    def counting_read(node: VFSNode, source: Any) -> str | None:
        reads.append(node.name)
        return real_read(node, source)

    monkeypatch.setattr(ios_containers, "read_identifier", counting_read)
    for name in ("widget", "nothing-matches"):
        results: list[dict] = []
        panel._collect_matches(
            vfs.root(), vfs, {"name": name}, "", results, panel._search_gen, True
        )
    assert sorted(reads) == sorted([APP_GUID, GROUP_GUID, PLUGIN_GUID, SYSTEM_GUID])
