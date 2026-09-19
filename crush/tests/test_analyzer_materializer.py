# SPDX-License-Identifier: Apache-2.0
"""Tests for MainWindow's selective materializer used by "Run Analyzer"
(crush/ui/main_window.py) and the cleanup-on-failure fix to the shared
_materialize_directory_node_for_external it's a sibling of.

Motivated by a real failure: the original implementation copied a
right-clicked node's *entire* subtree before running an analyzer module,
even though a module only ever reads a handful of specific files -- on a
real full OS image this extracted far more than needed and hit "No space
left on device" (a 30G RAM-backed tmpfs, filled by two orphaned partial
extractions the original exception handler never cleaned up)."""
from __future__ import annotations

from pathlib import Path

from crush.core.vfs import DirectoryVFS
from crush.ui.main_window import MainWindow


def test_export_vfs_tree_matching_extracts_only_matching_files(
    qapp, tmp_path: Path
) -> None:
    root_dir = tmp_path / "image_root"
    frontboard = root_dir / "private" / "var" / "mobile" / "Library" / "FrontBoard"
    frontboard.mkdir(parents=True)
    (frontboard / "applicationState.db").write_bytes(b"DBDATA")
    dcim = root_dir / "private" / "var" / "mobile" / "Media" / "DCIM"
    dcim.mkdir(parents=True)
    (dcim / "IMG_0001.jpg").write_bytes(b"irrelevant photo data")

    vfs = DirectoryVFS(root_dir)
    root_node = vfs.root()
    dest = tmp_path / "out"

    win = MainWindow()
    try:
        win._export_vfs_tree_matching(root_node, vfs, dest, ["applicationState.db*"])

        extracted_files = [p for p in dest.rglob("*") if p.is_file()]
        assert len(extracted_files) == 1
        assert extracted_files[0].name == "applicationState.db"
        assert extracted_files[0].read_bytes() == b"DBDATA"
    finally:
        win.close()


def test_materialize_matching_files_returns_real_path_unchanged_for_directory_vfs(
    qapp, tmp_path: Path
) -> None:
    root_dir = tmp_path / "already_real"
    root_dir.mkdir()
    (root_dir / "applicationState.db").write_bytes(b"x")

    vfs = DirectoryVFS(root_dir)
    root_node = vfs.root()

    win = MainWindow()
    try:
        resolved = win._materialize_matching_files_for_external(
            root_node, vfs, ["applicationState.db*"]
        )
        assert resolved == (root_dir, None)
    finally:
        win.close()


def test_materialize_directory_node_cleans_up_tmp_dir_on_failure(
    qapp, tmp_path: Path, monkeypatch
) -> None:
    """A partially-written tmp_dir must never survive a failed extraction
    (e.g. disk full partway through) -- the original code left one behind
    on every failure, discovered when two such orphaned directories filled
    a 30G tmpfs after a real "No space left on device" error."""
    import crush.ui.main_window as main_window_module

    class _NotADirectoryVFS:
        """Deliberately unrelated to DirectoryVFS, so the isinstance()
        fast-path is skipped without needing to fake a real archive VFS."""

        def total_size(self, node) -> int:
            return 0

    created: dict[str, Path] = {}
    original_mkdtemp = main_window_module.tempfile.mkdtemp

    def _tracking_mkdtemp(*args, **kwargs):
        path = original_mkdtemp(*args, **kwargs)
        created["tmp_dir"] = Path(path)
        return path

    monkeypatch.setattr(main_window_module.tempfile, "mkdtemp", _tracking_mkdtemp)

    win = MainWindow()
    try:
        def _boom(node, vfs, dest):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(win, "_export_vfs_tree", _boom)

        fake_node = type("Node", (), {"name": "root"})()
        result = win._materialize_directory_node_for_external(fake_node, _NotADirectoryVFS())

        assert result is None
        assert "tmp_dir" in created
        assert not created["tmp_dir"].exists()
    finally:
        win.close()
