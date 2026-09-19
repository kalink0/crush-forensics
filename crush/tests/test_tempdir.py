# SPDX-License-Identifier: Apache-2.0
"""Central temp-directory configuration and free-space / RAM-backed checks."""
from __future__ import annotations

from collections import namedtuple
from pathlib import Path
from types import SimpleNamespace

import pytest

from crush.core import tempdir

_Usage = namedtuple("_Usage", "total used free")

_MOUNTINFO = "\n".join(
    [
        "22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw",
        "23 22 0:21 / /tmp rw,nosuid,nodev shared:2 - tmpfs tmpfs rw,size=30656768k",
        "24 22 259:3 / /home rw,relatime shared:3 - btrfs /dev/nvme0n1p3 rw",
        "25 24 0:30 / /home/x/RAM\\040disk rw shared:4 - tmpfs tmpfs rw",
    ]
)


@pytest.fixture(autouse=True)
def _reset() -> None:
    tempdir.configure(None)
    yield
    tempdir.configure(None)


def test_root_defaults_to_os_temp_and_honours_configuration(tmp_path: Path) -> None:
    assert tempdir.configured_root() is None
    tempdir.configure(tmp_path / "custom")
    assert tempdir.root() == tmp_path / "custom"
    made = tempdir.mkdtemp(prefix="t-")
    assert made.parent == tmp_path / "custom" and made.is_dir()
    fd, name = tempdir.mkstemp(prefix="t-", suffix=".db")
    import os

    os.close(fd)
    assert Path(name).parent == tmp_path / "custom"
    with tempdir.spool_file() as spool:
        spool.write(b"x")
    tempdir.configure("   ")
    assert tempdir.configured_root() is None


def test_unusable_root_raises_instead_of_falling_back(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x")
    tempdir.configure(blocker / "sub")
    with pytest.raises(OSError):
        tempdir.mkdtemp()


def test_mount_lookup_uses_longest_matching_mount() -> None:
    """Pure string logic, so it holds on every OS the tests run on."""
    assert tempdir._fs_type_for("/tmp/crush-x", _MOUNTINFO) == "tmpfs"
    assert tempdir._fs_type_for("/var/tmp/x", _MOUNTINFO) == "ext4"
    assert tempdir._fs_type_for("/home/kalinko/cache", _MOUNTINFO) == "btrfs"
    assert tempdir._fs_type_for("/home/x/RAM disk/sub", _MOUNTINFO) == "tmpfs"
    assert tempdir._fs_type_for("/tmpfoo/x", _MOUNTINFO) == "ext4"  # "/tmp" must not match "/tmpfoo"
    assert tempdir._fs_type_for("/tmp", "") is None


def test_filesystem_type_is_none_off_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tempdir, "sys", SimpleNamespace(platform="win32"))
    assert tempdir.filesystem_type(Path("/tmp")) is None


def _patch_env(
    monkeypatch: pytest.MonkeyPatch, *, free: int, fs: str | None, mem: int | None
) -> None:
    monkeypatch.setattr(tempdir.shutil, "disk_usage", lambda _p: _Usage(0, 0, free))
    monkeypatch.setattr(tempdir, "filesystem_type", lambda _p: fs)
    monkeypatch.setattr(tempdir, "_mem_available", lambda: mem)


GIB = 1024**3


def test_check_space_blocks_when_too_small(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    tempdir.configure(tmp_path)
    _patch_env(monkeypatch, free=5 * GIB, fs="ext4", mem=None)
    check = tempdir.check_space(17 * GIB)
    assert not check.enough_space
    assert not check.ram_backed and not check.ram_warning


def test_check_space_ok_on_disk(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    tempdir.configure(tmp_path)
    _patch_env(monkeypatch, free=100 * GIB, fs="ext4", mem=None)
    check = tempdir.check_space(17 * GIB)
    assert check.enough_space and not check.ram_warning


def test_ram_backed_warns_only_for_large_share_of_memory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    tempdir.configure(tmp_path)
    _patch_env(monkeypatch, free=29 * GIB, fs="tmpfs", mem=40 * GIB)
    big = tempdir.check_space(17 * GIB)
    assert big.enough_space and big.ram_backed and big.ram_warning
    small = tempdir.check_space(1 * GIB)
    assert small.ram_backed and not small.ram_warning


def test_ram_backed_with_unknown_memory_always_warns(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    tempdir.configure(tmp_path)
    _patch_env(monkeypatch, free=29 * GIB, fs="tmpfs", mem=None)
    assert tempdir.check_space(1024).ram_warning
