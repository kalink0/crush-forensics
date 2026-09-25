"""The browsed tree shows every stored entry under its stored name: dotfile
names kept (TAR), every one of several same-named entries (TAR, ZIP, 7z),
symbolic links and special files as what they are, never followed, and a
folder that can't be listed doesn't break the whole source."""
from __future__ import annotations

import io
import os
import plistlib
import sqlite3
import stat
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import pytest

from crush.core import vfs as vfs_module
from crush.core.vfs import (
    DirectoryVFS,
    FileVFS,
    ITunesBackupVFS,
    SevenZipVFS,
    TarVFS,
    VFSNode,
    ZipVFS,
    open_vfs,
)


def _children(node: VFSNode) -> dict[str, VFSNode]:
    return {c.name: c for c in node.children}


def _tar(path: Path, mode: str = "w") -> Path:
    with tarfile.open(path, mode) as tf:
        for name, data in [
            ("./.bashrc", b"a"), (".nomedia", b""), ("dir/.hidden/x.txt", b"x"),
            ("dup.txt", b"old"), ("dup.txt", b"new!"),
        ]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/data/secret"
        tf.addfile(link)
        hard = tarfile.TarInfo("hard")
        hard.type = tarfile.LNKTYPE
        hard.linkname = "dir/.hidden/x.txt"
        tf.addfile(hard)
        fifo = tarfile.TarInfo("fifo")
        fifo.type = tarfile.FIFOTYPE
        tf.addfile(fifo)
    return path


# -- TAR ------------------------------------------------------------------------

@pytest.mark.parametrize("mode", ["w", "w:gz"])
def test_tar_keeps_leading_dots(tmp_path: Path, mode: str) -> None:
    vfs = TarVFS(_tar(tmp_path / "t.tar", mode))
    names = _children(vfs.root())
    assert ".bashrc" in names and ".nomedia" in names
    assert "bashrc" not in names and "nomedia" not in names
    assert ".hidden" in _children(names["dir"])


@pytest.mark.parametrize("mode", ["w", "w:gz"])
def test_tar_shows_every_same_named_member(tmp_path: Path, mode: str) -> None:
    vfs = TarVFS(_tar(tmp_path / "t.tar", mode))
    names = _children(vfs.root())
    first, second = names["dup.txt"], names["dup.txt (2)"]
    assert (vfs.read(first), vfs.read(second)) == (b"old", b"new!")
    assert (vfs.peek(first, 8), vfs.peek(second, 8)) == (b"old", b"new!")
    assert (first.size, second.size) == (3, 4)
    assert "occurrence 1 of 2" in str(first.status) and "occurrence 2 of 2" in str(second.status)


def test_tar_links_and_special_files(tmp_path: Path) -> None:
    vfs = TarVFS(_tar(tmp_path / "t.tar"))
    names = _children(vfs.root())
    assert str(names["link"].status).startswith("Symbolic link → /data/secret")
    assert vfs.read(names["link"]) == b"/data/secret"
    assert str(names["hard"].status) == "Hard link to dir/.hidden/x.txt"
    assert vfs.read(names["hard"]) == b"x"
    assert str(names["fifo"].status) == "Special file (FIFO) — no content stored"
    assert vfs.read(names["fifo"]) == b""


# -- ZIP ------------------------------------------------------------------------

def test_zip_shows_every_same_named_entry_with_its_own_bytes(tmp_path: Path) -> None:
    path = tmp_path / "z.zip"
    with pytest.warns(UserWarning), zipfile.ZipFile(path, "w") as zf:
        zf.writestr("dup.txt", b"old")
        zf.writestr("dup.txt", b"new!")
    vfs = ZipVFS(path)
    names = _children(vfs.root())
    first, second = names["dup.txt"], names["dup.txt (2)"]
    assert (first.size, vfs.read(first)) == (3, b"old")
    assert (second.size, vfs.read(second)) == (4, b"new!")
    assert "occurrence 2 of 2" in str(second.status)


def test_zip_marks_symbolic_links(tmp_path: Path) -> None:
    path = tmp_path / "z.zip"
    with zipfile.ZipFile(path, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, "/data/secret")
        zf.writestr(".bashrc", b"a")
    vfs = ZipVFS(path)
    names = _children(vfs.root())
    assert str(names["link"].status).startswith("Symbolic link")
    assert vfs.read(names["link"]) == b"/data/secret"
    assert str(names[".bashrc"].status) == ""


# -- 7z -------------------------------------------------------------------------

def test_7z_shows_every_same_named_entry_with_its_own_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    py7zr = pytest.importorskip("py7zr")
    path = tmp_path / "s.7z"
    with py7zr.SevenZipFile(path, "w") as zf:
        zf.writestr(b"old", "dup.txt")
        zf.writestr(b"mid", "other.txt")
        zf.writestr(b"new!", "dup.txt")
    vfs = SevenZipVFS(path)
    names = _children(vfs.root())
    assert vfs.read(names["dup.txt"]) == b"old"
    assert vfs.read(names["dup.txt (2)"]) == b"new!"
    assert "occurrence 2 of 2" in str(names["dup.txt (2)"].status)

    prefetched = SevenZipVFS(path)
    assert prefetched.prefetch_all()
    assert prefetched.read(_children(prefetched.root())["dup.txt (2)"]) == b"new!"

    # Large-entry path: staged in a temp file, still the right occurrence.
    monkeypatch.setattr(vfs_module, "STREAM_THRESHOLD", 0)
    spooled = SevenZipVFS(path)
    spooled._read_cache.clear()
    with spooled.open(_children(spooled.root())["dup.txt (2)"]) as fh:
        assert fh.read() == b"new!"


# -- Folders --------------------------------------------------------------------

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="symlinks/FIFOs need POSIX")


@posix_only
def test_folder_symbolic_links_are_shown_not_followed(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("x")
    os.symlink("/etc/hostname", tmp_path / "link")
    os.symlink(tmp_path, tmp_path / "loop")  # would recurse forever if followed
    os.symlink("/does/not/exist", tmp_path / "broken")  # used to fail the whole open
    vfs = DirectoryVFS(tmp_path)
    names = _children(vfs.root())
    for name, target in (("link", "/etc/hostname"), ("loop", str(tmp_path)),
                         ("broken", "/does/not/exist")):
        node = names[name]
        assert not node.is_dir
        assert str(node.status).startswith(f"Symbolic link → {target}")
        assert vfs.read(node) == target.encode()


@posix_only
def test_folder_fifo_is_never_read(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "pipe")
    vfs = DirectoryVFS(tmp_path)
    node = _children(vfs.root())["pipe"]
    assert str(node.status) == "Special file (FIFO) — no content is read"
    assert vfs.read(node) == b""  # a real read would block forever


@posix_only
@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root can list anything")
def test_unlistable_folder_does_not_fail_the_source(tmp_path: Path) -> None:
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "secret.txt").write_text("s")
    (tmp_path / "ok.txt").write_text("ok")
    locked.chmod(0)
    try:
        vfs = DirectoryVFS(tmp_path)
    finally:
        locked.chmod(0o700)
    names = _children(vfs.root())
    assert str(names["locked"].status).startswith("Folder could not be listed: ")
    assert vfs.read(names["ok.txt"]) == b"ok"


# -- Access times ---------------------------------------------------------------

@pytest.mark.skipif(sys.platform != "linux", reason="O_NOATIME is Linux-only")
def test_folder_notes_files_it_cannot_protect_from_atime_updates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "a.txt").write_text("x")
    (tmp_path / "b.txt").write_text("y")
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)  # not the owner
    monkeypatch.setattr(vfs_module, "_read_only_mount", lambda _p: False)
    vfs = DirectoryVFS(tmp_path)
    assert str(vfs.load_note).startswith("2 file(s) are not owned by the current user")


@pytest.mark.skipif(sys.platform != "linux", reason="O_NOATIME is Linux-only")
def test_owned_folder_and_archives_get_no_atime_note(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root reads everything with O_NOATIME")
    (tmp_path / "a.txt").write_text("x")
    assert DirectoryVFS(tmp_path).load_note == ""
    archive = tmp_path / "x.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("a", "b")
    assert open_vfs(archive).load_note == ""  # only the container's atime, not its files'


@pytest.mark.skipif(sys.platform != "linux", reason="O_NOATIME is Linux-only")
def test_single_file_not_owned_gets_atime_note(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "evidence.bin"
    path.write_bytes(bytes(64))
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)
    monkeypatch.setattr(vfs_module, "_read_only_mount", lambda _p: False)
    vfs = open_vfs(path)
    assert isinstance(vfs, FileVFS)
    assert "access time" in str(vfs.load_note)


# -- iTunes backup ----------------------------------------------------------------

def _mbfile_blob(target: str) -> bytes:
    """A symbolic link's `Files.file` NSKeyedArchiver blob (MBFile)."""
    root = {"Target": plistlib.UID(2), "$class": plistlib.UID(3)}
    objects = ["$null", root, target, {"$classname": "MBFile", "$classes": ["MBFile", "NSObject"]}]
    return plistlib.dumps({
        "$archiver": "NSKeyedArchiver", "$version": 100000,
        "$top": {"root": plistlib.UID(1)}, "$objects": objects,
    }, fmt=plistlib.FMT_BINARY)


def test_itunes_symbolic_link_and_missing_content(itunes_backup_fixture: Path) -> None:
    conn = sqlite3.connect(itunes_backup_fixture / "Manifest.db")
    conn.execute("INSERT INTO Files VALUES (?, ?, ?, ?, ?)", (
        "a" * 40, "HomeDomain", "Library/link", 4, _mbfile_blob("/var/mobile/x"),
    ))
    conn.execute("INSERT INTO Files VALUES (?, ?, ?, ?, ?)", (
        "b" * 40, "HomeDomain", "Library/gone.txt", 1, b"",
    ))
    conn.commit()
    conn.close()

    vfs = ITunesBackupVFS(itunes_backup_fixture)
    library = _children(_children(vfs.root())["HomeDomain"])["Library"]
    names = _children(library)
    assert str(names["link"].status) == "Symbolic link → /var/mobile/x (content shown is the target)"
    assert vfs.read(names["link"]) == b"/var/mobile/x"
    assert str(names["gone.txt"].status).startswith("No content stored in the backup")


# -- Disk images (qnxprobe walk) --------------------------------------------------

class _FakeWalker:
    """listdir/entry over a dict tree: name -> (mode, size, children|None)."""

    def __init__(self, tree: dict[str, Any]) -> None:
        self._nodes: dict[int, tuple[int, int, dict[str, Any] | None]] = {}
        self._root = self._add(stat.S_IFDIR, 0, tree)

    def _add(self, mode: int, size: int, children: dict[str, Any] | None) -> int:
        handle = len(self._nodes)
        self._nodes[handle] = (mode, size, None)
        kids = None
        if children is not None:
            kids = {name: self._add(*spec) for name, spec in children.items()}
        self._nodes[handle] = (mode, size, kids)
        return handle

    def listdir(self, handle: int) -> list[tuple[str, int]]:
        return list((self._nodes[handle][2] or {}).items())

    def entry(self, handle: int) -> tuple[int, int, float]:
        mode, size, _ = self._nodes[handle]
        return mode, size, 0.0


def test_raw_walk_keeps_links_and_specials_and_types_devices_right() -> None:
    from crush.core.raw_image import _walk_into

    walker = _FakeWalker({
        "file": (stat.S_IFREG, 3, None),
        "link": (stat.S_IFLNK, 9, None),
        "blockdev": (stat.S_IFBLK, 0, None),  # shares the S_IFDIR bit
        "sock": (stat.S_IFSOCK, 0, None),
    })
    root = VFSNode(name="vol", path="/vol", is_dir=True)
    read_map: dict[str, Any] = {}
    _walk_into(walker, walker._root, root, read_map, "/vol", set())
    names = _children(root)
    assert set(names) == {"file", "link", "blockdev", "sock"}
    assert not names["blockdev"].is_dir and not names["sock"].is_dir
    assert str(names["link"].status).startswith("Symbolic link")
    assert str(names["blockdev"].status).startswith("Special file")
    assert read_map["/vol/link"].stored == b""


def test_raw_walk_marks_the_depth_guard() -> None:
    from crush.core.raw_image import _MAX_DEPTH, _walk_into

    tree: dict[str, Any] = {}
    level = tree
    for _ in range(_MAX_DEPTH + 3):
        child: dict[str, Any] = {}
        level["d"] = (stat.S_IFDIR, 0, child)
        level = child
    walker = _FakeWalker(tree)
    root = VFSNode(name="vol", path="/vol", is_dir=True)
    _walk_into(walker, walker._root, root, {}, "/vol", set())
    node = root
    while node.children:
        node = node.children[0]
    assert str(node.status).startswith(f"Not listed: nested deeper than {_MAX_DEPTH} directories")
