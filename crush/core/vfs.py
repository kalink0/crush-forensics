"""Virtual Filesystem (VFS) abstraction.

All source types (ZIP archive, directory, future: AFF4, tar) are presented
through a single interface so viewers never need to know the origin.
"""
from __future__ import annotations

import gzip
import io
import logging
import os
import plistlib
import re
import shutil
import sqlite3
import stat
import sys
import tarfile
import threading
import zipfile
import zlib
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any, Iterator, cast

from crush.core import tempdir
from crush.core.passwords import PasswordRequiredError, WrongPasswordError
from crush.core.vfs_stream import (
    COPY_CHUNK,
    STREAM_THRESHOLD,
    IterStream,
    LockedStream,
    buffered,
)

_logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from crush.core import ios_keybag

# android_backup_crypto and ios_keybag both import `cryptography`, whose
# compiled extension can fail to even load on some frozen macOS builds (a
# PyInstaller dylib-bundling quirk, not a Crush bug — see CHANGELOG). Both
# are therefore imported lazily, inside the methods that need them, so a
# broken build only fails when the user actually opens an Android/iTunes
# backup instead of crashing on startup for every source type.


class _AtimeRestoringIO:
    """Read-only file wrapper that restores atime after the file is closed (Windows).

    On Windows, os.utime() sets atime and mtime without touching ctime (creation
    time), so this is a clean atime-preserving read with no timestamp side-effects.

    Implements the full IO[bytes] interface by delegating to the wrapped file so
    that cast(IO[bytes], ...) is safe and all callers work without restriction.
    """

    def __init__(self, path: Path, f: IO[bytes], atime_ns: int, mtime_ns: int) -> None:
        self._path = path
        self._f = f
        self._atime_ns = atime_ns
        self._mtime_ns = mtime_ns

    # --- identity / metadata ---
    @property
    def name(self) -> str | int:
        return self._f.name

    @property
    def mode(self) -> str:
        return "rb"

    @property
    def closed(self) -> bool:
        return self._f.closed

    # --- positioning ---
    def seek(self, pos: int, whence: int = 0) -> int:
        return self._f.seek(pos, whence)

    def tell(self) -> int:
        return self._f.tell()

    def seekable(self) -> bool:
        return self._f.seekable()

    # --- reading ---
    def read(self, n: int = -1) -> bytes:
        return self._f.read(n)

    def readline(self, limit: int = -1) -> bytes:
        return self._f.readline(limit)

    def readlines(self, hint: int = -1) -> list[bytes]:
        return self._f.readlines(hint)

    def readable(self) -> bool:
        return True

    # --- writing (not supported) ---
    def write(self, s: bytes) -> int:
        raise io.UnsupportedOperation("write")

    def writelines(self, lines: list[bytes]) -> None:
        raise io.UnsupportedOperation("writelines")

    def writable(self) -> bool:
        return False

    def truncate(self, size: int | None = None) -> int:
        raise io.UnsupportedOperation("truncate")

    # --- misc ---
    def flush(self) -> None:
        self._f.flush()

    def fileno(self) -> int:
        return self._f.fileno()

    def isatty(self) -> bool:
        return False

    # --- iteration ---
    def __iter__(self) -> Iterator[bytes]:
        return iter(self._f)

    def __next__(self) -> bytes:
        return next(self._f)

    # --- context manager ---
    def __enter__(self) -> "_AtimeRestoringIO":
        return self

    def __exit__(self, *args: object) -> None:
        self._close()

    def close(self) -> None:
        self._close()

    def _close(self) -> None:
        self._f.close()
        try:
            os.utime(self._path, ns=(self._atime_ns, self._mtime_ns))
        except OSError as exc:
            _logger.warning("Could not restore the access time of %s: %s", self._path, exc)


def _read_noatime(path: Path) -> bytes:
    """Read a file without updating its atime where the OS supports it.

    Linux:   O_NOATIME flag; falls back to a plain read if the caller does not
             own the file or lacks CAP_FOWNER.
    Windows: save atime, read, restore atime via os.utime() (does not touch ctime).
    Others:  plain read.
    """
    if sys.platform == "linux":
        try:
            fd = os.open(str(path), os.O_RDONLY | os.O_NOATIME)
        except OSError:
            _logger.debug("O_NOATIME not permitted for %s; its access time may update", path)
            return path.read_bytes()
        with os.fdopen(fd, "rb") as f:
            return f.read()
    if sys.platform == "win32":
        st = path.stat()
        data = path.read_bytes()
        try:
            os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))
        except OSError as exc:
            _logger.warning("Could not restore the access time of %s: %s", path, exc)
        return data
    return path.read_bytes()


def _open_noatime(path: Path) -> IO[bytes]:
    """Open a file for reading without updating its atime where the OS supports it.

    Linux:   O_NOATIME flag; falls back to a plain open if not permitted.
    Windows: returns an _AtimeRestoringIO that restores atime on close.
    Others:  plain open.
    """
    if sys.platform == "linux":
        try:
            fd = os.open(str(path), os.O_RDONLY | os.O_NOATIME)
        except OSError:
            _logger.debug("O_NOATIME not permitted for %s; its access time may update", path)
            return open(path, "rb")
        return os.fdopen(fd, "rb")
    if sys.platform == "win32":
        st = path.stat()
        return cast(IO[bytes], _AtimeRestoringIO(path, open(path, "rb"), st.st_atime_ns, st.st_mtime_ns))
    return open(path, "rb")


@dataclass
class VFSNode:
    """A single node in the virtual filesystem tree."""
    name: str
    path: str          # Full virtual path e.g. "/var/mobile/Library/SMS/sms.db"
    is_dir: bool
    size: int = 0
    modified: float = 0.0
    accessed: float = 0.0
    changed: float = 0.0
    birth: float = 0.0
    children: list[VFSNode] = field(default_factory=list)
    # What the analyst must know about this entry that its name and bytes
    # don't show: a symbolic link, one of several entries stored under the
    # same name, a directory that couldn't be listed ... "" when nothing.
    status: str = ""

    @property
    def extension(self) -> str:
        return Path(self.name).suffix.lower()


class VFS(ABC):
    """Abstract virtual filesystem."""

    # Set by open_vfs() when the source didn't open the way its name or
    # content suggested (e.g. named .zip but no ZIP signature, a UFDR shown
    # as plain ZIP, a disk image that couldn't be read); the UI must
    # surface it.
    fallback_note: str = ""
    # Said once when the source is loaded, not with every file opened from
    # it (e.g. that reading may update the evidence files' access times).
    load_note: str = ""

    @abstractmethod
    def root(self) -> VFSNode: ...

    @abstractmethod
    def read(self, node: VFSNode) -> bytes: ...

    @abstractmethod
    def open(self, node: VFSNode) -> IO[bytes]: ...

    def close(self) -> None:
        """Optional cleanup for VFS implementations."""
        return None

    @abstractmethod
    def file_count(self, node: VFSNode) -> int:
        """Return number of files under node (including the node if it's a file)."""
        ...

    @abstractmethod
    def total_size(self, node: VFSNode) -> int:
        """Return total size of files under node (including the node if it's a file)."""
        ...

    def peek(self, node: VFSNode, n: int = 32) -> bytes:
        """Return first n bytes for magic-byte sniffing."""
        with self.open(node) as src:
            return src.read(n)


def _atime_note(root: Path, not_owned: int) -> str:
    """Why reading this source may update the evidence files' access
    times, or "" when Crush prevents it (see _read_noatime)."""
    if sys.platform == "win32":
        return ""  # restored after every read; a failure is logged per file
    if sys.platform != "linux":
        return (
            "Crush does not prevent access-time updates on this platform; "
            "mount the evidence read-only to prevent them"
        )
    if _read_only_mount(root):
        return ""
    if os.geteuid() == 0 or not not_owned:
        return ""
    return (
        f"{not_owned:,} file(s) are not owned by the current user, so Crush can't "
        "read them with O_NOATIME: reading them may update their access time "
        "(mount the evidence read-only to prevent this)"
    )


def _special_file_kind(mode: int) -> str:
    """"character device", "FIFO" ... for a mode that is neither a regular
    file, a directory nor a symbolic link."""
    for test, kind in (
        (stat.S_ISCHR, "character device"), (stat.S_ISBLK, "block device"),
        (stat.S_ISFIFO, "FIFO"), (stat.S_ISSOCK, "socket"),
    ):
        if test(mode):
            return kind
    return f"mode {stat.S_IFMT(mode):o}"


def _member_parts(name: str) -> list[str]:
    """Path components of an archive member name as stored: empty and "."
    components are dropped (a leading "./" or "/"), ".." and the leading
    dot of a name (".bashrc") are kept."""
    return [p for p in name.split("/") if p and p != "."]


def _free_sibling(nodes: dict[str, VFSNode], parent_path: str, name: str) -> tuple[str, str]:
    """Name and path for another entry stored under *name* in the same
    folder: "name (2)", "name (3)" ... (same scheme as $Recovered)."""
    k = 2
    while True:
        candidate = f"{name} ({k})"
        path = f"{parent_path.rstrip('/')}/{candidate}"
        if path not in nodes:
            return candidate, path
        k += 1


def _mark_duplicates(occurrences: dict[str, list[VFSNode]]) -> None:
    """Give every entry that shares its stored path with others a status
    saying so, numbered in archive order -- one is not the "real" one."""
    for same_name in occurrences.values():
        count = len(same_name)
        if count < 2:
            continue
        for k, node in enumerate(same_name, 1):
            note = (
                f"Stored {count} times in this archive under this name; "
                f"this is occurrence {k} of {count} (archive order)"
            )
            node.status = f"{node.status}; {note}" if node.status else note


class DirectoryVFS(VFS):
    """VFS backed by a plain directory on disk.

    Symbolic links below the opened folder are shown as links (their target
    is their content) and never followed: following would show the target's
    bytes under the link's name, loop on a link to a parent folder, and fail
    on a broken link. A folder that can't be listed and an entry that can't
    be read stay in the tree with a status instead of failing the whole
    source. Special files (FIFO, device, socket) are never read -- reading a
    FIFO blocks forever.
    """

    def __init__(self, path: str | Path) -> None:
        self._root_path = Path(path)
        # Content that isn't read from the file itself: a link's target, or
        # nothing at all for a special file.
        self._stored_content: dict[str, bytes] = {}
        self._not_owned = 0
        self._euid = os.geteuid() if hasattr(os, "geteuid") else None
        self._tree = self._build_node(self._root_path, is_root=True)
        self.load_note = _atime_note(self._root_path, self._not_owned)
        self._file_counts: dict[str, int] = {}
        self._total_sizes: dict[str, int] = {}
        self._compute_file_counts(self._tree)
        self._compute_total_sizes(self._tree)

    def root(self) -> VFSNode:
        return self._tree

    def _build_node(self, path: Path, is_root: bool = False) -> VFSNode:
        name = path.name or str(path)
        try:
            # The opened folder itself may be reached through a link (the
            # analyst chose it); everything below is taken as stored.
            st = path.stat() if is_root else path.lstat()
        except OSError as exc:
            node = VFSNode(name=name, path=str(path), is_dir=False,
                           status=f"Could not be read: {exc}")
            self._stored_content[node.path] = b""
            return node
        node = VFSNode(
            name=name,
            path=str(path),
            is_dir=stat.S_ISDIR(st.st_mode),
            size=st.st_size if stat.S_ISREG(st.st_mode) else 0,
            modified=st.st_mtime,
            accessed=st.st_atime,
            changed=st.st_ctime,
            birth=getattr(st, "st_birthtime", 0.0),
        )
        if stat.S_ISLNK(st.st_mode):
            try:
                target = os.readlink(path)
            except OSError as exc:
                node.status = f"Symbolic link (not followed); its target could not be read: {exc}"
                self._stored_content[node.path] = b""
            else:
                node.status = f"Symbolic link → {target} (not followed; content shown is the target)"
                self._stored_content[node.path] = os.fsencode(target)
                node.size = len(self._stored_content[node.path])
        elif node.is_dir:
            try:
                children = [self._build_node(child) for child in path.iterdir()]
            except OSError as exc:
                node.status = f"Folder could not be listed: {exc}"
                children = []
            node.children = sorted(children, key=lambda n: (not n.is_dir, n.name.lower()))
        elif not stat.S_ISREG(st.st_mode):
            node.status = f"Special file ({_special_file_kind(st.st_mode)}) — no content is read"
            self._stored_content[node.path] = b""
        elif self._euid is not None and st.st_uid != self._euid:
            self._not_owned += 1
        return node

    def read(self, node: VFSNode) -> bytes:
        stored = self._stored_content.get(node.path)
        if stored is not None:
            return stored
        return _read_noatime(Path(node.path))

    def open(self, node: VFSNode) -> IO[bytes]:
        stored = self._stored_content.get(node.path)
        if stored is not None:
            return BytesIO(stored)
        return _open_noatime(Path(node.path))

    def file_count(self, node: VFSNode) -> int:
        return self._file_counts.get(node.path, 0)

    def total_size(self, node: VFSNode) -> int:
        return self._total_sizes.get(node.path, 0)

    def _compute_file_counts(self, node: VFSNode) -> int:
        if not node.is_dir:
            self._file_counts[node.path] = 1
            return 1
        total = 0
        for child in node.children:
            total += self._compute_file_counts(child)
        self._file_counts[node.path] = total
        return total

    def _compute_total_sizes(self, node: VFSNode) -> int:
        if not node.is_dir:
            self._total_sizes[node.path] = node.size
            return node.size
        total = 0
        for child in node.children:
            total += self._compute_total_sizes(child)
        self._total_sizes[node.path] = total
        return total


class ZipVFS(VFS):
    """VFS backed by a ZIP archive (iOS/Android full-fs extractions), encrypted or not.

    A single ZipFile handle is shared across threads and protected by
    _zf_lock.  open() returns a BytesIO so callers never hold the lock
    while processing file content.

    Two unrelated encryption schemes exist for ZIP: legacy "ZipCrypto"
    (weak, stdlib zipfile already reads it natively via pwd=) and WinZip
    AES (strong, marked by compress_type == 99 — stdlib can list such
    entries but has no decompressor for that type at all). Rather than
    replacing the well-tested stdlib zipfile — this is the single most
    heavily used VFS backend in the app — a `pyzipper.AESZipFile` handle is
    constructed lazily and only used for the specific entries that need it.
    """

    _WZ_AES_COMPRESS_TYPE = 99

    def __init__(self, path: str | Path, *, password: str = "") -> None:
        self._zip_path = Path(path)
        self._zf = zipfile.ZipFile(self._zip_path, "r")
        self._password = password
        self._aes_zf: Any = None  # pyzipper.AESZipFile, constructed on first need
        self._zf_lock = threading.Lock()
        # virtual path -> index into infolist(): the exact entry, since a ZIP
        # may hold several entries under one name (open(name) gives the last).
        self._zip_entries: dict[str, int] = {}
        self._tree = self._build_tree()
        self._validate_password_if_needed()
        self._file_counts: dict[str, int] = {}
        self._total_sizes: dict[str, int] = {}
        self._compute_file_counts(self._tree)
        self._compute_total_sizes(self._tree)

    def _validate_password_if_needed(self) -> None:
        """Header-level metadata (flag_bits) is readable without a password
        even for encrypted entries, so check upfront and fail immediately at
        open time — matching every other password-protected VFS in this
        module — rather than only when the user later opens a specific file.
        """
        encrypted = [i for i, info in enumerate(self._zf.infolist()) if info.flag_bits & 0x1]
        if not encrypted:
            return
        if not self._password:
            raise PasswordRequiredError(f"ZIP archive is password-protected: {self._zip_path}")
        try:
            with self._open_entry(encrypted[0]) as f:
                f.read()
        except RuntimeError as exc:
            raise WrongPasswordError("Incorrect ZIP archive password") from exc

    def _aes_zip(self) -> Any:
        if self._aes_zf is None:
            import pyzipper

            self._aes_zf = pyzipper.AESZipFile(self._zip_path, "r")
        return self._aes_zf

    def _open_entry(self, index: int) -> IO[bytes]:
        """Open the infolist() entry at *index* -- by entry, not by name, so
        each of several same-named entries reads its own bytes."""
        pwd = self._password.encode("utf-8") if self._password else None
        info = self._zf.infolist()[index]
        if info.compress_type == self._WZ_AES_COMPRESS_TYPE:
            aes = self._aes_zip()
            return cast(IO[bytes], aes.open(aes.infolist()[index], pwd=pwd))
        return self._zf.open(info, pwd=pwd)

    def _build_tree(self) -> VFSNode:
        root = VFSNode(name=self._zip_path.name, path="/", is_dir=True)
        nodes: dict[str, VFSNode] = {"/": root}
        _offsets: dict[str, int] = {}  # virtual_path -> header_offset for storage-order prescan
        occurrences: dict[str, list[VFSNode]] = {}

        # Archive order, so same-named entries are numbered as stored.
        for index, info in enumerate(self._zf.infolist()):
            is_dir_entry = info.filename.endswith("/")
            parts = _member_parts(info.filename.rstrip("/"))
            if not parts:
                continue
            zip_ts = 0.0
            if info.date_time:
                from datetime import datetime
                zip_ts = datetime(*info.date_time).timestamp()
            for depth in range(1, len(parts)):
                virtual_path = "/" + "/".join(parts[:depth])
                if virtual_path not in nodes:
                    parent_path = "/" + "/".join(parts[: depth - 1]) if depth > 1 else "/"
                    node = VFSNode(name=parts[depth - 1], path=virtual_path, is_dir=True,
                                   modified=zip_ts)
                    nodes[parent_path].children.append(node)
                    nodes[virtual_path] = node
            stored_path = "/" + "/".join(parts)
            parent_path = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
            name = parts[-1]
            if is_dir_entry:
                if stored_path not in nodes:
                    node = VFSNode(name=name, path=stored_path, is_dir=True, modified=zip_ts)
                    nodes[parent_path].children.append(node)
                    nodes[stored_path] = node
                continue
            virtual_path = stored_path
            if virtual_path in nodes:
                name, virtual_path = _free_sibling(nodes, parent_path, name)
            node = VFSNode(name=name, path=virtual_path, is_dir=False,
                           size=info.file_size, modified=zip_ts)
            if info.create_system == 3 and stat.S_ISLNK(info.external_attr >> 16):
                node.status = "Symbolic link (content shown is the stored link target)"
            nodes[parent_path].children.append(node)
            nodes[virtual_path] = node
            occurrences.setdefault(stored_path, []).append(node)
            self._zip_entries[virtual_path] = index
            _offsets[virtual_path] = info.header_offset
        _mark_duplicates(occurrences)

        for node in nodes.values():
            node.children.sort(key=lambda n: (not n.is_dir, n.name.lower()))

        self._storage_ordered_nodes: list[VFSNode] = [
            nodes[vp] for vp, _ in sorted(_offsets.items(), key=lambda x: x[1])
        ]
        return root

    def root(self) -> VFSNode:
        return self._tree

    def storage_ordered_files(self) -> list[VFSNode]:
        """Return all file nodes sorted by their offset in the ZIP (sequential read order)."""
        return self._storage_ordered_nodes

    def peek(self, node: VFSNode, n: int = 32) -> bytes:
        with self._zf_lock:
            try:
                with self._open_entry(self._zip_entry(node)) as f:
                    return f.read(n)
            except RuntimeError as exc:
                raise WrongPasswordError("Incorrect ZIP archive password") from exc

    def read(self, node: VFSNode) -> bytes:
        with self._zf_lock:
            try:
                with self._open_entry(self._zip_entry(node)) as f:
                    return f.read()
            except RuntimeError as exc:
                raise WrongPasswordError("Incorrect ZIP archive password") from exc

    def open(self, node: VFSNode) -> IO[bytes]:
        if node.size <= STREAM_THRESHOLD:
            return BytesIO(self.read(node))
        with self._zf_lock:
            try:
                inner = self._open_entry(self._zip_entry(node))
            except RuntimeError as exc:
                raise WrongPasswordError("Incorrect ZIP archive password") from exc
        return buffered(LockedStream(inner, self._zf_lock))

    def _zip_entry(self, node: VFSNode) -> int:
        index = self._zip_entries.get(node.path)
        if index is None:
            raise FileNotFoundError(f"Not in ZIP: {node.path}")
        return index

    def close(self) -> None:
        self._zf.close()
        if self._aes_zf is not None:
            self._aes_zf.close()

    def file_count(self, node: VFSNode) -> int:
        return self._file_counts.get(node.path, 0)

    def total_size(self, node: VFSNode) -> int:
        return self._total_sizes.get(node.path, 0)

    def _compute_file_counts(self, node: VFSNode) -> int:
        if not node.is_dir:
            self._file_counts[node.path] = 1
            return 1
        total = 0
        for child in node.children:
            total += self._compute_file_counts(child)
        self._file_counts[node.path] = total
        return total

    def _compute_total_sizes(self, node: VFSNode) -> int:
        if not node.is_dir:
            self._total_sizes[node.path] = node.size
            return node.size
        total = 0
        for child in node.children:
            total += self._compute_total_sizes(child)
        self._total_sizes[node.path] = total
        return total


class TarVFS(VFS):
    """VFS backed by a TAR archive (plain, gzip, bzip2, or xz compressed).

    Compressed tar files cannot seek randomly, so reads are serialized with a
    per-instance lock to allow safe concurrent peek() from multiple threads.

    A compressed tar has no index, and reaching a member means decompressing
    everything before it -- minutes for a member deep in a multi-GB archive.
    Building the tree already has to read the whole stream once, so that one
    pass also keeps the first _HEAD_CACHE_BYTES of every file; peek() is
    answered from them without touching the archive. Without this, the
    tree's per-row type detection (a peek per visible file, on the UI
    thread) froze the window for minutes on every folder opened.
    """

    _HEAD_CACHE_BYTES = 2048

    def __init__(self, path: str | Path) -> None:
        self._tar_path = Path(path)
        self._head_cache: dict[str, bytes] = {}
        self._tf = tarfile.open(str(self._tar_path), "r:*")
        self._tf_lock = threading.Lock()
        self._members: dict[str, tarfile.TarInfo] = {}
        self._tree = self._build_tree(self._read_compressed_heads(self._tar_path, self._tf))
        self._file_counts: dict[str, int] = {}
        self._total_sizes: dict[str, int] = {}
        self._compute_file_counts(self._tree)
        self._compute_total_sizes(self._tree)

    @classmethod
    def _read_compressed_heads(cls, path: Path, tf: tarfile.TarFile) -> dict[int, bytes] | None:
        """For a gzip/bzip2/xz tar: walk every member once (the same pass
        getmembers() makes, forward only) and keep the first bytes of each
        regular file. None for a plain tar, where random access is cheap and
        no cache is needed. Leaves *tf* with all members loaded."""
        with open(path, "rb") as f:
            magic = f.read(6)
        if not (magic[:2] == b"\x1f\x8b" or magic[:3] == b"BZh" or magic[:6] == b"\xfd7zXZ\x00"):
            return None
        # Keyed by the member's header offset, not its name: a TAR may hold
        # several members under one name.
        heads: dict[int, bytes] = {}
        while (member := tf.next()) is not None:
            if member.isfile():
                fh = tf.extractfile(member)
                if fh is not None:
                    heads[member.offset] = fh.read(cls._HEAD_CACHE_BYTES)
        return heads

    def _build_tree(self, heads: dict[int, bytes] | None = None) -> VFSNode:
        """Every member in archive order: several members under one name
        (appended updates) each get their own node, symbolic links show
        their target as content, hard links read their target's bytes, and
        special files (devices, FIFOs) stay visible with no content."""
        root = VFSNode(name=self._tar_path.name, path="/", is_dir=True)
        nodes: dict[str, VFSNode] = {"/": root}
        self._head_cache = {}
        # Content that isn't a member's data stream: a symbolic link's target,
        # or nothing for a special file.
        self._stored_content: dict[str, bytes] = {}
        occurrences: dict[str, list[VFSNode]] = {}
        by_name: dict[str, tarfile.TarInfo] = {}

        for member in self._tf.getmembers():
            parts = _member_parts(member.name)
            if not parts:
                continue
            mtime = float(member.mtime)
            for depth in range(1, len(parts)):
                virtual_path = "/" + "/".join(parts[:depth])
                if virtual_path not in nodes:
                    parent_path = "/" + "/".join(parts[: depth - 1]) if depth > 1 else "/"
                    node = VFSNode(name=parts[depth - 1], path=virtual_path, is_dir=True,
                                   modified=mtime)
                    nodes[parent_path].children.append(node)
                    nodes[virtual_path] = node
            stored_path = "/" + "/".join(parts)
            parent_path = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
            name = parts[-1]
            if member.isdir():
                if stored_path not in nodes:
                    node = VFSNode(name=name, path=stored_path, is_dir=True, modified=mtime)
                    nodes[parent_path].children.append(node)
                    nodes[stored_path] = node
                continue
            virtual_path = stored_path
            if virtual_path in nodes:
                name, virtual_path = _free_sibling(nodes, parent_path, name)
            node = VFSNode(name=name, path=virtual_path, is_dir=False, modified=mtime)
            if member.isfile():
                node.size = member.size
                self._members[virtual_path] = member
                if heads is not None and member.offset in heads:
                    self._head_cache[virtual_path] = heads[member.offset]
            elif member.issym():
                target = member.linkname.encode("utf-8", "surrogateescape")
                node.size = len(target)
                node.status = f"Symbolic link → {member.linkname} (content shown is the target)"
                self._stored_content[virtual_path] = target
            elif member.islnk():
                linked = by_name.get(member.linkname)
                node.size = linked.size if linked is not None else 0
                node.status = f"Hard link to {member.linkname}"
                self._members[virtual_path] = member
            else:
                kind = (
                    "character device" if member.ischr() else "block device" if member.isblk()
                    else "FIFO" if member.isfifo() else f"type {member.type!r}"
                )
                node.status = f"Special file ({kind}) — no content stored"
                self._stored_content[virtual_path] = b""
            by_name[member.name] = member
            nodes[parent_path].children.append(node)
            nodes[virtual_path] = node
            occurrences.setdefault(stored_path, []).append(node)
        _mark_duplicates(occurrences)

        for node in nodes.values():
            node.children.sort(key=lambda n: (not n.is_dir, n.name.lower()))
        return root

    def root(self) -> VFSNode:
        return self._tree

    def read(self, node: VFSNode) -> bytes:
        stored = self._stored_content.get(node.path)
        if stored is not None:
            return stored
        member = self._members.get(node.path)
        if member is None:
            raise FileNotFoundError(f"Not in TAR: {node.path}")
        with self._tf_lock:
            f = self._tf.extractfile(member)
            if f is None:
                raise OSError(f"Cannot extract (symlink or special file): {node.path}")
            return f.read()

    def peek(self, node: VFSNode, n: int = 32) -> bytes:
        stored = self._stored_content.get(node.path)
        if stored is not None:
            return stored[:n]
        member = self._members.get(node.path)
        if member is None:
            raise FileNotFoundError(f"Not in TAR: {node.path}")
        head = self._head_cache.get(node.path)
        if head is not None and (n <= len(head) or len(head) >= member.size):
            return head[:n]
        with self._tf_lock:
            f = self._tf.extractfile(member)
            if f is None:
                raise OSError(f"Cannot extract (symlink or special file): {node.path}")
            with f:
                return f.read(n)

    def open(self, node: VFSNode) -> IO[bytes]:
        if node.size <= STREAM_THRESHOLD or node.path in self._stored_content:
            return BytesIO(self.read(node))
        member = self._members.get(node.path)
        if member is None:
            raise FileNotFoundError(f"Not in TAR: {node.path}")
        with self._tf_lock:
            f = self._tf.extractfile(member)
        if f is None:
            raise OSError(f"Cannot extract (symlink or special file): {node.path}")
        return buffered(LockedStream(f, self._tf_lock))

    def close(self) -> None:
        self._tf.close()

    def file_count(self, node: VFSNode) -> int:
        return self._file_counts.get(node.path, 0)

    def total_size(self, node: VFSNode) -> int:
        return self._total_sizes.get(node.path, 0)

    def _compute_file_counts(self, node: VFSNode) -> int:
        if not node.is_dir:
            self._file_counts[node.path] = 1
            return 1
        total = 0
        for child in node.children:
            total += self._compute_file_counts(child)
        self._file_counts[node.path] = total
        return total

    def _compute_total_sizes(self, node: VFSNode) -> int:
        if not node.is_dir:
            self._total_sizes[node.path] = node.size
            return node.size
        total = 0
        for child in node.children:
            total += self._compute_total_sizes(child)
        self._total_sizes[node.path] = total
        return total


class GzipVFS(VFS):
    """VFS backed by a standalone gzip-compressed file (not a .tar.gz — a
    single compressed file, e.g. a rotated log like syslog.gz).

    Presents as a directory containing the one decompressed member. The
    member's name comes from the gzip header's stored original filename
    (FNAME flag, RFC 1952) when present, otherwise falls back to the
    archive's own name with .gz/.tgz stripped. Concatenated gzip members
    (RFC 1952 permits multiple streams back to back in one file) are
    decompressed in full, matching what the gzip module and `gzip -d` do —
    the size is computed from the actual decompressed bytes rather than the
    trailer's ISIZE field, which only covers the last member and wraps at
    4 GiB.
    """

    def __init__(self, path: str | Path) -> None:
        self._gz_path = Path(path)
        member_name, mtime = self._read_header_metadata()
        # One chunked pass computes the real decompressed size. The bytes are
        # only kept in memory while they stay under STREAM_THRESHOLD; a larger
        # member is re-decompressed from the file on demand instead.
        self._data: bytes | None = None
        kept: list[bytes] | None = []
        self._size = 0
        with gzip.open(self._gz_path, "rb") as f:
            while chunk := f.read(COPY_CHUNK):
                self._size += len(chunk)
                if kept is not None:
                    kept.append(chunk)
                    if self._size > STREAM_THRESHOLD:
                        kept = None
        if kept is not None:
            self._data = b"".join(kept)
        self._member_path = f"/{member_name}"
        self._root = VFSNode(name=self._gz_path.name, path="/", is_dir=True)
        self._root.children.append(
            VFSNode(
                name=member_name,
                path=self._member_path,
                is_dir=False,
                size=self._size,
                modified=mtime,
            )
        )

    def _read_header_metadata(self) -> tuple[str, float]:
        """Parse the gzip header (RFC 1952) for the original filename and
        mtime, without decompressing."""
        name = None
        mtime = 0.0
        with open(self._gz_path, "rb") as f:
            head = f.read(4096)
        if len(head) >= 10 and head[0:2] == b"\x1f\x8b":
            flg = head[3]
            mtime_val = int.from_bytes(head[4:8], "little")
            if mtime_val:
                mtime = float(mtime_val)
            pos = 10
            if flg & 0x04 and len(head) >= pos + 2:  # FEXTRA
                xlen = int.from_bytes(head[pos:pos + 2], "little")
                pos += 2 + xlen
            if flg & 0x08 and 0 <= pos < len(head):  # FNAME
                end = head.find(b"\x00", pos)
                if end != -1:
                    try:
                        name = head[pos:end].decode("latin-1") or None
                    except Exception:
                        name = None
        if not name:
            stem = self._gz_path.name
            if stem.lower().endswith(".tgz"):
                name = stem[:-4] + ".tar"
            elif stem.lower().endswith(".gz"):
                name = stem[:-3]
            else:
                name = stem + ".out"
            if not name:
                name = "data"
        return name, mtime

    def root(self) -> VFSNode:
        return self._root

    def read(self, node: VFSNode) -> bytes:
        if node.path != self._member_path:
            raise FileNotFoundError(f"Not in gzip: {node.path}")
        if self._data is not None:
            return self._data
        with gzip.open(self._gz_path, "rb") as f:
            return f.read()

    def open(self, node: VFSNode) -> IO[bytes]:
        if node.path != self._member_path:
            raise FileNotFoundError(f"Not in gzip: {node.path}")
        if self._data is not None:
            return BytesIO(self._data)
        return cast(IO[bytes], gzip.open(self._gz_path, "rb"))

    def file_count(self, node: VFSNode) -> int:
        return 1

    def total_size(self, node: VFSNode) -> int:
        return self._size


class AndroidBackupVFS(TarVFS):
    """VFS backed by an `adb backup` container (.ab), encrypted or not.

    The .ab format is a text header (magic, version, compressed flag,
    encryption flag) followed by a single tar stream, optionally
    deflate-compressed and/or AES-256 encrypted (see
    `crush.core.android_backup_crypto` for the password-based key unwrap).

    The tar stream is decompressed/decrypted once, chunk by chunk, into an
    unlinked temp file (in the configured temp directory) and then handled
    identically to a plain TarVFS by reusing its tree-building and read
    logic. Nothing of the payload is held in RAM, so a multi-GB backup opens
    with bounded memory.
    """

    def __init__(self, path: str | Path, *, password: str = "") -> None:
        self._tar_path = Path(path)
        self._spool: IO[bytes] = tempdir.spool_file("crush-ab-")
        try:
            self._extract_tar_to(self._tar_path, password, self._spool)
            self._spool.seek(0)
            self._tf = tarfile.open(fileobj=self._spool, mode="r:")
        except BaseException:
            self._spool.close()
            raise
        self._tf_lock = threading.Lock()
        self._members: dict[str, tarfile.TarInfo] = {}
        self._tree = self._build_tree()
        self._file_counts: dict[str, int] = {}
        self._total_sizes: dict[str, int] = {}
        self._compute_file_counts(self._tree)
        self._compute_total_sizes(self._tree)

    def close(self) -> None:
        super().close()
        self._spool.close()

    @staticmethod
    def _read_chunks(f: IO[bytes]) -> Iterator[bytes]:
        while True:
            chunk = f.read(COPY_CHUNK)
            if not chunk:
                return
            yield chunk

    @staticmethod
    def _inflate(chunks: Iterator[bytes]) -> Iterator[bytes]:
        inflater = zlib.decompressobj()
        for chunk in chunks:
            out = inflater.decompress(chunk)
            if out:
                yield out
        tail = inflater.flush()
        if tail:
            yield tail

    @staticmethod
    def _extract_tar_to(path: Path, password: str, out: IO[bytes]) -> None:
        with open(path, "rb") as f:
            magic = f.readline().strip()
            if magic != b"ANDROID BACKUP":
                raise ValueError(f"Not an Android backup: {path}")
            version = int(f.readline().strip())
            compressed = f.readline().strip() == b"1"
            encryption = f.readline().strip()

            chunks: Iterator[bytes]
            if encryption == b"none":
                chunks = AndroidBackupVFS._read_chunks(f)
            else:
                if encryption != b"AES-256":
                    raise ValueError(f"Unsupported Android backup encryption: {encryption!r}")
                if not password:
                    raise PasswordRequiredError(f"Android backup is password-protected: {path}")

                user_salt = bytes.fromhex(f.readline().strip().decode("ascii"))
                checksum_salt = bytes.fromhex(f.readline().strip().decode("ascii"))
                rounds = int(f.readline().strip())
                user_iv = bytes.fromhex(f.readline().strip().decode("ascii"))
                master_key_blob = bytes.fromhex(f.readline().strip().decode("ascii"))

                from crush.core import android_backup_crypto

                master_key, master_iv = android_backup_crypto.unwrap_master_key(
                    password, user_salt, checksum_salt, rounds, user_iv, master_key_blob, version
                )
                chunks = android_backup_crypto.decrypt_payload_stream(
                    master_key, master_iv, AndroidBackupVFS._read_chunks(f)
                )
            if compressed:
                chunks = AndroidBackupVFS._inflate(chunks)
            for chunk in chunks:
                out.write(chunk)


def _clear_wal_header_flag(manifest_db: bytes) -> bytes:
    """Clear the WAL flag in a SQLite header so sqlite3's deserialize() can open it.

    Real-world Manifest.db files are commonly checkpointed WAL databases (file
    format read/write version = 2 at header offsets 18/19). sqlite3.Connection
    .deserialize() opens the buffer as a plain in-memory database and can't
    handle that mode — but since Manifest.db always travels without its `-wal`
    file, everything is already checkpointed into the main pages, so flipping
    the version bytes back to 1 (rollback journal) is safe and doesn't touch
    any actual table data.
    """
    if len(manifest_db) >= 20 and manifest_db[18] == 2 and manifest_db[19] == 2:
        manifest_db = manifest_db[:18] + b"\x01\x01" + manifest_db[20:]
    return manifest_db


class ITunesBackupVFS(VFS):
    """VFS backed by an iTunes/Finder iOS backup directory.

    A backup directory holds `Manifest.db` (SQLite table `Files`: fileID,
    domain, relativePath, flags) plus the actual file contents stored flat
    under the backup root, named by fileID (a SHA1 hash) — sharded into 256
    two-character subdirectories since iOS 10, flat before that. The virtual
    tree is built from `domain/relativePath` so it reads like the on-device
    filesystem instead of the flat on-disk fileID layout.

    Since iOS 10.2, `Manifest.db` itself is always AES encrypted (see
    `crush.core.ios_keybag`) regardless of whether the backup has a password;
    `password` only needs to be non-empty for backups with `IsEncrypted=True`.
    """

    _FLAG_DIR = 2  # iOS backup Files.flags: 1 = file, 2 = directory, 4 = symlink.
    _FLAG_SYMLINK = 4

    def __init__(
        self, path: str | Path, *, password: str = "", _cleanup_dir: Path | None = None
    ) -> None:
        self._backup_path = Path(path)
        self._password = password
        self._cleanup_dir = _cleanup_dir
        self._keybag: ios_keybag.BackupKeyBag | None = None

        self._file_locations: dict[str, Path] = {}
        self._file_protection: dict[str, tuple[int, bytes]] = {}
        self._stored_content: dict[str, bytes] = {}  # symbolic links: their target
        self._tree = self._build_tree()
        self._file_counts: dict[str, int] = {}
        self._total_sizes: dict[str, int] = {}
        self._compute_file_counts(self._tree)
        self._compute_total_sizes(self._tree)

    def _load_manifest_db_bytes(self) -> bytes:
        manifest_plist_path = self._backup_path / "Manifest.plist"
        manifest_plist: dict[str, object] = {}
        if manifest_plist_path.is_file():
            manifest_plist = plistlib.loads(manifest_plist_path.read_bytes())

        if manifest_plist.get("IsEncrypted", False) and not self._password:
            raise PasswordRequiredError(
                f"iTunes backup is password-protected: {self._backup_path}"
            )

        raw = (self._backup_path / "Manifest.db").read_bytes()
        if "BackupKeyBag" not in manifest_plist:
            return raw  # Pre-iOS-10.2 backup: Manifest.db was never encrypted.

        from crush.core import ios_keybag

        self._keybag = ios_keybag.BackupKeyBag(
            cast(bytes, manifest_plist["BackupKeyBag"]), self._password
        )
        manifest_key = self._keybag.unwrap_manifest_key(cast(bytes, manifest_plist["ManifestKey"]))
        return ios_keybag.aes_cbc_decrypt_and_unpad(manifest_key, raw)

    def close(self) -> None:
        if self._cleanup_dir is not None:
            shutil.rmtree(self._cleanup_dir, ignore_errors=True)

    def _build_tree(self) -> VFSNode:
        root = VFSNode(name=self._backup_path.name, path="/", is_dir=True)
        nodes: dict[str, VFSNode] = {"/": root}

        conn = sqlite3.connect(":memory:")
        try:
            conn.deserialize(_clear_wal_header_flag(self._load_manifest_db_bytes()))
            rows = conn.execute(
                "SELECT fileID, domain, relativePath, flags, file FROM Files"
            ).fetchall()
        finally:
            conn.close()

        for file_id, domain, relative_path, flags, file_blob in rows:
            raw_path = f"{domain}/{relative_path}" if relative_path else domain
            parts = [p for p in raw_path.split("/") if p]
            if not parts:
                continue
            is_leaf_dir = flags == self._FLAG_DIR
            virtual_path = "/"
            for depth, _ in enumerate(parts, 1):
                virtual_path = "/" + "/".join(parts[:depth])
                if virtual_path not in nodes:
                    is_dir = depth < len(parts) or is_leaf_dir
                    node = VFSNode(name=parts[depth - 1], path=virtual_path, is_dir=is_dir)
                    parent_path = "/" + "/".join(parts[: depth - 1]) if depth > 1 else "/"
                    nodes[parent_path].children.append(node)
                    nodes[virtual_path] = node
            if not is_leaf_dir and self._keybag is not None and file_blob:
                from crush.core import ios_keybag

                try:
                    protection = ios_keybag.extract_file_protection(file_blob)
                except Exception:
                    protection = None  # Malformed per-file metadata; read back raw bytes.
                if protection is not None:
                    self._file_protection[virtual_path] = protection
            if flags == self._FLAG_SYMLINK:
                # A link has no content file in the backup; its target is
                # recorded in the file's metadata blob.
                node = nodes[virtual_path]
                target = None
                if file_blob:
                    from crush.core import ios_keybag

                    try:
                        target = ios_keybag.extract_symlink_target(file_blob)
                    except Exception:
                        target = None
                if target is None:
                    node.status = "Symbolic link (the backup records no target for it)"
                    self._stored_content[virtual_path] = b""
                else:
                    node.status = f"Symbolic link → {target} (content shown is the target)"
                    self._stored_content[virtual_path] = target.encode("utf-8")
                node.size = len(self._stored_content[virtual_path])
            elif not is_leaf_dir:
                located = self._locate_file(file_id)
                if located is not None:
                    nodes[virtual_path].size = located.stat().st_size
                    self._file_locations[virtual_path] = located
                else:
                    nodes[virtual_path].status = (
                        f"No content stored in the backup for this entry (fileID {file_id})"
                    )

        for node in nodes.values():
            node.children.sort(key=lambda n: (not n.is_dir, n.name.lower()))
        return root

    def _locate_file(self, file_id: str) -> Path | None:
        sharded = self._backup_path / file_id[:2] / file_id
        if sharded.is_file():
            return sharded
        flat = self._backup_path / file_id
        if flat.is_file():
            return flat
        return None

    def original_backup_path(self, node: VFSNode) -> str | None:
        """On-disk path (relative to the backup root) this node's content is
        actually stored under, e.g. "ab/ab54f7c9...e1" — the raw fileID-named
        file, before domain/relativePath resolution. None for directories or
        entries with no backing file (e.g. unresolved manifest rows)."""
        located = self._file_locations.get(node.path)
        if located is None:
            return None
        return str(located.relative_to(self._backup_path))

    def root(self) -> VFSNode:
        return self._tree

    def read(self, node: VFSNode) -> bytes:
        stored = self._stored_content.get(node.path)
        if stored is not None:
            return stored
        located = self._file_locations.get(node.path)
        if located is None:
            raise FileNotFoundError(f"Not backed by a file in the backup: {node.path}")
        raw = _read_noatime(located)
        protection = self._file_protection.get(node.path)
        if protection is None or self._keybag is None:
            return raw
        protection_class, encryption_key_entry = protection
        file_key = self._keybag.unwrap_file_key(protection_class, encryption_key_entry)

        from crush.core import ios_keybag

        return ios_keybag.aes_cbc_decrypt_and_unpad(file_key, raw)

    def open(self, node: VFSNode) -> IO[bytes]:
        stored = self._stored_content.get(node.path)
        if stored is not None:
            return BytesIO(stored)
        located = self._file_locations.get(node.path)
        if located is None:
            raise FileNotFoundError(f"Not backed by a file in the backup: {node.path}")
        protection = self._file_protection.get(node.path)
        if protection is None or self._keybag is None:
            return _open_noatime(located)
        if located.stat().st_size <= STREAM_THRESHOLD:
            return BytesIO(self.read(node))
        protection_class, encryption_key_entry = protection
        file_key = self._keybag.unwrap_file_key(protection_class, encryption_key_entry)

        from crush.core import ios_keybag

        def make_iter() -> Iterator[bytes]:
            with _open_noatime(located) as f:
                yield from ios_keybag.aes_cbc_decrypt_stream(
                    file_key, iter(lambda: f.read(COPY_CHUNK), b"")
                )

        return buffered(IterStream(make_iter, node.size))

    def file_count(self, node: VFSNode) -> int:
        return self._file_counts.get(node.path, 0)

    def total_size(self, node: VFSNode) -> int:
        return self._total_sizes.get(node.path, 0)

    def _compute_file_counts(self, node: VFSNode) -> int:
        if not node.is_dir:
            self._file_counts[node.path] = 1
            return 1
        total = 0
        for child in node.children:
            total += self._compute_file_counts(child)
        self._file_counts[node.path] = total
        return total

    def _compute_total_sizes(self, node: VFSNode) -> int:
        if not node.is_dir:
            self._total_sizes[node.path] = node.size
            return node.size
        total = 0
        for child in node.children:
            total += self._compute_total_sizes(child)
        self._total_sizes[node.path] = total
        return total


# py7zr has no way to write directly into a caller-supplied buffer of unknown
# size, so BytesIOFactory needs a byte cap up front. Set it absurdly high so it
# never truncates a real file — see feedback_no_silent_limits in project memory.
_SEVENZIP_EXTRACT_LIMIT = 1 << 40  # 1 TiB

# Bounds peak memory for prefetch_all() (bulk decompression of every entry in
# one pass, to avoid re-decompressing shared solid blocks once per file).
# Archives above this size fall back to extracting one entry at a time —
# slower but bounded to whatever the caller actually reads, never skipped or
# truncated, just a different (still fully correct) code path.
_SEVENZIP_PREFETCH_SIZE_LIMIT = 1 << 30  # 1 GiB


def _make_7z_spool_factory() -> Any:
    """A py7zr WriterFactory that writes each extracted member into an
    unlinked temp file instead of memory. Built lazily so importing this
    module never requires py7zr."""
    from py7zr.io import Py7zIO, WriterFactory

    class _SpoolIO(Py7zIO):
        def __init__(self) -> None:
            self.fh = tempdir.spool_file("crush-7z-")

        def write(self, s: bytes | bytearray) -> int:
            return self.fh.write(s)

        def read(self, size: int | None = None) -> bytes:
            return self.fh.read(-1 if size is None else size)

        def seek(self, offset: int, whence: int = 0) -> int:
            return self.fh.seek(offset, whence)

        def flush(self) -> None:
            self.fh.flush()

        def size(self) -> int:
            pos = self.fh.tell()
            end = self.fh.seek(0, 2)
            self.fh.seek(pos)
            return end

    class _SpoolFactory(WriterFactory):
        def __init__(self) -> None:
            self._files: dict[str, _SpoolIO] = {}

        def create(self, filename: str) -> Py7zIO:
            spool = _SpoolIO()
            self._files[filename] = spool
            self.last = spool
            return spool

        def take(self, filename: str) -> IO[bytes]:
            spool = self._files[filename]
            spool.fh.seek(0)
            return spool.fh

    return _SpoolFactory()


def _make_7z_sequence_factory(spool: bool) -> Any:
    """A py7zr WriterFactory that keeps every product in creation order
    (see SevenZipVFS._extract_entries): in memory, or each in an unlinked
    temp file when *spool* (large entries)."""
    from py7zr.io import Py7zBytesIO, WriterFactory

    spool_factory = _make_7z_spool_factory() if spool else None

    class _SequenceFactory(WriterFactory):
        def __init__(self) -> None:
            self.products: list[Any] = []

        def create(self, filename: str) -> Any:
            if spool_factory is not None:
                spool_factory.create(filename)
                product = spool_factory.last
                self.products.append(product.fh)
                return product
            product = Py7zBytesIO(filename, _SEVENZIP_EXTRACT_LIMIT)
            self.products.append(product)
            return product

    return _SequenceFactory()


class SevenZipVFS(VFS):
    """VFS backed by a 7z archive, encrypted or not.

    Unlike zipfile/tarfile, py7zr cannot open an arbitrary entry as an
    independent stream — solid compression blocks mean extracting any file
    requires a full pass over the archive, and the archive object must be
    reset() before the next operation. Reads are therefore fully serialized
    under a per-instance lock (the whole extract+reset cycle, not just the
    file object as in ZipVFS).

    py7zr handles the AES/PBKDF2 decryption itself; this class only needs to
    pass the password through and translate its exceptions to the shared
    PasswordRequiredError/WrongPasswordError contract. Two cases:
    - Header encryption (file listing itself is encrypted): py7zr raises
      PasswordRequired() at construction with no password, or a bare
      TypeError ("Unknown field: ...") with a wrong one — decrypting the
      header with the wrong AES key yields garbage that fails to parse as a
      valid 7z header structure, so py7zr has no way to tell "wrong
      password" apart from "corrupt file" there.
    - Content-only encryption: construction/listing always succeeds; a
      missing password raises PasswordRequired() at extract() time. A wrong
      one decrypts to garbage -- AES-CBC has no built-in integrity check the
      way RFC 3394 key-wrap does -- and *which* exception that garbage then
      trips is unstable across platforms/py7zr versions, same as the header
      case above: usually lzma.LZMAError ("Corrupt input data") when the
      garbage doesn't even decompress, but observed as py7zr's own
      CrcError on macOS CI when it happens to decompress into something
      that still fails the archive's own CRC32 check.
    """

    def __init__(self, path: str | Path, *, password: str = "") -> None:
        import py7zr

        self._path = Path(path)
        try:
            self._zf = py7zr.SevenZipFile(self._path, "r", password=password or None)
        except py7zr.exceptions.PasswordRequired as exc:
            raise PasswordRequiredError(f"7z archive is password-protected: {path}") from exc
        except (TypeError, py7zr.exceptions.Bad7zFile) as exc:
            # Decrypting the header with the wrong AES key yields garbage
            # that fails to parse as a valid 7z header structure -- py7zr
            # has no way to tell "wrong password" apart from "corrupt file"
            # here, and *which* parse step trips first (and so which
            # exception type surfaces) is not stable across py7zr versions
            # or even across archives on different platforms: observed as a
            # bare TypeError ("Unknown field: ...") on Linux and a
            # Bad7zFile ("end id expected but ... found") on Windows CI for
            # the same wrong-password fixture.
            if password:
                raise WrongPasswordError("Incorrect 7z archive password") from exc
            raise
        self._zf_lock = threading.Lock()
        # virtual path -> stored filename, and its position in the archive's
        # entry list: several entries may share one filename, and py7zr
        # extracts them in archive order (see _extract_entries).
        self._entry_names: dict[str, str] = {}
        self._entry_order: dict[str, int] = {}
        self._read_cache: dict[str, bytes] = {}  # by virtual path
        self._tree = self._build_tree()
        self._validate_password_against_content()
        self._file_counts: dict[str, int] = {}
        self._total_sizes: dict[str, int] = {}
        self._compute_file_counts(self._tree)
        self._compute_total_sizes(self._tree)

    def _validate_password_against_content(self) -> None:
        """Header encryption already failed at construction if the password
        was missing/wrong. Content-only encryption doesn't block listing, so
        without this check a missing/wrong password would only surface later
        — confusingly, from a background type-detection prescan or when the
        user opens a specific file — instead of immediately at open time like
        every other password-protected VFS in this module.
        """
        if not self._entry_names:
            return
        from py7zr.io import NullIOFactory

        # The smallest entry is enough to prove the key works (all content
        # shares one), and is the cheapest to decompress. Its bytes are only
        # kept when small -- a huge first entry must not be pinned in RAM.
        sizes = {n.path: n.size for n in self._iter_files(self._tree)}
        # An empty entry has no data stream, so it proves nothing about the key.
        candidates = [vp for vp in self._entry_names if sizes.get(vp, 0) > 0] or list(self._entry_names)
        vpath = min(candidates, key=lambda vp: sizes.get(vp, 0))
        with self._zf_lock:
            if sizes.get(vpath, 0) <= STREAM_THRESHOLD:
                for vp, data in self._extract_bytes([vpath]).items():
                    self._read_cache[vp] = data
            else:
                self._extract([self._entry_names[vpath]], NullIOFactory())  # type: ignore[no-untyped-call]

    @staticmethod
    def _iter_files(node: VFSNode) -> Iterator[VFSNode]:
        stack = [node]
        while stack:
            cur = stack.pop()
            if cur.is_dir:
                stack.extend(cur.children)
            else:
                yield cur

    def _build_tree(self) -> VFSNode:
        root = VFSNode(name=self._path.name, path="/", is_dir=True)
        nodes: dict[str, VFSNode] = {"/": root}
        occurrences: dict[str, list[VFSNode]] = {}

        infos = self._zf.list()
        self._zf.reset()

        # Archive order, so same-named entries are numbered as stored.
        for order, info in enumerate(infos):
            parts = _member_parts(info.filename.rstrip("/"))
            if not parts:
                continue
            ts = info.creationtime.timestamp() if info.creationtime else 0.0
            for depth in range(1, len(parts)):
                virtual_path = "/" + "/".join(parts[:depth])
                if virtual_path not in nodes:
                    parent_path = "/" + "/".join(parts[: depth - 1]) if depth > 1 else "/"
                    node = VFSNode(name=parts[depth - 1], path=virtual_path, is_dir=True,
                                   modified=ts)
                    nodes[parent_path].children.append(node)
                    nodes[virtual_path] = node
            stored_path = "/" + "/".join(parts)
            parent_path = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
            name = parts[-1]
            if info.is_directory:
                if stored_path not in nodes:
                    node = VFSNode(name=name, path=stored_path, is_dir=True, modified=ts)
                    nodes[parent_path].children.append(node)
                    nodes[stored_path] = node
                continue
            virtual_path = stored_path
            if virtual_path in nodes:
                name, virtual_path = _free_sibling(nodes, parent_path, name)
            node = VFSNode(name=name, path=virtual_path, is_dir=False,
                           size=info.uncompressed, modified=ts)
            if info.is_symlink:
                node.status = "Symbolic link (content shown is the stored link target)"
            nodes[parent_path].children.append(node)
            nodes[virtual_path] = node
            occurrences.setdefault(stored_path, []).append(node)
            self._entry_names[virtual_path] = info.filename
            self._entry_order[virtual_path] = order
        _mark_duplicates(occurrences)

        for node in nodes.values():
            node.children.sort(key=lambda n: (not n.is_dir, n.name.lower()))
        return root

    def root(self) -> VFSNode:
        return self._tree

    def _extract(self, targets: list[str], factory: Any) -> None:
        import lzma

        import py7zr

        try:
            self._zf.extract(targets=targets, factory=factory)
        except py7zr.exceptions.PasswordRequired as exc:
            raise PasswordRequiredError(f"7z archive is password-protected: {self._path}") from exc
        except (lzma.LZMAError, py7zr.exceptions.CrcError) as exc:
            raise WrongPasswordError("Incorrect 7z archive password") from exc
        finally:
            self._zf.reset()

    def _extract_entries(self, vpaths: list[str], spool: bool) -> dict[str, Any]:
        """Extract the entries behind *vpaths* in one pass and map each
        virtual path to its own product. Targets are filenames, so every
        entry stored under a requested filename comes out -- in archive
        order, which pairs each product with its entry even when several
        share one filename (py7zr renames the copies, so names can't)."""
        names = {self._entry_names[vp] for vp in vpaths}
        expected = sorted(
            (vp for vp, name in self._entry_names.items() if name in names),
            key=self._entry_order.__getitem__,
        )
        factory = _make_7z_sequence_factory(spool)
        self._extract(sorted(names), factory)
        if len(factory.products) != len(expected):
            raise OSError(
                f"7z extraction returned {len(factory.products)} entries, "
                f"expected {len(expected)} for {sorted(names)}"
            )
        return dict(zip(expected, factory.products))

    def _extract_bytes(self, vpaths: list[str]) -> dict[str, bytes]:
        return {vp: product.read() for vp, product in self._extract_entries(vpaths, spool=False).items()}

    def read(self, node: VFSNode) -> bytes:
        if node.path not in self._entry_names:
            raise FileNotFoundError(f"Not in 7z: {node.path}")
        cached = self._read_cache.get(node.path)
        if cached is not None:
            return cached
        with self._zf_lock:
            extracted = self._extract_bytes([node.path])
        for vp, data in extracted.items():
            if len(data) <= STREAM_THRESHOLD:
                self._read_cache[vp] = data
        return extracted[node.path]

    def open(self, node: VFSNode) -> IO[bytes]:
        if node.path in self._read_cache or node.size <= STREAM_THRESHOLD:
            return BytesIO(self.read(node))
        if node.path not in self._entry_names:
            raise FileNotFoundError(f"Not in 7z: {node.path}")
        # py7zr can only decompress a member front to back, so a large one is
        # staged once in an unlinked temp file (bounded RAM, seekable).
        with self._zf_lock:
            spools = self._extract_entries([node.path], spool=True)
        for vp, fh in spools.items():
            if vp != node.path:
                fh.close()
        fh = spools[node.path]
        fh.seek(0)
        return cast(IO[bytes], fh)

    def prefetch_all(self) -> bool:
        """Batch-extract every not-yet-cached entry in a single archive pass.

        A solid 7z block gets decompressed once total instead of once per file
        it contains, which is what the type-detection prescan needs (it peeks
        every file). Skipped when the archive's total size exceeds
        _SEVENZIP_PREFETCH_SIZE_LIMIT — callers keep working either way since
        read() falls back to extracting one entry at a time.
        """
        if self.total_size(self._tree) > _SEVENZIP_PREFETCH_SIZE_LIMIT:
            return False
        missing = [vp for vp in self._entry_names if vp not in self._read_cache]
        if not missing:
            return True
        with self._zf_lock:
            self._read_cache.update(self._extract_bytes(missing))
        return True

    def close(self) -> None:
        self._zf.close()

    def file_count(self, node: VFSNode) -> int:
        return self._file_counts.get(node.path, 0)

    def total_size(self, node: VFSNode) -> int:
        return self._total_sizes.get(node.path, 0)

    def _compute_file_counts(self, node: VFSNode) -> int:
        if not node.is_dir:
            self._file_counts[node.path] = 1
            return 1
        total = 0
        for child in node.children:
            total += self._compute_file_counts(child)
        self._file_counts[node.path] = total
        return total

    def _compute_total_sizes(self, node: VFSNode) -> int:
        if not node.is_dir:
            self._total_sizes[node.path] = node.size
            return node.size
        total = 0
        for child in node.children:
            total += self._compute_total_sizes(child)
        self._total_sizes[node.path] = total
        return total


class RawImageVFS(VFS):
    """VFS backed by a raw disk image (.img/.dd/split .001 set) or an
    EWF (Expert Witness Format, .E01 + segments) acquisition, read in place
    via the vendored qnxprobe (+ ewfprobe) readers — no mounting, no admin
    rights, and only the files an examiner actually opens leave the image.

    One top-level child per volume qnxprobe finds (a partition table entry
    or a bare filesystem), named after qnxprobe's own LBA-based identity so
    two volumes can never collide. A volume whose filesystem qnxprobe
    recognises but cannot walk still appears, as a non-browsable leaf
    carrying its size, rather than being silently dropped — this project's
    standing rule is that unsupported content must always surface as an
    explicit status, never render as a silent empty/zero result.
    """

    def __init__(self, path: str | Path) -> None:
        from crush.core.raw_image import build_volume_node, open_raw_image

        self._path = Path(path)
        self._handle = open_raw_image(self._path)
        self._lock = threading.Lock()
        self._read_map: dict[str, Any] = {}

        root = VFSNode(name=self._path.name, path="/", is_dir=True)
        for vol in self._handle.volumes:
            root.children.append(build_volume_node(vol, self._read_map))
        root.children.sort(key=lambda n: (not n.is_dir, n.name.lower()))
        self._tree = root

        self._file_counts: dict[str, int] = {}
        self._total_sizes: dict[str, int] = {}
        self._compute_file_counts(self._tree)
        self._compute_total_sizes(self._tree)

    def root(self) -> VFSNode:
        return self._tree

    def _resolve_entry(self, node: VFSNode) -> Any:
        from crush.core.raw_image import RawImageFileUnreadableError

        entry = self._read_map.get(node.path)
        if entry is None:
            raise RawImageFileUnreadableError(f"No such entry: {node.path}")
        return entry

    def read(self, node: VFSNode) -> bytes:
        from crush.core.raw_image import read_deleted_file, read_raw_region, read_walker_file

        entry = self._resolve_entry(node)
        if entry.stored is not None:
            return bytes(entry.stored)
        with self._lock:
            if entry.deleted is not None:
                return read_deleted_file(entry.walker, entry.deleted, entry.size)
            if entry.walker is None:
                # A volume qnxprobe recognises but can't walk (or doesn't
                # recognise at all) -- still fully readable as the raw bytes
                # of that region, never hidden.
                return read_raw_region(self._handle.image, entry.base, entry.size)
            return read_walker_file(entry.walker, entry.node, entry.size)

    def open(self, node: VFSNode) -> IO[bytes]:
        from crush.core.raw_image import (
            stream_deleted_file,
            stream_raw_region,
            stream_walker_file,
        )

        entry = self._resolve_entry(node)
        if entry.size <= STREAM_THRESHOLD:
            return BytesIO(self.read(node))

        def make_iter() -> Iterator[bytes]:
            if entry.deleted is not None:
                return stream_deleted_file(entry.walker, entry.deleted, entry.size)
            if entry.walker is None:
                return stream_raw_region(self._handle.image, entry.base, entry.size)
            return stream_walker_file(entry.walker, entry.node, entry.size)

        return buffered(IterStream(make_iter, entry.size, lock=self._lock))

    def peek(self, node: VFSNode, n: int = 32) -> bytes:
        from crush.core.raw_image import peek_deleted_file, peek_raw_region, peek_walker_file

        entry = self._resolve_entry(node)
        if entry.stored is not None:
            return bytes(entry.stored[:n])
        with self._lock:
            if entry.deleted is not None:
                return peek_deleted_file(entry.walker, entry.deleted, entry.size, n)
            if entry.walker is None:
                return peek_raw_region(self._handle.image, entry.base, entry.size, n)
            return peek_walker_file(entry.walker, entry.node, entry.size, n)

    def close(self) -> None:
        self._handle.close()

    def volume_info(self, node: VFSNode) -> dict[str, str] | None:
        """qnxprobe's own diagnosis for a node that needs an explicit status
        rather than looking like an ordinary, unremarkable file: a recovered
        deleted file, an unallocated gap, or a partition whose filesystem is
        recognised but has no walker, or isn't recognised at all. None for a
        normal, live, walker-backed file. This project's rule is that
        unsupported (and recovered-but-uncertain) content must always carry
        an explicit status.
        """
        entry = self._read_map.get(node.path)
        if entry is None or entry.stored is not None:
            return None
        if entry.deleted is not None:
            status = (
                "recovered (content intact)" if entry.deleted.recoverable
                else f"not recoverable: {entry.deleted.reason}"
            )
            return {"kind": "deleted file", "note": status}
        if entry.walker is not None:
            return None
        return {"kind": entry.kind, "note": entry.note}

    def is_ewf(self) -> bool:
        """True when this source is an EWF (.E01) acquisition."""
        return self._handle.is_ewf

    def verify_ewf(
        self, progress: Callable[[int, int], None] | None = None
    ) -> dict[str, Any]:
        """Recompute this EWF acquisition's MD5/SHA1 and compare them to the
        acquisition's own stored hashes. Only valid when is_ewf() is True."""
        from crush.core.raw_image import verify_ewf

        return verify_ewf(self._handle, progress=progress)

    def file_count(self, node: VFSNode) -> int:
        return self._file_counts.get(node.path, 0)

    def total_size(self, node: VFSNode) -> int:
        return self._total_sizes.get(node.path, 0)

    def _compute_file_counts(self, node: VFSNode) -> int:
        if not node.is_dir:
            self._file_counts[node.path] = 1
            return 1
        total = 0
        for child in node.children:
            total += self._compute_file_counts(child)
        self._file_counts[node.path] = total
        return total

    def _compute_total_sizes(self, node: VFSNode) -> int:
        if not node.is_dir:
            self._total_sizes[node.path] = node.size
            return node.size
        total = 0
        for child in node.children:
            total += self._compute_total_sizes(child)
        self._total_sizes[node.path] = total
        return total


class UFDRVFS(VFS):
    """VFS backed by a Cellebrite UFDR (Physical Analyzer report/delivery
    container). Browses the original device's file/folder tree, decoded
    from the container's embedded PostgreSQL dump -- see crush.core.ufdr
    for the format details and every fact this was verified against.

    Only the device filesystem is exposed here; Cellebrite's other ~185
    forensic tables (Contacts, Calls, Chats, ...) are out of scope.
    """

    def __init__(self, path: str | Path) -> None:
        from crush.core.ufdr import UFDRHandle, open_ufdr

        self._path = Path(path)
        self._handle: UFDRHandle = open_ufdr(self._path)
        self._zf_lock = threading.Lock()
        self._tree = self._handle.tree
        self._file_counts: dict[str, int] = {}
        self._total_sizes: dict[str, int] = {}
        self._compute_file_counts(self._tree)
        self._compute_total_sizes(self._tree)

    def root(self) -> VFSNode:
        return self._tree

    def read(self, node: VFSNode) -> bytes:
        info = self._handle.resolve(node)
        with self._zf_lock:
            return self._handle.zf.read(info)

    def open(self, node: VFSNode) -> IO[bytes]:
        info = self._handle.resolve(node)
        if node.size <= STREAM_THRESHOLD:
            return BytesIO(self.read(node))
        with self._zf_lock:
            inner = self._handle.zf.open(info)
        return buffered(LockedStream(inner, self._zf_lock))

    def peek(self, node: VFSNode, n: int = 32) -> bytes:
        info = self._handle.resolve(node)
        with self._zf_lock:
            with self._handle.zf.open(info) as f:
                return f.read(n)

    def node_info(self, node: VFSNode) -> dict[str, str] | None:
        """Cellebrite's own recorded MD5/SHA-256/category for *node*, plus an
        explicit "not located" status if its bytes couldn't be found in the
        container -- None for directories. See _enrich_with_format_info."""
        return self._handle.node_info(node)

    def close(self) -> None:
        self._handle.close()

    def file_count(self, node: VFSNode) -> int:
        return self._file_counts.get(node.path, 0)

    def total_size(self, node: VFSNode) -> int:
        return self._total_sizes.get(node.path, 0)

    def _compute_file_counts(self, node: VFSNode) -> int:
        if not node.is_dir:
            self._file_counts[node.path] = 1
            return 1
        total = 0
        for child in node.children:
            total += self._compute_file_counts(child)
        self._file_counts[node.path] = total
        return total

    def _compute_total_sizes(self, node: VFSNode) -> int:
        if not node.is_dir:
            self._total_sizes[node.path] = node.size
            return node.size
        total = 0
        for child in node.children:
            total += self._compute_total_sizes(child)
        self._total_sizes[node.path] = total
        return total


class BytesVFS(VFS):
    """VFS backed by a single in-memory bytes object (for artifact chaining)."""

    def __init__(self, data: bytes, name: str = "blob", path: str | None = None) -> None:
        self._data = data
        if path is None and name.startswith("/"):
            path = name
            name = name.rstrip("/").rsplit("/", 1)[-1] or "blob"
        self._root = VFSNode(
            name=name,
            path=path or f"/{name}",
            is_dir=False,
            size=len(data),
        )

    def root(self) -> VFSNode:
        return self._root

    def read(self, node: VFSNode) -> bytes:
        return self._data

    def open(self, node: VFSNode) -> IO[bytes]:
        return BytesIO(self._data)

    def file_count(self, node: VFSNode) -> int:
        return 1

    def total_size(self, node: VFSNode) -> int:
        return len(self._data)


def find_sibling(node: VFSNode, vfs: VFS, name_suffix: str) -> "VFSNode | None":
    """Find a sibling VFSNode whose name equals node.name + name_suffix.

    Path comparisons are done on a "/"-normalized form: ``DirectoryVFS`` builds
    ``node.path`` from ``str(Path(...))``, which uses backslashes on Windows,
    while archive-backed VFS implementations always use "/" — normalizing here
    lets the same lookup work against either.
    """
    target_name = node.name + name_suffix
    node_path = node.path.replace("\\", "/")
    parent_path = node_path.rsplit("/", 1)[0] or "/"
    target_path = (parent_path.rstrip("/") + "/" + target_name).replace("//", "/")
    return _find_node_by_path(vfs.root(), target_path)


def _find_node_by_path(node: VFSNode, path: str) -> "VFSNode | None":
    """Descend by matching path segments — touches only the nodes on the direct
    path from the root to the target (roughly tree depth), not every node in
    the tree. The previous version recursed into every child unconditionally,
    so looking up one sibling file cost a full traversal of the whole VFS —
    unnoticeable on a small source, but a real hit on a full filesystem
    extraction with hundreds of thousands of nodes.

    *path* is already "/"-normalized by the caller; node.path is normalized
    here for comparison (see find_sibling's docstring)."""
    node_path = node.path.replace("\\", "/")
    if node_path == path:
        return node
    node_prefix = node_path if node_path.endswith("/") else node_path + "/"
    if node_path != "/" and not path.startswith(node_prefix):
        return None  # target isn't under this subtree at all
    remainder = path[len(node_prefix):] if node_path != "/" else path.lstrip("/")
    next_name = remainder.split("/", 1)[0]
    for child in node.children:
        if child.name == next_name:
            return _find_node_by_path(child, path)
    return None


def resolve_relative_path(root: VFSNode, rel_path: str) -> "VFSNode | None":
    """Walk *root*'s children by name to find the node at *rel_path* (e.g.
    ``"Documents/chat.db"``, relative to *root* itself). Accepts both "/" and
    "\\" as separators, so a path typed on Windows still resolves. Returns
    None if any segment along the way isn't found — the caller must surface
    that explicitly rather than silently doing nothing (see
    feedback_explicit_unsupported_marking)."""
    parts = [p for p in re.split(r"[\\/]+", rel_path.strip()) if p not in ("", ".")]
    node = root
    for part in parts:
        found = next((child for child in node.children if child.name == part), None)
        if found is None:
            return None
        node = found
    return node


# Archive signatures at offset 0. ZIP: local file header, end of central
# directory (all an empty archive has) and the split/spanned-archive marker
# ahead of the first local header (PKWARE APPNOTE 4.3.7, 4.3.16, 8.5.3).
# 7z: signature header (7-Zip 7zFormat.txt). TAR: "ustar" at offset 257 in
# the first header block, POSIX ("ustar\0") and GNU ("ustar  \0") alike.
_ZIP_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08PK\x03\x04")
_7Z_SIGNATURE = b"7z\xbc\xaf\x27\x1c"
_GZIP_MAGIC = b"\x1f\x8b"
_BZIP2_MAGIC = b"BZh"
_XZ_MAGIC = b"\xfd7zXZ\x00"
_ANDROID_BACKUP_MAGIC = b"ANDROID BACKUP"
SNIFF_BYTES = 512

# Names that announce an archive. Only used to say "named X, but it isn't"
# when the content disagrees -- and for pre-POSIX (V7) TAR, which has no
# magic, so its name is all there is to go by.
_NAMED_ARCHIVES = {".zip": "ZIP", ".7z": "7z", ".ufdr": "ZIP (UFDR)", ".gz": "gzip", ".ab": "Android backup"}
_TAR_SUFFIXES = (".tar", ".tgz", ".tbz2", ".txz", ".tar.gz", ".tar.bz2", ".tar.xz")


def archive_kind(head: bytes) -> str | None:
    """The browsable-source kind that a file's first bytes prove: "zip",
    "7z", "tar", "gzip" or "android_backup"; None otherwise. bzip2/xz give
    None -- only decompressing shows whether a TAR is inside. Needs up to
    SNIFF_BYTES of *head* (the TAR magic sits at offset 257)."""
    if head.startswith(_ZIP_SIGNATURES):
        return "zip"
    if head.startswith(_7Z_SIGNATURE):
        return "7z"
    if head[257:262] == b"ustar":
        return "tar"
    if head.startswith(_GZIP_MAGIC):
        return "gzip"
    # The first line, within 64 bytes (a file with no newline, e.g. a disk
    # image starting with zeros, must not be read whole to find out).
    if head[:64].split(b"\n", 1)[0].strip() == _ANDROID_BACKUP_MAGIC:
        return "android_backup"
    return None


def zip_leading_bytes(path: str | Path) -> int | None:
    """How many bytes precede a ZIP archive that is found through its end
    of central directory record rather than at offset 0 (self-extracting
    executable, ZIP appended to an image), or None when there is none or
    it holds no entries."""
    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
    except (zipfile.BadZipFile, OSError, ValueError, EOFError, NotImplementedError):
        return None
    if not infos:
        return None
    return min(info.header_offset for info in infos) or None


def open_vfs(path: str | Path, *, password: str = "", embedded_zip: bool = False) -> VFS:
    """Factory — open the right VFS type for a source path, by its content
    (see _open_vfs), and note once if reading it may update the evidence's
    access times."""
    vfs = _open_vfs(path, password=password, embedded_zip=embedded_zip)
    if not vfs.load_note:
        vfs.load_note = _source_atime_note(Path(path), vfs)
    return vfs


def _read_only_mount(path: Path) -> bool:
    try:
        return bool(os.statvfs(path).f_flag & os.ST_RDONLY)
    except (OSError, AttributeError):  # no statvfs on Windows
        return False


def _source_atime_note(path: Path, vfs: VFS) -> str:
    """load_note for a single file opened directly (DirectoryVFS sets its
    own). Archives, backups and disk images get none: only the container's
    access time can change there, never that of the files inside it."""
    if not isinstance(vfs, FileVFS):
        return ""
    try:
        owner = path.stat().st_uid
    except OSError:
        return ""
    euid = os.geteuid() if hasattr(os, "geteuid") else None
    return _atime_note(path, 1 if euid is not None and owner != euid else 0)


def _open_vfs(path: str | Path, *, password: str = "", embedded_zip: bool = False) -> VFS:
    """Open the right VFS type for a source path, by its content.

    Archives, backups and disk images are recognised by their bytes; a name
    only counts for V7 TAR (no magic). A file named like an archive whose
    content isn't one opens as a single file, and its fallback_note says so.
    *embedded_zip* also opens a ZIP that follows leading bytes -- the
    explicit "Open in New Window" path; a plain open only notes it.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File no longer exists: {p}")
    if p.is_dir():
        if _is_itunes_backup_dir(p):
            return ITunesBackupVFS(p, password=password)
        return DirectoryVFS(p)
    if not p.is_file():
        raise ValueError(f"Unsupported source type: {p}")

    notes: list[str] = []
    with open(p, "rb") as f:
        head = f.read(SNIFF_BYTES)
    kind = archive_kind(head)
    vfs: VFS | None = None
    if kind == "zip":
        vfs = _open_zip(p, password, notes)
    elif kind == "7z":
        vfs = _open_7z(p, password, notes)
    elif kind == "tar":
        vfs = _open_tar(p, "TAR signature found", notes)
    elif kind == "gzip":
        return TarVFS(p) if _is_gzip_wrapped_tar(p) else GzipVFS(p)
    elif kind == "android_backup":
        return AndroidBackupVFS(p, password=password)
    elif head.startswith((_BZIP2_MAGIC, _XZ_MAGIC)) and _is_compressed_tar(p):
        vfs = _open_tar(p, "Compressed TAR found", notes)
    elif p.name.lower().endswith(_TAR_SUFFIXES):
        # Pre-POSIX (V7) TAR has no magic; its name is all there is.
        vfs = _open_tar(p, f"Named {_tar_suffix(p)}", notes)
    if vfs is not None:
        vfs.fallback_note = "; ".join(notes)
        return vfs

    label = _NAMED_ARCHIVES.get(p.suffix.lower())
    if label is not None and kind is None and not notes:
        notes.append(f"Named {p.suffix.lower()}, but no {label} signature found")
    if kind is None:
        leading = zip_leading_bytes(p)
        if leading is not None:
            if embedded_zip:
                zip_vfs = _open_zip(p, password, notes)
                if zip_vfs is not None:
                    zip_vfs.fallback_note = "; ".join(
                        [f"ZIP archive opened after {leading:,} leading bytes", *notes]
                    )
                    return zip_vfs
            else:
                notes.append(
                    f"Contains a ZIP archive after {leading:,} leading bytes — "
                    "right-click → Open in New Window to browse it"
                )

    # A disk image is recognised by its content, never its name -- .bin
    # or no extension at all are as common as .img/.dd. qnxprobe itself
    # decides (partition table, bare filesystem, EWF signature); anything
    # it finds nothing browsable in stays a file.
    from crush.core.raw_image import RawImageOpenError

    try:
        vfs = RawImageVFS(p)
    except RawImageOpenError as exc:
        vfs = FileVFS(p)
        raw_note = _raw_image_fallback_note(p, exc)
        if raw_note:
            notes.append(raw_note)
    vfs.fallback_note = "; ".join(notes)
    return vfs


def _open_zip(p: Path, password: str, notes: list[str]) -> VFS | None:
    """UFDRVFS for a UFDR's layout, else ZipVFS; None (reason in *notes*)
    when the archive can't be read. Password errors propagate."""
    from crush.core.ufdr import UFDROpenError, is_ufdr_zip

    if is_ufdr_zip(p):
        try:
            return UFDRVFS(p)
        except UFDROpenError as exc:
            notes.append(f"UFDR layout found, but not opened as UFDR ({exc}); shown as plain ZIP")
    try:
        return ZipVFS(p, password=password)
    except (zipfile.BadZipFile, OSError, ValueError, EOFError, NotImplementedError) as exc:
        if isinstance(exc, (PasswordRequiredError, WrongPasswordError)):
            raise
        notes.append(f"ZIP signature found, but not opened as ZIP — {exc}")
        return None


def _open_7z(p: Path, password: str, notes: list[str]) -> VFS | None:
    """SevenZipVFS; None (reason in *notes*) when the archive can't be
    read. Password errors propagate."""
    import py7zr

    try:
        return SevenZipVFS(p, password=password)
    except (py7zr.exceptions.ArchiveError, TypeError) as exc:
        notes.append(f"7z signature found, but not opened as 7z — {exc}")
        return None


def _open_tar(p: Path, what: str, notes: list[str]) -> VFS | None:
    try:
        return TarVFS(p)
    except (tarfile.TarError, OSError, EOFError) as exc:
        notes.append(f"{what}, but not opened as TAR — {exc}")
        return None


def _tar_suffix(p: Path) -> str:
    name = p.name.lower()
    return next(s for s in sorted(_TAR_SUFFIXES, key=len, reverse=True) if name.endswith(s))


_RAW_IMAGE_SUFFIXES = (".img", ".dd", ".raw", ".e01", ".001")


def _raw_image_fallback_note(path: Path, exc: Exception) -> str:
    """Why a file that was meant to be a disk image opened as a plain file,
    or "" when nothing suggests it was meant to be one.

    Every file is offered to qnxprobe, so "nothing browsable found" is the
    normal answer for a database or a log and says nothing. It is only worth
    surfacing when the file announces itself as an image: an image
    extension, the EWF signature, or a numbered segment of a split set
    (FTK-style three-digit suffix) that couldn't be joined.
    """
    import crush.core.raw_image  # noqa: F401 — registers vendored ewfprobe before qnxprobe loads
    from crush.third_party import qnxprobe

    suffix = path.suffix.lower()
    split_error = isinstance(exc.__cause__, qnxprobe.SplitImageError)
    is_segment = len(suffix) >= 4 and suffix[1:].isascii() and suffix[1:].isdigit()
    if (
        suffix in _RAW_IMAGE_SUFFIXES
        or qnxprobe.looks_like_ewf(str(path))  # type: ignore[no-untyped-call]
        or (split_error and is_segment)
    ):
        return f"Not opened as a disk image — {exc}"
    return ""


def is_browsable_source_file(path: str | Path) -> bool:
    """True when open_vfs() would open this on-disk file as a browsable
    source (archive, backup, disk image) rather than a single file -- the
    content-sniffed cases only; extension-routed archives are the caller's
    cheaper check. Mirrors open_vfs()'s own sniffing."""
    p = Path(path)
    if not p.is_file():
        return False
    with open(p, "rb") as f:
        head = f.read(SNIFF_BYTES)
    if archive_kind(head) is not None:
        return True
    if head.startswith((_BZIP2_MAGIC, _XZ_MAGIC)) and _is_compressed_tar(p):
        return True
    from crush.core.raw_image import RawImageOpenError, open_raw_image

    try:
        open_raw_image(p).close()
    except RawImageOpenError:
        return False
    return True


def _is_compressed_tar(path: Path) -> bool:
    """True if a bzip2- or xz-magic file decompresses to a TAR (ustar magic
    at offset 257) -- the bzip2/xz counterpart of _is_gzip_wrapped_tar."""
    import bz2
    import lzma

    try:
        with open(path, "rb") as f:
            is_bzip2 = f.read(3) == _BZIP2_MAGIC
    except OSError:
        return False
    opener = bz2.open if is_bzip2 else lzma.open
    try:
        with opener(path, "rb") as f:
            head = f.read(265)
    except (OSError, EOFError, lzma.LZMAError):
        return False
    return head[257:262] == b"ustar"


def _is_gzip_wrapped_tar(path: Path) -> bool:
    """True if a gzip-magic file decompresses to a TAR (ustar magic at
    offset 257) rather than an arbitrary single file — used to route a
    renamed or extensionless .tar.gz correctly, since a gzip-wrapped tar is
    indistinguishable from plain gzip by its outer magic bytes alone. A
    named .tar.gz/.tgz skips this (already routed to TarVFS by extension)."""
    try:
        with gzip.open(path, "rb") as f:
            head = f.read(265)
    except OSError:
        return False
    return head[257:262] == b"ustar"


def _is_itunes_backup_dir(path: Path) -> bool:
    """A backup folder has Manifest.db plus an Info.plist or Manifest.plist sibling."""
    return (path / "Manifest.db").is_file() and (
        (path / "Info.plist").is_file() or (path / "Manifest.plist").is_file()
    )


_HEX_SHARD_RE = re.compile(r"^[0-9a-fA-F]{2}$")


def _has_hex_shard_sibling(names: set[str], prefix: str) -> bool:
    """True if a two-hex-character subdirectory (the "ab/ab123..." fileID
    sharding real backups use since iOS 10) sits directly alongside
    Manifest.db — not just anywhere in the archive, but as an immediate
    sibling at the same directory level."""
    for name in names:
        if not name.startswith(prefix):
            continue
        top = name[len(prefix):].split("/", 1)[0]
        if _HEX_SHARD_RE.match(top):
            return True
    return False


def _manifest_plist_has_backup_keybag(zf: zipfile.ZipFile, manifest_plist_name: str) -> bool:
    """Every real Manifest.plist (encrypted backup or not) has a BackupKeyBag
    since iOS 10.2 — a name collision with some unrelated app's own
    Manifest.db/Info.plist won't also happen to have this exact key."""
    try:
        data = plistlib.loads(zf.read(manifest_plist_name))
    except Exception:
        return False
    return isinstance(data, dict) and "BackupKeyBag" in data


def detect_itunes_backup_in_zip(path: str | Path) -> str | None:
    """Return the in-zip directory prefix of a wrapped iTunes backup, or None.

    Filename matching alone is not enough — a full filesystem extraction can
    easily contain an unrelated app with its own "Manifest.db" sitting next
    to the "Info.plist" every app bundle has, which used to be a false
    positive here. Four signals are now required together: the three backup
    metadata files (Info.plist, Manifest.plist, Status.plist — not just one
    of two), a hex-sharded fileID subdirectory as an immediate sibling of
    Manifest.db, and Manifest.plist actually containing a BackupKeyBag (the
    one content check, cheap since it's a single small file).
    """
    with zipfile.ZipFile(path) as zf:
        names = set(zf.namelist())
        for name in names:
            if not name.endswith("Manifest.db"):
                continue
            prefix = name[: -len("Manifest.db")]
            if not (
                f"{prefix}Info.plist" in names
                and f"{prefix}Manifest.plist" in names
                and f"{prefix}Status.plist" in names
            ):
                continue
            if not _has_hex_shard_sibling(names, prefix):
                continue
            if not _manifest_plist_has_backup_keybag(zf, f"{prefix}Manifest.plist"):
                continue
            return prefix
    return None


def open_itunes_backup_from_zip(
    path: str | Path, prefix: str, *, password: str = ""
) -> ITunesBackupVFS:
    """Extract a wrapped iTunes backup out of a zip and open it.

    Only called once the user has confirmed they want this (see
    detect_itunes_backup_in_zip); the extracted copy is removed again when
    the returned VFS is closed.
    """
    tmp_dir = tempdir.mkdtemp(prefix="crush-itunes-backup-")
    try:
        with zipfile.ZipFile(path) as zf:
            zf.extractall(tmp_dir)
        return ITunesBackupVFS(tmp_dir / prefix, password=password, _cleanup_dir=tmp_dir)
    except Exception:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise


class FileVFS(VFS):
    """VFS backed by a single file."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        stat = self._path.stat()
        self._root = VFSNode(
            name=self._path.name,
            path=str(self._path),
            is_dir=False,
            size=stat.st_size,
            modified=stat.st_mtime,
            accessed=stat.st_atime,
            changed=stat.st_ctime,
            birth=getattr(stat, "st_birthtime", 0.0),
        )

    def root(self) -> VFSNode:
        return self._root

    def read(self, node: VFSNode) -> bytes:
        return _read_noatime(Path(node.path))

    def open(self, node: VFSNode) -> IO[bytes]:
        return _open_noatime(Path(node.path))

    def file_count(self, node: VFSNode) -> int:
        return 1

    def total_size(self, node: VFSNode) -> int:
        return node.size
