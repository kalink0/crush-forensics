"""Virtual Filesystem (VFS) abstraction.

All source types (ZIP archive, directory, future: AFF4, tar) are presented
through a single interface so viewers never need to know the origin.
"""
from __future__ import annotations

import os
import plistlib
import re
import shutil
import sqlite3
import sys
import tarfile
import tempfile
import threading
import zipfile
import zlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import io
from io import BytesIO
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any, Iterator, cast

from crush.core.passwords import PasswordRequiredError, WrongPasswordError

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
        except OSError:
            pass


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
            return path.read_bytes()
        with os.fdopen(fd, "rb") as f:
            return f.read()
    if sys.platform == "win32":
        st = path.stat()
        data = path.read_bytes()
        try:
            os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))
        except OSError:
            pass
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

    @property
    def extension(self) -> str:
        return Path(self.name).suffix.lower()


class VFS(ABC):
    """Abstract virtual filesystem."""

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


class DirectoryVFS(VFS):
    """VFS backed by a plain directory on disk."""

    def __init__(self, path: str | Path) -> None:
        self._root_path = Path(path)
        self._tree = self._build_node(self._root_path)
        self._file_counts: dict[str, int] = {}
        self._total_sizes: dict[str, int] = {}
        self._compute_file_counts(self._tree)
        self._compute_total_sizes(self._tree)

    def root(self) -> VFSNode:
        return self._tree

    def _build_node(self, path: Path) -> VFSNode:
        stat = path.stat()
        node = VFSNode(
            name=path.name or str(path),
            path=str(path),
            is_dir=path.is_dir(),
            size=stat.st_size if path.is_file() else 0,
            modified=stat.st_mtime,
            accessed=stat.st_atime,
            changed=stat.st_ctime,
            birth=getattr(stat, "st_birthtime", 0.0),
        )
        if path.is_dir():
            node.children = sorted(
                [self._build_node(child) for child in path.iterdir()],
                key=lambda n: (not n.is_dir, n.name.lower()),
            )
        return node

    def read(self, node: VFSNode) -> bytes:
        return _read_noatime(Path(node.path))

    def open(self, node: VFSNode) -> IO[bytes]:
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
        self._zip_names: dict[str, str] = {}
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
        encrypted_names = [info.filename for info in self._zf.infolist() if info.flag_bits & 0x1]
        if not encrypted_names:
            return
        if not self._password:
            raise PasswordRequiredError(f"ZIP archive is password-protected: {self._zip_path}")
        try:
            with self._open_entry(encrypted_names[0]) as f:
                f.read()
        except RuntimeError as exc:
            raise WrongPasswordError("Incorrect ZIP archive password") from exc

    def _aes_zip(self) -> Any:
        if self._aes_zf is None:
            import pyzipper

            self._aes_zf = pyzipper.AESZipFile(self._zip_path, "r")
        return self._aes_zf

    def _open_entry(self, name: str) -> IO[bytes]:
        pwd = self._password.encode("utf-8") if self._password else None
        if self._zf.getinfo(name).compress_type == self._WZ_AES_COMPRESS_TYPE:
            return cast(IO[bytes], self._aes_zip().open(name, pwd=pwd))
        return self._zf.open(name, pwd=pwd)

    def _build_tree(self) -> VFSNode:
        root = VFSNode(name=self._zip_path.name, path="/", is_dir=True)
        nodes: dict[str, VFSNode] = {"/": root}
        _offsets: dict[str, int] = {}  # virtual_path -> header_offset for storage-order prescan

        for info in sorted(self._zf.infolist(), key=lambda i: i.filename):
            # Filter empty components (from leading/double slashes) and "." — same
            # normalisation TarVFS applies with lstrip("./").  Keeps ".." intact so
            # the archive structure is represented faithfully.
            parts = [p for p in info.filename.rstrip("/").split("/") if p and p != "."]
            if not parts:
                continue
            for depth, _ in enumerate(parts, 1):
                virtual_path = "/" + "/".join(parts[:depth])
                if virtual_path not in nodes:
                    is_dir = depth < len(parts) or info.filename.endswith("/")
                    zip_ts = 0.0
                    if info.date_time:
                        from datetime import datetime
                        zip_ts = datetime(*info.date_time).timestamp()
                    node = VFSNode(
                        name=parts[depth - 1],
                        path=virtual_path,
                        is_dir=is_dir,
                        size=info.file_size if not is_dir else 0,
                        modified=zip_ts,
                    )
                    parent_path = "/" + "/".join(parts[: depth - 1]) if depth > 1 else "/"
                    nodes[parent_path].children.append(node)
                    nodes[virtual_path] = node
                if depth == len(parts) and not info.filename.endswith("/"):
                    self._zip_names[virtual_path] = info.filename
                    _offsets[virtual_path] = info.header_offset

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
                with self._open_entry(self._zip_name(node)) as f:
                    return f.read(n)
            except RuntimeError as exc:
                raise WrongPasswordError("Incorrect ZIP archive password") from exc

    def read(self, node: VFSNode) -> bytes:
        with self._zf_lock:
            try:
                with self._open_entry(self._zip_name(node)) as f:
                    return f.read()
            except RuntimeError as exc:
                raise WrongPasswordError("Incorrect ZIP archive password") from exc

    def open(self, node: VFSNode) -> IO[bytes]:
        return BytesIO(self.read(node))

    def _zip_name(self, node: VFSNode) -> str:
        return self._zip_names.get(node.path, node.path.lstrip("/"))

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
    """

    def __init__(self, path: str | Path) -> None:
        self._tar_path = Path(path)
        self._tf = tarfile.open(str(self._tar_path), "r:*")
        self._tf_lock = threading.Lock()
        self._members: dict[str, tarfile.TarInfo] = {}
        self._tree = self._build_tree()
        self._file_counts: dict[str, int] = {}
        self._total_sizes: dict[str, int] = {}
        self._compute_file_counts(self._tree)
        self._compute_total_sizes(self._tree)

    def _build_tree(self) -> VFSNode:
        root = VFSNode(name=self._tar_path.name, path="/", is_dir=True)
        nodes: dict[str, VFSNode] = {"/": root}

        for member in self._tf.getmembers():
            raw_name = member.name.lstrip("./")
            if not raw_name:
                continue
            parts = raw_name.split("/")
            for depth in range(1, len(parts) + 1):
                virtual_path = "/" + "/".join(parts[:depth])
                if virtual_path in nodes:
                    continue
                is_dir = depth < len(parts) or member.isdir()
                node = VFSNode(
                    name=parts[depth - 1],
                    path=virtual_path,
                    is_dir=is_dir,
                    size=member.size if (not is_dir and member.isfile()) else 0,
                    modified=float(member.mtime),
                )
                parent_path = "/" + "/".join(parts[: depth - 1]) if depth > 1 else "/"
                if parent_path in nodes:
                    nodes[parent_path].children.append(node)
                nodes[virtual_path] = node
            if member.isfile():
                self._members[virtual_path] = member

        for node in nodes.values():
            node.children.sort(key=lambda n: (not n.is_dir, n.name.lower()))
        return root

    def root(self) -> VFSNode:
        return self._tree

    def read(self, node: VFSNode) -> bytes:
        member = self._members.get(node.path)
        if member is None:
            raise FileNotFoundError(f"Not in TAR: {node.path}")
        with self._tf_lock:
            f = self._tf.extractfile(member)
            if f is None:
                raise OSError(f"Cannot extract (symlink or special file): {node.path}")
            return f.read()

    def open(self, node: VFSNode) -> IO[bytes]:
        return BytesIO(self.read(node))

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


class AndroidBackupVFS(TarVFS):
    """VFS backed by an `adb backup` container (.ab), encrypted or not.

    The .ab format is a text header (magic, version, compressed flag,
    encryption flag) followed by a single tar stream, optionally
    deflate-compressed and/or AES-256 encrypted (see
    `crush.core.android_backup_crypto` for the password-based key unwrap).

    The tar stream is decompressed fully upfront (backups are app-data
    sized, not full-disk images) and then handled identically to a plain
    TarVFS by reusing its tree-building and read logic.
    """

    def __init__(self, path: str | Path, *, password: str = "") -> None:
        self._tar_path = Path(path)
        self._tf = tarfile.open(
            fileobj=BytesIO(self._extract_tar_bytes(self._tar_path, password)), mode="r:"
        )
        self._tf_lock = threading.Lock()
        self._members: dict[str, tarfile.TarInfo] = {}
        self._tree = self._build_tree()
        self._file_counts: dict[str, int] = {}
        self._total_sizes: dict[str, int] = {}
        self._compute_file_counts(self._tree)
        self._compute_total_sizes(self._tree)

    @staticmethod
    def _extract_tar_bytes(path: Path, password: str = "") -> bytes:
        with open(path, "rb") as f:
            magic = f.readline().strip()
            if magic != b"ANDROID BACKUP":
                raise ValueError(f"Not an Android backup: {path}")
            version = int(f.readline().strip())
            compressed = f.readline().strip()
            encryption = f.readline().strip()

            if encryption == b"none":
                payload = f.read()
                return zlib.decompress(payload) if compressed == b"1" else payload

            if encryption != b"AES-256":
                raise ValueError(f"Unsupported Android backup encryption: {encryption!r}")
            if not password:
                raise PasswordRequiredError(f"Android backup is password-protected: {path}")

            user_salt = bytes.fromhex(f.readline().strip().decode("ascii"))
            checksum_salt = bytes.fromhex(f.readline().strip().decode("ascii"))
            rounds = int(f.readline().strip())
            user_iv = bytes.fromhex(f.readline().strip().decode("ascii"))
            master_key_blob = bytes.fromhex(f.readline().strip().decode("ascii"))
            ciphertext = f.read()

        from crush.core import android_backup_crypto

        master_key, master_iv = android_backup_crypto.unwrap_master_key(
            password, user_salt, checksum_salt, rounds, user_iv, master_key_blob, version
        )
        payload = android_backup_crypto.decrypt_payload(master_key, master_iv, ciphertext)
        return zlib.decompress(payload) if compressed == b"1" else payload


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

    def __init__(
        self, path: str | Path, *, password: str = "", _cleanup_dir: Path | None = None
    ) -> None:
        self._backup_path = Path(path)
        self._password = password
        self._cleanup_dir = _cleanup_dir
        self._keybag: ios_keybag.BackupKeyBag | None = None

        self._file_locations: dict[str, Path] = {}
        self._file_protection: dict[str, tuple[int, bytes]] = {}
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
            if not is_leaf_dir:
                located = self._locate_file(file_id)
                if located is not None:
                    nodes[virtual_path].size = located.stat().st_size
                    self._file_locations[virtual_path] = located

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
        if node.path in self._file_protection:
            return BytesIO(self.read(node))
        located = self._file_locations.get(node.path)
        if located is None:
            raise FileNotFoundError(f"Not backed by a file in the backup: {node.path}")
        return _open_noatime(located)

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
        self._entry_names: dict[str, str] = {}
        self._read_cache: dict[str, bytes] = {}
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
        from py7zr.io import BytesIOFactory

        name = next(iter(self._entry_names.values()))
        with self._zf_lock:
            factory = BytesIOFactory(limit=_SEVENZIP_EXTRACT_LIMIT)
            self._extract([name], factory)
            buf = factory.get(name)  # type: ignore[no-untyped-call]
            self._read_cache[name] = buf.read() if buf is not None else b""

    def _build_tree(self) -> VFSNode:
        root = VFSNode(name=self._path.name, path="/", is_dir=True)
        nodes: dict[str, VFSNode] = {"/": root}

        infos = self._zf.list()
        self._zf.reset()

        for info in sorted(infos, key=lambda i: i.filename):
            parts = [p for p in info.filename.rstrip("/").split("/") if p and p != "."]
            if not parts:
                continue
            for depth, _ in enumerate(parts, 1):
                virtual_path = "/" + "/".join(parts[:depth])
                if virtual_path not in nodes:
                    is_dir = depth < len(parts) or info.is_directory
                    ts = info.creationtime.timestamp() if info.creationtime else 0.0
                    node = VFSNode(
                        name=parts[depth - 1],
                        path=virtual_path,
                        is_dir=is_dir,
                        size=info.uncompressed if not is_dir else 0,
                        modified=ts,
                    )
                    parent_path = "/" + "/".join(parts[: depth - 1]) if depth > 1 else "/"
                    nodes[parent_path].children.append(node)
                    nodes[virtual_path] = node
                if depth == len(parts) and not info.is_directory:
                    self._entry_names[virtual_path] = info.filename

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

    def read(self, node: VFSNode) -> bytes:
        name = self._entry_names.get(node.path, node.path.lstrip("/"))
        cached = self._read_cache.get(name)
        if cached is not None:
            return cached
        from py7zr.io import BytesIOFactory

        with self._zf_lock:
            factory = BytesIOFactory(limit=_SEVENZIP_EXTRACT_LIMIT)
            self._extract([name], factory)
            buf = factory.get(name)  # type: ignore[no-untyped-call]
            data = buf.read() if buf is not None else b""
        self._read_cache[name] = data
        return data

    def open(self, node: VFSNode) -> IO[bytes]:
        return BytesIO(self.read(node))

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
        missing = [name for name in self._entry_names.values() if name not in self._read_cache]
        if not missing:
            return True
        from py7zr.io import BytesIOFactory

        with self._zf_lock:
            factory = BytesIOFactory(limit=_SEVENZIP_EXTRACT_LIMIT)
            self._zf.extract(targets=missing, factory=factory)
            for name in missing:
                buf = factory.get(name)  # type: ignore[no-untyped-call]
                self._read_cache[name] = buf.read() if buf is not None else b""
            self._zf.reset()
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


class BytesVFS(VFS):
    """VFS backed by a single in-memory bytes object (for artifact chaining)."""

    def __init__(self, data: bytes, name: str = "blob") -> None:
        self._data = data
        self._root = VFSNode(
            name=name,
            path=f"/{name}",
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
    """Find a sibling VFSNode whose name equals node.name + name_suffix."""
    target_name = node.name + name_suffix
    parent_path = node.path.rsplit("/", 1)[0] or "/"
    target_path = (parent_path.rstrip("/") + "/" + target_name).replace("//", "/")
    return _find_node_by_path(vfs.root(), target_path)


def _find_node_by_path(node: VFSNode, path: str) -> "VFSNode | None":
    if node.path == path:
        return node
    for child in node.children:
        result = _find_node_by_path(child, path)
        if result is not None:
            return result
    return None


def open_vfs(path: str | Path, *, password: str = "") -> VFS:
    """Factory — open the right VFS type based on the source path."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File no longer exists: {p}")
    if p.is_dir():
        if _is_itunes_backup_dir(p):
            return ITunesBackupVFS(p, password=password)
        return DirectoryVFS(p)
    name_lower = p.name.lower()
    if p.suffix.lower() == ".zip":
        return ZipVFS(p, password=password)
    if p.suffix.lower() == ".7z":
        return SevenZipVFS(p, password=password)
    if (
        p.suffix.lower() in (".tar", ".tgz", ".tbz2", ".txz")
        or name_lower.endswith(".tar.gz")
        or name_lower.endswith(".tar.bz2")
        or name_lower.endswith(".tar.xz")
    ):
        return TarVFS(p)
    if p.suffix.lower() == ".ab" or _is_android_backup(p):
        return AndroidBackupVFS(p, password=password)
    if p.is_file():
        return FileVFS(p)
    raise ValueError(f"Unsupported source type: {p}")


def _is_android_backup(path: Path) -> bool:
    """Magic-byte sniff for extensionless Android backup containers."""
    if not path.is_file():
        return False
    with open(path, "rb") as f:
        return f.readline().strip() == b"ANDROID BACKUP"


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
    tmp_dir = Path(tempfile.mkdtemp(prefix="crush-itunes-backup-"))
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
