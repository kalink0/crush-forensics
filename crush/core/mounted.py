# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Sources built from other sources' trees.

A ZIP can hold an iTunes backup beside other data -- an extraction in the
UFED layout keeps the backup under `Backup Service/<UDID>/Snapshot/` next
to `AFC Service/`, `Applications/` and `Lockdown Service/`. Opened as the
backup alone, everything beside it would be left out; opened as a ZIP, the
backup is only its stored, hash-named files. `_MountVFS` shows both: the
ZIP's tree, with each backup's folder holding the opened backup instead.

`ZipWithITunesBackupVFS` is that for a ZIP opened directly; a UFD's dumps
(crush.core.ufd) use the same mechanism.
"""
from __future__ import annotations

import logging
import threading
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import IO, Any

from crush.core.issues import ParseIssue
from crush.core.passwords import PasswordRequiredError, WrongPasswordError
from crush.core.vfs import (
    VFS,
    VFSNode,
    ZipVFS,
    itunes_backup_prefixes,
    open_itunes_backup_from_zip,
)

_logger = logging.getLogger(__name__)


class _MountVFS(VFS):
    """A tree of folders of its own, holding nodes of other VFSes (a ZIP's
    folder, an iTunes backup). Each such node is a copy under this tree's
    path; reading it reads the node it stands for."""

    def __init__(self, root: VFSNode) -> None:
        self._root = root
        self._nodes: dict[str, VFSNode] = {root.path: root}
        self._held: dict[str, tuple[VFS, VFSNode]] = {}
        self._subs: list[VFS] = []
        self._own_info: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._file_counts: dict[str, int] = {}
        self._total_sizes: dict[str, int] = {}

    # Building ----------------------------------------------------------------

    def _child_path(self, parent: VFSNode, name: str) -> str:
        return f"/{name}" if parent.path == "/" else f"{parent.path}/{name}"

    def _folder(self, parent: VFSNode, name: str, status: Any = "") -> VFSNode:
        path = self._child_path(parent, name)
        k = 2
        while path in self._nodes:
            path = self._child_path(parent, f"{name} ({k})")
            k += 1
        node = VFSNode(name=path.rsplit("/", 1)[-1], path=path, is_dir=True, status=status)
        parent.children.append(node)
        self._nodes[path] = node
        return node

    def _hold(
        self, dst: VFSNode, sub: VFS, src: VFSNode,
        replace: Callable[[VFSNode, VFSNode], bool] | None = None,
        skip: Callable[[VFSNode], bool] | None = None,
    ) -> None:
        """Copy *src*'s children (of *sub*) under *dst*. *replace* may put
        something else in a child's place (returns True when it did); *skip*
        leaves a child out (the caller shows it elsewhere)."""
        for child in src.children:
            if skip is not None and skip(child):
                continue
            path = self._child_path(dst, child.name)
            copy = VFSNode(
                name=child.name, path=path, is_dir=child.is_dir, size=child.size,
                modified=child.modified, accessed=child.accessed, changed=child.changed,
                birth=child.birth, status=child.status, stored_times=child.stored_times,
            )
            if replace is not None and child.is_dir and replace(child, copy):
                dst.children.append(copy)
                self._nodes[path] = copy
                continue
            dst.children.append(copy)
            self._nodes[path] = copy
            self._held[path] = (sub, child)
            if child.is_dir:
                self._hold(copy, sub, child, replace, skip)

    def _hold_zip_folder(
        self, dst: VFSNode, zip_vfs: ZipVFS, src: VFSNode, file: Path, *,
        typed_password: str, recorded_password: str = "",
    ) -> None:
        """*src*'s tree (a folder of the ZIP *file*) under *dst*, every
        iTunes backup in it -- recognised by its content -- opened as the
        backup in its folder's place; *src* itself too, when it is one (a
        ZIP holding a backup with no folder around it)."""
        with zipfile.ZipFile(file) as zf:
            backups = {"/" + p.rstrip("/") for p in itunes_backup_prefixes(zf)}
        if src.path in backups:
            self._hold_backup(dst, zip_vfs, src, file, typed_password, recorded_password)
            return

        def replace(child: VFSNode, copy: VFSNode) -> bool:
            if child.path not in backups:
                return False
            self._hold_backup(copy, zip_vfs, child, file, typed_password, recorded_password)
            return True

        self._hold(dst, zip_vfs, src, replace=replace)

    def _hold_backup(
        self, copy: VFSNode, zip_vfs: ZipVFS, child: VFSNode, file: Path,
        typed_password: str, recorded_password: str,
    ) -> None:
        """The iTunes backup in ZIP folder *child*, opened as the backup --
        with the password the source records (a UFD's BackupPassword), else
        the one the analyst typed: a password typed for another source of a
        UFDX never replaces one that opens. A password error goes to the
        caller (the analyst is asked); any other failure shows the folder's
        stored files instead, its status saying why."""
        prefix = "" if child.path == "/" else child.path.lstrip("/") + "/"
        try:
            backup = open_itunes_backup_from_zip(
                file, prefix, password=recorded_password, fallback_password=typed_password,
            )
        except WrongPasswordError as exc:
            if typed_password or not recorded_password:
                raise
            raise WrongPasswordError(ParseIssue("ufd.backup_password_rejected")) from exc
        except PasswordRequiredError:
            raise
        except Exception as exc:  # noqa: BLE001 -- shown as the folder's status
            copy.status = ParseIssue("vfs.itunes_backup_not_opened", detail=str(exc))
            if copy is not self._root:
                self._held[copy.path] = (zip_vfs, child)
            self._hold(copy, zip_vfs, child)
            return
        self._subs.append(backup)
        if recorded_password and backup.password == recorded_password:
            source = ParseIssue("ufd.password_from_ufd")
        elif backup.password:
            source = ParseIssue("vfs.password_typed")
        else:
            source = ParseIssue("vfs.password_none")
        copy.status = ParseIssue("vfs.itunes_backup_opened", {"password": source})
        self._hold(copy, backup, backup.root())

    def _finish(self) -> None:
        self._count(self._root)

    def _count(self, node: VFSNode) -> tuple[int, int]:
        if not node.is_dir:
            self._file_counts[node.path], self._total_sizes[node.path] = 1, node.size
            return 1, node.size
        files = size = 0
        for child in node.children:
            f, s = self._count(child)
            files += f
            size += s
        self._file_counts[node.path], self._total_sizes[node.path] = files, size
        return files, size

    # Reading -----------------------------------------------------------------

    def _sub(self, node: VFSNode) -> tuple[VFS, VFSNode]:
        held = self._held.get(node.path)
        if held is None:
            raise IsADirectoryError(node.path)
        return held

    def root(self) -> VFSNode:
        return self._root

    def delegate(self, node: VFSNode) -> tuple[VFS, VFSNode]:
        held = self._held.get(node.path)
        if held is None:
            return self, node
        sub, inner = held
        return sub.delegate(inner)

    def storage_ordered_files(self) -> list[VFSNode]:
        """This tree's file nodes in the order their ZIPs store them (for
        the type pre-scan's sequential reads); files of other sources after."""
        by_inner: dict[tuple[int, str], VFSNode] = {
            (id(sub), inner.path): self._nodes[path]
            for path, (sub, inner) in self._held.items()
            if not self._nodes[path].is_dir
        }
        ordered: list[VFSNode] = []
        seen: set[str] = set()
        for sub in self._subs:
            order = getattr(sub, "storage_ordered_files", None)
            if order is None:
                continue
            for inner in order():
                held = by_inner.get((id(sub), inner.path))
                if held is not None and held.path not in seen:
                    ordered.append(held)
                    seen.add(held.path)
        ordered.extend(
            n for p, n in self._nodes.items() if not n.is_dir and p not in seen
        )
        return ordered

    def read(self, node: VFSNode) -> bytes:
        sub, inner = self._sub(node)
        return sub.read(inner)

    def open(self, node: VFSNode) -> IO[bytes]:
        sub, inner = self._sub(node)
        return sub.open(inner)

    def peek(self, node: VFSNode, n: int = 32) -> bytes:
        sub, inner = self._sub(node)
        return sub.peek(inner, n)

    def peek_if_cached(self, node: VFSNode, n: int = 32) -> bytes | None:
        held = self._held.get(node.path)
        return None if held is None else held[0].peek_if_cached(held[1], n)

    def needs_prepare(self, node: VFSNode) -> bool:
        held = self._held.get(node.path)
        return False if held is None else held[0].needs_prepare(held[1])

    def prepare(self, node: VFSNode) -> None:
        held = self._held.get(node.path)
        if held is not None:
            held[0].prepare(held[1])

    def stored_times(self, node: VFSNode) -> Any:
        held = self._held.get(node.path)
        return node.stored_times if held is None else held[0].stored_times(held[1])

    def node_info(self, node: VFSNode) -> dict[str, Any] | None:
        own = self._own_info.get(node.path)
        if own is not None:
            return own
        held = self._held.get(node.path)
        if held is None:
            return None
        info = getattr(held[0], "node_info", None)
        return info(held[1]) if info is not None else None

    def file_count(self, node: VFSNode) -> int:
        return self._file_counts.get(node.path, 0)

    def total_size(self, node: VFSNode) -> int:
        return self._total_sizes.get(node.path, 0)

    def close(self) -> None:
        for sub in self._subs:
            try:
                sub.close()
            except Exception:  # noqa: BLE001 -- close every source regardless
                _logger.exception("closing %r failed", sub)


class ZipWithITunesBackupVFS(_MountVFS):
    """A ZIP holding an iTunes backup, opened whole: every member as in the
    ZIP, each backup's folder holding the opened backup instead of its
    stored, hash-named files. *password* opens the backup (and an encrypted
    ZIP)."""

    def __init__(self, path: str | Path, *, password: str = "") -> None:
        self._path = Path(path)
        zip_vfs = ZipVFS(self._path, password=password)
        super().__init__(VFSNode(name=self._path.name, path="/", is_dir=True))
        self._subs.append(zip_vfs)
        try:
            self._hold_zip_folder(
                self._root, zip_vfs, zip_vfs.root(), self._path, typed_password=password,
            )
        except Exception:
            self.close()
            raise
        self._finish()
