"""Case session — holds all open VFS sources and a search index."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from crush.core.hashing import HashStore
from crush.core.vfs import VFS, VFSNode, open_vfs


@dataclass
class OpenArtifact:
    node: VFSNode
    vfs: VFS
    parser_name: str
    viewer_type: str
    data: Any
    sub_nodes: list[VFSNode] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class Session:
    def __init__(self, name: str = "Untitled case") -> None:
        self.name = name
        self.integrity_mode: bool = False
        self.sources: list[VFS] = []
        self.open_artifacts: list[OpenArtifact] = []
        # Hashes computed in this window, per source; kept while the source is open.
        self.hashes = HashStore()
        # id(vfs) -> (vfs, the path it was opened from); see source_label.
        # The VFS is held so its id can't be reused for another source.
        self._source_paths: dict[int, tuple[VFS, str]] = {}
        self._db = sqlite3.connect(":memory:")
        self._init_db()

    def _init_db(self) -> None:
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS artifact (
                id      INTEGER PRIMARY KEY,
                path    TEXT NOT NULL,
                type    TEXT NOT NULL,
                summary TEXT
            );
            CREATE VIRTUAL TABLE IF NOT EXISTS artifact_fts
                USING fts5(path, content, content='artifact', content_rowid='id');
        """)

    def add_source(
        self, path: str | Path, *, password: str = "", embedded_zip: bool = False,
        as_disk_image: bool = False, private_key: str = "",
    ) -> VFS:
        vfs = open_vfs(
            path, password=password, embedded_zip=embedded_zip, as_disk_image=as_disk_image,
            private_key=private_key,
        )
        self.sources.append(vfs)
        self._source_paths[id(vfs)] = (vfs, str(path))
        return vfs

    def add_source_vfs(self, vfs: VFS, path: str | Path | None = None) -> VFS:
        """Attach an already-constructed VFS (e.g. built outside open_vfs() after a
        user confirmation, like opening a zipped iTunes backup as such);
        *path*: what it was opened from."""
        self.sources.append(vfs)
        if path is not None:
            self._source_paths[id(vfs)] = (vfs, str(path))
        return vfs

    def source_label(self, vfs: VFS) -> str:
        """What *vfs* was opened from (the image, archive or folder path),
        else its root's name."""
        held = self._source_paths.get(id(vfs))
        if held is not None and held[0] is vfs:
            return held[1]
        return vfs.root().name

    def detach_source(self, vfs: VFS) -> VFS:
        """Hand an open source to another session (another window) without
        closing it. Its computed hashes are dropped here; the other window
        starts without them."""
        self.sources = [item for item in self.sources if item is not vfs]
        self.hashes.forget(vfs)
        self._source_paths.pop(id(vfs), None)
        return vfs

    def replace_source(self, old: VFS, new: VFS) -> None:
        """Put *new* in *old*'s place and close *old* (the same source read
        again, e.g. with an encrypted volume opened)."""
        self.sources = [new if item is old else item for item in self.sources]
        self.hashes.forget(old)
        held = self._source_paths.pop(id(old), None)
        if held is not None:
            self._source_paths[id(new)] = (new, held[1])
        try:
            old.close()
        except Exception:
            pass

    def remove_source(self, vfs: VFS) -> None:
        if vfs in self.sources:
            self.sources = [item for item in self.sources if item is not vfs]
        self.hashes.forget(vfs)
        self._source_paths.pop(id(vfs), None)
        try:
            vfs.close()
        except Exception:
            pass

    def record_artifact(self, artifact: OpenArtifact, text_content: str = "") -> None:
        self.open_artifacts.append(artifact)
        cur = self._db.execute(
            "INSERT INTO artifact (path, type, summary) VALUES (?, ?, ?)",
            (artifact.node.path, artifact.parser_name, text_content[:500]),
        )
        if text_content:
            self._db.execute(
                "INSERT INTO artifact_fts (rowid, path, content) VALUES (?, ?, ?)",
                (cur.lastrowid, artifact.node.path, text_content),
            )
        self._db.commit()

    def search(self, query: str) -> list[dict[str, Any]]:
        rows = self._db.execute(
            """SELECT a.path, a.type, snippet(artifact_fts, 1, '<b>', '</b>', '...', 20)
               FROM artifact_fts
               JOIN artifact a ON a.id = artifact_fts.rowid
               WHERE artifact_fts MATCH ?
               ORDER BY rank""",
            (query,),
        ).fetchall()
        return [{"path": r[0], "type": r[1], "snippet": r[2]} for r in rows]

    def close(self) -> None:
        self.hashes.clear()
        self._source_paths.clear()
        self._db.close()
        for vfs in self.sources:
            vfs.close()
