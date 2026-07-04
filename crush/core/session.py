"""Case session — holds all open VFS sources and a search index."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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

    def add_source(self, path: str | Path, *, password: str = "") -> VFS:
        vfs = open_vfs(path, password=password)
        self.sources.append(vfs)
        return vfs

    def add_source_vfs(self, vfs: VFS) -> VFS:
        """Attach an already-constructed VFS (e.g. built outside open_vfs() after a
        user confirmation, like opening a zipped iTunes backup as such)."""
        self.sources.append(vfs)
        return vfs

    def remove_source(self, vfs: VFS) -> None:
        if vfs in self.sources:
            self.sources = [item for item in self.sources if item is not vfs]
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
        self._db.close()
        for vfs in self.sources:
            vfs.close()
