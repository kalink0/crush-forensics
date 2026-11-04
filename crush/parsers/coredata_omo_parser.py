# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Optimized Core Data model files (.omo inside a .momd bundle), recognised
by their first bytes "momv2$sr" (192 of 192 observed files) -- not decoded:
shown as hex with a status saying so."""
from __future__ import annotations

from crush.core.issues import ParseIssue
from crush.core.vfs import VFS, VFSNode
from crush.parsers.base import AbstractParser, ParseResult

OMO_MAGIC = b"momv2$sr"


class CoreDataOmoParser(AbstractParser):
    SUPPORTED_EXTENSIONS = [".omo"]
    DISPLAY_NAME = "Core Data optimized model (not decoded)"

    def can_parse(self, path: str, peek_bytes: bytes) -> bool:
        return peek_bytes[: len(OMO_MAGIC)] == OMO_MAGIC

    def parse(self, node: VFSNode, vfs: VFS) -> ParseResult:
        raw = vfs.read(node)
        status = ParseIssue("coredata.omo_not_decoded")
        return ParseResult(
            viewer_type="hex",
            data=raw,
            metadata={"Format": status, "Status": status, "File size": f"{node.size:,} B"},
        )
