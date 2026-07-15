# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""PDF parser — renders pages (via pypdfium2) and extracts text (via pypdf)."""
from __future__ import annotations

import logging
from io import BytesIO
from typing import Any

from crush.core.passwords import WrongPasswordError
from crush.core.vfs import VFS, VFSNode
from crush.parsers.base import AbstractParser, ParseResult

_logger = logging.getLogger(__name__)


class PDFParser(AbstractParser):
    SUPPORTED_EXTENSIONS = [".pdf"]
    DISPLAY_NAME = "PDF document"
    SUPPORTS_PASSWORD = True

    def can_parse(self, path: str, peek_bytes: bytes) -> bool:
        return peek_bytes[:4] == b"%PDF"

    def parse(self, node: VFSNode, vfs: VFS, password: str | None = None) -> ParseResult:
        raw = vfs.read(node)
        try:
            import pypdf
        except ImportError:
            return ParseResult(
                viewer_type="hex",
                data=raw,
                metadata={
                    "Format": "PDF",
                    "Note": "Install pypdf for text extraction: pip install pypdf",
                    "File size": f"{node.size:,} B",
                },
            )
        try:
            reader = pypdf.PdfReader(BytesIO(raw), strict=False)
            if reader.is_encrypted:
                if password is None:
                    # A plain double-click never auto-prompts -- same as
                    # Realm/SQLCipher -- but unlike those, a PDF's %PDF
                    # header/xref/trailer structure is never itself
                    # encrypted (only string/stream content is), so we can
                    # tell "this is a PDF, and it's encrypted" for certain
                    # here and say so directly, rather than surfacing pypdf's
                    # raw FileNotDecryptedError text as an incidental hint.
                    return ParseResult(
                        viewer_type="hex",
                        data=raw,
                        metadata={
                            "Format": "PDF",
                            "File size": f"{node.size:,} B",
                            "Possibly Encrypted": "Try Open as → PDF (Encrypted)…",
                        },
                    )
                result = reader.decrypt(password)
                if not result:
                    raise WrongPasswordError(f"Wrong password for encrypted PDF: {node.path}")
            pages: list[str] = []
            for i, page in enumerate(reader.pages, 1):
                try:
                    text = page.extract_text() or ""
                except Exception:
                    text = ""
                if text.strip():
                    pages.append(f"--- Page {i} ---\n{text.strip()}")

            full_text = "\n\n".join(pages) if pages else "[No extractable text in this PDF]"

            meta: dict[str, Any] = {
                "Format": "PDF",
                "Pages": str(len(reader.pages)),
                "File size": f"{node.size:,} B",
            }
            info = reader.metadata
            if info:
                for attr, label in (
                    ("/Title", "Title"),
                    ("/Author", "Author"),
                    ("/Creator", "Creator"),
                    ("/Producer", "Producer"),
                    ("/CreationDate", "CreationDate"),
                    ("/ModDate", "ModDate"),
                ):
                    val = info.get(attr, "")
                    if val:
                        meta[label] = str(val)[:200]

            return ParseResult(
                viewer_type="pdf",
                data=raw,
                metadata=meta,
                text_index=full_text[:4000],
                viewer_hints={"extracted_text": full_text, "password": password},
            )
        except WrongPasswordError:
            raise
        except Exception as exc:
            _logger.warning("PDF parse error for %s: %s", node.path, exc)
            return ParseResult(
                viewer_type="hex",
                data=raw,
                metadata={
                    "Parse error": str(exc),
                    "Format": "PDF (parse failed)",
                    "File size": f"{node.size:,} B",
                },
            )
