# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""PDF parser — renders pages (via pypdfium2) and extracts text (via pypdf)."""
from __future__ import annotations

import logging
from io import BytesIO
from typing import Any, NamedTuple

from crush.core.passwords import WrongPasswordError
from crush.core.vfs import VFS, VFSNode
from crush.parsers.base import AbstractParser, ParseResult

_logger = logging.getLogger(__name__)


class PdfRevision(NamedTuple):
    """One entry in a PDF's incremental-update chain (oldest to newest,
    see PDFParser._split_revisions). Carries the same signals computed for
    the current/final document -- JavaScript, signatures, and attachments
    can each be added in one revision and removed in a later one, so
    checking only the final state can miss them (relevant for IR, not
    just "what does this PDF look like now")."""
    data: bytes
    text: str
    has_javascript: bool
    signatures: str
    attachments: list[tuple[str, bytes]]


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
            pdf_version = reader.pdf_header or ""  # e.g. "%PDF-1.7" -- always
            # readable even when encrypted, since only string/stream content
            # is ciphertext, never the header/xref/trailer structure.
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
                            "PDF Version": pdf_version,
                            "File size": f"{node.size:,} B",
                            "Possibly Encrypted": "Try Open as → PDF (Encrypted)…",
                        },
                    )
                result = reader.decrypt(password)
                if not result:
                    raise WrongPasswordError(f"Wrong password for encrypted PDF: {node.path}")
            full_text = self._extract_text(reader)

            meta: dict[str, Any] = {
                "Format": "PDF",
                "PDF Version": pdf_version,
                "Pages": str(len(reader.pages)),
                "File size": f"{node.size:,} B",
            }
            if password is not None:
                meta["Encrypted"] = "Yes (password supplied)"
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
            self._add_xmp_metadata(reader, meta)
            meta["JavaScript"] = "Present" if self._has_javascript(reader) else "Not present"
            meta["Signatures"] = self._signature_summary(reader) or "None"
            attachments = self._extract_attachments(reader)
            meta["Attachments"] = f"{len(attachments)} file(s)"

            revision_slices = self._split_revisions(raw)
            meta["Revisions"] = str(len(revision_slices))
            revisions: list[PdfRevision] = []
            if len(revision_slices) > 1:
                for rev_bytes in revision_slices:
                    try:
                        rev_reader = pypdf.PdfReader(BytesIO(rev_bytes), strict=False)
                        if rev_reader.is_encrypted and password is not None:
                            rev_reader.decrypt(password)
                        revisions.append(PdfRevision(
                            data=rev_bytes,
                            text=self._extract_text(rev_reader),
                            has_javascript=self._has_javascript(rev_reader),
                            signatures=self._signature_summary(rev_reader) or "None",
                            attachments=self._extract_attachments(rev_reader),
                        ))
                    except Exception:
                        revisions.append(PdfRevision(
                            rev_bytes, "[Unable to extract text for this revision]",
                            False, "Unknown", [],
                        ))

            return ParseResult(
                viewer_type="pdf",
                data=raw,
                metadata=meta,
                text_index=full_text[:4000],
                viewer_hints={
                    "extracted_text": full_text,
                    "password": password,
                    "attachments": attachments,
                    "revisions": revisions,
                },
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

    @staticmethod
    def _extract_text(reader: Any) -> str:
        pages: list[str] = []
        for i, page in enumerate(reader.pages, 1):
            try:
                text = page.extract_text() or ""
            except Exception:
                text = ""
            if text.strip():
                pages.append(f"--- Page {i} ---\n{text.strip()}")
        return "\n\n".join(pages) if pages else "[No extractable text in this PDF]"

    @staticmethod
    def _format_xmp_value(val: Any) -> str:
        """dc_creator/dc_subject are RDF Seq -> list[str]; dc_title/
        dc_description are RDF Alt -> dict[lang, str] (language
        alternatives) -- pypdf returns both as native Python containers,
        not flat strings, so they need formatting rather than str()."""
        if isinstance(val, dict):
            return val.get("x-default") or next(iter(val.values()), "")
        if isinstance(val, (list, tuple)):
            return ", ".join(str(v) for v in val)
        return str(val)

    @classmethod
    def _add_xmp_metadata(cls, reader: Any, meta: dict[str, Any]) -> None:
        """XMP is a metadata stream separate from the /Info dictionary --
        a mismatch between the two (e.g. different tool names or dates) is
        itself a forensic signal, so both are kept, never merged."""
        try:
            xmp = reader.xmp_metadata
        except Exception:
            xmp = None
        if xmp is None:
            return
        for attr, label in (
            ("dc_creator", "XMP Creator"),
            ("dc_title", "XMP Title"),
            ("dc_description", "XMP Description"),
            ("xmp_creator_tool", "XMP Creator Tool"),
            ("xmp_create_date", "XMP Create Date"),
            ("xmp_modify_date", "XMP Modify Date"),
            ("xmpmm_document_id", "XMP Document ID"),
            ("xmpmm_instance_id", "XMP Instance ID"),
        ):
            try:
                val = getattr(xmp, attr, None)
            except Exception:
                val = None
            if val:
                formatted = cls._format_xmp_value(val)
                if formatted:
                    meta[label] = formatted[:200]

    @staticmethod
    def _has_javascript(reader: Any) -> bool:
        """Document-level JavaScript, per the two standard PDF-spec
        locations (ISO 32000-1 12.6.4.16): the Catalog's /Names/JavaScript
        name tree, and a /JavaScript /OpenAction. Does not recurse into
        every annotation/form-field's own /AA (additional-actions) dict --
        that would need a full object-graph walk, not attempted here."""
        try:
            catalog = reader.root_object
            names = catalog.get("/Names")
            if names is not None and "/JavaScript" in names:
                return True
            open_action = catalog.get("/OpenAction")
            if open_action is not None and open_action.get("/S") == "/JavaScript":
                return True
        except Exception:
            pass
        return False

    @staticmethod
    def _signature_summary(reader: Any) -> str:
        """Signature form fields (ISO 32000-1 12.8): AcroForm /Fields
        entries with /FT /Sig. Only top-level fields are checked, not
        fields nested inside a /Kids hierarchy."""
        try:
            acroform = reader.root_object.get("/AcroForm")
            if not acroform:
                return ""
            fields = acroform.get("/Fields") or []
            total = 0
            signed = 0
            for f in fields:
                field = f.get_object() if hasattr(f, "get_object") else f
                if field.get("/FT") == "/Sig":
                    total += 1
                    if field.get("/V"):
                        signed += 1
            if total == 0:
                return ""
            return f"{signed}/{total} signature field(s) signed"
        except Exception:
            return ""

    @staticmethod
    def _extract_attachments(reader: Any) -> list[tuple[str, bytes]]:
        """Embedded files (ISO 32000-1 7.11), exposed by pypdf as filename
        -> list[bytes] since the /EmbeddedFiles name tree allows more than
        one attachment under the same name."""
        out: list[tuple[str, bytes]] = []
        try:
            for name, blobs in reader.attachments.items():
                for blob in blobs:
                    out.append((name, blob))
        except Exception:
            pass
        return out

    @staticmethod
    def _split_revisions(raw: bytes) -> list[bytes]:
        """Walk the /Prev trailer chain backward from the current (newest)
        revision (ISO 32000-1 7.5.6/7.5.8: each incremental update's
        trailer points at the byte offset of the previous revision's own
        xref section). Truncating the file right after that earlier
        revision's own %%EOF yields a byte string that is itself a
        complete, independently parseable PDF -- verified directly against
        hand-built multi-revision fixtures, not assumed. Returns
        oldest-first; always at least [raw], even for a never-updated
        file or one that fails to parse at all."""
        import pypdf

        revisions = [raw]
        current = raw
        seen_offsets: set[int] = set()
        while True:
            try:
                r = pypdf.PdfReader(BytesIO(current), strict=False)
                prev = r.trailer.get("/Prev")
            except Exception:
                break
            if prev is None:
                break
            prev_offset = int(prev)
            if prev_offset in seen_offsets:
                break  # cyclic /Prev chain -- stop rather than loop forever
            seen_offsets.add(prev_offset)
            eof_pos = current.find(b"%%EOF", prev_offset)
            if eof_pos == -1:
                break
            current = current[: eof_pos + len(b"%%EOF")]
            revisions.append(current)
        revisions.reverse()
        return revisions
