# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""PDF parser — renders pages (via pypdfium2) and extracts text (via pypdf)."""
from __future__ import annotations

import logging
from io import BytesIO
from typing import Any, NamedTuple

from crush.core.issues import ParseIssue
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
    just "what does this PDF look like now").

    Each signal is a ParseIssue stating what was found, or why it could
    not be checked; *error* is set when the revision could not be opened
    at all (the other fields are then empty, not negative findings)."""
    data: bytes
    text: str
    text_status: ParseIssue | None
    javascript: ParseIssue
    signatures: ParseIssue
    attachments: list[tuple[str, bytes]]
    attachments_status: ParseIssue
    error: ParseIssue | None = None

    @property
    def notable(self) -> bool:
        """True unless every check ran and found nothing."""
        return bool(
            self.error
            or self.attachments
            or self.javascript.code != "pdf.js_not_present"
            or self.signatures.code != "pdf.signatures_none"
            or self.attachments_status.code != "pdf.attachments"
        )


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
                    "Note": ParseIssue("pdf.pypdf_missing"),
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
                            "Possibly Encrypted": ParseIssue("pdf.try_encrypted"),
                        },
                    )
                result = reader.decrypt(password)
                if not result:
                    raise WrongPasswordError(ParseIssue("pdf.wrong_password", {"path": node.path}))
            full_text, text_status = self._extract_text(reader)

            meta: dict[str, Any] = {
                "Format": "PDF",
                "PDF Version": pdf_version,
                "Pages": str(len(reader.pages)),
                "File size": f"{node.size:,} B",
            }
            if password is not None:
                meta["Encrypted"] = ParseIssue("pdf.encrypted_password")
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
                        meta[label] = str(val)
            meta["XMP"] = self._add_xmp_metadata(reader, meta)
            if text_status is not None:
                meta["Text extraction"] = text_status
            meta["JavaScript"] = self._javascript_status(reader)
            meta["Signatures"] = self._signature_status(reader)
            attachments, attachments_status = self._extract_attachments(reader)
            meta["Attachments"] = attachments_status

            revision_slices, chain_issue = self._split_revisions(raw)
            meta["Revisions"] = str(len(revision_slices))
            if chain_issue is not None:
                meta["Revision chain"] = chain_issue
            revisions: list[PdfRevision] = []
            if len(revision_slices) > 1:
                revisions = [self._revision(rev_bytes, password) for rev_bytes in revision_slices]

            return ParseResult(
                viewer_type="pdf",
                data=raw,
                metadata=meta,
                text_index=full_text[:4000],
                viewer_hints={
                    "extracted_text": full_text,
                    "text_status": text_status,
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
                    "Parse error": ParseIssue("pdf.parse_failed", detail=str(exc)),
                    "Format": ParseIssue("pdf.format_parse_failed"),
                    "File size": f"{node.size:,} B",
                },
            )

    @classmethod
    def _revision(cls, rev_bytes: bytes, password: str | None) -> PdfRevision:
        import pypdf

        try:
            rev_reader = pypdf.PdfReader(BytesIO(rev_bytes), strict=False)
            if rev_reader.is_encrypted and password is not None:
                rev_reader.decrypt(password)
            text, text_status = cls._extract_text(rev_reader)
            attachments, attachments_status = cls._extract_attachments(rev_reader)
            return PdfRevision(
                data=rev_bytes,
                text=text,
                text_status=text_status,
                javascript=cls._javascript_status(rev_reader),
                signatures=cls._signature_status(rev_reader),
                attachments=attachments,
                attachments_status=attachments_status,
            )
        except Exception as exc:
            error = ParseIssue("pdf.revision_failed", detail=str(exc))
            return PdfRevision(rev_bytes, "", error, error, error, [], error, error)

    @staticmethod
    def _extract_text(reader: Any) -> tuple[str, ParseIssue | None]:
        """(text, status). The status names every page whose extraction
        failed, or says there is no text at all; None when every page was
        read and at least one had text."""
        pages: list[str] = []
        failures: list[ParseIssue] = []
        for i, page in enumerate(reader.pages, 1):
            try:
                text = page.extract_text() or ""
            except Exception as exc:
                failures.append(ParseIssue("pdf.text_page_failure", {"page": i}, detail=str(exc)))
                continue
            if text.strip():
                pages.append(f"--- Page {i} ---\n{text.strip()}")
        status = None
        if failures:
            status = ParseIssue("pdf.text_pages_failed", {
                "count": len(failures), "failures": failures,
            })
        elif not pages:
            status = ParseIssue("pdf.no_text")
        return "\n\n".join(pages), status

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
    def _add_xmp_metadata(cls, reader: Any, meta: dict[str, Any]) -> ParseIssue:
        """XMP is a metadata stream separate from the /Info dictionary --
        a mismatch between the two (e.g. different tool names or dates) is
        itself a forensic signal, so both are kept, never merged. Returns
        the XMP status (present / not present / why it couldn't be read)."""
        try:
            xmp = reader.xmp_metadata
        except Exception as exc:
            return ParseIssue("pdf.xmp_failed", detail=str(exc))
        if xmp is None:
            return ParseIssue("pdf.xmp_not_present")
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
            except Exception as exc:
                meta[label] = ParseIssue("pdf.xmp_failed", detail=str(exc))
                continue
            if val:
                formatted = cls._format_xmp_value(val)
                if formatted:
                    meta[label] = formatted
        return ParseIssue("pdf.xmp_present")

    @staticmethod
    def _javascript_status(reader: Any) -> ParseIssue:
        """Document-level JavaScript, per the two standard PDF-spec
        locations (ISO 32000-1 12.6.4.16): the Catalog's /Names/JavaScript
        name tree, and a /JavaScript /OpenAction. Does not recurse into
        every annotation/form-field's own /AA (additional-actions) dict --
        that would need a full object-graph walk, not attempted here; the
        "not present" status says so."""
        try:
            catalog = reader.root_object
            names = catalog.get("/Names")
            if names is not None and "/JavaScript" in names:
                return ParseIssue("pdf.js_present")
            open_action = catalog.get("/OpenAction")
            if open_action is not None and open_action.get("/S") == "/JavaScript":
                return ParseIssue("pdf.js_present")
        except Exception as exc:
            return ParseIssue("pdf.js_check_failed", detail=str(exc))
        return ParseIssue("pdf.js_not_present")

    @staticmethod
    def _signature_status(reader: Any) -> ParseIssue:
        """Signature form fields (ISO 32000-1 12.8): AcroForm /Fields
        entries with /FT /Sig. Only top-level fields are checked, not
        fields nested inside a /Kids hierarchy; the "none" status says so."""
        try:
            acroform = reader.root_object.get("/AcroForm")
            fields = (acroform.get("/Fields") or []) if acroform else []
            total = 0
            signed = 0
            for f in fields:
                field = f.get_object() if hasattr(f, "get_object") else f
                if field.get("/FT") == "/Sig":
                    total += 1
                    if field.get("/V"):
                        signed += 1
        except Exception as exc:
            return ParseIssue("pdf.signatures_check_failed", detail=str(exc))
        if total == 0:
            return ParseIssue("pdf.signatures_none")
        return ParseIssue("pdf.signatures_signed", {"signed": signed, "total": total})

    @staticmethod
    def _extract_attachments(reader: Any) -> tuple[list[tuple[str, bytes]], ParseIssue]:
        """Embedded files (ISO 32000-1 7.11), exposed by pypdf as filename
        -> list[bytes] since the /EmbeddedFiles name tree allows more than
        one attachment under the same name. The status gives the count, or
        how many were read before reading failed and why."""
        out: list[tuple[str, bytes]] = []
        try:
            for name, blobs in reader.attachments.items():
                for blob in blobs:
                    out.append((name, blob))
        except Exception as exc:
            return out, ParseIssue("pdf.attachments_failed", {"count": len(out)}, detail=str(exc))
        return out, ParseIssue("pdf.attachments", {"count": len(out)})

    @staticmethod
    def _split_revisions(raw: bytes) -> tuple[list[bytes], ParseIssue | None]:
        """Walk the /Prev trailer chain backward from the current (newest)
        revision (ISO 32000-1 7.5.6/7.5.8: each incremental update's
        trailer points at the byte offset of the previous revision's own
        xref section). Truncating the file right after that earlier
        revision's own %%EOF yields a byte string that is itself a
        complete, independently parseable PDF -- verified directly against
        hand-built multi-revision fixtures, not assumed. Returns
        oldest-first; always at least [raw], even for a never-updated
        file or one that fails to parse at all. The issue says why the
        walk stopped early, if it did (None: the chain ended normally)."""
        import pypdf

        revisions = [raw]
        current = raw
        seen_offsets: set[int] = set()
        stop: ParseIssue | None = None
        while True:
            try:
                r = pypdf.PdfReader(BytesIO(current), strict=False)
                prev = r.trailer.get("/Prev")
            except Exception as exc:
                stop = ParseIssue(
                    "pdf.revchain_parse_failed", {"count": len(revisions)}, detail=str(exc),
                )
                break
            if prev is None:
                break
            try:
                prev_offset = int(prev)
            except (TypeError, ValueError) as exc:
                stop = ParseIssue("pdf.revchain_bad_prev", {"count": len(revisions)}, detail=str(exc))
                break
            if prev_offset in seen_offsets:
                stop = ParseIssue("pdf.revchain_cycle", {
                    "count": len(revisions), "offset": prev_offset,
                })
                break
            seen_offsets.add(prev_offset)
            eof_pos = current.find(b"%%EOF", prev_offset)
            if eof_pos == -1:
                stop = ParseIssue("pdf.revchain_no_eof", {
                    "count": len(revisions), "offset": prev_offset,
                })
                break
            current = current[: eof_pos + len(b"%%EOF")]
            revisions.append(current)
        revisions.reverse()
        return revisions, stop
