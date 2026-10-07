# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Cellebrite UFD and UFDX: the files an extraction is opened from.

A .ufd is an INI file UFED (and tools rebuilding its layout, such as UFADE)
writes beside an extraction. It is the entry point an examiner opens: its
[Dumps] section names the files the extraction consists of (a ZIP), and one
section per dump says how to read it -- `Type=ZIPfolder` with a
`ZIPLogicalPath`, the ZIP folder the dump is (`Dump`, `extra`,
`iPhoneDump`). It also records the device, the acquisition ([General]:
tool, start and end time with their UTC offset as written), a SHA-256 of
each file ([SHA256]) and, from UFED, an HMAC over the file ([Hash]), whose
key only Cellebrite has. UFADE adds `BackupPassword` and `IsEncrypted` for
the iTunes backup inside its ZIP. Verified against two UFED and one UFADE
.ufd (all `UfdVer=1.2`).

A .ufdx is an XML `EvidenceCollection` listing several extractions of one
device, each by a relative path to its .ufd (Windows separators).

Opening one shows each dump as a folder named after its [Dumps] key
(FileDump, KeyStore), holding that ZIP folder. An iTunes backup found
inside a dump (by its content) opens as the backup. Everything else the
ZIP holds is shown too, in a folder of its own. Nothing is read beside
the files the .ufd names.
"""
from __future__ import annotations

import codecs
import hashlib
import logging
import re
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Any

from crush.core.issues import ParseIssue
from crush.core.mounted import _MountVFS
from crush.core.passwords import WrongPasswordError
from crush.core.vfs import VFS, VFSNode, ZipVFS, join_notes

_logger = logging.getLogger(__name__)

_SECTION_RE = re.compile(r"^\[([^\]\r\n]+)\]\s*$")
_ZIP_FOLDER = "ZIPfolder"


class UFDOpenError(ValueError):
    """*path* is not a readable UFD or UFDX."""


# -- Text and recognition ----------------------------------------------------


def _decode(raw: bytes) -> str:
    """The file's text: by its byte-order mark, else UTF-8. Undecodable
    bytes raise rather than being replaced -- a value must never be shown
    altered."""
    for bom, encoding in (
        (codecs.BOM_UTF8, "utf-8-sig"),
        (codecs.BOM_UTF16_LE, "utf-16"),
        (codecs.BOM_UTF16_BE, "utf-16"),
    ):
        if raw.startswith(bom):
            return raw.decode(encoding)
    return raw.decode("utf-8")


def _head_text(head: bytes) -> str:
    try:
        return _decode(head)
    except UnicodeDecodeError as exc:
        # A head can end mid-character; decode up to there.
        return _decode(head[: exc.start]) if exc.start else ""


def looks_like_ufd(head: bytes) -> bool:
    """A cheap first test on a file's first bytes: an INI section header
    first. is_ufd() decides."""
    text = _head_text(head).lstrip()
    first = text.splitlines()[0] if text else ""
    return bool(_SECTION_RE.match(first))


def looks_like_ufdx(head: bytes) -> bool:
    """A cheap first test: an EvidenceCollection element in the first
    bytes. is_ufdx() decides."""
    return re.search(r"<EvidenceCollection\b", _head_text(head)) is not None


def is_ufd(path: str | Path) -> bool:
    """True when *path* is a UFD: INI text with UfdVer in [General] or a
    [Dumps] section. Read whole only when it starts with a section header."""
    p = Path(path)
    try:
        with open(p, "rb") as f:
            if not looks_like_ufd(f.read(512)):
                return False
        ufd = parse_ufd(p)
    except (OSError, UnicodeDecodeError, UFDOpenError):
        return False
    return ufd.get("General", "UfdVer") is not None or ufd.has_section("Dumps")


def is_ufdx(path: str | Path) -> bool:
    p = Path(path)
    try:
        with open(p, "rb") as f:
            if not looks_like_ufdx(f.read(512)):
                return False
        parse_ufdx(p)
    except (OSError, UFDOpenError):
        return False
    return True


# -- UFD ---------------------------------------------------------------------


@dataclass
class Ufd:
    """A parsed .ufd: every section and key=value line, in file order and
    as written (a key may repeat), and the lines that are neither."""

    path: Path
    sections: list[tuple[str, list[tuple[str, str]]]] = field(default_factory=list)
    other_lines: list[str] = field(default_factory=list)

    def has_section(self, name: str) -> bool:
        return any(s == name for s, _ in self.sections)

    def items(self, name: str) -> list[tuple[str, str]]:
        return [kv for s, entries in self.sections if s == name for kv in entries]

    def get(self, section: str, key: str) -> str | None:
        for k, v in self.items(section):
            if k == key:
                return v
        return None


def parse_ufd(path: str | Path) -> Ufd:
    p = Path(path)
    try:
        text = _decode(p.read_bytes())
    except UnicodeDecodeError as exc:
        raise UFDOpenError(ParseIssue("ufd.not_text", detail=str(exc))) from exc
    ufd = Ufd(path=p)
    current: list[tuple[str, str]] | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        section = _SECTION_RE.match(stripped)
        if section:
            current = []
            ufd.sections.append((section.group(1), current))
        elif "=" in stripped and current is not None:
            key, _, value = stripped.partition("=")
            current.append((key.strip(), value.strip()))
        else:
            ufd.other_lines.append(stripped)
    if not ufd.sections:
        raise UFDOpenError(ParseIssue("ufd.no_sections"))
    return ufd


def _resolve(base: Path, ref: str) -> Path | None:
    """The file *ref* (as written in a .ufd/.ufdx: relative, Windows
    separators) names, relative to *base* -- exactly as written, since the
    tool that wrote the reference wrote the file too. None when it isn't
    there."""
    parts = PureWindowsPath(ref).parts
    target = Path(ref) if not parts or PureWindowsPath(ref).anchor else base.joinpath(*parts)
    return target if target.is_file() else None


# -- UFD source ----------------------------------------------------------------


def _ufd_fields(ufd: Ufd) -> dict[str, Any]:
    """Every key the .ufd records, as "Section / Key", in file order --
    values as written (times keep their UTC offset as written, e.g.
    "28/07/2024 07:27:27 (-4)"; nothing converted)."""
    info: dict[str, Any] = {}
    for section, entries in ufd.sections:
        for key, value in entries:
            label = f"{section} / {key}"
            k = 2
            while label in info:
                label = f"{section} / {key} ({k})"
                k += 1
            info[label] = value
    if ufd.other_lines:
        info["UFD lines not read"] = ParseIssue(
            "ufd.other_lines", {"count": len(ufd.other_lines)}, detail="\n".join(ufd.other_lines)
        )
    return info


class UFDVFS(_MountVFS):
    """A UFD opened as the source it describes. See the module docstring.

    *password* is the one the analyst typed: it opens an iTunes backup in
    a dump instead of the .ufd's BackupPassword (and an encrypted ZIP)."""

    def __init__(self, path: str | Path, *, password: str = "") -> None:
        self._path = Path(path)
        ufd = parse_ufd(self._path)
        super().__init__(VFSNode(name=self._path.name, path="/", is_dir=True))
        self.ufd = ufd
        self._password = password
        self._backup_password = ufd.get("General", "BackupPassword") or ""
        try:
            self._build()
        except Exception:
            self.close()
            raise
        self._own_info["/"] = _ufd_fields(ufd)
        self._finish()

    # Tree --------------------------------------------------------------------

    def _build(self) -> None:
        dumps = self.ufd.items("Dumps")
        if not dumps:
            self._root.status = ParseIssue("ufd.no_dumps")
            return
        zips: dict[Path, ZipVFS | ParseIssue] = {}
        covered: dict[Path, list[str]] = {}
        for key, ref in dumps:
            section = self.ufd.items(key)
            dump_type = self.ufd.get(key, "Type")
            file = _resolve(self._path.parent, ref)
            if file is None:
                self._folder(self._root, key, ParseIssue("ufd.dump_file_missing", {"file": ref}))
                continue
            if not section:
                self._folder(self._root, key, ParseIssue("ufd.dump_no_section", {"file": ref}))
                continue
            if dump_type != _ZIP_FOLDER:
                self._folder(self._root, key, ParseIssue(
                    "ufd.dump_type_unsupported", {"type": dump_type or "", "file": ref},
                ))
                continue
            if file not in zips:
                zips[file] = self._open_zip(file)
            zip_vfs = zips[file]
            if isinstance(zip_vfs, ParseIssue):
                self._folder(self._root, key, zip_vfs)
                continue
            logical = self.ufd.get(key, "ZIPLogicalPath") or ""
            parts = [p for p in re.split(r"[\\/]", logical) if p]
            src = _find(zip_vfs.root(), parts)
            if src is None or not src.is_dir:
                self._folder(self._root, key, ParseIssue(
                    "ufd.dump_path_missing", {"path": logical, "file": file.name},
                ))
                continue
            folder = self._folder(self._root, key, ParseIssue(
                "ufd.dump_folder", {"path": logical or "/", "file": file.name},
            ))
            self._hold_dump(folder, zip_vfs, src, file)
            covered.setdefault(file, []).append(src.path)
        for file, zip_vfs in zips.items():
            if isinstance(zip_vfs, ZipVFS):
                self._hold_rest(zip_vfs, covered.get(file, []), file)

    def _open_zip(self, file: Path) -> ZipVFS | ParseIssue:
        try:
            zip_vfs = ZipVFS(file, password=self._password)
        except (zipfile.BadZipFile, OSError, EOFError, NotImplementedError) as exc:
            return ParseIssue("ufd.zip_not_opened", {"file": file.name}, detail=str(exc))
        self._subs.append(zip_vfs)
        return zip_vfs

    def _hold_dump(self, folder: VFSNode, zip_vfs: ZipVFS, src: VFSNode, file: Path) -> None:
        """*src*'s tree under *folder*, an iTunes backup in it opened with
        the .ufd's BackupPassword (unless the analyst typed one)."""
        self._hold_zip_folder(
            folder, zip_vfs, src, file,
            typed_password=self._password, recorded_password=self._backup_password,
        )

    def _hold_rest(self, zip_vfs: ZipVFS, covered: list[str], file: Path) -> None:
        """What *file* holds outside every dump's ZIP folder, in a folder of
        its own -- shown, never dropped. Nothing when there is nothing."""
        covered_set = set(covered)
        if "/" in covered_set:
            return
        folder = self._folder(
            self._root, f"(other content of {file.name})",
            ParseIssue("ufd.other_content", {"file": file.name}),
        )
        self._hold(folder, zip_vfs, zip_vfs.root(), skip=lambda n: n.path in covered_set)
        # The folders on the way to a dump's ZIP folder are left with
        # nothing when it was all they held; a folder empty in the ZIP
        # itself stays.
        leading = {
            "/".join(c.split("/")[:depth]) for c in covered_set
            for depth in range(2, c.count("/") + 1)
        }
        _prune_empty(folder, leading, self._nodes, self._held)
        if not folder.children:
            self._root.children.remove(folder)
            self._nodes.pop(folder.path, None)

    # Acquisition -------------------------------------------------------------

    def acquisition(self) -> str | None:
        return "UFD"

    def verify_acquisition(
        self, progress: Callable[[int, int], None] | None = None
    ) -> dict[str, Any]:
        """Recompute the SHA-256 the .ufd records for each of its files
        ([SHA256]). A file it names that isn't there is a failed check. The
        [Hash] HMAC is keyed with Cellebrite's key and can't be recomputed:
        reported as recorded, not checked."""
        files = verify_ufd_files(self.ufd, progress)
        return _verify_result(files, self.ufd.get("Hash", "HMAC"))


def verify_ufd_files(
    ufd: Ufd, progress: Callable[[int, int], None] | None = None, label_prefix: str = "",
) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    for ref, stored in ufd.items("SHA256"):
        path = _resolve(ufd.path.parent, ref)
        entry: dict[str, Any] = {
            "name": label_prefix + ref, "algorithm": "SHA-256", "stored": stored.lower(),
            "computed": None, "found": path is not None,
        }
        if path is not None:
            digest = hashlib.sha256()
            total = path.stat().st_size
            done = 0
            with open(path, "rb") as f:
                while chunk := f.read(1 << 20):
                    digest.update(chunk)
                    done += len(chunk)
                    if progress is not None:
                        progress(done, total)
            entry["computed"] = digest.hexdigest()
        entry["match"] = entry["computed"] == entry["stored"]
        files.append(entry)
    return files


def _verify_result(files: list[dict[str, Any]], hmac: str | None) -> dict[str, Any]:
    return {
        "stored": {}, "computed": {},
        "recorded_files": files,
        "recorded_hmac": hmac,
        "match": bool(files) and all(f["match"] for f in files),
    }


def _find(root: VFSNode, parts: list[str]) -> VFSNode | None:
    node: VFSNode | None = root
    for part in parts:
        assert node is not None
        node = next((c for c in node.children if c.name == part), None)
        if node is None:
            return None
    return node


def _prune_empty(
    node: VFSNode, leading: set[str], nodes: dict[str, VFSNode],
    held: dict[str, tuple[VFS, VFSNode]],
) -> None:
    """Drop the folders whose ZIP path is in *leading* (on the way to a
    dump's ZIP folder) once nothing is left in them."""
    kept = []
    for child in node.children:
        if child.is_dir:
            _prune_empty(child, leading, nodes, held)
            inner = held.get(child.path)
            if not child.children and inner is not None and inner[1].path in leading:
                nodes.pop(child.path, None)
                held.pop(child.path, None)
                continue
        kept.append(child)
    node.children = kept


# -- UFDX source ---------------------------------------------------------------


@dataclass
class Ufdx:
    path: Path
    attributes: dict[str, str]
    device: dict[str, str]
    extractions: list[dict[str, str]]


def _local(tag: Any) -> str:
    return str(tag).rsplit("}", 1)[-1]


def parse_ufdx(path: str | Path) -> Ufdx:
    from lxml import etree

    p = Path(path)
    parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)
    try:
        root = etree.fromstring(p.read_bytes(), parser)
    except etree.XMLSyntaxError as exc:
        raise UFDOpenError(ParseIssue("ufdx.not_xml", detail=str(exc))) from exc
    if _local(root.tag) != "EvidenceCollection":
        raise UFDOpenError(ParseIssue("ufdx.not_evidence_collection", {"root": _local(root.tag)}))
    device: dict[str, str] = {}
    extractions: list[dict[str, str]] = []
    for el in root:
        if _local(el.tag) == "DeviceInfo":
            device.update({str(k): str(v) for k, v in el.attrib.items()})
        elif _local(el.tag) == "Extractions":
            for ex in el:
                if _local(ex.tag) == "Extraction":
                    extractions.append({str(k): str(v) for k, v in ex.attrib.items()})
    return Ufdx(
        path=p, attributes={str(k): str(v) for k, v in root.attrib.items()},
        device=device, extractions=extractions,
    )


class UFDXVFS(_MountVFS):
    """A UFDX opened as the extractions it lists: one folder per
    extraction (named after the folder its .ufd is in, as UFED writes it,
    e.g. "EXTRACTION_FFS 01"), each holding what that .ufd opens."""

    def __init__(self, path: str | Path, *, password: str = "") -> None:
        self._path = Path(path)
        self.ufdx = parse_ufdx(self._path)
        super().__init__(VFSNode(name=self._path.name, path="/", is_dir=True))
        # Every listed extraction in UFDX order, by its folder: its UFD, or
        # why it wasn't opened (the .ufd's name as written beside it).
        self._extractions: list[tuple[str, UFDVFS | tuple[str, ParseIssue]]] = []
        try:
            self._build(password)
        except Exception:
            self.close()
            raise
        info: dict[str, Any] = {f"EvidenceCollection / {k}": v for k, v in self.ufdx.attributes.items()}
        info.update({f"DeviceInfo / {k}": v for k, v in self.ufdx.device.items()})
        self._own_info["/"] = info
        self._finish()

    def _build(self, password: str) -> None:
        if not self.ufdx.extractions:
            self._root.status = ParseIssue("ufdx.no_extractions")
            return
        for ex in self.ufdx.extractions:
            ref = ex.get("Path", "")
            parts = PureWindowsPath(ref).parts
            name = parts[-2] if len(parts) > 1 else (parts[-1] if parts else "(no path)")
            file = _resolve(self._path.parent, ref) if ref else None
            what = {"path": ref, "type": ex.get("TransferType", "")}
            ufd_name = parts[-1] if parts else ""
            if file is None:
                issue = ParseIssue("ufdx.extraction_missing", what)
                folder = self._folder(self._root, name, issue)
                self._extractions.append((folder.name, (ufd_name, issue)))
                continue
            try:
                ufd = UFDVFS(file, password=password)
            except WrongPasswordError as exc:
                # One password is entered for the whole UFDX: say which
                # extraction it didn't open.
                reason = exc.args[0] if exc.args else ""
                raise WrongPasswordError(ParseIssue(
                    "ufdx.extraction_password_rejected", {**what, "reason": reason},
                )) from exc
            except UFDOpenError as exc:
                issue = ParseIssue("ufdx.extraction_not_opened", what, detail=str(exc))
                folder = self._folder(self._root, name, issue)
                self._extractions.append((folder.name, (ufd_name, issue)))
                continue
            self._subs.append(ufd)
            folder = self._folder(self._root, name, join_notes([
                ParseIssue("ufdx.extraction", what), ufd.root().status,
            ]))
            self._own_info[folder.path] = ufd.node_info(ufd.root()) or {}
            self._hold(folder, ufd, ufd.root())
            self._extractions.append((folder.name, ufd))

    def acquisition(self) -> str | None:
        return "UFDX"

    def verify_acquisition(
        self, progress: Callable[[int, int], None] | None = None
    ) -> dict[str, Any]:
        """Every listed .ufd's recorded file hashes, each named with its
        extraction's folder. A listed extraction that is missing or couldn't
        be read is a failed check, with the reason as its status."""
        files: list[dict[str, Any]] = []
        hmacs: list[str] = []
        for name, ufd in self._extractions:
            if not isinstance(ufd, UFDVFS):
                ufd_name, issue = ufd
                files.append({
                    "name": f"{name}/{ufd_name}" if ufd_name else name,
                    "algorithm": None, "stored": None, "computed": None,
                    "found": False, "match": False, "status": issue,
                })
                continue
            files.extend(verify_ufd_files(ufd.ufd, progress, label_prefix=f"{name}/"))
            hmac = ufd.ufd.get("Hash", "HMAC")
            if hmac:
                hmacs.append(f"{name}: {hmac}")
        return _verify_result(files, "; ".join(hmacs) or None)
