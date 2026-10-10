# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""LevelDB parser (vendored ccl_leveldb, MIT)."""
from __future__ import annotations

import logging
import re
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

from crush.core import tempdir
from crush.core.issues import ParseIssue
from crush.core.vfs import VFS, VFSNode, join_notes
from crush.parsers.base import AbstractParser, ParseResult
from crush.third_party.ccl_leveldb import KeyState
from crush.third_party.ccl_leveldb.ccl_leveldb import FileType, LdbFile, LogFile, ManifestFile

# LevelDB names its files after a decimal file number of at least six digits
# ("%06llu", db/filename.cc), the number the MANIFEST records for them.
# Anchored: a copy such as "000005.ldb.bak" or "MANIFEST-000002.bak" is not
# one of the database's own files. (The vendored reader takes the names as
# hex and six digits only.)
_DATA_FILE_RE = re.compile(r"^([0-9]{6,})\.(ldb|log|sst)$", re.IGNORECASE)
_MANIFEST_RE = re.compile(r"^MANIFEST-([0-9]{6,})$")
# Every MANIFEST-named file is shown in the Overview, copies included.
_MANIFEST_LISTED_RE = re.compile(r"^MANIFEST-[0-9]{6,}")
_logger = logging.getLogger(__name__)


def _file_number(path: Path) -> int:
    """The file number of a data file matched by _DATA_FILE_RE."""
    return int(path.name.split(".", 1)[0])


def _file_label(file_no: int) -> str:
    """A file number written the way LevelDB names the file."""
    return f"{file_no:06d}"


def _data_files(directory: Path) -> list[Path]:
    """The table and log files in *directory*, in file-number order."""
    found = [p for p in directory.iterdir() if p.is_file() and _DATA_FILE_RE.match(p.name)]
    return sorted(found, key=_file_number)


def _manifest_number(name: str) -> int | None:
    match = _MANIFEST_RE.match(name)
    return int(match.group(1)) if match else None


def _current_manifest(
    directory: Path, reason: Callable[[Exception], str]
) -> tuple[Path | None, dict[str, Any]]:
    """The MANIFEST that CURRENT names, as LevelDB finds it on opening
    (VersionSet::Recover): CURRENT holds the file name followed by a line
    break. None when CURRENT can't be used -- then no MANIFEST is taken as
    the current one, not even the highest-numbered. Also what the Overview
    shows for CURRENT."""
    path = directory / "CURRENT"
    if not path.is_file():
        return None, {"Status": ParseIssue("leveldb.current_missing")}
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return None, {"Status": ParseIssue("leveldb.current_unreadable", detail=reason(exc))}
    text = raw.decode("utf-8", errors="replace")
    name = text[:-1] if text.endswith("\n") else text
    notes: list[Any] = [] if text.endswith("\n") else [ParseIssue("leveldb.current_no_newline")]
    if _manifest_number(name) is None:
        return None, {
            "Content": repr(text),
            "Status": join_notes([*notes, ParseIssue("leveldb.current_invalid")]),
        }
    shown: dict[str, Any] = {"Active MANIFEST": name}
    if not (directory / name).is_file():
        notes.append(ParseIssue("leveldb.current_target_missing", {"name": name}))
        shown["Status"] = join_notes(notes)
        return None, shown
    if notes:
        shown["Status"] = join_notes(notes)
    return directory / name, shown

def _try_utf8(raw: bytes) -> str | None:
    """Return UTF-8 decoded string, or None if not valid UTF-8."""
    try:
        return raw.decode("utf-8")
    except (UnicodeDecodeError, AttributeError):
        return None


def _decode_internal_key(raw: bytes) -> str:
    """Return displayable representation of an LDB internal key (strips 8-byte seq/type suffix)."""
    user_key = raw[:-8] if len(raw) > 8 else raw
    text = _try_utf8(user_key)
    if text is not None:
        return text
    return user_key.hex()


class LeveldbParser(AbstractParser):
    SUPPORTED_EXTENSIONS: list[str] = []
    DISPLAY_NAME = "LevelDB"

    def can_parse(self, path: str, peek_bytes: bytes) -> bool:  # noqa: ARG002
        return False

    def can_parse_dir(self, node: VFSNode) -> bool:
        for child in node.children:
            if _DATA_FILE_RE.match(child.name):
                return True
            if child.name.startswith("MANIFEST-"):
                return True
        return False

    def parse(self, node: VFSNode, vfs: VFS) -> ParseResult:
        if not node.is_dir:
            raise ValueError("LevelDB parser expects a directory")
        if not self.can_parse_dir(node):
            raise ValueError("Not a LevelDB directory")

        tmp_dir = tempdir.mkdtemp(prefix="crush-leveldb-")
        try:
            _export_dir(node, vfs, tmp_dir)
            return self._parse_tmp(node, vfs, tmp_dir)
        finally:
            try:
                shutil.rmtree(tmp_dir, ignore_errors=True)
            except Exception:
                pass

    def _parse_tmp(self, node: VFSNode, vfs: VFS, tmp_dir: Path) -> ParseResult:
        manifests_display: dict[str, Any] = {}
        # Files that exist but couldn't be read or parsed, with the reason --
        # shown in the Overview instead of silently leaving them out.
        unreadable: dict[str, ParseIssue] = {}
        file_to_level: dict[int, int] = {}
        file_key_ranges: dict[int, dict[str, Any]] = {}

        def reason(exc: Exception) -> str:
            # The reader names the files it opened, the working copies in
            # tmp_dir; show where they are in the evidence instead.
            evidence = node.path.rstrip("/")
            return str(exc).replace(str(tmp_dir), evidence).replace(
                evidence + "\\", evidence + "/"
            )

        # Every file is opened and read on its own: one that can't be read
        # is listed with the reason and the others are still read.
        # The MANIFEST that CURRENT names gives the files their level, size
        # and key range (#9).
        current, current_shown = _current_manifest(tmp_dir, reason)
        if current is not None:
            try:
                manifest = ManifestFile(current)
            except Exception as exc:  # noqa: BLE001 -- listed by the loop below
                _logger.debug("Could not open %s: %s", current.name, exc)
                current_shown["Status"] = join_notes([
                    current_shown.get("Status"),
                    ParseIssue("leveldb.current_target_unreadable", {"name": current.name}),
                ])
                current = None
            else:
                _, file_to_level, file_key_ranges, _ = _parse_manifest(manifest)
                manifest.close()  # type: ignore[no-untyped-call]
        current_no = _manifest_number(current.name) if current is not None else None

        # Parse ALL MANIFEST files for the Overview, not just the current one (#6)
        for mpath in sorted(tmp_dir.iterdir(), key=lambda p: p.name):
            if not _MANIFEST_LISTED_RE.match(mpath.name):
                continue
            try:
                mf = ManifestFile(mpath)
                mdata, _, _, partial = _parse_manifest(mf)
                mf.close()  # type: ignore[no-untyped-call]
                label = mpath.name + (" (current)" if mpath == current else "")
                notes: list[Any] = [partial]
                number = _manifest_number(mpath.name)
                if current_no is not None and number is not None and number > current_no:
                    # Written but never named by CURRENT, e.g. when LevelDB
                    # stopped between creating it and switching CURRENT.
                    notes.append(ParseIssue("leveldb.manifest_after_current"))
                status = join_notes(notes)
                if status:
                    mdata = {"Status": status, **mdata}
                if mdata:
                    manifests_display[label] = mdata
            except Exception as exc:  # noqa: BLE001
                _logger.debug("Could not parse %s: %s", mpath.name, exc)
                unreadable[mpath.name] = ParseIssue("leveldb.manifest_failed", detail=reason(exc))
        manifests_display["CURRENT"] = current_shown

        # Per-file counters: file_name → {type, level, total, live, deleted, unknown}
        file_stats: dict[str, dict[str, Any]] = {}
        records: list[dict[str, Any]] = []
        data_files = _data_files(tmp_dir)
        not_whole = 0  # data files not read to their end

        for path in data_files:
            try:
                # Any: the vendored __iter__ is annotated Iterable, not Iterator.
                reader: Any = (
                    LogFile(path) if path.suffix.lower() == ".log" else LdbFile(path)
                )
            except Exception as exc:  # noqa: BLE001
                _logger.warning("LevelDB: could not open %s in %s: %s", path.name, node.path, exc)
                unreadable[path.name] = ParseIssue("leveldb.file_unreadable", detail=reason(exc))
                not_whole += 1
                continue
            fname = path.name
            # A row for every file that opens, even one holding no records.
            fs = file_stats[fname] = {
                "name": fname,
                "type": (FileType.Log if isinstance(reader, LogFile) else FileType.Ldb).name,
                "level": file_to_level.get(_file_number(path), -1),
                "total": 0,
                "live": 0,
                "deleted": 0,
                "unknown": 0,
            }
            from_file = 0
            try:
                for record in reader:
                    fs["total"] += 1
                    state_name = record.state.name
                    if record.state == KeyState.Live:
                        fs["live"] += 1
                    elif record.state == KeyState.Deleted:
                        fs["deleted"] += 1
                    else:
                        fs["unknown"] += 1

                    uk = record.user_key
                    val = record.value if record.value is not None else b""

                    records.append({
                        "seq": record.seq,
                        "state": state_name,
                        "file": fname,
                        "offset": record.offset,
                        "internal_key_bytes": record.key,
                        "user_key_bytes": uk,
                        "user_key_text": _try_utf8(uk),
                        "value_bytes": val,
                        "value_text": _try_utf8(val),
                        "compressed": record.was_compressed,
                    })
                    from_file += 1
            except Exception as exc:  # noqa: BLE001
                _logger.warning("LevelDB read error in %s of %s: %s", path.name, node.path, exc)
                unreadable[path.name] = ParseIssue(
                    "leveldb.read_stopped", {"count": from_file}, detail=reason(exc),
                )
                not_whole += 1
            finally:
                reader.close()

        # Merge manifest key ranges and file sizes into file_stats (#8)
        for fstat in file_stats.values():
            kr = file_key_ranges.get(_file_number(Path(fstat["name"])))
            fstat["size"] = kr["size"] if kr else None
            fstat["smallest_key"] = kr["smallest"] if kr else ""
            fstat["largest_key"] = kr["largest"] if kr else ""

        # Read LOG and LOG.old in full — no truncation (#10)
        log_files: dict[str, str] = {}
        for log_name in ("LOG", "LOG.old"):
            log_path = tmp_dir / log_name
            if log_path.exists():
                try:
                    log_files[log_name] = log_path.read_text(encoding="utf-8", errors="replace")
                except Exception as exc:  # noqa: BLE001
                    _logger.debug("Could not read %s: %s", log_name, exc)
                    unreadable[log_name] = ParseIssue("leveldb.file_unreadable", detail=reason(exc))
        if unreadable:
            manifests_display["Unreadable files"] = unreadable

        total = len(records)
        live_count = sum(1 for r in records if r["state"] == "Live")
        deleted_count = sum(1 for r in records if r["state"] == "Deleted")

        meta: dict[str, Any] = {
            "Format": "LevelDB",
            "Records": f"{total:,}",
            "Live": f"{live_count:,}",
            "Deleted": f"{deleted_count:,}",
            "Files": f"{vfs.file_count(node):,}",
            "Total size": f"{vfs.total_size(node):,} B",
        }
        if not_whole:
            meta["Parse warning"] = ParseIssue(
                "leveldb.data_files_not_read", {"count": not_whole, "total": len(data_files)},
            )

        data: dict[str, Any] = {
            "manifests": manifests_display,
            "files": sorted(file_stats.values(), key=lambda f: f["name"]),
            "records": records,
            "log_files": log_files,
        }

        text_parts: list[str] = []
        for r in records:
            if r["user_key_text"]:
                text_parts.append(r["user_key_text"][:256])
            if r["value_text"]:
                text_parts.append(r["value_text"][:256])
            if len(text_parts) >= 2000:
                break

        return ParseResult(
            viewer_type="leveldb",
            data=data,
            metadata=meta,
            text_index=" ".join(text_parts[:2000]),
        )


def _parse_manifest(
    manifest: ManifestFile,
) -> tuple[dict[str, Any], dict[int, int], dict[int, dict[str, Any]], ParseIssue | None]:
    """Extract summary info, file-to-level map, and per-file key ranges from
    a ManifestFile, plus why reading stopped early (None: read to the end)."""
    file_to_level: dict[int, int] = dict(manifest.file_to_level)
    file_key_ranges: dict[int, dict[str, Any]] = {}  # fno → {size, smallest, largest}

    comparator: str | None = None
    last_sequence: int | None = None
    log_number: int | None = None
    prev_log_number: int | None = None
    next_file_number: int | None = None
    compaction_history: list[dict[str, Any]] = []
    partial: ParseIssue | None = None

    try:
        for edit in manifest:
            if edit.comparator and comparator is None:
                comparator = edit.comparator
            if edit.last_sequence is not None:
                last_sequence = edit.last_sequence
            if edit.log_number is not None:
                log_number = edit.log_number
            if edit.prev_log_number is not None:
                prev_log_number = edit.prev_log_number
            if edit.next_file_number is not None:
                next_file_number = edit.next_file_number
            for nf in edit.new_files:
                file_key_ranges[nf.file_no] = {
                    "size": nf.file_size,
                    "smallest": _decode_internal_key(nf.smallest_key),
                    "largest": _decode_internal_key(nf.largest_key),
                }
            if edit.new_files or edit.deleted_files:
                entry: dict[str, Any] = {}
                if edit.new_files:
                    entry["new"] = [
                        {"level": nf.level, "file": _file_label(nf.file_no), "size": nf.file_size}
                        for nf in edit.new_files
                    ]
                if edit.deleted_files:
                    entry["deleted"] = [
                        {"level": df.level, "file": _file_label(df.file_no)}
                        for df in edit.deleted_files
                    ]
                if entry:
                    compaction_history.append(entry)
    except Exception as exc:
        _logger.debug("Manifest parse warning: %s", exc)
        partial = ParseIssue("leveldb.manifest_partial", detail=str(exc))

    # Build levels summary: level → list of file numbers
    levels: dict[str, list[str]] = {}
    for fno, level in sorted(file_to_level.items()):
        key = f"Level {level}"
        levels.setdefault(key, []).append(_file_label(fno))

    manifest_data: dict[str, Any] = {}
    if comparator:
        manifest_data["Comparator"] = comparator
    if last_sequence is not None:
        manifest_data["Last sequence"] = last_sequence
    if log_number is not None:
        manifest_data["Log number"] = log_number
    if prev_log_number is not None:
        manifest_data["Prev log number"] = prev_log_number
    if next_file_number is not None:
        manifest_data["Next file number"] = next_file_number
    if levels:
        manifest_data["Files by level"] = {k: ", ".join(v) for k, v in sorted(levels.items())}
    if compaction_history:
        manifest_data["Compaction history"] = compaction_history

    return manifest_data, file_to_level, file_key_ranges, partial


def _export_dir(node: VFSNode, vfs: VFS, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    for child in node.children:
        child_target = target / child.name
        if child.is_dir:
            _export_dir(child, vfs, child_target)
        else:
            child_target.parent.mkdir(parents=True, exist_ok=True)
            with vfs.open(child) as src, open(child_target, "wb") as dst:
                dst.write(src.read())
