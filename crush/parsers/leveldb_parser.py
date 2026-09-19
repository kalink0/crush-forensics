# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""LevelDB parser (vendored ccl_leveldb, MIT)."""
from __future__ import annotations

import logging
import re
import shutil
from pathlib import Path
from typing import Any

from crush.core import tempdir
from crush.core.vfs import VFS, VFSNode
from crush.parsers.base import AbstractParser, ParseResult
from crush.third_party.ccl_leveldb import KeyState, RawLevelDb
from crush.third_party.ccl_leveldb.ccl_leveldb import ManifestFile

_DATA_FILE_RE = re.compile(r"^[0-9]{6}\.(ldb|log|sst)$", re.IGNORECASE)
_logger = logging.getLogger(__name__)

_MAX_TEXT_LEN = 256  # truncation limit for decoded text fields


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
        return text[:_MAX_TEXT_LEN]
    return user_key[:32].hex() + ("…" if len(user_key) > 32 else "")


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
        file_to_level: dict[int, int] = {}
        file_key_ranges: dict[int, dict[str, Any]] = {}

        try:
            with RawLevelDb(tmp_dir) as db:
                current_fno = db.manifest.file_no if db.manifest else -1

                if db.manifest:
                    _, file_to_level, file_key_ranges = _parse_manifest(db.manifest)

                # Parse ALL MANIFEST files for the Overview, not just the latest (#6)
                _mfest_re = re.compile(ManifestFile.MANIFEST_FILENAME_PATTERN)
                for mpath in sorted(tmp_dir.iterdir(), key=lambda p: p.name):
                    if not _mfest_re.match(mpath.name):
                        continue
                    try:
                        mf = ManifestFile(mpath)
                        mdata, _, _ = _parse_manifest(mf)
                        fno = mf.file_no
                        mf.close()  # type: ignore[no-untyped-call]
                        label = mpath.name + (" (current)" if fno == current_fno else "")
                        if mdata:
                            manifests_display[label] = mdata
                    except Exception as exc:  # noqa: BLE001
                        _logger.debug("Could not parse %s: %s", mpath.name, exc)

                # CURRENT file (#9)
                current_file = tmp_dir / "CURRENT"
                if current_file.exists():
                    try:
                        target = current_file.read_text(encoding="utf-8", errors="replace").strip()
                        manifests_display["CURRENT"] = {"Active MANIFEST": target}
                    except Exception as exc:  # noqa: BLE001
                        _logger.debug("Could not read CURRENT: %s", exc)

                # Per-file counters: file_name → {type, level, total, live, deleted, unknown}
                file_stats: dict[str, dict[str, Any]] = {}

                records: list[dict[str, Any]] = []
                parse_warning = ""

                try:
                    for record in db.iterate_records_raw():
                        fname = Path(record.origin_file).name

                        if fname not in file_stats:
                            try:
                                fno = int(Path(record.origin_file).stem, 16)
                            except ValueError:
                                fno = -1
                            file_stats[fname] = {
                                "name": fname,
                                "type": record.file_type.name,
                                "level": file_to_level.get(fno, -1),
                                "total": 0,
                                "live": 0,
                                "deleted": 0,
                                "unknown": 0,
                            }

                        fs = file_stats[fname]
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

                except Exception as exc:
                    _logger.warning("LevelDB read error for %s: %s", node.path, exc)
                    parse_warning = str(exc)
                    if not records:
                        return ParseResult(
                            viewer_type="tree",
                            data={"error": str(exc), "hint": "LevelDB could not be opened"},
                            metadata={
                                "Format": "LevelDB (parse failed)",
                                "Parse error": str(exc),
                                "Files": f"{vfs.file_count(node):,}",
                            },
                        )

        except Exception as exc:
            _logger.warning("LevelDB open error for %s: %s", node.path, exc)
            return ParseResult(
                viewer_type="tree",
                data={"error": str(exc), "hint": "LevelDB could not be opened"},
                metadata={"Format": "LevelDB (parse failed)", "Parse error": str(exc)},
            )

        # Merge manifest key ranges and file sizes into file_stats (#8)
        for fstat in file_stats.values():
            try:
                fno = int(Path(fstat["name"]).stem, 16)
            except ValueError:
                continue
            kr = file_key_ranges.get(fno)
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
        if parse_warning:
            meta["Parse warning"] = parse_warning

        data: dict[str, Any] = {
            "manifests": manifests_display,
            "files": sorted(file_stats.values(), key=lambda f: f["name"]),
            "records": records,
            "log_files": log_files,
        }

        text_parts: list[str] = []
        for r in records:
            if r["user_key_text"]:
                text_parts.append(r["user_key_text"][:_MAX_TEXT_LEN])
            if r["value_text"]:
                text_parts.append(r["value_text"][:_MAX_TEXT_LEN])
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
) -> tuple[dict[str, Any], dict[int, int], dict[int, dict[str, Any]]]:
    """Extract summary info, file-to-level map, and per-file key ranges from a ManifestFile."""
    file_to_level: dict[int, int] = dict(manifest.file_to_level)
    file_key_ranges: dict[int, dict[str, Any]] = {}  # fno → {size, smallest, largest}

    comparator: str | None = None
    last_sequence: int | None = None
    log_number: int | None = None
    prev_log_number: int | None = None
    next_file_number: int | None = None
    compaction_history: list[dict[str, Any]] = []

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
                        {"level": nf.level, "file": f"{nf.file_no:06x}", "size": nf.file_size}
                        for nf in edit.new_files
                    ]
                if edit.deleted_files:
                    entry["deleted"] = [
                        {"level": df.level, "file": f"{df.file_no:06x}"}
                        for df in edit.deleted_files
                    ]
                if entry:
                    compaction_history.append(entry)
    except Exception as exc:
        _logger.debug("Manifest parse warning: %s", exc)

    # Build levels summary: level → list of file numbers
    levels: dict[str, list[str]] = {}
    for fno, level in sorted(file_to_level.items()):
        key = f"Level {level}"
        levels.setdefault(key, []).append(f"{fno:06x}")

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

    return manifest_data, file_to_level, file_key_ranges


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
