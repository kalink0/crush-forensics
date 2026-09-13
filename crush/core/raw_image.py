# SPDX-License-Identifier: Apache-2.0
"""Raw disk image (.img/.dd/split .001 sets) and EWF (Expert Witness Format,
.E01) acquisition reading, backed by the vendored `crush.third_party.qnxprobe`
(+ `ewfprobe`) readers.

qnxprobe reads MBR/GPT partition tables and then NTFS, FAT32, exFAT,
ext2/3/4, F2FS, HFS+, APFS, QNX6, QNX4, ETFS, EFS and QNX IFS directly from a
raw image or a bare partition — no mounting, no admin rights. ewfprobe reads
an EWF (.E01) acquisition, joining its numbered segments, as an ordinary
seekable stream that qnxprobe reads exactly like a raw image.

`RawImageVFS` (crush/core/vfs.py) is the thin VFS-facing wrapper; this module
holds everything specific to the two vendored readers.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

# qnxprobe reaches its EWF reader with a bare `import ewfprobe`, falling back
# to a sys.path insertion of its own directory when that fails. Registering
# our vendored copy under the bare name first means it resolves correctly
# both from source and in a frozen (PyInstaller) build, where qnxprobe's own
# sys.path fallback cannot find a sibling file — mirrors how iLEAPP/ALEAPP
# wire the same two vendored libraries together.
from crush.third_party.ewfprobe import ewfprobe as _ewfprobe

sys.modules.setdefault("ewfprobe", _ewfprobe)
from crush.third_party import qnxprobe  # noqa: E402

if TYPE_CHECKING:
    from crush.core.vfs import VFSNode

_MAX_DEPTH = 64  # a directory this deep in a walk is a loop, not a directory


class RawImageOpenError(ValueError):
    """The path is not a raw image / EWF acquisition qnxprobe or ewfprobe can read."""


class RawImageTruncatedReadError(OSError):
    """A file's declared size reaches past the end of the image."""


class RawImageFileUnreadableError(OSError):
    """The filesystem reader could not return this file's content."""


@dataclass
class RawImageHandle:
    """An opened raw image or EWF acquisition, with its volume list."""

    path: Path
    image: Any  # a plain file object, qnxprobe.SegmentedImage, or ewfprobe.EwfImage
    size: int
    volumes: list[dict[str, Any]]
    is_ewf: bool

    def close(self) -> None:
        try:
            self.image.close()
        except Exception:  # pragma: no cover — best-effort cleanup
            pass


def verify_ewf(
    handle: RawImageHandle, progress: Callable[[int, int], None] | None = None
) -> dict[str, Any]:
    """Recompute an EWF acquisition's MD5/SHA1 and compare them to the
    acquisition's own stored hashes (written by the tool that made it).

    Returns ewfprobe's own result dict: `computed`, `stored`, `match` (True,
    False, or None when the acquisition recorded no hash to compare against),
    `bytes`, `checksum_errors`. Only valid for an EWF source — raw images
    have no built-in hash of their own to verify against, which is exactly
    why this is separate from (and not a substitute for) that case.
    """
    if not handle.is_ewf:
        raise ValueError(f"{handle.path.name} is not an EWF acquisition")
    return handle.image.verify(progress=progress)  # type: ignore[no-any-return]


@dataclass
class _Entry:
    """Where one VFSNode's bytes live: a walker + its opaque node handle for
    a real file, or (walker=None) a raw byte range of the image itself for a
    volume whose filesystem qnxprobe recognises but has no walker for, or
    doesn't recognise at all -- `base` is that region's offset in the image.
    Never hidden or made unreadable: a forensic tool showing "nothing here"
    for a region it simply doesn't parse would be actively misleading, so
    this reads as the raw bytes an examiner can inspect directly (e.g. via
    Hex View) instead.
    """

    walker: Any | None
    node: Any | None
    size: int
    base: int | None = None
    kind: str = ""
    note: str = ""
    deleted: Any | None = None  # a *DeletedFile record, when this is a recovered entry


def open_raw_image(path: Path) -> RawImageHandle:
    """Open `path` as a raw disk image or EWF acquisition and list its volumes.

    Raises RawImageOpenError when the path isn't actually a readable image:
    a split set with a numbering gap, a bad EWF header, or a file in which no
    partition table or bare filesystem could be found at all.
    """
    is_ewf = qnxprobe.looks_like_ewf(str(path))  # type: ignore[no-untyped-call]
    try:
        image = qnxprobe.open_image(str(path))  # type: ignore[no-untyped-call]
    except qnxprobe.SplitImageError as exc:
        raise RawImageOpenError(f"{path.name}: {exc}") from exc
    except Exception as exc:
        raise RawImageOpenError(
            f"{path.name}: not a readable raw image or EWF acquisition ({exc})"
        ) from exc

    try:
        size = qnxprobe.image_size(image)  # type: ignore[no-untyped-call]
        vols = qnxprobe.volumes(image, size)  # type: ignore[no-untyped-call]
    except Exception as exc:
        image.close()
        raise RawImageOpenError(f"{path.name}: could not read volumes ({exc})") from exc

    # qnxprobe.volumes() always reports *something* for a region it scanned,
    # even a "not recognised" entry with no walker for a file that holds no
    # partition table or filesystem it knows at all — so an empty list alone
    # never actually happens for a normal file. What matters is whether any
    # volume has something to browse; if not, a plain hex view of the same
    # bytes is strictly more useful than an empty RawImageVFS tree.
    if not any(vol.get("walker") is not None for vol in vols):
        image.close()
        raise RawImageOpenError(
            f"{path.name}: no partition table or recognized filesystem found"
        )

    vols = vols + _compute_unallocated_gaps(vols, size)
    return RawImageHandle(path=path, image=image, size=size, volumes=vols, is_ewf=is_ewf)


def _compute_unallocated_gaps(vols: list[dict[str, Any]], total_size: int) -> list[dict[str, Any]]:
    """Synthesize an "unallocated" volumes()-shaped entry for every byte
    range not covered by one of qnxprobe's own regions.

    qnxprobe.volumes() reports only the partition table's own entries (MBR
    primaries, logical volumes, GPT entries) — unlike a tool such as The
    Sleuth Kit's `mmls`, it never reports the gaps between or around them
    (pre-partition alignment padding, slack after the last partition,
    space between logical volumes). That space can legitimately hold
    carved or deleted data, so it must still be visible and readable, not
    silently absent from the tree just because no partition table entry
    claims it.
    """
    regions = sorted(
        ((vol.get("base") or 0, vol.get("size") or 0) for vol in vols),
        key=lambda region: region[0],
    )
    gaps: list[dict[str, Any]] = []
    cursor = 0
    for base, size in regions:
        if base > cursor:
            gaps.append({
                "name": f"unallocated_{cursor}", "base": cursor, "size": base - cursor,
                "kind": "unallocated", "note": "space outside any partition table entry",
                "walker": None,
            })
        cursor = max(cursor, base + size)
    if cursor < total_size:
        gaps.append({
            "name": f"unallocated_{cursor}", "base": cursor, "size": total_size - cursor,
            "kind": "unallocated", "note": "space outside any partition table entry",
            "walker": None,
        })
    return gaps


def build_volume_node(vol: dict[str, Any], read_map: dict[str, _Entry]) -> "VFSNode":
    """One top-level VFSNode for a qnxprobe volumes() entry.

    A volume with no walker (recognised filesystem qnxprobe can't walk, an
    extended-partition container, or nothing recognised at all) becomes a
    non-browsable leaf carrying its size and the reason, rather than being
    silently dropped -- and it stays fully readable as the raw bytes of that
    region (e.g. via Hex View), since a forensic tool must never make part
    of the source look less accessible than it actually is.
    """
    from crush.core.vfs import VFSNode

    name = vol.get("name") or f"lba{vol.get('lba', 0)}"
    size = vol.get("size") or 0
    path = f"/{name}"
    walker = vol.get("walker")

    if walker is None:
        read_map[path] = _Entry(
            walker=None, node=None, size=size, base=vol.get("base"),
            kind=vol.get("kind", "unknown"), note=vol.get("note", ""),
        )
        return VFSNode(name=name, path=path, is_dir=False, size=size)

    node = VFSNode(name=name, path=path, is_dir=True)
    _walk_into(walker, walker.root, node, read_map, path, set())
    if hasattr(walker, "deleted_files"):
        _add_deleted_files_node(walker, node, read_map, path)
    return node


def _add_deleted_files_node(
    walker: Any, volume_node: "VFSNode", read_map: dict[str, _Entry], base_path: str,
) -> None:
    """A flat `$Recovered` child of the volume, one leaf per entry
    walker.deleted_files() yields (NTFS/FAT32/exFAT only -- the only
    filesystems qnxprobe has this for). Not reassembled into the deleted
    files' original folders: that needs mapping each entry's `parent`
    handle back onto a live directory that may itself be gone, which is
    real additional complexity for a placement detail, not for whether the
    data is recoverable and visible at all -- flat is enough for that.

    Every entry is listed, including ones qnxprobe itself judged not
    recoverable (clusters reused, attributes overflowed, etc.) -- with an
    explicit reason available via read(), never silently absent, matching
    every other unsupported/partial case in this module.
    """
    from crush.core.vfs import VFSNode

    try:
        entries = list(walker.deleted_files())
    except Exception:
        return  # a failure enumerating deleted files must not break the live tree
    if not entries:
        return

    recovered_path = f"{base_path}/$Recovered"
    recovered = VFSNode(name="$Recovered", path=recovered_path, is_dir=True)
    seen_names: dict[str, int] = {}
    for entry in entries:
        name = entry.name or "(unnamed)"
        count = seen_names.get(name, 0)
        seen_names[name] = count + 1
        unique_name = name if count == 0 else f"{name} ({count})"
        child_path = f"{recovered_path}/{unique_name}"
        recovered.children.append(
            VFSNode(name=unique_name, path=child_path, is_dir=False, size=entry.size or 0)
        )
        read_map[child_path] = _Entry(walker=walker, node=None, size=entry.size or 0, deleted=entry)

    recovered.children.sort(key=lambda n: n.name.lower())
    volume_node.children.append(recovered)
    volume_node.children.sort(key=lambda n: (not n.is_dir, n.name.lower()))


def _walk_into(
    walker: Any,
    wnode: Any,
    vfs_node: "VFSNode",
    read_map: dict[str, _Entry],
    base_path: str,
    seen: set[Any],
    depth: int = 0,
) -> None:
    from crush.core.vfs import VFSNode

    if depth > _MAX_DEPTH or wnode in seen:
        return
    seen.add(wnode)
    try:
        if hasattr(walker, "listdir_records"):
            # FAT/exFAT keep a wall-clock reading with no timezone rather
            # than an instant; listdir_records() hands it back as text.
            listing = [
                (name, child, (recorded or {}).get("modified", ""))
                for name, child, recorded in walker.listdir_records(wnode)
            ]
        else:
            listing = [(name, child, "") for name, child in walker.listdir(wnode)]
    except Exception:
        return  # this directory couldn't be listed; its siblings still can be
    listing.sort(key=lambda item: item[0])

    children: list[VFSNode] = []
    for name, child, _reading in listing:
        try:
            ent = walker.entry(child)
        except Exception:
            continue
        if not ent:
            continue
        mode, size, mtime = ent
        child_path = f"{base_path}/{name}"
        if mode & qnxprobe.S_IFDIR:
            child_node = VFSNode(name=name, path=child_path, is_dir=True, modified=mtime or 0.0)
            children.append(child_node)
            _walk_into(walker, child, child_node, read_map, child_path, seen, depth + 1)
        elif (mode & 0o170000) == 0o100000:  # regular files only
            child_node = VFSNode(
                name=name, path=child_path, is_dir=False, size=size or 0, modified=mtime or 0.0,
            )
            children.append(child_node)
            read_map[child_path] = _Entry(walker=walker, node=child, size=size or 0)
        # symlinks and specials hold no bytes to stage — not represented

    children.sort(key=lambda n: (not n.is_dir, n.name.lower()))
    vfs_node.children = children


def read_walker_file(walker: Any, node: Any, size: int) -> bytes:
    """Materialize one file's bytes via `walker.read_file(node, size)`.

    A read past the end of the image comes back zero-filled rather than
    raising, so the copy's length alone says nothing about whether the file
    was whole. qnxprobe counts every byte it fell short by in a module-level
    counter; sampling it before and after is how a cut-short file is told
    from a whole one.
    """
    shortfall_before = qnxprobe.EOF_SHORTFALL["bytes"]
    chunks: list[bytes] = []
    got = 0
    try:
        for chunk in walker.read_file(node, size):
            chunks.append(chunk)
            got += len(chunk)
    except Exception as exc:
        raise RawImageFileUnreadableError(f"could not read file: {exc}") from exc

    cut_by = qnxprobe.EOF_SHORTFALL["bytes"] - shortfall_before
    if cut_by:
        present = max(min(got, size - cut_by), 0)
        raise RawImageTruncatedReadError(
            f"only {present:,} of {size:,} bytes are in the image "
            f"(the image ends before the file does)"
        )
    return b"".join(chunks)


def read_deleted_file(walker: Any, entry: Any, size: int) -> bytes:
    """Materialize a recovered deleted file's bytes via
    `walker.read_deleted(entry, size)`.

    Checked against `entry.recoverable` first, rather than letting the
    walker's own read raise: qnxprobe already knows and names the reason
    (clusters reused, attributes overflowed, ...) at `deleted_files()` time,
    so surfacing that directly is clearer than a generic read failure.
    """
    if not entry.recoverable:
        raise RawImageFileUnreadableError(
            f"deleted file {entry.name!r} is not recoverable: {entry.reason}"
        )
    shortfall_before = qnxprobe.EOF_SHORTFALL["bytes"]
    chunks: list[bytes] = []
    got = 0
    try:
        for chunk in walker.read_deleted(entry, size):
            chunks.append(chunk)
            got += len(chunk)
    except Exception as exc:
        raise RawImageFileUnreadableError(
            f"deleted file {entry.name!r}: could not read it: {exc}"
        ) from exc

    cut_by = qnxprobe.EOF_SHORTFALL["bytes"] - shortfall_before
    if cut_by:
        present = max(min(got, size - cut_by), 0)
        raise RawImageTruncatedReadError(
            f"only {present:,} of {size:,} bytes of deleted file {entry.name!r} "
            f"are in the image (the image ends before the file does)"
        )
    return b"".join(chunks)


def peek_walker_file(walker: Any, node: Any, size: int, n: int) -> bytes:
    """Read at most the first `n` bytes of a file, without materializing the
    whole thing.

    Every walker's `read_file()` yields incrementally rather than building
    the whole file in memory first — up to 1 MiB per chunk for large
    non-resident NTFS/ext data, for instance — so stopping the generator
    once enough bytes have arrived costs at most one (or a few) chunks,
    never the whole file. This matters because magic-byte type sniffing
    calls peek() on every file during the filesystem panel's background
    scan; without this, sniffing 32 bytes of a multi-GB video on a real
    device image would read the entire file just to throw almost all of
    it away.
    """
    chunks: list[bytes] = []
    got = 0
    try:
        for chunk in walker.read_file(node, size):
            chunks.append(chunk)
            got += len(chunk)
            if got >= n:
                break
    except Exception as exc:
        raise RawImageFileUnreadableError(f"could not read file: {exc}") from exc
    return b"".join(chunks)[:n]


def peek_deleted_file(walker: Any, entry: Any, size: int, n: int) -> bytes:
    """Read at most the first `n` bytes of a recovered deleted file.

    NTFS's read_deleted() chunks the same way read_file() does, so this
    stays cheap there; FAT32/exFAT's read_deleted() builds the whole file
    in memory before its one yield regardless, so this saves nothing for
    those two -- but a deleted-files listing is normally far smaller than
    a volume's live tree, so that's an acceptable, not a silent, cost.
    """
    if not entry.recoverable:
        raise RawImageFileUnreadableError(
            f"deleted file {entry.name!r} is not recoverable: {entry.reason}"
        )
    chunks: list[bytes] = []
    got = 0
    try:
        for chunk in walker.read_deleted(entry, size):
            chunks.append(chunk)
            got += len(chunk)
            if got >= n:
                break
    except Exception as exc:
        raise RawImageFileUnreadableError(
            f"deleted file {entry.name!r}: could not read it: {exc}"
        ) from exc
    return b"".join(chunks)[:n]


def read_raw_region(image: Any, base: int, size: int) -> bytes:
    """Read `size` bytes at byte offset `base` directly from the image.

    Used for a volume whose filesystem qnxprobe recognises but has no
    walker for, or doesn't recognise at all: rather than being unreadable,
    it's still exactly what a hex view of that part of the disk would show.
    """
    image.seek(base)
    data: bytes = image.read(size)
    if len(data) < size:
        raise RawImageTruncatedReadError(
            f"only {len(data):,} of {size:,} bytes are in the image "
            f"(the image ends before this region does)"
        )
    return data


def peek_raw_region(image: Any, base: int, size: int, n: int) -> bytes:
    """Read at most the first `n` bytes of a raw region -- no truncation
    error, unlike read_raw_region(): reading fewer than `n` bytes near the
    very end of the image is an expected, harmless outcome for a magic-byte
    sniff, not a sign anything is actually missing.
    """
    image.seek(base)
    data: bytes = image.read(min(n, size))
    return data
