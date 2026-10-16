# SPDX-License-Identifier: Apache-2.0
"""Raw disk image (.img/.dd/split .001 sets) and EWF (Expert Witness Format,
.E01) acquisition reading, backed by the vendored `crush.third_party.qnxprobe`
(+ `ewfprobe`) readers.

qnxprobe reads MBR/GPT partition tables (512- and 4096-byte sectors), the
logical volumes of an LVM2 volume group, and then NTFS, FAT32, FAT16, FAT12,
exFAT, ext2/3/4, F2FS, HFS+, APFS, QNX6, QNX4, ETFS, EFS, QNX IFS, SquashFS,
JFFS2, UBI/UBIFS and YAFFS1/YAFFS2 directly from a raw image,
a bare partition or a flash dump — no mounting, no admin rights. ewfprobe reads
a container -- an EWF (.E01) or other forensic acquisition, an Apple disk image,
a virtual machine disk -- joining its files and decrypting it when given what
opens it, as an ordinary seekable stream that qnxprobe reads exactly like a raw
image.

`RawImageVFS` (crush/core/vfs.py) is the thin VFS-facing wrapper; this module
holds everything specific to the two vendored readers.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

# qnxprobe reaches its EWF reader with a bare `import ewfprobe`, falling back
# to a sys.path insertion of its own directory when that fails. Registering
# our vendored copy under the bare name first means it resolves correctly
# both from source and in a frozen (PyInstaller) build, where qnxprobe's own
# sys.path fallback cannot find a sibling file — mirrors how iLEAPP/ALEAPP
# wire the same two vendored libraries together.
from crush.core.issues import ParseIssue
from crush.core.load_phase import (
    PHASE_OPEN_IMAGE,
    PHASE_SEARCH_VOLUMES,
    PHASE_UNLOCK_VOLUMES,
    report_phase,
)
from crush.core.stored_times import fat_stored_times
from crush.third_party.ewfprobe import ewfprobe as _ewfprobe

sys.modules.setdefault("ewfprobe", _ewfprobe)
from crush.third_party import qnxprobe  # noqa: E402
from crush.third_party.qnxprobe.qnxprobe import (  # noqa: E402
    ApfsWalker,
    BitLocker,
    ExfatWalker,
    Luks,
    identify_fs,
    unlock_apfs,
    unlock_bitlocker,
    unlock_luks,
)

if TYPE_CHECKING:
    from crush.core.vfs import VFSNode

_MAX_DEPTH = 64  # a directory this deep in a walk is a loop, not a directory

# The first bytes of the containers the image reader opens, taken from the
# reader's own constants so the hint never drifts from what it recognises.
# Only for a hint on a file that can't be handed to the reader by path (a
# member of an archive): a fixed VHD's footer, a UDIF trailer and an AFF4's
# ZIP comment are not in the first bytes, and a file on disk is asked about
# through container_format() instead.
CONTAINER_HEAD_SIGNATURES: tuple[bytes, ...] = (
    qnxprobe.EWF_SIGNATURE,
    qnxprobe.EWF2_SIGNATURE,
    qnxprobe.AFF_SIGNATURE,
    qnxprobe.DMG_ENCRYPTED_SIGNATURE,
    qnxprobe.ADCRYPT_SIGNATURE,
    qnxprobe.SPARSEIMAGE_SIGNATURE,
    qnxprobe.VHDX_SIGNATURE,
    qnxprobe.VHD_COOKIE,          # a dynamic or differencing VHD's copy of its footer
    qnxprobe.VMDK_SPARSE_MAGIC,
    qnxprobe.VMDK_COWD_MAGIC,
    qnxprobe.VMDK_DESCRIPTOR_START,
    qnxprobe.QCOW_MAGIC,
)
# FTK Imager's AD encryption: what it holds (a disk image or an AD1) shows
# only once its password or key opened it.
AD_ENCRYPTED_SIGNATURE: bytes = qnxprobe.ADCRYPT_SIGNATURE
# Logical evidence (EnCase L01/Lx01, FTK Imager AD1): copies of files, not a disk.
LOGICAL_EVIDENCE_SIGNATURES: tuple[bytes, ...] = (
    qnxprobe.L01_SIGNATURE,
    qnxprobe.LX01_SIGNATURE,
    qnxprobe.AD1_SIGNATURE,
)
# The ones that open as a source of their own (LogicalEvidenceVFS): ewfprobe
# reads L01 and AD1, not Lx01.
OPENED_LOGICAL_SIGNATURES: tuple[bytes, ...] = (
    qnxprobe.L01_SIGNATURE,
    qnxprobe.AD1_SIGNATURE,
)

# How a hint names what qnxprobe.acquisition_format() recognised.
_CONTAINER_LABELS = {
    "EWF": "EWF",
    "EWF2": "EWF2",
    "AFF": "AFF",
    "AFD": "AFD",
    "AFF4": "AFF4",
    "UDIF": "Apple disk image",
    "SPARSEIMAGE": "Apple sparse image",
    "SPARSEBUNDLE": "Apple sparse bundle",
    "DMG_ENCRYPTED": "encrypted Apple disk image",
    "AD_ENCRYPTED": "FTK Imager AD-encrypted",
    "VHD": "VHD",
    "VHDX": "VHDX",
    "VMDK": "VMDK",
    "QCOW": "QCOW",
}


class RawImageOpenError(ValueError):
    """The path is not a raw image / EWF acquisition qnxprobe or ewfprobe can read."""


class RawImageTruncatedReadError(OSError):
    """A file's declared size reaches past the end of the image."""


class RawImageFileUnreadableError(OSError):
    """The filesystem reader could not return this file's content."""


@dataclass(frozen=True)
class VolumeSecrets:
    """What the analyst gave to open the encrypted volumes inside a disk image
    (BitLocker, APFS, LUKS): every one is tried on every locked volume, as
    qnxprobe does. Held in memory for as long as the source is open; never
    written anywhere."""

    # Tried as a BitLocker password and recovery password, an APFS password
    # and personal recovery key, and a LUKS passphrase.
    passwords: tuple[str, ...] = ()
    # Paths of BitLocker startup key files (.BEK).
    key_files: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.passwords or self.key_files)

    def merged(self, other: VolumeSecrets) -> VolumeSecrets:
        """These secrets and *other*'s, each once, in the order given."""
        return VolumeSecrets(
            passwords=tuple(dict.fromkeys(self.passwords + other.passwords)),
            key_files=tuple(dict.fromkeys(self.key_files + other.key_files)),
        )


@dataclass
class RawImageHandle:
    """An opened raw image or forensic acquisition, with its volume list."""

    path: Path
    image: Any  # a plain file object, qnxprobe.SegmentedImage, or ewfprobe.EwfImage
    size: int
    volumes: list[dict[str, Any]]
    # The image as stored, before the volumes the secrets opened were
    # decrypted in place: what a region that is encrypted on the disk (a LUKS
    # container) reads from, so its bytes stay the ones the disk holds.
    stored: Any = None
    # The reader's full report on each LVM2 physical volume, by its base:
    # volumes() keeps only its first two lines.
    lvm_reports: dict[int, list[str]] = field(default_factory=dict)
    # ewfprobe's name for the container ("EWF-E01", "EWF-S01", "EWF2-Ex01",
    # "AFF", "AFD", "AFM", and since ewfprobe 0.12 "AFF4", "UDIF",
    # "SPARSEIMAGE", "UDRW" (an encrypted read-write Apple disk image), "RAW"
    # (an AD-encrypted raw set), "VHD", "VHDX", "VMDK", "QCOW"), None for a
    # raw image or split set.
    acquisition: str | None = None
    # The reader's description of the container: the files it is read from
    # (segments, a virtual disk's parents) and what opened it when encrypted.
    # "" for a raw image or split set.
    container: str = ""

    @property
    def missing_pages(self) -> int:
        """Pages of an AFF/AFD the acquisition declares but doesn't hold:
        ewfprobe reads each as the image's bad-sector marker, as AFFLIB does."""
        return int(getattr(self.image, "missing_page_count", 0) or 0)

    def close(self) -> None:
        try:
            self.image.close()
        except Exception:  # pragma: no cover — best-effort cleanup
            pass


def verify_acquisition(
    handle: RawImageHandle, progress: Callable[[int, int], None] | None = None
) -> dict[str, Any]:
    """Recompute an acquisition's hashes and compare them to the ones it
    stored itself (written by the tool that made it).

    Returns ewfprobe's own result dict: `computed`, `stored`, `match` (True,
    False, or None when the acquisition recorded no hash to compare against),
    `bytes`, `checksum_errors`, `missing_page_count`. Only valid for an
    acquisition -- raw images have no built-in hash of their own to verify
    against, which is exactly why this is separate from (and not a
    substitute for) that case.
    """
    if handle.acquisition is None:
        raise ValueError(f"{handle.path.name} is not a forensic acquisition")
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
    # Content not read from the image: b"" for a symbolic link or special
    # file, whose node status says what it is (the walkers don't decode
    # link targets).
    stored: bytes | None = None
    deleted: Any | None = None  # a *DeletedFile record, when this is a recovered entry
    # A region read from the image as stored (RawImageHandle.stored), not
    # through the decryption of the volumes opened inside it.
    as_stored: bool = False


def open_raw_image(
    path: Path, *, password: str = "", private_key: str = "",
    secrets: VolumeSecrets | None = None,
) -> RawImageHandle:
    """Open `path` as a raw disk image, a forensic acquisition (EWF .E01,
    SMART .s01, EWF2 .Ex01, AFF/AFD, AFF4), an Apple disk image (.dmg,
    .sparseimage, or a .sparsebundle folder) or a virtual disk (VHD, VHDX,
    VMDK, QCOW), and list its
    volumes. *password* opens an encrypted container (an encrypted Apple disk
    image, an AD-encrypted set, an encrypted AFF); *private_key* is the path
    of the key file that opens one sealed to a certificate. *secrets* are
    tried on the encrypted volumes inside the disk (BitLocker, APFS, LUKS);
    a volume none of them opens stays listed, with the reader's reason.

    Raises RawImageOpenError when the path isn't actually a readable image:
    a split set with a numbering gap, a bad acquisition header, logical
    evidence (L01/Lx01/AD1, which holds files, not a disk), a file of an Apple
    sparse bundle, or a file in which no partition table or bare filesystem
    could be found at all. An encrypted container opened without what opens
    it raises PasswordRequiredError (PrivateKeyRequiredError when only a
    private key does), and with a password or key that doesn't open it
    WrongPasswordError (WrongPrivateKeyError).
    """
    from crush.core.passwords import (
        PasswordRequiredError,
        PrivateKeyRequiredError,
        WrongPasswordError,
        WrongPrivateKeyError,
    )

    kind = qnxprobe.acquisition_format(str(path))  # type: ignore[no-untyped-call]
    if kind in ("L01", "Lx01", "AD1"):
        # qnxprobe refuses these too, but points to its own command line.
        # open_vfs() opens L01 and AD1 as logical evidence before this.
        maker = "FTK Imager" if kind == "AD1" else "EnCase"
        raise RawImageOpenError(
            f"{path.name}: {maker} logical evidence ({kind}) holds copies of files, "
            "not a disk, so there is no partition table or filesystem to read; "
            + ("Crush doesn't read Lx01" if kind == "Lx01"
               else "it opens as logical evidence instead")
        )
    bundle = sparse_bundle_of(path)
    if bundle is not None:
        # One file of a sparse bundle on its own is a piece of the disk (a
        # band) or the bundle's bookkeeping, not a disk; open_vfs() opens the
        # bundle folder instead.
        raise RawImageOpenError(
            f"{path.name} is part of the Apple sparse bundle {bundle.name} (a folder "
            "whose band files together hold the disk); open the bundle itself"
        )
    report_phase(PHASE_OPEN_IMAGE)
    try:
        image = qnxprobe.open_image(  # type: ignore[no-untyped-call]
            str(path), password=password or None, private_key=private_key or None,
        )
    except qnxprobe.ImagePasswordError as exc:
        by_key = exc.needs == "private key"
        # A password or key was given and doesn't open it (a key for a set
        # that opens only with a password): it was wrong, and the reader's
        # reason says what opens it.
        if exc.wrong or password or private_key:
            wrong = WrongPrivateKeyError if private_key and not password else WrongPasswordError
            raise wrong(ParseIssue(
                "password.image_wrong_key" if wrong is WrongPrivateKeyError
                else "password.image_wrong",
                detail=str(exc),
            )) from exc
        required = PrivateKeyRequiredError if by_key else PasswordRequiredError
        raise required(ParseIssue(
            "password.image_key_required" if by_key else "password.image_required",
            {"path": str(path)}, detail=str(exc),
        )) from exc
    except qnxprobe.SplitImageError as exc:
        raise RawImageOpenError(f"{path.name}: {exc}") from exc
    except Exception as exc:
        if private_key and _asks_for_a_secret(path):
            # The key file itself could not be used (unreadable, not an RSA
            # key): the image asks for one without it, so ask again.
            raise WrongPrivateKeyError(
                ParseIssue("password.image_wrong_key", detail=str(exc))
            ) from exc
        raise RawImageOpenError(
            f"{path.name}: not a readable raw image or acquisition ({exc})"
        ) from exc

    stored = image
    try:
        size = qnxprobe.image_size(image)  # type: ignore[no-untyped-call]
        if secrets:
            # In qnxprobe's own order (its main()): each wraps the image so
            # that what it opened reads decrypted in place, and a LUKS
            # container has to be open before the LVM2 volumes inside it are
            # looked for. Only with secrets: each one looks for its volumes
            # in every region again.
            report_phase(PHASE_UNLOCK_VOLUMES)
            passwords, key_files = list(secrets.passwords), list(secrets.key_files)
            image, _found = unlock_bitlocker(  # type: ignore[no-untyped-call]
                image, size, passwords, key_files,
            )
            image, _found = unlock_apfs(image, size, passwords)  # type: ignore[no-untyped-call]
            image, _found = unlock_luks(image, size, passwords)  # type: ignore[no-untyped-call]
        report_phase(PHASE_SEARCH_VOLUMES)
        # An LVM2 logical volume split into runs, or striped, is read through
        # a map and placed past the image's end; its base reads only through
        # the handle lvm_image() returns (the image itself when there is none),
        # so that handle is the one kept.
        image = qnxprobe.lvm_image(image, size)  # type: ignore[no-untyped-call]
        vols = qnxprobe.volumes(image, size)  # type: ignore[no-untyped-call]
        lvm_reports = {
            vol["base"]: list(
                identify_fs(image, vol["base"], vol["size"])[1]  # type: ignore[no-untyped-call]
            )
            for vol in vols if vol.get("kind") == "lvm2 pv"
        }
    except Exception as exc:
        image.close()
        raise RawImageOpenError(f"{path.name}: could not read volumes ({exc})") from exc

    # qnxprobe.volumes() always reports *something* for a region it scanned,
    # even a "not recognised" entry with no walker for a file that holds no
    # partition table or filesystem it knows at all — so an empty list alone
    # never actually happens for a normal file. What matters is whether any
    # volume has something to browse; if not, a plain hex view of the same
    # bytes is strictly more useful than an empty RawImageVFS tree. Not for an
    # acquisition: its file holds the container (compressed chunks, headers),
    # not the acquired disk, so it stays open and the disk shows as the
    # unrecognised region qnxprobe reports -- readable, and verifiable. Nor
    # when a volume is locked: it opens with a secret given once it is listed.
    if (
        not kind
        and not any(vol.get("walker") is not None for vol in vols)
        and not any(volume_is_locked(vol, image) for vol in vols)
    ):
        image.close()
        # A volume the reader names but cannot read says why in its note (a
        # locked BitLocker volume: what would open it). Passing that on beats
        # saying nothing was recognised, which would not be true.
        reasons = [
            f"{vol.get('name') or 'volume'} is {vol['kind']}: {vol['note']}"
            for vol in vols
            if vol.get("note") and vol.get("kind") not in (None, "", "not recognised")
        ]
        if reasons:
            raise RawImageOpenError(f"{path.name}: no readable filesystem ({'; '.join(reasons)})")
        raise RawImageOpenError(
            f"{path.name}: no partition table or recognized filesystem found"
        )

    vols = vols + _compute_unallocated_gaps(vols, size) + _lvm_free_extent_regions(vols)
    acquisition = getattr(image, "format", None) if kind else None
    # Which files the disk is read from (every segment, a virtual disk's
    # parents) and what opened an encrypted container, in the reader's words:
    # a differencing disk's files come partly from its parent, which the
    # analyst has to know to say where a file is stored.
    container = qnxprobe.describe_acquisition(image) if kind else ""  # type: ignore[no-untyped-call]
    return RawImageHandle(
        path=path, image=image, size=size, volumes=vols, acquisition=acquisition,
        container=container, stored=stored, lvm_reports=lvm_reports,
    )


def _asks_for_a_secret(path: Path) -> bool:
    """True when opening *path* with nothing given is refused for want of a
    password or private key -- whether a failure with a key given lies with
    the key rather than with the image."""
    try:
        qnxprobe.open_image(str(path)).close()  # type: ignore[no-untyped-call]
    except qnxprobe.ImagePasswordError:
        return True
    except Exception:
        return False
    return False


def container_format(path: Path) -> str | None:
    """The container the image reader recognises *path* as, by content
    (qnxprobe.acquisition_format: "EWF", "AFF4", "UDIF", "VHDX", "L01", ...),
    or None for anything else -- which Open Disk Image… reads as raw. Only
    for hints and notes: a file the recognition itself fails on is not
    named, and opening it is never stopped by that."""
    try:
        return qnxprobe.acquisition_format(str(path))  # type: ignore[no-untyped-call,no-any-return]
    except Exception:
        return None


def container_label(kind: str) -> str:
    """A container_format() answer as a hint names it."""
    return _CONTAINER_LABELS.get(kind, kind)


def sparse_bundle_of(path: Path) -> Path | None:
    """The Apple sparse bundle folder *path* is a file of -- its Info.plist,
    token or lock beside it, or a band in its bands/ folder -- recognised by
    the bundle's Info.plist, not by names; None otherwise."""
    for folder in (path.parent, path.parent.parent):
        if folder == path or not folder.is_dir():
            continue
        if sparse_bundle_kind(folder):
            return folder
    return None


def sparse_bundle_kind(folder: Path) -> str | None:
    """"SPARSEBUNDLE" (or "DMG_ENCRYPTED" for an encrypted one) when *folder*
    is an Apple sparse bundle, by its Info.plist; None otherwise."""
    kind = container_format(folder)
    return kind if kind in ("SPARSEBUNDLE", "DMG_ENCRYPTED") else None


# The BitLocker protectors a secret the analyst gives opens (qnxprobe main()).
_BITLOCKER_GIVEN_PROTECTORS = ("password", "recovery password", "startup key")


def volume_is_locked(vol: dict[str, Any], image: Any) -> bool:
    """Whether a volumes() entry is encrypted and was not opened, so a secret
    may open it: a BitLocker volume (an opened one is listed as the
    filesystem inside it), a LUKS container no passphrase opened, or an APFS
    container with a volume whose blocks are ciphertext and whose key was not
    derived. Not a LUKS container inside a logical volume read through a map:
    qnxprobe does not open one there, whatever is given; nor a BitLocker
    volume with no password, recovery password or startup key protector (its
    only protector the device's TPM), as qnxprobe's own report decides when
    to say what to give."""
    kind = vol.get("kind")
    if kind == "bitlocker":
        try:
            volume = BitLocker.open(  # type: ignore[no-untyped-call]
                image, vol.get("base"), vol.get("size"),
            )
        except Exception:
            return False
        return bool(
            volume is not None and not volume.why
            and any(k in _BITLOCKER_GIVEN_PROTECTORS for k, _id in volume.protectors)
        )
    if kind == "luks":
        base = vol.get("base")
        placed = set((getattr(image, "lvm_virtual", None) or {}).values())
        return base not in (getattr(image, "luks", None) or {}) and base not in placed
    walker = vol.get("walker")
    if isinstance(walker, ApfsWalker):
        try:
            return any(
                walker.encryption(i) == "locked"  # type: ignore[no-untyped-call]
                for i in range(len(walker.volumes))
            )
        except Exception:
            return False
    return False


def _lvm_free_extent_regions(vols: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """A volumes()-shaped entry for every run of an LVM2 physical volume's
    extents that no logical volume holds, as qnxprobe reports them
    ("free_extents"): readable on their own, as the gaps between partition
    table entries are, rather than only as part of the physical volume."""
    regions: list[dict[str, Any]] = []
    for vol in vols:
        for base, size in vol.get("free_extents") or ():
            regions.append({
                "name": f"lvm_free_{base}", "base": base, "size": size,
                "kind": "lvm2 free extents",
                "note": f"extents of the LVM2 physical volume {vol.get('name') or vol.get('label')} "
                        "that no logical volume is allocated",
                "walker": None,
            })
    return regions


@dataclass
class VolumeFacts:
    """What the reader reports about one top-level volume beyond its name and
    size, for the Properties panel, and what of it the volume's own status
    has to say because it bears on how far its content can be trusted."""

    properties: dict[str, Any]
    statuses: list[ParseIssue]
    locked: bool = False


def _lvm_layout(lvm_map: Any) -> Any:
    """Every run (or set of stripes) of a logical volume read through a map,
    with its place in the volume and its offset(s) in the image."""
    from crush.core.vfs import join_notes

    parts: list[Any] = []
    for seg in lvm_map.describe():
        start, length = seg["volume_offset"], seg["length"]
        span = {"start": f"{start:,}", "end": f"{start + length - 1:,}"}
        if "stripe_size" in seg:
            parts.append(ParseIssue("entry.raw_lvm_stripes", {
                **span, "stripe": f"{seg['stripe_size']:,}",
                "offsets": ", ".join(f"{o:,}" for o in seg["image_offsets"]),
            }))
        else:
            parts.append(ParseIssue("entry.raw_lvm_run", {
                **span, "offset": f"{seg['image_offsets'][0]:,}",
            }))
    return join_notes(parts)


def _lvm_report_line(label: str, reports: dict[int, list[str]]) -> str:
    """The physical volumes' report line on the logical volume *label*
    ("LVM vg/lv"): "logical volume lv, …: read as LVM vg/lv …"."""
    wanted = re.compile(rf"read as {re.escape(label)}(?: |$)")
    for lines in reports.values():
        for line in lines:
            if line.startswith("logical volume ") and wanted.search(line):
                return line
    return ""


# How the reader's report line names the copy a RAID1 or mirror volume held
# in one run is read from (qnxprobe _lvm_group, _lvm_shape_words).
_LVM_COPY_LINE = re.compile(r"\((?P<kind>\S+), read from its copy (?P<copy>\S+)\)$")


def _luks_key_derivation(image: Any, base: int, size: int | None) -> Any:
    """How each keyslot of the LUKS container at *base* derives its key from a
    passphrase, as its header records it: what opening it costs (an Argon2
    keyslot needs its memory cost in RAM)."""
    from crush.core.vfs import join_notes

    container = next(
        (lk for lk in getattr(image, "luks_found", None) or () if lk.base == base), None,
    ) or Luks.open(image, base, size)  # type: ignore[no-untyped-call]
    if container is None:
        return ""
    parts: list[Any] = []
    for slot in container.keyslots:
        kdf = slot.get("kdf") or {}
        if kdf.get("type") in ("argon2i", "argon2id"):
            parts.append(ParseIssue("entry.raw_luks_argon2", {
                "slot": str(slot.get("id")), "type": str(kdf["type"]),
                "memory": f"{int(kdf.get('memory', 0)) // 1024:,}",
                "time": str(kdf.get("time")), "cpus": str(kdf.get("cpus")),
            }))
        elif kdf.get("type") == "pbkdf2":
            parts.append(ParseIssue("entry.raw_luks_pbkdf2", {
                "slot": str(slot.get("id")), "hash": str(kdf.get("hash")),
                "iterations": f"{int(kdf.get('iterations', 0)):,}",
            }))
    return join_notes(parts)


def volume_facts(vol: dict[str, Any], handle: RawImageHandle) -> VolumeFacts:
    """The reader's facts on a volumes() entry (or one Crush added: a gap, a
    run of free extents), each under its Properties label."""
    props: dict[str, Any] = {}
    statuses: list[ParseIssue] = []
    if vol.get("label"):
        props["Region"] = vol["label"]
    props["Filesystem"] = vol.get("kind") or "unknown"
    base = vol.get("base")
    lvm_map = vol.get("lvm_map")
    if isinstance(base, int) and base < handle.size:
        props["Image offset"] = f"{base:,}"
    if lvm_map is not None:
        props["Layout"] = _lvm_layout(lvm_map)
    label = str(vol.get("label") or "")
    report_line = _lvm_report_line(label, handle.lvm_reports) if label.startswith("LVM ") else ""
    copy_kind = getattr(lvm_map, "copy_kind", None)
    copy_name = getattr(lvm_map, "copy_name", None)
    if copy_name is None and report_line:
        # A copy held in one run has no map: the report line is where the
        # reader says which copy it read.
        match = _LVM_COPY_LINE.search(report_line)
        if match:
            copy_kind, copy_name = match["kind"], match["copy"]
    if copy_name:
        copy_read = ParseIssue("entry.raw_lvm_copy_read", {
            "kind": str(copy_kind), "copy": str(copy_name),
        })
        props["Copy read"] = copy_read
        statuses.append(copy_read)
    if vol.get("encryption"):
        props["Encryption"] = vol["encryption"]
    if vol.get("kind") == "luks" and isinstance(base, int):
        derivation = _luks_key_derivation(handle.image, base, vol.get("size"))
        if derivation:
            props["Key derivation"] = derivation
    if vol.get("kind") == "lvm2 pv" and base in handle.lvm_reports:
        # The whole report: the detail is its first two lines.
        props["LVM report"] = "; ".join(handle.lvm_reports[base])
    else:
        if vol.get("detail"):
            props["Reader detail"] = vol["detail"]
        if report_line:
            props["LVM report"] = report_line
    missing = vol.get("missing_past_end") or 0
    if missing:
        past_end = ParseIssue("entry.raw_volume_past_end", {"bytes": f"{missing:,}"})
        props["Past image end"] = past_end
        statuses.append(past_end)
    return VolumeFacts(props, statuses, volume_is_locked(vol, handle.image))


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
    # A logical volume read through a map is placed past the image's end
    # (qnxprobe.lvm_image): its runs lie inside the physical volumes listed
    # here, so it covers nothing of its own.
    regions = sorted(
        ((vol.get("base") or 0, vol.get("size") or 0) for vol in vols
         if (vol.get("base") or 0) < total_size),
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


def build_volume_node(
    vol: dict[str, Any], read_map: dict[str, _Entry], facts: VolumeFacts | None = None,
    image_size: int | None = None,
) -> "VFSNode":
    """One top-level VFSNode for a qnxprobe volumes() entry.

    A volume with no walker (recognised filesystem qnxprobe can't walk, an
    extended-partition container, or nothing recognised at all) becomes a
    non-browsable leaf carrying its size and the reason, rather than being
    silently dropped -- and it stays fully readable as the raw bytes of that
    region (e.g. via Hex View), since a forensic tool must never make part
    of the source look less accessible than it actually is.
    """
    from crush.core.vfs import VFSNode, join_notes

    name = vol.get("name") or f"lba{vol.get('lba', 0)}"
    size = vol.get("size") or 0
    path = f"/{name}"
    walker = vol.get("walker")
    # What bears on trusting the content (one copy of several read, part
    # of the volume past the image's end) is on the node itself.
    facts_status = list(facts.statuses) if facts else []

    if walker is None:
        base = vol.get("base")
        read_map[path] = _Entry(
            walker=None, node=None, size=size, base=base,
            kind=vol.get("kind", "unknown"), note=vol.get("note", ""),
            # A LUKS container's bytes are the ones on the disk, also once
            # it is open (the opened data is a region of its own).
            as_stored=(
                vol.get("kind") == "luks" and isinstance(base, int)
                and image_size is not None and base < image_size
            ),
        )
        leaf = VFSNode(name=name, path=path, is_dir=False, size=size)
        if facts_status:
            leaf.status = join_notes(facts_status)
        return leaf

    node = VFSNode(name=name, path=path, is_dir=True)
    # A walker that was built but can't read its volume here says why (a
    # zstd SquashFS on a Python without zstd lists nothing); without this
    # the volume would look like an empty filesystem.
    notes: list[Any] = list(facts_status)
    if vol.get("note"):
        notes.insert(0, ParseIssue("entry.raw_volume_note", detail=str(vol["note"])))
    if notes:
        node.status = join_notes(notes)
    _walk_into(walker, walker.root, node, read_map, path, set())
    # The root folder can carry named streams too; they sit beside its
    # entries as ":name", the way the root's own name is empty.
    _add_stream_nodes(walker, walker.root, "", path, node.children, read_map)
    node.children.sort(key=lambda n: (not n.is_dir, n.name.lower()))
    if hasattr(walker, "deleted_files"):
        _add_deleted_files_node(walker, node, read_map, path)
    elif hasattr(walker, "recover_deleted"):
        _add_deleted_files_node(walker, node, read_map, path, walker.recover_deleted)
    return node


def _add_deleted_files_node(
    walker: Any, volume_node: "VFSNode", read_map: dict[str, _Entry], base_path: str,
    enumerate_deleted: Callable[[], Any] | None = None,
) -> None:
    """A flat `$Recovered` child of the volume, one leaf per entry the
    walker's deleted-file enumeration yields: deleted_files() on NTFS/FAT32/
    FAT16/FAT12/exFAT, recover_deleted() on YAFFS2/JFFS2/UBIFS (and UBI, for the UBIFS
    volumes it holds) and QNX EFS -- the filesystems qnxprobe has this for. Not
    reassembled into the deleted files' original folders: that needs
    mapping each entry's `parent` handle back onto a live directory that
    may itself be gone, which is real additional complexity for a placement
    detail, not for whether the data is recoverable and visible at all --
    flat is enough for that. Where the record names the original folder
    (the flash records' `parent_path`), volume_info() shows it.

    Every entry is listed, including ones qnxprobe itself judged not
    recoverable (clusters reused, attributes overflowed, pages erased,
    etc.) -- with an explicit reason available via read(), never silently
    absent, matching every other unsupported/partial case in this module.
    """
    from crush.core.vfs import VFSNode, join_notes

    try:
        entries = list((enumerate_deleted or walker.deleted_files)())
    except Exception as exc:
        # Must not break the live tree -- but must not look like "no deleted
        # files" either.
        volume_node.status = join_notes([
            volume_node.status, ParseIssue("entry.raw_deleted_enum_failed", detail=str(exc)),
        ])
        return
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
        # The flash records carry the file's last mtime (Unix seconds, as
        # stored); NTFS/FAT records keep theirs in other fields.
        mtime = getattr(entry, "mtime", None)
        recovered.children.append(VFSNode(
            name=unique_name, path=child_path, is_dir=False, size=entry.size or 0,
            modified=float(mtime) if isinstance(mtime, (int, float)) else 0.0,
        ))
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

    if depth > _MAX_DEPTH:
        vfs_node.status = ParseIssue("entry.raw_depth", {"limit": _MAX_DEPTH})
        return
    if wnode in seen:
        vfs_node.status = ParseIssue("entry.raw_loop")
        return
    seen.add(wnode)
    try:
        if hasattr(walker, "listdir_records"):
            # FAT/exFAT keep a wall-clock reading with no timezone rather
            # than an instant (entry() gives mtime 0); listdir_records()
            # hands the readings back as text.
            exfat = isinstance(walker, ExfatWalker)
            listing = [
                (name, child, fat_stored_times(recorded or {}, exfat=exfat))
                for name, child, recorded in walker.listdir_records(wnode)
            ]
        else:
            listing = [(name, child, []) for name, child in walker.listdir(wnode)]
    except Exception as exc:
        # Its siblings still can be listed; this one says why it's empty.
        vfs_node.status = ParseIssue("entry.raw_unlisted", detail=str(exc))
        return
    listing.sort(key=lambda item: item[0])

    children: list[VFSNode] = []
    for name, child, times in listing:
        child_path = f"{base_path}/{name}"
        try:
            ent = walker.entry(child)
            problem = None if ent else "no metadata returned"
        except Exception as exc:
            ent, problem = None, str(exc)
        if not ent:
            # Listed by its directory, but its type and size are unknown:
            # keep it visible, with no content, instead of dropping it.
            children.append(VFSNode(
                name=name, path=child_path, is_dir=False,
                status=ParseIssue("entry.raw_entry_unreadable", detail=problem or ""),
                stored_times=times,
            ))
            read_map[child_path] = _Entry(walker=None, node=None, size=0, stored=b"")
            continue
        mode, size, mtime = ent
        if (mode & 0o170000) == qnxprobe.S_IFDIR:  # not just the bit: block devices and sockets share it
            child_node = VFSNode(name=name, path=child_path, is_dir=True, modified=mtime or 0.0,
                                 stored_times=times)
            children.append(child_node)
            _walk_into(walker, child, child_node, read_map, child_path, seen, depth + 1)
            _add_stream_nodes(walker, child, name, base_path, children, read_map)
        elif (mode & 0o170000) == 0o100000:  # regular files only
            child_node = VFSNode(
                name=name, path=child_path, is_dir=False, size=size or 0, modified=mtime or 0.0,
                stored_times=times,
            )
            children.append(child_node)
            read_map[child_path] = _Entry(walker=walker, node=child, size=size or 0)
            _add_stream_nodes(walker, child, name, base_path, children, read_map)
        else:
            # Symbolic links and special files stay visible: the walkers
            # don't decode link targets, and specials hold no content.
            status = (
                ParseIssue("entry.symlink_raw") if (mode & 0o170000) == qnxprobe.S_IFLNK
                else ParseIssue("entry.special_raw", {"mode": f"{mode & 0o170000:o}"})
            )
            child_node = VFSNode(
                name=name, path=child_path, is_dir=False, size=0, modified=mtime or 0.0,
                status=status, stored_times=times,
            )
            children.append(child_node)
            read_map[child_path] = _Entry(walker=None, node=None, size=0, stored=b"")

    children.sort(key=lambda n: (not n.is_dir, n.name.lower()))
    vfs_node.children = children


def _add_stream_nodes(
    walker: Any,
    wnode: Any,
    owner: str,
    base_path: str,
    children: list["VFSNode"],
    read_map: dict[str, _Entry],
) -> None:
    """One `owner:stream` leaf beside a file or folder for every named stream
    the walker reports on it: NTFS alternate data streams, HFS+ resource
    forks, APFS extended attributes kept in a stream of their own. Their
    bytes are not part of the file's own size or content, so without a node
    of their own they would not be seen at all.

    Only NTFS streams are readable (walker.streams() gives each a node that
    read_file() takes). qnxprobe reads an NTFS stream from its first stored
    cluster and does not list a stream that stores nothing; both are said on
    the node. Where the walker names a stream but has no reader for it, the
    node has no content and says so -- its recorded size is in the status,
    never shown as the size of bytes that aren't there.
    """
    from crush.core.vfs import VFSNode

    named_streams = getattr(walker, "named_streams", None)
    if named_streams is None:
        return
    try:
        named = named_streams(wnode) or []
        readable = (
            {sname: (ref, size) for sname, ref, size in walker.streams(wnode)}
            if named and hasattr(walker, "streams") else {}
        )
    except Exception as exc:
        # The file itself is listed; only its streams could not be named.
        children.append(VFSNode(
            name=f"{owner}:?", path=f"{base_path}/{owner}:?", is_dir=False,
            status=ParseIssue("entry.streams_unlisted", detail=str(exc)),
        ))
        read_map[f"{base_path}/{owner}:?"] = _Entry(walker=None, node=None, size=0, stored=b"")
        return
    shown_owner = owner or "/"  # the root folder's own name is empty
    for sname, recorded in named:
        stream_name = f"{owner}:{sname}"
        stream_path = f"{base_path}/{stream_name}"
        if sname in readable:
            ref, size = readable[sname]
            hole = walker.front_hole(ref) if hasattr(walker, "front_hole") else 0
            status = (
                ParseIssue("entry.stream_front_hole", {
                    "owner": shown_owner, "skipped": f"{hole:,}", "recorded": f"{recorded:,}",
                }) if hole else ParseIssue("entry.stream", {"owner": shown_owner})
            )
            children.append(VFSNode(
                name=stream_name, path=stream_path, is_dir=False, size=size or 0, status=status,
            ))
            read_map[stream_path] = _Entry(walker=walker, node=ref, size=size or 0)
            continue
        status = (
            ParseIssue("entry.stream_nothing_stored", {"owner": shown_owner, "recorded": f"{recorded:,}"})
            if hasattr(walker, "streams")
            else ParseIssue("entry.stream_no_reader", {"owner": shown_owner, "recorded": f"{recorded:,}"})
        )
        children.append(VFSNode(name=stream_name, path=stream_path, is_dir=False, status=status))
        read_map[stream_path] = _Entry(walker=None, node=None, size=0, stored=b"")


def _check_cluster_chain(walker: Any, node: Any, size: int, got: int) -> None:
    """Raise when a FAT or exFAT file read short because its cluster chain
    ends before its recorded size.

    The directory entry records the size and the allocation table records the
    clusters, and a volume can hold the two in disagreement. The reader then
    returns only what the chain reaches, with nothing lost past the end of the
    image, so the short copy would otherwise pass for the whole file.
    """
    if got >= size:
        return
    cut = qnxprobe.chain_shortfall(walker, node)  # type: ignore[no-untyped-call]
    if cut:
        raise RawImageFileUnreadableError(
            f"only {got:,} of {size:,} bytes can be read: the volume's cluster chain "
            f"for this file ends after {cut[0]:,} of the {cut[1]:,} clusters its size needs"
        )


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
    _check_cluster_chain(walker, node, size, got)
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


def stream_walker_file(walker: Any, node: Any, size: int) -> Iterator[bytes]:
    """Yield one file's bytes chunk by chunk, with read_walker_file()'s
    failure semantics but without materializing the whole file.

    The short-image check runs when the generator is exhausted, so a file cut
    off by the end of the image raises RawImageTruncatedReadError from the
    read that would have returned its last bytes, instead of ending silently.
    """
    shortfall_before = qnxprobe.EOF_SHORTFALL["bytes"]
    got = 0
    try:
        for chunk in walker.read_file(node, size):
            got += len(chunk)
            yield chunk
    except Exception as exc:
        raise RawImageFileUnreadableError(f"could not read file: {exc}") from exc
    cut_by = qnxprobe.EOF_SHORTFALL["bytes"] - shortfall_before
    if cut_by:
        present = max(min(got, size - cut_by), 0)
        raise RawImageTruncatedReadError(
            f"only {present:,} of {size:,} bytes are in the image "
            f"(the image ends before the file does)"
        )
    _check_cluster_chain(walker, node, size, got)


def stream_deleted_file(walker: Any, entry: Any, size: int) -> Iterator[bytes]:
    """Chunked counterpart of read_deleted_file(); same errors, raised lazily."""
    if not entry.recoverable:
        raise RawImageFileUnreadableError(
            f"deleted file {entry.name!r} is not recoverable: {entry.reason}"
        )
    shortfall_before = qnxprobe.EOF_SHORTFALL["bytes"]
    got = 0
    try:
        for chunk in walker.read_deleted(entry, size):
            got += len(chunk)
            yield chunk
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


def stream_raw_region(
    image: Any, base: int, size: int, chunk_size: int = 1024 * 1024
) -> Iterator[bytes]:
    """Chunked counterpart of read_raw_region()."""
    done = 0
    while done < size:
        image.seek(base + done)
        data: bytes = image.read(min(chunk_size, size - done))
        if not data:
            raise RawImageTruncatedReadError(
                f"only {done:,} of {size:,} bytes are in the image "
                f"(the image ends before this region does)"
            )
        done += len(data)
        yield data


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
    stays cheap there; FAT's and exFAT's read_deleted() builds the whole
    file in memory before its one yield regardless, so this saves nothing
    for those (nor for the flash filesystems, whose read_deleted() rebuilds
    the file from its pages or nodes first) -- but a deleted-files listing is normally far smaller than
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
