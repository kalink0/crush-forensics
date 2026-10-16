#!/usr/bin/env python3
#
# SPDX-License-Identifier: Apache-2.0
"""RawImageVFS on the logical volumes of an LVM2 volume group, and on a LUKS
container.

The images are abrignoni/qnxprobe's own MIT-licensed test fixtures
(tests/fixtures at the vendored commit), renamed with a `raw_` prefix.
`raw_lvm` is lvm-fixture: lvm2 wrote a volume group on two GPT partitions
with logical volumes that are one run of extents, split into two runs,
striped across both physical volumes, and RAID1, each holding an ext4
filesystem. `raw_lvm.sha256` lists every file hashed from the mounted
logical volumes, as `<logical volume>/<path>`. `raw_luks1` is luks1-cbc, a
LUKS1 container cryptsetup wrote; its passphrase and the hashes of the files
in it are the fixture's own (luks-fixtures.json, luks-fixture.sha256).
"""
from __future__ import annotations

import gzip
import hashlib
from pathlib import Path

import pytest

from crush.core.issues import render_value
from crush.core.load_phase import (
    PHASE_OPEN_IMAGE,
    PHASE_READ_FILESYSTEMS,
    PHASE_SEARCH_VOLUMES,
    PHASE_UNLOCK_VOLUMES,
    phase_reporter,
)
from crush.core.raw_image import VolumeSecrets
from crush.core.vfs import RawImageVFS, VFSNode, find_node
from crush.tests.conftest import FIXTURES_DIR

_LUKS_PASSPHRASE = "correct horse battery staple"
_LUKS_FILES = {
    "docs/sectors.bin": "2696852dbc2c025ae522c54747890adc141c69ae7817acff1e3458c4a2e2fbcf",
    "readme.txt": "64a063cbb20c417e93112f68d569f18cff0b0068d4217bf425e0bc7419efa9f4",
}


def _open(
    tmp_path: Path, stem: str, *passwords: str,
) -> tuple[RawImageVFS, Path]:
    img = tmp_path / f"{stem}.img"
    if not img.exists():
        img.write_bytes(gzip.decompress((FIXTURES_DIR / f"{stem}.img.gz").read_bytes()))
    return RawImageVFS(img, secrets=VolumeSecrets(passwords=passwords)), img


def _child(vfs: RawImageVFS, name_start: str) -> VFSNode:
    return next(c for c in vfs.root().children if c.name.startswith(name_start))


def _files(node: VFSNode) -> list[VFSNode]:
    out: list[VFSNode] = []
    for child in node.children:
        if child.is_dir:
            out.extend(_files(child))
        else:
            out.append(child)
    return out


@pytest.mark.forensic(
    category="Known-output Verification",
    subject="Raw disk image",
    desc="Every file on the logical volumes of an LVM2 volume group (one run, split into "
    "runs, striped, RAID1) reads back with the bytes hashed from the mounted volumes",
)
def test_every_file_lvm_wrote_reads_back_under_its_logical_volume(tmp_path: Path) -> None:
    """Each logical volume, whether it is one run, split into runs, striped or
    RAID1, is a folder of its own, and every file in it has the bytes hashed
    from the mounted volume."""
    want: dict[str, str] = {}
    for line in (FIXTURES_DIR / "raw_lvm.sha256").read_text(encoding="utf-8").splitlines():
        digest, _, relpath = line.partition("  ")
        want[relpath] = digest
    vfs, _img = _open(tmp_path, "raw_lvm")
    try:
        folder = {
            str(v["label"]).removeprefix("LVM fixvg/"): f"/{v['name']}"
            for v in vfs._handle.volumes
            if str(v.get("label", "")).startswith("LVM fixvg/")
        }
        got: dict[str, str] = {}
        for node in vfs.root().children:
            lv = next((k for k, p in folder.items() if p == node.path), None)
            if lv is None or not node.is_dir:
                continue
            prefix = node.path.rstrip("/") + "/"
            for f in _files(node):
                got[f"{lv}/{f.path.removeprefix(prefix)}"] = hashlib.sha256(vfs.read(f)).hexdigest()
        assert len(want) == 10
        assert {path: got.get(path) for path in want} == want
        assert {"data", "striped", "mirror"} <= {p.split("/")[0] for p in want}
    finally:
        vfs.close()


@pytest.mark.forensic(
    category="Known-output Verification",
    subject="Raw disk image",
    desc="The space no partition covers is listed up to the image's end and reads as the "
    "image holds it; an LVM2 volume read through a map adds no gap of its own",
)
def test_a_volume_read_through_a_map_leaves_no_gap_past_the_image(tmp_path: Path) -> None:
    """A logical volume split into runs or striped is placed past the image's
    end. The space no region covers is still listed, and ends at the image's
    end: the placed volume adds no gap of its own."""
    vfs, img = _open(tmp_path, "raw_lvm")
    try:
        size = img.stat().st_size
        gaps = [v for v in vfs._handle.volumes if v["kind"] == "unallocated"]
        assert gaps
        assert max(v["base"] + v["size"] for v in gaps) == size
        for v in gaps:
            node = next(c for c in vfs.root().children if c.name == v["name"])
            assert len(vfs.read(node)) == v["size"]
        mapped = [v for v in vfs._handle.volumes if v.get("lba") is None and v["kind"] == "ext4"]
        assert sorted(str(v["label"]) for v in mapped) == ["LVM fixvg/data", "LVM fixvg/striped"]
    finally:
        vfs.close()


@pytest.mark.forensic(
    category="Known-output Verification",
    subject="Raw disk image",
    desc="An LVM2 RAID1 volume says which copy it is read from and that the copies are not "
    "compared; a split or striped volume lists every run with its offset in the image",
)
def test_what_the_reader_reports_on_each_volume_is_shown(tmp_path: Path) -> None:
    """A logical volume read from one copy of a RAID1 volume says so on the
    volume itself, and that the other copies are not compared; a volume read
    through a map lists every run and its stripes with their image offsets;
    a physical volume carries the reader's whole report, not its first two
    lines."""
    vfs, _img = _open(tmp_path, "raw_lvm")
    try:
        mirror = _child(vfs, "lvm_lba47104_fixvg_mirror")
        assert mirror.is_dir
        status = render_value(mirror.status)
        assert "read from its copy mirror_rimage_0 only" in status
        assert "not checked" in status
        assert render_value(vfs.node_info(mirror)["Copy read"]) == status  # type: ignore[index]

        data = vfs.node_info(_child(vfs, "lvm_lba16384_fixvg_data")) or {}
        assert "Image offset" not in data  # placed past the image: no single place in it
        assert render_value(data["Layout"]) == (
            "volume bytes 0–3,145,727 at image offset 8,388,608; "
            "volume bytes 3,145,728–6,291,455 at image offset 13,631,488"
        )
        striped = vfs.node_info(_child(vfs, "lvm_lba32768_fixvg_striped")) or {}
        assert render_value(striped["Layout"]) == (
            "volume bytes 0–4,194,303 striped in 65,536-byte stripes across image "
            "offsets 16,777,216, 31,457,280"
        )

        pv = vfs.node_info(_child(vfs, "p1_lba2048_lvm_a")) or {}
        report = str(pv["LVM report"])
        assert "logical volume mirror, 2.0 MiB: read as LVM fixvg/mirror" in report
        assert "10 extent(s) of pv1" in report
        root = vfs.node_info(_child(vfs, "lvm_lba4096_fixvg_root")) or {}
        assert root["Filesystem"] == "ext4"
        assert root["Image offset"] == "2,097,152"
        assert "rootfix" in str(root["Reader detail"])
    finally:
        vfs.close()


@pytest.mark.forensic(
    category="Known-output Verification",
    subject="Raw disk image",
    desc="The extents of an LVM2 physical volume no logical volume holds are listed and "
    "read as the image holds them",
)
def test_lvm_free_extents_are_a_readable_region_of_their_own(tmp_path: Path) -> None:
    """The extents of a physical volume that no logical volume holds are
    listed beside the gaps between partitions, readable as the image holds
    them, and named as what they are."""
    vfs, img = _open(tmp_path, "raw_lvm")
    try:
        node = _child(vfs, "lvm_free_")
        assert node.name == "lvm_free_36700160" and node.size == 10 * 1024 * 1024
        info = vfs.volume_info(node) or {}
        assert info["kind"] == "lvm2 free extents"
        assert "no logical volume is allocated" in str(info["note"])
        with img.open("rb") as raw:
            raw.seek(36700160)
            assert vfs.read(node) == raw.read(node.size)
    finally:
        vfs.close()


@pytest.mark.forensic(
    category="Known-output Verification",
    subject="Raw disk image",
    desc="A LUKS container without its passphrase is listed as locked, with the reader's "
    "reason, and reads as the bytes on the disk",
)
def test_a_luks_container_stays_listed_until_its_passphrase_is_given(tmp_path: Path) -> None:
    """Without a passphrase the container is listed as locked (so it can be
    unlocked), with the reader's reason and its keyslot's key derivation,
    and reads as the bytes on the disk."""
    vfs, img = _open(tmp_path, "raw_luks1")
    try:
        container = _child(vfs, "lba0")
        assert vfs.is_locked_volume(container)
        assert "LUKS-encrypted and not read" in str((vfs.volume_info(container) or {})["note"])
        info = vfs.node_info(container) or {}
        assert info["Encryption"] == "LUKS1, locked"
        assert render_value(info["Key derivation"]) == "keyslot 0: PBKDF2-sha1, 1,000 iterations"
        assert vfs.read(container) == img.read_bytes()
    finally:
        vfs.close()


@pytest.mark.forensic(
    category="Known-output Verification",
    subject="Raw disk image",
    desc="A LUKS1 container opened with its passphrase lists files with the bytes its "
    "volume held, and the container still reads as the encrypted bytes on the disk",
)
def test_a_luks_container_opens_with_its_passphrase(tmp_path: Path) -> None:
    """With its passphrase among wrong ones, the container's data is a volume
    of its own whose files have the bytes cryptsetup's volume held, the
    container says what opened it, and the container itself still reads as
    the encrypted bytes on the disk, not as the decrypted data."""
    vfs, img = _open(tmp_path, "raw_luks1", "not it", _LUKS_PASSPHRASE)
    try:
        container = _child(vfs, "lba0")
        assert not vfs.is_locked_volume(container)
        assert (vfs.node_info(container) or {})["Encryption"] == (
            "LUKS1 aes-cbc-essiv:sha256, opened with keyslot 0"
        )
        assert vfs.read(container) == img.read_bytes()
        data = _child(vfs, "luks_")
        assert data.is_dir
        got = {
            path: hashlib.sha256(vfs.read(find_node(vfs, f"{data.path}/{path}"))).hexdigest()  # type: ignore[arg-type]
            for path in _LUKS_FILES
        }
        assert got == _LUKS_FILES
    finally:
        vfs.close()


def test_a_wrong_passphrase_leaves_it_locked_and_says_so(tmp_path: Path) -> None:
    vfs, _img = _open(tmp_path, "raw_luks1", "not it")
    try:
        container = _child(vfs, "lba0")
        assert vfs.is_locked_volume(container)
        assert "no passphrase given opens a keyslot" in str(
            (vfs.volume_info(container) or {})["note"]
        )
        assert not any(c.name.startswith("luks_") for c in vfs.root().children)
    finally:
        vfs.close()


def test_secrets_given_later_are_tried_with_the_earlier_ones(tmp_path: Path) -> None:
    """Unlocking reads the image again with every secret given so far."""
    first, _img = _open(tmp_path, "raw_luks1", "not it")
    try:
        second = first.with_volume_secrets(VolumeSecrets(passwords=(_LUKS_PASSPHRASE,)))
    finally:
        first.close()
    try:
        assert second.volume_secrets.passwords == ("not it", _LUKS_PASSPHRASE)
        assert not second.is_locked_volume(_child(second, "lba0"))
        assert _child(second, "luks_").is_dir
    finally:
        second.close()


def test_opening_a_disk_image_reports_its_phases(tmp_path: Path) -> None:
    """The wait dialog is told each step: the volume search on its own, and
    the unlock only when secrets were given."""
    seen: list[str] = []
    with phase_reporter(seen.append):
        _open(tmp_path, "raw_luks1")[0].close()
        plain = list(seen)
        seen.clear()
        _open(tmp_path, "raw_luks1", _LUKS_PASSPHRASE)[0].close()
    assert plain == [PHASE_OPEN_IMAGE, PHASE_SEARCH_VOLUMES, PHASE_READ_FILESYSTEMS]
    assert seen == [
        PHASE_OPEN_IMAGE, PHASE_UNLOCK_VOLUMES, PHASE_SEARCH_VOLUMES, PHASE_READ_FILESYSTEMS,
    ]
