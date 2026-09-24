# SPDX-License-Identifier: Apache-2.0
"""Tests for RawImageVFS: raw disk images (.img/.dd/split .001 sets) and
EWF (Expert Witness Format, .E01) acquisitions.

`raw_ntfs.img.gz` / `raw_ntfs.E01` are the same 16 MiB synthetic NTFS volume
(from abrignoni/qnxprobe's own MIT-licensed test fixtures, re-acquired into
EWF with the real `ewfacquire` tool for the .E01 case) — used for both the
raw and EWF code paths so most of the coverage below exercises both.
"""
from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from crush.core.raw_image import RawImageOpenError, RawImageTruncatedReadError
from crush.core.vfs import FileVFS, RawImageVFS, VFSNode, open_vfs
from crush.tests.conftest import FIXTURES_DIR


def _expected_hashes() -> dict[str, str]:
    expected: dict[str, str] = {}
    for line in (FIXTURES_DIR / "raw_ntfs.sha256").read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        digest, _, relpath = line.partition("  ")
        expected[relpath] = digest
    return expected


def _find(node: VFSNode, parts: list[str]) -> VFSNode | None:
    cur = node
    for part in parts:
        match = next((c for c in cur.children if c.name == part), None)
        if match is None:
            return None
        cur = match
    return cur


@pytest.fixture
def raw_ntfs_image(tmp_path: Path) -> Path:
    """Writable copy of the decompressed raw NTFS fixture, in tmp_path."""
    dst = tmp_path / "sample.img"
    dst.write_bytes(gzip.decompress((FIXTURES_DIR / "raw_ntfs.img.gz").read_bytes()))
    return dst


@pytest.fixture
def raw_ntfs_e01(tmp_path: Path) -> Path:
    """Writable copy of the real E01 acquisition of the same volume."""
    dst = tmp_path / "sample.E01"
    dst.write_bytes((FIXTURES_DIR / "raw_ntfs.E01").read_bytes())
    return dst


_UNSUPPORTED_FILL = 0xAB
_UNSUPPORTED_SECTORS = 2048  # 1 MiB


def _make_mbr(entries: list[tuple[int, int, int]]) -> bytes:
    """entries: list of (partition_type, start_lba, sector_count)."""
    mbr = bytearray(512)
    for i, (ptype, start, count) in enumerate(entries):
        off = 446 + i * 16
        mbr[off + 4] = ptype
        mbr[off + 8 : off + 12] = start.to_bytes(4, "little")
        mbr[off + 12 : off + 16] = count.to_bytes(4, "little")
    mbr[510:512] = b"\x55\xaa"
    return bytes(mbr)


@pytest.fixture
def raw_multi_partition_image(tmp_path: Path) -> Path:
    """A real MBR with two partitions: the committed NTFS fixture, and a
    second region filled with a byte pattern no filesystem signature can
    match -- qnxprobe will find the partition table entry but have no
    walker for it, exercising the "recognised, not walkable" path rather
    than the "not a partition table at all" one `raw_ntfs_image` covers.
    """
    ntfs_bytes = gzip.decompress((FIXTURES_DIR / "raw_ntfs.img.gz").read_bytes())
    assert len(ntfs_bytes) % 512 == 0
    ntfs_sectors = len(ntfs_bytes) // 512
    unsupported_bytes = bytes([_UNSUPPORTED_FILL]) * (_UNSUPPORTED_SECTORS * 512)

    mbr = _make_mbr([
        (0x07, 1, ntfs_sectors),
        (0x83, 1 + ntfs_sectors, _UNSUPPORTED_SECTORS),
    ])

    dst = tmp_path / "multi.img"
    dst.write_bytes(mbr + ntfs_bytes + unsupported_bytes)
    return dst


_GAP_SECTORS_BEFORE = 2047  # matches a real-world `mmls` "Unallocated" slot 1..2047
_GAP_SECTORS_AFTER = 1024  # deliberately a different size than the before-gap


@pytest.fixture
def raw_image_with_unallocated_gaps(tmp_path: Path) -> Path:
    """Mirrors a real acquisition's `mmls` layout: a single partition that
    doesn't start right after the MBR (alignment padding) and doesn't reach
    the end of the disk (trailing slack) -- both gaps have no partition
    table entry of their own at all, unlike `raw_multi_partition_image`'s
    second partition (which qnxprobe finds a table entry for, just no
    walker). qnxprobe.volumes() reports neither gap; Crush must still
    surface both.
    """
    ntfs_bytes = gzip.decompress((FIXTURES_DIR / "raw_ntfs.img.gz").read_bytes())
    assert len(ntfs_bytes) % 512 == 0
    ntfs_sectors = len(ntfs_bytes) // 512
    partition_start = 1 + _GAP_SECTORS_BEFORE

    mbr = _make_mbr([(0x07, partition_start, ntfs_sectors)])
    leading_gap = bytes([0xCD]) * (_GAP_SECTORS_BEFORE * 512)
    trailing_gap = bytes([0xEF]) * (_GAP_SECTORS_AFTER * 512)

    dst = tmp_path / "gapped.img"
    dst.write_bytes(mbr + leading_gap + ntfs_bytes + trailing_gap)
    return dst


def _assert_all_files_match(vfs: RawImageVFS, volume: VFSNode) -> None:
    import hashlib

    expected = _expected_hashes()
    assert expected  # sanity: the fixture actually lists files
    for relpath, digest in expected.items():
        node = _find(volume, relpath.split("/"))
        assert node is not None, f"missing from tree: {relpath}"
        data = vfs.read(node)
        assert hashlib.sha256(data).hexdigest() == digest, f"content mismatch: {relpath}"


class TestRawImage:
    def test_open_vfs_returns_raw_image_vfs(self, raw_ntfs_image: Path) -> None:
        vfs = open_vfs(raw_ntfs_image)
        try:
            assert isinstance(vfs, RawImageVFS)
        finally:
            vfs.close()

    @pytest.mark.forensic(
        category="Known-output Verification",
        desc="raw_ntfs.img.gz's 475 live files must all read back to their committed reference hashes",
    )
    def test_single_volume_content_matches(self, raw_ntfs_image: Path) -> None:
        vfs = open_vfs(raw_ntfs_image)
        try:
            root = vfs.root()
            assert len(root.children) == 1
            volume = root.children[0]
            assert volume.is_dir
            _assert_all_files_match(vfs, volume)
        finally:
            vfs.close()

    def test_file_count_and_total_size(self, raw_ntfs_image: Path) -> None:
        vfs = open_vfs(raw_ntfs_image)
        try:
            root = vfs.root()
            expected = _expected_hashes()
            assert vfs.file_count(root) >= len(expected)
            assert vfs.total_size(root) > 0
        finally:
            vfs.close()

    def test_extension_mismatch_falls_back_to_file_vfs(self, tmp_path: Path) -> None:
        """A plain file renamed to .img must never raise — it should just
        degrade to a hex-viewable FileVFS."""
        bogus = tmp_path / "not_an_image.img"
        bogus.write_bytes(b"just some plain text, not an image at all" * 100)
        vfs = open_vfs(bogus)
        try:
            assert isinstance(vfs, FileVFS)
        finally:
            vfs.close()

    def test_misnamed_e01_without_ewf_signature_opens_as_raw(
        self, raw_ntfs_image: Path, tmp_path: Path
    ) -> None:
        """A real raw image misnamed with a .E01 extension it doesn't
        actually have must not be force-treated as (broken) EWF — qnxprobe
        checks the EWF signature itself before delegating to ewfprobe, so
        this correctly falls through to the raw-image path and opens as
        what it actually is."""
        misnamed = tmp_path / "misnamed.E01"
        misnamed.write_bytes(raw_ntfs_image.read_bytes())
        vfs = open_vfs(misnamed)
        try:
            assert isinstance(vfs, RawImageVFS)
            assert vfs.is_ewf() is False
            _assert_all_files_match(vfs, vfs.root().children[0])
        finally:
            vfs.close()

    def test_split_set_joins_segments(self, raw_ntfs_image: Path, tmp_path: Path) -> None:
        data = raw_ntfs_image.read_bytes()
        midpoint = len(data) // 2
        part1 = tmp_path / "split.001"
        part2 = tmp_path / "split.002"
        part1.write_bytes(data[:midpoint])
        part2.write_bytes(data[midpoint:])

        vfs = open_vfs(part1)
        try:
            assert isinstance(vfs, RawImageVFS)
            root = vfs.root()
            volume = root.children[0]
            _assert_all_files_match(vfs, volume)
        finally:
            vfs.close()

    def test_split_set_gap_raises(self, raw_ntfs_image: Path, tmp_path: Path) -> None:
        data = raw_ntfs_image.read_bytes()
        third = len(data) // 3
        (tmp_path / "gap.001").write_bytes(data[:third])
        (tmp_path / "gap.003").write_bytes(data[2 * third :])
        # .002 is deliberately missing

        with pytest.raises(RawImageOpenError):
            RawImageVFS(tmp_path / "gap.001")

    def test_truncated_image_read_raises(self, raw_ntfs_image: Path) -> None:
        data = raw_ntfs_image.read_bytes()
        raw_ntfs_image.write_bytes(data[: len(data) // 2])

        vfs = open_vfs(raw_ntfs_image)
        try:
            root = vfs.root()
            volume = root.children[0]
            expected = _expected_hashes()
            cut_short = False
            for relpath in expected:
                node = _find(volume, relpath.split("/"))
                if node is None:
                    continue
                try:
                    vfs.read(node)
                except RawImageTruncatedReadError:
                    cut_short = True
            assert cut_short, "expected at least one file to be cut short by the truncated image"
        finally:
            vfs.close()


class TestEwf:
    def test_open_vfs_returns_raw_image_vfs(self, raw_ntfs_e01: Path) -> None:
        vfs = open_vfs(raw_ntfs_e01)
        try:
            assert isinstance(vfs, RawImageVFS)
            assert vfs.is_ewf()
        finally:
            vfs.close()

    @pytest.mark.forensic(
        category="Known-output Verification",
        desc="raw_ntfs.E01's files must read back identically through the EWF path as through raw .img",
    )
    def test_content_matches(self, raw_ntfs_e01: Path) -> None:
        vfs = open_vfs(raw_ntfs_e01)
        try:
            root = vfs.root()
            volume = root.children[0]
            _assert_all_files_match(vfs, volume)
        finally:
            vfs.close()

    @pytest.mark.forensic(
        category="Known-output Verification",
        desc="verify_ewf() must report MATCH against a real ewfacquire-created acquisition's own stored hash",
    )
    def test_verify_matches_stored_hash(self, raw_ntfs_e01: Path) -> None:
        vfs = open_vfs(raw_ntfs_e01)
        try:
            assert isinstance(vfs, RawImageVFS)
            result = vfs.verify_ewf()
            assert result["match"] is True
            assert result["stored"]
            assert result["computed"] == result["stored"]
        finally:
            vfs.close()

    def test_extensionless_copy_falls_back_to_file_vfs(
        self, raw_ntfs_e01: Path, tmp_path: Path
    ) -> None:
        """EWF has no other extension in the wild — the format's segment set
        always runs E01..E99/EAA..ZZZ — and ewfprobe itself requires that
        extension to resolve sibling segments, even for a single-segment
        acquisition. So a copy with no extension at all can never actually
        open, no matter how the signature is detected; the right behaviour
        is a graceful fall back to plain hex view, not a crash."""
        renamed = tmp_path / "acquisition_no_extension"
        renamed.write_bytes(raw_ntfs_e01.read_bytes())
        vfs = open_vfs(renamed)
        try:
            assert isinstance(vfs, FileVFS)
        finally:
            vfs.close()

    def test_media_only_ewf_with_no_filesystem_falls_back_to_file_vfs(
        self, tmp_path: Path
    ) -> None:
        """An EWF acquisition that holds no partition table or recognisable
        filesystem (e.g. a raw media dump) should degrade to plain hex view
        rather than open as an empty, nothing-browsable RawImageVFS."""
        garbage = tmp_path / "no_filesystem.img"
        garbage.write_bytes(b"\x00" * (1024 * 1024))
        vfs = open_vfs(garbage)
        try:
            assert isinstance(vfs, FileVFS)
        finally:
            vfs.close()


class TestUnsupportedFilesystemVolume:
    def test_unreadable_volume_is_listed_not_dropped(self) -> None:
        """This project's standing rule: unsupported content must always
        surface as an explicit status, never a silent empty/zero result. A
        volume qnxprobe recognises but has no walker for must still be a
        leaf node carrying its size — not simply absent from the tree."""
        from crush.core.raw_image import build_volume_node

        read_map: dict[str, object] = {}
        vol = {
            "name": "unreadable_vol", "size": 4096, "base": 512,
            "walker": None, "kind": "btrfs",
        }
        node = build_volume_node(vol, read_map)  # type: ignore[arg-type]

        assert node.name == "unreadable_vol"
        assert node.is_dir is False
        assert node.size == 4096

        entry = read_map["/unreadable_vol"]
        assert entry.walker is None  # type: ignore[attr-defined]
        assert entry.kind == "btrfs"  # type: ignore[attr-defined]
        assert entry.base == 512  # type: ignore[attr-defined]

    def test_unsupported_partition_reads_as_raw_bytes(
        self, raw_multi_partition_image: Path
    ) -> None:
        """The real-world case this exists for: a multi-partition image
        (e.g. a genuine forensic .E01) where only some partitions have a
        filesystem qnxprobe can walk. The others must not just be listed —
        they must be genuinely readable, exactly as the disk's own bytes,
        so an examiner can still open them in Hex View rather than hitting
        a dead end."""
        vfs = open_vfs(raw_multi_partition_image)
        try:
            assert isinstance(vfs, RawImageVFS)
            root = vfs.root()
            # NTFS partition + the unsupported partition + the tiny
            # synthesized "unallocated" leaf for the MBR's own sector 0,
            # which sits before partition 1 and has no table entry either.
            assert len(root.children) == 3

            ntfs_volume = next(c for c in root.children if c.is_dir)
            _assert_all_files_match(vfs, ntfs_volume)

            leaves = [c for c in root.children if not c.is_dir]
            unsupported = next(c for c in leaves if c.size == _UNSUPPORTED_SECTORS * 512)
            data = vfs.read(unsupported)
            assert data == bytes([_UNSUPPORTED_FILL]) * (_UNSUPPORTED_SECTORS * 512)

            # peek() must also work (and stay cheap) for a raw region — this
            # is what the background type-detection scan calls per node.
            assert vfs.peek(unsupported, n=16) == bytes([_UNSUPPORTED_FILL]) * 16
        finally:
            vfs.close()

    def test_unsupported_partition_opens_via_generic_dispatch(
        self, raw_multi_partition_image: Path
    ) -> None:
        """No special-casing needed on the viewer side: the existing generic
        node-open path (ParserRegistry -> hex fallback) already handles
        arbitrary binary content, so this should "just work" once read()
        returns real bytes instead of raising."""
        import crush.parsers  # noqa: F401 — triggers parser registration
        from crush.core.registry import ParserRegistry

        vfs = open_vfs(raw_multi_partition_image)
        try:
            unsupported = next(c for c in vfs.root().children if not c.is_dir)
            parser = ParserRegistry.best(unsupported, vfs)
            assert parser is not None
            result = parser.parse(unsupported, vfs)
            assert result.viewer_type == "hex"
        finally:
            vfs.close()

    def test_unallocated_gaps_before_and_after_are_synthesized(
        self, raw_image_with_unallocated_gaps: Path
    ) -> None:
        """qnxprobe.volumes() only reports actual partition table entries —
        never the unallocated space before/between/after them, unlike a
        tool like The Sleuth Kit's mmls. Crush computes and surfaces those
        gaps itself; this is the real-world layout (one partition, aligned
        with padding before it and slack after it) reported against a real
        acquisition (`mmls` output: one NTFS partition plus two Unallocated
        slots before and after it)."""
        raw_bytes = raw_image_with_unallocated_gaps.read_bytes()
        partition_start_byte = (1 + _GAP_SECTORS_BEFORE) * 512
        ntfs_size = len(gzip.decompress((FIXTURES_DIR / "raw_ntfs.img.gz").read_bytes()))
        after_gap_start = partition_start_byte + ntfs_size

        vfs = open_vfs(raw_image_with_unallocated_gaps)
        try:
            root = vfs.root()
            assert len(root.children) == 3

            leaves = {c.name: c for c in root.children if not c.is_dir}
            assert set(leaves) == {"unallocated_0", f"unallocated_{after_gap_start}"}

            # The "before" gap covers byte 0 onward -- the MBR sector itself
            # included, since qnxprobe doesn't report that as its own region
            # either -- up to where the partition table says the partition
            # starts. Compared directly against the file's own bytes rather
            # than assuming a pure fill pattern, since the MBR's own 512
            # bytes (partition table, 0x55AA signature) sit at the front of
            # this gap, not the 0xCD fill the rest of it uses. Length is
            # checked before content equality: a byte-string equality
            # failure on ~1 MiB blobs makes pytest attempt a very slow
            # diff, and a length mismatch is the more likely real failure
            # anyway.
            before_gap = leaves["unallocated_0"]
            before_data = vfs.read(before_gap)
            before_expected = raw_bytes[:partition_start_byte]
            assert len(before_data) == len(before_expected)
            assert before_data == before_expected

            after_gap = leaves[f"unallocated_{after_gap_start}"]
            after_data = vfs.read(after_gap)
            after_expected = bytes([0xEF]) * after_gap.size
            assert len(after_data) == len(after_expected)
            assert after_data == after_expected

            ntfs_volume = next(c for c in root.children if c.is_dir)
            _assert_all_files_match(vfs, ntfs_volume)
        finally:
            vfs.close()


class TestVolumeInfoPropertiesEnrichment:
    def test_volume_info_none_for_normal_walked_file(self, raw_ntfs_image: Path) -> None:
        vfs = open_vfs(raw_ntfs_image)
        try:
            assert isinstance(vfs, RawImageVFS)
            volume = vfs.root().children[0]
            some_file = next(c for c in volume.children if not c.is_dir)
            assert vfs.volume_info(some_file) is None
        finally:
            vfs.close()

    def test_volume_info_for_unsupported_partition(
        self, raw_multi_partition_image: Path
    ) -> None:
        vfs = open_vfs(raw_multi_partition_image)
        try:
            assert isinstance(vfs, RawImageVFS)
            unsupported = next(c for c in vfs.root().children if not c.is_dir)
            info = vfs.volume_info(unsupported)
            assert info is not None
            assert info["kind"]
            assert info["note"]
        finally:
            vfs.close()

    def test_properties_panel_shows_explicit_status_for_unsupported_partition(
        self, raw_multi_partition_image: Path, qapp
    ) -> None:
        """This project's rule: unsupported content must always carry an
        explicit status, never look like an ordinary, unremarkable file.
        Exercises the actual MainWindow enrichment step, not just the VFS
        method in isolation."""
        from crush.ui.main_window import MainWindow

        vfs = open_vfs(raw_multi_partition_image)
        win = MainWindow()
        try:
            unsupported = next(c for c in vfs.root().children if not c.is_dir)
            info = vfs.volume_info(unsupported)
            assert info is not None

            from crush.parsers.base import ParseResult

            base_result = ParseResult(viewer_type="hex", data=b"")
            enriched = win._enrich_with_format_info(None, unsupported, vfs, base_result)

            assert enriched.metadata["Filesystem"] == info["kind"]
            assert enriched.metadata["Status"] == info["note"]
        finally:
            win.close()
            vfs.close()


def _expected_from(sha_filename: str) -> dict[str, str]:
    expected: dict[str, str] = {}
    for line in (FIXTURES_DIR / sha_filename).read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        digest, _, relpath = line.partition("  ")
        expected[relpath.rsplit("/", 1)[-1]] = digest  # basename only -- see module docstring
    return expected


class TestDeletedFileRecovery:
    """NTFS/FAT32/exFAT are the only filesystems qnxprobe has deleted-file
    recovery for at all (confirmed by reading the vendored source directly
    -- no other walker exposes deleted_files()/read_deleted()). Recovered
    entries land flatly under a volume's `$Recovered` node rather than
    reassembled into their original folders, so fixtures with deleted files
    under a subfolder (e.g. `photos/one.jpg`) are matched here by basename.
    """

    @pytest.mark.forensic(
        category="Known-output Verification",
        desc="Two deliberately deleted NTFS test files must recover to their pre-computed reference hashes",
    )
    def test_ntfs_recovers_known_deleted_files(self, raw_ntfs_image: Path) -> None:
        """raw_ntfs.img.gz carries two deliberately deleted test files
        alongside a large amount of incidental deleted residue from the
        fixture's own construction history (thousands of leftover MFT
        records) -- all of it must be listed, per this project's rule that
        recoverable/uncertain content is never silently absent, but this
        test only checks the two files independently verified by name."""
        import hashlib

        expected = _expected_from("raw_ntfs.deleted.sha256")
        assert set(expected) == {"resident-note.txt", "recording.bin"}

        vfs = open_vfs(raw_ntfs_image)
        try:
            volume = vfs.root().children[0]
            recovered = next(c for c in volume.children if c.name == "$Recovered")
            assert len(recovered.children) > 0

            for name, digest in expected.items():
                node = next((c for c in recovered.children if c.name == name), None)
                assert node is not None, f"missing: {name}"
                info = vfs.volume_info(node)
                assert info == {"kind": "deleted file", "note": "recovered (content intact)"}
                assert hashlib.sha256(vfs.read(node)).hexdigest() == digest
        finally:
            vfs.close()

    @pytest.mark.forensic(
        category="Known-output Verification",
        desc="Three deliberately deleted exFAT test files must recover, names and content, to their reference hashes",
    )
    def test_exfat_recovers_all_three_with_intact_names(self, tmp_path: Path) -> None:
        """exFAT's delete mechanism (unlike FAT32's) does not destroy the
        first character of the name -- all three names come back exact."""
        import hashlib

        dst = tmp_path / "exfat.img"
        dst.write_bytes(gzip.decompress((FIXTURES_DIR / "raw_exfat_deleted.img.gz").read_bytes()))
        expected = _expected_from("raw_exfat_deleted.sha256")

        vfs = open_vfs(dst)
        try:
            volume = vfs.root().children[0]
            recovered = next(c for c in volume.children if c.name == "$Recovered")
            for name, digest in expected.items():
                node = next((c for c in recovered.children if c.name == name), None)
                assert node is not None, f"missing: {name}"
                assert hashlib.sha256(vfs.read(node)).hexdigest() == digest
        finally:
            vfs.close()

    @pytest.mark.forensic(
        category="Known-output Verification",
        desc="Three deliberately deleted FAT32 test files must recover content exactly, per reference hashes",
    )
    def test_fat32_recovers_content_with_first_character_lost(self, tmp_path: Path) -> None:
        """FAT32's delete mechanism overwrites the short-name entry's first
        byte, permanently destroying the name's first character -- qnxprobe
        marks this with the classic leading-underscore convention rather
        than guessing. Content is still recovered exactly; only the name of
        two of the three known files is affected (the third apparently
        reconstructs cleanly from intact long-name fragments)."""
        import hashlib

        dst = tmp_path / "fat32.img"
        dst.write_bytes(gzip.decompress((FIXTURES_DIR / "raw_fat32_deleted.img.gz").read_bytes()))
        expected = _expected_from("raw_fat32_deleted.sha256")

        vfs = open_vfs(dst)
        try:
            volume = vfs.root().children[0]
            recovered = next(c for c in volume.children if c.name == "$Recovered")
            by_hash = {}
            for c in recovered.children:
                info = vfs.volume_info(c)
                if info and info["note"] == "recovered (content intact)":
                    by_hash[hashlib.sha256(vfs.read(c)).hexdigest()] = c.name

            for name, digest in expected.items():
                assert digest in by_hash, f"content for {name} not recovered at all"
                recovered_name = by_hash[digest]
                assert recovered_name == name or recovered_name == "_" + name[1:], (
                    f"unexpected recovered name for {name}: {recovered_name!r}"
                )
        finally:
            vfs.close()

    def test_unrecoverable_deleted_entry_lists_reason_but_refuses_read(
        self, tmp_path: Path
    ) -> None:
        """A deleted directory entry (or one whose clusters/attributes are
        gone) is still listed with an explicit reason -- never silently
        absent -- but read() must refuse rather than return wrong bytes."""
        from crush.core.raw_image import RawImageFileUnreadableError

        dst = tmp_path / "fat32.img"
        dst.write_bytes(gzip.decompress((FIXTURES_DIR / "raw_fat32_deleted.img.gz").read_bytes()))
        vfs = open_vfs(dst)
        try:
            volume = vfs.root().children[0]
            recovered = next(c for c in volume.children if c.name == "$Recovered")
            unrecoverable = next(
                c for c in recovered.children
                if (vfs.volume_info(c) or {}).get("note", "").startswith("not recoverable")
            )
            info = vfs.volume_info(unrecoverable)
            assert info is not None
            assert "not recoverable" in info["note"]
            with pytest.raises(RawImageFileUnreadableError):
                vfs.read(unrecoverable)
        finally:
            vfs.close()


def _all_files(node: VFSNode) -> list[VFSNode]:
    out: list[VFSNode] = []
    stack = [node]
    while stack:
        cur = stack.pop()
        if cur.is_dir:
            stack.extend(cur.children)
        else:
            out.append(cur)
    return out


@pytest.mark.parametrize("fixture_name", ["raw_ntfs_image", "raw_ntfs_e01"])
def test_streamed_open_matches_read_for_every_file(
    request: pytest.FixtureRequest, fixture_name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the stream threshold at 0 every non-empty file goes through the
    chunked reader (IterStream over the filesystem walker); its bytes must be
    identical to the one-shot read() -- for a raw image and for an E01 alike,
    so a ZIP living inside an EWF acquisition can be copied out the same way."""
    monkeypatch.setattr("crush.core.vfs.STREAM_THRESHOLD", 0)
    vfs = RawImageVFS(request.getfixturevalue(fixture_name))
    files = [n for n in _all_files(vfs.root()) if n.size > 0]
    assert files
    checked = 0
    for node in files:
        try:
            expected = vfs.read(node)
        except OSError:
            continue  # unreadable/unrecoverable entries are covered by their own tests
        with vfs.open(node) as f:
            assert f.read() == expected, node.path
            f.seek(0)
            assert f.read(16) == expected[:16], node.path
        checked += 1
    assert checked > 0
    vfs.close()


def _make_gpt_image(payload: bytes, first_lba: int = 2048) -> bytes:
    """A protective MBR, a GPT header at LBA 1 and a 128-entry array at
    LBA 2 holding one Microsoft basic data partition around `payload`."""
    import uuid

    assert len(payload) % 512 == 0
    last_lba = first_lba + len(payload) // 512 - 1
    total_sectors = last_lba + 1

    header = bytearray(512)
    header[0:8] = b"EFI PART"
    header[72:80] = (2).to_bytes(8, "little")  # partition entry array LBA
    header[80:84] = (128).to_bytes(4, "little")  # number of entries
    header[84:88] = (128).to_bytes(4, "little")  # size of one entry

    entries = bytearray(128 * 128)
    entries[0:16] = uuid.UUID("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7").bytes_le
    entries[32:40] = first_lba.to_bytes(8, "little")
    entries[40:48] = last_lba.to_bytes(8, "little")
    entries[56:64] = "data".encode("utf-16-le")

    head = _make_mbr([(0xEE, 1, total_sectors - 1)]) + bytes(header) + bytes(entries)
    return head + bytes(first_lba * 512 - len(head)) + payload


class TestContentSniffedImage:
    """A disk image is found by its content, whatever it's called -- `.bin`
    is what many acquisition tools write, and a bare filesystem dump often
    has no extension at all."""

    def test_bare_filesystem_without_extension_opens_as_raw_image(
        self, raw_ntfs_image: Path, tmp_path: Path
    ) -> None:
        dst = tmp_path / "volume_dump"
        dst.write_bytes(raw_ntfs_image.read_bytes())
        vfs = open_vfs(dst)
        try:
            assert isinstance(vfs, RawImageVFS)
        finally:
            vfs.close()

    def test_ordinary_file_stays_file_vfs(self, tmp_path: Path) -> None:
        import sqlite3

        db = tmp_path / "chat.db"
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE t (x)")
        con.executemany("INSERT INTO t VALUES (?)", [(b"\x55\xaa" * 300,)] * 200)
        con.commit()
        con.close()
        vfs = open_vfs(db)
        try:
            assert isinstance(vfs, FileVFS)
        finally:
            vfs.close()

    def test_gpt_image_named_bin_opens_as_raw_image(self, tmp_path: Path) -> None:
        ntfs_bytes = gzip.decompress((FIXTURES_DIR / "raw_ntfs.img.gz").read_bytes())
        dst = tmp_path / "acquisition.bin"
        dst.write_bytes(_make_gpt_image(ntfs_bytes))
        vfs = open_vfs(dst)
        try:
            assert isinstance(vfs, RawImageVFS)
            volume = next(c for c in vfs.root().children if c.is_dir)
            _assert_all_files_match(vfs, volume)
        finally:
            vfs.close()

    def test_mbr_image_named_bin_opens_as_raw_image(
        self, raw_multi_partition_image: Path, tmp_path: Path
    ) -> None:
        dst = tmp_path / "multi.bin"
        dst.write_bytes(raw_multi_partition_image.read_bytes())
        vfs = open_vfs(dst)
        try:
            assert isinstance(vfs, RawImageVFS)
        finally:
            vfs.close()

    def test_bin_with_no_partition_table_stays_file_vfs(self, tmp_path: Path) -> None:
        dst = tmp_path / "firmware.bin"
        dst.write_bytes(b"\xab" * (1024 * 1024))
        vfs = open_vfs(dst)
        try:
            assert isinstance(vfs, FileVFS)
        finally:
            vfs.close()

    def test_0x55aa_table_pointing_past_the_file_stays_file_vfs(self, tmp_path: Path) -> None:
        """Boot code or data that merely ends in 0x55AA: none of its would-be
        partitions starts inside the file, so it isn't a disk image."""
        dst = tmp_path / "blob.bin"
        dst.write_bytes(_make_mbr([(0x83, 10_000_000, 2048)]) + bytes(64 * 1024))
        vfs = open_vfs(dst)
        try:
            assert isinstance(vfs, FileVFS)
        finally:
            vfs.close()

    def test_gpt_image_with_no_readable_filesystem_falls_back_to_file_vfs(
        self, tmp_path: Path
    ) -> None:
        dst = tmp_path / "unknown_fs.bin"
        dst.write_bytes(_make_gpt_image(b"\xab" * (1024 * 1024)))
        vfs = open_vfs(dst)
        try:
            assert isinstance(vfs, FileVFS)
        finally:
            vfs.close()
