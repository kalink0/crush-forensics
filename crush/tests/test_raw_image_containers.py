# SPDX-License-Identifier: Apache-2.0
"""The containers Open Disk Image… reads through ewfprobe 0.12 beside EWF and
AFF: AFF4, Apple disk images, VHD/VHDX, VMDK and QCOW virtual disks, and the
encrypted containers that open with a password or a private key.

Every fixture was written by the tool named in fixtures/acquisition/README.md
(hdiutil, pyaff4, AFFLIB, FTK Imager, Windows diskpart, qemu-img) and is
copied unmodified from ewfprobe's tests; the expected disk hashes are the ones
those tools' own output recorded (ewfprobe's manifests), not what the reader
produced.
"""
from __future__ import annotations

import gzip
import hashlib
import shutil
from pathlib import Path

import pytest

from crush.core.passwords import (
    PasswordRequiredError,
    PrivateKeyRequiredError,
    WrongPasswordError,
    WrongPrivateKeyError,
)
from crush.core.vfs import DirectoryVFS, FileVFS, RawImageVFS, VFSNode, ZipVFS, open_vfs
from crush.tests.conftest import FIXTURES_DIR

ACQ = FIXTURES_DIR / "acquisition"

# The generated source disk every hdiutil/AFFLIB variant was made from
# (ewfprobe tests/fixtures/manifest.json: raw, gpt_dmg, encrypted_dmg "small").
_SOURCE_DISK = ("770be732aafc4962c6940a2076c35471419621d9d6ca57cda60cbd6e82a8b36f", 3_145_728)
_GPT_DISK = ("7094494ccc3edb30e8a242761e8d9048e1c3e59a0fc1a87579b7b88f352df9f8", 2_254_848)
_SMALL_DISK = ("2d0eae247eef9f48fa16666ee549724f54ef6538933b0eb2828cc6d3e95a8a17", 196_608)
_BANDED_DISK = ("34da288883b19cd673922b2674d8a25faf1d07e7dbd4335240718c1c7044ea3a", 2_129_920)
_AD_SOURCE = ("b824970a22f4c9a99128bba83eff9494b6beac41c1664481891b2fde2cb37a15", 1_257_984)
# The disk as Windows presented it after a read-only attach, and as qemu-img
# wrote it (ewfprobe tests/fixtures/virtual/manifest.json).
_WINDOWS = {
    "dynamic.vhd": ("9c3f0307666540e9a842d9ac25bb3b345315a1b11672ef6405f3d6025123a439", 67_108_864),
    "diff.vhd": ("e659ec65ed1a1440f19623e93add1295ccc9bae6ffadd117cdb48570da488454", 67_108_864),
    "dynamicx.vhdx": ("accfb130d8eb8321c8e494f1864d6913caeb442e840ececef2566b92935d0703", 67_108_864),
    "diffx.vhdx": ("7b13afa8921351a813e8073705258ccf56fffb2bc3ca4762ce0103463f7dbb25", 67_108_864),
}
_QEMU_VHD = ("35a9e0259822cd934990ad1e371e1fa0e4c2e5d2fa0de831d84a1c49044cb429", 16_781_312)
_QEMU_DISK = ("eda5100326096c7e523e664a6e8283d1559d5b9e46d63c688c6c5b9f1b690329", 16_777_216)
_QEMU_DELTA = ("760ff6531c146c65a91bd48e08f82d59e23c6002340282eb449b6bf5c66947fe", 16_777_216)
_QEMU_OVERLAY = ("5794a0fb70a7483949cb8f5e8166ce5ef202dffcdab29abae3b88027ef2bf5b6", 16_777_216)
# MD5 of the stream pyaff4 was given (ewfprobe tests/test_aff4.py, KNOWN).
_AFF4_STREAM_MD5 = "8dd04764855150cb5ac7f36dd584571d"

_DMG_PASSWORD = "ewfprobe-test-password"
_AFF_PASSWORD = "ewfprobe-aff-password"
_AD_PASSWORD = "ewfprobe-ad-test"


def _place(tmp_path: Path, *rels: str) -> Path:
    """Copy fixtures into tmp_path (a .gz one decompressed), the first of
    them being the file to open."""
    first: Path | None = None
    for rel in rels:
        src = ACQ / rel
        name = Path(rel).name
        if name.endswith(".gz"):
            dst = tmp_path / name[:-3]
            dst.write_bytes(gzip.decompress(src.read_bytes()))
        else:
            dst = tmp_path / name
            shutil.copy(src, dst)
        first = first or dst
    assert first is not None
    return first


def _place_bundle(tmp_path: Path, name: str) -> Path:
    """Copy a sparse bundle folder into tmp_path (a .gz band decompressed to
    the band hdiutil wrote) and return the bundle's path."""
    src = ACQ / name
    dst = tmp_path / name
    for f in sorted(src.rglob("*")):
        if not f.is_file():
            continue
        target = dst / f.relative_to(src)
        target.parent.mkdir(parents=True, exist_ok=True)
        if f.name.endswith(".gz"):
            target.with_name(f.name[:-3]).write_bytes(gzip.decompress(f.read_bytes()))
        else:
            shutil.copy(f, target)
    return dst


def _disk_sha256(vfs: RawImageVFS) -> tuple[str, int]:
    """SHA-256 and length of the whole disk as Crush reads it: every
    top-level region of the tree is the disk's bytes at its offset, so the
    raw image handle is read end to end instead."""
    image = vfs._handle.image
    image.seek(0)
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = image.read(1 << 20)
        if not chunk:
            break
        digest.update(chunk)
        total += len(chunk)
    return digest.hexdigest(), total


def _find(node: VFSNode, parts: list[str]) -> VFSNode | None:
    cur = node
    for part in parts:
        match = next((c for c in cur.children if c.name == part), None)
        if match is None:
            return None
        cur = match
    return cur


def _assert_disk(path: Path, container: str, expected: tuple[str, int], **secret: str) -> str:
    """Open *path* as a disk image and check its container and whole-disk
    hash; returns the root's note (what the disk is read from)."""
    vfs = open_vfs(path, as_disk_image=True, **secret)
    try:
        assert isinstance(vfs, RawImageVFS), getattr(vfs, "fallback_note", "")
        assert vfs.acquisition() == container
        assert _disk_sha256(vfs) == expected
        return str(vfs.root().status)
    finally:
        vfs.close()


def _assert_unmodified(files: list[Path], path: Path, **secret: str) -> None:
    before = {f: (hashlib.sha256(f.read_bytes()).hexdigest(), f.stat().st_mtime_ns) for f in files}
    vfs = open_vfs(path, as_disk_image=True, **secret)
    try:
        assert isinstance(vfs, RawImageVFS)
        _disk_sha256(vfs)
        vfs.verify_acquisition()
    finally:
        vfs.close()
    after = {f: (hashlib.sha256(f.read_bytes()).hexdigest(), f.stat().st_mtime_ns) for f in files}
    assert after == before


def _assert_no_hash_to_compare(path: Path) -> None:
    """A container that records no hash of its disk must never verify as a
    match -- there is nothing to compare against."""
    vfs = open_vfs(path, as_disk_image=True)
    try:
        assert isinstance(vfs, RawImageVFS)
        result = vfs.verify_acquisition()
        assert result["stored"] == {}
        assert result["match"] is None
        assert result["container_checks"] == []
    finally:
        vfs.close()


# ---------------------------------------------------------------------------
# AFF4
# ---------------------------------------------------------------------------

class TestAff4:
    @pytest.mark.forensic(
        category="Known-output Verification",
        subject="AFF4 acquisition (.aff4)",
        desc="pyaff4-zlib.aff4, written by pyaff4 (the AFF4 reference implementation), must "
             "open as an AFF4 acquisition whose stream reads back to the MD5 of the content "
             "pyaff4 was given",
    )
    def test_stream_matches_what_pyaff4_was_given(self, tmp_path: Path) -> None:
        path = _place(tmp_path, "pyaff4-zlib.aff4")
        vfs = open_vfs(path, as_disk_image=True)
        try:
            assert isinstance(vfs, RawImageVFS)
            assert vfs.acquisition() == "AFF4"
            (region,) = vfs.root().children
            assert hashlib.md5(vfs.read(region)).hexdigest() == _AFF4_STREAM_MD5
            assert "AFF4 acquisition of one file" in str(vfs.root().status)
        finally:
            vfs.close()

    @pytest.mark.forensic(
        category="Source Immutability",
        subject="AFF4 acquisition (.aff4)",
        desc="Reading the whole stream of pyaff4-zlib.aff4 and verifying it must leave the "
             "file byte-identical, with an unchanged mtime",
    )
    def test_source_unmodified(self, tmp_path: Path) -> None:
        path = _place(tmp_path, "pyaff4-zlib.aff4")
        _assert_unmodified([path], path)

    def test_normal_open_names_aff4_and_points_at_open_disk_image(self, tmp_path: Path) -> None:
        """Opened normally, pyaff4's container is not browsed as a ZIP (its
        members carry a zero DOS date, which the ZIP reader refuses) -- the
        note says why, names the AFF4 container and points at Open Disk
        Image… for its disk."""
        path = _place(tmp_path, "pyaff4-zlib.aff4")
        vfs = open_vfs(path)
        try:
            note = str(vfs.fallback_note)
            assert "AFF4 container" in note and "Open Disk Image" in note
        finally:
            vfs.close()

    def test_an_aff4_browsed_as_zip_says_it_is_one(self, tmp_path: Path) -> None:
        """An AFF4 whose ZIP opens is shown as the ZIP it is stored in --
        its members are real bytes of the file -- and the note says it is an
        AFF4 container, recognised by the volume URI in the ZIP comment."""
        import zipfile

        path = tmp_path / "container.aff4"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("information.turtle", "@prefix aff4: <http://aff4.org/Schema#> .\n")
            zf.comment = b"aff4://10cf2ea2-beab-4162-9f38-f0dd44251b52"
        vfs = open_vfs(path)
        try:
            assert isinstance(vfs, ZipVFS)
            note = str(vfs.fallback_note)
            assert "AFF4 container shown as the ZIP archive" in note
            assert "Open Disk Image" in note
        finally:
            vfs.close()


# ---------------------------------------------------------------------------
# Apple disk images
# ---------------------------------------------------------------------------

class TestAppleDiskImage:
    @pytest.mark.forensic(
        category="Known-output Verification",
        subject="Apple disk image (.dmg/.sparseimage/.sparsebundle)",
        desc="dmg-udzo.dmg (hdiutil, UDZO) must open as an Apple disk image whose disk reads "
             "back to the SHA-256 of the source disk it was made from",
    )
    def test_udif_matches_source(self, tmp_path: Path) -> None:
        _assert_disk(_place(tmp_path, "dmg-udzo.dmg"), "UDIF", _SOURCE_DISK)

    @pytest.mark.forensic(
        category="Known-output Verification",
        subject="Apple disk image (.dmg/.sparseimage/.sparsebundle)",
        desc="The five-file segmented dmg-gpt-segmented.dmg (hdiutil) must be joined from its "
             ".dmgpart files, say so, and read back to the SHA-256 of its GPT source disk",
    )
    def test_segmented_udif_is_joined_and_says_so(self, tmp_path: Path) -> None:
        parts = ["dmg-gpt-segmented.dmg"] + [f"dmg-gpt-segmented.00{i}.dmgpart" for i in range(2, 6)]
        note = _assert_disk(_place(tmp_path, *parts), "UDIF", _GPT_DISK)
        assert "of 5 files, joined by the reader" in note

    @pytest.mark.forensic(
        category="Known-output Verification",
        subject="Apple disk image (.dmg/.sparseimage/.sparsebundle)",
        desc="Verify Acquisition Hash on dmg-udzo.dmg must recompute the image's own data, "
             "block table and master checksums and find every one matching",
    )
    def test_verify_recomputes_the_images_own_checksums(self, tmp_path: Path) -> None:
        vfs = open_vfs(_place(tmp_path, "dmg-udzo.dmg"), as_disk_image=True)
        try:
            assert isinstance(vfs, RawImageVFS)
            result = vfs.verify_acquisition()
            checks = result["container_checks"]
            assert [c["what"] for c in checks][0] == "data"
            assert checks[-1]["what"] == "master"
            assert all(c["match"] for c in checks)
        finally:
            vfs.close()

    @pytest.mark.forensic(
        category="Known-output Verification",
        subject="Apple disk image (.dmg/.sparseimage/.sparsebundle)",
        desc="The encrypted dmg-enc-sparse-aes128.sparseimage (hdiutil, AES-128) must ask for "
             "its password, refuse a wrong one, and with the right one read back to the "
             "SHA-256 of its source disk, saying it was decrypted",
    )
    def test_encrypted_sparse_image_opens_with_its_password(self, tmp_path: Path) -> None:
        path = _place(tmp_path, "dmg-enc-sparse-aes128.sparseimage")
        with pytest.raises(PasswordRequiredError) as required:
            open_vfs(path, as_disk_image=True)
        assert not isinstance(required.value, PrivateKeyRequiredError)
        with pytest.raises(WrongPasswordError):
            open_vfs(path, as_disk_image=True, password="not-the-password")
        note = _assert_disk(path, "SPARSEIMAGE", _SMALL_DISK, password=_DMG_PASSWORD)
        assert "encrypted (AES-128) and opened with its password" in note

    @pytest.mark.forensic(
        category="Known-output Verification",
        subject="Apple disk image (.dmg/.sparseimage/.sparsebundle)",
        desc="dmg-cert-only-udzo-aes256.dmg, sealed by hdiutil to a certificate only, must ask "
             "for a private key (not a password), and with its key read back to the SHA-256 "
             "of its source disk, saying it was opened with the key",
    )
    def test_certificate_only_image_opens_with_its_private_key(self, tmp_path: Path) -> None:
        path = _place(tmp_path, "dmg-cert-only-udzo-aes256.dmg", "dmg-cert-test-key-2048.pem")
        key = str(tmp_path / "dmg-cert-test-key-2048.pem")
        with pytest.raises(PrivateKeyRequiredError):
            open_vfs(path, as_disk_image=True)
        with pytest.raises(PrivateKeyRequiredError):
            open_vfs(path, as_disk_image=True, password="a password opens nothing here")
        note = _assert_disk(path, "UDIF", _SMALL_DISK, private_key=key)
        assert "opened with its private key" in note

    def test_an_unusable_key_file_asks_again(self, tmp_path: Path) -> None:
        """A key file that can't be read as a key is the key's fault, not the
        image's: asked for again, with the reader's reason."""
        path = _place(tmp_path, "dmg-cert-only-udzo-aes256.dmg")
        junk = tmp_path / "junk.pem"
        junk.write_bytes(b"not a key\n")
        with pytest.raises(WrongPrivateKeyError, match="RSA key"):
            open_vfs(path, as_disk_image=True, private_key=str(junk))
        with pytest.raises(WrongPrivateKeyError, match="could not be read"):
            open_vfs(path, as_disk_image=True, private_key=str(tmp_path / "missing.pem"))

    @pytest.mark.forensic(
        category="Source Immutability",
        subject="Apple disk image (.dmg/.sparseimage/.sparsebundle)",
        desc="Reading the whole disk of the segmented dmg-gpt-segmented.dmg and of the "
             "encrypted dmg-enc-sparse-aes128.sparseimage and verifying them must leave every "
             "file byte-identical, with an unchanged mtime",
    )
    def test_source_unmodified(self, tmp_path: Path) -> None:
        parts = ["dmg-gpt-segmented.dmg"] + [f"dmg-gpt-segmented.00{i}.dmgpart" for i in range(2, 6)]
        (tmp_path / "seg").mkdir()
        (tmp_path / "enc").mkdir()
        segmented = _place(tmp_path / "seg", *parts)
        _assert_unmodified(sorted(segmented.parent.iterdir()), segmented)
        encrypted = _place(tmp_path / "enc", "dmg-enc-sparse-aes128.sparseimage")
        _assert_unmodified([encrypted], encrypted, password=_DMG_PASSWORD)

    @pytest.mark.forensic(
        category="Known-output Verification",
        subject="Apple disk image (.dmg/.sparseimage/.sparsebundle)",
        desc="The sparse bundle dmg-sparsebundle.sparsebundle (hdiutil) must open as a disk "
             "image from its folder and from any file in it (Info.plist, a band), say it is "
             "read from the bundle's band files, and read back to the SHA-256 of its source "
             "disk",
    )
    def test_sparse_bundle_opens_whole_from_its_folder_or_any_file(self, tmp_path: Path) -> None:
        bundle = _place_bundle(tmp_path, "dmg-sparsebundle.sparsebundle")
        note = _assert_disk(bundle, "SPARSEBUNDLE", _SOURCE_DISK)
        assert "Apple sparse bundle of 3 stored band files" in note
        for member in (bundle / "Info.plist", bundle / "bands" / "1"):
            _assert_disk(member, "SPARSEBUNDLE", _SOURCE_DISK)
            vfs = open_vfs(member, as_disk_image=True)
            try:
                assert vfs.root().name == bundle.name
                rel = member.relative_to(bundle).as_posix()
                assert f"{rel} is a file of the Apple sparse bundle {bundle.name}" in str(
                    vfs.load_note
                )
            finally:
                vfs.close()

    @pytest.mark.forensic(
        category="Known-output Verification",
        subject="Apple disk image (.dmg/.sparseimage/.sparsebundle)",
        desc="The encrypted sparse bundle dmg-enc-sparsebundle-aes256.sparsebundle (hdiutil, "
             "AES-256) must ask for its password and with it read back to the SHA-256 of the "
             "disk hdiutil attach read from it",
    )
    def test_encrypted_sparse_bundle_opens_with_its_password(self, tmp_path: Path) -> None:
        bundle = _place_bundle(tmp_path, "dmg-enc-sparsebundle-aes256.sparsebundle")
        with pytest.raises(PasswordRequiredError):
            open_vfs(bundle, as_disk_image=True)
        note = _assert_disk(bundle, "SPARSEBUNDLE", _BANDED_DISK, password=_DMG_PASSWORD)
        assert "encrypted (AES-256) and opened with its password" in note

    def test_a_sparse_bundle_opened_normally_is_its_folder_and_says_so(
        self, tmp_path: Path
    ) -> None:
        """Opened as a folder, a sparse bundle shows its own files -- real
        files of the folder -- and says how to read the disk they hold; a
        file of it opened normally gets the hint as well."""
        bundle = _place_bundle(tmp_path, "dmg-sparsebundle.sparsebundle")
        folder = open_vfs(bundle)
        try:
            assert isinstance(folder, DirectoryVFS)
            note = str(folder.fallback_note)
            assert "Apple sparse bundle shown as the folder" in note
            assert "Open Disk Image" in note
        finally:
            folder.close()
        band = open_vfs(bundle / "bands" / "1")
        try:
            assert isinstance(band, FileVFS)
            assert "a file of the Apple sparse bundle" in str(band.fallback_note)
        finally:
            band.close()

    @pytest.mark.forensic(
        category="Source Immutability",
        subject="Apple disk image (.dmg/.sparseimage/.sparsebundle)",
        desc="Reading the whole disk of the sparse bundle dmg-sparsebundle.sparsebundle and "
             "verifying it must leave every file of the bundle byte-identical, with an "
             "unchanged mtime",
    )
    def test_sparse_bundle_source_unmodified(self, tmp_path: Path) -> None:
        bundle = _place_bundle(tmp_path, "dmg-sparsebundle.sparsebundle")
        files = sorted(f for f in bundle.rglob("*") if f.is_file())
        _assert_unmodified(files, bundle)


# ---------------------------------------------------------------------------
# Encrypted AFF and AD-encrypted EWF (subjects of their own container)
# ---------------------------------------------------------------------------

class TestEncryptedAcquisitions:
    @pytest.mark.forensic(
        category="Known-output Verification",
        subject="AFF acquisition (.aff/.afd)",
        desc="aff-enc-pass.aff, encrypted by AFFLIB with a passphrase, must ask for it, refuse "
             "a wrong one, and with the right one read back to the SHA-256 of its source disk "
             "and verify as MATCH against its stored hashes",
    )
    def test_encrypted_aff_opens_with_its_passphrase(self, tmp_path: Path) -> None:
        path = _place(tmp_path, "aff-enc-pass.aff")
        with pytest.raises(PasswordRequiredError):
            open_vfs(path, as_disk_image=True)
        with pytest.raises(WrongPasswordError):
            open_vfs(path, as_disk_image=True, password="wrong")
        note = _assert_disk(path, "AFF", _SOURCE_DISK, password=_AFF_PASSWORD)
        assert "opened with its password" in note
        vfs = open_vfs(path, as_disk_image=True, password=_AFF_PASSWORD)
        try:
            assert isinstance(vfs, RawImageVFS)
            result = vfs.verify_acquisition()
            assert result["stored"] and result["match"] is True
        finally:
            vfs.close()

    @pytest.mark.forensic(
        category="Known-output Verification",
        subject="EWF acquisition (.E01)",
        desc="The two-segment ftk-ad-e01.E01, AD-encrypted by FTK Imager, must ask for its "
             "password, and with it read back to the SHA-256 of the source FTK Imager "
             "acquired and verify as MATCH against the MD5 and SHA-1 FTK Imager recorded",
    )
    def test_ad_encrypted_e01_opens_with_its_password(self, tmp_path: Path) -> None:
        path = _place(tmp_path, "ftk-ad-e01.E01", "ftk-ad-e01.E02")
        with pytest.raises(PasswordRequiredError):
            open_vfs(path, as_disk_image=True)
        note = _assert_disk(path, "EWF-E01", _AD_SOURCE, password=_AD_PASSWORD)
        assert "of 2 segments" in note and "opened with its password" in note
        vfs = open_vfs(path, as_disk_image=True, password=_AD_PASSWORD)
        try:
            assert isinstance(vfs, RawImageVFS)
            result = vfs.verify_acquisition()
            assert result["stored"] == {
                "MD5": "fbc8c24845be0e9f7596b46ef88b27a2",
                "SHA1": "c8fcc8e1eb278de2ae4d0d058867ec561c4b38d3",
            }
            assert result["match"] is True
        finally:
            vfs.close()

    @pytest.mark.forensic(
        category="Source Immutability",
        subject="EWF acquisition (.E01)",
        desc="Decrypting and reading the whole disk of the AD-encrypted ftk-ad-e01.E01 set and "
             "verifying it must leave both segments byte-identical, with unchanged mtimes",
    )
    def test_ad_encrypted_source_unmodified(self, tmp_path: Path) -> None:
        path = _place(tmp_path, "ftk-ad-e01.E01", "ftk-ad-e01.E02")
        _assert_unmodified(sorted(tmp_path.iterdir()), path, password=_AD_PASSWORD)


# ---------------------------------------------------------------------------
# VHD / VHDX
# ---------------------------------------------------------------------------

_WIN = "virtual/windows/"
_QEMU = "virtual/qemu-compact/"


class TestVhdVhdx:
    @pytest.mark.forensic(
        category="Known-output Verification",
        subject="VHD/VHDX virtual disk",
        desc="dynamic.vhd and dynamicx.vhdx, written by Windows 11 diskpart, must read back to "
             "the SHA-256 of the disk as Windows itself presented it",
    )
    @pytest.mark.parametrize("name, container", [("dynamic.vhd", "VHD"), ("dynamicx.vhdx", "VHDX")])
    def test_windows_disk_matches_what_windows_presented(
        self, tmp_path: Path, name: str, container: str
    ) -> None:
        note = _assert_disk(_place(tmp_path, _WIN + name + ".gz"), container, _WINDOWS[name])
        assert "over its parent" not in note

    @pytest.mark.forensic(
        category="Known-output Verification",
        subject="VHD/VHDX virtual disk",
        desc="The differencing diff.vhd and diffx.vhdx (Windows 11) must be read over their "
             "parents, name the parent, read back to the SHA-256 of the disk Windows "
             "presented, and show the file only the child holds",
    )
    @pytest.mark.parametrize("name, parent, container", [
        ("diff.vhd", "dynamic.vhd", "VHD"), ("diffx.vhdx", "dynamicx.vhdx", "VHDX"),
    ])
    def test_differencing_disk_is_read_over_its_parent_and_says_so(
        self, tmp_path: Path, name: str, parent: str, container: str
    ) -> None:
        path = _place(tmp_path, _WIN + name + ".gz", _WIN + parent + ".gz")
        note = _assert_disk(path, container, _WINDOWS[name])
        assert f"over its parent {parent}" in note
        vfs = open_vfs(path, as_disk_image=True)
        try:
            (volume,) = [c for c in vfs.root().children if c.is_dir]
            assert _find(volume, ["child.txt"]) is not None
        finally:
            vfs.close()
        parent_only = open_vfs(tmp_path / parent, as_disk_image=True)
        try:
            (volume,) = [c for c in parent_only.root().children if c.is_dir]
            assert _find(volume, ["child.txt"]) is None
        finally:
            parent_only.close()

    @pytest.mark.forensic(
        category="Known-output Verification",
        subject="VHD/VHDX virtual disk",
        desc="vhd-fixed.vhd and vhdx-fixed.vhdx, written by qemu-img, must read back to the "
             "SHA-256 of the disk qemu-img was given",
    )
    def test_qemu_fixed_disks_match(self, tmp_path: Path) -> None:
        (tmp_path / "vhd").mkdir()
        (tmp_path / "vhdx").mkdir()
        _assert_disk(_place(tmp_path / "vhd", _QEMU + "vhd-fixed.vhd.gz"), "VHD", _QEMU_VHD)
        _assert_disk(_place(tmp_path / "vhdx", _QEMU + "vhdx-fixed.vhdx.gz"), "VHDX", _QEMU_DISK)

    @pytest.mark.forensic(
        category="Known-output Verification",
        subject="VHD/VHDX virtual disk",
        desc="Verify Acquisition Hash on dynamic.vhd, which records no hash of its disk, must "
             "report nothing to compare against, never a match",
    )
    def test_verify_has_nothing_to_compare(self, tmp_path: Path) -> None:
        _assert_no_hash_to_compare(_place(tmp_path, _WIN + "dynamic.vhd.gz"))

    @pytest.mark.forensic(
        category="Source Immutability",
        subject="VHD/VHDX virtual disk",
        desc="Reading the whole disk of the differencing diff.vhd and verifying it must leave "
             "both it and its parent byte-identical, with unchanged mtimes",
    )
    def test_source_unmodified(self, tmp_path: Path) -> None:
        path = _place(tmp_path, _WIN + "diff.vhd.gz", _WIN + "dynamic.vhd.gz")
        _assert_unmodified(sorted(tmp_path.iterdir()), path)

    @pytest.mark.parametrize("rel, says", [
        (_WIN + "diff.vhd.gz", "its parent, C:\\VDWork\\dynamic.vhd, is not beside it"),
        (_WIN + "diffx.vhdx.gz", "is not beside it"),
        (_QEMU + "vmdk-delta.vmdk.gz", "its parent, vmdk-base.vmdk, is not beside it"),
        (_QEMU + "qcow2-overlay.qcow2.gz", "qcow2-base.qcow2, which is not beside it"),
        (_QEMU + "vmdk-monolithicFlat.vmdk.gz", "extent vmdk-monolithicFlat-flat.vmdk"),
    ])
    def test_a_disk_without_its_parent_or_extent_is_refused(
        self, tmp_path: Path, rel: str, says: str
    ) -> None:
        """Read without its parent, a differencing disk would show only what
        it changed, as though that were the disk: refused, naming what's
        missing."""
        vfs = open_vfs(_place(tmp_path, rel), as_disk_image=True)
        try:
            assert isinstance(vfs, FileVFS)
            assert says in str(vfs.fallback_note)
        finally:
            vfs.close()

    def test_normal_open_hints_by_content_whatever_the_name(self, tmp_path: Path) -> None:
        """A fixed VHD's only signature is its footer, at the end of the
        file: the hint still finds it, by the image reader's own test."""
        _place(tmp_path, _QEMU + "vhd-fixed.vhd.gz").rename(tmp_path / "evidence")
        vfs = open_vfs(tmp_path / "evidence")
        try:
            assert isinstance(vfs, FileVFS)
            assert "VHD container" in str(vfs.fallback_note)
        finally:
            vfs.close()


# ---------------------------------------------------------------------------
# VMDK
# ---------------------------------------------------------------------------

class TestVmdk:
    @pytest.mark.forensic(
        category="Known-output Verification",
        subject="VMDK virtual disk",
        desc="The monolithicSparse, streamOptimized and monolithicFlat (descriptor + flat "
             "extent) VMDKs qemu-img wrote must read back to the SHA-256 of the disk "
             "qemu-img was given",
    )
    @pytest.mark.parametrize("files", [
        ["vmdk-monolithicSparse.vmdk"],
        ["vmdk-streamOptimized.vmdk"],
        ["vmdk-monolithicFlat.vmdk", "vmdk-monolithicFlat-flat.vmdk"],
    ])
    def test_disk_matches(self, tmp_path: Path, files: list[str]) -> None:
        path = _place(tmp_path, *(_QEMU + f + ".gz" for f in files))
        note = _assert_disk(path, "VMDK", _QEMU_DISK)
        if len(files) > 1:
            assert "of 2 files, joined by the reader" in note

    @pytest.mark.forensic(
        category="Known-output Verification",
        subject="VMDK virtual disk",
        desc="The delta vmdk-delta.vmdk (qemu-img) must be read over its base, name it, and "
             "read back to the SHA-256 qemu-img's disk had after the delta's writes",
    )
    def test_delta_is_read_over_its_base_and_says_so(self, tmp_path: Path) -> None:
        path = _place(tmp_path, _QEMU + "vmdk-delta.vmdk.gz", _QEMU + "vmdk-base.vmdk.gz")
        note = _assert_disk(path, "VMDK", _QEMU_DELTA)
        assert "over its parent vmdk-base.vmdk" in note

    @pytest.mark.forensic(
        category="Source Immutability",
        subject="VMDK virtual disk",
        desc="Reading the whole disk of vmdk-delta.vmdk and verifying it must leave the delta "
             "and its base byte-identical, with unchanged mtimes",
    )
    def test_source_unmodified(self, tmp_path: Path) -> None:
        path = _place(tmp_path, _QEMU + "vmdk-delta.vmdk.gz", _QEMU + "vmdk-base.vmdk.gz")
        _assert_unmodified(sorted(tmp_path.iterdir()), path)


# ---------------------------------------------------------------------------
# QCOW
# ---------------------------------------------------------------------------

class TestQcow:
    @pytest.mark.forensic(
        category="Known-output Verification",
        subject="QCOW virtual disk",
        desc="qcow2-v3.qcow2 and qcow1.qcow, written by qemu-img, must read back to the "
             "SHA-256 of the disk qemu-img was given",
    )
    @pytest.mark.parametrize("name", ["qcow2-v3.qcow2", "qcow1.qcow"])
    def test_disk_matches(self, tmp_path: Path, name: str) -> None:
        _assert_disk(_place(tmp_path, _QEMU + name + ".gz"), "QCOW", _QEMU_DISK)

    @pytest.mark.forensic(
        category="Known-output Verification",
        subject="QCOW virtual disk",
        desc="The overlay qcow2-overlay.qcow2 (qemu-img) must be read over its backing file, "
             "name it, and read back to the SHA-256 qemu-img's disk had after the overlay's "
             "writes",
    )
    def test_overlay_is_read_over_its_backing_file_and_says_so(self, tmp_path: Path) -> None:
        path = _place(tmp_path, _QEMU + "qcow2-overlay.qcow2.gz", _QEMU + "qcow2-base.qcow2.gz")
        note = _assert_disk(path, "QCOW", _QEMU_OVERLAY)
        assert "over its parent qcow2-base.qcow2" in note

    def test_luks_encrypted_qcow_is_refused_with_the_reason(self, tmp_path: Path) -> None:
        """The reader doesn't decrypt LUKS: refused, saying so, never read
        as the ciphertext of a disk."""
        vfs = open_vfs(_place(tmp_path, _QEMU + "qcow2-luks.qcow2.gz"), as_disk_image=True)
        try:
            assert isinstance(vfs, FileVFS)
            assert "encrypted (LUKS)" in str(vfs.fallback_note)
        finally:
            vfs.close()

    @pytest.mark.forensic(
        category="Source Immutability",
        subject="QCOW virtual disk",
        desc="Reading the whole disk of qcow2-overlay.qcow2 and verifying it must leave the "
             "overlay and its backing file byte-identical, with unchanged mtimes",
    )
    def test_source_unmodified(self, tmp_path: Path) -> None:
        path = _place(tmp_path, _QEMU + "qcow2-overlay.qcow2.gz", _QEMU + "qcow2-base.qcow2.gz")
        _assert_unmodified(sorted(tmp_path.iterdir()), path)


# ---------------------------------------------------------------------------
# The prompt for what opens an encrypted disk image
# ---------------------------------------------------------------------------

class TestDiskImageKeyDialog:
    def test_ok_needs_exactly_one_of_password_and_key(self, qapp: object) -> None:
        from PySide6.QtWidgets import QDialogButtonBox

        from crush.ui.disk_image_key_dialog import DiskImageKeyDialog

        dialog = DiskImageKeyDialog(reason="x is encrypted", needs="password")
        ok = dialog._buttons.button(QDialogButtonBox.StandardButton.Ok)
        assert not ok.isEnabled()
        dialog._password_edit.setText(" pass with spaces ")
        assert ok.isEnabled()
        assert dialog.password() == " pass with spaces "
        dialog._key_edit.setText("/keys/k.pem")
        assert not ok.isEnabled()
        dialog._password_edit.clear()
        assert ok.isEnabled()
        assert dialog.private_key() == "/keys/k.pem"

    def test_wide_enough_for_the_reason_without_resizing(self, qapp: object) -> None:
        """The reader's reason (often with a path in it) must not be broken
        into a narrow column the analyst has to widen every time."""
        from crush.ui.disk_image_key_dialog import _MIN_WIDTH_CHARS, DiskImageKeyDialog

        dialog = DiskImageKeyDialog(
            reason="Disk image is encrypted: /evidence/case/x.sparseimage — x.sparseimage is "
                   "an encrypted Apple disk image and opens only with its password",
            was_wrong=True,
        )
        expected = dialog.fontMetrics().averageCharWidth() * _MIN_WIDTH_CHARS
        assert dialog.minimumWidth() == expected
        assert dialog.width() >= expected

    def test_a_retry_asks_the_way_the_first_prompt_did(self) -> None:
        """A rejected key for an image sealed only to a certificate asks for
        the key again, not for a password as well; an image that opens with
        a password keeps both fields."""
        from crush.ui.main_window import _disk_image_retry_needs

        needs, memo = _disk_image_retry_needs(None, "/x.dmg", False, "private key")
        assert needs == "private key"
        needs, memo = _disk_image_retry_needs(memo, "/x.dmg", True, "password")
        assert needs == "private key"
        needs, memo = _disk_image_retry_needs(None, "/y.aff", False, "password")
        needs, memo = _disk_image_retry_needs(memo, "/y.aff", True, "password")
        assert needs == "password"
        # another image starts afresh
        needs, _ = _disk_image_retry_needs(("/x.dmg", "private key"), "/z.dmg", True, "password")
        assert needs == "password"

    def test_certificate_only_offers_only_the_key(self, qapp: object) -> None:
        from crush.ui.disk_image_key_dialog import DiskImageKeyDialog

        dialog = DiskImageKeyDialog(reason="sealed", needs="private key")
        dialog._password_edit.setText("typed anyway")
        assert dialog.password() == ""
