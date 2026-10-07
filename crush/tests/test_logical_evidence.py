# SPDX-License-Identifier: Apache-2.0
"""Logical evidence -- EnCase L01 and FTK Imager AD1 -- as a source of its
own (LogicalEvidenceVFS), checked against what the tools that wrote the
fixtures recorded themselves: FTK Imager's file listing (.ad1.csv) and log
(.ad1.txt), the manifest of the folder imaged, and the MD5s EnCase stored.
See fixtures/acquisition/README.md for where each fixture comes from.
"""
from __future__ import annotations

import gzip
import hashlib
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from crush.core.issues import ParseIssue
from crush.core.logical_evidence import LogicalHandle, build_tree
from crush.core.passwords import (
    PasswordRequiredError,
    PrivateKeyRequiredError,
    WrongPasswordError,
    WrongPrivateKeyError,
)
from crush.core.stored_times import ACCESSED, BIRTH, MODIFIED
from crush.core.vfs import (
    FileVFS,
    LogicalEvidenceVFS,
    VFSNode,
    is_browsable_source_file,
    open_vfs,
)
from crush.tests.conftest import FIXTURES_DIR

LOGICAL = FIXTURES_DIR / "acquisition" / "logical"
AD1_PASSWORD = "Ad1Test-2026!"


def _copy(tmp_path: Path, *names: str) -> list[Path]:
    """Writable copies in tmp_path; a .gz fixture is decompressed under its
    own name."""
    out = []
    for name in names:
        src = LOGICAL / name
        if name.endswith(".gz"):
            dst = tmp_path / name[:-3]
            dst.write_bytes(gzip.decompress(src.read_bytes()))
        else:
            dst = tmp_path / name
            shutil.copyfile(src, dst)
        out.append(dst)
    return out


@pytest.fixture
def ad1_multi(tmp_path: Path) -> Path:
    return _copy(tmp_path, "lean-multi-ntfs-c9.ad1", "lean-multi-ntfs-c9.ad1.txt")[0]


@pytest.fixture
def ad1_set(tmp_path: Path) -> Path:
    """The four-file set, with FTK Imager's log; returns its third file."""
    paths = _copy(tmp_path, *(f"lean-src-c0-1mb.ad{n}.gz" for n in range(1, 5)),
                  "lean-src-c0-1mb.ad1.txt")
    return paths[2]


@pytest.fixture
def ad1_encrypted(tmp_path: Path) -> Path:
    return _copy(tmp_path, "lean-src-c6-1mb-adcrypt.ad1", "lean-src-c6-1mb-adcrypt.ad2",
                 "lean-src-c6-1mb-adcrypt.ad1.txt")[0]


@pytest.fixture
def ad1_cert(tmp_path: Path) -> Path:
    return _copy(tmp_path, "ftk-ad-cert-ad1.ad1", "ftk-ad-cert-ad1.ad1.txt")[0]


@pytest.fixture
def l01(tmp_path: Path) -> Path:
    return _copy(tmp_path, "tracy-phone-2012-07-05-1640.L01.gz")[0]


def _files(node: VFSNode) -> list[VFSNode]:
    if not node.is_dir:
        return [node]
    return [f for c in node.children for f in _files(c)]


def _ftk_listing(name: str) -> list[dict[str, str]]:
    """FTK Imager's own file listing (UTF-16, tab separated)."""
    text = (LOGICAL / name).read_text(encoding="utf-16")
    lines = [line for line in text.splitlines() if line.strip()]
    header = [h.strip() for h in lines[0].split("\t")]
    return [dict(zip(header, (v.strip() for v in line.split("\t")))) for line in lines[1:]]


_FTK_MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}


def _ftk_time(text: str) -> float:
    """FTK Imager's listing time, e.g. "2022-May-16 23:19:09.765432", as UTC.
    The month is FTK Imager's English abbreviation, read without the locale
    (Qt tests set it to the system's)."""
    year, month, rest = text.split("-", 2)
    dt = datetime.strptime(f"{year}-{_FTK_MONTHS[month]:02d}-{rest}", "%Y-%m-%d %H:%M:%S.%f")
    return dt.replace(tzinfo=timezone.utc).timestamp()


def _manifest() -> dict[str, tuple[int, str]]:
    """name -> (size, md5) of the folder imaged, as recorded before imaging."""
    out: dict[str, tuple[int, str]] = {}
    for line in (LOGICAL / "lean_manifest.txt").read_text(encoding="utf-8").splitlines()[2:]:
        cols = line.split("\t")
        if len(cols) > 3 and cols[1] and cols[0].startswith("C:\\AD1Lean\\src\\"):
            out[cols[0].rsplit("\\", 1)[1]] = (int(cols[1]), cols[2])
    return out


# ---------------------------------------------------------------------------
# AD1, against FTK Imager's own listing and log
# ---------------------------------------------------------------------------

class TestAd1:
    @pytest.mark.forensic(
        category="Known-output Verification",
        subject="FTK Imager logical evidence (.ad1)",
        desc="Every file FTK Imager lists in its own listing of the image appears with its "
             "size, recorded MD5/SHA-1, UTC times and deleted flag, and reads to that MD5",
    )
    def test_matches_ftk_imagers_listing(self, ad1_multi: Path) -> None:
        vfs = open_vfs(ad1_multi)
        assert isinstance(vfs, LogicalEvidenceVFS)
        try:
            by_name = {n.name: n for n in _files(vfs.root())}
            listed = [row for row in _ftk_listing("lean-multi-ntfs-c9.ad1.csv")
                      if row["Stored MD5 Hash"]]
            assert listed
            for row in listed:
                node = by_name[row["Filename"]]
                assert node.size == int(row["Size (bytes)"])
                info = vfs.node_info(node)
                assert info is not None
                assert info["Recorded MD5"] == row["Stored MD5 Hash"]
                assert info["Recorded SHA-1"] == row["Stored SHA1 Hash"]
                assert hashlib.md5(vfs.read(node)).hexdigest() == row["Stored MD5 Hash"]
                times = {t.kind: t.utc for t in node.stored_times}
                assert times[BIRTH] == pytest.approx(_ftk_time(row["Created"]), abs=1e-5)
                assert times[MODIFIED] == pytest.approx(_ftk_time(row["Modified"]), abs=1e-5)
                assert times[ACCESSED] == pytest.approx(_ftk_time(row["Accessed"]), abs=1e-5)
                deleted = isinstance(node.status, ParseIssue) and "entry.ad1_deleted" in repr(
                    node.status)
                assert deleted == (row["Is Deleted"] == "yes"), row["Filename"]
        finally:
            vfs.close()

    def test_entry_with_data_and_children_shows_both(self, ad1_multi: Path) -> None:
        """readme.txt holds its own data and a named stream ("extra"); the
        folders hold index data of their own. Nothing is hidden."""
        vfs = open_vfs(ad1_multi)
        try:
            root = vfs.root()
            known = _child(_child(_child(root, "U:\\:AD1LEAN [NTFS]"), "[root]"), "known")
            readme = _child(known, "readme.txt")
            assert readme.is_dir
            own = _child(readme, "readme.txt")
            assert vfs.read(own) == b"known AD1 test file\r\n"
            assert isinstance(own.status, ParseIssue)
            assert own.status.code == "entry.logical_own_data"
            assert vfs.read(_child(readme, "extra")) == b"alternate data stream\r\n"
            assert _child(known, "known").size == 568  # the folder's own data
        finally:
            vfs.close()

    @pytest.mark.forensic(
        category="Known-output Verification",
        subject="FTK Imager logical evidence (.ad1)",
        desc="Verify Acquisition Hash reproduces the image hash in FTK Imager's log and every "
             "file's recorded MD5 and SHA-1",
    )
    def test_verify_against_ftk_imagers_log(self, ad1_multi: Path) -> None:
        vfs = open_vfs(ad1_multi)
        try:
            assert vfs.acquisition() == "AD1"
            result = vfs.verify_acquisition()
        finally:
            vfs.close()
        assert result["stored"] == {"MD5": "430943c75fae0ff41334e4291cebf3f7",
                                    "SHA1": "c44ff0a31e17decce8776e236fef973f840c4d95"}
        assert result["match"] is True
        assert result["entry_md5_checked"] == 9 and result["entry_md5_mismatched"] == []
        assert result["entry_sha1_checked"] == 9 and result["entry_sha1_mismatched"] == []
        assert result["ad1_log"] == "lean-multi-ntfs-c9.ad1.txt"
        # The three folders' own data has no recorded hash: counted, not hidden.
        assert result["entry_count"] == 12
        assert result["entry_md5_missing"] == 3 and result["entry_sha1_missing"] == 3

    def test_without_ftk_imagers_log_no_image_hash(self, tmp_path: Path) -> None:
        """The image hash is in FTK Imager's log, not in the AD1: without the
        log there is none to compare, and that is said."""
        path = _copy(tmp_path, "lean-multi-ntfs-c9.ad1")[0]
        vfs = open_vfs(path)
        try:
            result = vfs.verify_acquisition()
        finally:
            vfs.close()
        assert result["stored"] == {} and result["match"] is None
        assert result["ad1_log"] is None
        assert result["ad1_log_expected"] == "lean-multi-ntfs-c9.ad1.txt"
        assert result["entry_md5_checked"] == 9

    @pytest.mark.forensic(
        category="Completeness",
        subject="FTK Imager logical evidence (.ad1)",
        desc="An AD1 set in four files opens whole from any of its files, every file "
             "matching the manifest of the folder imaged",
    )
    def test_set_opens_whole_from_any_file(self, ad1_set: Path) -> None:
        vfs = open_vfs(ad1_set)
        assert isinstance(vfs, LogicalEvidenceVFS)
        try:
            assert "4 segments" in str(vfs.root().status)
            manifest = _manifest()
            files = {n.name: n for n in _files(vfs.root())}
            assert set(manifest) <= set(files)
            for name, (size, md5) in manifest.items():
                assert files[name].size == size
                assert hashlib.md5(vfs.read(files[name])).hexdigest() == md5
            assert vfs.verify_acquisition()["match"] is True
        finally:
            vfs.close()

    def test_encrypted_opens_with_its_password(self, ad1_encrypted: Path, ad1_set: Path) -> None:
        plain = open_vfs(ad1_encrypted)
        # What it holds shows once it is opened: pointed at Open Disk Image….
        assert isinstance(plain, FileVFS)
        assert plain.disk_image_path == ad1_encrypted
        note = plain.fallback_note
        assert isinstance(note, ParseIssue) and note.code == "vfs.ad_encrypted_hint"
        assert "a disk image or AD1 logical evidence" in str(note)
        with pytest.raises(PasswordRequiredError):
            open_vfs(ad1_encrypted, as_disk_image=True)
        with pytest.raises(WrongPasswordError):
            open_vfs(ad1_encrypted, as_disk_image=True, password="not the password")
        vfs = open_vfs(ad1_encrypted, as_disk_image=True, password=AD1_PASSWORD)
        same = open_vfs(ad1_set)
        assert isinstance(vfs, LogicalEvidenceVFS)
        try:
            assert "opened with its password" in str(vfs.root().status)
            got = {n.path: vfs.read(n) for n in _files(vfs.root())}
            want = {n.path: same.read(n) for n in _files(same.root())}
            assert got == want  # the same folder, imaged twice
            assert vfs.verify_acquisition()["match"] is True
        finally:
            vfs.close()
            same.close()

    def test_a_secret_that_does_not_open_it_is_wrong(
        self, tmp_path: Path, ad1_encrypted: Path, ad1_cert: Path
    ) -> None:
        """A password or key given that doesn't open the set is refused as
        wrong, with the reader's reason -- also a key for a set that opens
        only with its password, and a key file that isn't a key -- so the
        prompt that asks again says so."""
        key = str(LOGICAL / "ad-cert-test-key-2048.pem")
        junk = tmp_path / "junk.pem"
        junk.write_bytes(b"not a key\n")
        with pytest.raises(WrongPrivateKeyError, match="opens only with its password"):
            open_vfs(ad1_encrypted, as_disk_image=True, private_key=key)
        with pytest.raises(WrongPasswordError, match="private key"):
            open_vfs(ad1_cert, as_disk_image=True, password="a password opens nothing here")
        with pytest.raises(WrongPrivateKeyError, match="RSA key"):
            open_vfs(ad1_cert, as_disk_image=True, private_key=str(junk))

    def test_sealed_to_a_certificate_opens_with_its_key(self, ad1_cert: Path) -> None:
        with pytest.raises(PrivateKeyRequiredError):
            open_vfs(ad1_cert, as_disk_image=True)
        key = str(LOGICAL / "ad-cert-test-key-2048.pem")
        vfs = open_vfs(ad1_cert, as_disk_image=True, private_key=key)
        assert isinstance(vfs, LogicalEvidenceVFS)
        try:
            names = sorted(n.name for n in _files(vfs.root()))
            assert names == ["alpha.txt", "bravo.bin", "charlie.txt"]
            for node in _files(vfs.root()):
                info = vfs.node_info(node)
                assert info is not None
                assert hashlib.md5(vfs.read(node)).hexdigest() == info["Recorded MD5"]
            assert vfs.verify_acquisition()["match"] is True
        finally:
            vfs.close()


def _child(node: VFSNode, name: str) -> VFSNode:
    return next(c for c in node.children if c.name == name)


# ---------------------------------------------------------------------------
# L01, against the MD5s EnCase stored
# ---------------------------------------------------------------------------

class TestL01:
    @pytest.mark.forensic(
        category="Completeness",
        subject="EnCase logical evidence (.L01)",
        desc="Every entry of the L01 that holds data is in the tree exactly once, "
             "an entry with data and entries beneath it as well",
    )
    def test_every_entry_with_data_is_shown_once(self, l01: Path) -> None:
        vfs = open_vfs(l01)
        assert isinstance(vfs, LogicalEvidenceVFS)
        try:
            image = vfs._handle.image
            expected = {id(e) for e in image.logical_entries
                        if e.size or not (e.children or e.is_folder)}
            shown = [id(e) for e in vfs._handle.entries.values()]
            assert len(shown) == len(set(shown)) == len(expected)
            assert set(shown) == expected
            own = [n for n in _files(vfs.root())
                   if isinstance(n.status, ParseIssue) and "entry.logical_own_data"
                   in repr(n.status)]
            assert len(own) == 123
        finally:
            vfs.close()

    @pytest.mark.forensic(
        category="Known-output Verification",
        subject="EnCase logical evidence (.L01)",
        desc="Every MD5 EnCase recorded for a file of the L01 matches the file as read",
    )
    def test_recorded_md5s_match(self, l01: Path) -> None:
        vfs = open_vfs(l01)
        try:
            result = vfs.verify_acquisition()
        finally:
            vfs.close()
        assert result["stored"] == {} and result["match"] is None  # no image hash in it
        assert result["entry_md5_checked"] == 108
        assert result["entry_md5_mismatched"] == []
        # What wasn't checked is counted: 9,342 entries with data (9,219
        # files and the own data of 123 entries with entries beneath them).
        assert result["entry_count"] == 9342
        assert result["entry_md5_missing"] == 9342 - 108
        assert result["entry_sha1_unchecked"] == 0

    def test_sparse_entry_reads_from_its_duplicate(self, l01: Path) -> None:
        vfs = open_vfs(l01)
        try:
            (node,) = [n for n in _files(vfs.root())
                       if isinstance(n.status, ParseIssue) and "entry.l01_sparse" in repr(n.status)]
            data = vfs.read(node)
            assert len(data) == node.size == 12288
            assert data.startswith(b"SQLite format 3\x00")
        finally:
            vfs.close()

    @pytest.mark.parametrize("name", ["evidence", "evidence.bin"])
    def test_without_a_segment_name_says_why(self, l01: Path, name: str) -> None:
        """Recognised by its content, but the reader finds an L01's segments
        by their names (.L01, .L02 ...), as for an E01; a file with no such
        name opens as a single file and says why -- never as part of a set
        it can't find."""
        renamed = l01.with_name(name)
        l01.rename(renamed)
        vfs = open_vfs(renamed)
        try:
            assert isinstance(vfs, FileVFS)
            note = vfs.fallback_note
            assert isinstance(note, ParseIssue) and note.code == "vfs.logical_not_opened"
            assert note.detail  # the reader's reason, verbatim
        finally:
            vfs.close()


# ---------------------------------------------------------------------------
# Tree rules, on entries no fixture has
# ---------------------------------------------------------------------------

def _entry(name: str, size: int = 0, children: list[Any] | None = None, **kw: Any) -> Any:
    return SimpleNamespace(
        name=name, size=size, children=children or [], is_folder=bool(children),
        times={}, md5=None, sha1=None, is_deleted=False, flags=0, duplicate_offset=None,
        values={}, **kw,
    )


def test_slash_in_name_and_repeated_names(tmp_path: Path) -> None:
    root = _entry("", children=[_entry("a/b", 1), _entry("same", 2), _entry("same", 3)])
    handle = LogicalHandle(path=tmp_path / "x.L01",
                           image=SimpleNamespace(format="EWF-L01", logical_root=root))
    tree = build_tree(handle)
    names = sorted(c.name for c in tree.children)
    assert names == ["a∕b", "same", "same (2)"]
    slash = _child(tree, "a∕b")
    assert isinstance(slash.status, ParseIssue) and slash.status.code == "entry.name_has_slash"
    for name in ("same", "same (2)"):
        status = _child(tree, name).status
        assert isinstance(status, ParseIssue) and status.code == "entry.duplicate"
    assert len(handle.entries) == 3


def test_browsable_by_content(tmp_path: Path, ad1_multi: Path, l01: Path) -> None:
    """Open in New Window offers an L01 or AD1 inside a folder, archive or
    image (any name); Lx01 isn't read."""
    assert is_browsable_source_file(ad1_multi)
    assert is_browsable_source_file(l01)
    lx01 = tmp_path / "x.Lx01"
    lx01.write_bytes(b"LEF2\x0d\x0a\x81\x00" + bytes(64))
    assert not is_browsable_source_file(lx01)


# ---------------------------------------------------------------------------
# The same guarantees as every other source (one test per subject and
# category: the coverage page reads literal markers)
# ---------------------------------------------------------------------------

def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _evidence(kind: str, tmp_path: Path) -> list[Path]:
    """The evidence files of the set -- first the one opened."""
    if kind == "l01":
        return _copy(tmp_path, "tracy-phone-2012-07-05-1640.L01.gz")
    return _copy(tmp_path, "lean-multi-ntfs-c9.ad1", "lean-multi-ntfs-c9.ad1.txt")


def _read_some(path: Path) -> None:
    vfs = open_vfs(path)
    assert isinstance(vfs, LogicalEvidenceVFS)
    try:
        for node in _files(vfs.root())[:40]:
            vfs.read(node)
            vfs.peek(node)
        vfs.verify_acquisition()
    finally:
        vfs.close()


def _check_unmodified(kind: str, tmp_path: Path) -> None:
    evidence = _evidence(kind, tmp_path)
    before = {p: _sha256(p) for p in evidence}
    _read_some(evidence[0])
    assert {p: _sha256(p) for p in evidence} == before


def _check_timestamps(kind: str, tmp_path: Path) -> None:
    evidence = _evidence(kind, tmp_path)
    before = {p: (p.stat().st_mtime_ns, p.stat().st_ctime_ns) for p in evidence}
    _read_some(evidence[0])
    assert {p: (p.stat().st_mtime_ns, p.stat().st_ctime_ns) for p in evidence} == before


def _check_no_siblings(kind: str, tmp_path: Path) -> None:
    evidence = _evidence(kind, tmp_path)
    before = set(evidence[0].parent.iterdir())
    _read_some(evidence[0])
    assert set(evidence[0].parent.iterdir()) == before


def _check_readonly(kind: str, tmp_path: Path) -> None:
    evidence = _evidence(kind, tmp_path)
    for p in evidence:
        p.chmod(0o444)
    try:
        _read_some(evidence[0])
    finally:
        for p in evidence:
            p.chmod(0o644)


def _check_reproducible(kind: str, tmp_path: Path) -> None:
    path = _evidence(kind, tmp_path)[0]

    def snapshot() -> list[tuple[str, int, str]]:
        vfs = open_vfs(path)
        try:
            return [(n.path, n.size, hashlib.sha256(vfs.read(n)).hexdigest())
                    for n in _files(vfs.root())[:200]]
        finally:
            vfs.close()

    assert snapshot() == snapshot()


@pytest.mark.forensic(
    category="Source Immutability",
    subject="EnCase logical evidence (.L01)",
    desc="Opening, reading and verifying an L01 leaves its bytes unchanged",
)
def test_l01_does_not_modify_source(tmp_path: Path) -> None:
    _check_unmodified("l01", tmp_path)


@pytest.mark.forensic(
    category="Source Immutability",
    subject="FTK Imager logical evidence (.ad1)",
    desc="Opening, reading and verifying an AD1 leaves its bytes and FTK Imager's log unchanged",
)
def test_ad1_does_not_modify_source(tmp_path: Path) -> None:
    _check_unmodified("ad1", tmp_path)


@pytest.mark.forensic(
    category="Source Immutability",
    subject="EnCase logical evidence (.L01)",
    desc="Opening, reading and verifying an L01 leaves its mtime and ctime unchanged",
)
def test_l01_does_not_change_timestamps(tmp_path: Path) -> None:
    _check_timestamps("l01", tmp_path)


@pytest.mark.forensic(
    category="Source Immutability",
    subject="FTK Imager logical evidence (.ad1)",
    desc="Opening, reading and verifying an AD1 leaves its and its log's mtime and ctime "
         "unchanged",
)
def test_ad1_does_not_change_timestamps(tmp_path: Path) -> None:
    _check_timestamps("ad1", tmp_path)


@pytest.mark.forensic(
    category="No Side Effects",
    subject="EnCase logical evidence (.L01)",
    desc="Opening, reading and verifying an L01 creates no files beside it",
)
def test_l01_creates_no_sibling_files(tmp_path: Path) -> None:
    _check_no_siblings("l01", tmp_path)


@pytest.mark.forensic(
    category="No Side Effects",
    subject="FTK Imager logical evidence (.ad1)",
    desc="Opening, reading and verifying an AD1 creates no files beside it",
)
def test_ad1_creates_no_sibling_files(tmp_path: Path) -> None:
    _check_no_siblings("ad1", tmp_path)


@pytest.mark.skipif(os.name == "nt", reason="chmod semantics differ on Windows")
@pytest.mark.forensic(
    category="Read-only Media",
    subject="EnCase logical evidence (.L01)",
    desc="An L01 opens, reads and verifies when its file is chmod 0o444",
)
def test_l01_works_on_readonly_media(tmp_path: Path) -> None:
    _check_readonly("l01", tmp_path)


@pytest.mark.skipif(os.name == "nt", reason="chmod semantics differ on Windows")
@pytest.mark.forensic(
    category="Read-only Media",
    subject="FTK Imager logical evidence (.ad1)",
    desc="An AD1 opens, reads and verifies when its files are chmod 0o444",
)
def test_ad1_works_on_readonly_media(tmp_path: Path) -> None:
    _check_readonly("ad1", tmp_path)


@pytest.mark.forensic(
    category="Reproducibility",
    subject="EnCase logical evidence (.L01)",
    desc="Opening an L01 twice gives the same tree and the same bytes",
)
def test_l01_reproducible(tmp_path: Path) -> None:
    _check_reproducible("l01", tmp_path)


@pytest.mark.forensic(
    category="Reproducibility",
    subject="FTK Imager logical evidence (.ad1)",
    desc="Opening an AD1 twice gives the same tree and the same bytes",
)
def test_ad1_reproducible(tmp_path: Path) -> None:
    _check_reproducible("ad1", tmp_path)
