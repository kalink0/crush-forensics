# SPDX-License-Identifier: Apache-2.0
"""Tests for opening a Cellebrite UFD/UFDX as the extraction it describes.

Synthetic files, shaped like real ones: two UFED .ufd (UfdVer 1.2, a
FileDump and a KeyStore dump in one ZIP, `Dump/` and `extra/`), a UFED
.ufdx listing one extraction by a Windows path, and a UFADE .ufd whose ZIP
holds an encrypted iTunes backup under
`iPhoneDump/Backup Service/<UDID>/Snapshot/` with its BackupPassword.
"""
from __future__ import annotations

import codecs
import hashlib
import os
import zipfile
from pathlib import Path
from typing import Any

import pytest

from crush.core.passwords import PasswordRequiredError, WrongPasswordError
from crush.core.ufd import UFDVFS, UFDXVFS, is_ufd, is_ufdx
from crush.core.vfs import FileVFS, ITunesBackupVFS, VFSNode, open_vfs

UFED_UFD = """[DeviceInfo]
IMEI1=354977438494370
Model=Pixel 7a
OS=Android 14
Vendor=Google

[Dumps]
FileDump=EXTRACTION_FFS.zip
KeyStore=EXTRACTION_FFS.zip

[ExtractionStatus]
ExtractionStatus=Success

[FileDump]
Type=ZIPfolder
ZIPLogicalPath=Dump

[General]
AcquisitionTool=Inseyets UFED_Pro_Advanced
Date=28/07/2024 07:27:27 (-4)
EndTime=28/07/2024 08:38:16 (-4)
UfdVer=1.2

[KeyStore]
Type=ZIPfolder
ZIPLogicalPath=extra

[SHA256]
EXTRACTION_FFS.zip={zip_sha}

[Hash]
HMAC=VAlY9hB4f+5Y6GJuJifsQdVsjyWgvOxTPcUZqDNSQ/0=
"""


def _zip(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return path


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def _ufed(tmp_path: Path, members: dict[str, bytes] | None = None, *, text: str = UFED_UFD,
          name: str = "EXTRACTION_FFS.ufd", encoding: str = "ascii", crlf: bool = True) -> Path:
    zip_path = _zip(tmp_path / "EXTRACTION_FFS.zip", members if members is not None else {
        "Dump/data/data/com.example/databases/a.db": b"SQLite format 3\x00",
        "Dump/system/build.prop": b"ro.build=1",
        "extra/Secrets/secrets.json": b"{}",
    })
    body = text.replace("{zip_sha}", _sha256(zip_path))
    if crlf:
        body = body.replace("\n", "\r\n")
    raw = body.encode(encoding)
    if encoding == "utf-16-le":
        raw = codecs.BOM_UTF16_LE + raw
    ufd = tmp_path / name
    ufd.write_bytes(raw)
    return ufd


def _find(node: VFSNode, *parts: str) -> VFSNode:
    for part in parts:
        node = next(c for c in node.children if c.name == part)
    return node


def _names(node: VFSNode) -> list[str]:
    return [c.name for c in node.children]


# -- Opening and tree -----------------------------------------------------------


def test_ufd_opens_its_dumps_as_folders_named_after_them(tmp_path: Path) -> None:
    vfs = open_vfs(_ufed(tmp_path))
    assert isinstance(vfs, UFDVFS)
    root = vfs.root()
    assert _names(root) == ["FileDump", "KeyStore"]
    file_dump, key_store = root.children
    assert str(file_dump.status) == "Folder Dump of EXTRACTION_FFS.zip, as the UFD names it"
    assert _names(file_dump) == ["data", "system"]
    db = _find(file_dump, "data", "data", "com.example", "databases", "a.db")
    assert db.path == "/FileDump/data/data/com.example/databases/a.db"
    assert vfs.read(db) == b"SQLite format 3\x00"
    assert vfs.peek(db, 6) == b"SQLite"
    with vfs.open(db) as f:
        assert f.read() == b"SQLite format 3\x00"
    assert _names(_find(key_store, "Secrets")) == ["secrets.json"]
    assert vfs.file_count(root) == 3
    vfs.close()


def test_ufd_root_shows_every_recorded_value_as_written(tmp_path: Path) -> None:
    vfs = open_vfs(_ufed(tmp_path))
    info = vfs.node_info(vfs.root())  # type: ignore[attr-defined]
    assert info["General / Date"] == "28/07/2024 07:27:27 (-4)"  # offset kept, nothing converted
    assert info["DeviceInfo / IMEI1"] == "354977438494370"
    assert info["Hash / HMAC"] == "VAlY9hB4f+5Y6GJuJifsQdVsjyWgvOxTPcUZqDNSQ/0="
    assert list(info)[0] == "DeviceInfo / IMEI1"  # file order
    vfs.close()


@pytest.mark.parametrize("name", ["EXTRACTION_FFS.ufd", "renamed.txt", "no_extension"])
def test_ufd_is_recognised_by_content(tmp_path: Path, name: str) -> None:
    ufd = _ufed(tmp_path, name=name)
    assert is_ufd(ufd)
    assert isinstance(open_vfs(ufd), UFDVFS)


def test_ufd_with_utf16_bom_and_lf_lines(tmp_path: Path) -> None:
    vfs = open_vfs(_ufed(tmp_path, encoding="utf-16-le", crlf=False))
    assert isinstance(vfs, UFDVFS)
    assert _names(vfs.root()) == ["FileDump", "KeyStore"]
    vfs.close()


def test_other_ini_file_is_not_a_ufd(tmp_path: Path) -> None:
    ini = tmp_path / "settings.ini"
    ini.write_text("[General]\nTheme=dark\n")
    assert not is_ufd(ini)
    assert isinstance(open_vfs(ini), FileVFS)


def test_missing_zip_unsupported_type_and_missing_folder_are_explicit(tmp_path: Path) -> None:
    text = UFED_UFD.replace("KeyStore=EXTRACTION_FFS.zip", "KeyStore=EXTRACTION_FFS.zip\n"
                            "Physical=EXTRACTION_PHY.bin\nGone=missing.zip\nOdd=EXTRACTION_FFS.zip")
    text = text.replace("ZIPLogicalPath=extra", "ZIPLogicalPath=nope")
    text += "\n[Physical]\nType=Binary\n"
    _zip(tmp_path / "EXTRACTION_PHY.bin", {"x": b"x"})
    vfs = open_vfs(_ufed(tmp_path, text=text))
    root = vfs.root()
    assert _names(root) == ["FileDump", "KeyStore", "Physical", "Gone", "Odd",
                            "(other content of EXTRACTION_FFS.zip)"]
    key_store, physical, gone, odd = root.children[1:5]
    assert str(key_store.status) == (
        "The UFD names folder nope of EXTRACTION_FFS.zip for this dump; the ZIP has no such folder"
    )
    assert str(physical.status) == (
        'Dump type "Binary" (EXTRACTION_PHY.bin) isn\'t read; only ZIPfolder is supported'
    )
    assert str(gone.status) == "The UFD names missing.zip for this dump; it isn't beside the UFD"
    assert str(odd.status) == (
        "The UFD names EXTRACTION_FFS.zip for this dump but has no section saying how to read it"
    )
    # extra/ is no dump's folder any more: shown, not dropped.
    other = root.children[5]
    assert _names(other) == ["extra"]
    vfs.close()


def test_zip_content_outside_the_dumps_is_shown_apart(tmp_path: Path) -> None:
    vfs = open_vfs(_ufed(tmp_path, {
        "Dump/a.txt": b"a",
        "extra/k": b"k",
        "readme.txt": b"loose",
        "empty_dir/": b"",
    }))
    other = _find(vfs.root(), "(other content of EXTRACTION_FFS.zip)")
    assert str(other.status) == (
        "What EXTRACTION_FFS.zip holds outside the folders the UFD names for its dumps"
    )
    # Neither Dump/ nor extra/ again; a folder empty in the ZIP itself stays.
    assert _names(other) == ["empty_dir", "readme.txt"]
    assert vfs.read(_find(other, "readme.txt")) == b"loose"
    vfs.close()


def test_nested_dump_folder_leaves_its_siblings_in_other_content(tmp_path: Path) -> None:
    text = UFED_UFD.replace("ZIPLogicalPath=Dump", "ZIPLogicalPath=out\\Dump")
    vfs = open_vfs(_ufed(tmp_path, {
        "out/Dump/a.txt": b"a", "out/log.txt": b"log", "extra/k": b"k",
    }, text=text))
    assert _names(_find(vfs.root(), "FileDump")) == ["a.txt"]
    other = _find(vfs.root(), "(other content of EXTRACTION_FFS.zip)")
    assert _names(_find(other, "out")) == ["log.txt"]
    vfs.close()


def test_dump_file_must_match_its_name_exactly(tmp_path: Path) -> None:
    # The tool that wrote the .ufd wrote the file: a name differing in
    # case is another file, not looked for.
    text = UFED_UFD.replace("FileDump=EXTRACTION_FFS.zip", "FileDump=extraction_ffs.ZIP")
    vfs = open_vfs(_ufed(tmp_path, text=text))
    assert str(_find(vfs.root(), "FileDump").status) == (
        "The UFD names extraction_ffs.ZIP for this dump; it isn't beside the UFD"
    )
    vfs.close()


# -- Verify Acquisition Hash ----------------------------------------------------


def test_verify_checks_each_recorded_file_hash(tmp_path: Path) -> None:
    vfs = open_vfs(_ufed(tmp_path))
    assert vfs.acquisition() == "UFD"
    result = vfs.verify_acquisition()
    assert result["match"] is True
    [entry] = result["recorded_files"]
    assert entry["name"] == "EXTRACTION_FFS.zip" and entry["match"]
    assert result["recorded_hmac"] == "VAlY9hB4f+5Y6GJuJifsQdVsjyWgvOxTPcUZqDNSQ/0="
    vfs.close()


def test_verify_reports_changed_and_missing_files(tmp_path: Path) -> None:
    text = UFED_UFD.replace(
        "EXTRACTION_FFS.zip={zip_sha}",
        "EXTRACTION_FFS.zip=" + "0" * 64 + "\nSummaryReport.pdf=" + "1" * 64,
    )
    vfs = open_vfs(_ufed(tmp_path, text=text))
    result = vfs.verify_acquisition()
    assert result["match"] is False
    zip_entry, pdf_entry = result["recorded_files"]
    assert zip_entry["found"] and not zip_entry["match"] and zip_entry["computed"]
    assert not pdf_entry["found"] and pdf_entry["computed"] is None
    vfs.close()


def test_verify_report_names_the_hmac_as_not_checked(tmp_path: Path) -> None:
    from crush.ui.verify_result_dialog import verify_report_html

    vfs = open_vfs(_ufed(tmp_path))
    report = verify_report_html(vfs.verify_acquisition(), [])
    assert "MATCH — every file hash the acquisition recorded matches its file" in report
    assert "EXTRACTION_FFS.zip (SHA-256)" in report
    assert "can&#x27;t be recomputed: not checked" in report or "can't be recomputed: not checked" in report
    vfs.close()


# -- UFDX -----------------------------------------------------------------------


UFDX = """<?xml version="1.0"?>
<EvidenceCollection xmlns:xsd="http://www.w3.org/2001/XMLSchema" EvidenceID="45f159bd">
  <DeviceInfo Vendor="Google" Model="Pixel 7a" Guid="98ec76e1" />
  <Extractions>
    <Extraction TransferType="FileSystemDump" Path="EXTRACTION_FFS 01\\EXTRACTION_FFS.ufd" />
    <Extraction TransferType="Logical" Path="EXTRACTION_LOG 02\\EXTRACTION_LOG.ufd" />
  </Extractions>
</EvidenceCollection>
"""


def _ufdx(tmp_path: Path) -> Path:
    """A .ufdx, its extraction folder with .ufd and ZIP, in *tmp_path*/evidence."""
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    ext = evidence / "EXTRACTION_FFS 01"
    ext.mkdir()
    _ufed(ext)
    ufdx = evidence / "EvidenceCollection.ufdx"
    ufdx.write_text(UFDX.replace("\n", "\r\n"))
    return ufdx


def test_ufdx_opens_each_listed_extraction(tmp_path: Path) -> None:
    ufdx = _ufdx(tmp_path)
    assert is_ufdx(ufdx)
    vfs = open_vfs(ufdx)
    assert isinstance(vfs, UFDXVFS)
    root = vfs.root()
    assert _names(root) == ["EXTRACTION_FFS 01", "EXTRACTION_LOG 02"]
    ffs, log = root.children
    assert str(ffs.status) == (
        "Extraction EXTRACTION_FFS 01\\EXTRACTION_FFS.ufd (FileSystemDump), as the UFDX lists it"
    )
    assert _names(ffs) == ["FileDump", "KeyStore"]
    db = _find(ffs, "FileDump", "data", "data", "com.example", "databases", "a.db")
    assert vfs.read(db) == b"SQLite format 3\x00"
    assert str(log.status) == (
        "The UFDX lists extraction EXTRACTION_LOG 02\\EXTRACTION_LOG.ufd (Logical); it isn't there"
    )
    info = vfs.node_info(root)  # type: ignore[attr-defined]
    assert info["DeviceInfo / Model"] == "Pixel 7a"
    assert vfs.node_info(ffs)["General / UfdVer"] == "1.2"  # type: ignore[attr-defined]
    vfs.close()


def test_ufdx_verify_covers_every_extraction(tmp_path: Path) -> None:
    vfs = open_vfs(_ufdx(tmp_path))
    assert vfs.acquisition() == "UFDX"
    result = vfs.verify_acquisition()
    assert [f["name"] for f in result["recorded_files"]] == ["EXTRACTION_FFS 01/EXTRACTION_FFS.zip"]
    assert result["match"] is True
    vfs.close()


# -- iTunes backup in a dump (UFADE) ---------------------------------------------


UFADE_UFD = """[DeviceInfo]
Model=iPhone12,8
Vendor=Apple

[Dumps]
FileDump=Apple_iPhone.zip

[FileDump]
Type=ZIPfolder
ZIPLogicalPath=iPhoneDump

[General]
AcquisitionTool=UFADE
BackupPassword={password}
IsEncrypted=True
UfdVer=1.2

[SHA256]
Apple_iPhone.zip={zip_sha}
"""

UDID = "00008030-000A2D6E3601C01F"


def _ufade(tmp_path: Path, factory: Any, *, backup_password: str, ufd_password: str) -> Path:
    """A UFADE .ufd and its ZIP in *tmp_path*/evidence (the backup is built
    beside it, so the evidence folder holds only the evidence)."""
    build = tmp_path / "build"
    build.mkdir()
    backup: Path = factory(build, password=backup_password)
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    members: dict[str, bytes] = {
        "iPhoneDump/Lockdown Service/PhoneInfo.xml": b"<PhoneInfo/>",
        "iPhoneDump/AFC Service/Downloads/x.txt": b"x",
    }
    for f in backup.rglob("*"):
        if f.is_file():
            members[f"iPhoneDump/Backup Service/{UDID}/Snapshot/{f.relative_to(backup).as_posix()}"] = (
                f.read_bytes()
            )
    zip_path = _zip(evidence / "Apple_iPhone.zip", members)
    ufd = evidence / "Apple_iPhone.ufd"
    ufd.write_text(
        UFADE_UFD.replace("{password}", ufd_password).replace("{zip_sha}", _sha256(zip_path))
    )
    return ufd


def test_itunes_backup_in_a_dump_opens_with_the_ufds_backup_password(
    tmp_path: Path, itunes_backup_keybag_factory: Any,
) -> None:
    ufd = _ufade(tmp_path, itunes_backup_keybag_factory, backup_password="12345", ufd_password="12345")
    vfs = open_vfs(ufd)
    dump = _find(vfs.root(), "FileDump")
    assert _names(dump) == ["AFC Service", "Backup Service", "Lockdown Service"]
    snapshot = _find(dump, "Backup Service", UDID, "Snapshot")
    assert str(snapshot.status).startswith(
        "An iTunes backup, opened as one (with the BackupPassword the UFD records)"
    )
    sms = _find(snapshot, "HomeDomain", "Library", "SMS", "sms.db")
    assert vfs.read(sms) == b"SQLite format 3\x00"
    inner_vfs, inner = vfs.delegate(sms)
    assert isinstance(inner_vfs, ITunesBackupVFS)
    assert inner_vfs.original_backup_path(inner) == "3d/3d0d7e5fb2ce288813306e4d0f11ac329e64a91d"
    notes = _find(snapshot, "HomeDomain", "Library", "Notes", "notes.sqlite")
    assert vfs.read(notes) == b"protected note content" * 4
    vfs.close()


def test_wrong_ufd_backup_password_asks_and_typed_one_opens(
    tmp_path: Path, itunes_backup_keybag_factory: Any,
) -> None:
    ufd = _ufade(tmp_path, itunes_backup_keybag_factory, backup_password="secret", ufd_password="12345")
    with pytest.raises(WrongPasswordError, match="BackupPassword the UFD records doesn't open"):
        open_vfs(ufd)
    vfs = open_vfs(ufd, password="secret")
    snapshot = _find(vfs.root(), "FileDump", "Backup Service", UDID, "Snapshot")
    assert "(with the password entered)" in str(snapshot.status)
    vfs.close()


def test_no_backup_password_recorded_asks_for_one(
    tmp_path: Path, itunes_backup_keybag_factory: Any,
) -> None:
    ufd = _ufade(tmp_path, itunes_backup_keybag_factory, backup_password="secret", ufd_password="")
    with pytest.raises(PasswordRequiredError):
        open_vfs(ufd)


def test_only_the_backups_members_are_extracted(
    tmp_path: Path, itunes_backup_keybag_factory: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    ufd = _ufade(tmp_path, itunes_backup_keybag_factory, backup_password="12345", ufd_password="12345")
    extracted: list[str] = []
    real = zipfile.ZipFile.extract

    def spy(self: zipfile.ZipFile, member: Any, path: Any = None, pwd: Any = None) -> str:
        extracted.append(member.filename if isinstance(member, zipfile.ZipInfo) else member)
        return real(self, member, path, pwd)

    monkeypatch.setattr(zipfile.ZipFile, "extract", spy)
    open_vfs(ufd).close()
    assert extracted and all(n.startswith(f"iPhoneDump/Backup Service/{UDID}/Snapshot/") for n in extracted)


# ---------------------------------------------------------------------------
# The same guarantees as every other source (one test per subject and
# category: the coverage page reads literal markers). The UFD is UFADE's,
# whose iTunes backup is extracted to the temp directory on opening; the
# UFDX lists a UFED extraction.
# ---------------------------------------------------------------------------


def _evidence(kind: str, tmp_path: Path, factory: Any) -> Path:
    """The file opened; every file of its folder is evidence."""
    if kind == "ufd":
        return _ufade(tmp_path, factory, backup_password="12345", ufd_password="12345")
    return _ufdx(tmp_path)


def _evidence_files(opened: Path) -> list[Path]:
    return sorted(p for p in opened.parent.rglob("*") if p.is_file())


def _files_of(node: VFSNode) -> list[VFSNode]:
    if not node.is_dir:
        return [node]
    return [f for c in node.children for f in _files_of(c)]


def _read_all(opened: Path) -> None:
    """Open, read and peek every file, and verify."""
    vfs = open_vfs(opened)
    try:
        for node in _files_of(vfs.root()):
            vfs.read(node)
            vfs.peek(node)
        vfs.verify_acquisition()
    finally:
        vfs.close()


def _check_unmodified(kind: str, tmp_path: Path, factory: Any) -> None:
    opened = _evidence(kind, tmp_path, factory)
    before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in _evidence_files(opened)}
    _read_all(opened)
    assert {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in _evidence_files(opened)} == before


def _check_timestamps(kind: str, tmp_path: Path, factory: Any) -> None:
    opened = _evidence(kind, tmp_path, factory)
    before = {p: (p.stat().st_mtime_ns, p.stat().st_ctime_ns) for p in _evidence_files(opened)}
    _read_all(opened)
    assert {p: (p.stat().st_mtime_ns, p.stat().st_ctime_ns) for p in _evidence_files(opened)} == before


def _check_no_siblings(kind: str, tmp_path: Path, factory: Any) -> None:
    opened = _evidence(kind, tmp_path, factory)
    before = set(opened.parent.rglob("*"))
    _read_all(opened)
    assert set(opened.parent.rglob("*")) == before


def _check_readonly(kind: str, tmp_path: Path, factory: Any) -> None:
    """Files 0o444 and their folders 0o555: also proves that nothing --
    the extracted iTunes backup included -- is written beside the evidence."""
    opened = _evidence(kind, tmp_path, factory)
    dirs = sorted({p.parent for p in _evidence_files(opened)}, key=lambda d: len(d.parts))
    for p in _evidence_files(opened):
        p.chmod(0o444)
    for d in reversed(dirs):
        d.chmod(0o555)
    try:
        _read_all(opened)
    finally:
        for d in dirs:
            d.chmod(0o755)
        for p in _evidence_files(opened):
            p.chmod(0o644)


def _check_reproducible(kind: str, tmp_path: Path, factory: Any) -> None:
    opened = _evidence(kind, tmp_path, factory)

    def snapshot() -> list[tuple[str, int, str, str]]:
        vfs = open_vfs(opened)
        try:
            return [(n.path, n.size, str(n.status), hashlib.sha256(vfs.read(n)).hexdigest())
                    for n in _files_of(vfs.root())]
        finally:
            vfs.close()

    assert snapshot() == snapshot()


@pytest.mark.forensic(
    category="Source Immutability",
    subject="Cellebrite UFD",
    desc="Opening, reading and verifying a UFD (with an iTunes backup in its dump) leaves the "
         ".ufd and its ZIP unchanged",
)
def test_ufd_does_not_modify_source(tmp_path: Path, itunes_backup_keybag_factory: Any) -> None:
    _check_unmodified("ufd", tmp_path, itunes_backup_keybag_factory)


@pytest.mark.forensic(
    category="Source Immutability",
    subject="Cellebrite UFDX",
    desc="Opening, reading and verifying a UFDX leaves the .ufdx, its .ufd and ZIP unchanged",
)
def test_ufdx_does_not_modify_source(tmp_path: Path, itunes_backup_keybag_factory: Any) -> None:
    _check_unmodified("ufdx", tmp_path, itunes_backup_keybag_factory)


@pytest.mark.forensic(
    category="Source Immutability",
    subject="Cellebrite UFD",
    desc="Opening, reading and verifying a UFD leaves the mtime and ctime of the .ufd and its "
         "ZIP unchanged",
)
def test_ufd_does_not_change_timestamps(tmp_path: Path, itunes_backup_keybag_factory: Any) -> None:
    _check_timestamps("ufd", tmp_path, itunes_backup_keybag_factory)


@pytest.mark.forensic(
    category="Source Immutability",
    subject="Cellebrite UFDX",
    desc="Opening, reading and verifying a UFDX leaves the mtime and ctime of all its files "
         "unchanged",
)
def test_ufdx_does_not_change_timestamps(tmp_path: Path, itunes_backup_keybag_factory: Any) -> None:
    _check_timestamps("ufdx", tmp_path, itunes_backup_keybag_factory)


@pytest.mark.forensic(
    category="No Side Effects",
    subject="Cellebrite UFD",
    desc="Opening, reading and verifying a UFD creates no files beside it, the extracted "
         "iTunes backup included",
)
def test_ufd_creates_no_sibling_files(tmp_path: Path, itunes_backup_keybag_factory: Any) -> None:
    _check_no_siblings("ufd", tmp_path, itunes_backup_keybag_factory)


@pytest.mark.forensic(
    category="No Side Effects",
    subject="Cellebrite UFDX",
    desc="Opening, reading and verifying a UFDX creates no files in or beside its folders",
)
def test_ufdx_creates_no_sibling_files(tmp_path: Path, itunes_backup_keybag_factory: Any) -> None:
    _check_no_siblings("ufdx", tmp_path, itunes_backup_keybag_factory)


@pytest.mark.skipif(os.name == "nt", reason="chmod semantics differ on Windows")
@pytest.mark.forensic(
    category="Read-only Media",
    subject="Cellebrite UFD",
    desc="A UFD opens, reads and verifies, its iTunes backup included, with its files 0o444 "
         "and their folder 0o555",
)
def test_ufd_works_on_readonly_media(tmp_path: Path, itunes_backup_keybag_factory: Any) -> None:
    _check_readonly("ufd", tmp_path, itunes_backup_keybag_factory)


@pytest.mark.skipif(os.name == "nt", reason="chmod semantics differ on Windows")
@pytest.mark.forensic(
    category="Read-only Media",
    subject="Cellebrite UFDX",
    desc="A UFDX opens, reads and verifies with its files 0o444 and their folders 0o555",
)
def test_ufdx_works_on_readonly_media(tmp_path: Path, itunes_backup_keybag_factory: Any) -> None:
    _check_readonly("ufdx", tmp_path, itunes_backup_keybag_factory)


@pytest.mark.forensic(
    category="Reproducibility",
    subject="Cellebrite UFD",
    desc="Opening a UFD twice gives the same tree, statuses and bytes",
)
def test_ufd_reproducible(tmp_path: Path, itunes_backup_keybag_factory: Any) -> None:
    _check_reproducible("ufd", tmp_path, itunes_backup_keybag_factory)


@pytest.mark.forensic(
    category="Reproducibility",
    subject="Cellebrite UFDX",
    desc="Opening a UFDX twice gives the same tree, statuses and bytes",
)
def test_ufdx_reproducible(tmp_path: Path, itunes_backup_keybag_factory: Any) -> None:
    _check_reproducible("ufdx", tmp_path, itunes_backup_keybag_factory)
