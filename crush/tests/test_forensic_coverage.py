# SPDX-License-Identifier: Apache-2.0
"""crush/docs/forensic-test-coverage.md and the subject list behind it
(SUBJECT_GROUPS in forensic_report.py): the page is up to date, every
forensic marker names a known subject, and every source type, disk-image
filesystem and parser in the code has a subject -- so nothing Crush reads
is missing from the page."""
from __future__ import annotations

import importlib
import importlib.util
import inspect
import pkgutil
import sys
from pathlib import Path

import crush.parsers
from crush.core import raw_image  # registers the vendored ewfprobe qnxprobe imports
from crush.core import ufd  # its sources subclass VFS: counted whatever ran before
from crush.core import vfs as vfs_module
from crush.parsers.base import AbstractParser
from crush.tests import forensic_report

ROOT = Path(__file__).resolve().parents[2]
qnxprobe_module = importlib.import_module("crush.third_party.qnxprobe.qnxprobe")
assert raw_image and ufd

def _load_script():
    spec = importlib.util.spec_from_file_location(
        "forensic_coverage_script", ROOT / "scripts" / "forensic_coverage.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # @dataclass looks its module up there
    spec.loader.exec_module(module)
    return module


cov = _load_script()

# Which subjects stand for which code. Each class is one source type, filesystem
# walker or parser; a subject may cover several classes and a class several subjects.
VFS_SUBJECTS: dict[str, tuple[str, ...]] = {
    "DirectoryVFS": ("Folder",),
    "FileVFS": ("Single file",),
    "ZipVFS": ("ZIP archive",),
    "SevenZipVFS": ("7z archive",),
    "TarVFS": ("TAR archive",),
    "GzipVFS": ("gzip file",),
    "AndroidBackupVFS": ("Android backup (.ab)",),
    "ITunesBackupVFS": ("iTunes backup",),
    "ZipWithITunesBackupVFS": ("iTunes backup",),
    "UFDRVFS": ("Cellebrite UFDR",),
    "UFDVFS": ("Cellebrite UFD",),
    "UFDXVFS": ("Cellebrite UFDX",),
    "LogicalEvidenceVFS": ("EnCase logical evidence (.L01)", "FTK Imager logical evidence (.ad1)"),
    "RawImageVFS": (
        "Raw disk image", "EWF acquisition (.E01)", "SMART acquisition (.s01)",
        "EWF2 acquisition (.Ex01)", "AFF acquisition (.aff/.afd)", "AFF4 acquisition (.aff4)",
        "Apple disk image (.dmg/.sparseimage/.sparsebundle)", "VHD/VHDX virtual disk",
        "VMDK virtual disk",
        "QCOW virtual disk",
    ),
}
# VFS classes that aren't a source of evidence, and why.
NOT_A_SOURCE: dict[str, str] = {
    "BytesVFS": "holds bytes Crush has already read (e.g. a BLOB opened as a file)",
    "_MountVFS": "the base of UFDVFS/UFDXVFS (other sources' trees in one), never opened itself",
}
WALKER_SUBJECTS: dict[str, tuple[str, ...]] = {
    "NtfsWalker": ("NTFS",),
    "Fat32Walker": ("FAT32",),
    "ExfatWalker": ("exFAT",),
    "ExtWalker": ("ext2/3/4",),
    "F2fsWalker": ("F2FS",),
    "HfsPlusWalker": ("HFS+",),
    "ApfsWalker": ("APFS",),
    "Qnx6Walker": ("QNX6",),
    "Qnx4Walker": ("QNX4",),
    "IfsWalker": ("QNX IFS",),
    "EtfsWalker": ("ETFS",),
    "EfsWalker": ("EFS",),
    "SquashfsWalker": ("SquashFS",),
    "Jffs2Walker": ("JFFS2",),
    "UbiWalker": ("UBI",),
    "UbifsWalker": ("UBIFS",),
    "YaffsWalker": ("YAFFS1/YAFFS2",),
    "ConfigStoreWalker": ("U-Boot environment / NVRAM store",),
}
PARSER_SUBJECTS: dict[str, tuple[str, ...]] = {
    "SQLiteParser": ("SQLite database",),
    "SQLiteWALParser": ("SQLite WAL",),
    "SQLiteJournalParser": ("SQLite rollback journal",),
    "RealmParser": ("Realm database",),
    "LeveldbParser": ("LevelDB",),
    "MMKVParser": ("MMKV",),
    "PlistParser": ("Property list (plist)",),
    "AbxParser": ("Android Binary XML (ABX)",),
    "SegbParser": ("SEGB",),
    "XmlParser": ("XML",),
    "JsonParser": ("JSON",),
    "ProtobufParser": ("Protobuf", "Protobuf with .proto schema"),
    "PDFParser": ("PDF",),
    "ImageParser": ("Image", "Apple ATX", "Apple KTX"),
    "MediaParser": ("Audio/video",),
    "LogParser": ("Log file",),
    "HexFallbackParser": ("Hex view (any file)",),
}
# Subjects with no class of their own to check against.
TOOL_SUBJECTS = ("BLOB Inspector", "Value Inspector", "Multi-Log Studio")


def _subclasses(base: type) -> set[str]:
    """Names of every subclass of base in Crush itself -- not the stand-ins
    other test modules define."""
    found: set[str] = set()
    todo = [base]
    while todo:
        for sub in todo.pop().__subclasses__():
            if sub.__module__.startswith("crush.tests"):
                continue
            if sub.__name__ not in found:
                found.add(sub.__name__)
                todo.append(sub)
    return found


def test_generated_page_is_up_to_date() -> None:
    assert cov.OUTPUT.read_text(encoding="utf-8") == cov.build(cov.collect()), (
        "crush/docs/forensic-test-coverage.md is out of date -- run: "
        "python scripts/forensic_coverage.py build"
    )


def test_every_marker_names_a_known_category_and_subject() -> None:
    checks = cov.collect()
    assert checks
    assert cov.problems(checks) == []


def test_every_source_type_has_a_subject() -> None:
    assert _subclasses(vfs_module.VFS) == set(VFS_SUBJECTS) | set(NOT_A_SOURCE)


def test_every_disk_image_filesystem_has_a_subject() -> None:
    walkers = {
        name for name, obj in inspect.getmembers(qnxprobe_module, inspect.isclass)
        if name.endswith("Walker")
    }
    assert walkers == set(WALKER_SUBJECTS)


def test_every_parser_has_a_subject() -> None:
    for info in pkgutil.iter_modules(crush.parsers.__path__):
        importlib.import_module(f"crush.parsers.{info.name}")
    assert _subclasses(AbstractParser) == set(PARSER_SUBJECTS)


def test_subject_list_matches_the_code() -> None:
    anchored = {
        s for mapping in (VFS_SUBJECTS, WALKER_SUBJECTS, PARSER_SUBJECTS)
        for subjects in mapping.values() for s in subjects
    }
    assert set(forensic_report.SUBJECTS) == anchored | set(TOOL_SUBJECTS)
    assert len(forensic_report.SUBJECTS) == len(set(forensic_report.SUBJECTS))


def test_not_applicable_entries_are_known() -> None:
    for subject, category in forensic_report.NOT_APPLICABLE:
        assert subject in forensic_report.SUBJECTS
        assert category in forensic_report.CATEGORY_ORDER


def test_subject_links_are_unique() -> None:
    headings = ["Categories", "Overview", "Checks", *forensic_report.SUBJECT_GROUPS]
    anchors = [cov.anchor(s) for s in forensic_report.SUBJECTS]
    assert len(anchors) == len(set(anchors))
    assert not set(anchors) & {cov.anchor(h) for h in headings}
