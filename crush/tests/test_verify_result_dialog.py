# SPDX-License-Identifier: Apache-2.0
"""The Verify Acquisition Hash result: one block per check, the stored and
the recomputed value each on a line of its own and in full, the recomputed
one marked green when it matches and red when it doesn't."""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest
from PySide6.QtWidgets import QApplication

from crush.core.vfs import RawImageVFS, open_vfs
from crush.tests.conftest import FIXTURES_DIR
from crush.ui.main_window import verify_status_tag
from crush.ui.verify_result_dialog import VerifyResultDialog, verify_report_html

_GREEN = "#2e7d32"
_RED = "#c62828"


def test_udif_checks_each_in_a_block_of_their_own(tmp_path: Path) -> None:
    """dmg-udzo.dmg (hdiutil) records no hash of the disk, and a data, a
    block table and a master checksum: each is listed with both values,
    every one marked as matching."""
    path = tmp_path / "dmg-udzo.dmg"
    shutil.copy(FIXTURES_DIR / "acquisition" / "dmg-udzo.dmg", path)
    vfs = open_vfs(path, as_disk_image=True)
    try:
        assert isinstance(vfs, RawImageVFS)
        result = vfs.verify_acquisition()
    finally:
        vfs.close()
    report = verify_report_html(result, [])
    assert "recorded no hash of the whole disk" in report
    checks = result["container_checks"]
    assert len(checks) >= 3
    for check in checks:
        assert f"<b>{check['what']} ({check['algorithm']})</b>" in report
        assert f"<code>{check['stored']}</code>" in report
    assert report.count("✓") == len(checks)
    assert _RED not in report and "MISMATCH" not in report


def test_whole_disk_hashes_match_in_green() -> None:
    result = {
        "stored": {"MD5": "aa" * 16, "SHA1": "bb" * 20},
        "computed": {"MD5": "aa" * 16, "SHA1": "bb" * 20},
        "match": True,
    }
    report = verify_report_html(result, [])
    assert "MATCH — the acquisition's own recorded hash matches its data" in report
    assert "Hash of the whole disk" in report
    assert report.count(f"color:{_GREEN}'><code>") == 2
    assert "aa" * 16 in report and "bb" * 20 in report


def test_mismatch_shows_both_values_in_full_and_red() -> None:
    result = {
        "stored": {"MD5": "aa" * 16},
        "computed": {"MD5": "cc" * 16},
        "match": False,
        "container_checks": [
            {"what": "master", "algorithm": "CRC32", "stored": "deadbeef",
             "computed": "00c0ffee", "match": False},
        ],
    }
    report = verify_report_html(result, ["1 of the container's own checks do not match."])
    assert "MISMATCH — the acquisition's data does not match" in report
    assert "aa" * 16 in report and "cc" * 16 in report
    assert f"color:{_RED}'><code>{'cc' * 16}</code> <b>✗ MISMATCH</b>" in report
    assert f"color:{_RED}'><code>00c0ffee</code> <b>✗ MISMATCH</b>" in report
    assert "1 of the container's own checks do not match." in report


def test_stored_hash_not_computed_says_so() -> None:
    result = {"stored": {"SHA256": "dd" * 32}, "computed": {}, "match": None}
    report = verify_report_html(result, [])
    assert "(not computed)" in report and "✗ MISMATCH" in report


def test_names_from_the_container_are_escaped() -> None:
    """A block table's name comes from the image: shown as text, never
    as markup."""
    result = {
        "stored": {}, "computed": {}, "match": None,
        "container_checks": [
            {"what": "block table <b>x</b>", "algorithm": "CRC32", "stored": "1",
             "computed": "1", "match": True},
        ],
    }
    report = verify_report_html(result, [])
    assert "block table &lt;b&gt;x&lt;/b&gt;" in report
    assert "recorded no hash of the whole disk" in report


def test_no_hash_and_no_checks_says_so() -> None:
    report = verify_report_html({"stored": {}, "computed": {}, "match": None}, [])
    assert "This acquisition recorded no hash to verify against." in report


def test_ad1_names_the_log_its_hash_comes_from(tmp_path: Path) -> None:
    """An AD1 doesn't hold its image hash: the report names FTK Imager's log
    it was read from, and lists the files' recorded hashes checked."""
    logical = FIXTURES_DIR / "acquisition" / "logical"
    for name in ("lean-multi-ntfs-c9.ad1", "lean-multi-ntfs-c9.ad1.txt"):
        shutil.copy(logical / name, tmp_path / name)
    vfs = open_vfs(tmp_path / "lean-multi-ntfs-c9.ad1")
    try:
        result = vfs.verify_acquisition()
    finally:
        vfs.close()
    report = verify_report_html(result, [], holds_files=True)
    assert "FTK Imager's log beside it, lean-multi-ntfs-c9.ad1.txt" in report
    assert "Hash of the whole image" in report and "whole disk" not in report
    assert "MD5: 9 file(s) checked, all match" in report
    assert "SHA-1: 9 file(s) checked, all match" in report
    assert "3 of 12 file(s) have no recorded MD5 and were not checked against one." in report
    assert "3 of 12 file(s) have no recorded SHA-1 and were not checked against one." in report


def test_files_without_a_recorded_hash_are_counted() -> None:
    """An L01 where few files have a recorded MD5 or SHA-1: each "all match"
    comes with how many were not checked against that hash."""
    result = {"stored": {}, "computed": {}, "match": None, "entry_md5_checked": 108,
              "entry_md5_mismatched": [], "entry_sha1_checked": 5,
              "entry_sha1_mismatched": [], "entry_count": 9342, "entry_md5_missing": 9234,
              "entry_sha1_missing": 9337}
    report = verify_report_html(result, [], holds_files=True)
    assert "MD5: 108 file(s) checked, all match" in report
    assert "SHA-1: 5 file(s) checked, all match" in report
    assert "9,234 of 9,342 file(s) have no recorded MD5 and were not checked against one." \
        in report
    assert "9,337 of 9,342 file(s) have no recorded SHA-1 and were not checked against one." \
        in report


def test_ad1_without_its_log_says_so() -> None:
    result = {"stored": {}, "computed": {}, "match": None, "entry_md5_checked": 3,
              "entry_md5_mismatched": [], "ad1_log": None, "ad1_log_expected": "x.ad1.txt"}
    report = verify_report_html(result, [], holds_files=True)
    assert "FTK Imager writes it to its log beside the image (x.ad1.txt), which was not found" \
        in report
    assert "recorded no hash of its whole data; the hashes it recorded of its files were " \
        "checked" in report


def test_every_file_whose_hash_differs_is_listed() -> None:
    bad = [f"folder/file{i}.bin" for i in range(30)]
    result = {"stored": {}, "computed": {}, "match": None, "entry_md5_checked": 40,
              "entry_md5_mismatched": bad}
    report = verify_report_html(result, ["30 file(s) do not match their recorded hash."],
                                holds_files=True)
    assert "MD5: 30 of 40 file(s) checked do not match:" in report
    for path in bad:
        assert f"<code>{path}</code>" in report


def test_logical_evidence_without_file_hashes_says_so() -> None:
    report = verify_report_html({"stored": {}, "computed": {}, "match": None}, [],
                                holds_files=True)
    assert "This acquisition recorded no hash to verify against." in report
    assert "No file has a recorded hash to check." in report


def _damaged() -> dict[str, Any]:
    """Synthetic: every kind of damage ewfprobe 0.17's verify() reports, more
    items of each than a short list would show. No fixture holds them all."""
    return {
        "stored": {"MD5": "aa" * 16}, "computed": {"MD5": "aa" * 16}, "match": True,
        "unreadable_chunks": [{"chunk": i, "offset": i * 32768, "error": f"bad chunk {i}"}
                              for i in range(12)],
        "entry_unreadable": [{"path": f"dir/file{i}.bin", "error": f"err {i}"}
                             for i in range(25)],
        "table_errors": [
            {"file": "x.E01", "offset": 4096, "used": "table2"},
            {"file": "x.E02", "offset": 8192, "used": "table as stored"},
        ],
        "segment_set_errors": [{"file": f"x.L0{i}", "expected_file": "x.L01"}
                               for i in range(2, 9)],
        "logical_unreached_bytes": 123456,
        "logical_unreached_spans": [{"offset": 1000 * i, "length": 10 + i} for i in range(5)],
    }


def test_damage_lists_every_item() -> None:
    report = verify_report_html(_damaged(), [])
    assert "Damage found while reading" in report
    assert "12 chunk(s) could not be read:" in report
    for i in range(12):
        assert f"chunk {i:,} at byte {i * 32768:,}: bad chunk {i}" in report
    assert "25 file(s) could not be read:" in report
    for i in range(25):
        assert f"dir/file{i}.bin: err {i}" in report
    assert "2 chunk table(s) fail their checksum:" in report
    assert "x.E01, chunk table at byte 4,096: its copy (table2) passes and was read in its " \
        "place" in report
    assert "x.E02, chunk table at byte 8,192: no copy passes; the table was read as stored" \
        in report
    assert "7 segment file(s) record a different acquisition:" in report
    for i in range(2, 9):
        assert f"x.L0{i} records a different acquisition than x.L01" in report
    assert "123,456 byte(s) of the AD1's logical space are not reached from its item tree." \
        in report
    assert "the reader lists at most 5 spans" in report
    for i in range(5):
        assert f"{10 + i:,} byte(s) at byte {1000 * i:,}" in report


def test_match_with_damage_is_never_a_clean_match() -> None:
    """A stored hash that matches beside damage: neither the headline nor
    the status bar reads as a clean MATCH."""
    result = _damaged()
    report = verify_report_html(result, [])
    assert "MATCH — the acquisition's own recorded hash matches its data" not in report
    assert "matches its data, but damage was found while reading it" in report
    assert f"color:{_GREEN}'><b>" not in report
    tag = verify_status_tag(result)
    assert tag == "{path}  [verify: MATCH] [damage found]"
    for key in ("unreadable_chunks", "entry_unreadable", "table_errors",
                "segment_set_errors", "logical_unreached_bytes"):
        one = {"stored": {"MD5": "aa" * 16}, "computed": {"MD5": "aa" * 16}, "match": True,
               key: result[key]}
        assert verify_status_tag(one).endswith("[damage found]"), key
        assert "but damage was found" in verify_report_html(one, []), key


def test_disk_image_damage_is_shown_too() -> None:
    """An ASIF stores no hash; its unreadable chunks are what its verify
    finds, and show on a disk image's report as on logical evidence."""
    result = {"stored": {}, "computed": {}, "match": None, "container_checks": [],
              "unreadable_chunks": [{"chunk": 3, "offset": 3 << 20, "error": "short read"}]}
    report = verify_report_html(result, [])
    assert "chunk 3 at byte 3,145,728: short read" in report
    assert verify_status_tag(result) == "{path}  [verify: no stored hash] [damage found]"


def test_entries_not_collected_are_listed_and_not_checked() -> None:
    """Synthetic (no fixture has one): folders EnCase recorded with their
    MD5 but not their content. Each is listed; with the files checked and
    those without a hash they add up to every file."""
    folders = [f"Root/Folder {i}" for i in range(15)]
    result = {"stored": {}, "computed": {}, "match": None, "entry_md5_checked": 100,
              "entry_md5_mismatched": [], "entry_sha1_checked": 0, "entry_sha1_mismatched": [],
              "entry_count": 200, "entry_md5_missing": 85, "entry_sha1_missing": 185,
              "entry_content_not_collected": folders}
    report = verify_report_html(result, [], holds_files=True)
    assert "15 of 200 file(s) were not checked against any recorded hash: the acquisition " \
        "did not collect their content:" in report
    for folder in folders:
        assert f"<code>{folder}</code>" in report
    tag = verify_status_tag(result)
    assert "[85 file(s) without a recorded MD5, not checked]" in tag
    assert "[185 file(s) without a recorded SHA-1, not checked]" in tag
    assert "[15 file(s) whose content was not collected, not checked]" in tag
    assert "damage found" not in tag


def test_only_entries_not_collected_carry_a_hash() -> None:
    """Every hash the set records belongs to an entry it didn't collect:
    neither "no hash recorded" nor "no file has a recorded hash"."""
    result = {"stored": {}, "computed": {}, "match": None, "entry_count": 3,
              "entry_md5_missing": 2, "entry_sha1_missing": 2,
              "entry_content_not_collected": ["Folder"]}
    report = verify_report_html(result, [], holds_files=True)
    assert "recorded no hash to verify against" not in report
    assert "No file has a recorded hash to check." not in report
    assert "hold no collected content and were not checked" in report


def test_status_tag_counts_files_without_sha1() -> None:
    result = {"stored": {}, "computed": {}, "match": None, "entry_md5_checked": 9,
              "entry_md5_mismatched": [], "entry_sha1_checked": 9, "entry_sha1_mismatched": [],
              "entry_count": 12, "entry_md5_missing": 3, "entry_sha1_missing": 3}
    assert verify_status_tag(result) == (
        "{path}  [verify: no stored hash, file hashes match] [3 file(s) without a recorded "
        "MD5, not checked] [3 file(s) without a recorded SHA-1, not checked]"
    )


def test_an_error_with_a_result_gives_the_result() -> None:
    """ewfprobe raises with the result attached when its caller doesn't keep
    going; that result is reported rather than only the error's message.
    An error without one propagates (another format's unreadable chunk)."""
    from crush.core.raw_image import verify_image
    from crush.third_party.ewfprobe import ewfprobe

    class Raises:
        def __init__(self, result: dict[str, Any] | None) -> None:
            self.result = result

        def verify(self, progress: object = None, keep_going: bool = False) -> dict[str, Any]:
            error = ewfprobe.EwfFormatError("chunk 3 could not be read")
            if self.result is not None:
                error.result = self.result  # type: ignore[attr-defined]
            raise error

    assert verify_image(Raises({"match": None, "unreadable_chunks": [1]})) == {
        "match": None, "unreadable_chunks": [1]}
    with pytest.raises(ewfprobe.EwfFormatError, match="chunk 3"):
        verify_image(Raises(None))


def test_dialog_shows_the_report(qapp: QApplication) -> None:
    dialog = VerifyResultDialog(None, "Verify Acquisition Hash", verify_report_html(
        {"stored": {"MD5": "aa" * 16}, "computed": {"MD5": "aa" * 16}, "match": True}, [],
    ))
    assert "aa" * 16 in dialog.browser.toPlainText()
    assert dialog.browser.isReadOnly()
