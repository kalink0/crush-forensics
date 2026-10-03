# SPDX-License-Identifier: Apache-2.0
"""The Verify Acquisition Hash result: one block per check, the stored and
the recomputed value each on a line of its own and in full, the recomputed
one marked green when it matches and red when it doesn't."""
from __future__ import annotations

import shutil
from pathlib import Path

from PySide6.QtWidgets import QApplication

from crush.core.vfs import RawImageVFS, open_vfs
from crush.tests.conftest import FIXTURES_DIR
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


def test_dialog_shows_the_report(qapp: QApplication) -> None:
    dialog = VerifyResultDialog(None, "Verify Acquisition Hash", verify_report_html(
        {"stored": {"MD5": "aa" * 16}, "computed": {"MD5": "aa" * 16}, "match": True}, [],
    ))
    assert "aa" * 16 in dialog.browser.toPlainText()
    assert dialog.browser.isReadOnly()
