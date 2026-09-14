# SPDX-License-Identifier: Apache-2.0
"""Tests for the crush-analyze launcher (self-re-exec subprocess, contract
v1 result parsing). See docs/design/analyzer-runner.md."""
from __future__ import annotations

import plistlib
import sqlite3
from pathlib import Path

import pytest

from crush.core.analyzer_launcher import AnalyzerRunError, list_analyzer_modules, run_analyzer


def test_list_analyzer_modules_includes_the_bundled_modules() -> None:
    modules = list_analyzer_modules()

    ids = {m["id"] for m in modules}
    assert "stub" in ids
    assert "get_installed_apps" in ids


def test_run_analyzer_stub_module_against_an_empty_directory(tmp_path: Path) -> None:
    result = run_analyzer(tmp_path, module_id="stub")

    assert result["status"] == "ok"
    assert result["rows"] == []
    assert result["run"]["dev_mode"] is False
    assert result["run"]["module_source"] == "bundled"


def test_run_analyzer_unknown_module_raises() -> None:
    with pytest.raises(AnalyzerRunError):
        run_analyzer(Path("."), module_id="does-not-exist")


def test_run_analyzer_requires_module_id_or_module_path() -> None:
    with pytest.raises(ValueError):
        run_analyzer(Path("."))


def test_run_analyzer_installed_apps_against_a_synthetic_fixture(tmp_path: Path) -> None:
    db_path = (
        tmp_path / "private" / "var" / "mobile" / "Library" / "FrontBoard" / "applicationState.db"
    )
    db_path.parent.mkdir(parents=True)
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE application_identifier_tab "
        "(id INTEGER PRIMARY KEY, application_identifier TEXT)"
    )
    conn.execute("CREATE TABLE key_tab (id INTEGER PRIMARY KEY, key TEXT)")
    conn.execute("CREATE TABLE kvs (application_identifier INTEGER, key INTEGER, value BLOB)")
    conn.execute("INSERT INTO application_identifier_tab VALUES (1, 'app1')")
    conn.execute("INSERT INTO key_tab VALUES (1, 'compatibilityInfo')")
    compat_plist = plistlib.dumps(
        {
            "bundleIdentifier": "com.example.testapp",
            "bundlePath": "/private/var/containers/Bundle/Application/XXXX/TestApp.app",
            "sandboxPath": "/private/var/mobile/Containers/Data/Application/XXXX",
        },
        fmt=plistlib.FMT_BINARY,
    )
    conn.execute("INSERT INTO kvs VALUES (1, 1, ?)", (compat_plist,))
    conn.commit()
    conn.close()

    result = run_analyzer(tmp_path, module_id="get_installed_apps")

    assert result["status"] == "ok"
    assert result["rows"] == [
        {
            "_row_status": "ok",
            "bundle_id": "com.example.testapp",
            "bundle_path": "/private/var/containers/Bundle/Application/XXXX/TestApp.app",
            "sandbox_path": "/private/var/mobile/Containers/Data/Application/XXXX",
        }
    ]
