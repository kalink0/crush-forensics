# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Integrity mode never logs or lists the SHA-256 of no bytes for an entry
whose status says no content is read or stored (here: a FIFO in a folder
source), on open, on extraction, and in both exports' hash lists."""
from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path

import pytest

from crush.core.vfs import DirectoryVFS, VFSNode

pytestmark = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs a FIFO")

_EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@pytest.fixture
def source(tmp_path: Path) -> Path:
    root = tmp_path / "src"
    root.mkdir()
    (root / "a.txt").write_bytes(b"alpha")
    os.mkfifo(root / "pipe")
    return root


@pytest.fixture(autouse=True)
def _crush_log(caplog: pytest.LogCaptureFixture):  # noqa: ANN202
    # "crush" doesn't propagate to the root logger caplog listens on.
    logger = logging.getLogger("crush")
    logger.addHandler(caplog.handler)
    caplog.set_level(logging.INFO)
    caplog.set_level(logging.INFO, logger="crush")
    yield
    logger.removeHandler(caplog.handler)


def _child(vfs: DirectoryVFS, name: str) -> VFSNode:
    return next(n for n in vfs.root().children if n.name == name)


def _messages(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records]


def test_open_logs_not_hashed_for_a_fifo(qapp, source: Path, caplog) -> None:
    from crush.ui.main_window import MainWindow

    caplog.set_level(logging.INFO)
    vfs = DirectoryVFS(source)
    win = MainWindow()
    try:
        win.session.integrity_mode = True
        win._hash_node_if_integrity(_child(vfs, "pipe"), vfs)
        win._hash_node_if_integrity(_child(vfs, "a.txt"), vfs)
    finally:
        win.close()
    messages = _messages(caplog)
    assert any(
        m.startswith("INTEGRITY not hashed: no content read") and m.endswith("pipe")
        for m in messages
    ), messages
    assert not any(_EMPTY_SHA256 in m for m in messages)
    assert any(hashlib.sha256(b"alpha").hexdigest() in m for m in messages)


def test_extract_logs_not_hashed_for_a_fifo(
    qapp, source: Path, caplog, monkeypatch,
) -> None:
    from crush.ui import extract_dialog
    from crush.ui.main_window import MainWindow

    monkeypatch.setattr(extract_dialog, "confirm_temp_space", lambda *a, **k: True)
    caplog.set_level(logging.INFO)
    vfs = DirectoryVFS(source)
    win = MainWindow()
    try:
        win.session.integrity_mode = True
        copied = win._materialize_node_for_external(_child(vfs, "pipe"), vfs)
        assert copied is not None and copied.read_bytes() == b""
        assert win.session.hashes.get(vfs, _child(vfs, "pipe")) == {}
    finally:
        win.close()
    messages = _messages(caplog)
    assert any(m.startswith("INTEGRITY not hashed: no content read") for m in messages)
    assert not any(_EMPTY_SHA256 in m for m in messages)


def test_export_keeps_the_empty_file_but_lists_it_as_not_hashed(
    qapp, source: Path, tmp_path: Path, caplog,
) -> None:
    from crush.core.hashing import HashStore
    from crush.ui.main_window import _ExportWorker

    caplog.set_level(logging.INFO)
    vfs = DirectoryVFS(source)
    dest = tmp_path / "out"
    dest.mkdir()
    store = HashStore()
    worker = _ExportWorker(vfs, vfs.root(), str(dest), True, hashes=store)
    worker._run()
    worker.deleteLater()

    assert (dest / "src" / "pipe").read_bytes() == b""  # the structure stays complete
    lines = (dest / "src" / "crush-export-hashes.txt").read_text(encoding="utf-8").splitlines()
    assert "not hashed: no content read (Special file (FIFO) — no content is read)  0  pipe" in lines
    assert f"{hashlib.sha256(b'alpha').hexdigest()}  5  a.txt" in lines
    assert not any(_EMPTY_SHA256 in ln for ln in lines)
    assert store.get(vfs, _child(vfs, "pipe")) == {}
    messages = _messages(caplog)
    assert any(m.startswith("INTEGRITY export not hashed: no content read") for m in messages)
    assert not any(_EMPTY_SHA256 in m for m in messages)


def test_multi_export_lists_a_fifo_as_not_hashed(qapp, source: Path, tmp_path: Path, caplog) -> None:
    from crush.ui.main_window import _ExportMultiWorker

    caplog.set_level(logging.INFO)
    vfs = DirectoryVFS(source)
    dest = tmp_path / "out"
    dest.mkdir()
    entries = [(_child(vfs, "pipe"), vfs, "/pipe"), (_child(vfs, "a.txt"), vfs, "/a.txt")]
    worker = _ExportMultiWorker(entries, str(dest), True, "x")
    worker._run()
    worker.deleteLater()

    (export_root,) = list(dest.iterdir())
    assert (export_root / "pipe").read_bytes() == b""
    lines = (export_root / "crush-export-hashes.txt").read_text(encoding="utf-8").splitlines()
    assert "not hashed: no content read (Special file (FIFO) — no content is read)  0  pipe" in lines
    assert f"{hashlib.sha256(b'alpha').hexdigest()}  5  a.txt" in lines
    assert not any(_EMPTY_SHA256 in ln for ln in lines)
    messages = _messages(caplog)
    assert any(m.startswith("INTEGRITY export not hashed: no content read") for m in messages)
    assert not any(_EMPTY_SHA256 in m for m in messages)
