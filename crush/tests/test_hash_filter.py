# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""The Filesystem panel's hash: filter token: matched against hashes
already computed in the window only, files only, with its coverage shown."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from crush.core.hashing import (
    QUERY_NOT_HEX,
    QUERY_TOO_LONG,
    parse_hash_query,
    query_can_match,
    query_matches,
)
from crush.core.session import Session
from crush.core.vfs import DirectoryVFS, VFSNode

_MD5_A = hashlib.md5(b"alpha").digest()
_SHA1_A = hashlib.sha1(b"alpha").digest()
_SHA256_A = hashlib.sha256(b"alpha").digest()


# --- the query ---------------------------------------------------------------

@pytest.mark.parametrize(("length", "algorithm"), [(32, "md5"), (40, "sha1"), (64, "sha256")])
def test_full_length_names_the_algorithm(length: int, algorithm: str) -> None:
    query = parse_hash_query("A" * length)
    assert (query.hex, query.algorithm, query.problem) == ("a" * length, algorithm, "")


@pytest.mark.parametrize("length", [1, 8, 31, 33, 39, 41, 63])
def test_other_lengths_are_a_prefix(length: int) -> None:
    query = parse_hash_query("0" * length)
    assert query.algorithm is None and not query.problem


def test_not_hex_and_too_long_are_problems() -> None:
    assert parse_hash_query("xyz").problem == QUERY_NOT_HEX
    assert parse_hash_query("0" * 65).problem == QUERY_TOO_LONG


def test_each_algorithm_matches_only_its_own_values() -> None:
    computed = {"md5": [_MD5_A], "sha1": [_SHA1_A], "sha256": [_SHA256_A]}
    for digest in (_MD5_A, _SHA1_A, _SHA256_A):
        assert query_matches(parse_hash_query(digest.hex().upper()), computed)
    # A full MD5 isn't looked for among SHA-256 values.
    assert not query_matches(parse_hash_query(_SHA256_A.hex()[:32]), {"sha256": [_SHA256_A]})
    assert not query_can_match(parse_hash_query(_MD5_A.hex()), {"sha256": [_SHA256_A]})


def test_prefix_matches_across_algorithms() -> None:
    computed = {"md5": [_MD5_A], "sha256": [_SHA256_A]}
    assert query_matches(parse_hash_query(_SHA256_A.hex()[:10]), computed)
    assert query_matches(parse_hash_query(_MD5_A.hex()[:6]), computed)
    assert not query_matches(parse_hash_query("ffffffffffff"), {"md5": [b"\x00" * 16]})


def test_a_differing_second_value_matches_too() -> None:
    first, second = b"\x01" * 32, b"\x02" * 32
    computed = {"sha256": [first, second]}
    assert query_matches(parse_hash_query(second.hex()), computed)
    assert query_matches(parse_hash_query(first.hex()), computed)


# --- the panel ---------------------------------------------------------------

@pytest.fixture
def tree(tmp_path: Path) -> Path:
    (tmp_path / "a.txt").write_bytes(b"alpha")
    (tmp_path / "b.txt").write_bytes(b"beta")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "c.txt").write_bytes(b"gamma")
    return tmp_path


def _child(vfs: DirectoryVFS, name: str) -> VFSNode:
    return next(n for n in vfs.root().children if n.name == name)


def _search(panel, vfs: DirectoryVFS, text: str) -> list[str]:  # noqa: ANN001
    panel._search_gen += 1
    panel._search_worker([vfs], panel._parse_filter_text(text), panel._search_gen)
    model = panel._search_model
    return [model.item(row, 0).text() for row in range(model.rowCount())]


@pytest.fixture
def panel_with_hash(qapp, widgets, tree: Path):  # noqa: ANN001, ANN201
    from crush.ui.fs_panel import FilesystemPanel

    session = Session()
    vfs = DirectoryVFS(tree)
    session.hashes.record(vfs, _child(vfs, "a.txt"), {"md5": _MD5_A, "sha256": _SHA256_A})
    panel = widgets(FilesystemPanel(session))
    yield panel, vfs, session
    session.close()


def test_full_hash_lists_the_file_and_says_what_was_matched(panel_with_hash) -> None:  # noqa: ANN001
    panel, vfs, _ = panel_with_hash
    assert _search(panel, vfs, f"hash:{_MD5_A.hex()}") == ["a.txt"]
    assert not panel._search_note.isHidden()
    assert panel._search_note.text() == (
        "Matched against computed MD5 hashes: 1 of 3 files have one — files without one "
        "can't match."
    )


def test_a_file_without_a_hash_is_counted_not_matched(panel_with_hash) -> None:  # noqa: ANN001
    panel, vfs, _ = panel_with_hash
    # b.txt and sub/c.txt were never hashed: not listed, counted as not hashed.
    assert _search(panel, vfs, "hash:2c17") == ["a.txt"]
    assert panel._search_note.text().startswith(
        "Matched against computed hashes (prefix, any algorithm): 1 of 3 files hashed"
    )
    assert _search(panel, vfs, "hash:ffff") == []
    assert "1 of 3 files hashed" in panel._search_note.text()


def test_sha1_not_computed_is_said_per_algorithm(panel_with_hash) -> None:  # noqa: ANN001
    panel, vfs, _ = panel_with_hash
    assert _search(panel, vfs, f"hash:{_SHA1_A.hex()}") == []
    assert panel._search_note.text().startswith("Matched against computed SHA-1 hashes: 0 of 3")


def test_combines_with_name_and_lists_files_only(panel_with_hash) -> None:  # noqa: ANN001
    panel, vfs, session = panel_with_hash
    assert _search(panel, vfs, f"name:b hash:{_SHA256_A.hex()}") == []
    assert "0 of 1 files have one" in panel._search_note.text()
    assert _search(panel, vfs, f"name:a hash:{_SHA256_A.hex()[:8]}") == ["a.txt"]
    # A folder never matches, whatever is stored for it.
    session.hashes.record(vfs, _child(vfs, "sub"), {"md5": _MD5_A})
    assert _search(panel, vfs, f"hash:{_MD5_A.hex()}") == ["a.txt"]


@pytest.mark.parametrize(("text", "note"), [
    ("-hash:2c17", "-hash: is not supported"),
    ("hash:xyz", "hash: takes hexadecimal digits"),
    ("hash:" + "0" * 65, "hash: takes at most 64 hexadecimal digits"),
])
def test_unsupported_input_says_why_nothing_is_listed(panel_with_hash, text: str, note: str) -> None:  # noqa: ANN001
    panel, vfs, _ = panel_with_hash
    assert _search(panel, vfs, text) == []
    assert panel._search_note.text().startswith(note)
    assert not panel._search_note.isHidden()


def test_no_note_without_a_hash_token(panel_with_hash) -> None:  # noqa: ANN001
    panel, vfs, _ = panel_with_hash
    _search(panel, vfs, f"hash:{_MD5_A.hex()}")
    assert sorted(_search(panel, vfs, "name:txt")) == ["a.txt", "b.txt", "c.txt"]
    assert panel._search_note.isHidden()
