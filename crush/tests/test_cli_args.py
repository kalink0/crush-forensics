# SPDX-License-Identifier: Apache-2.0
"""Tests for CLI argument parsing (crush __main__)."""
from __future__ import annotations

from crush.__main__ import _parse_args


def test_parse_args_no_paths_defaults() -> None:
    args = _parse_args([])

    assert args.paths == []
    assert args.open_paths is None


def test_parse_args_positional_paths() -> None:
    args = _parse_args(["/tmp/foo.zip", "/tmp/bar"])

    assert args.paths == ["/tmp/foo.zip", "/tmp/bar"]
    assert args.open_paths is None


def test_parse_args_open_flag_repeatable() -> None:
    args = _parse_args(["--open", "/tmp/foo", "--open", "/tmp/bar"])

    assert args.open_paths == ["/tmp/foo", "/tmp/bar"]


def test_parse_args_positional_and_open_combined() -> None:
    args = _parse_args(["/tmp/positional", "--open", "/tmp/flagged"])

    assert args.paths == ["/tmp/positional"]
    assert args.open_paths == ["/tmp/flagged"]
