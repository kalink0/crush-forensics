# SPDX-License-Identifier: Apache-2.0
"""Realm Strings tab: every text run in the .realm file's bytes, by the one
string rule every Strings view uses, each attributed to the array, freed
block or file part its bytes sit in (crush/core/realm_strings.py)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from crush.core.realm_strings import (
    KIND_ACTIVE,
    KIND_FOOTER,
    KIND_FREED,
    KIND_HEADER,
    KIND_INACTIVE,
    KIND_UNREACHED,
    AREA_IN_FREED,
    scan_realm_strings,
)
from crush.core.vfs import DirectoryVFS
from crush.parsers.realm_parser import RealmParser
from crush.tests.conftest import FIXTURES_DIR

_REALMS = sorted(p.name for p in FIXTURES_DIR.glob("*.realm"))


@pytest.mark.parametrize("name", _REALMS)
def test_every_byte_is_in_exactly_one_region(name: str) -> None:
    data = (FIXTURES_DIR / name).read_bytes()
    (fs,) = scan_realm_strings(data).files
    pos = 0
    for region in fs.regions:
        assert region.start == pos and region.end > region.start, region
        pos = region.end
    assert pos == len(data)
    assert fs.regions[0].kind == KIND_HEADER and fs.regions[0].end == 24
    for hit, touched in zip(fs.hits, fs.hit_regions, strict=True):
        assert touched
        assert fs.regions[touched[0]].start <= hit.offset < fs.regions[touched[0]].end


@pytest.mark.forensic(
    category="Completeness",
    subject="Realm database",
    desc="Strings in arrays only the inactive snapshot reaches, lying in freed blocks, are "
    "listed and attributed to the previous snapshot",
)
def test_previous_snapshot_strings_are_attributed() -> None:
    """mcdonalds_v9_data keeps a previous commit's arrays in space its active
    snapshot's free list names; the walk from the inactive top reference
    finds them."""
    data = (FIXTURES_DIR / "mcdonalds_v9_data.realm").read_bytes()
    (fs,) = scan_realm_strings(data).files
    kinds = {(r.kind, r.area) for r in fs.regions}
    assert (KIND_INACTIVE, AREA_IN_FREED) in kinds
    assert (KIND_ACTIVE, AREA_IN_FREED) not in kinds  # the active snapshot isn't in its own free list
    previous = [
        hit for hit, touched in zip(fs.hits, fs.hit_regions, strict=True)
        if any(fs.regions[i].kind == KIND_INACTIVE for i in touched)
    ]
    assert previous


def test_freed_block_bytes_and_streaming_footer() -> None:
    ifttt = (FIXTURES_DIR / "ifttt_v9_data.realm").read_bytes()
    (fs,) = scan_realm_strings(ifttt).files
    assert any(
        fs.regions[i].kind == KIND_FREED for touched in fs.hit_regions for i in touched
    )
    streaming = (FIXTURES_DIR / "streaming_form.realm").read_bytes()
    (fs,) = scan_realm_strings(streaming).files
    assert fs.regions[-1].kind == KIND_FOOTER and fs.regions[-1].end == len(streaming)


def test_no_header_lists_strings_and_says_why_nothing_is_attributed() -> None:
    data = b"\x00" * 32 + b"just some text in no realm file" + b"\x00" * 32
    result = scan_realm_strings(data)
    (fs,) = result.files
    assert [h.value for h in fs.hits] == ["just some text in no realm file"]
    assert {r.kind for r in fs.regions} == {KIND_UNREACHED}
    assert [p.code for p in result.problems] == ["realm_strings.header_not_detected"]


def test_every_realm_region_word_is_marked_for_translation() -> None:
    import crush.core.realm_strings as rs
    from crush.viewers.realm_viewer import _RealmStringsSource

    words = {
        value for name, value in vars(rs).items()
        if name.startswith(("KIND_", "AREA_")) and isinstance(value, str)
    }
    assert words and words <= set(_RealmStringsSource._REGION_WORDS)


def _parse(tmp_path: Path, name: str) -> dict[str, Any]:
    (tmp_path / name).write_bytes((FIXTURES_DIR / name).read_bytes())
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == name)
    return RealmParser().parse(node, vfs).data


def test_parser_has_no_strings_field_and_freed_blocks_use_the_shared_rule(tmp_path: Path) -> None:
    """The Strings tab scans the file itself; the parser's own min-20,
    deduplicated list is gone. A freed block's preview strings come from
    byte_strings.scan_strings, also for a block holding an array."""
    from crush.core.byte_strings import scan_strings

    data = _parse(tmp_path, "ifttt_v9_data.realm")
    assert "strings" not in data
    assert data["decrypted"] is False
    blocks = data["freed_blocks"]
    assert blocks
    for block in blocks:
        assert block["strings"] == [h.value for h in scan_strings(block["bytes"])]
    assert any(b["array_header"] is not None and b["strings"] for b in blocks)


def test_strings_tab_lists_regions_and_marks_strings_in_hex(qapp, widgets, tmp_path: Path) -> None:
    from PySide6.QtWidgets import QTabWidget

    from crush.viewers.realm_viewer import RealmViewer
    from crush.viewers.table_viewer import TableViewer

    data = _parse(tmp_path, "ifttt_v9_data.realm")
    viewer = widgets(RealmViewer(data))
    tabs = viewer.findChild(QTabWidget)
    index = next(i for i in range(tabs.count()) if tabs.tabText(i) == "Strings")
    tv = tabs.widget(index)
    assert isinstance(tv, TableViewer)
    assert tv._strings_model is None  # not scanned until shown
    viewer.show()
    tabs.setCurrentIndex(index)
    from PySide6.QtCore import Qt

    model = tv._table_view.model()
    headers = [model.headerData(c, Qt.Orientation.Horizontal) for c in range(model.columnCount())]
    assert headers == ["File", "Offset (B)", "Length (B)", "Encoding", "Region", "Value"]
    assert model.rowCount() == len(scan_realm_strings(data["__realm_file_bytes"]).files[0].hits)

    region_col, value_col = headers.index("Region"), headers.index("Value")
    regions = {model.data(model.index(r, region_col)) for r in range(model.rowCount())}
    assert {"Realm file header", "array (active snapshot)", "freed block"} <= regions

    tv._toggle_hex_pane()
    tv._table_view.setCurrentIndex(model.index(5, value_col))
    (start, end), = tv._hex_viewer._focus_ranges
    raw = data["__realm_file_bytes"]
    assert raw[start:end].decode("utf-8") == model.data(model.index(5, value_col))

    tv._table_view.clearSelection()
    tv._on_hex_offset_focused(start)
    assert tv._table_view.currentIndex().row() == 5
    assert "Realm file" in tv._sql_status.text()
    viewer.close()
