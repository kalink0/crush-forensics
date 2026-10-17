# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Where a LevelDB record's parts are: in its .log or table file, or -- for
a record of a compressed table block -- in the decompressed block; and the
Records tab showing them."""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from crush.core.vfs import DirectoryVFS
from crush.parsers.leveldb_parser import LeveldbParser
from crush.tests.test_parsers import _log_record, _varint
from crush.viewers.leveldb_viewer import LevelDbRecordsWidget, LevelDbViewer

_TABLE_MAGIC = 0xDB4775248B80FB57
_BLOCK = 32768


def _parse(tmp_path: Path) -> Any:
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == "db")
    return LeveldbParser().parse(node, vfs)


def _joined(raw: bytes, ranges: list[tuple[int, int]]) -> bytes:
    return b"".join(raw[s:e] for s, e in ranges)


def _internal_key(user_key: bytes, seq: int, live: bool = True) -> bytes:
    return user_key + struct.pack("<Q", (seq << 8) | (1 if live else 0))


def _block(entries: list[tuple[bytes, bytes]]) -> bytes:
    """A table block, every key prefix-compressed against the one before
    (one restart point, at the start)."""
    out = b""
    previous = b""
    for key, value in entries:
        shared = 0
        while shared < min(len(key), len(previous)) and key[shared] == previous[shared]:
            shared += 1
        out += _varint(shared) + _varint(len(key) - shared) + _varint(len(value))
        out += key[shared:] + value
        previous = key
    return out + struct.pack("<II", 0, 1)


def _snappy_literals(data: bytes) -> bytes:
    """*data* as a valid Snappy stream of literals only."""
    out = _varint(len(data))
    for i in range(0, len(data), 60):
        chunk = data[i:i + 60]
        out += bytes([(len(chunk) - 1) << 2]) + chunk
    return out


def _table(entries: list[tuple[bytes, bytes]], *, compressed: bool) -> tuple[bytes, int, int]:
    """A table file with one data block: (bytes, block offset, stored block
    length)."""
    plain = _block(entries)
    stored = _snappy_literals(plain) if compressed else plain
    data = stored + bytes([1 if compressed else 0]) + bytes(4)
    index = _block([(entries[-1][0], _varint(0) + _varint(len(stored)))])
    index_offset = len(data)
    data += index + bytes([0]) + bytes(4)
    handles = _varint(0) + _varint(0) + _varint(index_offset) + _varint(len(index))
    return data + handles.ljust(40, b"\x00") + struct.pack("<Q", _TABLE_MAGIC), 0, len(stored)


_TABLE_ENTRIES = [
    (_internal_key(b"user:alpha", 1), b"first value"),
    (_internal_key(b"user:alpine", 2), b"second"),
    (_internal_key(b"user:alps", 3), b"third value"),
]


def _write_table(tmp_path: Path, *, compressed: bool) -> bytes:
    db = tmp_path / "db"
    db.mkdir()
    raw, _, _ = _table(_TABLE_ENTRIES, compressed=compressed)
    (db / "000005.ldb").write_bytes(raw)
    return raw


def test_uncompressed_table_record_parts_are_its_bytes_in_the_file(tmp_path: Path) -> None:
    raw = _write_table(tmp_path, compressed=False)
    records = _parse(tmp_path).data["records"]
    assert len(records) == 3
    for rec, (ikey, value) in zip(records, _TABLE_ENTRIES):
        in_file = rec["location"]["in_file"]
        assert rec["location"]["compressed_block"] is None
        assert _joined(raw, in_file["key"]) == ikey[:-8] == rec["user_key_bytes"]
        assert _joined(raw, in_file["tag"]) == ikey[-8:]
        assert _joined(raw, in_file["value"]) == value
        assert in_file["entry"][0][0] == rec["offset"]


def test_prefix_compressed_key_includes_the_pieces_in_earlier_entries(tmp_path: Path) -> None:
    """"user:alps" shares "user:alp" with "user:alpine", which got it from
    "user:alpha": its first bytes are stored in the first entry."""
    raw = _write_table(tmp_path, compressed=False)
    records = _parse(tmp_path).data["records"]
    first_entry = records[0]["location"]["in_file"]["entry"][0]
    third_key = records[2]["location"]["in_file"]["key"]
    assert len(third_key) == 2
    assert first_entry[0] <= third_key[0][0] and third_key[0][1] <= first_entry[1]
    assert _joined(raw, third_key) == b"user:alps"


def test_compressed_block_record_points_at_the_block_and_into_it(tmp_path: Path) -> None:
    raw = _write_table(tmp_path, compressed=True)
    result = _parse(tmp_path)
    records = result.data["records"]
    _, offset, length = _table(_TABLE_ENTRIES, compressed=True)
    for rec, (ikey, value) in zip(records, _TABLE_ENTRIES):
        block = rec["location"]["compressed_block"]
        assert rec["location"]["in_file"] is None
        assert (block["offset"], block["length"], block["trailer"]) == (offset, length, 5)
        assert block["compression"] == "Snappy"
        assert block["records"] == 3
        decompressed = result.data["__file_bytes"].decompressed_block(
            "000005.ldb", block["offset"], block["length"]
        )
        assert _joined(decompressed, block["key"]) == ikey[:-8]
        assert _joined(decompressed, block["tag"]) == ikey[-8:]
        assert _joined(decompressed, block["value"]) == value
    assert result.data["__file_bytes"].file("000005.ldb") == raw


def _batch(entries: list[tuple[bytes, bytes]], seq: int) -> bytes:
    out = struct.pack("<QI", seq, len(entries))
    for key, value in entries:
        out += b"\x01" + _varint(len(key)) + key + _varint(len(value)) + value
    return out


def test_log_record_crossing_fragments_is_located_in_every_piece(tmp_path: Path) -> None:
    """A batch over two log blocks: the first entry's value is split by the
    block boundary and the second fragment's header; the second entry lies
    in the second fragment. Its offset is its position in the file (the
    vendored reader's was 7 bytes short: the header in between)."""
    big = bytes(range(256)) * 130  # 33,280 B
    batch = _batch([(b"big", big), (b"small", b"tail")], seq=10)
    first_len = _BLOCK - 7
    log = _log_record(2, batch[:first_len]) + _log_record(4, batch[first_len:])
    db = tmp_path / "db"
    db.mkdir()
    (db / "000003.log").write_bytes(log)

    records = _parse(tmp_path).data["records"]
    assert [r["user_key_bytes"] for r in records] == [b"big", b"small"]
    big_parts = records[0]["location"]["in_file"]
    assert len(big_parts["value"]) == 2
    assert _joined(log, big_parts["value"]) == big
    assert _joined(log, big_parts["batch_header"]) == struct.pack("<QI", 10, 2)

    small = records[1]
    parts = small["location"]["in_file"]
    assert _joined(log, parts["key"]) == b"small"
    assert _joined(log, parts["value"]) == b"tail"
    assert log[small["offset"]] == 1  # its type byte: a value
    assert small["offset"] == parts["type"][0][0] > _BLOCK
    assert parts["batch_header"] == big_parts["batch_header"]


def test_deleted_log_record_has_an_empty_value_range(tmp_path: Path) -> None:
    db = tmp_path / "db"
    db.mkdir()
    batch = struct.pack("<QI", 4, 1) + b"\x00" + _varint(4) + b"gone"
    log = _log_record(1, batch)
    (db / "000003.log").write_bytes(log)
    rec = _parse(tmp_path).data["records"][0]
    parts = rec["location"]["in_file"]
    assert _joined(log, parts["key"]) == b"gone"
    assert [e - s for s, e in parts["value"]] in ([], [0])


def test_entry_that_cant_be_read_keeps_the_records_before_it(tmp_path: Path) -> None:
    """A block whose last entry can't be read (it shares more key bytes
    than the key before it has): the entries before it are still read, then
    the file is listed as not read to its end."""
    plain = _block(_TABLE_ENTRIES[:2])
    broken = plain[:-8] + b"\x7f\x00\x00" + struct.pack("<II", 0, 1)
    stored_len = len(broken)
    data = broken + bytes(5)
    index = _block([(_TABLE_ENTRIES[1][0], _varint(0) + _varint(stored_len))])
    index_offset = len(data)
    data += index + bytes(5)
    handles = _varint(0) + _varint(0) + _varint(index_offset) + _varint(len(index))
    db = tmp_path / "db"
    db.mkdir()
    (db / "000005.ldb").write_bytes(
        data + handles.ljust(40, b"\x00") + struct.pack("<Q", _TABLE_MAGIC)
    )
    result = _parse(tmp_path)
    assert [r["user_key_bytes"] for r in result.data["records"]] == [b"user:alpha", b"user:alpine"]
    assert result.data["manifests"]["Read problems"]["000005.ldb"].code == "leveldb.read_stopped"


def _select(widget: LevelDbRecordsWidget, record: int) -> None:
    """Select the row of record number *record* (the table is sorted)."""
    proxy_row = widget._proxy.mapFromSource(widget._model.index(record, 0)).row()
    widget._table.selectRow(proxy_row)


def test_records_tab_highlights_the_record_in_its_file(tmp_path: Path, qapp, widgets) -> None:  # noqa: ARG001
    raw = _write_table(tmp_path, compressed=False)
    data = _parse(tmp_path).data
    viewer = widgets(LevelDbViewer(data))
    records_widget = viewer.findChild(LevelDbRecordsWidget)
    _select(records_widget, 2)
    in_file = data["records"][2]["location"]["in_file"]
    assert records_widget._hex_file._data == raw
    assert in_file["value"][0] in records_widget._hex_file._focus_ranges
    text = records_widget._file_label.text()
    assert "000005.ldb" in text and "user key" in text and "value" in text
    assert "isn't from a compressed block" in records_widget._block_label.text()


def test_records_tab_marks_a_compressed_record_and_shows_the_derived_block(
    tmp_path: Path, qapp, widgets,  # noqa: ARG001
) -> None:
    _write_table(tmp_path, compressed=True)
    data = _parse(tmp_path).data
    viewer = widgets(LevelDbViewer(data))
    records_widget = viewer.findChild(LevelDbRecordsWidget)
    _select(records_widget, 1)
    block = data["records"][1]["location"]["compressed_block"]
    whole = (block["offset"], block["offset"] + block["length"] + 5)
    assert records_widget._hex_file._focus_ranges == [whole]
    file_text = records_widget._file_label.text()
    assert "Snappy-compressed block" in file_text
    assert "3 records were read from this block" in file_text
    assert "can't be pointed at in the file" in file_text
    block_text = records_widget._block_label.text()
    assert block_text.startswith("Derived:")
    assert "not in the file" in block_text
    assert block["value"][0] in records_widget._hex_block._focus_ranges


def test_record_without_location_says_so(qapp, widgets) -> None:  # noqa: ARG001
    record = {
        "seq": 1, "state": "Live", "file": "000003.log", "offset": 0,
        "user_key_text": "k", "user_key_bytes": b"k", "value_text": "v", "value_bytes": b"v",
        "internal_key_bytes": b"", "compressed": False, "checksum_ok": True,
    }
    widget = widgets(LevelDbRecordsWidget([record]))
    _select(widget, 0)
    assert widget._file_label.text() == "No location in the file was recorded for this record."
