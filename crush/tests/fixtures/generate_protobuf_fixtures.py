# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Generate synthetic Protobuf fixtures for Crush tests.

The fixture bytes are hand-built from protobuf wire primitives so the expected
byte ranges are deterministic and visible. They do not use or copy any external
sample data.

To regenerate:

    python crush/tests/fixtures/generate_protobuf_fixtures.py

Then update ``checksums.json`` with the new files' SHA-256 digests.
"""
from __future__ import annotations

import gzip
import json
import struct
from pathlib import Path
from typing import Any

OUT_DIR = Path(__file__).resolve().parent


def varint(value: int) -> bytes:
    out = bytearray()
    n = value
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def key(field: int, wire_type: int) -> bytes:
    return varint((field << 3) | wire_type)


def fixed32(value: int) -> bytes:
    return struct.pack("<I", value)


def fixed64(value: int) -> bytes:
    return struct.pack("<Q", value)


def float32(value: float) -> bytes:
    return struct.pack("<f", value)


def double64(value: float) -> bytes:
    return struct.pack("<d", value)


def text(value: str) -> bytes:
    return value.encode("utf-8")


class MessageBuilder:
    def __init__(self) -> None:
        self.chunks: list[bytes] = []
        self.fields: list[dict[str, Any]] = []
        self.length = 0

    def raw(self) -> bytes:
        return b"".join(self.chunks)

    def add(
        self,
        *,
        field: int,
        name: str,
        wire_type: int,
        wire_label: str,
        payload: bytes,
        value: Any,
        note: str | None = None,
        children: list[dict[str, Any]] | None = None,
    ) -> None:
        key_bytes = key(field, wire_type)
        length_bytes = varint(len(payload)) if wire_type == 2 else b""
        start = self.length
        key_start = start
        key_end = key_start + len(key_bytes)
        length_start = key_end
        value_start = length_start + len(length_bytes)
        end = value_start + len(payload)

        self.chunks.extend([key_bytes, length_bytes, payload])
        self.length = end

        entry: dict[str, Any] = {
            "field": field,
            "name": name,
            "wire_type": wire_label,
            "byte_range": [start, end],
            "key_range": [key_start, key_end],
            "value_range": [value_start, end],
            "value": value,
        }
        if length_bytes:
            entry["length_range"] = [length_start, value_start]
            entry["length"] = len(payload)
        if note:
            entry["note"] = note
        if children is not None:
            entry["children"] = children
        self.fields.append(entry)


def offset_ranges(fields: list[dict[str, Any]], base: int) -> list[dict[str, Any]]:
    shifted: list[dict[str, Any]] = []
    for field in fields:
        entry: dict[str, Any] = {}
        for name, value in field.items():
            if name == "children":
                entry[name] = offset_ranges(value, base)
            elif name.endswith("_range") or name == "byte_range":
                entry[name] = [value[0] + base, value[1] + base]
            else:
                entry[name] = value
        shifted.append(entry)
    return shifted


def child_base(parent_length: int, field: int, payload_length: int) -> int:
    return parent_length + len(key(field, 2)) + len(varint(payload_length))


def write_fixture(stem: str, message_name: str, message: MessageBuilder) -> None:
    raw = message.raw()
    (OUT_DIR / f"{stem}.pb").write_bytes(raw)
    (OUT_DIR / f"{stem}.expected.json").write_text(
        json.dumps(
            {
                "fixture": f"{stem}.pb",
                "schema": "protobuf_test_messages.proto",
                "message": f"crush.fixtures.{message_name}",
                "size": len(raw),
                "hex": raw.hex(),
                "fields": message.fields,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def build_basic_wire_types() -> MessageBuilder:
    msg = MessageBuilder()
    msg.add(field=1, name="small_count", wire_type=0, wire_label="varint",
            payload=varint(1), value=1)
    msg.add(field=2, name="large_count", wire_type=0, wire_label="varint",
            payload=varint(300), value=300)
    msg.add(field=3, name="enabled", wire_type=0, wire_label="varint",
            payload=varint(1), value=True)
    msg.add(
        field=4,
        name="unix_timestamp",
        wire_type=0,
        wire_label="varint",
        payload=varint(1_700_000_000),
        value=1_700_000_000,
        note="Timestamp-like varint for interpretation checks.",
    )
    msg.add(field=5, name="temperature_c", wire_type=5, wire_label="fixed32",
            payload=float32(36.5), value=36.5)
    msg.add(field=6, name="magic_fixed32", wire_type=5, wire_label="fixed32",
            payload=fixed32(0x12345678), value=305_419_896)
    msg.add(field=7, name="ratio", wire_type=1, wire_label="fixed64",
            payload=double64(6.25), value=6.25)
    msg.add(field=8, name="magic_fixed64", wire_type=1, wire_label="fixed64",
            payload=fixed64(0x0102030405060708), value="0x0102030405060708")
    msg.add(field=9, name="note", wire_type=2, wire_label="length-delimited",
            payload=text("hello forensic protobuf"), value="hello forensic protobuf")
    msg.add(field=10, name="binary_blob", wire_type=2, wire_label="length-delimited",
            payload=bytes([0x00, 0xFF, 0x10, 0x80, 0x7F, 0x42]), value="00ff10807f42")
    msg.add(field=11, name="empty_blob", wire_type=2, wire_label="length-delimited",
            payload=b"", value="")
    msg.add(
        field=16,
        name="long_text",
        wire_type=2,
        wire_label="length-delimited",
        payload=text("L" * 130),
        value="L" * 130,
        note="Uses a multi-byte field key and multi-byte length varint.",
    )
    return msg


def build_inner_payload() -> MessageBuilder:
    msg = MessageBuilder()
    msg.add(field=1, name="inner_id", wire_type=0, wire_label="varint",
            payload=varint(7), value=7)
    msg.add(field=2, name="inner_label", wire_type=2, wire_label="length-delimited",
            payload=text("deep payload"), value="deep payload")
    return msg


def build_device() -> MessageBuilder:
    msg = MessageBuilder()
    msg.add(field=1, name="device_id", wire_type=2, wire_label="length-delimited",
            payload=text("device-001"), value="device-001")
    msg.add(field=2, name="active", wire_type=0, wire_label="varint",
            payload=varint(1), value=True)
    msg.add(field=3, name="battery_percent", wire_type=5, wire_label="fixed32",
            payload=float32(87.5), value=87.5)
    return msg


def build_event(index: int, label: str, score: float) -> MessageBuilder:
    msg = MessageBuilder()
    msg.add(field=1, name="event_index", wire_type=0, wire_label="varint",
            payload=varint(index), value=index)
    msg.add(field=2, name="event_label", wire_type=2, wire_label="length-delimited",
            payload=text(label), value=label)
    msg.add(field=3, name="score", wire_type=1, wire_label="fixed64",
            payload=double64(score), value=score)
    return msg


def add_message_field(
    parent: MessageBuilder,
    *,
    field: int,
    name: str,
    value: str,
    child: MessageBuilder,
    note: str | None = None,
) -> None:
    base = child_base(parent.length, field, child.length)
    parent.add(
        field=field,
        name=name,
        wire_type=2,
        wire_label="length-delimited",
        payload=child.raw(),
        value=value,
        note=note,
        children=offset_ranges(child.fields, base),
    )


def build_nested_mixed_payloads() -> MessageBuilder:
    msg = MessageBuilder()
    msg.add(field=1, name="version", wire_type=0, wire_label="varint",
            payload=varint(2), value=2)
    msg.add(field=2, name="title", wire_type=2, wire_label="length-delimited",
            payload=text("synthetic nested payload"), value="synthetic nested payload")

    add_message_field(msg, field=3, name="device", value="message", child=build_device())
    add_message_field(msg, field=4, name="events", value="message",
                      child=build_event(1, "created", 0.125))
    add_message_field(msg, field=4, name="events", value="message",
                      child=build_event(2, "updated", 9.75))

    json_text = json.dumps({"kind": "demo", "count": 3, "ok": True}, separators=(",", ":"))
    import base64
    b64_json = base64.b64encode(text(json_text))
    msg.add(
        field=5,
        name="base64_json",
        wire_type=2,
        wire_label="length-delimited",
        payload=b64_json,
        value=b64_json.decode("ascii"),
        note="Base64 text decodes to JSON.",
    )

    gzip_payload = gzip.compress(
        text(json.dumps({"compressed": True, "rows": [1, 2, 3]})),
        mtime=0,
    )
    msg.add(
        field=6,
        name="gzip_json",
        wire_type=2,
        wire_label="length-delimited",
        payload=gzip_payload,
        value=gzip_payload.hex(),
        note="gzip-compressed JSON for BLOB Inspector pipeline checks.",
    )

    add_message_field(
        msg,
        field=7,
        name="embedded_bytes_message",
        value="message-like bytes",
        child=build_inner_payload(),
        note="Schema says bytes, but schema-less decoding can treat it as a nested message.",
    )
    add_message_field(msg, field=8, name="structured_child", value="message",
                      child=build_inner_payload())
    return msg


PROTO = """syntax = "proto3";

package crush.fixtures;

message BasicWireTypes {
  uint32 small_count = 1;
  uint32 large_count = 2;
  bool enabled = 3;
  uint64 unix_timestamp = 4;
  float temperature_c = 5;
  fixed32 magic_fixed32 = 6;
  double ratio = 7;
  fixed64 magic_fixed64 = 8;
  string note = 9;
  bytes binary_blob = 10;
  bytes empty_blob = 11;
  string long_text = 16;
}

message NestedMixedPayloads {
  uint32 version = 1;
  string title = 2;
  Device device = 3;
  repeated Event events = 4;
  string base64_json = 5;
  bytes gzip_json = 6;
  bytes embedded_bytes_message = 7;
  InnerPayload structured_child = 8;
}

message Device {
  string device_id = 1;
  bool active = 2;
  float battery_percent = 3;
}

message Event {
  uint32 event_index = 1;
  string event_label = 2;
  double score = 3;
}

message InnerPayload {
  uint32 inner_id = 1;
  string inner_label = 2;
}
"""


def main() -> None:
    (OUT_DIR / "protobuf_test_messages.proto").write_text(PROTO, encoding="utf-8")
    write_fixture("protobuf_basic_wire_types", "BasicWireTypes", build_basic_wire_types())
    write_fixture(
        "protobuf_nested_mixed_payloads",
        "NestedMixedPayloads",
        build_nested_mixed_payloads(),
    )


if __name__ == "__main__":
    main()
