# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Shared protobuf schema loading, used by ProtobufViewer and the Blob Inspector.

Loads a .proto/.pb/.desc/.fds file into a DescriptorPool + message type list,
and decodes raw bytes against a chosen message type from that pool.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from crush.parsers.proto_wire import read_varint


class SchemaLoadError(Exception):
    """Raised when a schema file can't be loaded, compiled, or parsed."""


def compile_proto(path: Path) -> bytes:
    """Compile a .proto file to a serialized FileDescriptorSet via grpcio-tools."""
    try:
        from grpc_tools import protoc
    except Exception as exc:
        raise SchemaLoadError(".proto requires grpcio-tools or a .pb descriptor set") from exc

    import tempfile

    out_path = Path(tempfile.mkdtemp()) / "descriptor.fds"
    args = [
        "protoc",
        f"-I{path.parent}",
        f"--descriptor_set_out={out_path}",
        "--include_imports",
        str(path),
    ]
    rc = protoc.main(args)
    if rc != 0 or not out_path.exists():
        raise SchemaLoadError("Failed to compile .proto file")
    return out_path.read_bytes()


def collect_message_names(fds: Any) -> list[str]:
    """Flatten all (including nested) message type names out of a FileDescriptorSet."""
    names: list[str] = []

    def walk(prefix: str, msg: Any) -> None:
        full = f"{prefix}.{msg.name}" if prefix else msg.name
        names.append(full)
        for nested in msg.nested_type:
            walk(full, nested)

    for fd in fds.file:
        pkg = fd.package or ""
        for msg in fd.message_type:
            walk(pkg, msg)

    names.sort()
    return names


def load_descriptor_set(path: Path) -> dict[str, Any]:
    """Load a .proto/.pb/.desc/.fds file into a DescriptorPool + message name list.

    Returns {"pool": DescriptorPool, "message_names": list[str]}.
    Raises SchemaLoadError with a user-facing message on any failure.
    """
    try:
        from google.protobuf import descriptor_pb2, descriptor_pool
    except Exception as exc:
        raise SchemaLoadError("Install protobuf to use schema decoding") from exc

    if path.suffix.lower() == ".proto":
        data = compile_proto(path)
    else:
        data = path.read_bytes()

    fds = descriptor_pb2.FileDescriptorSet()
    try:
        fds.ParseFromString(data)
    except Exception as exc:
        raise SchemaLoadError("Invalid descriptor set") from exc

    pool = descriptor_pool.DescriptorPool()
    for fd in fds.file:
        pool.Add(fd)

    message_names = collect_message_names(fds)
    if not message_names:
        raise SchemaLoadError("No message types found")

    return {"pool": pool, "message_names": message_names}


def decode_message_with_schema(pool: Any, message_name: str, raw: bytes) -> Any:
    """Parse raw bytes as message_name using pool. Returns the populated message object."""
    from google.protobuf import message_factory

    descriptor = pool.FindMessageTypeByName(message_name)
    cls = message_factory.GetMessageClass(descriptor)
    msg = cls()
    msg.ParseFromString(raw)
    return msg


def schema_byte_ranges(
    pool: Any,
    message_name: str,
    raw: bytes,
) -> dict[tuple[str, ...], dict[str, tuple[int, int] | list[tuple[int, int]]]]:
    """Return tree-path to byte-range metadata for a schema-decoded message.

    Paths match json_format.MessageToDict(..., preserving_proto_field_name=True):
    dict keys are field names, and repeated values add their zero-based list index.
    Ranges are half-open absolute byte offsets into *raw*.
    """
    descriptor = pool.FindMessageTypeByName(message_name)
    counts: dict[tuple[str, ...], int] = {}
    ranges: dict[tuple[str, ...], dict[str, tuple[int, int] | list[tuple[int, int]]]] = {}
    _collect_message_ranges(raw, descriptor, (), 0, counts, ranges)
    return ranges


def _collect_message_ranges(
    data: bytes,
    descriptor: Any,
    path: tuple[str, ...],
    base_offset: int,
    counts: dict[tuple[str, ...], int],
    ranges: dict[tuple[str, ...], dict[str, tuple[int, int] | list[tuple[int, int]]]],
) -> None:
    fields_by_number = {field.number: field for field in descriptor.fields}
    idx = 0
    while idx < len(data):
        entry_start = idx
        key, idx_after_key = read_varint(data, idx)
        if key is None:
            break
        idx = idx_after_key
        field_number = key >> 3
        wire_type = key & 0x07
        field = fields_by_number.get(field_number)
        value_start = idx

        if wire_type == 0:
            _, idx = read_varint(data, idx)
        elif wire_type == 1:
            idx = min(len(data), idx + 8)
        elif wire_type == 2:
            length, idx_after_len = read_varint(data, idx)
            if length is None:
                break
            value_start = idx_after_len
            idx = min(len(data), idx_after_len + length)
        elif wire_type == 5:
            idx = min(len(data), idx + 4)
        else:
            break

        if field is None:
            continue

        field_path = path + (field.name,)
        target_path = _schema_value_path(field, field_path, counts)
        key_range = (base_offset + entry_start, base_offset + idx_after_key)
        value_range = (base_offset + value_start, base_offset + idx)
        byte_range = (base_offset + entry_start, base_offset + idx)
        highlight_ranges = [key_range]
        if wire_type == 2:
            highlight_ranges.append((base_offset + idx_after_key, base_offset + value_start))
        highlight_ranges.append(value_range)
        _store_range(ranges, field_path, byte_range, highlight_ranges)
        if target_path != field_path:
            _store_range(ranges, target_path, byte_range, highlight_ranges)

        if wire_type == 2 and field.message_type is not None and value_start <= idx:
            payload = data[value_start:idx]
            if _is_map_field(field):
                # Map fields render as a dict keyed by decoded map keys. Keep the
                # enclosing field mapped; per-entry key paths require value decode.
                continue
            _collect_message_ranges(
                payload,
                field.message_type,
                target_path,
                base_offset + value_start,
                counts,
                ranges,
            )


def _schema_value_path(
    field: Any,
    field_path: tuple[str, ...],
    counts: dict[tuple[str, ...], int],
) -> tuple[str, ...]:
    if _is_map_field(field):
        return field_path
    if not _is_repeated(field):
        return field_path
    index = counts.get(field_path, 0)
    counts[field_path] = index + 1
    return field_path + (str(index),)


def _is_repeated(field: Any) -> bool:
    return bool(field.label == field.LABEL_REPEATED)


def _is_map_field(field: Any) -> bool:
    if field.message_type is None:
        return False
    return bool(getattr(field.message_type.GetOptions(), "map_entry", False))


def _store_range(
    ranges: dict[tuple[str, ...], dict[str, tuple[int, int] | list[tuple[int, int]]]],
    path: tuple[str, ...],
    byte_range: tuple[int, int],
    highlight_ranges: list[tuple[int, int]],
) -> None:
    existing = ranges.get(path)
    if existing is None:
        ranges[path] = {
            "byte_range": byte_range,
            "highlight_ranges": list(highlight_ranges),
        }
        return

    existing_byte_range = existing.get("byte_range")
    if isinstance(existing_byte_range, tuple):
        existing["byte_range"] = (
            min(existing_byte_range[0], byte_range[0]),
            max(existing_byte_range[1], byte_range[1]),
        )
    else:
        existing["byte_range"] = byte_range
    existing_highlights = existing.get("highlight_ranges")
    if isinstance(existing_highlights, list):
        existing_highlights.extend(highlight_ranges)
    else:
        existing["highlight_ranges"] = list(highlight_ranges)
