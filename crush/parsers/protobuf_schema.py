# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Shared protobuf schema loading, used by ProtobufViewer and the Blob Inspector.

Loads a .proto/.pb/.desc/.fds file into a DescriptorPool + message type list,
and decodes raw bytes against a chosen message type from that pool.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any


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
