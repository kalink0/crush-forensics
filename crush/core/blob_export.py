# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""What the BLOB Inspector writes next to an export — no Qt.

An export is the bytes after the decode pipeline (or an image rendered from
them); the sidecar JSON next to it records where they came from and how:
the source, the inspected bytes' and every step's size and SHA-256, what a
step left undecoded, and the exported file's own size and SHA-256. It is
versioned (``schema_version``) so later readers -- e.g. a saved pipeline
"recipe" -- can rely on its shape.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from crush.core.blob_decode import Decoded

SIDECAR_SCHEMA_VERSION = 1
SIDECAR_SUFFIX = ".crush.json"

# What the exported file holds.
OUTPUT_BYTES = "bytes after the decode pipeline"
OUTPUT_RENDERED_PNG = "image rendered from the bytes after the decode pipeline (PNG)"


@dataclass(frozen=True)
class PipelineStep:
    name: str  # the step's English name, e.g. "zlib decompress"
    result: Decoded


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sidecar_path(export_path: str) -> str:
    return export_path + SIDECAR_SUFFIX


def _step_entry(step: PipelineStep) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "step": step.name,
        "output_size": len(step.result.data),
        "output_sha256": sha256(step.result.data),
    }
    if step.result.trailing_offset is not None:
        entry["not_decoded"] = {
            "offset": step.result.trailing_offset,
            "size": step.result.trailing_size,
            **({"reason": step.result.trailing_reason} if step.result.trailing_reason else {}),
        }
    if step.result.end_marker_missing:
        entry["end_of_stream_marker_missing"] = True
    return entry


def build_sidecar(
    *,
    tool_version: str,
    source: dict[str, str],
    inspected: bytes,
    steps: list[PipelineStep],
    output_file: str,
    output_kind: str,
    output: bytes,
    rendering: dict[str, str] | None = None,
    created: datetime | None = None,
) -> dict[str, Any]:
    """The sidecar's content. *source* is the provenance the inspector was
    opened with (source file, table/row, key …); *rendering* describes how
    a rendered image was produced (only for :data:`OUTPUT_RENDERED_PNG`)."""
    when = created or datetime.now(timezone.utc)
    sidecar: dict[str, Any] = {
        "schema_version": SIDECAR_SCHEMA_VERSION,
        "tool": {"name": "Crush", "version": tool_version},
        "created_utc": when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": dict(source),
        "inspected": {"size": len(inspected), "sha256": sha256(inspected)},
        "pipeline": [_step_entry(step) for step in steps],
        "output": {
            "file": output_file,
            "content": output_kind,
            "size": len(output),
            "sha256": sha256(output),
        },
    }
    if rendering:
        sidecar["rendering"] = dict(rendering)
    return sidecar


def sidecar_json(sidecar: dict[str, Any]) -> str:
    return json.dumps(sidecar, indent=2, ensure_ascii=False) + "\n"
