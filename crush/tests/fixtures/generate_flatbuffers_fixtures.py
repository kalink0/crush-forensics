# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Generate the synthetic FlatBuffers fixtures for Crush tests.

Everything is produced by the bundled flatc (scripts/download_flatc_binaries.py)
from the schemas and the JSON record in this directory, so the bytes are
what the reference compiler writes -- no external sample data is used:

- flatbuffers_record.bfbs / flatbuffers_record_v1.bfbs: the schemas
  (flatbuffers_record.fbs + its include; the v1 schema lacks one field),
  compiled with ``flatc -b --schema`` -- the first with --bfbs-builtins
  (as Crush compiles a .fbs), v1 without (no bit_flags /
  nested_flatbuffer attributes recorded).
- flatbuffers_record.bin: flatbuffers_record.data.json as a FlatBuffer
  (``flatc -b``), with the CRSH file_identifier.
- flatbuffers_record_sizeprefixed.bin: the same, ``--size-prefixed``.
- flatbuffers_record_vector64.bin: the record plus a ``(vector64)`` field
  (bytes 9, 8, 7), which flatc's JSON output can't write.
- flatbuffers_record.expected.json: flatc's own JSON of flatbuffers_record.bin
  (``flatc --json --strict-json --raw-binary``) -- the ground truth the
  schema decode is checked against.

To regenerate:

    python crush/tests/fixtures/generate_flatbuffers_fixtures.py

Then update ``checksums.json`` with the new files' SHA-256 digests.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(OUT_DIR.parents[2]))

from crush.parsers.flatbuffers_schema import flatc_path  # noqa: E402


def _run(*args: str) -> None:
    subprocess.run([str(flatc_path()), *args], check=True)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        # With --bfbs-builtins as Crush compiles a .fbs; v1 without, as many
        # .bfbs files found on devices are (no bit_flags/nested_flatbuffer).
        for name, extra in (("flatbuffers_record", ["--bfbs-builtins"]), ("flatbuffers_record_v1", [])):
            _run("-b", "--schema", *extra, "-I", str(OUT_DIR), "-o", str(work), str(OUT_DIR / f"{name}.fbs"))
            shutil.copyfile(work / f"{name}.bfbs", OUT_DIR / f"{name}.bfbs")

        schema = str(OUT_DIR / "flatbuffers_record.fbs")
        data = str(OUT_DIR / "flatbuffers_record.data.json")
        _run("-b", "-I", str(OUT_DIR), "-o", str(work), schema, data)
        shutil.copyfile(work / "flatbuffers_record.data.crsh", OUT_DIR / "flatbuffers_record.bin")

        sp = work / "sp"
        _run("-b", "--size-prefixed", "-I", str(OUT_DIR), "-o", str(sp), schema, data)
        shutil.copyfile(sp / "flatbuffers_record.data.crsh", OUT_DIR / "flatbuffers_record_sizeprefixed.bin")

        # flatc's JSON output can't write a (vector64) field ("unknown
        # type"), so the record with one is a file of its own, checked by
        # its known bytes instead of flatc's JSON.
        record = json.loads(Path(data).read_text())
        record["big"] = [9, 8, 7]
        (work / "flatbuffers_record_vector64.json").write_text(json.dumps(record))
        _run("-b", "-I", str(OUT_DIR), "-o", str(work), schema, str(work / "flatbuffers_record_vector64.json"))
        shutil.copyfile(work / "flatbuffers_record_vector64.crsh", OUT_DIR / "flatbuffers_record_vector64.bin")

        js = work / "json"
        _run("--json", "--strict-json", "--raw-binary", "-I", str(OUT_DIR), "-o", str(js),
             schema, "--", str(OUT_DIR / "flatbuffers_record.bin"))
        shutil.copyfile(js / "flatbuffers_record.json", OUT_DIR / "flatbuffers_record.expected.json")
    for name in ("flatbuffers_record.bfbs", "flatbuffers_record_v1.bfbs", "flatbuffers_record.bin",
                 "flatbuffers_record_sizeprefixed.bin", "flatbuffers_record_vector64.bin",
                 "flatbuffers_record.expected.json"):
        print(f"wrote {name} ({(OUT_DIR / name).stat().st_size} B)")


if __name__ == "__main__":
    main()
