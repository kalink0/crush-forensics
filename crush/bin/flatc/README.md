# flatc binaries

This directory holds the platform-appropriate binary of **flatc**, the
FlatBuffers schema compiler. Crush uses it to compile a text schema (`.fbs`)
to a binary schema (`.bfbs`) for the FlatBuffers viewer and the BLOB
Inspector. A `.bfbs` is read without flatc.

- **Project:** https://github.com/google/flatbuffers
- **Licence:** Apache 2.0 (same as Crush)
- **Version bundled:** see `VERSION` in `scripts/download_flatc_binaries.py`

## Expected filenames

| Platform | Filename | Source |
|---|---|---|
| Linux x86\_64 | `flatc-linux-x86_64` | official release binary (statically linked) |
| Linux aarch64 | `flatc-linux-aarch64` | built from the release source tarball |
| macOS (arm64 + x86\_64) | `flatc-macos` | built from the release source tarball, targets macOS 13.0 |
| Windows x86\_64 | `flatc-windows-x86_64.exe` | official release binary |

## Downloading

Run the helper script from the repository root:

```bash
python scripts/download_flatc_binaries.py
```

It downloads the Linux x86\_64 and Windows binaries on every OS, verifies
their SHA-256, and on macOS or Linux aarch64 also builds flatc from the
release's source tarball (needs `cmake` and a C++ compiler). The official
macOS binaries require macOS 15.5; the build targets macOS 13.0 instead.

## Why binaries are not committed to git

They are pre-built artifacts of several MB each that change rarely.
Committing them would bloat the repository history permanently. The script
fetches the exact version pinned in `scripts/download_flatc_binaries.py`.
