# crush-forensics

![crush](.github/crush_readme_banner.svg)

*Surf through data types — from archive to hex in one flow.*

[![CI](https://github.com/kalink0/crush-forensics/actions/workflows/ci.yml/badge.svg)](https://github.com/kalink0/crush-forensics/actions/workflows/ci.yml)
[![Nightly](https://github.com/kalink0/crush-forensics/actions/workflows/nightly.yml/badge.svg)](https://github.com/kalink0/crush-forensics/actions/workflows/nightly.yml)
[![Forensic audit](https://img.shields.io/endpoint?url=https%3A%2F%2Fkalink0.github.io%2Fcrush-forensics%2Faudit%2Fbadge.json)](https://kalink0.github.io/crush-forensics/audit/)
[![Release](https://img.shields.io/github/v/release/kalink0/crush-forensics?display_name=tag)](https://github.com/kalink0/crush-forensics/releases)
[![License](https://img.shields.io/github/license/kalink0/crush-forensics)](https://github.com/kalink0/crush-forensics/blob/main/LICENSE)
![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20windows%20%7C%20macOS-success)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)

**Crush is a digital forensic analysis workbench.** Open archives, mobile backups, disk images, folders and single files, identify what's inside, and inspect it in dedicated viewers. Sources are opened without extracting them first. Built for examiners who need to look inside a specific file or source, not run a full processing pipeline. Every release runs a forensic test suite that checks whether Crush leaves the evidence untouched.

## Install

| Platform | Command |
|----------|---------|
| macOS (Homebrew) | `brew tap kalink0/forensics && brew trust kalink0/forensics && brew install --cask crush-forensics` |
| Windows (winget) | `winget install kalink0.Crush` |
| Windows (Scoop) | `scoop bucket add forensics https://github.com/kalink0/scoop-forensics` then `scoop install forensics/crush-forensics` |
| Linux | AppImage from [Releases](https://github.com/kalink0/crush-forensics/releases); needs glibc 2.39 or newer (e.g. Ubuntu 24.04, Debian 13) |

Running from source: see [Development setup](#development-setup).

## What Crush opens

| Source | Details |
|--------|---------|
| Archives | ZIP, TAR, 7z — browsed in place, including password-protected ones |
| Mobile backups | iOS (iTunes/Finder) and Android (`adb backup`) — browsable as a file tree (iOS rebuilt from `Manifest.db` instead of hashed names), encrypted backups supported |
| Disk images | Raw and forensic acquisitions (E01 and others) with common desktop, mobile and embedded/flash filesystems — no mounting, no admin rights. Built on [ewfprobe](https://github.com/abrignoni/ewfprobe) and [qnxprobe](https://github.com/abrignoni/qnxprobe) by Alexis Brignoni. |
| Logical evidence | EnCase L01 and FTK Imager AD1 (also AD-encrypted) — the collected files with their recorded hashes |
| Cellebrite UFD / UFDX | ZIP-based extractions — browsed as a file tree, recorded hashes verifiable; physical images and other dump types not supported |
| Cellebrite UFDR (10.x) | File system and derived files (e.g. decrypted app databases) — browsed under their device paths, recorded hashes verifiable |
| Folders & files | Any folder or single file |

Not a full disk-forensics suite: no carving, no journal analysis, no snapshots, no RAID/LVM. Exact formats, filesystems and limitations: [Format Support & Parser Limitations](crush/docs/format-support.md).

## Viewers

| Category | Viewers |
|----------|---------|
| Databases | SQLite (incl. WAL, free blocks/pages, SQLCipher¹), LevelDB, Realm (incl. encrypted¹), MMKV |
| Structured data | JSON, XML, Plist/BPlist, ABX, SEGB, Protobuf (schema-less or with schema) |
| Raw & text | Hex, Text |
| Media & documents | Image (incl. C2PA / AI-provenance metadata, no signature validation), Audio/Video, PDF (incl. revision history) |
| Logs | Multi-Log Studio; **Send to Peach** hands sources to the bundled [peach-forensics](https://github.com/kalink0/peach-forensics) log viewer |

¹ Key must be supplied by the user; Crush does not recover keys.

## Analysis tools

- **File format database** — magic-byte/extension identification with platform, forensic relevance and spec link, also for formats without a viewer.
- **Value Inspector** — every plausible interpretation of a value at once: integers, floats, timestamp epochs, UUIDs, network addresses, sizes.
- **BLOB Inspector** — chain decode/decompress steps (Base64, hex, zlib, gzip, lzfse) and render as hex, text, JSON, XML, plist, ABX, Protobuf or image. Open the result as a new tab, or export it with a sidecar recording source, steps and SHA-256 hashes. Available on any BLOB cell or pasted value (Tools → BLOB Inspector).
- **Hex provenance** — with the hex view open, selecting an entry in the SQLite, Protobuf, MMKV or Realm viewer shows exactly where its bytes are.
- **Run Analyzer** — run curated modules ported from iLEAPP/ALEAPP against a directory; results as a sortable, searchable table.

Details for all features: [Feature Reference](crush/docs/feature-reference.md)

## Forensic integrity

**Integrity mode** — file, ZIP and TAR sources hashed on open, exports get a hash manifest.

**Forensic test suite** — runs on Linux, macOS and Windows:

- Source immutability
- No side-effect files (e.g. SQLite `-wal`/`-shm`)
- Read-only media
- Known-output verification (SHA-256-pinned references)
- Completeness
- Reproducibility

Every release attaches its own audit result, including failures: [latest audit report](https://kalink0.github.io/crush-forensics/audit/) · [all releases](https://kalink0.github.io/crush-forensics/audit/history.html) · [JSON](https://github.com/kalink0/crush-forensics/releases/latest/download/crush-forensic-audit.json) · [test coverage per format/source](crush/docs/forensic-test-coverage.md)

## Screenshots

| Start screen (Linux) | SQLite summary (Windows) |
|---|---|
| ![](crush/docs/pictures/example_start_screen.png) | ![](crush/docs/pictures/example_ios_win_sqlite_summary.png) |
| **BLOB Inspector (Linux)** | **Value Inspector (Linux)** |
| ![](crush/docs/pictures/example_BLOB_inspector.png) | ![](crush/docs/pictures/example_value_inspector.png) |

<details>
<summary>More screenshots</summary>

Drag & drop files (Linux)
![Drag & drop zones (Linux)](crush/docs/pictures/example_drag_drop.png)

Format reference (Linux)
![Format reference (Linux)](crush/docs/pictures/example_lin_file_formats.png)

iOS SEGB (Windows)
![iOS SEGB (Windows)](crush/docs/pictures/example_ios_win_segb.png)

Android ABX (Linux)
![Android ABX (Linux)](crush/docs/pictures/example_android_lin_abx.png)

Android Video (Linux)
![Android Video (Linux)](crush/docs/pictures/example_android_lin_video.png)

Integrity Mode (Linux)
![Integrity Mode (Linux)](crush/docs/pictures/example_dark_forensic_mode_linux.png)

</details>

## Documentation

- [Feature Reference](crush/docs/feature-reference.md)
- [Format Support & Parser Limitations](crush/docs/format-support.md)
- [Format Reference](https://kalink0.github.io/crush-forensics/formats/): every format in Crush's format database (forensic relevance, signatures, references, Crush support), as of the latest build (nightly or release)
- [Forensic Test Coverage](crush/docs/forensic-test-coverage.md)
- [Translating Crush](TRANSLATING.md)

## Deep dives

| Topic | Post |
|-------|------|
| SQLite | [What Hides in the WAL](https://bebinary4n6.blogspot.com/2026/05/what-hides-in-wal-sqlite-forensics-with.html) |
| RealmDB | [Object by Object](https://bebinary4n6.blogspot.com/2026/05/object-by-object-realmdb-forensics-with.html) |
| LevelDB | [Reading the CURRENT](https://bebinary4n6.blogspot.com/2026/05/reading-current-leveldb-forensics-with.html) |
| SEGB / Biome | [Beyond the C](https://bebinary4n6.blogspot.com/2026/05/beyond-c-segb-and-biome-forensics-with.html) |
| Protobuf | [Reading the Wire](https://bebinary4n6.blogspot.com/2026/06/reading-wire-protobuf-without-map.html) |

## Usage

```bash
crush /path/to/evidence.zip /path/to/case_folder
crush --open /path/to/evidence.zip --open /path/to/case_folder
```

Positional paths and `--open PATH` (repeatable) are equivalent; each invocation opens a new window.

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
python scripts/download_unifiedlog_binaries.py   # Apple Unified Log support
python scripts/download_peach_binaries.py        # "Send to Peach"
crush                                             # or: python -m crush
```

<details>
<summary>System dependencies (if Qt, media or libmagic errors occur)</summary>

| Purpose | Debian/Ubuntu | Fedora | Arch |
|---------|---------------|--------|------|
| Qt GUI | `libgl1 libegl1 libxcb-xinerama0 libxkbcommon-x11-0` | `mesa-libGL mesa-libEGL libxcb libxkbcommon-x11` | `mesa libglvnd libxcb libxkbcommon-x11` |
| libmagic | `libmagic1` | `file-libs` | `file` |
| Audio/Video | `gstreamer1.0-plugins-base gstreamer1.0-plugins-good` | `gstreamer1-plugins-base gstreamer1-plugins-good` | `gstreamer gst-plugins-base gst-plugins-good` |
| Audio output | `libpulse0` | `pulseaudio-libs` | `libpulse` |

- **macOS:** `brew install libmagic`; install `gstreamer` only if media playback fails.
- **Windows:** nothing extra; if the app fails to start, install the Microsoft Visual C++ Redistributable 2015–2022 (x64).

</details>

## Acknowledgements

Crush builds on the work of the DFIR community:

- [CCL Solutions Group](https://github.com/cclgroupltd) — bundled [ccl_bplist](https://github.com/cclgroupltd/ccl-bplist) (BSD 3-Clause), [ccl_segb](https://github.com/cclgroupltd/ccl_segb) (MIT), [ccl_leveldb](https://github.com/cclgroupltd/ccl_chromium_reader) (MIT)
- [Mandiant](https://github.com/mandiant) — [macos-UnifiedLogs](https://github.com/mandiant/macos-UnifiedLogs) for Apple Unified Log parsing (Apache 2.0)
- [Alexis Brignoni](https://github.com/abrignoni) — [ewfprobe](https://github.com/abrignoni/ewfprobe) and [qnxprobe](https://github.com/abrignoni/qnxprobe) (disk images and filesystems, MIT), [mmkv-parser](https://github.com/abrignoni/mmkv-parser) (MIT) and the [iLEAPP](https://github.com/abrignoni/iLEAPP)/[ALEAPP](https://github.com/abrignoni/ALEAPP) artifact scripts behind Run Analyzer (MIT)
- Sibling projects: [peach-forensics](https://github.com/kalink0/peach-forensics) (log viewer) and [crush-analyze](https://github.com/kalink0/crush-analyze) (analyzer modules), both Apache 2.0

Special thanks to [@dugeonlady](https://github.com/dugeonlady) for suggesting the Rainbow theme — because digital forensics tools don't have to be grey. Or dark. Someone has to bring colour to the hex dump. Evidence: *View → Theme → Rainbow*. She was right.

![Rainbow theme](crush/docs/pictures/rainbow_theme.gif)

Parts of this software were developed with assistance from [Claude AI / Claude Code](https://claude.ai) by Anthropic.

## Bugs and feature requests

[GitHub Issues](https://github.com/kalink0/crush-forensics/issues) — please include the Crush version (**Help → About**), your OS, and steps to reproduce.