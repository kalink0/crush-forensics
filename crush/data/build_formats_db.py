# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Build script — regenerates formats.db from the FORMATS list below.

Run from the project root:
    python -m crush.data.build_formats_db

This is the single source of truth for all format knowledge.
Parsers carry no metadata — format info lives here only.

formats.db is English. Every forensic_relevance and magic-byte description
is written as QT_TRANSLATE_NOOP("FormatKnowledge", text, <the format's
name>) so it lands in the translation catalog (scripts/i18n.py update); the
UI translates it at display time. Write a multi-line text as adjacent
string literals *without* parentheses around them -- lupdate silently
skips a parenthesised text. test_format_db checks both.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from crush.core.issues import QT_TRANSLATE_NOOP

_OUT = Path(__file__).parent / "formats.db"

# ---------------------------------------------------------------------------
# Format definitions
# Each entry:
#   name            Full human-readable name
#   short_name      Abbreviation shown in UI
#   category        database | configuration | log | execution | document |
#                   filesystem | disk_image | archive | serialization |
#                   memory | network | uncategorized
#                   (a new one also goes into format_db.FORMAT_CATEGORIES,
#                   the translation catalog's list)
#   forensic_relevance  What an investigator would find here
#   platforms       List of strings: "iOS", "macOS", "Android", "Windows", "Linux"
#   parser_class    Class name that handles this — either a crush/parsers/
#                   AbstractParser subclass (per-file content parser, looked
#                   up via FormatDatabase.by_parser_class() from a running
#                   parser instance), or a crush/core/vfs.py VFS backend
#                   (whole-container support, e.g. ZipVFS/TarVFS/
#                   AndroidBackupVFS — never looked up that way, but still
#                   drives the "Supported" vs "Not yet supported" label in
#                   the Format Reference / Format Info dialogs). None if
#                   Crush doesn't support this format at all yet.
#   magic           List of dicts: {"offset": int | None, "value": bytes,
#                                   "description": str}
#                   All entries must match for a hit. Use offset=None for
#                   trailer/unknown offsets (informational only).
#   extensions      List of lowercase extensions including the dot
#   links           List of (label, url) tuples — reference links
#   status          "draft" (excluded from DB) | "reviewed" (included in DB)
# ---------------------------------------------------------------------------

FORMATS: list[dict[str, Any]] = [
    {
        "name": "Android Binary XML (ABX)",
        "short_name": "ABX",
        "category": "configuration",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Android system and app configuration stored as compact binary XML, "
            "introduced in Android 12. Key files include packages.xml (installed apps "
            "and permissions), settings files (global, secure, system), and app backup "
            "manifests. Provides insight into installed software, permission grants, "
            "and system configuration state.",
            "Android Binary XML (ABX)",
        ),
        "platforms": ["Android"],
        "parser_class": "AbxParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\x41\x42\x58\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Android Binary XML header",
                    "Android Binary XML (ABX)",
                ),
            }
        ],
        "extensions": [".xml", ".abx"],
        "links": [
            (
                "AOSP source (BinaryXmlSerializer)",
                "https://cs.android.com/android/platform/superproject/main/+/main:frameworks/libs/modules-utils/java/com/android/modules/utils/BinaryXmlSerializer.java",
            ),
            (
                "AOSP abx utility source",
                "https://android.googlesource.com/platform/frameworks/base/+/master/cmds/abx/",
            ),
            (
                "CCL Solutions Group — ABX research",
                "https://www.cclsolutionsgroup.com/post/android-abx-binary-xml",
            ),
            (
                "Android settings forensic analysis (Mattia Epifani)",
                "https://blog.digital-forensics.it/2024/01/analysis-of-android-settings-during.html",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "Android Backup Archive",
        "short_name": "Android backup",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Backup created via ADB backup functionality (deprecated since Android 12 / API 31+). "
            "The archive is a TAR stream compressed with Deflate, optionally encrypted with AES-256. "
            "Contains app data, shared storage, and system settings depending on app configuration. "
            "Forensically relevant as a logical acquisition path — but significantly limited: "
            "apps setting allowBackup=false (e.g. banking, messaging) are excluded, "
            "and apps targeting Android 12+ are automatically excluded. "
            "Can reveal installed app data, preferences, and media for apps that permit backup.",
            "Android Backup Archive",
        ),
        "platforms": ["Android"],
        "parser_class": "AndroidBackupVFS",
        "magic": [
            {
                "offset": 0,
                "value": b"\x41\x4e\x44\x52\x4f\x49\x44\x20\x42\x41\x43\x4b\x55\x50\x0a",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Android backup header",
                    "Android Backup Archive",
                ),
            }
        ],
        "extensions": [".ab"],
        "links": [
            (
                "AOSP source (BackupManagerService)",
                "https://android.googlesource.com/platform/frameworks/base/+/refs/heads/jb-dev/services/java/com/android/server/BackupManagerService.java",
            ),
            (
                "Android Backup Extractor (ABE)",
                "https://github.com/nelenkov/android-backup-extractor",
            ),
            (
                "Format internals (Nikolay Elenkov)",
                "https://nelenkov.blogspot.com/2012/06/unpacking-android-backups.html",
            ),
            (
                "ADB backup forensic acquisition (Andrea Fortuna)",
                "https://andreafortuna.org/2017/12/29/forensic-logical-acquisition-of-android-devices-using-adb-backup/",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "Binary Property List",
        "short_name": "bplist",
        "category": "configuration",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "App preferences, caches, configuration, and iOS/macOS backup structures "
            "such as Manifest.plist and Info.plist. Many bplist files are NSKeyedArchiver "
            "object graphs — recognisable by the '$archiver' key — which can contain "
            "messages, contacts, health records, and other complex app data. "
            "Timestamps use Mac Absolute Time (seconds since 2001-01-01 UTC). "
            "Widely used across all Apple platforms and most third-party iOS/macOS apps.",
            "Binary Property List",
        ),
        "platforms": ["iOS", "macOS"],
        "parser_class": "PlistParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\x62\x70\x6c\x69\x73\x74",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Binary plist magic ('bplist')",
                    "Binary Property List",
                ),
            }
        ],
        "extensions": [".plist"],
        "links": [
            (
                "Apple CoreFoundation source (format spec)",
                "https://github.com/apple-oss-distributions/CF/blob/CF-550/CFBinaryPList.c",
            ),
            (
                "Apple developer docs (Property Lists)",
                "https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFPropertyLists/",
            ),
            (
                "Mobile Forensics – The File Format Handbook: Property Lists (Springer, 2022)",
                "https://doi.org/10.1007/978-3-030-98467-0_6",
            ),
            (
                "NSKeyedArchiver plist forensics (Sarah Edwards / mac4n6)",
                "https://www.mac4n6.com/blog/tag/plist",
            ),
            (
                "ccl-bplist Python module (CCL Solutions Group)",
                "https://github.com/cclgroupltd/ccl-bplist",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "CBOR (Concise Binary Object Representation)",
        "short_name": "CBOR",
        "category": "serialization",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "RFC 8949 binary serialization format increasingly found in mobile and web app data. "
            "Mandatory encoding for WebAuthn/FIDO2 authentication — passkey credential data, "
            "attestation objects, and public key material on iOS, Android, and Windows are "
            "CBOR-encoded. Also used in some messaging app caches and IoT device communication. "
            "No magic bytes — identification relies on file extension or surrounding context. "
            "Structurally similar to JSON but binary; a CBOR decoder is required to recover "
            "readable key/value structures.",
            "CBOR (Concise Binary Object Representation)",
        ),
        "platforms": ["iOS", "macOS", "Android", "Windows"],
        "parser_class": None,
        "magic": [],
        "extensions": [".cbor"],
        "links": [
            (
                "Format spec (RFC 8949)",
                "https://www.rfc-editor.org/rfc/rfc8949.html",
            ),
            (
                "CBOR overview and tools",
                "https://cbor.io/",
            ),
            (
                "COSE structures and process (CBOR Object Signing and Encryption, RFC 9052)",
                "https://www.rfc-editor.org/rfc/rfc9052.html",
            ),
            (
                "WebAuthn spec (CBOR usage)",
                "https://www.w3.org/TR/webauthn-2/",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "Realm Database",
        "short_name": "Realm",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Mobile app local object store used as a SQLite alternative, now marketed "
            "as MongoDB Atlas Device SDK. A single '.realm' file stores all object data "
            "in a B+ tree of fixed-size arrays. Crush extracts the full schema (class/table "
            "names such as 'class_Driver', 'class_Event', 'class_Photo') and decodes both "
            "root references (top_ref[0] / top_ref[1]) that act as a WAL-like journaling "
            "pair — the inactive branch may contain superseded data not yet checkpointed. "
            "Class names reveal which app features were in use and what data categories "
            "are present (users, locations, media, events, etc.). "
            "Some Realm databases are AES-256 encrypted — key material is typically "
            "hardcoded or derivable from the app binary.",
            "Realm Database",
        ),
        "platforms": ["iOS", "macOS", "Android", "Windows", "Linux"],
        "parser_class": "RealmParser",
        "magic": [
            {
                "offset": 16,
                "value": b"\x54\x2d\x44\x42",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Realm header mnemonic (T-DB)",
                    "Realm Database",
                ),
            }
        ],
        "extensions": [".realm"],
        "links": [
            (
                "Realm Studio (open .realm files)",
                "https://www.mongodb.com/docs/atlas/device-sdks/studio/open-realm-file/",
            ),
            (
                "Realm forensics primer (Alexis Brignoni)",
                "https://abrignoni.blogspot.com/2019/11/realm-database-storage-primer-for.html",
            ),
            (
                "The Realm Files - Vol 3 - The Realm Header (Damien Attoe)",
                "https://digital4n6withdamien.blogspot.com/2026/01/the-realm-files-vol-3-realm-header.html",
            ),
            (
                "The Realm Files - Vol 2 - Physical Structure Overview (Damien Attoe)",
                "https://digital4n6withdamien.blogspot.com/2025/11/the-realm-files-vol-2-physical.html",
            ),
            (
                "Deleted data recovery from Realm DB (ScienceDirect)",
                "https://www.sciencedirect.com/science/article/abs/pii/S2666281722000221",
            ),
            (
                "Mobile Forensics – The File Format Handbook: Realm (Springer, 2022)",
                "https://doi.org/10.1007/978-3-030-98467-0_8",
            ),
            (
                "Object by Object — RealmDB Forensics with crush (beBinary)",
                "https://bebinary4n6.blogspot.com/2026/05/object-by-object-realmdb-forensics-with.html",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "Android DEX Bytecode",
        "short_name": "DEX",
        "category": "execution",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Compiled Android application bytecode executed by the Android Runtime (ART). "
            "Found as classes.dex (and classes2.dex, classes3.dex in multi-DEX apps) inside "
            "APK packages, which are ZIP archives. Decompilation with tools like jadx or "
            "apktool can recover app logic, hardcoded API keys, credentials, server endpoints, "
            "and encryption keys. Presence of OAT/ODEX companions confirms the app was "
            "installed and executed on the device.",
            "Android DEX Bytecode",
        ),
        "platforms": ["Android"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"\x64\x65\x78\x0a",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "DEX magic ('dex\\n')",
                    "Android DEX Bytecode",
                ),
            }
        ],
        "extensions": [".dex"],
        "links": [
            (
                "DEX format specification (AOSP)",
                "https://source.android.com/docs/core/runtime/dex-format",
            ),
            (
                "jadx — DEX to Java decompiler",
                "https://github.com/skylot/jadx",
            ),
            (
                "apktool — APK reverse engineering",
                "https://apktool.org/",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "Apple Disk Image (DMG)",
        "short_name": "DMG",
        "category": "disk_image",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Apple disk image format. A UDIF image consists of data blocks (raw or "
            "compressed with zlib, bzip2, LZFSE or LZMA), an XML property list holding the "
            "block map, and a 512-byte 'koly' trailer at EOF instead of a file header; raw "
            "images can lack the trailer. Typically contains an HFS+, APFS, FAT32 or ExFAT "
            "filesystem. Can be AES-128 or AES-256 encrypted with a password or a "
            "certificate; an encrypted image begins 'encrcdsa' (version 2) or ends with "
            "'cdsaencr' (version 1), and the 'koly' trailer is then inside the encrypted "
            "data. Variants: segmented UDIF (.dmgpart), sparse image (.sparseimage, header "
            "'sprs', blocks allocated as written), sparse bundle (.sparsebundle, a folder "
            "of band files). Common as a software installer (Downloads folders), as "
            "user-created encrypted containers, as the storage of Time Machine backups to "
            "network destinations (sparse bundle), and as a preferred acquisition format "
            "for macOS devices (SWGDE).",
            "Apple Disk Image (DMG)",
        ),
        "platforms": ["macOS"],
        "parser_class": "RawImageVFS",
        "magic": [
            {
                "offset": None,
                "value": b"\x6b\x6f\x6c\x79",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "UDIF 'koly' trailer block at EOF-512 (no file header magic)",
                    "Apple Disk Image (DMG)",
                ),
            },
            {
                "offset": 0,
                "value": b"encrcdsa",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Encrypted disk image, version 2 header",
                    "Apple Disk Image (DMG)",
                ),
            },
            {
                "offset": None,
                "value": b"cdsaencr",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Encrypted disk image, version 1 trailer at EOF",
                    "Apple Disk Image (DMG)",
                ),
            },
            {
                "offset": 0,
                "value": b"sprs",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Sparse image (.sparseimage) header",
                    "Apple Disk Image (DMG)",
                ),
            },
        ],
        "extensions": [".dmg", ".sparseimage", ".sparsebundle"],
        "links": [
            (
                "Mac OS disk image types — format documentation (libyal/libmodi)",
                "https://github.com/libyal/libmodi/blob/main/documentation/Mac%20OS%20disk%20image%20types.asciidoc",
            ),
            (
                "DMG format reverse-engineered (newosxbook.com)",
                "https://newosxbook.com/DMG.html",
            ),
            (
                "Apple Disk Image (Wikipedia — UDIF structure)",
                "https://en.wikipedia.org/wiki/Apple_Disk_Image",
            ),
            (
                "ForensicsWiki — DMG",
                "https://forensics.wiki/dmg/",
            ),
            (
                "SWGDE Best Practices macOS Forensic Acquisition",
                "https://www.swgde.org/documents/published-complete-listing/23-f-005-swgde-best-practices-apple-macos-forensic-acquisition/",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "ELF Executable",
        "short_name": "ELF",
        "category": "execution",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Native executable and shared library format for Android and Linux. "
            "On Android, ELF shared libraries (.so) are bundled inside APK packages "
            "under lib/ and loaded at runtime via JNI — they often contain hardcoded "
            "strings, API endpoints, encryption keys, and security-sensitive logic "
            "not visible in DEX bytecode. Malware authors frequently move sensitive "
            "code into native libraries precisely because ELF is harder to decompile "
            "than DEX. On Linux, ELF binaries reveal installed software and potential "
            "implants. Strings extraction is a fast first step; full analysis requires "
            "a disassembler such as Ghidra or IDA Pro.",
            "ELF Executable",
        ),
        "platforms": ["Android", "Linux"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"\x7f\x45\x4c\x46",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ELF magic number",
                    "ELF Executable",
                ),
            }
        ],
        "extensions": [".so", ".elf"],
        "links": [
            (
                "ELF format specification (man page)",
                "https://man7.org/linux/man-pages/man5/elf.5.html",
            ),
            (
                "Ghidra — open source reverse engineering tool (NSA)",
                "https://github.com/NationalSecurityAgency/ghidra",
            ),
            (
                "Reversing Android native libraries (HackTricks)",
                "https://hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/reversing-native-libraries.html",
            ),
            (
                "ELF shared library injection forensics",
                "https://engineering.backtrace.io/2016-04-14-elf-shared-library-injection-forensics/",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "Windows Event Log (EVTX)",
        "short_name": "EVTX",
        "category": "log",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Windows structured event log format used since Vista/Server 2008, "
            "stored under C:\\Windows\\System32\\winevt\\Logs\\. "
            "Key forensic sources: Security.evtx (logons 4624/4625, account changes, "
            "privilege use 4672), System.evtx (service installs, crashes, boot events), "
            "Microsoft-Windows-PowerShell (4103/4104 script block logging), "
            "Microsoft-Windows-Sysmon (process creation, network, file events). "
            "Event ID 1102 (Security log cleared) and 104 (System log cleared) are "
            "significant anti-forensic indicators. "
            "Note: event messages are not stored in the EVTX file itself — they are "
            "resolved via provider DLLs at display time. Copying EVTX files off-system "
            "may result in unresolvable messages without a message database.",
            "Windows Event Log (EVTX)",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"\x45\x6c\x66\x46\x69\x6c\x65\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "EVTX file signature ('ElfFile')",
                    "Windows Event Log (EVTX)",
                ),
            }
        ],
        "extensions": [".evtx"],
        "links": [
            (
                "EVTX format specification (libevtx)",
                "https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc",
            ),
            (
                "ForensicsWiki — Windows XML Event Log (EVTX)",
                "https://forensics.wiki/windows_xml_event_log_(evtx)/",
            ),
            (
                "Windows Event Log forensics (ElcomSoft)",
                "https://blog.elcomsoft.com/2026/02/forensic-analysis-of-windows-10-and-11-event-logs/",
            ),
            (
                "EVTX and message resolution (Velociraptor docs)",
                "https://docs.velociraptor.app/docs/forensic/event_logs/",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "JPEG Image",
        "short_name": "JPEG",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Photos and screenshots from device cameras, messaging apps, and downloads. "
            "EXIF metadata can contain GPS coordinates, timestamps, device model, camera "
            "settings, and an embedded thumbnail — the thumbnail may reveal original content "
            "even after the main image was cropped or edited. "
            "EXIF data can be stripped or manipulated, so timestamps should be corroborated "
            "with filesystem metadata and other sources. "
            "Quantization tables in the JPEG structure can identify the software used to "
            "save or re-encode the file. "
            "JPEG is a common steganographic carrier — data can be hidden in DCT coefficients "
            "or appended after the EOI marker. "
            "XMP metadata may additionally record editing history and software chain. "
            "An embedded C2PA (Content Credentials) manifest, carried in APP11 marker "
            "segments, can record the generating/editing software, an IPTC Digital Source "
            "Type (a direct AI-generation/-editing signal), and a signed claim identity — "
            "not present in most images, but increasingly common from AI generation tools "
            "and some camera/editing apps.",
            "JPEG Image",
        ),
        "platforms": ["iOS", "macOS", "Android", "Windows", "Linux"],
        "parser_class": "ImageParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\xff\xd8\xff",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "JPEG SOI marker",
                    "JPEG Image",
                ),
            }
        ],
        "extensions": [".jpg", ".jpeg"],
        "links": [
            (
                "JPEG format spec (ITU-T T.81)",
                "https://www.itu.int/rec/T-REC-T.81/en",
            ),
            (
                "EXIF spec (CIPA DC-008)",
                "https://www.cipa.jp/e/std/std-sec.html",
            ),
            (
                "Forensically — online JPEG forensics tool",
                "https://29a.ch/photo-forensics/",
            ),
            (
                "Authentication of digital image using EXIF metadata and decoding properties (IJSRCSEIT 2018)",
                "https://doi.org/10.32628/CSEIT183815",
            ),
            (
                "ExifTool — read/write metadata",
                "https://exiftool.org/",
            ),
            (
                "C2PA Technical Specification (Content Credentials)",
                "https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "PNG Image",
        "short_name": "PNG",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Lossless image format used for screenshots, app icons, and UI graphics. "
            "Unlike JPEG, PNG uses lossless compression — pixel data is preserved exactly. "
            "Metadata is stored in typed chunks: tEXt/zTXt for plain-text comments, "
            "iTXt for Unicode and XMP data, tIME for last-modification timestamp, "
            "eXIf for EXIF data (PNG 1.6+). "
            "The IEND chunk marks the end of the file — any data appended after IEND "
            "is forensically significant and may indicate steganography or embedded payloads. "
            "LSB steganography in IDAT pixel data is common and detectable with tools like zsteg. "
            "Screenshots typically lack camera EXIF metadata, which can help distinguish them "
            "from camera photos. The iDOT chunk is Apple-specific and undocumented. "
            "An embedded C2PA (Content Credentials) manifest, carried in the ancillary "
            "'caBX' chunk, can record generating/editing software, an IPTC Digital Source "
            "Type (a direct AI-generation/-editing signal), and a signed claim identity — "
            "PNG is a common output format for AI image generators.",
            "PNG Image",
        ),
        "platforms": ["iOS", "macOS", "Android", "Windows"],
        "parser_class": "ImageParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "PNG signature",
                    "PNG Image",
                ),
            }
        ],
        "extensions": [".png"],
        "links": [
            (
                "PNG format spec (W3C)",
                "https://www.w3.org/TR/PNG/",
            ),
            (
                "PNG chunk types reference",
                "https://www.dcode.fr/png-chunks",
            ),
            (
                "pngcheck — PNG integrity and chunk inspector",
                "http://www.libpng.org/pub/png/apps/pngcheck.html",
            ),
            (
                "Steganography detection in PNG (IEND, LSB, chunks)",
                "https://klaroskope.com/learn/steganography-detection-techniques",
            ),
            (
                "C2PA Technical Specification (Content Credentials)",
                "https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "GIF Image",
        "short_name": "GIF",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Palette-based image format supporting animation, used in messaging apps, "
            "browser caches, and social media. Limited to 256 colors per frame — genuine "
            "photos in GIF format are rare and worth scrutinizing. "
            "GIF89a adds animation frames, comment extensions (free-text metadata), "
            "plain text extensions, and application extensions. "
            "The file terminates with a trailer byte (0x3B) — any data appended after "
            "the trailer is forensically significant. "
            "Steganography is possible via LSB encoding in the global color palette, "
            "palette reordering, or data hidden in comment/application extension blocks. "
            "Animated GIFs can hide different content in individual frames. "
            "A C2PA (Content Credentials) manifest, when present, is carried in a "
            "dedicated Application Extension block (identifier 'C2PA_GIF') and can record "
            "generating/editing software and an IPTC Digital Source Type — a direct "
            "AI-generation/-editing signal.",
            "GIF Image",
        ),
        "platforms": ["iOS", "macOS", "Android", "Windows"],
        "parser_class": "ImageParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\x47\x49\x46\x38\x37\x61",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "GIF87a header — static images only",
                    "GIF Image",
                ),
            },
            {
                "offset": 0,
                "value": b"\x47\x49\x46\x38\x39\x61",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "GIF89a header — animation, comments, and extensions supported",
                    "GIF Image",
                ),
            },
        ],
        "extensions": [".gif"],
        "links": [
            (
                "GIF89a format spec",
                "https://www.w3.org/Graphics/GIF/spec-gif89a.txt",
            ),
            (
                "ForensicsWiki — GIF",
                "https://forensics.wiki/gif/",
            ),
            (
                "GIF steganography from first principles",
                "https://dtm.uk/gif-steganography/",
            ),
            (
                "C2PA Technical Specification (Content Credentials)",
                "https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "BMP Image",
        "short_name": "BMP",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Uncompressed bitmap format common in Windows apps, legacy software, "
            "and some screenshot tools. "
            "The BITMAPFILEHEADER at offset 2 contains the declared file size — "
            "any discrepancy between this value and actual file size indicates "
            "appended data or truncation. BMP has no EOF marker, so trailing data "
            "detection relies entirely on this size field. "
            "Pixel data is stored bottom-up by default — row order matters for carving. "
            "Can use RLE compression for 4-bit and 8-bit images. "
            "Very rare on modern mobile devices — presence in an acquisition may itself "
            "be noteworthy. Widely used in Windows clipboard operations and legacy software.",
            "BMP Image",
        ),
        "platforms": ["Windows", "Android"],
        "parser_class": "ImageParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\x42\x4d",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "BMP file header signature ('BM')",
                    "BMP Image",
                ),
            }
        ],
        "extensions": [".bmp", ".dib"],
        "links": [
            (
                "BMP format spec (Microsoft)",
                "https://learn.microsoft.com/en-us/windows/win32/gdi/bitmap-storage",
            ),
            (
                "BMP format (Wikipedia — comprehensive)",
                "https://en.wikipedia.org/wiki/BMP_file_format",
            ),
            (
                "BMP format (Kaitai Struct — formal spec)",
                "https://formats.kaitai.io/bmp/",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "TIFF Image",
        "short_name": "TIFF",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Flexible container format for high-quality images, document scans, and "
            "camera RAW derivatives. Supports multiple pages in a single file — "
            "multi-page TIFFs are common for scanned documents and fax transmissions "
            "(CCITT Group 3/4 compression). "
            "Carries extensive EXIF, XMP, IPTC, and GPS metadata in Image File Directories (IFDs). "
            "Two byte-order variants: little-endian ('II', Intel) and big-endian ('MM', Motorola), "
            "each with a different magic sequence. "
            "TIFF is the base container for many RAW camera formats (CR2, NEF, DNG) and "
            "for EXIF metadata embedded in JPEG files. "
            "Digital libraries and forensic archives commonly use TIFF as the preservation format. "
            "SubIFDs can contain embedded thumbnails or alternate image representations. "
            "A C2PA (Content Credentials) manifest, when present, is carried in tag 0xCD41 "
            "(52545) of the last IFD in the main-IFD chain — relevant for TIFF-based RAW "
            "formats (DNG, TIFF/EP) as well as plain TIFF.",
            "TIFF Image",
        ),
        "platforms": ["iOS", "macOS", "Windows"],
        "parser_class": "ImageParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\x49\x49\x2a\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "TIFF little-endian (Intel byte order, 'II')",
                    "TIFF Image",
                ),
            },
            {
                "offset": 0,
                "value": b"\x4d\x4d\x00\x2a",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "TIFF big-endian (Motorola byte order, 'MM')",
                    "TIFF Image",
                ),
            },
        ],
        "extensions": [".tif", ".tiff"],
        "links": [
            (
                "TIFF Revision 6.0 specification (Aldus/Adobe, copy hosted by ITU)",
                "https://www.itu.int/itudoc/itu-t/com16/tiff-fx/docs/tiff6.pdf",
            ),
            (
                "TIFF format overview (Wikipedia)",
                "https://en.wikipedia.org/wiki/TIFF",
            ),
            (
                "TIFF tags reference (Library of Congress)",
                "https://www.loc.gov/preservation/digital/formats/content/tiff_tags.shtml",
            ),
            (
                "ExifTool — TIFF/EXIF metadata read/write",
                "https://exiftool.org/",
            ),
            (
                "C2PA Technical Specification (Content Credentials)",
                "https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "WebP Image",
        "short_name": "WebP",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Modern image format used by Chrome, Android apps, and messaging platforms "
            "for compressed photos, stickers, and screenshots. "
            "Stored in a RIFF container — 'RIFF' at offset 0, 'WEBP' at offset 8. "
            "Supports lossy (VP8) and lossless (VP8L) compression, animation (ANMF frames), "
            "alpha channel, ICC color profiles, and EXIF/XMP metadata in dedicated chunks. "
            "WhatsApp, Telegram, and Signal use WebP for stickers and image storage. "
            "Android has used WebP for screenshots since Android 11. "
            "The lossless variant preserves pixel data exactly — useful for detecting re-encoding. "
            "Unknown chunks in the RIFF structure may contain application-specific or hidden data. "
            "A C2PA (Content Credentials) manifest, when present, is carried in a dedicated "
            "'C2PA' RIFF chunk and can record generating/editing software and an IPTC "
            "Digital Source Type — a direct AI-generation/-editing signal.",
            "WebP Image",
        ),
        "platforms": ["iOS", "macOS", "Android", "Windows"],
        "parser_class": "ImageParser",
        "magic": [
            {
                "offset": 0,
                "value": b"RIFF",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "RIFF container header",
                    "WebP Image",
                ),
            },
            {
                "offset": 8,
                "value": b"\x57\x45\x42\x50",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "WebP signature within RIFF container ('WEBP' at offset 8)",
                    "WebP Image",
                ),
            }
        ],
        "extensions": [".webp"],
        "links": [
            (
                "WebP container specification (Google)",
                "https://developers.google.com/speed/webp/docs/riff_container",
            ),
            (
                "WebP Image Format (RFC 9649)",
                "https://datatracker.ietf.org/doc/rfc9649/",
            ),
            (
                "WebP metadata handling (exiv2)",
                "https://dev.exiv2.org/projects/exiv2/wiki/The_Metadata_in_WEBP_files",
            ),
            (
                "C2PA Technical Specification (Content Credentials)",
                "https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "HEIC / HEIF Image",
        "short_name": "HEIC/HEIF",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Default photo format on iOS 11+ and supported by Android since version 8. "
            "HEIF (ISO/IEC 23008-12) is the container; HEVC (H.265) is the default codec — "
            "hence the .heic extension on Apple devices. "
            "A single file can contain multiple images: Burst shots, Live Photos "
            "(still image + video clip), Portrait mode depth maps, and HDR variants. "
            "Live Photo video components may be stored separately as .mov alongside the .heic. "
            "Rich EXIF, XMP, and IPTC metadata per image, including GPS, timestamps, "
            "device model, and lens information. Depth maps from Portrait mode are stored "
            "as auxiliary images with XMP metadata. "
            "When iOS transfers HEIC to Windows/Mac via cable or email, it may silently "
            "convert to JPEG — stripping metadata in the process. "
            "Traditional JPEG-based image authentication algorithms do not apply to HEIC. "
            "iCloud Photo Library syncs HEIC — relevant for cloud artifact correlation. "
            "A C2PA (Content Credentials) manifest, when present, is carried in a top-level "
            "ISOBMFF 'uuid' box (a fixed extended-type UUID identifies it as C2PA, since "
            "some decoders reject unknown top-level box types outright) and can record "
            "generating/editing software and an IPTC Digital Source Type — a direct "
            "AI-generation/-editing signal.",
            "HEIC / HEIF Image",
        ),
        "platforms": ["iOS", "macOS", "Android", "Windows"],
        "parser_class": "ImageParser",
        "magic": [
            {
                "offset": 8,
                "value": b"\x68\x65\x69\x63",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "HEIC brand identifier in ISOBMFF ftyp box (offset 8)",
                    "HEIC / HEIF Image",
                ),
            },
            {
                "offset": 8,
                "value": b"hevc",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "HEIC image sequence brand 'hevc' in ISOBMFF ftyp box (offset 8)",
                    "HEIC / HEIF Image",
                ),
            },
            {
                "offset": 8,
                "value": b"hevx",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "HEIC image sequence brand 'hevx' in ISOBMFF ftyp box (offset 8)",
                    "HEIC / HEIF Image",
                ),
            },
            {
                "offset": 8,
                "value": b"heim",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "HEIC multiview brand 'heim' in ISOBMFF ftyp box (offset 8)",
                    "HEIC / HEIF Image",
                ),
            },
            {
                "offset": 8,
                "value": b"heis",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "HEIC scalable brand 'heis' in ISOBMFF ftyp box (offset 8)",
                    "HEIC / HEIF Image",
                ),
            },
            {
                "offset": 8,
                "value": b"hevm",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "HEIC multiview sequence brand 'hevm' in ISOBMFF ftyp box (offset 8)",
                    "HEIC / HEIF Image",
                ),
            },
            {
                "offset": 8,
                "value": b"hevs",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "HEIC scalable sequence brand 'hevs' in ISOBMFF ftyp box (offset 8)",
                    "HEIC / HEIF Image",
                ),
            },
            {
                "offset": 8,
                "value": b"msf1",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "HEIF image sequence brand 'msf1' in ISOBMFF ftyp box (offset 8)",
                    "HEIC / HEIF Image",
                ),
            },
            {
                "offset": 8,
                "value": b"\x68\x65\x69\x78",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "HEIF brand 'heix' in ISOBMFF ftyp box (offset 8)",
                    "HEIC / HEIF Image",
                ),
            },
            {
                "offset": 8,
                "value": b"\x6d\x69\x66\x31",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "HEIF brand 'mif1' in ISOBMFF ftyp box (offset 8)",
                    "HEIC / HEIF Image",
                ),
            },
        ],
        "extensions": [".heic", ".heif"],
        "links": [
            (
                "Apple HEIF WWDC 2017 session (format internals)",
                "https://developer.apple.com/videos/play/wwdc2017/513/",
            ),
            (
                "HEIF format spec (Nokia)",
                "https://nokiatech.github.io/heif/",
            ),
            (
                "HEIF format overview (Library of Congress)",
                "https://www.loc.gov/preservation/digital/formats/fdd/fdd000525.shtml",
            ),
            (
                "Forensic considerations for the High Efficiency Image File Format (McKeown & Russell, IEEE Cyber Security 2020)",
                "https://doi.org/10.1109/CyberSecurity49315.2020.9138890",
            ),
            (
                "HEIF forensics — authentication implications (Amped Software)",
                "https://blog.ampedsoftware.com/2017/09/29/heif-image-files-forensics-authentication-apocalypse",
            ),
            (
                "C2PA Technical Specification (Content Credentials)",
                "https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "JPEG XL Image",
        "short_name": "JPEG XL",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Next-generation image format standardised as ISO/IEC 18181 (2022). "
            "Supports both lossy and lossless compression with significantly better "
            "efficiency than JPEG; lossless JPEG transcoding (bit-exact round-trip) is "
            "a first-class feature. "
            "Two container variants exist with distinct magic sequences: the bare "
            "codestream (\\xff\\x0a at offset 0) and the ISOBMFF/JXL container "
            "(12-byte signature starting with \\x00\\x00\\x00\\x0c\\x4a\\x58\\x4c at "
            "offset 0), which supports EXIF, XMP, and multiple frames. "
            "Adoption is growing in high-end cameras, Apple ecosystem (iOS 17+, "
            "macOS Sonoma+), and some Android OEMs. "
            "iOS ProRAW JPEG XL files may embed full DNG data in a JXL container. "
            "Forensically relevant: timestamp and GPS metadata in EXIF boxes, "
            "lossless re-encoding makes tampering detection harder than with JPEG, "
            "and the format's novelty means older tools may fail to parse it. "
            "A C2PA (Content Credentials) manifest, when present in the box-form container, "
            "is a top-level JUMBF superbox — the bare codestream variant cannot carry one at "
            "all. Can record generating/editing software and an IPTC Digital Source Type — "
            "a direct AI-generation/-editing signal.",
            "JPEG XL Image",
        ),
        "platforms": ["iOS", "macOS", "Android", "Windows"],
        "parser_class": "ImageParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\xff\x0a",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "JPEG XL naked codestream signature",
                    "JPEG XL Image",
                ),
            },
            {
                "offset": 0,
                "value": b"\x00\x00\x00\x0c\x4a\x58\x4c\x20\x0d\x0a\x87\x0a",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "JPEG XL ISOBMFF/JXL container signature",
                    "JPEG XL Image",
                ),
            },
        ],
        "extensions": [".jxl"],
        "links": [
            (
                "JPEG XL — official specification overview",
                "https://jpeg.org/jpegxl/",
            ),
            (
                "ISO/IEC 18181 — JPEG XL standard",
                "https://www.iso.org/standard/77977.html",
            ),
            (
                "JPEG XL container format (libjxl wiki)",
                "https://github.com/libjxl/libjxl/blob/main/doc/format_overview.md",
            ),
            (
                "JPEG XL file format overview (Library of Congress)",
                "https://www.loc.gov/preservation/digital/formats/fdd/fdd000538.shtml",
            ),
            (
                "C2PA Technical Specification (Content Credentials)",
                "https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "AVIF Image",
        "short_name": "AVIF",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "AV1 Image File Format — a royalty-free still-image format based on the AV1 video "
            "codec and the ISOBMFF container (ISO/IEC 23000-22). "
            "Adopted by Chrome (2020), Firefox (2021), Safari (2023), Android (2019), "
            "and increasingly by social media platforms (Netflix, YouTube, Discord) for "
            "bandwidth-efficient image delivery. "
            "Like HEIC, AVIF uses the ISOBMFF ftyp box structure; the brand identifier "
            "'avif' or 'avis' (for image sequences / animations) appears at offset 8–11. "
            "Supports EXIF, XMP, and ICC colour profiles embedded in 'meta' boxes — "
            "GPS coordinates, capture timestamps, and device model are preserved when the "
            "originating app writes EXIF. "
            "AVIF files from social media have often had metadata stripped server-side, "
            "which is itself a forensic indicator of the image's provenance. "
            "The AV1 bitstream inside is distinct from H.265 (HEVC used in HEIC), so "
            "HEIC-specific codec detection tools will not recognise AVIF content. "
            "Animation / multi-frame AVIF ('avis' brand) is increasingly used as a GIF "
            "replacement — relevant when investigating multimedia evidence. "
            "Like HEIC, a C2PA (Content Credentials) manifest, when present, is carried in "
            "a top-level ISOBMFF 'uuid' box and can record generating/editing software and "
            "an IPTC Digital Source Type — a direct AI-generation/-editing signal.",
            "AVIF Image",
        ),
        "platforms": ["Android", "iOS", "macOS", "Windows"],
        "parser_class": "ImageParser",
        "magic": [
            {
                "offset": 8,
                "value": b"\x61\x76\x69\x66",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "AVIF brand identifier 'avif' in ISOBMFF ftyp box (offset 8)",
                    "AVIF Image",
                ),
            },
            {
                "offset": 8,
                "value": b"\x61\x76\x69\x73",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "AVIF animation brand 'avis' in ISOBMFF ftyp box (offset 8)",
                    "AVIF Image",
                ),
            },
        ],
        "extensions": [".avif"],
        "links": [
            (
                "AVIF — AOM specification",
                "https://aomediacodec.github.io/av1-avif/",
            ),
            (
                "AVIF format overview (Library of Congress)",
                "https://www.loc.gov/preservation/digital/formats/fdd/fdd000540.shtml",
            ),
            (
                "ISOBMFF — ISO/IEC 14496-12 base media file format",
                "https://www.iso.org/standard/83102.html",
            ),
            (
                "C2PA Technical Specification (Content Credentials)",
                "https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "Apple ATX Texture Archive",
        "short_name": "ATX",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Apple AAPL texture container wrapping ASTC image payloads, including "
            "some LZFSE-compressed variants. Found in iOS and macOS UI caches such as "
            "wallpapers, PosterBoard snapshots, avatars, widgets, and app-generated "
            "interface imagery. Decoding can expose visible user interface state or "
            "cached imagery that standard image viewers miss because the file is not a "
            "JPEG/PNG container.",
            "Apple ATX Texture Archive",
        ),
        "platforms": ["iOS", "macOS"],
        "parser_class": "ImageParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\x41\x41\x50\x4c\x0d\x0a\x1a\x0a",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Apple ATX AAPL container signature",
                    "Apple ATX Texture Archive",
                ),
            }
        ],
        "extensions": [".atx"],
        "links": [
            (
                "ATX reader reference implementation",
                "https://github.com/galba-arueira/atx_reader",
            ),
            (
                "ASTC block format (Khronos Data Format Specification)",
                "https://registry.khronos.org/DataFormat/specs/1.3/dataformat.1.3.html#ASTC",
            ),
            (
                "Apple LZFSE compression algorithm",
                "https://developer.apple.com/documentation/compression/algorithm/lzfse",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "Khronos KTX 1.1 Texture",
        "short_name": "KTX",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Khronos texture container. On iOS the payload is normally ASTC 4x4, "
            "optionally LZFSE-compressed, flagged by a Compression_APPLE entry in the "
            "key/value block. Observed holding application snapshots "
            "(Library/Caches/Snapshots and SplashBoard/Snapshots), Safari tab thumbnails "
            "(Library/Safari/Thumbnails) and, less often, Photos attachment previews. "
            "Snapshots appear in this container and in Apple's AAPL/ATX one depending on "
            "the release; the Safari thumbnails in every tested image were this container "
            "and not ATX. A snapshot is the "
            "image the system captured of an app's screen when it was last backgrounded, so "
            "decoding one can show on-screen content at that moment. The same extension is "
            "also used by textures shipped inside system frameworks and apps, which carry "
            "other pixel formats and are not user content.",
            "Khronos KTX 1.1 Texture",
        ),
        "platforms": ["iOS", "macOS"],
        "parser_class": "ImageParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\xabKTX 11\xbb\r\n\x1a\n",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Khronos KTX 1.1 file identifier",
                    "Khronos KTX 1.1 Texture",
                ),
            }
        ],
        "extensions": [".ktx"],
        "links": [
            (
                "KTX File Format Specification v1.1 (Khronos)",
                "https://registry.khronos.org/KTX/specs/1.0/ktxspec.v1.html",
            ),
            (
                "KHR_texture_compression_astc_hdr (glInternalFormat enum values)",
                "https://registry.khronos.org/OpenGL/extensions/KHR/KHR_texture_compression_astc_hdr.txt",
            ),
            (
                "ios_ktx2png reference implementation (Yogesh Khatri, MIT)",
                "https://github.com/ydkhatri/MacForensics/tree/master/IOS_KTX_TO_PNG",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "iOS Crash Report",
        "short_name": "IPS / crash",
        "category": "log",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Application and system crash reports generated by iOS and macOS. "
            "Two formats: the newer .ips format (iOS 15+ / macOS 12+, JSON-based with "
            "bug_type field — value 309 indicates a crash report) and the older .crash "
            "format (plain text). "
            "Each report contains: app name, bundle ID and version, iOS/macOS version, "
            "device model, hardware identifier (CrashReporter Key), incident UUID, "
            "precise crash timestamp, exception type and reason, "
            "and thread states with stack traces. "
            "Forensically relevant for: establishing a precise timeline of app crashes, "
            "identifying exploitation attempts or repeated crashes of security-relevant apps, "
            "detecting jailbreak-related crashes, and corroborating user activity. "
            "Stored on-device under /var/mobile/Library/Logs/CrashReporter/ and accessible "
            "via Settings → Privacy → Analytics & Improvements → Analytics Data.",
            "iOS Crash Report",
        ),
        "platforms": ["iOS", "macOS"],
        "parser_class": None,
        "magic": [],
        "extensions": [".ips", ".crash"],
        "links": [
            (
                "Apple developer docs — examining crash report fields",
                "https://developer.apple.com/documentation/xcode/examining-the-fields-in-a-crash-report",
            ),
            (
                "Apple developer docs — interpreting JSON crash report format",
                "https://developer.apple.com/documentation/xcode/interpreting-the-json-format-of-a-crash-report",
            ),
            (
                "iOS crash logs forensics (ArtiFast / forensafe.com)",
                "https://forensafe.com/blogs/AppleCrashLogs.html",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "JSON Document",
        "short_name": "JSON",
        "category": "serialization",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Human-readable serialization format used pervasively in mobile and web apps. "
            "Forensically relevant as: app configuration and cached API responses, "
            "browser localStorage/sessionStorage exports, browser bookmarks and preferences "
            "(Chrome Bookmarks file, Firefox logins.json), "
            "chat and social media data exports (WhatsApp, Signal, Twitter/X archive), "
            "location data in GeoJSON format, and structured log files (JSONL/NDJSON). "
            "Many apps store sensitive data in plaintext JSON without encryption — "
            "credentials, tokens, and personal data are frequently found in app data directories. "
            "No magic bytes — identification relies on file extension or content inspection "
            "for the leading '{' or '[' character.",
            "JSON Document",
        ),
        "platforms": ["iOS", "macOS", "Android", "Windows"],
        "parser_class": "JsonParser",
        "magic": [],
        "extensions": [".json", ".geojson", ".jsonl", ".ndjson"],
        "links": [
            (
                "JSON format spec (RFC 8259)",
                "https://datatracker.ietf.org/doc/html/rfc8259",
            ),
            (
                "GeoJSON format spec (RFC 7946)",
                "https://datatracker.ietf.org/doc/html/rfc7946",
            ),
            (
                "Browser artifacts — JSON files in forensics (HackTricks)",
                "https://hacktricks.wiki/en/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/browser-artifacts.html",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "LevelDB Database",
        "short_name": "LevelDB",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Key-value store used by Chrome/Chromium (IndexedDB, localStorage, sessionStorage), "
            "Electron-based apps (Discord, WhatsApp Desktop, Signal Desktop), "
            "and many Android and iOS apps for caches and app state. "
            "LevelDB is not a single file but a directory containing: "
            "CURRENT and MANIFEST-###### (metadata), "
            ".ldb/.sst files (sorted string tables with key-value data), "
            "and ######.log files (write-ahead log with recent mutations). "
            "All files must be parsed together for a complete view. "
            "Deleted or overwritten records survive in .log files with sequence numbers "
            "and a deleted/live state flag — deleted data is often recoverable. "
            "Values are frequently serialized as Protobuf (Chrome V8 objects) or JSON. "
            "Chrome IndexedDB stores web app state, cached API responses, and "
            "browser localStorage — common sources of social media and messaging artifacts.",
            "LevelDB Database",
        ),
        "platforms": ["iOS", "macOS", "Android", "Windows"],
        "parser_class": "LeveldbParser",
        "magic": [],
        "extensions": [".ldb", ".log"],
        "links": [
            (
                "LevelDB format specification (Google)",
                "https://github.com/google/leveldb/blob/main/doc/impl.md",
            ),
            (
                "LevelDB forensics primer — Chrome, Electron and LevelDB (CCL)",
                "https://www.cclsolutionsgroup.com/post/hang-on-thats-not-sqlite-chrome-electron-and-leveldb",
            ),
            (
                "IndexedDB on Chromium — deep dive (CCL)",
                "https://www.cclsolutionsgroup.com/post/indexeddb-on-chromium",
            ),
            (
                "Chrome Session/Local Storage in LevelDB (CCL)",
                "https://www.cclsolutionsgroup.com/post/chromium-session-storage-and-local-storage",
            ),
            (
                "MIC: Memory analysis of IndexedDB data on Chromium-based applications (FSI: Digital Investigation 2024)",
                "https://www.sciencedirect.com/science/article/pii/S2666281724001331",
            ),
            (
                "ForensicsWiki — LevelDB format",
                "https://forensics.wiki/leveldb_format/",
            ),
            (
                "Reading the CURRENT — LevelDB Forensics with crush (beBinary)",
                "https://bebinary4n6.blogspot.com/2026/05/reading-current-leveldb-forensics-with.html",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "MMKV Key-Value Store",
        "short_name": "MMKV",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Tencent's mmap-backed key-value store (github.com/Tencent/MMKV, BSD-3-Clause), "
            "used by many Android and iOS apps in place of SharedPreferences or "
            "NSUserDefaults — including WeChat, TikTok, Temu, SHEIN, Xiaohongshu, Weibo, "
            "Discord and Coinbase. Usually found as a file named mmkv.default (the "
            "library's default instance) inside a folder literally named mmkv, alongside "
            "a same-named <name>.crc sibling file carrying integrity/encryption metadata. "
            "Has no magic bytes, so it cannot be auto-detected — open via the filesystem "
            "panel's Open as -> MMKV context menu action. "
            "The store is append-only between rewrites: setting a key appends a new entry "
            "rather than editing the old one, so superseded values and removed keys "
            "(recorded as a zero-length value, not a real deletion) remain recoverable in "
            "file order until the next full rewrite. Optionally AES-CFB encrypted, with the "
            "key stored by neither file — decryptable if the app's key is known.",
            "MMKV Key-Value Store",
        ),
        "platforms": ["Android", "iOS"],
        "parser_class": "MMKVParser",
        "magic": [],
        "extensions": [],
        "links": [
            (
                "Tencent/MMKV (upstream project)",
                "https://github.com/Tencent/MMKV",
            ),
            (
                "MMKV design deep dive (Tencent/MMKV wiki)",
                "https://github.com/Tencent/MMKV/wiki/design_eng",
            ),
            (
                "abrignoni/mmkv-parser — reference reader crush's parser is built on (MIT)",
                "https://github.com/abrignoni/mmkv-parser",
            ),
            (
                "You down with MMKV? (LEAPPs Blog)",
                "https://leapps.org/blog-post?post=2026-09-04-you-down-with-mmkv",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "Apple Unified Log Archive (logarchive)",
        "short_name": "logarchive",
        "category": "log",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Packaged Apple Unified Log bundle containing tracev3 binary log files, "
            "uuidtext string catalogs, timesync boot-anchor records, and a DSC directory. "
            "Produced by 'log collect' on macOS/iOS or assembled from a full iOS filesystem "
            "acquisition (/private/var/db/diagnostics/ + /private/var/db/uuidtext/ siblings). "
            "Provides a complete, timestamp-anchored log timeline with resolved process names, "
            "subsystems, and categories across typically 28-30 days of device activity. "
            "Key forensic artifacts: app launches and terminations, lock/unlock and screen events, "
            "network connections, Siri activations, biometric authentication attempts, "
            "USB/external media connections, userActionEvent entries (explicit user interactions), "
            "lossEvent entries (log buffer overflow gaps), and crash precursors. "
            "Private message fields may contain data redacted in live-system logs "
            "but preserved in binary acquisitions. "
            "Full string resolution requires uuidtext/, timesync/, and DSC — "
            "without them, message text falls back to raw format-string fragments. "
            "Crush assembles the correct logarchive layout from iOS full-filesystem "
            "acquisitions automatically.",
            "Apple Unified Log Archive (logarchive)",
        ),
        "platforms": ["iOS", "macOS"],
        "parser_class": "UnifiedLogConverter",
        "magic": [],
        "extensions": [".logarchive"],
        "links": [
            (
                "Apple OSLog documentation",
                "https://developer.apple.com/documentation/oslog",
            ),
            (
                "Mandiant macos-UnifiedLogs parser",
                "https://github.com/mandiant/macos-UnifiedLogs",
            ),
            (
                "iOS Unified Logs research (ios-unifiedlogs.com)",
                "https://www.ios-unifiedlogs.com/",
            ),
            (
                "Thesis Friday — Unified Log analysis series (Tim Korver)",
                "https://thesisfriday.com/",
            ),
            (
                "Reviewing macOS Unified Logs — forensic guide (Mandiant/Google)",
                "https://cloud.google.com/blog/topics/threat-intelligence/reviewing-macos-unified-logs/",
            ),
            (
                "Logs Unite! — forensic analysis of Apple Unified Logs (Sarah Edwards)",
                "https://github.com/mac4n6/Presentations/blob/master/Logs%20Unite!%20-%20Forensic%20Analysis%20of%20Apple%20Unified%20Logs/LogsUnite.pdf",
            ),
            (
                "Apple Unified Logging and Activity Tracing formats (libyal)",
                "https://github.com/libyal/dtformats/blob/main/documentation/Apple%20Unified%20Logging%20and%20Activity%20Tracing%20formats.asciidoc",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "LZFSE Compressed Data",
        "short_name": "LZFSE",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Apple-proprietary lossless compression algorithm introduced with iOS 9 "
            "and macOS 10.11 (El Capitan). Used in OTA software updates, IPSW firmware "
            "payloads, Dyld Shared Cache (DSC), kernelcache, some system binaries, "
            "and app data. Files must be decompressed before content analysis. "
            "Identified by the 'bvx2' magic (0x62767832). "
            "Apple also uses a simpler variant called LZVN (used for inputs under 4096 bytes "
            "and unconditionally in Mach-O compressed segments). "
            "The open-source lzfse CLI tool (github.com/lzfse/lzfse) can decompress files. "
            "Also used in Apple Archive (.aar) format since macOS Big Sur.",
            "LZFSE Compressed Data",
        ),
        "platforms": ["iOS", "macOS"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"\x62\x76\x78\x32",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "LZFSE magic ('bvx2')",
                    "LZFSE Compressed Data",
                ),
            }
        ],
        "extensions": [],
        "links": [
            (
                "LZFSE reference implementation (Apple/GitHub)",
                "https://github.com/lzfse/lzfse",
            ),
            (
                "Apple developer docs — Compression framework",
                "https://developer.apple.com/documentation/compression/algorithm/lzfse",
            ),
            (
                "LZFSE overview (Wikipedia)",
                "https://en.wikipedia.org/wiki/LZFSE",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "Mach-O Executable",
        "short_name": "Mach-O",
        "category": "execution",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Native executable, library, and object format for iOS and macOS. "
            "App binaries can be analysed for hardcoded strings, URLs, API endpoints, "
            "encryption keys, and embedded credentials. "
            "Entitlements (XML embedded via LC_CODE_SIGNATURE) define app sandbox "
            "capabilities and permissions — relevant for identifying over-privileged apps "
            "or jailbreak bypass attempts. "
            "Code signatures link the binary to a developer identity and detect tampering. "
            "Fat/Universal Binaries contain multiple architecture slices (e.g. arm64 + x86_64) "
            "in a single file, preceded by a fat_header with magic 0xCAFEBABE. "
            "Analysis tools: jtool2, otool, Ghidra, IDA Pro, class-dump, lipo, strings.",
            "Mach-O Executable",
        ),
        "platforms": ["iOS", "macOS"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"\xcf\xfa\xed\xfe",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Mach-O 64-bit little-endian (arm64, x86_64) — most common on modern devices",
                    "Mach-O Executable",
                ),
            },
            {
                "offset": 0,
                "value": b"\xce\xfa\xed\xfe",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Mach-O 32-bit little-endian",
                    "Mach-O Executable",
                ),
            },
            {
                "offset": 0,
                "value": b"\xca\xfe\xba\xbe",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Fat/Universal Binary — contains multiple architecture slices",
                    "Mach-O Executable",
                ),
            },
            {
                "offset": 0,
                "value": b"\xfe\xed\xfa\xcf",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Mach-O 64-bit big-endian",
                    "Mach-O Executable",
                ),
            },
        ],
        "extensions": ["", ".dylib", ".framework", ".o"],
        "links": [
            (
                "Apple developer docs — Mach-O format reference",
                "https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/MachOOverview.html",
            ),
            (
                "Mach-O ABI reference (GitHub mirror)",
                "https://github.com/aidansteele/osx-abi-macho-file-format-reference",
            ),
            (
                "Mach-O format overview (Wikipedia)",
                "https://en.wikipedia.org/wiki/Mach-O",
            ),
            (
                "Mach-O forensics — code signing and entitlements (Hexiosec)",
                "https://hexiosec.com/blog/macho-files/",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "MP4 Video",
        "short_name": "MP4",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Versatile ISOBMFF container format (ISO/IEC 14496-12) for video recordings, "
            "screen captures, and downloaded media. "
            "The ftyp box at offset 4 identifies the specific brand (mp42, isom, M4V, etc.). "
            "The mvhd (Movie Header) box contains creation and modification timestamps "
            "in QuickTime epoch (seconds since 1904-01-01 UTC — not Unix epoch). "
            "The udta (User Data) box may contain device make/model, recording software, "
            "and GPS coordinates (e.g. from GoPro, DJI, dashcams, smartphones). "
            "Metadata changes when a video is re-encoded or edited — "
            "altered mvhd timestamps and missing udta boxes are indicators of processing. "
            "Screen recordings from iOS and Android are commonly stored as MP4. "
            "ExifTool and MediaInfo are standard tools for metadata extraction.",
            "MP4 Video",
        ),
        "platforms": ["iOS", "macOS", "Android", "Windows"],
        "parser_class": "MediaParser",
        "magic": [
            {
                "offset": 4,
                "value": b"\x66\x74\x79\x70",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ISOBMFF ftyp box at offset 4",
                    "MP4 Video",
                ),
            }
        ],
        "extensions": [".mp4", ".m4v"],
        "links": [
            (
                "ISOBMFF format overview (Wikipedia)",
                "https://en.wikipedia.org/wiki/ISO_base_media_file_format",
            ),
            (
                "MP4 file format spec (ISO/IEC 14496-14)",
                "https://www.iso.org/standard/79110.html",
            ),
            (
                "Authentication of digital MP4 video recordings using file containers and metadata properties (IJCSE 2021)",
                "https://doi.org/10.21817/ijcsenet/2021/v10i2/211002004",
            ),
            (
                "MPEG-4 file structure forensics — mvhd and metadata (UC Denver)",
                "https://www.ucdenver.edu/docs/librariesprovider27/ncmf-docs/theses/hall_thesis_fall2015.pdf",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "MOV Video (QuickTime)",
        "short_name": "MOV",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Apple's native video container format based on ISOBMFF/QuickTime. "
            "iOS camera recordings — including the video component of Live Photos — "
            "are stored as .mov files. macOS screen recordings also use MOV. "
            "Identified by ISOBMFF ftyp box at offset 4 with 'qt  ' brand at offset 8. "
            "Timestamps use the QuickTime epoch (seconds since 1904-01-01 UTC). "
            "GPS coordinates are stored as Apple-specific metadata keys "
            "('com.apple.quicktime.location.ISO6709') in the udta/Keys box — "
            "extractable with ExifTool or ffprobe. "
            "Device make/model, software version, and creation date are commonly present. "
            "Files processed by QuickTime Player, iMovie, or Final Cut Pro will show "
            "altered timestamps and may lack original device metadata — "
            "a key indicator of post-processing.",
            "MOV Video (QuickTime)",
        ),
        "platforms": ["iOS", "macOS"],
        "parser_class": "MediaParser",
        "magic": [
            {
                "offset": 4,
                "value": b"\x66\x74\x79\x70",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ISOBMFF ftyp box at offset 4",
                    "MOV Video (QuickTime)",
                ),
            },
            {
                "offset": 8,
                "value": b"\x71\x74\x20\x20",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "QuickTime brand identifier ('qt  ') at offset 8",
                    "MOV Video (QuickTime)",
                ),
            },
        ],
        "extensions": [".mov"],
        "links": [
            (
                "QuickTime file format spec (Apple)",
                "https://developer.apple.com/documentation/quicktime-file-format",
            ),
            (
                "Apple developer docs — QuickTime metadata atoms",
                "https://developer.apple.com/documentation/quicktime-file-format/metadata_atoms_and_types",
            ),
            (
                "Apple developer docs — location metadata in MOV",
                "https://developer.apple.com/documentation/quicktime-file-format/location_metadata",
            ),
            (
                "Geolocation metadata in iOS MOV files (practical guide)",
                "https://blog.addpipe.com/geolocation-metadata-ios-android-video-files/",
            ),
            (
                "ExifTool QuickTime tags reference",
                "https://exiftool.org/TagNames/QuickTime.html",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "AVI Video",
        "short_name": "AVI",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Legacy RIFF-based video container format common in older Windows recordings, "
            "CCTV/DVR systems, dashcams, and surveillance cameras. "
            "RIFF header at offset 0, 'AVI ' identifier at offset 8. "
            "AVI has no native creation timestamp fields — recording time must be inferred "
            "from filesystem metadata or INFO chunk strings. "
            "INFO chunks (ICRT, IDIT, ICRD, ISFT, INAM) may contain creation date/time, "
            "recording software, device info, and comments — content varies by device. "
            "The stream header (strh) fourcc identifies the codec, which can fingerprint "
            "the recording device or software. "
            "Files edited with AVIDemux, VirtualDub, or FFmpeg leave tool-specific "
            "JUNK chunks — a forensic indicator of post-processing. "
            "Standard RIFF is limited to ~4GB — larger files require OpenDML "
            "extension (AVI 2.0).",
            "AVI Video",
        ),
        "platforms": ["Windows", "Android"],
        "parser_class": "MediaParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\x52\x49\x46\x46",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "RIFF container header",
                    "AVI Video",
                ),
            },
            {
                "offset": 8,
                "value": b"\x41\x56\x49\x20",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "AVI subtype identifier ('AVI ') at offset 8",
                    "AVI Video",
                ),
            },
        ],
        "extensions": [".avi"],
        "links": [
            (
                "AVI RIFF file reference (Microsoft)",
                "https://learn.microsoft.com/en-us/windows/win32/directshow/avi-riff-file-reference",
            ),
            (
                "AVI format overview (Wikipedia)",
                "https://en.wikipedia.org/wiki/Audio_Video_Interleave",
            ),
            (
                "Forensic analysis of video file formats — AVI and MP4 (DFRWS 2014)",
                "https://dfrws.org/wp-content/uploads/2019/06/2014_EU_paper-forensic_analysis_of_video_file_formats.pdf",
            ),
            (
                "RIFF INFO tags in AVI (ExifTool)",
                "https://exiftool.org/TagNames/RIFF.html",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "MKV Video (Matroska)",
        "short_name": "MKV",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Open EBML-based container format for HD video, commonly found in "
            "downloaded media, media server libraries (Plex, Jellyfin), and screen recordings. "
            "Supports chapters, subtitles, attachments, and multiple audio/video tracks. "
            "The Segment Info element contains key forensic metadata: "
            "DateUTC (nanoseconds since 2001-01-01 UTC — the muxing timestamp), "
            "Title, MuxingApp (library used), and WritingApp (application used). "
            "WritingApp and MuxingApp are mandatory fields — they identify the software "
            "that created or remuxed the file (e.g. HandBrake, FFmpeg, MakeMKV, mkvmerge) "
            "and are strong indicators of post-processing. "
            "Shares the EBML magic (0x1A 0x45 0xDF 0xA3) with WebM — "
            "distinguished by DocType 'matroska' vs 'webm' in the EBML header.",
            "MKV Video (Matroska)",
        ),
        "platforms": ["Android", "Windows", "Linux"],
        "parser_class": "MediaParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\x1a\x45\xdf\xa3",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "EBML header (Matroska/WebM) — DocType 'matroska' identifies MKV",
                    "MKV Video (Matroska)",
                ),
            }
        ],
        "extensions": [".mkv"],
        "links": [
            (
                "Matroska format specification (RFC 9559)",
                "https://datatracker.ietf.org/doc/rfc9559/",
            ),
            (
                "Matroska technical basics",
                "https://www.matroska.org/technical/basics.html",
            ),
            (
                "Matroska element reference",
                "https://www.matroska.org/technical/elements.html",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "WebM Video",
        "short_name": "WebM",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Web-optimised video container based on a restricted subset of Matroska/EBML. "
            "Used by browsers (Chrome, Firefox, Edge), WebRTC recordings, "
            "YouTube downloads, and some Android apps. "
            "Shares the EBML magic (0x1A 0x45 0xDF 0xA3) with MKV — "
            "distinguished by DocType 'webm' in the EBML header. "
            "Restricted to VP8, VP9, or AV1 video with Vorbis or Opus audio only. "
            "Same Segment Info metadata as MKV: DateUTC (nanoseconds since 2001-01-01 UTC), "
            "WritingApp and MuxingApp identify the creation software. "
            "Browser-cached WebM segments from streaming services may contain "
            "partial content rather than complete videos. "
            "WebRTC recordings from browser video calls are commonly stored as WebM.",
            "WebM Video",
        ),
        "platforms": ["Android", "Windows", "Linux"],
        "parser_class": "MediaParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\x1a\x45\xdf\xa3",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "EBML header (Matroska/WebM) — DocType 'webm' identifies WebM",
                    "WebM Video",
                ),
            }
        ],
        "extensions": [".webm"],
        "links": [
            (
                "WebM container guidelines (WebM Project)",
                "https://www.webmproject.org/docs/container/",
            ),
            (
                "WebM overview (Wikipedia)",
                "https://en.wikipedia.org/wiki/WebM",
            ),
            (
                "Matroska format spec (RFC 9559) — WebM base format",
                "https://datatracker.ietf.org/doc/rfc9559/",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "3GP / 3G2 Video",
        "short_name": "3GP",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Mobile video container format based on ISOBMFF, defined by 3GPP (3GP) "
            "and 3GPP2 (3G2) for 3G mobile networks. "
            "3GP targets GSM/UMTS networks; 3G2 is the CDMA2000 variant with lower "
            "bandwidth usage. Both are required formats for MMS and IMS multimedia services. "
            "Shares the ISOBMFF box structure with MP4 — same mvhd timestamps "
            "(QuickTime epoch, seconds since 1904-01-01 UTC) and udta metadata. "
            "Typical video codecs: H.263, H.264; audio: AMR-NB, AAC. "
            "Typically low resolution (QCIF 176x144 to CIF 352x288) and bitrate, "
            "optimised for 2G/3G transmission. "
            "Found in older acquisitions, MMS message attachments, voice call recordings, "
            "and legacy Android/iOS camera recordings from pre-2012 devices. "
            "Some devices stored 3GP files with an .mp4 extension.",
            "3GP / 3G2 Video",
        ),
        "platforms": ["Android", "iOS"],
        "parser_class": "MediaParser",
        "magic": [
            {
                "offset": 4,
                "value": b"\x66\x74\x79\x70",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ISOBMFF ftyp box at offset 4",
                    "3GP / 3G2 Video",
                ),
            },
            {
                "offset": 8,
                "value": b"3g",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "3GPP/3GPP2 major brand ('3gp…', '3g2…', '3ge…' etc.) in the ftyp box (offset 8)",
                    "3GP / 3G2 Video",
                ),
            },
        ],
        "extensions": [".3gp", ".3g2"],
        "links": [
            (
                "3GP format specification (3GPP TS 26.244)",
                "https://www.3gpp.org/ftp/Specs/archive/26_series/26.244/",
            ),
            (
                "3GP and 3G2 overview (Wikipedia)",
                "https://en.wikipedia.org/wiki/3GP_and_3G2",
            ),
            (
                "Forensic analysis of mobile video formats (DFRWS 2014)",
                "https://dfrws.org/wp-content/uploads/2019/06/2014_EU_paper-forensic_analysis_of_video_file_formats.pdf",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "MP3 Audio",
        "short_name": "MP3",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Ubiquitous lossy audio format for music, voice memos, voicemails, "
            "and messaging app voice messages. "
            "ID3v2 tags (at file start, 'ID3' magic) can embed title, artist, album, "
            "year, comments, cover art, lyrics, URLs, and custom frames — "
            "some apps embed GPS coordinates or device info in custom ID3 frames. "
            "ID3v1 tags (last 128 bytes, 'TAG' marker) store basic metadata. "
            "VBR files often contain a Xing/LAME tag in the first MPEG frame — "
            "this encodes the encoding software (e.g. 'LAME 3.99') and settings, "
            "useful for source attribution and detecting re-encoding. "
            "Bitrate and sample rate can help fingerprint the recording device or app. "
            "No native timestamp — recording time must be inferred from ID3 tags "
            "or filesystem metadata.",
            "MP3 Audio",
        ),
        "platforms": ["iOS", "macOS", "Android", "Windows"],
        "parser_class": "MediaParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\x49\x44\x33",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ID3 tag header (MP3 with ID3v2 metadata)",
                    "MP3 Audio",
                ),
            },
            {
                "offset": 0,
                "value": b"\xff\xfb",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "MPEG-1 Layer 3 sync word (MP3 without ID3 header)",
                    "MP3 Audio",
                ),
            },
        ],
        "extensions": [".mp3"],
        "links": [
            (
                "ID3v2 specification (id3.org)",
                "https://id3.org/id3v2.3.0",
            ),
            (
                "ID3 overview (Wikipedia)",
                "https://en.wikipedia.org/wiki/ID3",
            ),
            (
                "LAME tag specification (encoder attribution)",
                "http://gabriel.mp3-tech.org/mp3infotag.html",
            ),
            (
                "ForensicsWiki — ID3",
                "https://forensics.wiki/id3/",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "WAV Audio",
        "short_name": "WAV",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Uncompressed PCM audio container based on RIFF, used for voice recordings, "
            "call recordings, dictation devices, bodycams, and professional recorders. "
            "RIFF INFO chunks may contain title, creation date, originator, and software. "
            "The Broadcast Wave Format (BWF) extension adds a 'bext' chunk with: "
            "originator name and reference, origination date and time (UTC, YYYY-MM-DD/HH:MM:SS), "
            "TimeReference (64-bit sample count since midnight — precise recording timestamp), "
            "and a CodingHistory field describing the encoding chain. "
            "No native encryption — audio is directly accessible. "
            "Standard RIFF is limited to ~4GB; larger files use RF64 extension. "
            "ExifTool and BWF MetaEdit extract all RIFF and BWF metadata.",
            "WAV Audio",
        ),
        "platforms": ["iOS", "macOS", "Android", "Windows"],
        "parser_class": "MediaParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\x52\x49\x46\x46",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "RIFF container header",
                    "WAV Audio",
                ),
            },
            {
                "offset": 8,
                "value": b"\x57\x41\x56\x45",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "WAVE subtype identifier at offset 8",
                    "WAV Audio",
                ),
            },
        ],
        "extensions": [".wav", ".bwf"],
        "links": [
            (
                "EBU Tech 3285 — Broadcast Wave Format specification",
                "https://tech.ebu.ch/docs/tech/tech3285.pdf",
            ),
            (
                "Broadcast Wave Format overview (Wikipedia)",
                "https://en.wikipedia.org/wiki/Broadcast_Wave_Format",
            ),
            (
                "Library of Congress — BWF format description",
                "https://www.loc.gov/preservation/digital/formats/fdd/fdd000356.shtml",
            ),
            (
                "BWF MetaEdit — open source BWF metadata tool",
                "https://mediaarea.net/BWFMetaEdit",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "M4A Audio",
        "short_name": "M4A",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "ISOBMFF audio-only container (ftyp brand 'M4A ') typically containing "
            "AAC (lossy) or ALAC (lossless) audio. "
            "Used for iTunes/Apple Music purchases and downloads, iOS Voice Memos, "
            "GarageBand exports, and FaceTime audio recordings. "
            "Shares box structure with MP4 — same mvhd timestamps "
            "(QuickTime epoch, seconds since 1904-01-01 UTC). "
            "iOS Voice Memos store recordings as M4A with the writing application "
            "field set to 'com.apple.VoiceMemos' — absence or alteration of this "
            "field is a forgery indicator. "
            "The 'ilst' box contains iTunes-style metadata tags (title, artist, "
            "album, comment, encoded date). "
            "iTunes Store purchases with FairPlay DRM use .m4p extension and "
            "cannot be decoded without authorization. "
            "ALAC variant (Apple Music lossless) is bit-perfect — no lossy artefacts.",
            "M4A Audio",
        ),
        "platforms": ["iOS", "macOS"],
        "parser_class": "MediaParser",
        "magic": [
            {
                "offset": 4,
                "value": b"\x66\x74\x79\x70",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ISOBMFF ftyp box at offset 4",
                    "M4A Audio",
                ),
            },
            {
                "offset": 8,
                "value": b"M4A ",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Apple audio major brand 'M4A ' in the ftyp box (offset 8)",
                    "M4A Audio",
                ),
            },
            {
                "offset": 8,
                "value": b"M4B ",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Apple audiobook major brand 'M4B ' in the ftyp box (offset 8)",
                    "M4A Audio",
                ),
            },
            {
                "offset": 8,
                "value": b"M4P ",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Apple protected audio major brand 'M4P ' in the ftyp box (offset 8)",
                    "M4A Audio",
                ),
            },
        ],
        "extensions": [".m4a", ".m4p", ".m4b"],
        "links": [
            (
                "MPEG-4 Part 14 — MP4/M4A file format (Wikipedia)",
                "https://en.wikipedia.org/wiki/MP4_file_format",
            ),
            (
                "Forensic originality identification of iPhone's voice memos (J. Phys.: Conf. Ser. 2019)",
                "https://doi.org/10.1088/1742-6596/1345/5/052053",
            ),
            (
                "ExifTool QuickTime tags (M4A metadata fields)",
                "https://exiftool.org/TagNames/QuickTime.html",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "AAC Audio",
        "short_name": "AAC",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Advanced Audio Coding — the dominant lossy audio codec on iOS and Android. "
            "AAC exists in multiple container forms requiring different analysis: "
            "(1) Raw ADTS-framed AAC (.aac) — sync word 0xFFF1 or 0xFFF9, "
            "self-synchronizing frames, minimal metadata, no embedded timestamps; "
            "common in Android voice recorder apps and streaming buffers. "
            "(2) ISOBMFF/M4A container — see M4A entry; most common on iOS. "
            "(3) ADIF (Audio Data Interchange Format) — rare, single header. "
            "Raw ADTS files abruptly stopped (e.g. by crash or battery removal) "
            "remain readable without finalization — unlike MPEG-4 which requires "
            "a complete moov box. "
            "Recording time must be inferred from filesystem timestamps or "
            "container metadata; ADTS carries no embedded timestamps. "
            "Bitrate and sampling rate can help fingerprint the recording device or app.",
            "AAC Audio",
        ),
        "platforms": ["iOS", "macOS", "Android", "Windows"],
        "parser_class": "MediaParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\xff\xf1",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ADTS AAC sync word — MPEG-4 AAC, no CRC",
                    "AAC Audio",
                ),
            },
            {
                "offset": 0,
                "value": b"\xff\xf9",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ADTS AAC sync word — MPEG-2 AAC, no CRC",
                    "AAC Audio",
                ),
            },
        ],
        "extensions": [".aac"],
        "links": [
            (
                "Advanced Audio Coding overview (Wikipedia)",
                "https://en.wikipedia.org/wiki/Advanced_Audio_Coding",
            ),
            (
                "ADTS format internals (MultimediaWiki)",
                "https://wiki.multimedia.cx/index.php/ADTS",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "FLAC Audio",
        "short_name": "FLAC",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Free Lossless Audio Codec — bit-perfect audio with native metadata support. "
            "Used for music archiving, high-quality recordings, and some Android devices. "
            "FLAC metadata blocks: STREAMINFO (sample rate, bit depth, channel count, "
            "and MD5 signature of the raw audio — useful for integrity verification), "
            "VORBIS_COMMENT (free-form key-value tags: title, artist, album, date, "
            "encoder, and any custom fields), PICTURE (embedded cover art), "
            "SEEKTABLE, and APPLICATION (vendor-specific data). "
            "The vendor string in VORBIS_COMMENT identifies the encoding library "
            "and version (e.g. 'reference libFLAC 1.3.0') — useful for source attribution. "
            "No native recording timestamp — inferred from filesystem metadata or "
            "VORBIS_COMMENT DATE field. "
            "Identified by 'fLaC' magic (0x664C6143) at offset 0.",
            "FLAC Audio",
        ),
        "platforms": ["Android", "Windows", "Linux"],
        "parser_class": "MediaParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\x66\x4c\x61\x43",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "FLAC stream marker ('fLaC')",
                    "FLAC Audio",
                ),
            }
        ],
        "extensions": [".flac"],
        "links": [
            (
                "FLAC format overview (Xiph.org)",
                "https://xiph.org/flac/documentation_format_overview.html",
            ),
            (
                "FLAC format specification (RFC 9639)",
                "https://www.rfc-editor.org/rfc/rfc9639.html",
            ),
            (
                "FLAC overview (Wikipedia)",
                "https://en.wikipedia.org/wiki/FLAC",
            ),
            (
                "metaflac — FLAC metadata command-line tool",
                "https://xiph.org/flac/documentation_tools_metaflac.html",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "OGG Audio",
        "short_name": "OGG",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Open bitstream container supporting multiple codecs — forensically "
            "encountered as Ogg Vorbis (music, games), Ogg Opus (voice messages), "
            "and Ogg FLAC (lossless audio). "
            "All OGG streams begin with the OggS capture pattern (0x4F676753). "
            "Ogg Opus is the dominant format for voice messages in modern messaging apps: "
            "WhatsApp stores voice notes as .opus (PTT-YYYYMMDD-WANNNN.opus — "
            "timestamp encoded in filename), Telegram stores as .ogg, "
            "both using Opus codec at 16-32 kbps. "
            "Vorbis comment metadata (same key-value format as FLAC) may contain "
            "title, artist, date, encoder, and custom fields. "
            "No native embedded timestamps — recording time inferred from filesystem "
            "metadata or messaging app databases.",
            "OGG Audio",
        ),
        "platforms": ["Android", "iOS", "Windows", "Linux"],
        "parser_class": "MediaParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\x4f\x67\x67\x53",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "OGG capture pattern ('OggS')",
                    "OGG Audio",
                ),
            }
        ],
        "extensions": [".ogg", ".oga", ".opus"],
        "links": [
            (
                "OGG format overview (Xiph.org)",
                "https://xiph.org/ogg/",
            ),
            (
                "Ogg encapsulation format specification (RFC 3533)",
                "https://www.rfc-editor.org/rfc/rfc3533.html",
            ),
            (
                "Opus codec specification (RFC 6716)",
                "https://datatracker.ietf.org/doc/html/rfc6716",
            ),
            (
                "Ogg Vorbis comment format",
                "https://xiph.org/vorbis/doc/v-comment.html",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "Opus Audio",
        "short_name": "Opus",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Low-latency voice and audio codec (RFC 6716) used in WebRTC, Discord, "
            "WhatsApp, Telegram, Signal, and VoIP applications. "
            "Opus is a codec, not a container — stored files use Ogg encapsulation "
            "as defined in RFC 7845, with the .opus extension. "
            "The Ogg ID header identifies the stream as Opus and contains channel count, "
            "sample rate, and pre-skip value. "
            "A Vorbis comment header follows with optional metadata tags. "
            "WhatsApp voice notes use .opus extension; Telegram uses .ogg — "
            "both are Ogg-encapsulated Opus at 16-32 kbps. "
            "WebRTC recordings may appear as raw Opus frames without Ogg container "
            "in browser cache or WebRTC dump files. "
            "No native embedded timestamps — recording time inferred from filesystem "
            "metadata, messaging app databases, or WhatsApp filename convention "
            "(PTT-YYYYMMDD-WANNNN.opus).",
            "Opus Audio",
        ),
        "platforms": ["Android", "iOS", "Windows", "Linux"],
        "parser_class": "MediaParser",
        "magic": [
            {
                "offset": 28,
                "value": b"\x4f\x70\x75\x73\x48\x65\x61\x64",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "OpusHead codec identification (RFC 7845 §5.1, offset 28 in first Ogg page)",
                    "Opus Audio",
                ),
            }
        ],
        "extensions": [".opus"],
        "links": [
            (
                "Opus codec specification (RFC 6716)",
                "https://datatracker.ietf.org/doc/html/rfc6716",
            ),
            (
                "Ogg encapsulation for Opus (RFC 7845)",
                "https://datatracker.ietf.org/doc/html/rfc7845",
            ),
            (
                "Opus FAQ (Xiph.org)",
                "https://wiki.xiph.org/OpusFAQ",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "WMA Audio",
        "short_name": "WMA",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Windows Media Audio — Microsoft proprietary audio format stored in the "
            "Advanced Systems Format (ASF) container. "
            "ASF is GUID-based: each object begins with a 16-byte GUID and size field. "
            "The Header Object contains metadata objects: title, author, copyright, "
            "creation date, and codec information. "
            "Four codec variants: WMA Standard (lossy), WMA Pro (multichannel/hi-res), "
            "WMA Lossless (bit-perfect), and WMA Voice (low-bitrate speech). "
            "DRM-protected WMA files (.wma with Windows Media DRM) cannot be decoded "
            "without a valid device-bound license — the license store on the original "
            "device may be required for decryption. "
            "Common on older Windows systems, Windows Phone devices, and Zune players. "
            "Rare on modern mobile devices — presence may indicate Windows Phone origin "
            "or legacy media library transfer.",
            "WMA Audio",
        ),
        "platforms": ["Windows"],
        "parser_class": "MediaParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ASF Header Object GUID",
                    "WMA Audio",
                ),
            }
        ],
        "extensions": [".wma", ".asf"],
        "links": [
            (
                "ASF format overview (Microsoft)",
                "https://learn.microsoft.com/en-us/windows/win32/wmformat/overview-of-the-asf-format",
            ),
            (
                "WMA format description (Library of Congress)",
                "https://www.loc.gov/preservation/digital/formats/fdd/fdd000027.shtml",
            ),
            (
                "ASF format description (Library of Congress)",
                "https://www.loc.gov/preservation/digital/formats/fdd/fdd000067.shtml",
            ),
            (
                "Windows Media Audio overview (Wikipedia)",
                "https://en.wikipedia.org/wiki/Windows_Media_Audio",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "AMR Audio",
        "short_name": "AMR",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Adaptive Multi-Rate speech codec standardised by 3GPP for GSM/UMTS networks. "
            "Two variants: AMR-NB (Narrowband, 4.75-12.2 kbps, 8 kHz sampling) and "
            "AMR-WB (Wideband/HD Voice, 6.6-23.85 kbps, 16 kHz, also known as G.722.2). "
            "Identified by ASCII magic: '#!AMR\\n' (NB) or '#!AMR-WB\\n' (WB). "
            "Used as the default voice recording format on older Android devices, "
            "in MMS attachments, and embedded in 3GP containers. "
            "AMR codec artefacts survive transcoding to WAV/PCM — "
            "quantization patterns in the waveform can identify mobile phone origin "
            "and detect splicing forgeries even after decompression. "
            "No native embedded timestamps — recording time inferred from filesystem "
            "metadata or messaging app databases. "
            "Replaced by AAC and Opus on modern devices but common in older acquisitions.",
            "AMR Audio",
        ),
        "platforms": ["Android"],
        "parser_class": "MediaParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\x23\x21\x41\x4d\x52\x0a",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "AMR-NB file magic ('#!AMR\\n')",
                    "AMR Audio",
                ),
            },
            {
                "offset": 0,
                "value": b"\x23\x21\x41\x4d\x52\x2d\x57\x42\x0a",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "AMR-WB file magic ('#!AMR-WB\\n')",
                    "AMR Audio",
                ),
            },
        ],
        "extensions": [".amr", ".awb"],
        "links": [
            (
                "AMR codec specification (3GPP TS 26.071)",
                "https://www.3gpp.org/ftp/Specs/archive/26_series/26.071/",
            ),
            (
                "Adaptive Multi-Rate audio codec (Wikipedia)",
                "https://en.wikipedia.org/wiki/Adaptive_Multi-Rate_audio_codec",
            ),
            (
                "Identification of AMR decompressed audio for forensics (ScienceDirect)",
                "https://www.sciencedirect.com/science/article/abs/pii/S1051200414003200",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "MessagePack",
        "short_name": "MsgPack",
        "category": "serialization",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Compact binary serialization format used as a JSON alternative in "
            "mobile apps, game clients, Redis, and network protocols. "
            "Self-describing at the type level (integers, strings, arrays, maps, binary, "
            "extensions) but field names are only present if the application includes them — "
            "without the originating schema, interpretation requires reverse engineering. "
            "No magic bytes — identification relies on file extension, database context, "
            "or heuristic parsing (first byte encodes type and length). "
            "The Timestamp extension type (-1) can encode nanosecond-precision timestamps — "
            "forensically relevant if used by the application. "
            "Forensically found in: app caches, network capture payloads, "
            "Redis RDB snapshots, and some iOS/Android app data directories. "
            "The msgpack Python library or MsgPack Explorer can decode raw files "
            "without schema knowledge.",
            "MessagePack",
        ),
        "platforms": ["iOS", "macOS", "Android", "Windows", "Linux"],
        "parser_class": None,
        "magic": [],
        "extensions": [".msgpack", ".mp"],
        "links": [
            (
                "MessagePack format specification",
                "https://github.com/msgpack/msgpack/blob/master/spec.md",
            ),
            (
                "MessagePack overview (msgpack.org)",
                "https://msgpack.org/",
            ),
            (
                "MessagePack overview (Wikipedia)",
                "https://en.wikipedia.org/wiki/MessagePack",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "NSKeyedArchiver",
        "short_name": "NSKeyedArchiver",
        "category": "serialization",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Apple's object graph serialization format, stored as a binary plist (bplist00) "
            "with a specific internal structure. "
            "Identified by the root dictionary keys: '$archiver' = 'NSKeyedArchiver', "
            "'$top' (entry point), '$objects' (object table array), and '$version'. "
            "Objects are referenced by UID pointers into the $objects table — "
            "circular references and complex graphs are supported. "
            "Used pervasively in iOS and macOS for: app state restoration, "
            "UserDefaults (complex object values), CoreData metadata, "
            "clipboard payloads, Siri intent donations (INInteraction), "
            "Biome store entries, and many app-specific data files. "
            "Custom file extensions are common (.sfl, .db, .archive) — "
            "a bplist header does not rule out NSKeyedArchiver encoding. "
            "Parsing requires a two-step process: first parse the bplist structure, "
            "then resolve UID references to reconstruct the object graph. "
            "Tools: ccl_bplist (Python, deserialise_NsKeyedArchiver), "
            "bpylist, plutil -p (macOS), and Mushy.",
            "NSKeyedArchiver",
        ),
        "platforms": ["iOS", "macOS"],
        "parser_class": "PlistParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\x62\x70\x6c\x69\x73\x74\x30\x30",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Binary plist header ('bplist00') — NSKeyedArchiver identified by internal keys",
                    "NSKeyedArchiver",
                ),
            }
        ],
        "extensions": [".plist", ".sfl", ".archive"],
        "links": [
            (
                "NSKeyedArchiver forensics — what are they and how to use them (CCL)",
                "https://digitalinvestigation.wordpress.com/2012/04/04/geek-post-nskeyedarchiver-files-what-are-they-and-how-can-i-use-them/",
            ),
            (
                "Manual analysis of NSKeyedArchiver plist files (Sarah Edwards / mac4n6)",
                "http://www.mac4n6.com/blog/2016/1/1/manual-analysis-of-nskeyedarchiver-formatted-plist-files-a-review-of-the-new-os-x-1011-recent-items",
            ),
            (
                "ccl_bplist — Python parser with NSKeyedArchiver support (CCL)",
                "https://github.com/cclgroupltd/ccl-bplist",
            ),
            (
                "iOS Biome AppIntent files — NSKeyedArchiver in practice (Blue Crew Forensics)",
                "https://bluecrewforensics.com/2022/03/07/ios-app-intents/",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "Android OAT/ART",
        "short_name": "OAT/ART",
        "category": "execution",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Android Runtime (ART) ahead-of-time compiled code artifacts introduced "
            "with Android 5.0 (Lollipop). Three file types form a triplet per app: "
            ".odex/.oat (ELF binary with AOT-compiled native code from dex2oat), "
            ".vdex (verified DEX bytecode — contains a copy of the original DEX "
            "since Android 8.0), and .art (optional ART heap image for fast startup). "
            "Presence of an .odex/.oat file for an app confirms the app was installed "
            "and optimized on the device — stronger execution evidence than APK alone. "
            "Prior to Android 8.0, the OAT file itself contained an embedded DEX copy — "
            "useful for recovering app code when the original APK is absent. "
            "Stored under /data/app/<package>/oat/<arch>/ for user apps "
            "and /data/dalvik-cache/ for system apps. "
            "The ELF build ID and dex2oat compilation timestamp indicate "
            "when the app was last installed or optimized.",
            "Android OAT/ART",
        ),
        "platforms": ["Android"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"\x7f\x45\x4c\x46",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ELF magic — OAT/ODEX files are ELF binaries",
                    "Android OAT/ART",
                ),
            }
        ],
        "extensions": [".oat", ".odex", ".vdex", ".art"],
        "links": [
            (
                "ART configuration and file types (Android AOSP)",
                "https://source.android.com/docs/core/runtime/configure",
            ),
            (
                "Android OAT/VDEX/DEX/ART formats (LIEF documentation)",
                "https://lief.re/doc/latest/tutorials/10_android_formats.html",
            ),
            (
                "Android compilation process — APK, DEX, OAT, VDEX, ART explained",
                "https://github.com/connglli/blog-notes/issues/35",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "PDF Document",
        "short_name": "PDF",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Portable Document Format — used pervasively for official documents, "
            "reports, forms, contracts, and communications. "
            "Two metadata layers: DocInfo dictionary (Author, Title, Creator, Producer, "
            "CreationDate, ModDate in D:YYYYMMDDHHmmSSOHH'mm' format including timezone) "
            "and XMP stream (richer, XML-based, with InstanceID, DocumentID, history). "
            "Creator identifies the authoring application (Word, LibreOffice, InDesign); "
            "Producer identifies the PDF engine (Acrobat, Ghostscript, pdfTeX) — "
            "mismatch between claimed document origin and Creator/Producer is a key "
            "fraud indicator (e.g. Creator: Canva on a bank statement). "
            "Incremental updates append new cross-reference tables (xref) without "
            "overwriting — each save event is preserved and recoverable. "
            "xref count > 1 indicates the document was saved multiple times; "
            "this structural record is harder to falsify than metadata fields. "
            "Earlier content versions (pre-redaction text, prior dates) may be "
            "recoverable from superseded objects in the same file. "
            "Can embed files, JavaScript (malware vector), digital signatures, "
            "and hidden layers (Optional Content Groups). "
            "Absent metadata on institutional documents is itself a fraud indicator.",
            "PDF Document",
        ),
        "platforms": ["iOS", "macOS", "Android", "Windows", "Linux"],
        "parser_class": "PDFParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\x25\x50\x44\x46\x2d",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "PDF header ('%PDF-')",
                    "PDF Document",
                ),
            }
        ],
        "extensions": [".pdf"],
        "links": [
            (
                "PDF metadata fields — complete forensic reference (HTPBE)",
                "https://htpbe.tech/blog/pdf-metadata-fields-complete-reference",
            ),
            (
                "PDF forensics and XMP metadata streams (Meridian Discovery)",
                "https://www.meridiandiscovery.com/articles/pdf-forensic-analysis-xmp-metadata/",
            ),
            (
                "PDF forensics and the metadata conundrum (PDF Association)",
                "https://pdfa.org/presentation/pdf-forensics-and-the-metadata-conundrum/",
            ),
            (
                "ExifTool — PDF metadata extraction",
                "https://exiftool.org/",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "Property List (XML plist)",
        "short_name": "XML plist",
        "category": "serialization",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Human-readable Apple property list format using XML serialization. "
            "Used for app preferences, configuration files, system settings, "
            "and iTunes/Xcode metadata. "
            "Info.plist in every iOS/macOS app bundle declares: bundle identifier "
            "(CFBundleIdentifier), version (CFBundleShortVersionString/CFBundleVersion), "
            "minimum OS version, URL schemes (LSApplicationQueriesSchemes), "
            "privacy usage descriptions (NSCamera/NSLocation/NSMicrophoneUsageDescription), "
            "background modes (UIBackgroundModes), and required device capabilities — "
            "key fields for app profiling and capability assessment. "
            "Dates are stored as ISO 8601 strings. "
            "Functionally equivalent to binary plist (bplist) — plutil converts between formats. "
            "Identified by XML declaration and Apple plist DOCTYPE. "
            "Some plists use JSON format in rare cases. "
            "Hardcoded API keys or credentials in Info.plist are a common "
            "security finding in app analysis.",
            "Property List (XML plist)",
        ),
        "platforms": ["iOS", "macOS"],
        "parser_class": "PlistParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\x3c\x3f\x78\x6d\x6c",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "XML declaration ('<?xml')",
                    "Property List (XML plist)",
                ),
            }
        ],
        "extensions": [".plist"],
        "links": [
            (
                "Apple property list format overview (Apple developer docs)",
                "https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/AboutInformationPropertyListFiles.html",
            ),
            (
                "Property list (Wikipedia — covers XML, binary, JSON variants)",
                "https://en.wikipedia.org/wiki/Property_list",
            ),
            (
                "Mobile Forensics – The File Format Handbook: Property Lists (Springer, 2022)",
                "https://doi.org/10.1007/978-3-030-98467-0_6",
            ),
            (
                "iOS plist forensics guide (mac4n6 / Sarah Edwards)",
                "https://www.mac4n6.com/blog/tag/plist",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "Protocol Buffers (protobuf)",
        "short_name": "protobuf",
        "category": "serialization",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Google's binary serialization format used by Android system services, "
            "Chrome/Edge/Brave (Network Action Predictor, Local State), "
            "Google apps (Gmail, Maps, Drive, Photos), Jetpack DataStore "
            "(Android SharedPreferences replacement), and gRPC network protocols. "
            "On Apple platforms, protobuf payloads appear as record bodies inside "
            "SEGB (.segb, .biome) files written by iOS and macOS system services "
            "(Screen Time, Health, Siri, Homekit, and others). "
            "No magic bytes — identification relies on file extension (.pb, .binarypb), "
            "database BLOB column context (common in Chrome SQLite databases), "
            "or heuristic detection of wire-format tag/length patterns. "
            "Not self-describing: without the .proto schema file, fields are visible "
            "only as field numbers and wire types (varint, length-delimited, "
            "fixed32, fixed64) — semantic meaning requires schema recovery. "
            "For open-source apps (Chrome, Chromium), schemas are often findable "
            "in the project source code. "
            "Partial blackbox decoding possible with Protoscope, pbtk, or CyberChef. "
            "Nested messages, repeated fields, and oneof unions are common structures.",
            "Protocol Buffers (protobuf)",
        ),
        "platforms": ["iOS", "macOS", "Android", "Windows", "Linux"],
        "parser_class": "ProtobufParser",
        "magic": [],
        "extensions": [".pb", ".binarypb"],
        "links": [
            (
                "Protocol Buffers encoding specification (Google)",
                "https://protobuf.dev/programming-guides/encoding/",
            ),
            (
                "Protocol Buffers overview (Wikipedia)",
                "https://en.wikipedia.org/wiki/Protocol_Buffers",
            ),
            (
                "Web browser protobuf artifacts — Chrome/Edge forensics (IBM X-Force)",
                "https://www.ibm.com/think/x-force/web-browser-artifacts-using-googles-data-interchange-format",
            ),
            (
                "Mobile Forensics – The File Format Handbook: Protocol Buffers (Springer, 2022)",
                "https://doi.org/10.1007/978-3-030-98467-0_9",
            ),
            (
                "Reading Protobuf wire format without a map — forensic deep dive (beBinary)",
                "https://bebinary4n6.blogspot.com/2026/06/reading-wire-protobuf-without-map.html",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "Windows Registry Hive",
        "short_name": "Registry Hive",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Windows hierarchical configuration database stored as binary hive files. "
            "Key forensic hives: "
            "SYSTEM (C:\\Windows\\System32\\config\\SYSTEM) — boot config, services, "
            "USB device history (USBSTOR), network interfaces, ShimCache, timezone; "
            "SOFTWARE — installed programs, Windows version, run keys, scheduled tasks; "
            "SAM — local account metadata, login counts, last login timestamps; "
            "NTUSER.DAT (%USERPROFILE%) — UserAssist (GUI execution with run counts "
            "and timestamps, ROT-13 encoded), RecentDocs MRU, TypedPaths, ShellBags, "
            "OpenSaveMRU, persistence run keys; "
            "UsrClass.dat — ShellBags for non-desktop folders, MUICache; "
            "Amcache.hve (C:\\Windows\\AppCompat\\Programs\\) — SHA-1 hashes and "
            "timestamps of executed programs. "
            "Each key has a LastWriteTime (Windows FILETIME: 100-nanosecond intervals "
            "since 1601-01-01 UTC). "
            "Transaction logs (.LOG1/.LOG2) contain uncommitted changes not yet written "
            "to the primary hive — must be merged for complete analysis. "
            "Deleted keys may survive in hive slack space.",
            "Windows Registry Hive",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"\x72\x65\x67\x66",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Registry hive signature ('regf')",
                    "Windows Registry Hive",
                ),
            }
        ],
        "extensions": [".dat", ".hve", ".log1", ".log2"],
        "links": [
            (
                "Windows Registry hive format specification (Maxim Suhanov)",
                "https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md",
            ),
            (
                "Windows Registry forensics — artifacts and analysis (ElcomSoft)",
                "https://blog.elcomsoft.com/2026/02/investigating-windows-registry/",
            ),
            (
                "Windows Registry (ForensicsWiki)",
                "https://forensics.wiki/windows_registry/",
            ),
            (
                "Registry Explorer and RECmd (Eric Zimmerman tools)",
                "https://ericzimmerman.github.io/#!index.md",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "Apple SEGB (Biome store)",
        "short_name": "SEGB",
        "category": "log",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Apple's Segmented Binary format — the on-disk storage container for iOS "
            "and macOS Biome data, which replaced much of KnowledgeC from iOS 16 onwards. "
            "Two versions: SEGB v1 (iOS 14-16, 56-byte header ending with 'SEGB' in ASCII, "
            "32-byte record headers with two Mac Absolute Time timestamps) and "
            "SEGB v2 (iOS 17+, 32-byte header, entries + trailer section). "
            "Each record payload is a protobuf — requiring schema knowledge for full decoding. "
            "130+ Biome streams cover: app focus/usage (replaces KnowledgeC), "
            "app installs, Safari history, Siri/AppIntent interactions (may contain "
            "deleted iMessages and Snapchat activity), CarPlay connections, "
            "notifications, location events, and screen activity. "
            "Located at /private/var/mobile/Library/Biome/streams/ and "
            "/private/var/db/biome/streams/ — each stream has 'local/' (device) "
            "and 'remote/' (iCloud-synced from other devices) subdirectories. "
            "Tombstone/ folder contains expired/deleted records — partially recoverable. "
            "Filenames are Mac Absolute Time floats (insert decimal 6 places from end). "
            "Data survives app deletion and may outlast primary databases.",
            "Apple SEGB (Biome store)",
        ),
        "platforms": ["iOS", "macOS"],
        "parser_class": "SegbParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\x53\x45\x47\x42",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "SEGB v2 signature at offset 0 (32-byte header)",
                    "Apple SEGB (Biome store)",
                ),
            },
            {
                "offset": 52,
                "value": b"\x53\x45\x47\x42",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "SEGB v1 signature at offset 52 (within 56-byte header)",
                    "Apple SEGB (Biome store)",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "ccl_segb — CCL parser for SEGB v1 and v2",
                "https://github.com/cclgroupltd/ccl-segb",
            ),
            (
                "iOS 16 Biome breakdown Part 1 — SEGB format (D20 Forensics)",
                "https://blog.d204n6.com/2022/09/ios-16-now-you-c-it-now-you-dont.html",
            ),
            (
                "SEGB v2 — iOS 17 format changes (Cellebrite)",
                "https://cellebrite.com/en/blog/understanding-and-decoding-the-newest-ios-segb-format/",
            ),
            (
                "iOS Biome AppIntent files — deleted iMessages in SEGB (Blue Crew Forensics)",
                "https://bluecrewforensics.com/2022/03/07/ios-app-intents/",
            ),
            (
                "Biome data as KnowledgeC successor (Magnet Forensics)",
                "https://www.magnetforensics.com/blog/bringing-it-back-with-biome-data/",
            ),
            (
                "84 Streams Later: Exploring the Evolution of Apple Biome in iOS",
                "https://blog.digital-forensics.it/2026/07/84-streams-later-exploring-evolution-of.html",
            ),
            
            (
                "Beyond the C — SEGB and Biome Forensics with crush (beBinary)",
                "https://bebinary4n6.blogspot.com/2026/05/beyond-c-segb-and-biome-forensics-with.html",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "Android Sparse Image",
        "short_name": "simg",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Android's space-efficient flash image format that replaces empty and "
            "repetitive blocks with metadata chunks, reducing image size for "
            "transmission and fastboot flashing. "
            "Used in factory images (Google, Samsung, OEM), OTA update packages, "
            "and custom ROM distributions. "
            "28-byte header (magic 0xED26FF3A) specifies block size (typically 4096 bytes), "
            "total output blocks, and chunk count. "
            "Three chunk types: RAW (data), DONT_CARE (empty/unwritten blocks), "
            "and FILL (repeated 4-byte pattern). "
            "Must be converted to raw before mounting or forensic analysis — "
            "simg2img (AOSP/anestisb port) converts to raw ext4/f2fs. "
            "Large images are sometimes split into multiple sparse chunks "
            "that must be reassembled before conversion. "
            "Forensically relevant as the delivery container for Android system "
            "partitions (system.img, vendor.img, product.img) — "
            "useful for comparing suspect device partitions against factory baselines.",
            "Android Sparse Image",
        ),
        "platforms": ["Android"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"\x3a\xff\x26\xed",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Android sparse image magic (0xED26FF3A little-endian)",
                    "Android Sparse Image",
                ),
            }
        ],
        "extensions": [".img", ".simg"],
        "links": [
            (
                "Android sparse image format (libsparse — AOSP source)",
                "https://android.googlesource.com/platform/system/core/+/refs/heads/master/libsparse/",
            ),
            (
                "Android sparse image format explained (2net.co.uk)",
                "https://2net.co.uk/tutorial/android-sparse-image-format",
            ),
            (
                "Formal sparse format specification (Kaitai Struct)",
                "https://formats.kaitai.io/android_sparse/",
            ),
            (
                "simg2img — standalone converter (anestisb/android-simg2img)",
                "https://github.com/anestisb/android-simg2img",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "SQLite Database",
        "short_name": "SQLite",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The dominant embedded database on iOS, Android, macOS, and Windows. "
            "Used by virtually every app for messages, call logs, contacts, browser "
            "history, location data, and app state. "
            "Identified by a 16-byte magic string ('SQLite format 3\\000') at offset 0. "
            "100-byte file header contains: page size, write version (rollback=1, WAL=2), "
            "encoding, and change counter. "
            "Key forensic recovery mechanisms: "
            "(1) Freelist — deleted pages retained in a free-page list; records survive "
            "until overwritten by new insertions. "
            "(2) Page slack space — deleted records within active pages may survive "
            "partially below the live cell pointer array. "
            "(3) WAL (Write-Ahead Log) — in WAL mode, the -wal file contains uncommitted "
            "and recently checkpointed pages; must be analysed alongside the main DB. "
            "WAL slack: after checkpoint, old pages remain in the WAL until overwritten "
            "from the start — prior database states are recoverable. "
            "CRITICAL: opening a WAL-mode database with a standard SQLite driver "
            "triggers a checkpoint, irreversibly committing and clearing the WAL — "
            "use read-only forensic tools or low-level parsing only. "
            "sqlite_sequence table gaps reveal deleted AUTOINCREMENT rows.",
            "SQLite Database",
        ),
        "platforms": ["iOS", "macOS", "Android", "Windows", "Linux"],
        "parser_class": "SQLiteParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\x53\x51\x4c\x69\x74\x65\x20\x66\x6f\x72\x6d\x61\x74\x20\x33\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "SQLite magic string ('SQLite format 3\\x00')",
                    "SQLite Database",
                ),
            }
        ],
        "extensions": [".db", ".sqlite", ".sqlite3", ".db3"],
        "links": [
            (
                "SQLite file format specification",
                "https://www.sqlite.org/fileformat.html",
            ),
            (
                "Mobile Forensics – The File Format Handbook: SQLite (Springer, 2022)",
                "https://doi.org/10.1007/978-3-030-98467-0_5",
            ),
            (
                "SQLite forensics — freelist, WAL, and unallocated space (Belkasoft)",
                "https://belkasoft.com/sqlite-analysis",
            ),
            (
                "Forensic analysis of SQLite WAL files (Sanderson Forensics)",
                "https://sqliteforensictoolkit.com/forensic-examination-of-sqlite-write-ahead-log-wal-files/",
            ),
            (
                "Making the Invisible Visible — recovering deleted SQLite records (FQLite)",
                "https://github.com/pawlaszczyk/fqlite",
            ),
            (
                "SQLite deleted record recovery techniques — survey (ScienceDirect 2025)",
                "https://www.sciencedirect.com/science/article/abs/pii/S2666281725001714",
            ),
            (
                "What Hides in the WAL — SQLite Forensics with crush (beBinary)",
                "https://bebinary4n6.blogspot.com/2026/05/what-hides-in-wal-sqlite-forensics-with.html",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "SQLite WAL",
        "short_name": "SQLite WAL",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Write-Ahead Log companion file for SQLite databases in WAL journal mode. "
            "Contains uncommitted database pages and, after checkpoint, WAL slack — "
            "old page versions that persist until overwritten from the start of the file. "
            "Must be analysed alongside the parent database file using the same schema. "
            "CRITICAL: opening the parent database with a standard SQLite driver "
            "triggers a checkpoint, committing and clearing the WAL — "
            "use read-only forensic tools only. "
            "Opened standalone (no companion database), crush shows the same per-frame "
            "inventory as raw decoded values, since column names require the schema. "
            "See SQLite Database entry for full forensic context.",
            "SQLite WAL",
        ),
        "platforms": ["iOS", "macOS", "Android", "Windows", "Linux"],
        "parser_class": "SQLiteWALParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\x37\x7f\x06\x82",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "SQLite WAL magic (big-endian)",
                    "SQLite WAL",
                ),
            }
        ],
        "extensions": ["-wal"],
        "links": [
            (
                "SQLite WAL format specification",
                "https://www.sqlite.org/walformat.html",
            ),
            (
                "Forensic analysis of SQLite WAL files (Sanderson Forensics)",
                "https://sqliteforensictoolkit.com/forensic-examination-of-sqlite-write-ahead-log-wal-files/",
            ),
            (
                "What Hides in the WAL — SQLite Forensics with crush (beBinary)",
                "https://bebinary4n6.blogspot.com/2026/05/what-hides-in-wal-sqlite-forensics-with.html",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "SQLite Rollback Journal",
        "short_name": "SQLite Journal",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Legacy (pre-WAL) companion file for a SQLite database in DELETE/TRUNCATE/"
            "PERSIST/MEMORY journal_mode. Holds the pre-transaction content of every page "
            "a still-open or crash-interrupted transaction touched, so SQLite can roll "
            "back an incomplete write on next open. Unlike -wal, this is the *old* page "
            "content, not the current one — forensically it means the opposite: the base "
            "database file's current on-disk pages for a hot journal's page numbers are "
            "the interrupted, never-committed write, and the journal itself holds what a "
            "proper rollback restores. "
            "A journal file present but with a zeroed/invalid header (PERSIST mode keeps "
            "the file after every commit but zeroes it) is stale, not hot, and must not "
            "be treated as recoverable content. "
            "Header (undocumented by SQLite as a stable format, reconstructed from its "
            "pager.c): 8-byte magic (d9 d5 05 f9 20 a1 63 d7), page-record count, "
            "checksum nonce, pre-transaction database size in pages, sector size, page "
            "size, then zero or more (page number + page content + checksum) records, "
            "possibly repeated across multiple header segments. "
            "Deleted rows and unallocated slack within a journaled page are recoverable "
            "the same way as in a live database page (freeblock chain, page-content-area "
            "gap) — crush surfaces every live/deleted/slack entry, not just live pages.",
            "SQLite Rollback Journal",
        ),
        "platforms": ["iOS", "macOS", "Android", "Windows", "Linux"],
        "parser_class": "SQLiteJournalParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "SQLite rollback-journal magic",
                    "SQLite Rollback Journal",
                ),
            }
        ],
        "extensions": ["-journal", ".db-journal"],
        "links": [
            (
                "SQLite file format specification (main database, for page-level context)",
                "https://www.sqlite.org/fileformat.html",
            ),
            (
                "What Hides in the WAL — SQLite Forensics with crush (beBinary)",
                "https://bebinary4n6.blogspot.com/2026/05/what-hides-in-wal-sqlite-forensics-with.html",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "TAR Archive",
        "short_name": "TAR",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Unix standard archive format packaging files and directory trees with "
            "full metadata preservation. TAR itself provides no compression — "
            "commonly combined with gzip (.tar.gz/.tgz), bzip2 (.tar.bz2), or "
            "xz (.tar.xz). "
            "Structure: each file entry has a 512-byte header containing filename, "
            "permissions, UID/GID (as octal ASCII), file size, and mtime "
            "(Unix epoch seconds as octal ASCII). "
            "Three major variants: V7 (no magic), USTAR/POSIX ('ustar\\0' at offset 257 "
            "— adds uname/gname and longer paths), GNU tar ('ustar  \\0' with two spaces), "
            "and PAX/POSIX.1-2001 (USTAR + extended header records for sub-second "
            "timestamps, unlimited path lengths, and UTF-8 encoding). "
            "Forensically relevant as: container for Android OTA payload.bin, "
            "iOS/macOS app packages (.ipa are ZIP, but some backup formats use TAR), "
            "Linux backup archives, Docker image layers, and forensic tool outputs. "
            "TAR has no deletion mechanism — updated files are appended as new entries; "
            "superseded versions of the same file remain in the archive. "
            "mtime in headers may reveal original file timestamps from the source system.",
            "TAR Archive",
        ),
        "platforms": ["Android", "Linux", "macOS", "iOS"],
        "parser_class": "TarVFS",
        "magic": [
            {
                "offset": 257,
                "value": b"\x75\x73\x74\x61\x72",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "USTAR/GNU magic ('ustar') at offset 257 in first header block",
                    "TAR Archive",
                ),
            }
        ],
        "extensions": [".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz"],
        "links": [
            (
                "TAR format specification (GNU tar manual)",
                "https://www.gnu.org/software/tar/manual/html_node/Standard.html",
            ),
            (
                "TAR archive format overview (Wikipedia)",
                "https://en.wikipedia.org/wiki/Tar_(computing)",
            ),
            (
                "TAR format internals and variants explained",
                "https://mort.coffee/home/tar/",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "EWF Acquisition",
        "short_name": "EWF",
        "category": "disk_image",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Expert Witness Format (EWF) — the .E01 forensic disk image format "
            "written and read by many acquisition tools (EnCase, FTK Imager, "
            "ewfacquire/libewf, X-Ways, and others). EWF-E01 (version 1) is "
            "reportedly based on ASR Data's earlier Expert Witness Compression "
            "Format; EnCase itself was originally named 'Expert Witness' before "
            "a trademark dispute with ASR Data over that name. "
            "Typically the primary evidence file in a case: a bit-for-bit "
            "physical or logical disk acquisition, stored as one or more "
            "numbered segments (.E01, .E02, ...), optionally compressed and "
            "hashed at acquisition time. "
            "This EWF-E01 (version 1) format is the one EnCase 6/7 and FTK "
            "Imager write and by far the most common in the field. SMART (.s01) "
            "acquisitions carry the same signature and are read the same way; "
            "the newer EWF2 (.Ex01) and the logical .L01/.Lx01 variants have "
            "entries of their own. "
            "The acquisition stores its own MD5/SHA1 of the media in a dedicated "
            "hash section, written by the acquisition tool — recomputing and "
            "comparing against it verifies the acquisition has not been altered "
            "since it was made, independent of any chain-of-custody paperwork.",
            "EWF Acquisition",
        ),
        "platforms": ["Windows", "macOS", "Linux"],
        "parser_class": "RawImageVFS",
        "magic": [
            {
                "offset": 0,
                "value": b"\x45\x56\x46\x09\x0d\x0a\xff\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "EWF-E01 / SMART signature ('EVF' + control bytes)",
                    "EWF Acquisition",
                ),
            }
        ],
        "extensions": [".e01", ".s01"],
        "links": [
            (
                "EnCase image file format — history and format versions (Forensics Wiki)",
                "https://forensics.wiki/encase_image_file_format/",
            ),
            (
                "Expert Witness Compression Format (EWF) — libewf project",
                "https://github.com/libyal/libewf/blob/main/documentation/Expert%20Witness%20Compression%20Format%20(EWF).asciidoc",
            ),
            (
                "abrignoni/ewfprobe — pure-Python EWF, EWF2, SMART and AFF reader",
                "https://github.com/abrignoni/ewfprobe",
            ),
            (
                "abrignoni/qnxprobe — raw image / partition reader used alongside ewfprobe",
                "https://github.com/abrignoni/qnxprobe",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "EWF2 Acquisition",
        "short_name": "Ex01",
        "category": "disk_image",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "EWF2 (.Ex01) — the second version of the Expert Witness Format, "
            "introduced with EnCase 7. Like EWF-E01 it holds a bit-for-bit disk "
            "acquisition in numbered segments (.Ex01, .Ex02, ...), compressed in "
            "chunks, with the MD5/SHA1 the acquisition tool computed stored "
            "alongside; recomputing and comparing against it verifies the "
            "acquisition has not been altered since it was made. EnCase can also "
            "encrypt an Ex01; that encryption is not publicly documented, and an "
            "encrypted Ex01 is refused with that reason rather than read.",
            "EWF2 Acquisition",
        ),
        "platforms": ["Windows", "macOS", "Linux"],
        "parser_class": "RawImageVFS",
        "magic": [
            {
                "offset": 0,
                "value": b"EVF2\x0d\x0a\x81\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "EWF2 signature ('EVF2' + control bytes)",
                    "EWF2 Acquisition",
                ),
            }
        ],
        "extensions": [".ex01"],
        "links": [
            (
                "EWF2 format specification — libewf project",
                "https://github.com/libyal/libewf/blob/main/documentation/Expert%20Witness%20Compression%20Format%202%20(EWF2).asciidoc",
            ),
            (
                "abrignoni/ewfprobe — pure-Python EWF, EWF2, SMART and AFF reader",
                "https://github.com/abrignoni/ewfprobe",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "AFF Acquisition",
        "short_name": "AFF",
        "category": "disk_image",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Advanced Forensic Format (AFF) — an open disk acquisition format "
            "from AFFLIB, written by tools such as affconvert and FTK Imager. The "
            "disk is stored in compressed pages beside named metadata segments, "
            "which can hold the acquisition's own MD5/SHA1 of the disk and a "
            "count of bad sectors. An AFD is the same acquisition split over "
            "several .aff files in a folder whose name ends in .afd. A page the "
            "acquisition declares but doesn't hold reads as the image's "
            "bad-sector marker, not as data from the device. AFF4, the later "
            "successor, is a different format.",
            "AFF Acquisition",
        ),
        "platforms": ["Windows", "macOS", "Linux"],
        "parser_class": "RawImageVFS",
        "magic": [
            {
                "offset": 0,
                "value": b"AFF10\x0d\x0a\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "AFF signature ('AFF10' + control bytes), in every file of an AFD",
                    "AFF Acquisition",
                ),
            }
        ],
        "extensions": [".aff"],
        "links": [
            (
                "Advanced Forensics Format (Forensics Wiki)",
                "https://forensics.wiki/aff/",
            ),
            (
                "AFFLIB — the reference implementation",
                "https://github.com/sshock/AFFLIBv3",
            ),
            (
                "abrignoni/ewfprobe — pure-Python EWF, EWF2, SMART and AFF reader",
                "https://github.com/abrignoni/ewfprobe",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "AFF4 Acquisition",
        "short_name": "AFF4",
        "category": "disk_image",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Advanced Forensic Format 4 — an acquisition format stored as a ZIP64 "
            "container. The acquired data is held in compressed, chunked image streams, "
            "mapped onto the source's address space by map streams, with RDF metadata "
            "(information.turtle) describing source, acquisition and streams; the volume "
            "URI (aff4://...) is in the ZIP comment and in container.description. A "
            "container can be striped across several .aff4 files. Stores hashes of "
            "streams, chunks, maps and of the whole source, so the acquisition can be "
            "verified. Used for disk images and for memory acquisitions: sparse maps "
            "represent physical memory with gaps, and the metadata category (e.g. "
            "aff4:category memory/physical) tells which one an image holds. Variants: "
            "encrypted AFF4 and AFF4-L for logical evidence.",
            "AFF4 Acquisition",
        ),
        "platforms": ["Windows", "macOS", "Linux"],
        "parser_class": "RawImageVFS",
        "magic": [
            {
                # Informational only (offset None): at offset 0 it would be any
                # ZIP's signature, and the format identified by it.
                "offset": None,
                "value": b"aff4://",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "A ZIP whose comment holds the aff4:// volume URI, or whose first "
                    "member is container.description",
                    "AFF4 Acquisition",
                ),
            }
        ],
        "extensions": [".aff4"],
        "links": [
            (
                "AFF4 Standard (aff4/Standard)",
                "https://github.com/aff4/Standard",
            ),
            (
                "pyaff4 — the AFF4 reference implementation",
                "https://github.com/aff4/pyaff4",
            ),
            (
                "ForensicsWiki — Advanced Forensic Framework 4 (AFF4)",
                "https://forensics.wiki/aff4/",
            ),
            (
                "Cohen, Garfinkel, Schatz — Extending the Advanced Forensic Format to "
                "accommodate Multiple Data Sources, Logical Evidence, Arbitrary Information "
                "and Forensic Workflow (DFRWS 2009)",
                "https://dfrws.org/presentation/extending-the-advanced-forensic-format-to-accommodate-multiple-data-sources-logical-evidence-arbitrary-information-and-forensic-workflow/",
            ),
            (
                "Schatz — AFF4-L: A scalable open logical evidence container (DFRWS 2019)",
                "https://dfrws.org/presentation/aff4-l-a-scalable-open-logical-evidence-container/",
            ),
            (
                "The AFF4 Imager — documentation (incl. memory acquisition)",
                "https://aff4-imager.readthedocs.io/en/latest/",
            ),
            (
                "abrignoni/ewfprobe — the reader Crush uses",
                "https://github.com/abrignoni/ewfprobe",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "Microsoft Virtual Hard Disk (VHD)",
        "short_name": "VHD",
        "category": "disk_image",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Virtual Hard Disk — a 512-byte footer starting 'conectix' at the end of the "
            "file describes the disk. Three types: fixed (the disk's bytes followed by "
            "the footer), dynamic (a copy of the footer at offset 0, a dynamic header "
            "and a block allocation table; blocks are allocated as written) and "
            "differencing (holds only the blocks changed since a parent VHD; the disk's "
            "content spans both files). Older Virtual PC versions split a VHD on FAT32 "
            "volumes into .v01, .v02 … files. Used by Virtual PC, early Hyper-V, Windows "
            "disk management and Windows Backup images. Mounts with a double-click since "
            "Windows 8 and is used as a container to deliver malware past "
            "Mark-of-the-Web (MITRE ATT&CK T1553.005).",
            "Microsoft Virtual Hard Disk (VHD)",
        ),
        "platforms": ["Windows"],
        "parser_class": "RawImageVFS",
        "magic": [
            {
                "offset": None,
                "value": b"conectix",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Footer cookie 'conectix' in the last 512 bytes",
                    "Microsoft Virtual Hard Disk (VHD)",
                ),
            },
            {
                "offset": 0,
                "value": b"conectix",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Copy of the footer at offset 0, in a dynamic or differencing VHD",
                    "Microsoft Virtual Hard Disk (VHD)",
                ),
            },
        ],
        "extensions": [".vhd"],
        "links": [
            (
                "Virtual Hard Disk (VHD) image format — format documentation (libyal/libvhdi)",
                "https://github.com/libyal/libvhdi/blob/main/documentation/Virtual%20Hard%20Disk%20(VHD)%20image%20format.asciidoc",
            ),
            (
                "Unsplitting a split virtual hard disk (Microsoft, Virtual PC Guy)",
                "https://learn.microsoft.com/en-us/archive/blogs/virtual_pc_guy/unsplitting-a-split-virtual-hard-disk",
            ),
            (
                "ForensicsWiki — Virtual Hard Disk (VHD)",
                "https://forensics.wiki/virtual_hard_disk_(vhd)/",
            ),
            (
                "MITRE ATT&CK T1553.005 — Mark-of-the-Web Bypass",
                "https://attack.mitre.org/techniques/T1553/005/",
            ),
            (
                "abrignoni/ewfprobe — the reader Crush uses",
                "https://github.com/abrignoni/ewfprobe",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "Microsoft Virtual Hard Disk v2 (VHDX)",
        "short_name": "VHDX",
        "category": "disk_image",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Virtual Hard Disk v2 — the successor of VHD. Begins with the file type "
            "identifier 'vhdxfile', followed by two redundant headers, a log for crash "
            "consistency, a block allocation table and a metadata region. Fixed, dynamic "
            "and differencing disks as in VHD; a differencing disk holds only the blocks "
            "changed since its parent. Used by Hyper-V, Windows disk management and "
            "backup products. WSL 2 stores each Linux distribution as ext4.vhdx under "
            "%LOCALAPPDATA%\\Packages\\…\\LocalState\\, and Docker Desktop stores its "
            "data in a VHDX, so a Windows host can hold complete Linux filesystems. "
            "Mounts with a double-click and is used to deliver malware past "
            "Mark-of-the-Web.",
            "Microsoft Virtual Hard Disk v2 (VHDX)",
        ),
        "platforms": ["Windows"],
        "parser_class": "RawImageVFS",
        "magic": [
            {
                "offset": 0,
                "value": b"vhdxfile",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "VHDX file type identifier 'vhdxfile'",
                    "Microsoft Virtual Hard Disk v2 (VHDX)",
                ),
            }
        ],
        "extensions": [".vhdx"],
        "links": [
            (
                "[MS-VHDX]: Virtual Hard Disk v2 (VHDX) File Format (Microsoft)",
                "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-vhdx/",
            ),
            (
                "Virtual Hard Disk version 2 (VHDX) image format — format documentation "
                "(libyal/libvhdi)",
                "https://github.com/libyal/libvhdi/blob/main/documentation/Virtual%20Hard%20Disk%20version%202%20(VHDX)%20image%20format.asciidoc",
            ),
            (
                "MITRE ATT&CK T1553.005 — Mark-of-the-Web Bypass",
                "https://attack.mitre.org/techniques/T1553/005/",
            ),
            (
                "abrignoni/ewfprobe — the reader Crush uses",
                "https://github.com/abrignoni/ewfprobe",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "VMware Virtual Disk (VMDK)",
        "short_name": "VMDK",
        "category": "disk_image",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "VMware virtual disk. A disk is a text descriptor ('# Disk DescriptorFile') "
            "naming one or more extents — sparse ('KDMV', older ESX 'COWD'), "
            "stream-optimized (compressed, as in OVA/OVF exports), flat (the disk's bytes "
            "as they are) or SESPARSE — embedded in the descriptor's file or stored "
            "beside it, often split into 2 GB pieces. A snapshot is a delta disk holding "
            "only what changed since its parent; the disk's content spans the chain. "
            "Used by VMware Workstation, Fusion and ESXi, and by VirtualBox. Snapshots "
            "and suspended VMs come with .vmem and .vmsn files beside the disk that hold "
            "the VM's memory.",
            "VMware Virtual Disk (VMDK)",
        ),
        "platforms": ["Windows", "macOS", "Linux"],
        "parser_class": "RawImageVFS",
        "magic": [
            {
                "offset": 0,
                "value": b"KDMV",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Sparse extent magic 'KDMV' (a descriptor file instead begins "
                    "'# Disk DescriptorFile')",
                    "VMware Virtual Disk (VMDK)",
                ),
            },
            {
                "offset": 0,
                "value": b"COWD",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Older ESX sparse (COWD) extent",
                    "VMware Virtual Disk (VMDK)",
                ),
            },
        ],
        "extensions": [".vmdk"],
        "links": [
            (
                "VMware Virtual Disk Format (VMDK) — format documentation (libyal/libvmdk)",
                "https://github.com/libyal/libvmdk/blob/main/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc",
            ),
            (
                "ForensicsWiki — VMware Virtual Disk Format (VMDK)",
                "https://forensics.wiki/vmware_virtual_disk_format_(vmdk)/",
            ),
            (
                "abrignoni/ewfprobe — the reader Crush uses",
                "https://github.com/abrignoni/ewfprobe",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "QEMU Copy-On-Write Disk (QCOW)",
        "short_name": "QCOW",
        "category": "disk_image",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "QEMU Copy-On-Write disk (QCOW version 1, QCOW2 versions 2 and 3). Begins "
            "'QFI' 0xFB and the version, followed by a header, a two-level cluster table "
            "(L1/L2) and refcount tables. Clusters are allocated as written and can be "
            "compressed; an image can hold internal snapshots, keep its data in an "
            "external file, or be an overlay of a backing file, so the disk's content "
            "spans both files. Can be encrypted with LUKS or QEMU's older AES. Used by "
            "KVM/libvirt, Proxmox, OpenStack and GNS3, and by the Android Emulator, "
            "which keeps a virtual device's user data as a QCOW2 overlay "
            "(userdata-qemu.img.qcow2).",
            "QEMU Copy-On-Write Disk (QCOW)",
        ),
        "platforms": ["Linux"],
        "parser_class": "RawImageVFS",
        "magic": [
            {
                "offset": 0,
                "value": b"QFI\xfb",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "QCOW magic 'QFI' 0xFB, followed by the version (1, 2 or 3)",
                    "QEMU Copy-On-Write Disk (QCOW)",
                ),
            }
        ],
        "extensions": [".qcow", ".qcow2"],
        "links": [
            (
                "The QCOW2 Image Format (QEMU docs/interop/qcow2.rst)",
                "https://www.qemu.org/docs/master/interop/qcow2.html",
            ),
            (
                "QEMU Copy-On-Write file format — format documentation (libyal/libqcow)",
                "https://github.com/libyal/libqcow/blob/main/documentation/QEMU%20Copy-On-Write%20file%20format.asciidoc",
            ),
            (
                "ForensicsWiki — QCOW image format",
                "https://forensics.wiki/qcow_image_format/",
            ),
            (
                "abrignoni/ewfprobe — the reader Crush uses",
                "https://github.com/abrignoni/ewfprobe",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "EnCase Logical Evidence",
        "short_name": "L01",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "EnCase logical evidence (.L01, and .Lx01 in the EWF2 format) — "
            "copies of selected files and folders, collected by EnCase, with "
            "their names, times and stored MD5/SHA1, rather than a disk. It "
            "holds no partition table or filesystem. Crush doesn't open logical "
            "evidence yet: opened as a disk image it is refused with that "
            "reason, and a normal open shows the file's own bytes.",
            "EnCase Logical Evidence",
        ),
        "platforms": ["Windows", "macOS", "Linux"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"LVF\x09\x0d\x0a\xff\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "L01 signature ('LVF' + control bytes)",
                    "EnCase Logical Evidence",
                ),
            },
            {
                "offset": 0,
                "value": b"LEF2\x0d\x0a\x81\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Lx01 signature ('LEF2' + control bytes)",
                    "EnCase Logical Evidence",
                ),
            },
        ],
        "extensions": [".l01", ".lx01"],
        "links": [
            (
                "Expert Witness Compression Format (EWF) — libewf project (L01 section)",
                "https://github.com/libyal/libewf/blob/main/documentation/Expert%20Witness%20Compression%20Format%20(EWF).asciidoc",
            ),
            (
                "ForensicsWiki — EnCase image file format (incl. L01)",
                "https://forensics.wiki/encase_image_file_format/",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "FTK Imager Logical Evidence (AD1)",
        "short_name": "AD1",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "AccessData (now Exterro) custom content image — a logical image of selected "
            "files and folders, not a disk: no partition table, no filesystem, no "
            "unallocated space, so deleted data is only included if it was selected as a "
            "file. Every segment (.ad1, .ad2, .ad3 …) begins 'ADSEGMENTEDFILE'; the first "
            "segment carries the logical image header 'ADLOGICALIMAGE'. Stores the file "
            "tree with names, timestamps, attributes and per-file hashes, with file "
            "content compressed in chunks. Can be protected with AD encryption (password "
            "or certificate). Common for targeted and triage collections and for "
            "evidence handed over by other parties; the content can come from any "
            "system.",
            "FTK Imager Logical Evidence (AD1)",
        ),
        "platforms": ["Windows", "macOS", "Linux"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"ADSEGMENTEDFILE\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "AD1 segment signature 'ADSEGMENTEDFILE', in every file of the set",
                    "FTK Imager Logical Evidence (AD1)",
                ),
            },
            {
                "offset": 0x200,
                "value": b"ADLOGICALIMAGE",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Logical image header, in the first file of the set",
                    "FTK Imager Logical Evidence (AD1)",
                ),
            },
        ],
        "extensions": [".ad1"],
        "links": [
            (
                "pcbje/pyad1 — notes and reader for the AD1 format (work in progress)",
                "https://github.com/pcbje/pyad1",
            ),
            (
                "Dissect — dissect.evidence.ad1 (AD1 reader)",
                "https://docs.dissect.tools/en/latest/api/dissect/evidence/ad1/index.html",
            ),
            (
                "PRONOM fmt/842 — AccessData Custom Content Image",
                "https://www.nationalarchives.gov.uk/PRONOM/fmt/842",
            ),
            (
                "PRONOM fmt/843 — AccessData Custom Content Image (Encrypted)",
                "https://www.nationalarchives.gov.uk/PRONOM/fmt/843",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "Apple Unified Log (tracev3)",
        "short_name": "tracev3",
        "category": "log",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Binary log chunk format used by Apple's Unified Logging System. "
            "Individual .tracev3 files are stored under "
            "/private/var/db/diagnostics/ in Persist/, Special/, Signpost/, "
            "and HighVolume/ subdirectories. "
            "Each file contains compressed, timestamped log entries referencing "
            "format strings via uuidtext/ catalogs and the Dyld Shared Cache (DSC). "
            "Cannot be parsed in isolation — requires companion uuidtext/, timesync/, "
            "and DSC directories for full string resolution and timestamp anchoring. "
            "Identified by the magic bytes 0x0C 0x10 0x00 0x00 at offset 0. "
            "In crush, the logarchive viewer assembles these files automatically "
            "from iOS full-filesystem acquisitions into a parseable bundle. "
            "See the Apple Unified Log Archive (logarchive) entry for full "
            "forensic context and artifact categories.",
            "Apple Unified Log (tracev3)",
        ),
        "platforms": ["iOS", "macOS"],
        "parser_class": "UnifiedLogConverter",
        "magic": [
            {
                "offset": 0,
                "value": b"\x0c\x10\x00\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "tracev3 file magic",
                    "Apple Unified Log (tracev3)",
                ),
            }
        ],
        "extensions": [".tracev3"],
        "links": [
            (
                "Apple Unified Logging formats — tracev3 internals (libyal)",
                "https://github.com/libyal/dtformats/blob/main/documentation/Apple%20Unified%20Logging%20and%20Activity%20Tracing%20formats.asciidoc",
            ),
            (
                "Mandiant macos-UnifiedLogs parser",
                "https://github.com/mandiant/macos-UnifiedLogs",
            ),
            (
                "iOS Unified Logs research (ios-unifiedlogs.com)",
                "https://www.ios-unifiedlogs.com/",
            ),
            (
                "Thesis Friday — Unified Log analysis series (Tim Korver)",
                "https://thesisfriday.com/",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "XML Document",
        "short_name": "XML",
        "category": "serialization",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Human-readable markup format used pervasively for configuration, "
            "data exchange, and structured documents. "
            "Key forensic XML files on Android: "
            "AndroidManifest.xml (decoded from APK via apktool/jadx) — declares "
            "package name, version, permissions, exported components, intent filters, "
            "and allowBackup flag; critical for app capability assessment and malware analysis. "
            "packages.xml (/data/system/) — lists all installed packages with granted "
            "permissions, installer source (com.android.vending = Play Store vs sideloaded), "
            "and UID assignments. "
            "runtime-permissions.xml and roles.xml — dangerous permissions granted at runtime "
            "and default app assignments (Android 10+). "
            "SharedPreferences files (/data/data/<package>/shared_prefs/*.xml) — "
            "app configuration and user state, sometimes containing credentials or tokens. "
            "On iOS/macOS: XML plists (see Property List entry). "
            "In Office documents: OOXML internals (.docx/.xlsx/.pptx are ZIP+XML). "
            "No meaningful magic beyond the XML declaration '<?xml' at offset 0.",
            "XML Document",
        ),
        "platforms": ["iOS", "macOS", "Android", "Windows", "Linux"],
        "parser_class": "XmlParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\x3c\x3f\x78\x6d\x6c",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "XML declaration ('<?xml')",
                    "XML Document",
                ),
            }
        ],
        "extensions": [".xml"],
        "links": [
            (
                "XML specification (W3C)",
                "https://www.w3.org/TR/xml/",
            ),
            (
                "AndroidManifest.xml forensics — permissions and components",
                "https://greaterinternetfreedom.org/course/mobile-forensic-analysis-a-case-study-walkthrough-part-03-application-analysis-a-static-approach/",
            ),
            (
                "Android roles and permissions XML files (D20 Forensics)",
                "https://blog.d204n6.com/2021/01/android-roles-and-permissions-android.html",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "ZIP Archive",
        "short_name": "ZIP",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Ubiquitous archive format and basis for many higher-level formats: "
            "APK (Android apps), IPA (iOS apps), DOCX/XLSX/PPTX (Office Open XML), "
            "JAR (Java), and many others are ZIP archives with specific internal structures. "
            "Dual-directory structure: Local File Headers precede each entry's data, "
            "Central Directory at end-of-file is the authoritative index — "
            "discrepancies between them can indicate tampering, polyglot files, or malware. "
            "EOCD (End of Central Directory) comment field may contain hidden data, "
            "tracker IDs, or malware markers — scan the last 64KB for the EOCD magic. "
            "Timestamps use DOS date/time format: 2-second precision, local time, "
            "no timezone information — unreliable for precise forensic timeline. "
            "APK-specific: APK Signing Block v2+ inserts between the last Local File Header "
            "and Central Directory — presence indicates modern Android signing. "
            "ZIP structure variation (creator OS, compressor version, extra fields) "
            "can fingerprint the tool or OS used to create the archive. "
            "Encryption: ZipCrypto (legacy, weak — known-plaintext attack possible) "
            "or WinZip AES-256 (strong). "
            "Standard ZIP limited to 4GB — ZIP64 extension required for larger archives.",
            "ZIP Archive",
        ),
        "platforms": ["iOS", "macOS", "Android", "Windows", "Linux"],
        "parser_class": "ZipVFS",
        "magic": [
            {
                "offset": 0,
                "value": b"\x50\x4b\x03\x04",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ZIP Local File Header signature ('PK\\x03\\x04')",
                    "ZIP Archive",
                ),
            }
        ],
        "extensions": [".zip", ".apk", ".ipa", ".jar", ".docx", ".xlsx", ".pptx"],
        "links": [
            (
                "ZIP format specification (PKWARE APPNOTE)",
                "https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT",
            ),
            (
                "ZIP format overview (Wikipedia)",
                "https://en.wikipedia.org/wiki/ZIP_(file_format)",
            ),
            (
                "ZIP fingerprinting for provenance analysis (ScienceDirect)",
                "https://www.sciencedirect.com/science/article/abs/pii/S266628172100189X",
            ),
            (
                "APK is no longer a standard ZIP — APK Signing Block (Fortinet)",
                "https://www.fortinet.com/blog/threat-research/an-android-package-is-no-longer-a-zip",
            ),
            (
                "ForensicsWiki — ZIP format",
                "https://forensics.wiki/zip/",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "7-Zip Archive",
        "short_name": "7Z",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "General-purpose archive format with high compression ratios (LZMA/LZMA2), "
            "increasingly seen as a container for forensic tool output and exfiltrated "
            "data due to strong optional AES-256 encryption of both file contents and, "
            "with header encryption enabled, the file listing itself — an encrypted-header "
            "7z gives no visibility into archive contents (names, sizes, timestamps) "
            "without the password. "
            "Solid compression (default) groups multiple files into shared compression "
            "blocks, meaning a single corrupted block can affect the recoverability of "
            "several unrelated files at once — a mitigating vs. ZIP's per-file compression. "
            "Seen in the wild bundling malware droppers (compression ratio + optional "
            "encryption both help evade signature-based and content-inspection scanning), "
            "as well as legitimate acquisition tool exports.",
            "7-Zip Archive",
        ),
        "platforms": ["Windows", "Linux", "macOS", "Android"],
        "parser_class": "SevenZipVFS",
        "magic": [
            {
                "offset": 0,
                "value": b"\x37\x7a\xbc\xaf\x27\x1c",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "7z signature",
                    "7-Zip Archive",
                ),
            }
        ],
        "extensions": [".7z"],
        "links": [
            (
                "7z format specification (7-Zip)",
                "https://www.7-zip.org/7z.html",
            ),
            (
                "7z format overview (Wikipedia)",
                "https://en.wikipedia.org/wiki/7z",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "Apple Keychain",
        "short_name": "Keychain",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Apple's password management system storing credentials, private keys, "
            "certificates, Wi-Fi passwords, payment data, and secure notes. "
            "On iOS, implemented as a single SQLite database at "
            "/private/var/Keychains/keychain-2.db — the file is unencrypted "
            "but individual records have their acct, data, and svce fields "
            "encrypted with AES-256-GCM using per-row keys protected by the Secure Enclave. "
            "Records contain: account name (acct), service (svce), server, "
            "access group (agrp — identifies the owning app), protection class, "
            "and the encrypted secret (data). "
            "On macOS: Login Keychain (~/Library/Keychains/login.keychain-db), "
            "System Keychain (/Library/Keychains/), and "
            "Local Items/iCloud Keychain (keychain-2.db + user.kb keybag). "
            "If iCloud Keychain sync is enabled, keychain-2.db may contain "
            "credentials from all the user's Apple devices. "
            "Decryption on 64-bit devices requires either a jailbroken device, "
            "a known passcode, or specialized forensic tools (Elcomsoft EIFT, GrayKey). "
            "32-bit devices (pre-iPhone 6) allow offline decryption with extracted class keys.",
            "Apple Keychain",
        ),
        "platforms": ["iOS", "macOS"],
        "parser_class": "SQLiteParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\x53\x51\x4c\x69\x74\x65\x20\x66\x6f\x72\x6d\x61\x74\x20\x33\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "SQLite magic — keychain-2.db is a standard SQLite database",
                    "Apple Keychain",
                ),
            }
        ],
        "extensions": [".db"],
        "links": [
            (
                "Apple keychain data protection (Apple Security Guide)",
                "https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web",
            ),
            (
                "Extracting and decrypting iOS Keychain (ElcomSoft / DFIR Review)",
                "https://dfir.pubpub.org/pub/gqqxl93l",
            ),
            (
                "Deep dive into Apple Keychain decryption (Passware)",
                "https://blog.passware.com/a-deep-dive-into-apple-keychain-decryption/",
            ),
        ],
        "status": "reviewed",
    },

    {
        "name": "Android Keystore",
        "short_name": "Keystore",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Android's credential and key storage system. Two distinct layers: "
            "(1) App-level keystore files — BKS (Bouncy Castle KeyStore) or PKCS#12/PFX "
            "files bundled in APKs for certificate pinning and SSL. "
            "BKS files contain certificates, private keys, and trust anchors; "
            "their passwords are frequently hardcoded in app code. "
            "(2) System Keystore — hardware-backed key storage via the Keymaster/StrongBox "
            "TEE (Trusted Execution Environment), not directly accessible as a file. "
            "App keystore files (.bks, .keystore, .jks, .p12, .pfx) are "
            "found bundled in APK assets/ or res/raw/ directories. "
            "BKS files identified by proprietary Bouncy Castle magic; "
            "JKS by 0xFEEDFEED; PKCS#12 by 0x30 (ASN.1 SEQUENCE). "
            "JKS format is weakly protected and passwords are brute-forceable. "
            "Hardcoded keystore passwords in decompiled DEX are a common "
            "finding in mobile app security assessments.",
            "Android Keystore",
        ),
        "platforms": ["Android"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"\xfe\xed\xfe\xed",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "JKS (Java KeyStore) magic",
                    "Android Keystore",
                ),
            },
            {
                "offset": 0,
                "value": b"\x30",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "PKCS#12/PFX — ASN.1 SEQUENCE tag",
                    "Android Keystore",
                ),
            },
        ],
        "extensions": [".keystore", ".jks", ".bks", ".p12", ".pfx"],
        "links": [
            (
                "Android Keystore system (Android developer docs)",
                "https://developer.android.com/privacy-and-security/keystore",
            ),
            (
                "PKCS#12 format overview (Wikipedia)",
                "https://en.wikipedia.org/wiki/PKCS_12",
            ),
            (
                "Insecurity of Android keystores — brute-force of JKS (NDSS 2018)",
                "https://www.ndss-symposium.org/wp-content/uploads/2018/02/ndss2018_02B-1_Focardi_paper.pdf",
            ),
        ],
        "status": "reviewed",
    },

    {
        "name": "iOS Backup (iTunes/Finder)",
        "short_name": "iOS Backup",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Local iOS device backup created by iTunes (Windows/older macOS) or "
            "Finder (macOS 10.15+). Stored at: "
            "Windows: %APPDATA%\\Apple Computer\\MobileSync\\Backup\\{UDID}\\ "
            "macOS: ~/Library/Application Support/MobileSync/Backup/{UDID}\\ "
            "Structure: 256 subdirectories (00-ff) containing files named by "
            "SHA-1 hash of domain+'-'+relativePath — no file extensions, no original filenames. "
            "Four key metadata files: "
            "Info.plist (device info, installed apps, last backup date, iTunes version), "
            "Manifest.plist (backup keybag, encryption flag, WasPasscodeSet, app list), "
            "Status.plist (backup state, creation start date), "
            "Manifest.db (SQLite index mapping fileIDs to domain/relativePath/metadata). "
            "Since iOS 10.2, Manifest.db is ALWAYS KeyBag/AES-encrypted (ManifestKey "
            "in Manifest.plist), independent of whether a backup password is set — "
            "unencrypted backups just use an empty-password-derived KeyBag key, so "
            "no prompt is needed to read the file index. Individual file CONTENT is "
            "only additionally per-file encrypted (protection-class keys from the "
            "same KeyBag) when IsEncrypted=true (a real backup password was set); "
            "unencrypted backups leave file contents in the clear. "
            "Encryption password required for decryption of encrypted-backup file "
            "contents — not tied to device passcode. "
            "Keychain data (keychain-backup.plist) only present in encrypted backups. "
            "Manifest.plist's WasPasscodeSet and RestoreApplications may reveal "
            "jailbreak history even after device restoration.",
            "iOS Backup (iTunes/Finder)",
        ),
        "platforms": ["iOS"],
        "parser_class": "ITunesBackupVFS",
        "magic": [],
        "extensions": [],
        "links": [
            (
                "iTunes Backup format internals (The Apple Wiki)",
                "https://theapplewiki.com/wiki/ITunes_Backup",
            ),
            (
                "iPhone backup forensics 101 (Kinga Kieczkowska / OBTS v7)",
                "https://kieczkowska.wordpress.com/2025/04/29/iphone-backup-forensics-101/",
            ),
            (
                "iOS backup encryption and data protection (Medium / VulBusters)",
                "https://medium.com/@vulbusters/ios-data-protection-on-backup-6f53d588c830",
            ),
        ],
        "status": "reviewed",
    },

    {
        "name": "Windows Prefetch",
        "short_name": "Prefetch",
        "category": "log",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Windows execution evidence artifacts created when an application is run "
            "for the first time from a specific path. "
            "Stored under C:\\Windows\\Prefetch\\ as {EXECUTABLE}-{HASH}.pf, "
            "where HASH is derived from the executable's full path and command line. "
            "Enabled by default on Windows workstations; disabled on Windows Server. "
            "Each .pf file contains: executable name, run count, "
            "up to 8 last execution timestamps (Windows 8+ — earlier versions store 1), "
            "list of files and directories accessed in the first 10 seconds of execution, "
            "and volume serial number and creation timestamp. "
            "Note: actual execution time is approximately 10 seconds before the .pf "
            "file's last modification timestamp. "
            "Forensically: proves execution even if the original binary was deleted, "
            "reveals path from which malware was executed, "
            "detects anti-forensic tools (CCleaner, SDelete prefetch entries). "
            "Multiple .pf files for the same executable indicate execution from "
            "different paths. "
            "Post-Windows 8.1: files use MAM compression requiring specialized parsing. "
            "Format reversed by Joachim Metz (libscca); no official public specification.",
            "Windows Prefetch",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"\x11\x00\x00\x00\x53\x43\x43\x41",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Prefetch v17 header (Windows XP/2003)",
                    "Windows Prefetch",
                ),
            },
            {
                "offset": 0,
                "value": b"\x17\x00\x00\x00\x53\x43\x43\x41",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Prefetch v23 header (Windows Vista/7)",
                    "Windows Prefetch",
                ),
            },
            {
                "offset": 0,
                "value": b"\x1a\x00\x00\x00\x53\x43\x43\x41",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Prefetch v26 header (Windows 8.1)",
                    "Windows Prefetch",
                ),
            },
            {
                "offset": 0,
                "value": b"\x1e\x00\x00\x00\x53\x43\x43\x41",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Prefetch v30 header (Windows 10)",
                    "Windows Prefetch",
                ),
            },
        ],
        "extensions": [".pf"],
        "links": [
            (
                "Windows Prefetch File format spec (libscca — Joachim Metz)",
                "https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc",
            ),
            (
                "Prefetch forensics — execution evidence (Magnet Forensics)",
                "https://www.magnetforensics.com/blog/forensic-analysis-of-prefetch-files-in-windows/",
            ),
            (
                "PECmd — Prefetch parser (Eric Zimmerman)",
                "https://ericzimmerman.github.io/#!index.md",
            ),
            (
                "ForensicsWiki — Prefetch",
                "https://forensics.wiki/prefetch/",
            ),
        ],
        "status": "reviewed",
    },

    {
        "name": "Gzip Compressed Data",
        "short_name": "gzip",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Single-file lossless compression format using DEFLATE (RFC 1951), "
            "defined in RFC 1952. Identified by magic bytes 0x1F 0x8B at offset 0. "
            "10-byte header contains: compression method (CM=8 for DEFLATE), "
            "flags (FNAME, FCOMMENT, FEXTRA, FHCRC), "
            "mtime (4-byte Unix timestamp of original file — forensically significant, "
            "may reveal when the source file was last modified), "
            "OS byte (identifies the OS that created the file: 0=FAT, 3=Unix, 7=Mac, 11=NTFS), "
            "and optional original filename (FNAME flag). "
            "8-byte footer: CRC-32 of uncompressed data and original file size. "
            "Forensically common as: Android OTA payload.bin wrapper, "
            "Linux log rotation (.gz), iOS/macOS system files, "
            "network traffic content encoding, and database backups. "
            "Multiple gzip members can be concatenated in a single .gz file. "
            "OS byte and mtime can reveal the origin platform and source file age.",
            "Gzip Compressed Data",
        ),
        "platforms": ["Android", "Linux", "iOS", "macOS", "Windows"],
        "parser_class": "GzipVFS",
        "magic": [
            {
                "offset": 0,
                "value": b"\x1f\x8b",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Gzip magic number (ID1=0x1F, ID2=0x8B)",
                    "Gzip Compressed Data",
                ),
            }
        ],
        "extensions": [".gz", ".tgz"],
        "links": [
            (
                "GZIP file format specification (RFC 1952)",
                "https://www.rfc-editor.org/rfc/rfc1952.html",
            ),
            (
                "Gzip format overview (Wikipedia)",
                "https://en.wikipedia.org/wiki/Gzip",
            ),
            (
                "Gzip format (Library of Congress)",
                "https://www.loc.gov/preservation/digital/formats/fdd/fdd000599.shtml",
            ),
            (
                "Gzip (ForensicsWiki)",
                "https://forensics.wiki/gzip/",
            ),
        ],
        "status": "reviewed",
    },
    {
        "name": "Raw Disk Image",
        "short_name": "Raw",
        "category": "disk_image",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "A sector-for-sector copy of a disk, partition or flash chip with no container "
            "around it: no header, no metadata, no hash, no compression. Often split into "
            "numbered segments (.001, .002, …) that join into one stream. Everything the "
            "device held is in it, including unallocated space and slack; how and when it "
            "was acquired is only recorded outside the image.",
            "Raw Disk Image",
        ),
        "platforms": ["Windows", "macOS", "Linux", "Android", "iOS"],
        "parser_class": "RawImageVFS",
        "magic": [],
        "extensions": [".dd", ".raw", ".img", ".001"],
        "links": [
            (
                "ForensicsWiki — Raw image format",
                "https://forensics.wiki/raw_image_format/",
            ),
            (
                "abrignoni/qnxprobe — partition and filesystem reader",
                "https://github.com/abrignoni/qnxprobe",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Master Boot Record (MBR) Partition Table",
        "short_name": "MBR",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The classic PC partition scheme in the first sector of a disk: boot code, up "
            "to four primary partition entries and the 0x55AA boot signature. Further "
            "partitions chain through extended boot records. Each entry carries a type byte "
            "and a start and length in sectors; space outside every entry (before the "
            "first partition, between partitions, after the last) can hold remnants of "
            "earlier layouts. A GPT disk keeps a protective MBR with a single 0xEE entry.",
            "Master Boot Record (MBR) Partition Table",
        ),
        "platforms": ["Windows", "Linux", "macOS", "Android"],
        "parser_class": "RawImageVFS",
        "magic": [
            {
                "offset": 510,
                "value": b"U\xaa",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Boot signature 0x55AA at the end of sector 0",
                    "Master Boot Record (MBR) Partition Table",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "Master Boot Record (MBR) partition table format (libyal/libvsmbr)",
                "https://github.com/libyal/libvsmbr/blob/main/documentation/Master%20Boot%20Record%20(MBR)%20partition%20table%20format.asciidoc",
            ),
            (
                "ForensicsWiki — Master boot record",
                "https://forensics.wiki/master_boot_record/",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "GUID Partition Table (GPT)",
        "short_name": "GPT",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The UEFI partition scheme: a header in the second logical block, a partition "
            "entry array with a type GUID, unique GUID, start and end LBA and a UTF-16 name "
            "per partition, and a backup copy of both at the end of the disk. Both copies "
            "carry CRC32 checksums, so a primary and backup that disagree show the table "
            "was changed or damaged. Used by current Windows, macOS, Linux and Android "
            "devices; on 4Kn disks the header sits at byte 4096 instead of 512.",
            "GUID Partition Table (GPT)",
        ),
        "platforms": ["Windows", "macOS", "Linux", "Android"],
        "parser_class": "RawImageVFS",
        "magic": [
            {
                "offset": 512,
                "value": b"EFI PART",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "GPT header signature in LBA 1 (512-byte sectors)",
                    "GUID Partition Table (GPT)",
                ),
            },
            {
                "offset": 4096,
                "value": b"EFI PART",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "GPT header signature in LBA 1 (4096-byte sectors)",
                    "GUID Partition Table (GPT)",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "GUID Partition Table (GPT) format (libyal/libvsgpt)",
                "https://github.com/libyal/libvsgpt/blob/main/documentation/GUID%20Partition%20Table%20(GPT)%20format.asciidoc",
            ),
            (
                "ForensicsWiki — GPT",
                "https://forensics.wiki/gpt/",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Apple File System (APFS)",
        "short_name": "APFS",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Apple's copy-on-write filesystem on iOS 10.3+ and macOS 10.13+. A container "
            "holds several volumes sharing one space pool; metadata is kept in B-trees "
            "addressed through an object map, and every change is written to new blocks "
            "under a new transaction ID. Older checkpoints and superseded tree nodes can "
            "therefore remain on disk. Volumes may be encrypted per volume or per file "
            "(Data Protection on iOS) and can carry snapshots. Timestamps are nanoseconds "
            "since 1970 UTC.",
            "Apple File System (APFS)",
        ),
        "platforms": ["iOS", "macOS"],
        "parser_class": "RawImageVFS",
        "magic": [
            {
                "offset": 32,
                "value": b"NXSB",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Container superblock magic 'NXSB' (block 0)",
                    "Apple File System (APFS)",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "Apple File System Reference (Apple)",
                "https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf",
            ),
            (
                "Apple File System (APFS) — format documentation (libyal/libfsapfs)",
                "https://github.com/libyal/libfsapfs/blob/main/documentation/Apple%20File%20System%20(APFS).asciidoc",
            ),
            (
                "Mobile Forensics – The File Format Handbook: APFS (Springer, 2022)",
                "https://doi.org/10.1007/978-3-030-98467-0_1",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "HFS Plus / HFSX",
        "short_name": "HFS+",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Apple's filesystem before APFS (Mac OS 8.1 to macOS 10.12, still on many "
            "external drives and older Time Machine disks). Files and folders are records "
            "in a catalog B-tree, with an extents overflow file and an attributes file for "
            "extended attributes and compressed (decmpfs) data. HFSX is the case-sensitive "
            "variant. An optional journal records metadata changes. Timestamps are seconds "
            "since 1904, local time on the volume header's creation date and UTC elsewhere.",
            "HFS Plus / HFSX",
        ),
        "platforms": ["macOS", "iOS"],
        "parser_class": "RawImageVFS",
        "magic": [
            {
                "offset": 1024,
                "value": b"H+\x00\x04",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "HFS Plus volume header ('H+', version 4)",
                    "HFS Plus / HFSX",
                ),
            },
            {
                "offset": 1024,
                "value": b"HX\x00\x05",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "HFSX volume header ('HX', version 5)",
                    "HFS Plus / HFSX",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "Technical Note TN1150: HFS Plus Volume Format (Apple)",
                "https://developer.apple.com/library/archive/technotes/tn/tn1150.html",
            ),
            (
                "Hierarchical File System (HFS) — format documentation (libyal/libfshfs)",
                "https://github.com/libyal/libfshfs/blob/main/documentation/Hierarchical%20File%20System%20(HFS).asciidoc",
            ),
            (
                "ForensicsWiki — HFS+",
                "https://forensics.wiki/hfs+/",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "NTFS",
        "short_name": "NTFS",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The Windows filesystem. Every file and directory is an entry in the Master "
            "File Table ($MFT) with attributes such as $STANDARD_INFORMATION and "
            "$FILE_NAME, each holding its own set of four timestamps (100 ns since 1601 "
            "UTC). Small files are stored resident inside the MFT entry. Metadata files "
            "record history: $LogFile (transaction log), $UsnJrnl:$J (change journal), "
            "$Secure, $Bitmap. Alternate data streams (e.g. Zone.Identifier) and Volume "
            "Shadow Copies live on the same volume.",
            "NTFS",
        ),
        "platforms": ["Windows"],
        "parser_class": "RawImageVFS",
        "magic": [
            {
                "offset": 3,
                "value": b"NTFS    ",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "OEM identifier 'NTFS    ' in the boot sector",
                    "NTFS",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "New Technologies File System (NTFS) — format documentation (libyal/libfsntfs)",
                "https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc",
            ),
            (
                "ForensicsWiki — NTFS",
                "https://forensics.wiki/ntfs/",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "FAT32",
        "short_name": "FAT32",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The 32-bit File Allocation Table filesystem, used on USB sticks, SD cards, "
            "camera media, EFI system partitions and older Android/iOS-compatible storage. "
            "Directory entries hold an 8.3 name (plus long-name entries), attributes, size, "
            "first cluster and creation/modification/access times in local time with "
            "2-second (modification) and day (access) resolution. A deleted entry keeps "
            "most of its fields with the first name byte set to 0xE5.",
            "FAT32",
        ),
        "platforms": ["Windows", "macOS", "Linux", "Android"],
        "parser_class": "RawImageVFS",
        "magic": [
            {
                "offset": 82,
                "value": b"FAT32   ",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Filesystem type string 'FAT32   ' in the boot sector",
                    "FAT32",
                ),
            },
            {
                "offset": 510,
                "value": b"U\xaa",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Boot signature 0x55AA",
                    "FAT32",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "File Allocation Table (FAT) format (libyal/libfsfat)",
                "https://github.com/libyal/libfsfat/blob/main/documentation/File%20Allocation%20Table%20(FAT)%20format.asciidoc",
            ),
            (
                "ForensicsWiki — FAT",
                "https://forensics.wiki/fat/",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "FAT12 / FAT16",
        "short_name": "FAT12/16",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The 12- and 16-bit File Allocation Table variants, found on small volumes, old "
            "media, floppy images and some embedded devices. Directory entries have the "
            "same layout as on FAT32. The boot sector's filesystem-type string is "
            "informational only; per the specification the FAT type is decided by the "
            "cluster count.",
            "FAT12 / FAT16",
        ),
        "platforms": ["Windows", "Linux"],
        "parser_class": None,
        "magic": [
            {
                "offset": 54,
                "value": b"FAT12   ",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Filesystem type string 'FAT12   ' (informational field)",
                    "FAT12 / FAT16",
                ),
            },
            {
                "offset": 54,
                "value": b"FAT16   ",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Filesystem type string 'FAT16   ' (informational field)",
                    "FAT12 / FAT16",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "File Allocation Table (FAT) format (libyal/libfsfat)",
                "https://github.com/libyal/libfsfat/blob/main/documentation/File%20Allocation%20Table%20(FAT)%20format.asciidoc",
            ),
            (
                "ForensicsWiki — FAT",
                "https://forensics.wiki/fat/",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "exFAT",
        "short_name": "exFAT",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Microsoft's Extended FAT for flash media: SDXC cards, large USB drives and "
            "cameras. Files are described by entry sets (file, stream extension and file "
            "name entries) with timestamps that carry 10 ms resolution and a UTC offset. "
            "Contiguous files may have no FAT chain at all. A deleted entry set keeps its "
            "data with the in-use bit cleared.",
            "exFAT",
        ),
        "platforms": ["Windows", "macOS", "Linux", "Android"],
        "parser_class": "RawImageVFS",
        "magic": [
            {
                "offset": 3,
                "value": b"EXFAT   ",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Filesystem name 'EXFAT   ' in the boot sector",
                    "exFAT",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "exFAT File System Specification (Microsoft)",
                "https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification",
            ),
            (
                "File Allocation Table (FAT) format (libyal/libfsfat)",
                "https://github.com/libyal/libfsfat/blob/main/documentation/File%20Allocation%20Table%20(FAT)%20format.asciidoc",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "ext2 / ext3 / ext4",
        "short_name": "ext",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The Linux extended filesystem family, also the data and system partitions of "
            "many Android devices. Files are inodes with up to four timestamps (ext4: "
            "nanosecond resolution and creation time), block pointers or extents, and "
            "directory entries that link names to inode numbers. ext3/ext4 keep a journal "
            "whose older copies of metadata blocks can still describe deleted or changed "
            "files. The superblock records last mount path, mount and write times.",
            "ext2 / ext3 / ext4",
        ),
        "platforms": ["Linux", "Android"],
        "parser_class": "RawImageVFS",
        "magic": [
            {
                "offset": 1080,
                "value": b"S\xef",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Superblock magic 0xEF53 (superblock at byte 1024)",
                    "ext2 / ext3 / ext4",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "ext4 Data Structures and Algorithms (Linux kernel documentation)",
                "https://docs.kernel.org/filesystems/ext4/index.html",
            ),
            (
                "Extended File System (EXT) — format documentation (libyal/libfsext)",
                "https://github.com/libyal/libfsext/blob/main/documentation/Extended%20File%20System%20(EXT).asciidoc",
            ),
            (
                "ForensicsWiki — Extended file system (ext)",
                "https://forensics.wiki/extended_file_system_(ext)/",
            ),
            (
                "Mobile Forensics – The File Format Handbook: Ext4 (Springer, 2022)",
                "https://doi.org/10.1007/978-3-030-98467-0_2",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Flash-Friendly File System (F2FS)",
        "short_name": "F2FS",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "A log-structured filesystem for NAND flash, used as the userdata partition on "
            "many Android devices. Data and nodes are written to new segments rather than "
            "in place, and checkpoints alternate between two copies, so earlier versions of "
            "files and metadata can remain in segments that have not yet been cleaned. "
            "Inodes carry access, change, modification and (optionally) creation times.",
            "Flash-Friendly File System (F2FS)",
        ),
        "platforms": ["Android", "Linux"],
        "parser_class": "RawImageVFS",
        "magic": [
            {
                "offset": 1024,
                "value": b"\x10 \xf5\xf2",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Superblock magic 0xF2F52010 (byte 1024)",
                    "Flash-Friendly File System (F2FS)",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "Flash-Friendly File System (F2FS) (Linux kernel documentation)",
                "https://docs.kernel.org/filesystems/f2fs.html",
            ),
            (
                "Mobile Forensics – The File Format Handbook: F2FS (Springer, 2022)",
                "https://doi.org/10.1007/978-3-030-98467-0_3",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "QNX6 Filesystem",
        "short_name": "QNX6",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The QNX Neutrino power-safe filesystem, used in vehicle infotainment and "
            "telematics units and other embedded systems. Two superblocks alternate; the "
            "one with the higher serial number is current, and the other describes the "
            "previous state of the filesystem. Inodes and directory blocks are addressed "
            "through block pointer trees.",
            "QNX6 Filesystem",
        ),
        "platforms": ["QNX"],
        "parser_class": "RawImageVFS",
        "magic": [
            {
                "offset": 8192,
                "value": b"\x22\x11\x19h",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Superblock magic 0x68191122 after the 8 KiB boot block",
                    "QNX6 Filesystem",
                ),
            },
            {
                "offset": 0,
                "value": b"\x22\x11\x19h",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Superblock magic 0x68191122 at byte 0 (layouts without boot block)",
                    "QNX6 Filesystem",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "The QNX6 Filesystem (Linux kernel documentation)",
                "https://docs.kernel.org/filesystems/qnx6.html",
            ),
            (
                "Mobile Forensics – The File Format Handbook: QNX6 (Springer, 2022)",
                "https://doi.org/10.1007/978-3-030-98467-0_4",
            ),
            (
                "qnxmount — QNX filesystem parsers (Netherlands Forensic Institute)",
                "https://github.com/NetherlandsForensicInstitute/qnxmount",
            ),
            (
                "abrignoni/qnxprobe — QNX and embedded filesystem reader",
                "https://github.com/abrignoni/qnxprobe",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "QNX4 Filesystem",
        "short_name": "QNX4",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The older QNX filesystem, still found in embedded and automotive devices. It "
            "has no magic number: a volume is recognised by its root directory entry and "
            "the /.bitmap and /.inodes files. Directory entries hold the file's attributes "
            "directly; files with several names or long names use the separate .inodes "
            "file.",
            "QNX4 Filesystem",
        ),
        "platforms": ["QNX"],
        "parser_class": "RawImageVFS",
        "magic": [],
        "extensions": [],
        "links": [
            (
                "abrignoni/qnxprobe — QNX and embedded filesystem reader",
                "https://github.com/abrignoni/qnxprobe",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "QNX Image Filesystem (IFS)",
        "short_name": "QNX IFS",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "A QNX boot image: a startup header and startup code followed by a read-only "
            "image filesystem holding the kernel, drivers, libraries and the build script "
            "the system boots with. The image filesystem may be compressed. Shows what "
            "software and configuration a QNX device was built to start.",
            "QNX Image Filesystem (IFS)",
        ),
        "platforms": ["QNX"],
        "parser_class": "RawImageVFS",
        "magic": [
            {
                "offset": 0,
                "value": b"\xeb~\xff\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Startup header signature 0x00FF7EEB",
                    "QNX Image Filesystem (IFS)",
                ),
            },
        ],
        "extensions": [".ifs"],
        "links": [
            (
                "abrignoni/qnxprobe — QNX and embedded filesystem reader",
                "https://github.com/abrignoni/qnxprobe",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "QNX Embedded Transaction Filesystem (ETFS)",
        "short_name": "ETFS",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "A transaction-based QNX filesystem for NAND flash. Every write is a new "
            "transaction with a sequence number in the page's spare area; the current state "
            "is rebuilt by replaying them, so pages holding superseded versions of files "
            "can remain until they are reclaimed. It has no magic number: it is recognised "
            "by its reserved files (.filetable, .badblks, .counts) at fixed file IDs.",
            "QNX Embedded Transaction Filesystem (ETFS)",
        ),
        "platforms": ["QNX"],
        "parser_class": "RawImageVFS",
        "magic": [],
        "extensions": [],
        "links": [
            (
                "qnxmount — QNX filesystem parsers (Netherlands Forensic Institute)",
                "https://github.com/NetherlandsForensicInstitute/qnxmount",
            ),
            (
                "abrignoni/qnxprobe — QNX and embedded filesystem reader",
                "https://github.com/abrignoni/qnxprobe",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "QNX Embedded Flash Filesystem (EFS / F3S)",
        "short_name": "EFS",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The QNX flash filesystem for NOR flash (fs-flash3). The flash is divided into "
            "units holding extents; changes are copy-on-write, with a pointer from an old "
            "extent to the one that supersedes it, so older versions can remain readable. "
            "The partition is found by its boot record containing the text 'QSSL_F3S'.",
            "QNX Embedded Flash Filesystem (EFS / F3S)",
        ),
        "platforms": ["QNX"],
        "parser_class": "RawImageVFS",
        "magic": [
            {
                "offset": None,
                "value": b"QSSL_F3S",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Boot record signature 'QSSL_F3S' (offset depends on the unit layout)",
                    "QNX Embedded Flash Filesystem (EFS / F3S)",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "qnxmount — QNX filesystem parsers (Netherlands Forensic Institute)",
                "https://github.com/NetherlandsForensicInstitute/qnxmount",
            ),
            (
                "abrignoni/qnxprobe — QNX and embedded filesystem reader",
                "https://github.com/abrignoni/qnxprobe",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "SquashFS",
        "short_name": "SquashFS",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "A compressed read-only filesystem used for firmware images of routers, IoT "
            "devices, set-top boxes and Linux live systems. Inode and directory tables and "
            "file data are compressed in blocks; files are stored once and cannot be "
            "changed in place, so the image shows the firmware as built. Timestamps are "
            "seconds since 1970.",
            "SquashFS",
        ),
        "platforms": ["Linux"],
        "parser_class": "RawImageVFS",
        "magic": [
            {
                "offset": 0,
                "value": b"hsqs",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Superblock magic 'hsqs' (little-endian)",
                    "SquashFS",
                ),
            },
            {
                "offset": 0,
                "value": b"sqsh",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Superblock magic 'sqsh' (big-endian)",
                    "SquashFS",
                ),
            },
        ],
        "extensions": [".squashfs", ".sqsh"],
        "links": [
            (
                "Squashfs 4.0 Filesystem (Linux kernel documentation)",
                "https://docs.kernel.org/filesystems/squashfs.html",
            ),
            (
                "Squashfs binary format (dr-emann)",
                "https://dr-emann.github.io/squashfs/",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "JFFS2 (Journalling Flash File System v2)",
        "short_name": "JFFS2",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "A log-structured filesystem for raw NOR/NAND flash in embedded Linux devices. "
            "The whole filesystem is a sequence of nodes, each with a version number; the "
            "newest node for each inode wins, so older nodes holding earlier file contents "
            "and names can remain on the flash until garbage collection erases the block.",
            "JFFS2 (Journalling Flash File System v2)",
        ),
        "platforms": ["Linux"],
        "parser_class": "RawImageVFS",
        "magic": [
            {
                "offset": 0,
                "value": b"\x85\x19",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Node magic 0x1985 (little-endian)",
                    "JFFS2 (Journalling Flash File System v2)",
                ),
            },
            {
                "offset": 0,
                "value": b"\x19\x85",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Node magic 0x1985 (big-endian)",
                    "JFFS2 (Journalling Flash File System v2)",
                ),
            },
        ],
        "extensions": [".jffs2"],
        "links": [
            (
                "JFFS2 documentation (Linux MTD project)",
                "http://www.linux-mtd.infradead.org/doc/jffs2.html",
            ),
            (
                "JFFS: The Journalling Flash File System (David Woodhouse, Red Hat)",
                "https://sourceware.org/jffs2/jffs2.pdf",
            ),
            (
                "ForensicsWiki — JFFS2",
                "https://forensics.wiki/jffs2/",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "UBI (Unsorted Block Images)",
        "short_name": "UBI",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "A volume layer on raw NAND flash in embedded Linux devices. Each physical "
            "eraseblock starts with an erase-counter header and a volume-ID header that "
            "maps it to a logical block of a volume; a volume table names the volumes. "
            "Eraseblocks that held earlier copies of a logical block can remain until they "
            "are erased.",
            "UBI (Unsorted Block Images)",
        ),
        "platforms": ["Linux"],
        "parser_class": "RawImageVFS",
        "magic": [
            {
                "offset": 0,
                "value": b"UBI#",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Erase-counter header magic 'UBI#'",
                    "UBI (Unsorted Block Images)",
                ),
            },
        ],
        "extensions": [".ubi"],
        "links": [
            (
                "UBI documentation (Linux MTD project)",
                "http://www.linux-mtd.infradead.org/doc/ubi.html",
            ),
            (
                "UBI — Unsorted Block Images, design paper (Linux MTD project)",
                "http://www.linux-mtd.infradead.org/doc/ubidesign/ubidesign.pdf",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "UBIFS",
        "short_name": "UBIFS",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The flash filesystem that runs on a UBI volume. Nodes are written out of place "
            "and indexed by a wandering B+ tree; a journal holds recent changes. Nodes for "
            "superseded data can remain in the volume until it is garbage-collected.",
            "UBIFS",
        ),
        "platforms": ["Linux"],
        "parser_class": "RawImageVFS",
        "magic": [
            {
                "offset": 0,
                "value": b"1\x18\x10\x06",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Node magic 0x06101831",
                    "UBIFS",
                ),
            },
        ],
        "extensions": [".ubifs"],
        "links": [
            (
                "UBIFS documentation (Linux MTD project)",
                "http://www.linux-mtd.infradead.org/doc/ubifs.html",
            ),
            (
                "UBIFS white paper (Linux MTD project)",
                "http://www.linux-mtd.infradead.org/doc/ubifs_whitepaper.pdf",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "YAFFS1 / YAFFS2",
        "short_name": "YAFFS",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Yet Another Flash File System, used on NAND flash in older Android devices and "
            "embedded systems. Each page carries tags in its spare area naming the object "
            "and chunk it belongs to and a sequence number; the newest chunk wins, so "
            "earlier versions of files can remain on the flash. It has no magic number and "
            "is recognised by its page and spare-area layout.",
            "YAFFS1 / YAFFS2",
        ),
        "platforms": ["Android", "Linux"],
        "parser_class": "RawImageVFS",
        "magic": [],
        "extensions": [".yaffs", ".yaffs2"],
        "links": [
            (
                "YAFFS (official site)",
                "https://yaffs.net/",
            ),
            (
                "ForensicsWiki — YAFFS",
                "https://forensics.wiki/yaffs/",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "BitLocker Drive Encryption",
        "short_name": "BitLocker",
        "category": "disk_image",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Windows full-volume encryption. The volume keeps a boot sector with the "
            "'-FVE-FS-' signature and three copies of the FVE metadata, which list the key "
            "protectors (TPM, PIN, password, recovery password, startup key) and when the "
            "volume was encrypted. Everything else is ciphertext; without one of the "
            "protectors' secrets the files cannot be read. BitLocker To Go protects "
            "removable drives the same way.",
            "BitLocker Drive Encryption",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 3,
                "value": b"-FVE-FS-",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "BitLocker signature '-FVE-FS-' in the volume boot sector",
                    "BitLocker Drive Encryption",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "BitLocker Drive Encryption (BDE) format (libyal/libbde)",
                "https://github.com/libyal/libbde/blob/main/documentation/BitLocker%20Drive%20Encryption%20(BDE)%20format.asciidoc",
            ),
            (
                "ForensicsWiki — BitLocker disk encryption",
                "https://forensics.wiki/bitlocker_disk_encryption/",
            ),
            (
                "BitLocker overview (Microsoft)",
                "https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "AccessData AD Encryption (ADCRYPT)",
        "short_name": "ADCRYPT",
        "category": "disk_image",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The encryption wrapper FTK Imager can put around an acquisition (raw or E01 "
            "segments). Each encrypted file starts with an 'ADCRYPT' header; the content is "
            "AES-encrypted and opened with the password or the RSA private key "
            "(certificate) chosen at acquisition time.",
            "AccessData AD Encryption (ADCRYPT)",
        ),
        "platforms": ["Windows"],
        "parser_class": "RawImageVFS",
        "magic": [
            {
                "offset": 0,
                "value": b"ADCRYPT\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "AD encryption header 'ADCRYPT'",
                    "AccessData AD Encryption (ADCRYPT)",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "abrignoni/ewfprobe — reader with AD-encryption support",
                "https://github.com/abrignoni/ewfprobe",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Cellebrite UFDR",
        "short_name": "UFDR",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The report/delivery container exported by Cellebrite Physical Analyzer. It is "
            "a ZIP archive: the extracted files are stored under files/<category>/, while "
            "the device's original paths, sizes, timestamps and hashes are kept in "
            "DbData/database.db (a PostgreSQL custom-format dump). report.xml duplicates "
            "the data in an older XML layout. Large exports may be split into several "
            "segments.",
            "Cellebrite UFDR",
        ),
        "platforms": ["Android", "iOS"],
        "parser_class": "UFDRVFS",
        "magic": [
            {
                "offset": None,
                "value": b"PK\x03\x04",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ZIP container holding report.xml and DbData/database.db",
                    "Cellebrite UFDR",
                ),
            },
        ],
        "extensions": [".ufdr"],
        "links": [
            (
                "UFDR2DIR — UFDR to original file structure (DFIR Science)",
                "https://github.com/DFIRScience/UFDR2DIR",
            ),
            (
                "pg_dump custom archive format (PostgreSQL documentation)",
                "https://www.postgresql.org/docs/current/app-pgdump.html",
            ),
            (
                "ForensicsWiki — Cellebrite",
                "https://forensics.wiki/cellebrite/",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Android logcat (text)",
        "short_name": "logcat",
        "category": "log",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Text output of Android's logcat: one line per log message with date and time "
            "(device local time, no year in the default format), PID, TID, priority, tag "
            "and message. Found in bug reports, ADB extractions and app support exports. "
            "The binary log buffers on the device are ring buffers, so a capture only "
            "reaches back as far as the buffer did.",
            "Android logcat (text)",
        ),
        "platforms": ["Android"],
        "parser_class": "LogParser",
        "magic": [],
        "extensions": [".txt", ".log"],
        "links": [
            (
                "Logcat command-line tool (Android developers)",
                "https://developer.android.com/tools/logcat",
            ),
            (
                "Understand logging (Android Open Source Project)",
                "https://source.android.com/docs/core/tests/debug/understanding-logging",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Syslog (RFC 3164 / RFC 5424)",
        "short_name": "Syslog",
        "category": "log",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Text log format of Unix-like systems and network devices: one message per line "
            "with priority, timestamp, host name, process tag and message. RFC 3164 "
            "timestamps have no year and no time zone; RFC 5424 uses full ISO 8601 "
            "timestamps with offset. Found in /var/log on Linux and in exports from "
            "routers, firewalls and appliances.",
            "Syslog (RFC 3164 / RFC 5424)",
        ),
        "platforms": ["Linux", "macOS"],
        "parser_class": "LogParser",
        "magic": [],
        "extensions": [".log"],
        "links": [
            (
                "The BSD syslog Protocol (RFC 3164)",
                "https://www.rfc-editor.org/rfc/rfc3164.html",
            ),
            (
                "The Syslog Protocol (RFC 5424)",
                "https://www.rfc-editor.org/rfc/rfc5424.html",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "SQLCipher Encrypted Database",
        "short_name": "SQLCipher",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "An SQLite database with every page AES-256 encrypted, used by messengers and "
            "other apps (Signal, WeChat, many Android apps). Even the first 16 bytes are "
            "encrypted (they hold the key-derivation salt), so the file looks random and "
            "has no signature. Each page carries an IV and an HMAC; with the right key and "
            "settings it decrypts to an ordinary SQLite database.",
            "SQLCipher Encrypted Database",
        ),
        "platforms": ["Android", "iOS", "Windows", "macOS", "Linux"],
        "parser_class": "SQLiteParser",
        "magic": [],
        "extensions": [".db", ".sqlite"],
        "links": [
            (
                "SQLCipher design — security approach and features (Zetetic)",
                "https://www.zetetic.net/sqlcipher/design/",
            ),
            (
                "SQLCipher source (Zetetic)",
                "https://github.com/sqlcipher/sqlcipher",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Windows PE Executable",
        "short_name": "PE",
        "category": "execution",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The Portable Executable format of Windows programs and libraries (.exe, .dll, "
            ".sys). An MS-DOS stub points to the PE header with the target machine, a link "
            "timestamp, section table, imports and exports; resources hold version "
            "information (company, product, original file name) and icons. An Authenticode "
            "signature, if present, names the signer. Relevant for malware analysis and for "
            "linking a binary to its origin.",
            "Windows PE Executable",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"MZ",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "MS-DOS header 'MZ' (the PE header follows at e_lfanew)",
                    "Windows PE Executable",
                ),
            },
        ],
        "extensions": [".exe", ".dll", ".sys", ".scr", ".cpl"],
        "links": [
            (
                "PE Format (Microsoft)",
                "https://learn.microsoft.com/en-us/windows/win32/debug/pe-format",
            ),
            (
                "MZ, PE-COFF executable file format (libyal/libexe)",
                "https://github.com/libyal/libexe/blob/main/documentation/Executable%20(EXE)%20file%20format.asciidoc",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Windows Shortcut (LNK)",
        "short_name": "LNK",
        "category": "execution",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Windows shell link files, created when files are opened (Recent folder, Office "
            "recent items) and inside Jump Lists. They record the target's path, size and "
            "MAC times at the moment the link was written, the volume serial number and "
            "type, network share names and often the NetBIOS name and MAC address of the "
            "machine. Evidence of files and volumes that may no longer exist.",
            "Windows Shortcut (LNK)",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Header size 0x4C and LinkCLSID {00021401-0000-0000-C000-000000000046}",
                    "Windows Shortcut (LNK)",
                ),
            },
        ],
        "extensions": [".lnk"],
        "links": [
            (
                "[MS-SHLLINK]: Shell Link (.LNK) Binary File Format (Microsoft)",
                "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943",
            ),
            (
                "Windows Shortcut File (LNK) format (libyal/liblnk)",
                "https://github.com/libyal/liblnk/blob/main/documentation/Windows%20Shortcut%20File%20(LNK)%20format.asciidoc",
            ),
            (
                "ForensicsWiki — LNK",
                "https://forensics.wiki/lnk/",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Windows Jump Lists",
        "short_name": "Jump List",
        "category": "execution",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Per-application lists of recently and frequently used items, keyed by an "
            "AppID. AutomaticDestinations-ms files are OLE compound files holding one LNK "
            "stream per item and a DestList stream with access counts, last-access times "
            "and the host name; CustomDestinations-ms files are concatenated LNK records "
            "pinned or provided by the application. They persist after the referenced files "
            "are gone.",
            "Windows Jump Lists",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": None,
                "value": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "OLE compound file signature (AutomaticDestinations-ms); "
                    "the same bytes start every OLE compound file",
                    "Windows Jump Lists",
                ),
            },
        ],
        "extensions": [".automaticdestinations-ms", ".customdestinations-ms"],
        "links": [
            (
                "Jump lists format (libyal/dtformats)",
                "https://github.com/libyal/dtformats/blob/main/documentation/Jump%20lists%20format.asciidoc",
            ),
            (
                "ForensicsWiki — Jump lists",
                "https://forensics.wiki/jump_lists/",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "OLE Compound File (CFB)",
        "short_name": "CFB",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Microsoft's Compound File Binary format: a FAT-like filesystem inside one file "
            "with storages and streams. It is the container of legacy Office documents "
            "(.doc, .xls, .ppt), Outlook .msg messages, Thumbs.db, Jump Lists, MSI "
            "installers and many application files. The SummaryInformation streams carry "
            "author, last saved by, creation and edit times; unallocated sectors can keep "
            "data of earlier versions.",
            "OLE Compound File (CFB)",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Compound file signature D0 CF 11 E0 A1 B1 1A E1",
                    "OLE Compound File (CFB)",
                ),
            },
        ],
        "extensions": [".doc", ".xls", ".ppt", ".msg", ".msi", ".db"],
        "links": [
            (
                "[MS-CFB]: Compound File Binary File Format (Microsoft)",
                "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/53989ce4-7b05-4f8d-829b-d08d6148375b",
            ),
            (
                "OLE Compound File format (libyal/libolecf)",
                "https://github.com/libyal/libolecf/blob/main/documentation/OLE%20Compound%20File%20format.asciidoc",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Extensible Storage Engine (ESE) Database",
        "short_name": "ESE",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Microsoft's embedded database engine (JET Blue). Used by SRUM (SRUDB.dat — "
            "per-app network and energy usage), Windows Search (Windows.edb), Internet "
            "Explorer/Edge legacy WebCache, Active Directory (ntds.dit) and Exchange. Pages "
            "are written through transaction logs (.log/.jrs), and a database copied from "
            "a live system may be in a 'dirty shutdown' state with changes still only in "
            "the logs.",
            "Extensible Storage Engine (ESE) Database",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 4,
                "value": b"\xef\xcd\xab\x89",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "File header signature 0x89ABCDEF at offset 4",
                    "Extensible Storage Engine (ESE) Database",
                ),
            },
        ],
        "extensions": [".edb", ".dat", ".dit"],
        "links": [
            (
                "Extensible Storage Engine (ESE) Database File (EDB) format (libyal/libesedb)",
                "https://github.com/libyal/libesedb/blob/main/documentation/Extensible%20Storage%20Engine%20(ESE)%20Database%20File%20(EDB)%20format.asciidoc",
            ),
            (
                "ForensicsWiki — ESE database file format",
                "https://forensics.wiki/extensible_storage_engine_(ese)_database_file_(edb)_format/",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Windows Event Log (EVT, legacy)",
        "short_name": "EVT",
        "category": "log",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The binary event log of Windows NT to XP/2003 (AppEvent.Evt, SecEvent.Evt, "
            "SysEvent.Evt): a circular buffer of event records with record number, "
            "generated and written times, event ID, source and strings. Records from before "
            "a wrap can remain in the file's free space. Superseded by EVTX from Windows "
            "Vista on.",
            "Windows Event Log (EVT, legacy)",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 4,
                "value": b"LfLe",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Header signature 'LfLe' at offset 4",
                    "Windows Event Log (EVT, legacy)",
                ),
            },
        ],
        "extensions": [".evt"],
        "links": [
            (
                "Windows Event Viewer Log (EVT) format (libyal/libevt)",
                "https://github.com/libyal/libevt/blob/main/documentation/Windows%20Event%20Log%20(EVT)%20format.asciidoc",
            ),
            (
                "Event Log File Format (Microsoft)",
                "https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Windows Thumbnail Cache",
        "short_name": "Thumbcache",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Explorer's thumbnail databases (thumbcache_*.db with an index file "
            "thumbcache_idx.db, Windows Vista and later). Each entry holds a thumbnail "
            "image keyed by a cache ID. Thumbnails can remain after the original pictures, "
            "videos or documents were deleted or were on a removable or network drive.",
            "Windows Thumbnail Cache",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"CMMM",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Cache file signature 'CMMM'",
                    "Windows Thumbnail Cache",
                ),
            },
            {
                "offset": 0,
                "value": b"IMMM",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Index file signature 'IMMM'",
                    "Windows Thumbnail Cache",
                ),
            },
        ],
        "extensions": [".db"],
        "links": [
            (
                "Windows Explorer Thumbnail Cache database format (libyal/libwtcdb)",
                "https://github.com/libyal/libwtcdb/blob/main/documentation/Windows%20Explorer%20Thumbnail%20Cache%20database%20format.asciidoc",
            ),
            (
                "ForensicsWiki — Thumbs.db",
                "https://forensics.wiki/thumbs.db/",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "NTFS Master File Table ($MFT)",
        "short_name": "$MFT",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The NTFS metadata file holding one 1 KiB (sometimes 4 KiB) record per file and "
            "directory, often exported on its own for triage. Each record has the "
            "$STANDARD_INFORMATION and $FILE_NAME timestamps, names, parent reference, size "
            "and the data runs or resident data. Records of deleted files stay until "
            "reused.",
            "NTFS Master File Table ($MFT)",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"FILE",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "MFT entry signature 'FILE'",
                    "NTFS Master File Table ($MFT)",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "New Technologies File System (NTFS) — format documentation (libyal/libfsntfs)",
                "https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc",
            ),
            (
                "ForensicsWiki — $MFT",
                "https://forensics.wiki/$mft/",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "NTFS Transaction Log ($LogFile)",
        "short_name": "$LogFile",
        "category": "log",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The NTFS metadata journal: restart pages followed by log record pages "
            "describing redo and undo operations on MFT entries, indexes and bitmaps. "
            "Covers the most recent minutes to hours of file system activity, including "
            "creations, renames and deletions.",
            "NTFS Transaction Log ($LogFile)",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"RSTR",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Restart page signature 'RSTR'",
                    "NTFS Transaction Log ($LogFile)",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "New Technologies File System (NTFS) — format documentation (libyal/libfsntfs)",
                "https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "NTFS Change Journal ($UsnJrnl:$J)",
        "short_name": "$UsnJrnl",
        "category": "log",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The update sequence number journal in the $J stream of $Extend\\$UsnJrnl: one "
            "record per change with file reference, parent reference, timestamp, reason "
            "flags (create, rename, delete, data overwrite …) and file name. It often "
            "reaches back days or weeks and names files that no longer exist. The stream is "
            "sparse; only its end holds records.",
            "NTFS Change Journal ($UsnJrnl:$J)",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [],
        "extensions": [],
        "links": [
            (
                "USN_RECORD_V2 structure (Microsoft)",
                "https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2",
            ),
            (
                "New Technologies File System (NTFS) — format documentation (libyal/libfsntfs)",
                "https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Windows Recycle Bin ($I files)",
        "short_name": "$I",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "For each file moved to the Recycle Bin (Windows Vista and later), "
            "$Recycle.Bin\\<SID>\\ holds a $R file with the content and a $I file with the "
            "original path, size and deletion time. Version 2 (Windows 10 and later) stores "
            "the path length; version 1 a fixed 520-byte path. The header is just a "
            "version number, not a signature.",
            "Windows Recycle Bin ($I files)",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [],
        "extensions": [],
        "links": [
            (
                "Windows Recycle.Bin file formats (libyal/dtformats)",
                "https://github.com/libyal/dtformats/blob/main/documentation/Windows%20Recycle.Bin%20file%20formats.asciidoc",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Volume Shadow Copy (VSS)",
        "short_name": "VSS",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Copy-on-write snapshots of an NTFS volume (System Restore, backups, previous "
            "versions). The snapshot store is kept in files under System Volume Information "
            "and catalogued from a header at offset 0x1E00 of the volume. Each snapshot "
            "presents the volume as it was at its creation time, including files since "
            "deleted or changed.",
            "Volume Shadow Copy (VSS)",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 7680,
                "value": b"k\x87\x088v\xc1HN\xb7\xae\x04\x04nl\xc7R",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "VSS identifier {3808876B-C176-4E48-B7AE-04046E6CC752} at volume offset 0x1E00",
                    "Volume Shadow Copy (VSS)",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "Volume Shadow Snapshot (VSS) format (libyal/libvshadow)",
                "https://github.com/libyal/libvshadow/blob/main/documentation/Volume%20Shadow%20Snapshot%20(VSS)%20format.asciidoc",
            ),
            (
                "ForensicsWiki — Windows shadow volumes",
                "https://forensics.wiki/windows_shadow_volumes/",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Outlook Personal Folders (PST / OST)",
        "short_name": "PST",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Outlook's mailbox file: e-mails, attachments, calendar, contacts and tasks in "
            "a B-tree based node database (.pst for archives and POP accounts, .ost as the "
            "offline cache of Exchange/Microsoft 365). Deleted items can remain in "
            "unallocated blocks. Optional 'compressible' or 'high' encoding obscures but "
            "does not protect the content.",
            "Outlook Personal Folders (PST / OST)",
        ),
        "platforms": ["Windows", "macOS"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"!BDN",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Signature '!BDN'",
                    "Outlook Personal Folders (PST / OST)",
                ),
            },
        ],
        "extensions": [".pst", ".ost"],
        "links": [
            (
                "[MS-PST]: Outlook Personal Folders (.pst) File Format (Microsoft)",
                "https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/141923d5-15ab-4ef1-a524-6dce75aae546",
            ),
            (
                "Personal Folder File (PFF) format (libyal/libpff)",
                "https://github.com/libyal/libpff/blob/main/documentation/Personal%20Folder%20File%20(PFF)%20format.asciidoc",
            ),
            (
                "ForensicsWiki — Personal folder file (PAB, PST, OST)",
                "https://forensics.wiki/personal_folder_file_(pab,_pst,_ost)/",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Windows Minidump",
        "short_name": "MDMP",
        "category": "memory",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "A partial process or system memory dump written on crashes (Windows Error "
            "Reporting, %SystemRoot%\\Minidump) or on demand. Streams describe the threads, "
            "loaded modules with versions and timestamps, exception record, system "
            "information and selected memory ranges of the process at the time of the dump.",
            "Windows Minidump",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"MDMP",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Signature 'MDMP'",
                    "Windows Minidump",
                ),
            },
        ],
        "extensions": [".dmp", ".mdmp"],
        "links": [
            (
                "MINIDUMP_HEADER structure (Microsoft)",
                "https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_header",
            ),
            (
                "Minidump (MDMP) format (libyal/libmdmp)",
                "https://github.com/libyal/libmdmp/blob/main/documentation/Minidump%20(MDMP)%20format.asciidoc",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Windows Hibernation File (hiberfil.sys)",
        "short_name": "hiberfil",
        "category": "memory",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The compressed copy of physical memory Windows writes on hibernation and, with "
            "Fast Startup, on every shutdown (kernel session only). Contains processes, "
            "network state and decrypted keys as they were in RAM. After resume the header "
            "is wiped ('wake'/zeroed), but compressed memory pages can still be present.",
            "Windows Hibernation File (hiberfil.sys)",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"hibr",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Header signature 'hibr'",
                    "Windows Hibernation File (hiberfil.sys)",
                ),
            },
            {
                "offset": 0,
                "value": b"HIBR",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Header signature 'HIBR'",
                    "Windows Hibernation File (hiberfil.sys)",
                ),
            },
            {
                "offset": 0,
                "value": b"wake",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Header signature 'wake' (after resume)",
                    "Windows Hibernation File (hiberfil.sys)",
                ),
            },
            {
                "offset": 0,
                "value": b"WAKE",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Header signature 'WAKE' (after resume)",
                    "Windows Hibernation File (hiberfil.sys)",
                ),
            },
            {
                "offset": None,
                "value": b"RSTR",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Header signature 'RSTR' at offset 0; the same bytes start an NTFS "
                    "$LogFile restart page",
                    "Windows Hibernation File (hiberfil.sys)",
                ),
            },
        ],
        "extensions": [".sys"],
        "links": [
            (
                "Windows Hibernation File (hiberfil.sys) format (libyal/libhibr)",
                "https://github.com/libyal/libhibr/blob/main/documentation/Windows%20Hibernation%20File%20(hiberfil.sys)%20format.asciidoc",
            ),
            (
                "ForensicsWiki — Hiberfil.sys",
                "https://forensics.wiki/hiberfil.sys/",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Resilient File System (ReFS)",
        "short_name": "ReFS",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Microsoft's copy-on-write filesystem for Windows Server and Dev Drives on "
            "Windows 11. Metadata is held in B+ trees that are written to new locations on "
            "every change, so older tree pages can remain. Supports integrity streams "
            "(checksums) and block cloning.",
            "Resilient File System (ReFS)",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 3,
                "value": b"ReFS\x00\x00\x00\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "File system signature 'ReFS' in the volume boot record",
                    "Resilient File System (ReFS)",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "Resilient File System (ReFS) (libyal/libfsrefs)",
                "https://github.com/libyal/libfsrefs/blob/main/documentation/Resilient%20File%20System%20(ReFS).asciidoc",
            ),
            (
                "ForensicsWiki — Resilient file system (ReFS)",
                "https://forensics.wiki/resilient_file_system_(refs)/",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "macOS Keychain (file-based)",
        "short_name": "kych",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The macOS file keychain format of login.keychain-db and System.keychain (named "
            ".keychain before macOS 10.12). A CSSM database of tables for generic and "
            "internet passwords, certificates and keys; record attributes such as service, "
            "account, server and creation/modification dates are stored in the clear, the "
            "secrets are encrypted with keys derived from the keychain password. Distinct "
            "from the SQLite keychain-2.db of iOS and iCloud Keychain.",
            "macOS Keychain (file-based)",
        ),
        "platforms": ["macOS"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"kych",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Signature 'kych'",
                    "macOS Keychain (file-based)",
                ),
            },
        ],
        "extensions": [".keychain", ".keychain-db"],
        "links": [
            (
                "MacOS keychain database file format (libyal/dtformats)",
                "https://github.com/libyal/dtformats/blob/main/documentation/MacOS%20keychain%20database%20file%20format.asciidoc",
            ),
            (
                "chainbreaker — macOS keychain forensic tool (n0fate)",
                "https://github.com/n0fate/chainbreaker",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Apple File System Events (FSEvents)",
        "short_name": "FSEvents",
        "category": "log",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The file system event logs in /.fseventsd on macOS volumes (and some iOS "
            "extractions): gzip-compressed pages of records with the full path, event flags "
            "(created, renamed, modified, removed …), an event ID and, in newer versions, "
            "a file node ID. Records carry no timestamps of their own; times come from the "
            "log files and surrounding evidence. They can show files on volumes and in "
            "locations that no longer exist.",
            "Apple File System Events (FSEvents)",
        ),
        "platforms": ["macOS", "iOS"],
        "parser_class": None,
        "magic": [
            {
                "offset": None,
                "value": b"1SLD",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Page signature '1SLD' (inside the gzip stream)",
                    "Apple File System Events (FSEvents)",
                ),
            },
            {
                "offset": None,
                "value": b"2SLD",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Page signature '2SLD' (inside the gzip stream)",
                    "Apple File System Events (FSEvents)",
                ),
            },
            {
                "offset": None,
                "value": b"3SLD",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Page signature '3SLD' (inside the gzip stream)",
                    "Apple File System Events (FSEvents)",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "MacOS File System Events Disk Log Stream format (libyal/dtformats)",
                "https://github.com/libyal/dtformats/blob/main/documentation/MacOS%20File%20System%20Events%20Disk%20Log%20Stream%20format.asciidoc",
            ),
            (
                "FSEventsParser (G-C Partners)",
                "https://github.com/dlcowen/FSEventsParser",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Apple Spotlight Store",
        "short_name": "Spotlight",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Spotlight's metadata index (store.db and .store.db in .Spotlight-V100 on macOS "
            "volumes, and per-app indexes on iOS). Holds metadata attributes per indexed "
            "item such as names, paths, content type, dates (including last used), authors, "
            "download sources and text excerpts — also for files since deleted.",
            "Apple Spotlight Store",
        ),
        "platforms": ["macOS", "iOS"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"8tsd",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Signature '8tsd'",
                    "Apple Spotlight Store",
                ),
            },
        ],
        "extensions": [".db"],
        "links": [
            (
                "Apple Spotlight store file formats (libyal/dtformats)",
                "https://github.com/libyal/dtformats/blob/main/documentation/Apple%20Spotlight%20store%20database%20file%20format.asciidoc",
            ),
            (
                "spotlight_parser (Yogesh Khatri)",
                "https://github.com/ydkhatri/spotlight_parser",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Apple System Log (ASL)",
        "short_name": "ASL",
        "category": "log",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The binary log store of macOS 10.4 to 10.11 and early iOS, still written by "
            "some components afterwards (/private/var/log/asl/*.asl): records with "
            "timestamp, host, sender, facility, PID/UID/GID, level and message, plus "
            "free-form key-value pairs. Superseded by the Unified Log.",
            "Apple System Log (ASL)",
        ),
        "platforms": ["macOS", "iOS"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"ASL DB\x00\x00\x00\x00\x00\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Signature 'ASL DB'",
                    "Apple System Log (ASL)",
                ),
            },
        ],
        "extensions": [".asl"],
        "links": [
            (
                "Apple System Log (ASL) file format (libyal/dtformats)",
                "https://github.com/libyal/dtformats/blob/main/documentation/Apple%20System%20Log%20(ASL)%20file%20format.asciidoc",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "macOS Finder .DS_Store",
        "short_name": ".DS_Store",
        "category": "configuration",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Hidden Finder files storing per-folder view settings in a B-tree of records "
            "keyed by file name (icon position, view style, comments, etc.). Because "
            "records are kept for names the Finder has seen, a .DS_Store can list files "
            "that were in the folder earlier; copies also travel to network shares, USB "
            "drives and ZIP archives.",
            "macOS Finder .DS_Store",
        ),
        "platforms": ["macOS"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"\x00\x00\x00\x01Bud1",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Alignment value 1 followed by buddy-allocator magic 'Bud1'",
                    "macOS Finder .DS_Store",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "DS_Store format (Wim Lewis, Mac::Finder::DSStore)",
                "https://metacpan.org/dist/Mac-Finder-DSStore/view/DSStoreFormat.pod",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "AppleDouble / AppleSingle",
        "short_name": "AppleDouble",
        "category": "configuration",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Containers for Mac metadata on filesystems and transports that lack it: an "
            "AppleDouble '._name' file next to the data file (on FAT, exFAT, SMB shares, in "
            "__MACOSX folders of ZIP archives) holds the resource fork and Finder info, "
            "often extended attributes such as com.apple.quarantine with the download "
            "source. AppleSingle combines data and metadata in one file.",
            "AppleDouble / AppleSingle",
        ),
        "platforms": ["macOS"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"\x00\x05\x16\x07",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "AppleDouble magic 0x00051607",
                    "AppleDouble / AppleSingle",
                ),
            },
            {
                "offset": 0,
                "value": b"\x00\x05\x16\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "AppleSingle magic 0x00051600",
                    "AppleDouble / AppleSingle",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "MIME Encapsulation of Macintosh Files — MacMIME (RFC 1740)",
                "https://www.rfc-editor.org/rfc/rfc1740.html",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Apple Bill of Materials (BOM)",
        "short_name": "BOM",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Apple's BOMStore container of named blocks and trees. Installer receipts "
            "(/var/db/receipts/*.bom) list every file a package installed with mode, owner, "
            "size and checksum; compiled asset catalogs (Assets.car) in app bundles use "
            "the same container.",
            "Apple Bill of Materials (BOM)",
        ),
        "platforms": ["macOS", "iOS"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"BOMStore",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Signature 'BOMStore'",
                    "Apple Bill of Materials (BOM)",
                ),
            },
        ],
        "extensions": [".bom", ".car"],
        "links": [
            (
                "bomutils — BOM file reader/writer (source with format structures)",
                "https://github.com/hogliux/bomutils",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "XAR Archive",
        "short_name": "XAR",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The eXtensible ARchive format of macOS installer packages (.pkg), .xip "
            "archives and Safari extensions: a binary header, a zlib-compressed XML table "
            "of contents with paths, owners, modes, timestamps and checksums of every file, "
            "and a heap with the file data. Packages may carry a signing certificate chain "
            "in the table of contents.",
            "XAR Archive",
        ),
        "platforms": ["macOS"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"xar!",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Signature 'xar!'",
                    "XAR Archive",
                ),
            },
        ],
        "extensions": [".pkg", ".xar", ".xip"],
        "links": [
            (
                "xar format (mackyle/xar wiki)",
                "https://github.com/mackyle/xar/wiki/xarformat",
            ),
            (
                "xar source (Apple Open Source)",
                "https://github.com/apple-oss-distributions/xar",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Apple Encrypted Archive (AEA)",
        "short_name": "AEA",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Apple's signed and encrypted archive format, used for iOS/macOS firmware and "
            "OTA components. The content (usually an Apple Archive) is encrypted in "
            "segments; opening it requires the key, which for firmware is fetched from "
            "Apple's servers using metadata in the file.",
            "Apple Encrypted Archive (AEA)",
        ),
        "platforms": ["iOS", "macOS"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"AEA1",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Signature 'AEA1'",
                    "Apple Encrypted Archive (AEA)",
                ),
            },
        ],
        "extensions": [".aea"],
        "links": [
            (
                "AEA guide (blacktop/ipsw documentation)",
                "https://blacktop.github.io/ipsw/docs/guides/aea",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Apple Partition Map (APM)",
        "short_name": "APM",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The partition scheme of PowerPC Macs, still used on some older external disks "
            "and DMG images. A driver descriptor in block 0 is followed by one map entry "
            "per partition with name, type ('Apple_HFS', 'Apple_Free' …), start and size.",
            "Apple Partition Map (APM)",
        ),
        "platforms": ["macOS"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"ER",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Driver descriptor signature 'ER' (block 0)",
                    "Apple Partition Map (APM)",
                ),
            },
            {
                "offset": 512,
                "value": b"PM",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Partition map entry signature 'PM' (block 1)",
                    "Apple Partition Map (APM)",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "Apple Partition Map (APM) (libyal/libvsapm)",
                "https://github.com/libyal/libvsapm/blob/main/documentation/Apple%20partition%20map%20(APM)%20format.asciidoc",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Android Boot Image",
        "short_name": "Boot image",
        "category": "disk_image",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The boot partition image of Android devices: a header with OS version and "
            "patch level, kernel command line and sizes, followed by the kernel, ramdisk "
            "and (depending on header version) second-stage, DTB and recovery DTBO. Shows "
            "the kernel and init configuration a device boots with, and modifications such "
            "as rooting patches.",
            "Android Boot Image",
        ),
        "platforms": ["Android"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"ANDROID!",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Boot image magic 'ANDROID!'",
                    "Android Boot Image",
                ),
            },
            {
                "offset": 0,
                "value": b"VNDRBOOT",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Vendor boot image magic 'VNDRBOOT'",
                    "Android Boot Image",
                ),
            },
        ],
        "extensions": [".img"],
        "links": [
            (
                "Boot image header (Android Open Source Project)",
                "https://source.android.com/docs/core/architecture/bootloader/boot-image-header",
            ),
            (
                "bootimg.h (AOSP mkbootimg source)",
                "https://android.googlesource.com/platform/system/tools/mkbootimg/+/refs/heads/main/include/bootimg/bootimg.h",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "systemd Journal",
        "short_name": "journal",
        "category": "log",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The binary log of systemd-journald (/var/log/journal, /run/log/journal): "
            "entries of key-value fields (MESSAGE, _PID, _UID, _COMM, _BOOT_ID, …) with "
            "realtime and monotonic timestamps, hash-chained for sealing when Forward "
            "Secure Sealing is enabled. Archived journal files keep older entries; a file "
            "not closed cleanly is marked online/dirty.",
            "systemd Journal",
        ),
        "platforms": ["Linux"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"LPKSHHRH",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Signature 'LPKSHHRH'",
                    "systemd Journal",
                ),
            },
        ],
        "extensions": [".journal", ".journal~"],
        "links": [
            (
                "Journal File Format (systemd)",
                "https://systemd.io/JOURNAL_FILE_FORMAT/",
            ),
            (
                "Systemd journal file format (libyal/dtformats)",
                "https://github.com/libyal/dtformats/blob/main/documentation/Systemd%20journal%20file%20format.asciidoc",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "LUKS Encrypted Volume",
        "short_name": "LUKS",
        "category": "disk_image",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Linux Unified Key Setup, the standard Linux disk encryption format. A header "
            "with cipher, UUID and up to 8 (LUKS1) or 32 (LUKS2) key slots, each holding "
            "the volume key encrypted with a passphrase or key file; LUKS2 adds a JSON "
            "metadata area and a secondary header copy. Without a slot's secret the data "
            "area is ciphertext.",
            "LUKS Encrypted Volume",
        ),
        "platforms": ["Linux", "Android"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"LUKS\xba\xbe",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Primary header magic 'LUKS' 0xBA 0xBE",
                    "LUKS Encrypted Volume",
                ),
            },
            {
                "offset": 0,
                "value": b"SKUL\xba\xbe",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "LUKS2 secondary header magic 'SKUL' 0xBA 0xBE",
                    "LUKS Encrypted Volume",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "LUKS1 On-Disk Format Specification (cryptsetup)",
                "https://gitlab.com/cryptsetup/cryptsetup/-/wikis/LUKS-standard/on-disk-format.pdf",
            ),
            (
                "LUKS2 On-Disk Format Specification (cryptsetup)",
                "https://gitlab.com/cryptsetup/LUKS2-docs/-/raw/main/luks2_doc_wip.pdf",
            ),
            (
                "LUKS Disk Encryption format (libyal/libluksde)",
                "https://github.com/libyal/libluksde/blob/main/documentation/Linux%20Unified%20Key%20Setup%20(LUKS)%20Disk%20Encryption%20format.asciidoc",
            ),
            (
                "ForensicsWiki — Linux unified key setup (LUKS)",
                "https://forensics.wiki/linux_unified_key_setup_(luks)/",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Linux Logical Volume Manager (LVM2)",
        "short_name": "LVM2",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Linux volume management: a physical volume label in one of the first four "
            "sectors (normally the second) points to a text metadata area describing volume "
            "groups and logical volumes with their extents. The metadata area keeps "
            "earlier versions of the configuration in a ring buffer, so removed or resized "
            "logical volumes can be traced.",
            "Linux Logical Volume Manager (LVM2)",
        ),
        "platforms": ["Linux"],
        "parser_class": None,
        "magic": [
            {
                "offset": 512,
                "value": b"LABELONE",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Physical volume label 'LABELONE' (normally sector 1)",
                    "Linux Logical Volume Manager (LVM2)",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "LVM format specification (libyal/libvslvm)",
                "https://github.com/libyal/libvslvm/blob/main/documentation/Logical%20Volume%20Manager%20(LVM)%20format.asciidoc",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "utmp / wtmp / btmp Login Records",
        "short_name": "utmp",
        "category": "log",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Fixed-size binary login records on Linux and other Unix systems: utmp (current "
            "sessions), wtmp (login/logout, boot and shutdown history) and btmp (failed "
            "logins). Each record has type, PID, terminal, user name, remote host or IP and "
            "a timestamp. No header or signature; records are recognised by size and "
            "layout.",
            "utmp / wtmp / btmp Login Records",
        ),
        "platforms": ["Linux"],
        "parser_class": None,
        "magic": [],
        "extensions": [],
        "links": [
            (
                "utmp(5) — Linux manual page",
                "https://man7.org/linux/man-pages/man5/utmp.5.html",
            ),
            (
                "Utmp login records format (libyal/dtformats)",
                "https://github.com/libyal/dtformats/blob/main/documentation/Utmp%20login%20records%20format.asciidoc",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "LiME Memory Image",
        "short_name": "LiME",
        "category": "memory",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Physical memory captured from Linux and Android devices with the LiME kernel "
            "module. In 'lime' format each captured memory range is preceded by a 32-byte "
            "header with its start and end physical address; gaps between ranges are not "
            "stored. 'raw' and 'padded' formats have no headers.",
            "LiME Memory Image",
        ),
        "platforms": ["Linux", "Android"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"EMiL",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Range header magic 0x4C694D45 (little-endian 'EMiL')",
                    "LiME Memory Image",
                ),
            },
        ],
        "extensions": [".lime", ".mem"],
        "links": [
            (
                "LiME — Linux Memory Extractor",
                "https://github.com/jtsylve/LiME",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "XFS",
        "short_name": "XFS",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "A journaling filesystem used as the default on Red Hat Enterprise Linux and "
            "its derivatives and on many NAS devices. Allocation groups each manage their "
            "own inodes and free space through B+ trees; inodes carry nanosecond timestamps "
            "and, on v5 filesystems, a creation time.",
            "XFS",
        ),
        "platforms": ["Linux"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"XFSB",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Superblock signature 'XFSB'",
                    "XFS",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "X File System (XFS) (libyal/libfsxfs)",
                "https://github.com/libyal/libfsxfs/blob/main/documentation/X%20File%20System%20(XFS).asciidoc",
            ),
            (
                "ForensicsWiki — XFS",
                "https://forensics.wiki/xfs/",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Btrfs",
        "short_name": "Btrfs",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "A copy-on-write Linux filesystem with subvolumes and snapshots (default on "
            "openSUSE and Fedora desktops, Synology NAS). Metadata trees are written to new "
            "locations on every transaction, so earlier tree generations and snapshot "
            "contents can hold previous versions of files.",
            "Btrfs",
        ),
        "platforms": ["Linux"],
        "parser_class": None,
        "magic": [
            {
                "offset": 65600,
                "value": b"_BHRfS_M",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Superblock magic '_BHRfS_M' (superblock at 64 KiB)",
                    "Btrfs",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "On-disk Format (Btrfs documentation)",
                "https://btrfs.readthedocs.io/en/latest/dev/On-disk-format.html",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "PCAP Packet Capture",
        "short_name": "PCAP",
        "category": "network",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The classic libpcap capture format written by tcpdump, Wireshark and many "
            "network devices: a global header with link type and snapshot length, then one "
            "record per packet with a timestamp (microsecond or nanosecond resolution, UTC) "
            "and the captured bytes.",
            "PCAP Packet Capture",
        ),
        "platforms": ["Linux", "macOS", "Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"\xd4\xc3\xb2\xa1",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Magic 0xA1B2C3D4 little-endian (microseconds)",
                    "PCAP Packet Capture",
                ),
            },
            {
                "offset": 0,
                "value": b"\xa1\xb2\xc3\xd4",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Magic 0xA1B2C3D4 big-endian (microseconds)",
                    "PCAP Packet Capture",
                ),
            },
            {
                "offset": 0,
                "value": b"M<\xb2\xa1",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Magic 0xA1B23C4D little-endian (nanoseconds)",
                    "PCAP Packet Capture",
                ),
            },
            {
                "offset": 0,
                "value": b"\xa1\xb2<M",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Magic 0xA1B23C4D big-endian (nanoseconds)",
                    "PCAP Packet Capture",
                ),
            },
        ],
        "extensions": [".pcap", ".cap"],
        "links": [
            (
                "pcap-savefile(5) — libpcap file format (tcpdump)",
                "https://www.tcpdump.org/manpages/pcap-savefile.5.html",
            ),
            (
                "PCAP Capture File Format (IETF draft-ietf-opsawg-pcap)",
                "https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/",
            ),
            (
                "ForensicsWiki — PCAP",
                "https://forensics.wiki/pcap/",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "PCAPNG Packet Capture",
        "short_name": "PCAPNG",
        "category": "network",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The block-based successor of PCAP and Wireshark's default: section header, "
            "interface descriptions with names and time resolution, enhanced packet blocks, "
            "name resolution blocks, and comments. Can hold captures from several "
            "interfaces and link types in one file and records capture hardware, OS and "
            "application.",
            "PCAPNG Packet Capture",
        ),
        "platforms": ["Linux", "macOS", "Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"\x0a\x0d\x0d\x0a",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Section header block type 0x0A0D0D0A",
                    "PCAPNG Packet Capture",
                ),
            },
            {
                "offset": 8,
                "value": b"M<+\x1a",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Byte-order magic 0x1A2B3C4D (little-endian)",
                    "PCAPNG Packet Capture",
                ),
            },
        ],
        "extensions": [".pcapng", ".ntar"],
        "links": [
            (
                "PCAP Now Generic (pcapng) Capture File Format (IETF draft-ietf-opsawg-pcapng)",
                "https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/",
            ),
            (
                "PcapNg (Wireshark wiki)",
                "https://wiki.wireshark.org/Development/PcapNg",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "RAR Archive",
        "short_name": "RAR",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The RAR archive format (versions 1.5–4.x and 5.0): headers with file names, "
            "sizes, modification (and optionally creation and access) times and attributes; "
            "solid compression, multi-volume sets, recovery records and AES encryption of "
            "data or of the headers too. With encrypted headers even the file names are "
            "hidden.",
            "RAR Archive",
        ),
        "platforms": ["Windows", "macOS", "Linux", "Android"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"Rar!\x1a\x07\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "RAR 1.5–4.x signature",
                    "RAR Archive",
                ),
            },
            {
                "offset": 0,
                "value": b"Rar!\x1a\x07\x01\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "RAR 5.0 signature",
                    "RAR Archive",
                ),
            },
        ],
        "extensions": [".rar", ".r00", ".part1.rar"],
        "links": [
            (
                "RAR 5.0 archive format (RARLAB)",
                "https://www.rarlab.com/technote.htm",
            ),
            (
                "ForensicsWiki — RAR",
                "https://forensics.wiki/rar/",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "bzip2 Compressed Data",
        "short_name": "bzip2",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Block-sorting compressed stream holding a single file, often a TAR archive "
            "(.tar.bz2) or a log/disk image. No file name or timestamp is stored; each 900 "
            "KB-or-smaller block carries its own CRC, so undamaged blocks of a truncated or "
            "carved stream can still be decompressed.",
            "bzip2 Compressed Data",
        ),
        "platforms": ["Linux", "macOS", "Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"BZh",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Signature 'BZh' followed by the block size digit",
                    "bzip2 Compressed Data",
                ),
            },
        ],
        "extensions": [".bz2", ".tbz2", ".tbz"],
        "links": [
            (
                "bzip2 (sourceware.org)",
                "https://sourceware.org/bzip2/",
            ),
            (
                "The bzip2 format (Joe Tsai, dsnet/compress)",
                "https://github.com/dsnet/compress/blob/master/doc/bzip2-format.pdf",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "XZ Compressed Data",
        "short_name": "XZ",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "LZMA2-based compressed stream holding a single file, often a TAR archive "
            "(.tar.xz), Linux packages, kernel modules or firmware. Streams consist of "
            "blocks with integrity checks and an index; no file name or timestamp is "
            "stored.",
            "XZ Compressed Data",
        ),
        "platforms": ["Linux", "macOS", "Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"\xfd7zXZ\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Stream header magic FD 37 7A 58 5A 00",
                    "XZ Compressed Data",
                ),
            },
        ],
        "extensions": [".xz", ".txz"],
        "links": [
            (
                "The .xz File Format (Tukaani)",
                "https://tukaani.org/xz/xz-file-format.txt",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Zstandard Compressed Data",
        "short_name": "zstd",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Zstandard frames as used for .zst files, Linux packages and initramfs, browser "
            "and app caches and database pages. A frame header may record the content size "
            "and a dictionary ID; skippable frames can carry other data.",
            "Zstandard Compressed Data",
        ),
        "platforms": ["Linux", "Android", "Windows", "macOS"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"(\xb5/\xfd",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Frame magic 0xFD2FB528",
                    "Zstandard Compressed Data",
                ),
            },
        ],
        "extensions": [".zst", ".tzst"],
        "links": [
            (
                "Zstandard Compression and the 'application/zstd' Media Type (RFC 8878)",
                "https://www.rfc-editor.org/rfc/rfc8878.html",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "LZ4 Frame",
        "short_name": "LZ4",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The LZ4 frame format for .lz4 files and LZ4-compressed data in apps, kernels "
            "and databases. The frame descriptor records block size, checksums and "
            "optionally the content size. (Mozilla's jsonlz4 and Apple's LZ4 variants use "
            "other headers.)",
            "LZ4 Frame",
        ),
        "platforms": ["Linux", "Android", "Windows", "macOS"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"\x04\x22M\x18",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Frame magic 0x184D2204",
                    "LZ4 Frame",
                ),
            },
        ],
        "extensions": [".lz4"],
        "links": [
            (
                "LZ4 Frame Format Description (lz4 project)",
                "https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Mozilla LZ4 (jsonlz4)",
        "short_name": "jsonlz4",
        "category": "serialization",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Firefox's LZ4-compressed JSON files: session store (sessionstore.jsonlz4, "
            "recovery.jsonlz4 — open tabs, history per tab, form data, cookies), bookmark "
            "backups and add-on data. A custom header 'mozLz40' and the decompressed size "
            "precede an LZ4 block.",
            "Mozilla LZ4 (jsonlz4)",
        ),
        "platforms": ["Windows", "macOS", "Linux"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"mozLz40\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Header magic 'mozLz40'",
                    "Mozilla LZ4 (jsonlz4)",
                ),
            },
        ],
        "extensions": [".jsonlz4", ".mozlz4", ".baklz4"],
        "links": [
            (
                "dejsonlz4 — reference decoder (avih)",
                "https://github.com/avih/dejsonlz4",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Microsoft Cabinet (CAB)",
        "short_name": "CAB",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Microsoft's compressed archive format for installers, Windows updates and "
            "drivers. Holds file names, sizes, DOS date/time stamps and attributes for each "
            "file; can be split across several cabinets and signed with Authenticode.",
            "Microsoft Cabinet (CAB)",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"MSCF",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Signature 'MSCF'",
                    "Microsoft Cabinet (CAB)",
                ),
            },
        ],
        "extensions": [".cab"],
        "links": [
            (
                "Microsoft Cabinet Format (Microsoft)",
                "https://learn.microsoft.com/en-us/previous-versions/bb417343(v=msdn.10)",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "ISO 9660 Optical Disc Image",
        "short_name": "ISO",
        "category": "disk_image",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The CD/DVD filesystem image format, also used to deliver software and malware "
            "(mounted by a double-click on Windows). Volume descriptors from sector 16 on "
            "carry the volume name, creating application and creation date; Joliet and Rock "
            "Ridge extensions add long names and Unix attributes. UDF images may coexist "
            "in the same file.",
            "ISO 9660 Optical Disc Image",
        ),
        "platforms": ["Windows", "macOS", "Linux"],
        "parser_class": None,
        "magic": [
            {
                "offset": 32769,
                "value": b"CD001",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Volume descriptor identifier 'CD001' (sector 16)",
                    "ISO 9660 Optical Disc Image",
                ),
            },
        ],
        "extensions": [".iso"],
        "links": [
            (
                "ECMA-119 — Volume and File Structure of CDROM (Ecma International)",
                "https://ecma-international.org/publications-and-standards/standards/ecma-119/",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "KeePass Database (KDBX)",
        "short_name": "KDBX",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The password database of KeePass, KeePassXC and compatible apps. Outside the "
            "encrypted payload only the header is readable (cipher, key derivation function "
            "and its parameters); entries with titles, user names, passwords, URLs, notes "
            "and history are encrypted with a key derived from the master password and/or "
            "key file.",
            "KeePass Database (KDBX)",
        ),
        "platforms": ["Windows", "macOS", "Linux", "Android", "iOS"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"\x03\xd9\xa2\x9a",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Signature 1 0x9AA2D903",
                    "KeePass Database (KDBX)",
                ),
            },
            {
                "offset": 4,
                "value": b"g\xfbK\xb5",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Signature 2 0xB54BFB67 (KDBX 2.x and later)",
                    "KeePass Database (KDBX)",
                ),
            },
        ],
        "extensions": [".kdbx"],
        "links": [
            (
                "KDBX File Format Specification (KeePass)",
                "https://keepass.info/help/kb/kdbx.html",
            ),
            (
                "KDBX 4.1 (KeePass)",
                "https://keepass.info/help/kb/kdbx_4.1.html",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "VeraCrypt / TrueCrypt Volume",
        "short_name": "VeraCrypt",
        "category": "disk_image",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Encrypted containers and partitions of VeraCrypt and its predecessor "
            "TrueCrypt. The volume header is itself encrypted with a key derived from the "
            "password (and optional key files/PIM), so a volume has no signature and is "
            "indistinguishable from random data; a hidden volume can sit inside the free "
            "space of an outer one.",
            "VeraCrypt / TrueCrypt Volume",
        ),
        "platforms": ["Windows", "macOS", "Linux"],
        "parser_class": None,
        "magic": [],
        "extensions": [".hc", ".tc"],
        "links": [
            (
                "VeraCrypt Volume Format Specification (VeraCrypt)",
                "https://veracrypt.io/en/VeraCrypt%20Volume%20Format%20Specification.html",
            ),
            (
                "ForensicsWiki — TrueCrypt",
                "https://forensics.wiki/truecrypt/",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Mbox Mailbox",
        "short_name": "mbox",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "A mailbox stored as one text file of concatenated e-mail messages, each "
            "starting with a 'From ' separator line (sender and date). Used by Thunderbird, "
            "Apple Mail exports, Google Takeout and Unix mail spools. Messages deleted in "
            "the client can remain in the file until it is compacted.",
            "Mbox Mailbox",
        ),
        "platforms": ["Windows", "macOS", "Linux"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"From ",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Separator line 'From '",
                    "Mbox Mailbox",
                ),
            },
        ],
        "extensions": [".mbox", ".mbx"],
        "links": [
            (
                "The application/mbox Media Type (RFC 4155)",
                "https://www.rfc-editor.org/rfc/rfc4155.html",
            ),
            (
                "ForensicsWiki — Mbox",
                "https://forensics.wiki/mbox/",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "E-mail Message (EML / RFC 5322)",
        "short_name": "EML",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "A single e-mail message as text: header fields (From, To, Date, Subject, "
            "Message-ID) and the Received chain, which records each server that handled the "
            "message with time and addresses, followed by the MIME body and attachments. "
            "Authentication results (SPF, DKIM, DMARC) in the headers help judge whether a "
            "message is genuine. No signature; recognised by its header lines.",
            "E-mail Message (EML / RFC 5322)",
        ),
        "platforms": ["Windows", "macOS", "Linux", "iOS", "Android"],
        "parser_class": None,
        "magic": [],
        "extensions": [".eml"],
        "links": [
            (
                "Internet Message Format (RFC 5322)",
                "https://www.rfc-editor.org/rfc/rfc5322.html",
            ),
        ],
        "status": "draft",
    },
    {
        "name": "Chromium Disk Cache",
        "short_name": "Chrome cache",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The HTTP cache of Chrome, Edge and other Chromium browsers and Electron apps. "
            "The blockfile backend uses an index file and data_0..3 block files; the simple "
            "backend (Android, Linux) stores one file per entry. Entries hold the URL, "
            "response headers with server dates and the cached content (pages, images, "
            "scripts), also for sites no longer in history.",
            "Chromium Disk Cache",
        ),
        "platforms": ["Windows", "macOS", "Linux", "Android"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"\xc3\xca\x03\xc1",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Blockfile index magic 0xC103CAC3",
                    "Chromium Disk Cache",
                ),
            },
            {
                "offset": 0,
                "value": b"\xc3\xca\x04\xc1",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Blockfile data file magic 0xC104CAC3",
                    "Chromium Disk Cache",
                ),
            },
            {
                "offset": 0,
                "value": b"0\x5cr\xa7\x1bm\xfb\xfc",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Simple cache entry magic 0xFCFB6D1BA7725C30",
                    "Chromium Disk Cache",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "Chrome Cache file format (libyal/dtformats)",
                "https://github.com/libyal/dtformats/blob/main/documentation/Chrome%20Cache%20file%20format.asciidoc",
            ),
            (
                "Disk Cache (Chromium design documents)",
                "https://www.chromium.org/developers/design-documents/network-stack/disk-cache/",
            ),
            (
                "Very Simple Backend (Chromium design documents)",
                "https://www.chromium.org/developers/design-documents/network-stack/disk-cache/very-simple-backend/",
            ),
        ],
        "status": "draft",
    },
]


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def build(out_path: Path = _OUT) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        out_path.unlink()

    conn = sqlite3.connect(out_path)
    conn.executescript("""
        CREATE TABLE formats (
            id                  INTEGER PRIMARY KEY,
            name                TEXT NOT NULL,
            short_name          TEXT,
            category            TEXT,
            forensic_relevance  TEXT,
            platforms           TEXT,
            parser_class        TEXT
        );
        CREATE TABLE magic_bytes (
            id          INTEGER PRIMARY KEY,
            format_id   INTEGER NOT NULL REFERENCES formats(id),
            offset      INTEGER,
            pattern     BLOB NOT NULL,
            description TEXT
        );
        CREATE TABLE extensions (
            format_id   INTEGER NOT NULL REFERENCES formats(id),
            extension   TEXT NOT NULL
        );
        CREATE TABLE links (
            id          INTEGER PRIMARY KEY,
            format_id   INTEGER NOT NULL REFERENCES formats(id),
            label       TEXT NOT NULL,
            url         TEXT NOT NULL
        );
        CREATE INDEX idx_magic ON magic_bytes(pattern);
        CREATE INDEX idx_ext   ON extensions(extension);
        CREATE INDEX idx_links ON links(format_id);
    """)

    reviewed = [f for f in FORMATS if f.get("status") == "reviewed"]
    draft = [f for f in FORMATS if f.get("status") != "reviewed"]
    if draft:
        print(f"Skipping {len(draft)} draft format(s): {', '.join(f['name'] for f in draft)}")

    for fmt in reviewed:
        platforms = fmt.get("platforms", [])
        if isinstance(platforms, list):
            platforms_str = ",".join(platforms)
        else:
            platforms_str = platforms

        cur = conn.execute(
            "INSERT INTO formats (name, short_name, category, forensic_relevance, "
            "platforms, parser_class) VALUES (?,?,?,?,?,?)",
            (
                fmt["name"],
                fmt.get("short_name", ""),
                fmt.get("category", ""),
                fmt.get("forensic_relevance", ""),
                platforms_str,
                fmt.get("parser_class"),
            ),
        )
        fid = cur.lastrowid
        for m in fmt.get("magic", []):
            conn.execute(
                "INSERT INTO magic_bytes (format_id, offset, pattern, description) VALUES (?,?,?,?)",
                (fid, m.get("offset"), m["value"], m.get("description", "")),
            )
        for ext in fmt.get("extensions", []):
            conn.execute(
                "INSERT INTO extensions (format_id, extension) VALUES (?,?)",
                (fid, ext.lower()),
            )
        for label, url in fmt.get("links", []):
            conn.execute(
                "INSERT INTO links (format_id, label, url) VALUES (?,?,?)",
                (fid, label, url),
            )

    conn.commit()
    conn.close()
    print(f"Built {out_path}  ({len(reviewed)} reviewed formats, {len(FORMATS)} total)")


if __name__ == "__main__":
    build()
