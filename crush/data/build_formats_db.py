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

import re
import sqlite3
from datetime import date
from pathlib import Path
from typing import Any

from crush.core.issues import QT_TRANSLATE_NOOP

_OUT = Path(__file__).parent / "formats.db"

# ---------------------------------------------------------------------------
# Format definitions
# Each entry:
#   name            Full human-readable name
#   short_name      Abbreviation shown in UI. Required, and NEVER changed
#                   once published: it is the entry's permanent address on
#                   the format reference site (scripts/build_format_pages.py,
#                   /formats/<url_slug(short_name)>/). Pinned by
#                   scripts/format_pages/published_slugs.txt.
#   category        database | configuration | log | execution | document |
#                   filesystem | disk_image | logical_image | archive |
#                   serialization | media | memory | network | uncategorized
#                   (a new one also goes into format_db.FORMAT_CATEGORIES,
#                   the translation catalog's list)
#   forensic_relevance  Structure, notable specifics (e.g. retains deleted
#                   data, encryption, variants) and where the format is
#                   commonly found. No references to tools, apps, parsers
#                   or Crush support.
#   platforms       List of strings from PLATFORMS below (the operating
#                   system the format belongs to), or ALL_PLATFORMS for a
#                   format not tied to any. Stored in PLATFORMS order.
#   parser_class    Class name that handles this — either a crush/parsers/
#                   AbstractParser subclass (per-file content parser, looked
#                   up via FormatDatabase.for_parser() from a running
#                   parser instance), or a crush/core/vfs.py VFS backend
#                   (whole-container support, e.g. ZipVFS/TarVFS/
#                   AndroidBackupVFS — never looked up that way, but still
#                   drives the "Supported" vs "Not yet supported" label in
#                   the Format Reference / Format Info dialogs). None if
#                   Crush doesn't support this format at all yet.
#   magic           List of dicts: {"offset": int | None, "value": bytes,
#                                   "description": str}
#                   Each entry is checked on its own: every matching entry
#                   adds its length to the format's score and the highest
#                   score wins (FormatDatabase.identify). A signature that
#                   is only unique together (e.g. "ftyp" + major brand) is
#                   written as one contiguous pattern. Use offset=None for
#                   trailer/unknown offsets (informational only, never
#                   matched), and for a signature another entry shares or
#                   one too short to identify the format on its own (the
#                   description says why). A tie at the top score
#                   identifies nothing, and test_format_db checks that every
#                   format is identified by its own signatures.
#   extensions      List of lowercase extensions including the dot
#   links           List of (label, url) tuples — reference links
#   status          "draft" (excluded from DB) | "reviewed" (included in DB).
#                   draft: compiled from a brief web search (search engine
#                   or AI-assisted), nothing more. reviewed: checked
#                   manually -- sources verified and refined; signatures and
#                   structure checked against the specification where one
#                   exists, else against published reverse-engineering and
#                   own research; practical knowledge from casework and the
#                   DFIR community. The format reference site says so.
#   last_reviewed   ISO date ("YYYY-MM-DD") of the last manual review of the
#                   whole entry, or None
# ---------------------------------------------------------------------------

# Every value "platforms" may use, in the order they are stored.
PLATFORMS = ("Windows", "macOS", "Linux", "iOS", "Android", "QNX")
# For a format not tied to any operating system. It grows with PLATFORMS, so
# a format that merely occurs on every current platform lists them instead.
ALL_PLATFORMS = PLATFORMS

FORMATS: list[dict[str, Any]] = [
    {
        "name": "Android Binary XML (ABX)",
        "short_name": "ABX",
        "category": "serialization",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Android system configuration stored as compact binary XML, introduced "
            "in Android 12 and used mainly for system files. Files keep the .xml "
            "name (sometimes .abx) and are recognisable only by their header. Key "
            "files include packages.xml (installed apps and permissions) and the "
            "settings files (global, secure, system). Provides insight into "
            "installed software, permission grants, and system configuration state.",
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
                "https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/cmds/abx/",
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
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "Android Backup Archive",
        "short_name": "Android backup",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Backup created via ADB backup functionality (deprecated; restricted since Android 12 / API 31). "
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
                "AOSP source (BackupManagerService, Android 4.1 original implementation)",
                "https://android.googlesource.com/platform/frameworks/base/+/refs/heads/jb-dev/services/java/com/android/server/BackupManagerService.java",
            ),
            (
                "Android 12 behavior changes — adb backup restrictions",
                "https://developer.android.com/about/versions/12/behavior-changes-12",
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
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "Binary Property List",
        "short_name": "bplist",
        "category": "serialization",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "App preferences, caches, configuration, and iOS/macOS backup structures "
            "such as Manifest.plist and Info.plist. Many bplist files are NSKeyedArchiver "
            "object graphs — recognisable by the '$archiver' key — which can contain "
            "messages, contacts, health records, and other complex app data. "
            "Timestamps use Mac Absolute Time (seconds since 2001-01-01 UTC). "
            "Frequently embedded rather than stored as files: as BLOBs in SQLite "
            "databases and in extended attributes. "
            "Widely used across all Apple platforms and most third-party iOS/macOS apps.",
            "Binary Property List",
        ),
        "platforms": ["macOS", "iOS"],
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
        "last_reviewed": "2026-10-04",
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
            "No mandatory magic bytes — data may begin with the optional self-described CBOR tag "
            "(0xD9D9F7); otherwise identification relies on file extension or surrounding context. "
            "Structurally similar to JSON but binary; a CBOR decoder is required to recover "
            "readable key/value structures.",
            "CBOR (Concise Binary Object Representation)",
        ),
        "platforms": ALL_PLATFORMS,
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"\xd9\xd9\xf7",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Optional self-described CBOR tag 55799 (RFC 8949, 3.4.6)",
                    "CBOR (Concise Binary Object Representation)",
                ),
            }
        ],
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
                "WebAuthn Level 3 spec (CBOR usage)",
                "https://www.w3.org/TR/webauthn-3/",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "Realm Database",
        "short_name": "Realm",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Mobile app local object store used as a SQLite alternative, marketed by "
            "MongoDB as Atlas Device SDK until its deprecation in 2024. A single '.realm' "
            "file stores all object data in a B+ tree of fixed-size arrays. The file holds "
            "the full schema (class/table names such as 'class_Driver', 'class_Event', "
            "'class_Photo'). The header contains two root references (top_ref[0] / "
            "top_ref[1]) used for copy-on-write commits — a flag selects the active one, "
            "the inactive one points to the previous commit and may still reference "
            "superseded data. "
            "Class names reveal which app features were in use and what data categories "
            "are present (users, locations, media, events, etc.). "
            "Some Realm databases are AES-256 encrypted — key material may be hardcoded "
            "in the app binary or kept in the Keychain/Keystore.",
            "Realm Database",
        ),
        "platforms": ["Windows", "macOS", "Linux", "iOS", "Android"],
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
                "Methods for recovering deleted data from the Realm database (Kim et al., FSI: Digital Investigation, 2022)",
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
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "Android DEX Bytecode",
        "short_name": "DEX",
        "category": "execution",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Compiled Android application bytecode executed by the Android Runtime (ART). "
            "Found as classes.dex (and classes2.dex, classes3.dex in multi-DEX apps) inside "
            "APK packages, which are ZIP archives. Decompilation can recover app logic, "
            "hardcoded API keys, credentials, server endpoints, and encryption keys. "
            "OAT/ODEX/VDEX companions show the app was compiled for the device; they do not "
            "by themselves prove it was executed (preinstalled apps are compiled when the "
            "system image is built).",
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
                    "DEX magic ('dex\\n'), followed by a 3-digit version and NUL",
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
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "Apple Disk Image (DMG)",
        "short_name": "DMG",
        "category": "disk_image",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Apple disk image format. A UDIF image consists of data blocks (raw or "
            "compressed with ADC, zlib, bzip2, LZFSE or LZMA), an XML property list holding "
            "the block map, and a 512-byte 'koly' trailer at EOF instead of a file header; raw "
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
                    "Encrypted disk image, version 1 marker in the last 8 bytes",
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
                "Encrypted DMG header versions — dmg2john (John the Ripper)",
                "https://github.com/openwall/john/blob/bleeding-jumbo/run/dmg2john.py",
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
        "last_reviewed": "2026-10-04",
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
            "disassembly.",
            "ELF Executable",
        ),
        "platforms": ["Linux", "Android", "QNX"],
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
        "extensions": [".so", ".elf", ".ko", ".o"],
        "links": [
            (
                "System V ABI — generic ELF specification (gABI)",
                "https://refspecs.linuxfoundation.org/elf/gabi4+/contents.html",
            ),
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
                "ELF shared library injection forensics (Ryan O'Neill, 2016)",
                "https://engineering.backtrace.io/2016-04-14-elf-shared-library-injection-forensics/",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "Windows Event Log (EVTX)",
        "short_name": "EVTX",
        "category": "log",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Windows structured event log format used since Vista/Server 2008, "
            "stored under C:\\Windows\\System32\\winevt\\Logs\\. "
            "A 4 KB file header is followed by 64 KB chunks ('ElfChnk') of binary XML "
            "event records; records can remain in chunk free space and be recovered. "
            "Key forensic sources: Security.evtx (logons 4624/4625, account changes, "
            "privilege use 4672), System.evtx (service installs, crashes, boot events), "
            "Microsoft-Windows-PowerShell (4103/4104 script block logging), "
            "Microsoft-Windows-Sysmon (process creation, network, file events). "
            "Event ID 1102 (Security log cleared) and 104 (in System: another log "
            "cleared) are significant anti-forensic indicators. "
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
                "Forensic analysis of Windows 10 and 11 event logs (ElcomSoft, Oleg Afonin, 2026)",
                "https://blog.elcomsoft.com/2026/02/forensic-analysis-of-windows-10-and-11-event-logs/",
            ),
            (
                "EVTX and message resolution (Velociraptor docs)",
                "https://docs.velociraptor.app/docs/forensic/event_logs/",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "JPEG Image",
        "short_name": "JPEG",
        "category": "media",
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
        "platforms": ALL_PLATFORMS,
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
        "extensions": [".jpg", ".jpeg", ".jpe", ".jfif"],
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
                "Digital Image Authentication From JPEG Headers (Kee, Johnson, Farid — IEEE TIFS 2011)",
                "https://people.csail.mit.edu/kimo/publications/jpeg",
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
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "PNG Image",
        "short_name": "PNG",
        "category": "media",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Lossless image format used for screenshots, app icons, and UI graphics. "
            "Unlike JPEG, PNG uses lossless compression — pixel data is preserved exactly. "
            "Metadata is stored in typed chunks: tEXt/zTXt for plain-text comments, "
            "iTXt for Unicode and XMP data, tIME for last-modification timestamp, "
            "eXIf for EXIF data (registered extension, part of the PNG Third Edition). "
            "The IEND chunk marks the end of the file — any data appended after IEND "
            "is forensically significant and may indicate steganography or embedded payloads. "
            "LSB steganography in IDAT pixel data is common and detectable. "
            "Screenshots typically lack camera EXIF metadata, which can help distinguish them "
            "from camera photos. The iDOT chunk is Apple-specific and undocumented. "
            "An embedded C2PA (Content Credentials) manifest, carried in the ancillary "
            "'caBX' chunk, can record generating/editing software, an IPTC Digital Source "
            "Type (a direct AI-generation/-editing signal), and a signed claim identity — "
            "PNG is a common output format for AI image generators.",
            "PNG Image",
        ),
        "platforms": ALL_PLATFORMS,
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
                "PNG format spec (W3C, Third Edition)",
                "https://www.w3.org/TR/PNG/",
            ),
            (
                "PNG text chunk extractor (dCode)",
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
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "GIF Image",
        "short_name": "GIF",
        "category": "media",
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
        "platforms": ALL_PLATFORMS,
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
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "BMP Image",
        "short_name": "BMP",
        "category": "media",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Uncompressed bitmap format common in Windows apps, legacy software, "
            "and some screenshot tools. "
            "The BITMAPFILEHEADER declares the file size at offset 2 — "
            "any discrepancy between this value and actual file size indicates "
            "appended data or truncation. BMP has no EOF marker, so trailing data "
            "detection relies entirely on this size field. "
            "Pixel data is stored bottom-up by default — row order matters for carving. "
            "Can use RLE compression for 4-bit and 8-bit images. "
            "Very rare on modern mobile devices — presence in an acquisition may itself "
            "be noteworthy. Widely used in Windows clipboard operations and legacy software.",
            "BMP Image",
        ),
        "platforms": ["Windows"],
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
                "BITMAPFILEHEADER structure (Microsoft)",
                "https://learn.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-bitmapfileheader",
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
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "TIFF Image",
        "short_name": "TIFF",
        "category": "media",
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
        "platforms": ALL_PLATFORMS,
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
            {
                "offset": 0,
                "value": b"\x49\x49\x2b\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "BigTIFF little-endian (version 43, 'II')",
                    "TIFF Image",
                ),
            },
            {
                "offset": 0,
                "value": b"\x4d\x4d\x00\x2b",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "BigTIFF big-endian (version 43, 'MM')",
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
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "WebP Image",
        "short_name": "WebP",
        "category": "media",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Modern image format used by Chrome, Android apps, and messaging platforms "
            "for compressed photos, stickers, and screenshots. "
            "Stored in a RIFF container — 'RIFF' at offset 0, 'WEBP' at offset 8. "
            "Supports lossy (VP8) and lossless (VP8L) compression, animation (ANMF frames), "
            "alpha channel, ICC color profiles, and EXIF/XMP metadata in dedicated chunks. "
            "Messaging platforms commonly use WebP for stickers. "
            "The lossless variant preserves pixel data exactly — useful for detecting re-encoding. "
            "Unknown chunks in the RIFF structure may contain application-specific or hidden data. "
            "A C2PA (Content Credentials) manifest, when present, is carried in a dedicated "
            "'C2PA' RIFF chunk and can record generating/editing software and an IPTC "
            "Digital Source Type — a direct AI-generation/-editing signal.",
            "WebP Image",
        ),
        "platforms": ALL_PLATFORMS,
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
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "HEIC / HEIF Image",
        "short_name": "HEIC/HEIF",
        "category": "media",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Default photo format on iOS 11+; Android decodes HEIF since version 9 and "
            "captures HEIC from the camera since version 10. "
            "HEIF (ISO/IEC 23008-12) is the container; HEVC (H.265) is the default codec — "
            "hence the .heic extension on Apple devices. "
            "A single file can contain multiple images, e.g. image sequences, Portrait mode "
            "depth maps, and HDR variants. On iOS, Live Photos are stored as a .heic plus a "
            "separate .mov, and burst shots as individual files. "
            "Rich EXIF, XMP, and IPTC metadata per image, including GPS, timestamps, "
            "device model, and lens information. Depth maps from Portrait mode are stored "
            "as auxiliary images with XMP metadata. "
            "When iOS transfers HEIC to Windows/Mac via cable or email, it may silently "
            "convert to JPEG — the transferred file is then a re-encoded derivative, not the original. "
            "Traditional JPEG-based image authentication algorithms do not apply to HEIC. "
            "iCloud Photo Library syncs HEIC — relevant for cloud artifact correlation. "
            "A C2PA (Content Credentials) manifest, when present, is carried in a top-level "
            "ISOBMFF 'uuid' box (a fixed extended-type UUID identifies it as C2PA, since "
            "some decoders reject unknown top-level box types outright) and can record "
            "generating/editing software and an IPTC Digital Source Type — a direct "
            "AI-generation/-editing signal.",
            "HEIC / HEIF Image",
        ),
        "platforms": ALL_PLATFORMS,
        "parser_class": "ImageParser",
        "magic": [
            {
                "offset": 4,
                "value": b"ftypheic",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ftyp box with major brand 'heic' (HEVC image)",
                    "HEIC / HEIF Image",
                ),
            },
            {
                "offset": 4,
                "value": b"ftypheix",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ftyp box with major brand 'heix' (HEVC image, Main 10 / range extensions)",
                    "HEIC / HEIF Image",
                ),
            },
            {
                "offset": 4,
                "value": b"ftyphevc",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ftyp box with major brand 'hevc' (HEVC image sequence)",
                    "HEIC / HEIF Image",
                ),
            },
            {
                "offset": 4,
                "value": b"ftyphevx",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ftyp box with major brand 'hevx' (HEVC image sequence, extended profiles)",
                    "HEIC / HEIF Image",
                ),
            },
            {
                "offset": 4,
                "value": b"ftypheim",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ftyp box with major brand 'heim' (multiview HEVC image)",
                    "HEIC / HEIF Image",
                ),
            },
            {
                "offset": 4,
                "value": b"ftypheis",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ftyp box with major brand 'heis' (scalable HEVC image)",
                    "HEIC / HEIF Image",
                ),
            },
            {
                "offset": 4,
                "value": b"ftyphevm",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ftyp box with major brand 'hevm' (multiview HEVC image sequence)",
                    "HEIC / HEIF Image",
                ),
            },
            {
                "offset": 4,
                "value": b"ftyphevs",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ftyp box with major brand 'hevs' (scalable HEVC image sequence)",
                    "HEIC / HEIF Image",
                ),
            },
            {
                "offset": 4,
                "value": b"ftypmif1",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ftyp box with major brand 'mif1' (generic HEIF image)",
                    "HEIC / HEIF Image",
                ),
            },
            {
                "offset": 4,
                "value": b"ftypmsf1",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ftyp box with major brand 'msf1' (generic HEIF image sequence)",
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
                "HEIF in Android (AOSP)",
                "https://source.android.com/docs/core/camera/heif",
            ),
            (
                "Forensic considerations for the High Efficiency Image File Format (McKeown & Russell, IEEE Cyber Security 2020)",
                "https://doi.org/10.1109/CyberSecurity49315.2020.9138890",
            ),
            (
                "Forensic considerations for HEIF — open-access preprint (arXiv)",
                "https://arxiv.org/abs/2006.08060",
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
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "JPEG XL Image",
        "short_name": "JPEG XL",
        "category": "media",
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
            "iPhone ProRAW (iOS 18+) can store DNG files with JPEG XL-compressed image "
            "data (DNG 1.7) — these keep the .dng extension. "
            "Forensically relevant: timestamp and GPS metadata in EXIF boxes, "
            "lossless re-encoding makes tampering detection harder than with JPEG, "
            "and the format's novelty means older tools may fail to parse it. "
            "A C2PA (Content Credentials) manifest, when present in the box-form container, "
            "is a top-level JUMBF superbox — the bare codestream variant cannot carry one at "
            "all. Can record generating/editing software and an IPTC Digital Source Type — "
            "a direct AI-generation/-editing signal.",
            "JPEG XL Image",
        ),
        "platforms": ALL_PLATFORMS,
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
                "ISO/IEC 18181-1:2024 — JPEG XL core coding system",
                "https://www.iso.org/standard/85066.html",
            ),
            (
                "JPEG XL format overview (libjxl docs)",
                "https://github.com/libjxl/libjxl/blob/main/doc/format_overview.md",
            ),
            (
                "JPEG XL file format overview (Library of Congress)",
                "https://www.loc.gov/preservation/digital/formats/fdd/fdd000538.shtml",
            ),
            (
                "Supporting JPEG XL compression in Apple ProRAW capture",
                "https://juniperphoton.substack.com/p/supporting-jpeg-xl-compression-in",
            ),
            (
                "C2PA Technical Specification (Content Credentials)",
                "https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "AVIF Image",
        "short_name": "AVIF",
        "category": "media",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "AV1 Image File Format — a royalty-free still-image format based on the AV1 video "
            "codec, defined by AOM on top of HEIF (ISO/IEC 23008-12) with MIAF constraints "
            "(ISO/IEC 23000-22). "
            "Adopted by Chrome (2020), Firefox (2021), Safari (2022), Android 12 (2021), "
            "and increasingly by streaming and social media platforms for "
            "bandwidth-efficient image delivery. "
            "Like HEIC, AVIF uses the ISOBMFF ftyp box structure; the major brand "
            "'avif' or 'avis' (for image sequences / animations) follows 'ftyp' at offset 4. "
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
        "platforms": ALL_PLATFORMS,
        "parser_class": "ImageParser",
        "magic": [
            {
                "offset": 4,
                "value": b"ftypavif",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ftyp box with major brand 'avif' (AVIF image)",
                    "AVIF Image",
                ),
            },
            {
                "offset": 4,
                "value": b"ftypavis",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ftyp box with major brand 'avis' (AVIF image sequence / animation)",
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
                "HEIF — base format of AVIF (Library of Congress)",
                "https://www.loc.gov/preservation/digital/formats/fdd/fdd000525.shtml",
            ),
            (
                "ISOBMFF — ISO/IEC 14496-12:2026 base media file format",
                "https://www.iso.org/standard/85596.html",
            ),
            (
                "C2PA Technical Specification (Content Credentials)",
                "https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "Apple ATX Texture Archive",
        "short_name": "ATX",
        "category": "media",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Apple AAPL texture container wrapping ASTC image payloads, including "
            "some LZFSE-compressed variants. Found in iOS and macOS UI caches such as "
            "app switcher snapshots, wallpapers, PosterBoard snapshots, avatars, widgets, "
            "camera thumbnails, and app-generated interface imagery. Decoding can expose "
            "visible user interface state or cached imagery that standard image viewers "
            "miss because the file is not a JPEG/PNG container.",
            "Apple ATX Texture Archive",
        ),
        "platforms": ["macOS", "iOS"],
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
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "Khronos KTX 1.1 Texture",
        "short_name": "KTX",
        "category": "media",
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
        "platforms": ALL_PLATFORMS,
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
        "last_reviewed": "2026-10-04",
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
            "device model, an anonymised per-device identifier (CrashReporter Key, reset "
            "when the device is erased), incident UUID, process launch time, "
            "precise crash timestamp, exception type and reason, "
            "and thread states with stack traces. "
            "Forensically relevant for: establishing a precise timeline of app crashes, "
            "identifying exploitation attempts or repeated crashes of security-relevant apps, "
            "detecting jailbreak-related crashes, and corroborating user activity. "
            "Stored on iOS under /var/mobile/Library/Logs/CrashReporter/ (accessible via "
            "Settings → Privacy (& Security) → Analytics & Improvements → Analytics Data) and "
            "on macOS under ~/Library/Logs/DiagnosticReports/ and /Library/Logs/DiagnosticReports/.",
            "iOS Crash Report",
        ),
        "platforms": ["macOS", "iOS"],
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
        "last_reviewed": "2026-10-04",
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
            "(e.g. browser bookmark and saved-login files), "
            "data exports from online services, "
            "location data in GeoJSON format, and structured log files (JSONL/NDJSON). "
            "Many apps store sensitive data in plaintext JSON without encryption — "
            "credentials, tokens, and personal data are frequently found in app data directories. "
            "No magic bytes — identification relies on file extension or content inspection "
            "for the leading '{' or '[' character.",
            "JSON Document",
        ),
        "platforms": ALL_PLATFORMS,
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
                "JSON Lines format",
                "https://jsonlines.org/",
            ),
            (
                "Browser artifacts — JSON files in forensics (HackTricks)",
                "https://hacktricks.wiki/en/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/browser-artifacts.html",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "LevelDB Database",
        "short_name": "LevelDB",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Key-value store used by Chrome/Chromium (IndexedDB, localStorage, sessionStorage), "
            "Electron-based desktop apps, "
            "and many Android and iOS apps for caches and app state. "
            "LevelDB is not a single file but a directory containing: "
            "CURRENT and MANIFEST-###### (metadata), "
            ".ldb/.sst files (sorted string tables with key-value data, Snappy-compressed blocks), "
            "and ######.log files (write-ahead log with recent mutations). "
            "All files must be parsed together for a complete view. "
            "Deleted or overwritten records survive in .log files with sequence numbers "
            "and a deleted/live state flag — deleted data is often recoverable. "
            "Values are frequently serialized in the V8/Blink format (Chromium IndexedDB) or as JSON. "
            "Chromium's IndexedDB, Local Storage and Session Storage are separate LevelDB stores "
            "holding web app state and cached API responses — "
            "common sources of social media and messaging artifacts.",
            "LevelDB Database",
        ),
        "platforms": ALL_PLATFORMS,
        "parser_class": "LeveldbParser",
        "magic": [
            {
                "offset": None,
                "value": b"\x57\xfb\x80\x8b\x24\x75\x47\xdb",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Table file (.ldb/.sst) footer magic 0xdb4775248b80fb57 (little-endian) in the last 8 bytes",
                    "LevelDB Database",
                ),
            }
        ],
        "extensions": [".ldb", ".sst", ".log"],
        "links": [
            (
                "LevelDB format specification (Google)",
                "https://github.com/google/leveldb/blob/main/doc/impl.md",
            ),
            (
                "LevelDB table format (Google)",
                "https://github.com/google/leveldb/blob/main/doc/table_format.md",
            ),
            (
                "Hang on! That's not SQLite! Chrome, Electron and LevelDB (CCL, Alex Caithness, 2020)",
                "https://www.cclsolutionsgroup.com/post/hang-on-thats-not-sqlite-chrome-electron-and-leveldb",
            ),
            (
                "IndexedDB on Chromium (CCL, Alex Caithness, 2020)",
                "https://www.cclsolutionsgroup.com/post/indexeddb-on-chromium",
            ),
            (
                "Chromium Session Storage and Local Storage (CCL, Alex Caithness, 2021)",
                "https://www.cclsolutionsgroup.com/post/chromium-session-storage-and-local-storage",
            ),
            (
                "MIC: Memory analysis of IndexedDB data on Chromium-based applications (Jeong, Lee, Park — FSI: Digital Investigation 2024)",
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
        "last_reviewed": "2026-10-04",
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
            "Has no magic bytes, so it cannot be auto-detected. "
            "The store is append-only between rewrites: setting a key appends a new entry "
            "rather than editing the old one, so superseded values and removed keys "
            "(recorded as a zero-length value, not a real deletion) remain recoverable in "
            "file order until the next full rewrite. Optionally AES-CFB encrypted, with the "
            "key stored by neither file — decryptable if the app's key is known.",
            "MMKV Key-Value Store",
        ),
        "platforms": ["Windows", "macOS", "Linux", "iOS", "Android"],
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
                "You down with MMKV? (LEAPPs Blog, Alexis Brignoni)",
                "https://leapps.org/blog-post?post=2026-09-04-you-down-with-mmkv",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
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
            "subsystems, and categories; how far back it reaches depends on log volume, as "
            "storage is limited by size rather than by a fixed period. "
            "Key forensic artifacts: app launches and terminations, lock/unlock and screen events, "
            "network connections, Siri activations, biometric authentication attempts, "
            "USB/external media connections, userActionEvent entries (explicit user interactions), "
            "lossEvent entries (log buffer overflow gaps), and crash precursors. "
            "Values logged as private are redacted at write time (masked or hashed) unless "
            "private-data logging was enabled; a binary acquisition does not recover them. "
            "Full string resolution requires uuidtext/, timesync/, and DSC — "
            "without them, message text falls back to raw format-string fragments.",
            "Apple Unified Log Archive (logarchive)",
        ),
        "platforms": ["macOS", "iOS"],
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
                "iOS Unified Logs research (ios-unifiedlogs.com, Lionel Notari)",
                "https://www.ios-unifiedlogs.com/",
            ),
            (
                "Thesis Friday — Unified Log analysis series (Tim Korver)",
                "https://thesisfriday.com/",
            ),
            (
                "Reviewing macOS Unified Logs (Mandiant, Alexander Holcomb, 2022)",
                "https://cloud.google.com/blog/topics/threat-intelligence/reviewing-macos-unified-logs/",
            ),
            (
                "Logs Unite! — forensic analysis of Apple Unified Logs (Sarah Edwards)",
                "https://github.com/mac4n6/Presentations/blob/master/Logs%20Unite!%20-%20Forensic%20Analysis%20of%20Apple%20Unified%20Logs/LogsUnite.pdf",
            ),
            (
                "Apple Unified Logging and Activity Tracing formats (libyal, Joachim Metz)",
                "https://github.com/libyal/dtformats/blob/main/documentation/Apple%20Unified%20Logging%20and%20Activity%20Tracing%20formats.asciidoc",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
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
            "HFS+ and APFS transparent file compression also uses LZFSE/LZVN — the file's "
            "content is then stored compressed in a resource fork or extended attribute, "
            "not in the data stream. "
            "Also used in Apple Archive (.aar) format since macOS Big Sur.",
            "LZFSE Compressed Data",
        ),
        "platforms": ["macOS", "iOS"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"\x62\x76\x78\x32",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "LZFSE magic ('bvx2', compressed block with compressed tables)",
                    "LZFSE Compressed Data",
                ),
            },
            {
                "offset": 0,
                "value": b"bvx1",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "LZFSE magic ('bvx1', compressed block with uncompressed tables)",
                    "LZFSE Compressed Data",
                ),
            },
            {
                "offset": 0,
                "value": b"bvxn",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "LZVN-compressed block ('bvxn')",
                    "LZFSE Compressed Data",
                ),
            },
            {
                "offset": 0,
                "value": b"bvx-",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Uncompressed block ('bvx-')",
                    "LZFSE Compressed Data",
                ),
            },
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
        "last_reviewed": "2026-10-04",
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
            "in a single file, preceded by a fat_header with magic 0xCAFEBABE — the same "
            "magic as Java class files, so the following bytes (architecture count vs. "
            "class file version) must be checked to tell them apart.",
            "Mach-O Executable",
        ),
        "platforms": ["macOS", "iOS"],
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
                    "Fat/Universal Binary — contains multiple architecture slices (same magic as Java class files)",
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
            {
                "offset": 0,
                "value": b"\xfe\xed\xfa\xce",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Mach-O 32-bit big-endian",
                    "Mach-O Executable",
                ),
            },
        ],
        "extensions": [".dylib", ".o"],
        "links": [
            (
                "Apple mach-o/loader.h (XNU source — header and load command definitions)",
                "https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h",
            ),
            (
                "Apple developer docs — Mach-O format reference (archived)",
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
                "So Macho — a look at Apple executable files (Hexiosec, Scott Lester, 2020)",
                "https://hexiosec.com/blog/macho-files/",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "MP4 Video",
        "short_name": "MP4",
        "category": "media",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Versatile ISOBMFF container format (ISO/IEC 14496-12) for video recordings, "
            "screen captures, and downloaded media. "
            "The ftyp box at offset 4 identifies the specific brand (mp42, isom, M4V, etc.). "
            "The mvhd (Movie Header) box contains creation and modification timestamps "
            "in QuickTime epoch (seconds since 1904-01-01 UTC — not Unix epoch); despite "
            "the specification, many cameras store local time instead of UTC. "
            "The udta (User Data) box may contain device make/model, recording software, "
            "and GPS coordinates (e.g. from GoPro, DJI, dashcams, smartphones). "
            "Metadata changes when a video is re-encoded or edited — "
            "altered mvhd timestamps and missing udta boxes are indicators of processing. "
            "Screen recordings from iOS and Android are commonly stored as MP4.",
            "MP4 Video",
        ),
        "platforms": ALL_PLATFORMS,
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
                "ISOBMFF — ISO/IEC 14496-12:2026 base media file format",
                "https://www.iso.org/standard/85596.html",
            ),
            (
                "MP4 file format spec (ISO/IEC 14496-14)",
                "https://www.iso.org/standard/79110.html",
            ),
            (
                "QuickTime date/time tags — UTC vs. local time (ExifTool documentation)",
                "https://exiftool.org/TagNames/QuickTime.html",
            ),
            (
                "MPEG-4 Video Authentication Using File Structure and Metadata (J. R. Hall, NCMF thesis, 2015)",
                "https://www.ucdenver.edu/docs/librariesprovider27/ncmf-docs/theses/hall_thesis_fall2015.pdf",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "MOV Video (QuickTime)",
        "short_name": "MOV",
        "category": "media",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Apple's native video container format — the QuickTime File Format, on which "
            "ISOBMFF/MPEG-4 is based. "
            "iOS camera recordings — including the video component of Live Photos — "
            "are stored as .mov files. macOS screen recordings also use MOV. "
            "Identified by an ftyp box at offset 4 with the 'qt  ' brand; the ftyp box is "
            "optional in QuickTime, so older files begin directly with a moov, mdat or wide atom. "
            "Timestamps use the QuickTime epoch (seconds since 1904-01-01 UTC); many non-Apple "
            "cameras store local time instead, and iOS additionally records "
            "com.apple.quicktime.creationdate with a time-zone offset. "
            "GPS coordinates are stored as Apple-specific metadata keys "
            "('com.apple.quicktime.location.ISO6709') in the metadata atom (meta/keys/ilst). "
            "Device make/model, software version, and creation date are commonly present. "
            "Files processed by QuickTime Player, iMovie, or Final Cut Pro will show "
            "altered timestamps and may lack original device metadata — "
            "a key indicator of post-processing.",
            "MOV Video (QuickTime)",
        ),
        "platforms": ["macOS", "iOS"],
        "parser_class": "MediaParser",
        "magic": [
            {
                "offset": 4,
                "value": b"ftypqt  ",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ftyp box with QuickTime brand 'qt  '",
                    "MOV Video (QuickTime)",
                ),
            },
            {
                "offset": 4,
                "value": b"moov",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Older QuickTime file without ftyp, starting with a movie atom ('moov')",
                    "MOV Video (QuickTime)",
                ),
            },
            {
                "offset": 4,
                "value": b"mdat",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Older QuickTime file without ftyp, starting with a media data atom ('mdat')",
                    "MOV Video (QuickTime)",
                ),
            },
            {
                "offset": 4,
                "value": b"wide",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Older QuickTime file without ftyp, starting with a 'wide' placeholder atom",
                    "MOV Video (QuickTime)",
                ),
            },
        ],
        "extensions": [".mov"],
        "links": [
            (
                "QuickTime File Format specification (Apple)",
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
                "Geolocation metadata in iOS and Android video files (addpipe, 2025)",
                "https://blog.addpipe.com/geolocation-metadata-ios-android-video-files/",
            ),
            (
                "ExifTool QuickTime tags reference",
                "https://exiftool.org/TagNames/QuickTime.html",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "AVI Video",
        "short_name": "AVI",
        "category": "media",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Legacy RIFF-based video container format common in older Windows recordings, "
            "CCTV/DVR systems, dashcams, and surveillance cameras. "
            "RIFF header at offset 0, 'AVI ' identifier at offset 8. "
            "AVI has no native creation timestamp fields — recording time must be inferred "
            "from filesystem metadata or INFO chunk strings. "
            "INFO chunks (ICRD, IDIT, ISFT, INAM) and an IDIT chunk in the header list may "
            "contain creation date/time, recording software, device info, and comments — "
            "content varies by device. "
            "The stream header (strh) fourcc identifies the codec, which can fingerprint "
            "the recording device or software. "
            "Files edited with AVIDemux, VirtualDub, or FFmpeg leave software-specific "
            "structures (e.g. JUNK chunks, additional LIST chunks) — a forensic indicator "
            "of post-processing. "
            "Standard RIFF is limited to ~4GB — larger files require OpenDML "
            "extension (AVI 2.0).",
            "AVI Video",
        ),
        "platforms": ["Windows"],
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
                "Forensic analysis of video file formats (Gloe, Fischer, Kirchner — DFRWS EU 2014)",
                "https://dfrws.org/wp-content/uploads/2019/06/2014_EU_paper-forensic_analysis_of_video_file_formats.pdf",
            ),
            (
                "RIFF INFO tags in AVI (ExifTool)",
                "https://exiftool.org/TagNames/RIFF.html",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "MKV Video (Matroska)",
        "short_name": "MKV",
        "category": "media",
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
        "platforms": ALL_PLATFORMS,
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
        "extensions": [".mkv", ".mka", ".mks", ".mk3d"],
        "links": [
            (
                "Matroska format specification (RFC 9559)",
                "https://datatracker.ietf.org/doc/rfc9559/",
            ),
            (
                "EBML specification (RFC 8794)",
                "https://datatracker.ietf.org/doc/rfc8794/",
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
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "WebM Video",
        "short_name": "WebM",
        "category": "media",
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
        "platforms": ALL_PLATFORMS,
        "parser_class": "MediaParser",
        "magic": [
            {
                "offset": None,
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
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "3GP / 3G2 Video",
        "short_name": "3GP",
        "category": "media",
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
            "and legacy Android and feature-phone camera recordings. "
            "Some devices stored 3GP files with an .mp4 extension.",
            "3GP / 3G2 Video",
        ),
        "platforms": ALL_PLATFORMS,
        "parser_class": "MediaParser",
        "magic": [
            {
                "offset": 4,
                "value": b"ftyp3g",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ftyp box with a 3GPP/3GPP2 major brand ('3gp…', '3g2…', '3ge…' etc.)",
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
                "Forensic analysis of video file formats (Gloe, Fischer, Kirchner — DFRWS EU 2014)",
                "https://dfrws.org/wp-content/uploads/2019/06/2014_EU_paper-forensic_analysis_of_video_file_formats.pdf",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "MP3 Audio",
        "short_name": "MP3",
        "category": "media",
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
        "platforms": ALL_PLATFORMS,
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
            {
                "offset": 0,
                "value": b"\xff\xfa",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "MPEG-1 Layer 3 sync word with CRC (MP3 without ID3 header)",
                    "MP3 Audio",
                ),
            },
            {
                "offset": 0,
                "value": b"\xff\xf3",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "MPEG-2 Layer 3 sync word (MP3 without ID3 header)",
                    "MP3 Audio",
                ),
            },
            {
                "offset": 0,
                "value": b"\xff\xf2",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "MPEG-2 Layer 3 sync word with CRC (MP3 without ID3 header)",
                    "MP3 Audio",
                ),
            },
            {
                "offset": 0,
                "value": b"\xff\xe3",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "MPEG-2.5 Layer 3 sync word (MP3 without ID3 header)",
                    "MP3 Audio",
                ),
            },
            {
                "offset": 0,
                "value": b"\xff\xe2",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "MPEG-2.5 Layer 3 sync word with CRC (MP3 without ID3 header)",
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
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "WAV Audio",
        "short_name": "WAV",
        "category": "media",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "RIFF-based audio container, typically holding uncompressed PCM, used for voice "
            "recordings, call recordings, dictation devices, bodycams, and professional recorders. "
            "RIFF INFO chunks may contain title, creation date, originator, and software. "
            "The Broadcast Wave Format (BWF) extension adds a 'bext' chunk with: "
            "originator name and reference, origination date and time (YYYY-MM-DD / HH:MM:SS; "
            "time zone not defined by the specification), "
            "TimeReference (64-bit sample count since midnight — precise recording timestamp), "
            "and a CodingHistory field describing the encoding chain. "
            "No native encryption — audio is directly accessible. "
            "Standard RIFF is limited to ~4GB; larger files use RF64 extension.",
            "WAV Audio",
        ),
        "platforms": ALL_PLATFORMS,
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
                "offset": 0,
                "value": b"RF64",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "RF64 header (WAV/BWF larger than 4 GB)",
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
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "M4A Audio",
        "short_name": "M4A",
        "category": "media",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "ISOBMFF audio-only container (ftyp brand 'M4A ') typically containing "
            "AAC (lossy) or ALAC (lossless) audio. "
            "Used for iTunes/Apple Music purchases and downloads, iOS Voice Memos, "
            "and GarageBand exports. "
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
        "platforms": ["macOS", "iOS"],
        "parser_class": "MediaParser",
        "magic": [
            {
                "offset": 4,
                "value": b"ftypM4A ",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ftyp box with Apple audio major brand 'M4A '",
                    "M4A Audio",
                ),
            },
            {
                "offset": 4,
                "value": b"ftypM4B ",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ftyp box with Apple audiobook major brand 'M4B '",
                    "M4A Audio",
                ),
            },
            {
                "offset": 4,
                "value": b"ftypM4P ",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ftyp box with Apple protected audio major brand 'M4P '",
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
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "AAC Audio",
        "short_name": "AAC",
        "category": "media",
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
        "platforms": ALL_PLATFORMS,
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
            {
                "offset": 0,
                "value": b"\xff\xf0",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ADTS AAC sync word — MPEG-4 AAC, with CRC",
                    "AAC Audio",
                ),
            },
            {
                "offset": 0,
                "value": b"\xff\xf8",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ADTS AAC sync word — MPEG-2 AAC, with CRC",
                    "AAC Audio",
                ),
            },
            {
                "offset": 0,
                "value": b"ADIF",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ADIF header identifier",
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
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "FLAC Audio",
        "short_name": "FLAC",
        "category": "media",
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
        "platforms": ALL_PLATFORMS,
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
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "OGG Audio",
        "short_name": "OGG",
        "category": "media",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Open bitstream container supporting multiple codecs — forensically "
            "encountered as Ogg Vorbis (music, games), Ogg Opus (voice messages), "
            "and Ogg FLAC (lossless audio). "
            "All OGG streams begin with the OggS capture pattern (0x4F676753). "
            "Ogg Opus is the dominant format for voice messages in modern messaging apps: "
            "WhatsApp stores voice notes as .opus (PTT-YYYYMMDD-WANNNN.opus — "
            "date and a per-day counter encoded in the filename, no time of day), "
            "Telegram stores as .ogg, both using Opus codec at 16-32 kbps. "
            "Vorbis comment metadata (same key-value format as FLAC) may contain "
            "title, artist, date, encoder, and custom fields. "
            "No native embedded timestamps — recording time inferred from filesystem "
            "metadata or messaging app databases.",
            "OGG Audio",
        ),
        "platforms": ALL_PLATFORMS,
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
                "Ogg encapsulation for the Opus audio codec (RFC 7845)",
                "https://www.rfc-editor.org/rfc/rfc7845.html",
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
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "Opus Audio",
        "short_name": "Opus",
        "category": "media",
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
            "metadata, messaging app databases, or the WhatsApp filename convention "
            "(PTT-YYYYMMDD-WANNNN.opus — date only, no time of day).",
            "Opus Audio",
        ),
        "platforms": ALL_PLATFORMS,
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
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "WMA Audio",
        "short_name": "WMA",
        "category": "media",
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
                    "ASF Header Object GUID (shared with WMV; distinguished by stream type)",
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
                "ASF specification (Microsoft)",
                "https://download.microsoft.com/download/7/9/0/790fecaa-f64a-4a5e-a430-0bccdab3f1b4/ASF_Specification.doc",
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
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "AMR Audio",
        "short_name": "AMR",
        "category": "media",
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
        "platforms": ALL_PLATFORMS,
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
            {
                "offset": 0,
                "value": b"#!AMR_MC1.0\n",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "AMR-NB multichannel file magic ('#!AMR_MC1.0\\n')",
                    "AMR Audio",
                ),
            },
            {
                "offset": 0,
                "value": b"#!AMR-WB_MC1.0\n",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "AMR-WB multichannel file magic ('#!AMR-WB_MC1.0\\n')",
                    "AMR Audio",
                ),
            },
        ],
        "extensions": [".amr", ".awb"],
        "links": [
            (
                "AMR/AMR-WB storage format (RFC 4867, section 5)",
                "https://www.rfc-editor.org/rfc/rfc4867.html",
            ),
            (
                "AMR codec specification (3GPP TS 26.071)",
                "https://www.3gpp.org/ftp/Specs/archive/26_series/26.071/",
            ),
            (
                "Adaptive Multi-Rate audio codec (Wikipedia)",
                "https://en.wikipedia.org/wiki/Adaptive_Multi-Rate_audio_codec",
            ),
            (
                "Identification of AMR decompressed audio (Luo, Yang, Huang — Digital Signal Processing 2015)",
                "https://www.sciencedirect.com/science/article/abs/pii/S1051200414003200",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
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
            "and some iOS/Android app data directories.",
            "MessagePack",
        ),
        "platforms": ALL_PLATFORMS,
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
        "last_reviewed": "2026-10-04",
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
            "some Biome streams (e.g. App Intents, embedded in protobuf records), "
            "and many app-specific data files. "
            "Custom file extensions are common (.sfl, .db, .archive) — "
            "a bplist header does not rule out NSKeyedArchiver encoding. "
            "Parsing requires a two-step process: first parse the bplist structure, "
            "then resolve UID references to reconstruct the object graph.",
            "NSKeyedArchiver",
        ),
        "platforms": ["macOS", "iOS"],
        "parser_class": "PlistParser",
        "magic": [
            {
                "offset": None,
                "value": b"$archiver",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "'$archiver' key inside a binary plist (bplist00) — not detectable from the header",
                    "NSKeyedArchiver",
                ),
            }
        ],
        "extensions": [".plist", ".sfl", ".archive"],
        "links": [
            (
                "NSKeyedArchiver files — what are they, and how can I use them? (CCL, Alex Caithness, 2012)",
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
                "Analyzing iOS Biome AppIntent files — NSKeyedArchiver in practice (Blue Crew Forensics, John Hyla, 2022)",
                "https://bluecrewforensics.com/2022/03/07/ios-app-intents/",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
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
            "Presence of an .odex/.oat file shows the app was compiled for the device; "
            "it does not by itself prove execution (preinstalled apps are compiled when "
            "the system image is built). "
            "Prior to Android 8.0, the OAT file itself contained an embedded DEX copy — "
            "useful for recovering app code when the original APK is absent. "
            "Stored under /data/app/<package>/oat/<arch>/ for user apps, "
            "in an oat/ directory next to preinstalled system apps, "
            "and in /data/dalvik-cache/. "
            "File timestamps of these artifacts indicate when the app was last "
            "installed or (re)compiled.",
            "Android OAT/ART",
        ),
        "platforms": ["Android"],
        "parser_class": None,
        "magic": [
            {
                "offset": None,
                "value": b"oat\n",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "OAT header magic inside the ELF 'oatdata' section (.oat/.odex files are ELF binaries)",
                    "Android OAT/ART",
                ),
            },
            {
                "offset": 0,
                "value": b"vdex",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "VDEX file magic",
                    "Android OAT/ART",
                ),
            },
            {
                "offset": 0,
                "value": b"art\n",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ART image file magic",
                    "Android OAT/ART",
                ),
            },
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
                "Android compilation process and binaries (APK, DEX, OAT, ODEX, VDEX, ART)",
                "https://github.com/connglli/blog-notes/issues/35",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
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
            "xref count > 1 indicates the document was saved multiple times — except in "
            "linearized ('Fast Web View') files, which have two xref sections from the start; "
            "this structural record is harder to falsify than metadata fields. "
            "Earlier content versions (pre-redaction text, prior dates) may be "
            "recoverable from superseded objects in the same file. "
            "Can embed files, JavaScript (malware vector), digital signatures, "
            "and hidden layers (Optional Content Groups). "
            "Absent metadata on institutional documents is itself a fraud indicator.",
            "PDF Document",
        ),
        "platforms": ALL_PLATFORMS,
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
                "ISO 32000-2:2020 — PDF 2.0 specification (free via PDF Association)",
                "https://pdfa.org/resource/iso-32000-2/",
            ),
            (
                "PDF metadata forensics — field-by-field reference (HTPBE, 2026)",
                "https://htpbe.tech/blog/pdf-metadata-fields-complete-reference",
            ),
            (
                "PDF forensics and XMP metadata streams (Meridian Discovery)",
                "https://www.meridiandiscovery.com/articles/pdf-forensic-analysis-xmp-metadata/",
            ),
            (
                "PDF forensics and the metadata conundrum (PDF Association, Cherie Ekholm, 2025)",
                "https://pdfa.org/presentation/pdf-forensics-and-the-metadata-conundrum/",
            ),
            (
                "ExifTool — PDF metadata extraction",
                "https://exiftool.org/",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
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
            "minimum OS version, the app's own URL schemes (CFBundleURLTypes) and the "
            "schemes it queries in other apps (LSApplicationQueriesSchemes), "
            "privacy usage descriptions (NSCamera/NSLocation/NSMicrophoneUsageDescription), "
            "background modes (UIBackgroundModes), and required device capabilities — "
            "key fields for app profiling and capability assessment. "
            "Dates are stored as ISO 8601 strings. "
            "Functionally equivalent to binary plist (bplist). "
            "Identified by XML declaration and Apple plist DOCTYPE. "
            "Some plists use JSON format in rare cases. "
            "Hardcoded API keys or credentials in Info.plist are a common "
            "security finding in app analysis.",
            "Property List (XML plist)",
        ),
        "platforms": ["macOS", "iOS"],
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
            },
            {
                "offset": None,
                "value": b"<!DOCTYPE plist",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Apple plist DOCTYPE after the XML declaration — distinguishes a plist from generic XML",
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
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "Protocol Buffers (protobuf)",
        "short_name": "protobuf",
        "category": "serialization",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Google's binary serialization format used by Android system services, "
            "Chrome/Edge/Brave (e.g. BLOBs in the Network Action Predictor database), "
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
            "Nested messages, repeated fields, and oneof unions are common structures.",
            "Protocol Buffers (protobuf)",
        ),
        "platforms": ALL_PLATFORMS,
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
                "In the protobuf: web browser artifacts using Google's data interchange format (IBM X-Force, Chris Tappin, 2025)",
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
        "last_reviewed": "2026-10-04",
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
            "timestamps of programs present or executed on the system (an entry alone "
            "does not prove execution — corroborate with other artifacts). "
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
                "Investigating Windows Registry (ElcomSoft, Oleg Afonin, 2026)",
                "https://blog.elcomsoft.com/2026/02/investigating-windows-registry/",
            ),
            (
                "AmCache Analysis (ANSSI, Blanche Lagny, 2019)",
                "https://www.ssi.gouv.fr/publication/amcache-analysis/",
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
        "last_reviewed": "2026-10-04",
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
            "Current devices hold 300+ Biome stream folders, dozens of them forensically "
            "relevant, covering: app focus/usage (replaces KnowledgeC), "
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
        "platforms": ["macOS", "iOS"],
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
                "iOS 16 Biome breakdown Part 1 — SEGB format (D20 Forensics, 2022)",
                "https://blog.d204n6.com/2022/09/ios-16-now-you-c-it-now-you-dont.html",
            ),
            (
                "Understanding and decoding the newest iOS SEGB format (Cellebrite, 2023)",
                "https://cellebrite.com/en/blog/understanding-and-decoding-the-newest-ios-segb-format/",
            ),
            (
                "Analyzing iOS Biome AppIntent files (Blue Crew Forensics, John Hyla, 2022)",
                "https://bluecrewforensics.com/2022/03/07/ios-app-intents/",
            ),
            (
                "Bringing it back with Biome data (Magnet Forensics, 2023)",
                "https://www.magnetforensics.com/blog/bringing-it-back-with-biome-data/",
            ),
            (
                "84 Streams Later: Exploring the Evolution of Apple Biome in iOS (Mattia Epifani, 2026)",
                "https://blog.digital-forensics.it/2026/07/84-streams-later-exploring-evolution-of.html",
            ),
            (
                "Beyond the C — SEGB and Biome Forensics with crush (beBinary)",
                "https://bebinary4n6.blogspot.com/2026/05/beyond-c-segb-and-biome-forensics-with.html",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "Android Sparse Image",
        "short_name": "simg",
        "category": "disk_image",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Android's space-efficient flash image format that replaces empty and "
            "repetitive blocks with metadata chunks, reducing image size for "
            "transmission and fastboot flashing. "
            "Used in factory images (Google, Samsung, OEM), OTA update packages, "
            "and custom ROM distributions. "
            "28-byte header (magic 0xED26FF3A) specifies block size (typically 4096 bytes), "
            "total output blocks, and chunk count. "
            "Four chunk types: RAW (data), FILL (repeated 4-byte pattern), "
            "DONT_CARE (empty/unwritten blocks), and CRC32 (checksum). "
            "Must be converted to raw (e.g. ext4/f2fs) before mounting or forensic analysis. "
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
                "https://android.googlesource.com/platform/system/core/+/refs/heads/main/libsparse/",
            ),
            (
                "Android sparse image format explained (2net.co.uk, csimmonds, 2014)",
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
        "last_reviewed": "2026-10-04",
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
            "(2) Freeblocks and page slack space — deleted records within active pages "
            "may survive in freeblocks or partially in the unallocated area below the "
            "live cell pointer array. "
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
        "platforms": ALL_PLATFORMS,
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
                "Forensic analysis of SQLite databases: free lists, WAL, unallocated space and carving (Belkasoft)",
                "https://belkasoft.com/sqlite-analysis",
            ),
            (
                "Forensic examination of SQLite Write Ahead Log files (Sanderson Forensics)",
                "https://sqliteforensictoolkit.com/forensic-examination-of-sqlite-write-ahead-log-wal-files/",
            ),
            (
                "FQLite — deleted SQLite record recovery (Pawlaszczyk; see 'Making the Invisible Visible', 2021)",
                "https://github.com/pawlaszczyk/fqlite",
            ),
            (
                "A comprehensive analysis and evaluation of SQLite deleted record recovery techniques: a survey (Lee et al., FSI: Digital Investigation 2025)",
                "https://www.sciencedirect.com/science/article/abs/pii/S2666281725001714",
            ),
            (
                "What Hides in the WAL — SQLite Forensics with crush (beBinary)",
                "https://bebinary4n6.blogspot.com/2026/05/what-hides-in-wal-sqlite-forensics-with.html",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
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
            "Without the companion database, frames can still be decoded, but column "
            "names are only available from the schema. "
            "See SQLite Database entry for full forensic context.",
            "SQLite WAL",
        ),
        "platforms": ALL_PLATFORMS,
        "parser_class": "SQLiteWALParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\x37\x7f\x06\x82",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "SQLite WAL magic 0x377F0682 (checksums computed little-endian)",
                    "SQLite WAL",
                ),
            },
            {
                "offset": 0,
                "value": b"\x37\x7f\x06\x83",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "SQLite WAL magic 0x377F0683 (checksums computed big-endian)",
                    "SQLite WAL",
                ),
            },
        ],
        "extensions": ["-wal"],
        "links": [
            (
                "SQLite WAL file format (SQLite file format specification, section 4)",
                "https://www.sqlite.org/fileformat2.html#walformat",
            ),
            (
                "SQLite WAL-mode file format — WAL-index and locking",
                "https://www.sqlite.org/walformat.html",
            ),
            (
                "Forensic examination of SQLite Write Ahead Log files (Sanderson Forensics)",
                "https://sqliteforensictoolkit.com/forensic-examination-of-sqlite-write-ahead-log-wal-files/",
            ),
            (
                "What Hides in the WAL — SQLite Forensics with crush (beBinary)",
                "https://bebinary4n6.blogspot.com/2026/05/what-hides-in-wal-sqlite-forensics-with.html",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "SQLite Rollback Journal",
        "short_name": "SQLite Journal",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Legacy (pre-WAL) companion file for a SQLite database in DELETE/TRUNCATE/"
            "PERSIST journal_mode. Holds the pre-transaction content of every page "
            "a still-open or crash-interrupted transaction touched, so SQLite can roll "
            "back an incomplete write on next open. Unlike -wal, this is the *old* page "
            "content, not the current one — forensically it means the opposite: the base "
            "database file's current on-disk pages for a hot journal's page numbers are "
            "the interrupted, never-committed write, and the journal itself holds what a "
            "proper rollback restores. "
            "A journal file present but with a zeroed/invalid header (PERSIST mode keeps "
            "the file after every commit but zeroes its header) is stale, not hot — it must "
            "not be rolled back, but the page records after the zeroed header may still "
            "hold older page versions until the next transaction overwrites them. "
            "Header (documented in the SQLite file format specification): 8-byte magic "
            "(d9 d5 05 f9 20 a1 63 d7), page-record count, checksum nonce, pre-transaction "
            "database size in pages, sector size, page size, then zero or more "
            "(page number + page content + checksum) records, possibly repeated across "
            "multiple header segments. "
            "Deleted rows and unallocated slack within a journaled page are recoverable "
            "the same way as in a live database page (freeblock chain, page-content-area gap).",
            "SQLite Rollback Journal",
        ),
        "platforms": ALL_PLATFORMS,
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
                "SQLite rollback journal format (SQLite file format specification, section 4.1)",
                "https://www.sqlite.org/fileformat2.html#rollbackjournal",
            ),
            (
                "SQLite journal_mode pragma (DELETE, TRUNCATE, PERSIST, MEMORY)",
                "https://www.sqlite.org/pragma.html#pragma_journal_mode",
            ),
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
        "last_reviewed": "2026-10-04",
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
            "Four major variants: V7 (no magic), USTAR/POSIX ('ustar\\0' at offset 257 "
            "— adds uname/gname and longer paths), GNU tar ('ustar  \\0' with two spaces), "
            "and PAX/POSIX.1-2001 (USTAR + extended header records for sub-second "
            "timestamps, unlimited path lengths, and UTF-8 encoding). "
            "Forensically relevant as: Samsung firmware packages (.tar.md5), "
            "iOS/macOS app packages (.ipa are ZIP, but some backup formats use TAR), "
            "Linux backup archives, Docker image layers, and forensic tool outputs. "
            "TAR has no deletion mechanism — updated files are appended as new entries; "
            "superseded versions of the same file remain in the archive. "
            "mtime in headers may reveal original file timestamps from the source system.",
            "TAR Archive",
        ),
        "platforms": ALL_PLATFORMS,
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
                "The tar archive format, its extensions, and why GNU tar extracts in quadratic time (mort.coffee, 2022)",
                "https://mort.coffee/home/tar/",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
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
            "the newer EWF2 (.Ex01) and the logical .L01 variant have "
            "entries of their own. "
            "The acquisition stores its own MD5/SHA1 of the media in a dedicated "
            "hash section, written by the acquisition tool — recomputing and "
            "comparing against it verifies the acquisition has not been altered "
            "since it was made, independent of any chain-of-custody paperwork.",
            "EWF Acquisition",
        ),
        "platforms": ALL_PLATFORMS,
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
                "abrignoni/ewfprobe — pure-Python reader for EWF (E01, S01, Ex01, L01), AFF/AFF4, AD1 and virtual/Apple disk images",
                "https://github.com/abrignoni/ewfprobe",
            ),
            (
                "abrignoni/qnxprobe — filesystem reader (QNX, ext, F2FS, FAT, exFAT, NTFS, HFS+, APFS) used alongside ewfprobe",
                "https://github.com/abrignoni/qnxprobe",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
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
            "encrypt an Ex01 (AES-256); the encryption scheme is not publicly documented.",
            "EWF2 Acquisition",
        ),
        "platforms": ALL_PLATFORMS,
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
                "abrignoni/ewfprobe — pure-Python reader for EWF (E01, S01, Ex01, L01), AFF/AFF4, AD1 and virtual/Apple disk images",
                "https://github.com/abrignoni/ewfprobe",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
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
            "count of bad sectors. AFF can be encrypted. An AFD is the same "
            "acquisition split over several .aff files in a folder whose name ends "
            "in .afd; an AFM keeps the metadata in an AFF file and the disk data in "
            "a separate raw file. A page the acquisition declares but doesn't hold "
            "reads as the image's bad-sector marker, not as data from the device. "
            "AFF4, the later successor, is a different format.",
            "AFF Acquisition",
        ),
        "platforms": ALL_PLATFORMS,
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
        "extensions": [".aff", ".afm"],
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
                "abrignoni/ewfprobe — pure-Python reader for EWF (E01, S01, Ex01, L01), AFF/AFF4, AD1 and virtual/Apple disk images",
                "https://github.com/abrignoni/ewfprobe",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
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
        "platforms": ALL_PLATFORMS,
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
                "abrignoni/ewfprobe — pure-Python reader for EWF (E01, S01, Ex01, L01), AFF/AFF4, AD1 and virtual/Apple disk images",
                "https://github.com/abrignoni/ewfprobe",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
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
        "extensions": [".vhd", ".avhd"],
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
                "abrignoni/ewfprobe — pure-Python reader for EWF (E01, S01, Ex01, L01), AFF/AFF4, AD1 and virtual/Apple disk images",
                "https://github.com/abrignoni/ewfprobe",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
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
        "extensions": [".vhdx", ".avhdx"],
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
                "abrignoni/ewfprobe — pure-Python reader for EWF (E01, S01, Ex01, L01), AFF/AFF4, AD1 and virtual/Apple disk images",
                "https://github.com/abrignoni/ewfprobe",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
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
        "platforms": ALL_PLATFORMS,
        "parser_class": "RawImageVFS",
        "magic": [
            {
                "offset": 0,
                "value": b"KDMV",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Sparse extent magic 'KDMV'",
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
            {
                "offset": 0,
                "value": b"# Disk DescriptorFile",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Standalone VMDK descriptor file",
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
                "abrignoni/ewfprobe — pure-Python reader for EWF (E01, S01, Ex01, L01), AFF/AFF4, AD1 and virtual/Apple disk images",
                "https://github.com/abrignoni/ewfprobe",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
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
        "platforms": ALL_PLATFORMS,
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
                "abrignoni/ewfprobe — pure-Python reader for EWF (E01, S01, Ex01, L01), AFF/AFF4, AD1 and virtual/Apple disk images",
                "https://github.com/abrignoni/ewfprobe",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "EnCase Logical Evidence",
        "short_name": "L01",
        "category": "logical_image",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "EnCase logical evidence file (.L01) — copies "
            "of selected files and folders rather than a disk: no partition table, no "
            "filesystem, no unallocated space, so deleted data is only included if it "
            "was selected. Uses the EWF segment structure (.L01 … .L99, then .LAA …); "
            "an 'ltree' section stores the file tree with names, "
            "paths, timestamps, attributes and per-file MD5/SHA1 hashes, with the file "
            "content in compressed chunks. Common for targeted "
            "and triage collections and for evidence handed over by other parties; the "
            "content can come from any system.",
            "EnCase Logical Evidence",
        ),
        "platforms": ALL_PLATFORMS,
        "parser_class": "LogicalEvidenceVFS",
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
        ],
        "extensions": [".l01"],
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
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "FTK Imager Logical Evidence (AD1)",
        "short_name": "AD1",
        "category": "logical_image",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "AccessData (now Exterro) custom content image — a logical image of selected "
            "files and folders, not a disk: no partition table, no filesystem, no "
            "unallocated space, so deleted data is only included if it was selected as a "
            "file. Every segment (.ad1, .ad2, .ad3 …) begins 'ADSEGMENTEDFILE'; the first "
            "segment carries the logical image header 'ADLOGICALIMAGE'. Stores the file "
            "tree with names, timestamps, attributes and per-file hashes, with file "
            "content compressed in chunks. Can be protected with AD encryption (password "
            "or certificate); an encrypted image begins 'ADCRYPT' instead. Common for "
            "targeted and triage collections and for evidence handed over by other "
            "parties; the content can come from any system.",
            "FTK Imager Logical Evidence (AD1)",
        ),
        "platforms": ALL_PLATFORMS,
        "parser_class": "LogicalEvidenceVFS",
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
            {
                "offset": 0,
                "value": b"ADCRYPT",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Encrypted AD1 (AD encryption header)",
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
        "last_reviewed": "2026-10-04",
    },
    {
        "name": "Apple Unified Log (tracev3)",
        "short_name": "tracev3",
        "category": "log",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Binary log file format used by Apple's Unified Logging System. "
            "Individual .tracev3 files are stored under "
            "/private/var/db/diagnostics/ in Persist/, Special/, Signpost/, "
            "and HighVolume/ subdirectories, plus logdata.LiveData.tracev3 at its root. "
            "Each file is a sequence of chunks — a header, catalogs and LZ4-compressed "
            "chunksets holding the timestamped log entries — referencing "
            "format strings via uuidtext/ catalogs and the Dyld Shared Cache (DSC). "
            "Cannot be parsed in isolation — requires companion uuidtext/, timesync/, "
            "and DSC directories for full string resolution and timestamp anchoring. "
            "See the Apple Unified Log Archive (logarchive) entry for full "
            "forensic context and artifact categories.",
            "Apple Unified Log (tracev3)",
        ),
        "platforms": ["iOS", "macOS"],
        "parser_class": "UnifiedLogConverter",
        "magic": [
            {
                "offset": 0,
                "value": b"\x00\x10\x00\x00\x11\x00\x00\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Header chunk: tag 0x1000, sub tag 0x11 (little-endian)",
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
                "iOS Unified Logs research (Lionel Notari, ios-unifiedlogs.com)",
                "https://www.ios-unifiedlogs.com/",
            ),
            (
                "Thesis Friday — Unified Log analysis series (Tim Korver)",
                "https://thesisfriday.com/",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
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
            "AndroidManifest.xml (stored as binary XML inside the APK) — declares "
            "package name, version, permissions, exported components, intent filters, "
            "and allowBackup flag; critical for app capability assessment and malware analysis. "
            "packages.xml (/data/system/) — lists all installed packages with granted "
            "permissions, installer source (com.android.vending = Play Store vs sideloaded), "
            "and UID assignments. "
            "runtime-permissions.xml and roles.xml (Android 10+) — dangerous permissions "
            "granted at runtime and default app assignments. "
            "Since Android 12 the system writes packages.xml and most other XML files "
            "under /data/system in the binary ABX format (see ABX entry). "
            "SharedPreferences files (/data/data/<package>/shared_prefs/*.xml) — "
            "app configuration and user state, sometimes containing credentials or tokens. "
            "On Windows: Scheduled Tasks (C:\\Windows\\System32\\Tasks\\), stored as UTF-16 XML. "
            "On iOS/macOS: XML plists (see Property List entry). "
            "In Office documents: OOXML internals (.docx/.xlsx/.pptx are ZIP+XML).",
            "XML Document",
        ),
        "platforms": ALL_PLATFORMS,
        "parser_class": "XmlParser",
        "magic": [
            {
                "offset": 0,
                "value": b"\x3c\x3f\x78\x6d\x6c",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "XML declaration ('<?xml'); optional, so many XML files have no magic",
                    "XML Document",
                ),
            },
            {
                "offset": 0,
                "value": b"\xef\xbb\xbf<?xml",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "XML declaration with UTF-8 byte order mark",
                    "XML Document",
                ),
            },
            {
                "offset": 0,
                "value": b"\xff\xfe<\x00?\x00x\x00m\x00l\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "XML declaration in UTF-16LE with byte order mark",
                    "XML Document",
                ),
            },
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
                "Android - Roles and Permissions (Android 10/11) (D20 Forensics)",
                "https://blog.d204n6.com/2021/01/android-roles-and-permissions-android.html",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
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
            "no timezone information — unreliable for precise forensic timeline unless "
            "extra fields add UTC times (0x5455 extended timestamp, 0x000A NTFS "
            "modification/access/creation times). "
            "APK-specific: APK Signing Block v2+ inserts between the last Local File Header "
            "and Central Directory — presence indicates modern Android signing. "
            "ZIP structure variation (creator OS, compressor version, extra fields) "
            "can fingerprint the tool or OS used to create the archive. "
            "Encryption: ZipCrypto (legacy, weak — known-plaintext attack possible) "
            "or WinZip AES (128/192/256-bit, strong). "
            "Standard ZIP limited to 4GB — ZIP64 extension required for larger archives.",
            "ZIP Archive",
        ),
        "platforms": ALL_PLATFORMS,
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
            },
            {
                "offset": 0,
                "value": b"\x50\x4b\x05\x06",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Empty archive (End of Central Directory record only)",
                    "ZIP Archive",
                ),
            },
            {
                "offset": 0,
                "value": b"\x50\x4b\x07\x08\x50\x4b\x03\x04",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "First segment of a split/spanned archive (span signature followed by Local File Header)",
                    "ZIP Archive",
                ),
            },
            {
                "offset": None,
                "value": b"\x50\x4b\x05\x06",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "End of Central Directory record, within the last 64 KB of the file",
                    "ZIP Archive",
                ),
            },
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
                "File fingerprinting of the ZIP format for identifying and tracking provenance (FSI: Digital Investigation, 2021)",
                "https://www.sciencedirect.com/science/article/abs/pii/S266628172100189X",
            ),
            (
                "An Android Package is no Longer a ZIP — APK Signing Block (Fortinet, 2018)",
                "https://www.fortinet.com/blog/threat-research/an-android-package-is-no-longer-a-zip",
            ),
            (
                "ForensicsWiki — ZIP format",
                "https://forensics.wiki/zip/",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
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
            "A 32-byte signature header at offset 0 points to the archive header at the "
            "end of the file, which holds the file list; timestamps are stored as UTC "
            "FILETIME with 100 ns precision (modification time always, creation and "
            "access time optionally). "
            "Solid compression (default) groups multiple files into shared compression "
            "blocks, meaning a single corrupted block can affect the recoverability of "
            "several unrelated files at once — a drawback compared with ZIP's per-file "
            "compression. "
            "Seen in the wild bundling malware droppers (compression ratio + optional "
            "encryption both help evade signature-based and content-inspection scanning), "
            "as well as legitimate acquisition tool exports.",
            "7-Zip Archive",
        ),
        "platforms": ALL_PLATFORMS,
        "parser_class": "SevenZipVFS",
        "magic": [
            {
                "offset": 0,
                "value": b"\x37\x7a\xbc\xaf\x27\x1c",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "7z signature ('7z' BC AF 27 1C), followed by the format version",
                    "7-Zip Archive",
                ),
            }
        ],
        "extensions": [".7z"],
        "links": [
            (
                "7z format overview and features (7-Zip)",
                "https://www.7-zip.org/7z.html",
            ),
            (
                ".7z format specification (py7zr documentation)",
                "https://py7zr.readthedocs.io/en/latest/archive_format.html",
            ),
            (
                "7z format overview (Wikipedia)",
                "https://en.wikipedia.org/wiki/7z",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
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
            "/private/var/Keychains/keychain-2.db — the file itself is not encrypted, "
            "but each item is encrypted with two AES-256-GCM keys: a metadata key for its "
            "attributes (protected by the Secure Enclave, cached in the application "
            "processor) and a per-row key for the secret value (unwrapped only by the "
            "Secure Enclave), both bound to the item's protection class. "
            "Records contain: account name (acct), service (svce), server, "
            "access group (agrp — identifies the owning app), protection class, "
            "and the encrypted secret (data). "
            "On macOS: Login Keychain (~/Library/Keychains/login.keychain-db, .keychain "
            "before 10.12) and System Keychain (/Library/Keychains/System.keychain) use a "
            "separate big-endian database format beginning 'kych', not SQLite; "
            "Local Items/iCloud Keychain is a keychain-2.db (SQLite) with a user.kb keybag "
            "under ~/Library/Keychains/<UUID>/. "
            "If iCloud Keychain sync is enabled, keychain-2.db may contain "
            "credentials from all the user's Apple devices. "
            "Encrypted iTunes/Finder backups contain the keychain as keychain-backup.plist, "
            "decryptable offline with the backup password except for ThisDeviceOnly items. "
            "On devices with a Secure Enclave (iPhone 5s and later) the class keys can "
            "only be unwrapped on the device itself; older devices allow offline "
            "decryption with extracted class keys.",
            "Apple Keychain",
        ),
        "platforms": ["iOS", "macOS"],
        "parser_class": "SQLiteParser",
        "magic": [
            {
                "offset": None,
                "value": b"\x53\x51\x4c\x69\x74\x65\x20\x66\x6f\x72\x6d\x61\x74\x20\x33\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "SQLite magic — keychain-2.db is a standard SQLite database",
                    "Apple Keychain",
                ),
            },
        ],
        "extensions": [".db", ".keychain", ".keychain-db"],
        "links": [
            (
                "Apple keychain data protection (Apple Security Guide)",
                "https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web",
            ),
            (
                "MacOS keychain database file format (libyal/dtformats)",
                "https://github.com/libyal/dtformats/blob/main/documentation/MacOS%20keychain%20database%20file%20format.asciidoc",
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
        "last_reviewed": "2026-10-04"
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
            "(2) System Keystore — keys generated through Keymaster/KeyMint in the TEE "
            "or StrongBox are stored as wrapped key blobs under /data/misc/keystore/: "
            "up to Android 11 as one file per key in user_<N>/ named after the owning "
            "UID and alias, since Android 12 (keystore2) in the SQLite database "
            "persistent.sqlite. The key material cannot be used off the device, but "
            "aliases, owning UIDs and certificates remain readable. "
            "App keystore files (.bks, .keystore, .p12, .pfx) are "
            "found bundled in APK assets/ or res/raw/ directories. "
            "App keystores can also be JKS/JCEKS; see Java KeyStore. "
            "BKS has no magic and begins with its version number; "
            "PKCS#12 is DER (ASN.1 SEQUENCE, 0x30). "
            "Hardcoded keystore passwords in decompiled DEX are a common "
            "finding in mobile app security assessments.",
            "Android Keystore",
        ),
        "platforms": ["Android"],
        "parser_class": None,
        "magic": [
            {
                "offset": None,
                "value": b"\x30",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "PKCS#12/PFX — ASN.1 SEQUENCE tag (too generic to match on)",
                    "Android Keystore",
                ),
            },
        ],
        "extensions": [".keystore", ".bks", ".p12", ".pfx"],
        "links": [
            (
                "Android Keystore system (Android developer docs)",
                "https://developer.android.com/privacy-and-security/keystore",
            ),
            (
                "keystore2 database schema (AOSP system/security, database.rs)",
                "https://android.googlesource.com/platform/system/security/+/refs/heads/main/keystore2/src/database.rs",
            ),
            (
                "PKCS#12 format overview (Wikipedia)",
                "https://en.wikipedia.org/wiki/PKCS_12",
            ),
            (
                "Mind Your Keys? A Security Evaluation of Java Keystores (NDSS 2018)",
                "https://www.ndss-symposium.org/wp-content/uploads/2018/02/ndss2018_02B-1_Focardi_paper.pdf",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
    },
    {
        "name": "iOS Backup (iTunes/Finder)",
        "short_name": "iOS Backup",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Local iOS device backup created by iTunes (Windows/older macOS), "
            "Finder (macOS 10.15+) or the Apple Devices app (Windows). Stored at: "
            "Windows: %APPDATA%\\Apple Computer\\MobileSync\\Backup\\{UDID}\\ "
            "(Microsoft Store iTunes / Apple Devices: %USERPROFILE%\\Apple\\MobileSync\\Backup\\{UDID}\\) "
            "macOS: ~/Library/Application Support/MobileSync/Backup/{UDID}/ "
            "Structure (iOS 10+): 256 subdirectories (00-ff) containing files named by "
            "SHA-1 hash of domain+'-'+relativePath — no file extensions, no original filenames; "
            "older backups are flat and indexed by Manifest.mbdb. "
            "Four key metadata files: "
            "Info.plist (device info, installed apps, last backup date, iTunes version), "
            "Manifest.plist (backup keybag, encryption flag, WasPasscodeSet, app list), "
            "Status.plist (backup state, creation start date), "
            "Manifest.db (SQLite index mapping fileIDs to domain/relativePath/metadata). "
            "In encrypted backups (IsEncrypted=true) each file is encrypted with a "
            "per-file key wrapped by the backup keybag, and since iOS 10.2 Manifest.db "
            "itself is encrypted with the ManifestKey stored in Manifest.plist; "
            "unencrypted backups leave both the file contents and Manifest.db in the clear. "
            "The backup password is not tied to the device passcode. "
            "Keychain data (keychain-backup.plist) is present in both, but in unencrypted "
            "backups it stays protected with a device UID-derived key and cannot be "
            "decrypted off the device. "
            "Manifest.plist's WasPasscodeSet shows whether a passcode was set on the device.",
            "iOS Backup (iTunes/Finder)",
        ),
        "platforms": ["iOS", "Windows", "macOS"],
        "parser_class": "ITunesBackupVFS",
        "magic": [],
        "extensions": [],
        "links": [
            (
                "Keybags for Data Protection — backup keybag (Apple Platform Security)",
                "https://support.apple.com/guide/security/keybags-for-data-protection-sec6483d5760/web",
            ),
            (
                "iTunes Backup format internals, unencrypted / Manifest.mbdb (The Apple Wiki)",
                "https://theapplewiki.com/wiki/ITunes_Backup",
            ),
            (
                "iPhone backup forensics 101 (Kinga Kieczkowska / OBTS v7)",
                "https://kieczkowska.wordpress.com/2025/04/29/iphone-backup-forensics-101/",
            ),
            (
                "iOS Data Protection on Backup (VulBusters, Medium)",
                "https://medium.com/@vulbusters/ios-data-protection-on-backup-6f53d588c830",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
    },
    {
        "name": "Windows Prefetch",
        "short_name": "Prefetch",
        "category": "execution",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Windows execution evidence artifacts created when an application is run "
            "for the first time from a specific path. "
            "Stored under C:\\Windows\\Prefetch\\ as {EXECUTABLE}-{HASH}.pf, "
            "where HASH is derived from the executable's full device path (for hosting "
            "processes such as svchost.exe or rundll32.exe also from the command line). "
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
            "Since Windows 10 the files are stored compressed in a MAM container "
            "(LZXPRESS Huffman); the SCCA header is only visible after decompression. "
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
                    "Prefetch v26 header (Windows 8.0/8.1)",
                    "Windows Prefetch",
                ),
            },
            {
                "offset": 0,
                "value": b"\x1e\x00\x00\x00\x53\x43\x43\x41",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Prefetch v30 header (Windows 10, decompressed)",
                    "Windows Prefetch",
                ),
            },
            {
                "offset": 0,
                "value": b"\x1f\x00\x00\x00\x53\x43\x43\x41",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Prefetch v31 header (Windows 11, decompressed)",
                    "Windows Prefetch",
                ),
            },
            {
                "offset": 0,
                "value": b"\x4d\x41\x4d\x04",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Compressed prefetch file, MAM container 'MAM\\x04' (Windows 10+)",
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
        "last_reviewed": "2026-10-04"
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
            "may reveal when the source file was last modified; 0 if unavailable, "
            "e.g. when a stream was compressed or the name/time were suppressed), "
            "OS byte (identifies the OS that created the file: 0=FAT, 3=Unix, 7=Mac, 11=NTFS), "
            "and optional original filename (FNAME flag). "
            "8-byte footer: CRC-32 of uncompressed data and original file size (modulo 2^32). "
            "Forensically common as: Linux log rotation (.gz), "
            "compressed kernels and ramdisks in Android boot images (mainly older devices), "
            "iOS/macOS sysdiagnose archives (.tar.gz), "
            "network traffic content encoding, and database backups. "
            "Multiple gzip members can be concatenated in a single .gz file. "
            "OS byte and mtime can reveal the origin platform and source file age.",
            "Gzip Compressed Data",
        ),
        "platforms": ALL_PLATFORMS,
        "parser_class": "GzipVFS",
        "magic": [
            {
                "offset": 0,
                "value": b"\x1f\x8b\x08",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Gzip magic number (ID1=0x1F, ID2=0x8B) and compression method 8 (DEFLATE)",
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
        "last_reviewed": "2026-10-04"
    },
    {
        "name": "Raw Disk Image",
        "short_name": "Raw",
        "category": "disk_image",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "A sector-for-sector copy of a disk, partition or flash chip with no container "
            "around it: no header, no metadata, no hash, no compression. Often split into "
            "numbered segments (.001, .002, … or other schemes such as .aa, .ab, …) that "
            "join into one stream. Everything the device held is in it, including "
            "unallocated space and slack; how and when it was acquired is only recorded "
            "outside the image.",
            "Raw Disk Image",
        ),
        "platforms": ALL_PLATFORMS,
        "parser_class": "RawImageVFS",
        "magic": [],
        "extensions": [".dd", ".raw", ".img", ".001"],
        "links": [
            (
                "ForensicsWiki — Raw image format",
                "https://forensics.wiki/raw_image_format/",
            ),
            (
                "SWGDE Best Practices for Computer Forensic Acquisitions (17-F-002, v2.0) — raw vs. container formats",
                "https://www.swgde.org/wp-content/uploads/2024/03/2023-06-15-SWGDE-Best-Practices-for-Computer-Forensic-Acquisitions-17-F-002-2.0.pdf",
            ),
            (
                "dd (Unix) (Wikipedia)",
                "https://en.wikipedia.org/wiki/Dd_(Unix)",
            ),
            (
                "abrignoni/qnxprobe — MBR/GPT and filesystem reader for raw images (QNX6/QNX4, ETFS, EFS, ext2/3/4, F2FS, FAT32, exFAT, NTFS, HFS+, APFS, QNX IFS)",
                "https://github.com/abrignoni/qnxprobe",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
    },
    {
        "name": "Master Boot Record (MBR) Partition Table",
        "short_name": "MBR",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The classic PC partition scheme in the first sector of a disk: boot code, a "
            "4-byte disk signature at offset 440 (used by Windows to map volumes in the "
            "MountedDevices registry key), up to four primary partition entries and the "
            "0x55AA boot signature. Further partitions chain through extended boot "
            "records. Each entry carries a type byte and a start and length in sectors; "
            "space outside every entry (before the first partition, between partitions, "
            "after the last) can hold remnants of earlier layouts. A GPT disk keeps a "
            "protective MBR with a single 0xEE entry.",
            "Master Boot Record (MBR) Partition Table",
        ),
        "platforms": ALL_PLATFORMS,
        "parser_class": "RawImageVFS",
        "magic": [
            {
                "offset": 510,
                "value": b"U\xaa",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Boot signature 0x55AA at the end of sector 0 (also present in FAT/NTFS boot sectors)",
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
            (
                "abrignoni/qnxprobe — MBR/GPT and filesystem reader for raw images (QNX6/QNX4, ETFS, EFS, ext2/3/4, F2FS, FAT32, exFAT, NTFS, HFS+, APFS, QNX IFS)",
                "https://github.com/abrignoni/qnxprobe",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
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
        "platforms": ALL_PLATFORMS,
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
                "UEFI Specification 2.10 — GUID Partition Table (GPT) Disk Layout",
                "https://uefi.org/specs/UEFI/2.10/05_GUID_Partition_Table_Format.html",
            ),
            (
                "GUID Partition Table (GPT) format (libyal/libvsgpt)",
                "https://github.com/libyal/libvsgpt/blob/main/documentation/GUID%20Partition%20Table%20(GPT)%20format.asciidoc",
            ),
            (
                "ForensicsWiki — GPT",
                "https://forensics.wiki/gpt/",
            ),
            (
                "abrignoni/qnxprobe — MBR/GPT and filesystem reader for raw images (QNX6/QNX4, ETFS, EFS, ext2/3/4, F2FS, FAT32, exFAT, NTFS, HFS+, APFS, QNX IFS)",
                "https://github.com/abrignoni/qnxprobe",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
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
                "Apple File System Reference (Apple, 2020-06-22)",
                "https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf",
            ),
            (
                "Apple File System (APFS) — format documentation (libyal/libfsapfs)",
                "https://github.com/libyal/libfsapfs/blob/main/documentation/Apple%20File%20System%20(APFS).asciidoc",
            ),
            (
                "Mobile Forensics – The File Format Handbook: APFS (Rune Nordvik, Springer, 2022)",
                "https://doi.org/10.1007/978-3-030-98467-0_1",
            ),
            (
                "abrignoni/qnxprobe — MBR/GPT and filesystem reader for raw images (QNX6/QNX4, ETFS, EFS, ext2/3/4, F2FS, FAT32, exFAT, NTFS, HFS+, APFS, QNX IFS)",
                "https://github.com/abrignoni/qnxprobe",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
    },
    {
        "name": "HFS Plus / HFSX",
        "short_name": "HFS+",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Apple's filesystem before APFS (Mac OS 8.1 to macOS 10.12, on hard disks and "
            "Fusion Drives to 10.13, still on many external drives and older Time Machine "
            "disks). Files and folders are records in a catalog B-tree, with an extents "
            "overflow file and an attributes file for extended attributes and compressed "
            "(decmpfs) data. HFSX is the case-sensitive variant, also used by iOS before "
            "10.3. An optional journal records metadata changes. Timestamps are seconds "
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
            (
                "abrignoni/qnxprobe — MBR/GPT and filesystem reader for raw images (QNX6/QNX4, ETFS, EFS, ext2/3/4, F2FS, FAT32, exFAT, NTFS, HFS+, APFS, QNX IFS)",
                "https://github.com/abrignoni/qnxprobe",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
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
            "UTC); $STANDARD_INFORMATION times can be set through the API, $FILE_NAME "
            "times not readily, so comparing both helps detect timestomping. Small files "
            "are stored resident inside the MFT entry, and entries of deleted files remain "
            "until reused. Metadata files record history — $LogFile (transaction log), "
            "$UsnJrnl:$J (change journal) — next to $Secure (security descriptors) and "
            "$Bitmap (cluster allocation). Alternate data streams (e.g. Zone.Identifier) "
            "and Volume Shadow Copies live on the same volume.",
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
                "ForensicsWiki — New Technology File System (NTFS)",
                "https://forensics.wiki/new_technology_file_system_(ntfs)/",
            ),
            (
                "abrignoni/qnxprobe — MBR/GPT and filesystem reader for raw images (QNX6/QNX4, ETFS, EFS, ext2/3/4, F2FS, FAT32, exFAT, NTFS, HFS+, APFS, QNX IFS)",
                "https://github.com/abrignoni/qnxprobe",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
    },
    {
        "name": "FAT32",
        "short_name": "FAT32",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The 32-bit File Allocation Table filesystem, used on USB sticks, SD cards, "
            "camera media, EFI system partitions and Android SD cards. "
            "Directory entries hold an 8.3 name (plus long-name entries), attributes, size, "
            "first cluster and creation/modification/access times in local time with "
            "10 ms (creation), 2-second (modification) and day (access) resolution. "
            "A deleted entry keeps most of its fields with the first name byte set to "
            "0xE5, but the cluster chain in the FAT is cleared, so recovery beyond the "
            "first cluster assumes the file was stored contiguously.",
            "FAT32",
        ),
        "platforms": ALL_PLATFORMS,
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
            (
                "abrignoni/qnxprobe — MBR/GPT and filesystem reader for raw images (QNX6/QNX4, ETFS, EFS, ext2/3/4, F2FS, FAT32, exFAT, NTFS, HFS+, APFS, QNX IFS)",
                "https://github.com/abrignoni/qnxprobe",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
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
        "platforms": ALL_PLATFORMS,
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
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
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
        "platforms": ALL_PLATFORMS,
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
                "File Allocation Table (FAT) format, incl. exFAT (libyal/libfsfat)",
                "https://github.com/libyal/libfsfat/blob/main/documentation/File%20Allocation%20Table%20(FAT)%20format.asciidoc",
            ),
            (
                "abrignoni/qnxprobe — MBR/GPT and filesystem reader for raw images (QNX6/QNX4, ETFS, EFS, ext2/3/4, F2FS, FAT32, exFAT, NTFS, HFS+, APFS, QNX IFS)",
                "https://github.com/abrignoni/qnxprobe",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
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
            "directory entries that link names to inode numbers. ext3/ext4 clear a deleted "
            "file's block pointers or extents in the inode, but keep a journal whose older "
            "copies of metadata blocks can still describe deleted or changed files. The "
            "superblock records last mount path, mount and write times.",
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
                "Mobile Forensics – The File Format Handbook: Ext4 (Rune Nordvik, Springer, 2022)",
                "https://doi.org/10.1007/978-3-030-98467-0_2",
            ),
            (
                "abrignoni/qnxprobe — MBR/GPT and filesystem reader for raw images (QNX6/QNX4, ETFS, EFS, ext2/3/4, F2FS, FAT32, exFAT, NTFS, HFS+, APFS, QNX IFS)",
                "https://github.com/abrignoni/qnxprobe",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
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
                "F2FS on-disk structures — include/linux/f2fs_fs.h (Linux kernel source)",
                "https://github.com/torvalds/linux/blob/master/include/linux/f2fs_fs.h",
            ),
            (
                "Mobile Forensics – The File Format Handbook: The Flash-Friendly File System (F2FS) (Chris Currier, Springer, 2022)",
                "https://doi.org/10.1007/978-3-030-98467-0_3",
            ),
            (
                "abrignoni/qnxprobe — MBR/GPT and filesystem reader for raw images (QNX6/QNX4, ETFS, EFS, ext2/3/4, F2FS, FAT32, exFAT, NTFS, HFS+, APFS, QNX IFS)",
                "https://github.com/abrignoni/qnxprobe",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
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
            "through block pointer trees. Exists in little- and big-endian byte order.",
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
                    "Superblock magic 0x68191122 after the 8 KiB boot block (little-endian)",
                    "QNX6 Filesystem",
                ),
            },
            {
                "offset": 8192,
                "value": b"h\x19\x11\x22",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Superblock magic 0x68191122 after the 8 KiB boot block (big-endian)",
                    "QNX6 Filesystem",
                ),
            },
            {
                "offset": 0,
                "value": b"\x22\x11\x19h",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Superblock magic 0x68191122 at byte 0, layouts without boot block, e.g. Audi MMI 3G (little-endian)",
                    "QNX6 Filesystem",
                ),
            },
            {
                "offset": 0,
                "value": b"h\x19\x11\x22",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Superblock magic 0x68191122 at byte 0, layouts without boot block (big-endian)",
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
                "Mobile Forensics – The File Format Handbook: QNX6 (Conrad Meyer, Springer, 2022)",
                "https://doi.org/10.1007/978-3-030-98467-0_4",
            ),
            (
                "qnxmount — QNX6, ETFS and EFS parsers (Netherlands Forensic Institute)",
                "https://github.com/NetherlandsForensicInstitute/qnxmount",
            ),
            (
                "abrignoni/qnxprobe — MBR/GPT and filesystem reader for raw images (QNX6/QNX4, ETFS, EFS, ext2/3/4, F2FS, FAT32, exFAT, NTFS, HFS+, APFS, QNX IFS)",
                "https://github.com/abrignoni/qnxprobe",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
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
                "QNX 4 filesystem — root directory and special files (QNX Neutrino User's Guide)",
                "https://www.qnx.com/developers/docs/6.6.0.update/com.qnx.doc.neutrino.user_guide/topic/lost_data_Root_directory.html",
            ),
            (
                "QNX4 on-disk structures — include/uapi/linux/qnx4_fs.h (Linux kernel source)",
                "https://github.com/torvalds/linux/blob/master/include/uapi/linux/qnx4_fs.h",
            ),
            (
                "abrignoni/qnxprobe — MBR/GPT and filesystem reader for raw images (QNX6/QNX4, ETFS, EFS, ext2/3/4, F2FS, FAT32, exFAT, NTFS, HFS+, APFS, QNX IFS)",
                "https://github.com/abrignoni/qnxprobe",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
    },
    {
        "name": "QNX Image Filesystem (IFS)",
        "short_name": "QNX IFS",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "A QNX boot image: a startup header and startup code followed by a read-only "
            "image filesystem holding the kernel, drivers, libraries and the build script "
            "the system boots with. The image filesystem may be compressed (zlib, LZO or "
            "UCL). On x86 a preboot section can precede the startup header. Shows what "
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
                    "Startup header signature 0x00FF7EEB (little-endian)",
                    "QNX Image Filesystem (IFS)",
                ),
            },
            {
                "offset": 0,
                "value": b"\x00\xff~\xeb",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Startup header signature 0x00FF7EEB (big-endian)",
                    "QNX Image Filesystem (IFS)",
                ),
            },
            {
                "offset": None,
                "value": b"\xeb~\xff\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Startup header after a preboot section (x86 BIOS/UEFI images)",
                    "QNX Image Filesystem (IFS)",
                ),
            },
        ],
        "extensions": [".ifs"],
        "links": [
            (
                "The startup header (QNX SDP 8.0 — Building Embedded Systems)",
                "https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.building/topic/ipl/ipl_startup_header.html",
            ),
            (
                "dumpifs — Dump an image filesystem (QNX SDP 8.0 utilities reference)",
                "https://qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/d/dumpifs.html",
            ),
            (
                "abrignoni/qnxprobe — MBR/GPT and filesystem reader for raw images (QNX6/QNX4, ETFS, EFS, ext2/3/4, F2FS, FAT32, exFAT, NTFS, HFS+, APFS, QNX IFS)",
                "https://github.com/abrignoni/qnxprobe",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
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
            "can remain until they are reclaimed (background reclaim and wear levelling "
            "decide when). It has no magic number: it is recognised by its reserved files "
            "(.filetable, .badblks, .counts) at fixed file IDs.",
            "QNX Embedded Transaction Filesystem (ETFS)",
        ),
        "platforms": ["QNX"],
        "parser_class": "RawImageVFS",
        "magic": [],
        "extensions": [],
        "links": [
            (
                "Embedded transaction filesystem (ETFS) — QNX Neutrino System Architecture",
                "https://www.qnx.com/developers/docs/6.5.0SP1/neutrino/sys_arch/fsys.html",
            ),
            (
                "etfsctl — reserved files .filetable, .badblks, .counts (QNX utilities reference)",
                "https://www.qnx.com/developers/docs/6.5.0SP1/neutrino/utilities/e/etfsctl.html",
            ),
            (
                "qnxmount — QNX6, ETFS and EFS parsers (Netherlands Forensic Institute)",
                "https://github.com/NetherlandsForensicInstitute/qnxmount",
            ),
            (
                "abrignoni/qnxprobe — MBR/GPT and filesystem reader for raw images (QNX6/QNX4, ETFS, EFS, ext2/3/4, F2FS, FAT32, exFAT, NTFS, HFS+, APFS, QNX IFS)",
                "https://github.com/abrignoni/qnxprobe",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
    },
    {
        "name": "QNX Embedded Flash Filesystem (EFS / F3S)",
        "short_name": "EFS",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The QNX flash filesystem for NOR flash (FFS3, fs-flash3). The flash is divided "
            "into units holding extents; changes are copy-on-write, with a pointer from an "
            "old extent to the one that supersedes it, so older versions can remain "
            "readable until the unit is reclaimed. The partition is found by its boot "
            "record containing the text 'QSSL_F3S'.",
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
                "FFS3 filesystem — QNX SDP 8.0 System Architecture",
                "https://qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.sys_arch/topic/fsys_FFS3.html",
            ),
            (
                "qnxmount — QNX6, ETFS and EFS parsers (Netherlands Forensic Institute)",
                "https://github.com/NetherlandsForensicInstitute/qnxmount",
            ),
            (
                "abrignoni/qnxprobe — MBR/GPT and filesystem reader for raw images (QNX6/QNX4, ETFS, EFS, ext2/3/4, F2FS, FAT32, exFAT, NTFS, HFS+, APFS, QNX IFS)",
                "https://github.com/abrignoni/qnxprobe",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
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
            "unsigned seconds since 1970: each inode holds only a modification time, and "
            "the superblock records when the image was created.",
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
                    "Superblock magic 'sqsh' (big-endian, versions before 4.0)",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
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
                "value": b"\x85\x19\x03\x20",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Node magic 0x1985 + cleanmarker node 0x2003 (little-endian)",
                    "JFFS2 (Journalling Flash File System v2)",
                ),
            },
            {
                "offset": 0,
                "value": b"\x85\x19\x01\xe0",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Node magic 0x1985 + directory entry node 0xE001 (little-endian)",
                    "JFFS2 (Journalling Flash File System v2)",
                ),
            },
            {
                "offset": 0,
                "value": b"\x85\x19\x02\xe0",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Node magic 0x1985 + inode node 0xE002 (little-endian)",
                    "JFFS2 (Journalling Flash File System v2)",
                ),
            },
            {
                "offset": 0,
                "value": b"\x19\x85\x20\x03",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Node magic 0x1985 + cleanmarker node 0x2003 (big-endian)",
                    "JFFS2 (Journalling Flash File System v2)",
                ),
            },
            {
                "offset": 0,
                "value": b"\x19\x85\xe0\x01",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Node magic 0x1985 + directory entry node 0xE001 (big-endian)",
                    "JFFS2 (Journalling Flash File System v2)",
                ),
            },
            {
                "offset": 0,
                "value": b"\x19\x85\xe0\x02",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Node magic 0x1985 + inode node 0xE002 (big-endian)",
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
                "JFFS2 on-disk structures — include/uapi/linux/jffs2.h (Linux kernel source)",
                "https://github.com/torvalds/linux/blob/master/include/uapi/linux/jffs2.h",
            ),
            (
                "ForensicsWiki — JFFS2",
                "https://forensics.wiki/jffs2/",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
    },
    {
        "name": "UBI (Unsorted Block Images)",
        "short_name": "UBI",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "A volume layer on raw NAND flash in embedded Linux devices. Each physical "
            "eraseblock starts with an erase-counter header and (once mapped) a volume-ID "
            "header that maps it to a logical block of a volume; a volume table, kept twice "
            "in an internal layout volume, names the volumes. Eraseblocks that held earlier "
            "copies of a logical block can remain until they are erased.",
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
            {
                "offset": None,
                "value": b"UBI!",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Volume-ID header magic 'UBI!' (at the VID header offset given in the erase-counter header)",
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
            (
                "UBI on-flash structures — drivers/mtd/ubi/ubi-media.h (Linux kernel source)",
                "https://github.com/torvalds/linux/blob/master/drivers/mtd/ubi/ubi-media.h",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
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
                    "Node magic 0x06101831 (little-endian), superblock node in LEB 0",
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
                "A Brief Introduction to the Design of UBIFS (Adrian Hunter, 2008)",
                "http://www.linux-mtd.infradead.org/doc/ubifs_whitepaper.pdf",
            ),
            (
                "UBIFS on-flash structures — fs/ubifs/ubifs-media.h (Linux kernel source)",
                "https://github.com/torvalds/linux/blob/master/fs/ubifs/ubifs-media.h",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
    },
    {
        "name": "YAFFS1 / YAFFS2",
        "short_name": "YAFFS",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Yet Another Flash File System, used on NAND flash in older Android devices and "
            "embedded systems. Each page carries tags in its spare area naming the object "
            "and chunk it belongs to; YAFFS2 adds a per-block sequence number (YAFFS1 uses "
            "deletion markers and a 2-bit serial number). The newest chunk wins, so "
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
                "How Yaffs works (Aleph One, yaffs.net)",
                "https://yaffs.net/node/409",
            ),
            (
                "Forensic Analysis of YAFFS2 (Zimmermann, Spreitzenbarth, Schmitt, Freiling — SICHERHEIT 2012)",
                "https://dl.gi.de/handle/20.500.12116/18263",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
    },
    {
        "name": "BitLocker Drive Encryption",
        "short_name": "BitLocker",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Windows full-volume encryption. The volume keeps a boot sector with the "
            "'-FVE-FS-' signature (BitLocker To Go on FAT media: 'MSWIN4.1') and three "
            "copies of the FVE metadata, which list the key protectors (TPM, PIN, password, "
            "recovery password, startup key) and when the volume was encrypted. The rest "
            "is ciphertext, except free space on volumes encrypted 'used space only'; "
            "without one of the protectors' secrets the files cannot be read — unless "
            "protection is suspended or not yet set up, in which case a clear key is "
            "stored unprotected on the volume. BitLocker To Go protects removable drives "
            "the same way.",
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
            {
                "offset": None,
                "value": b"-FVE-FS-",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "FVE metadata block signature (three copies; also on BitLocker To Go volumes)",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
    },
    {
        "name": "AccessData AD Encryption (ADCRYPT)",
        "short_name": "ADCRYPT",
        "category": "disk_image",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The encryption wrapper FTK Imager can put around an acquisition (raw or E01 "
            "segments, or an AD1 logical image). Each encrypted file starts with an "
            "'ADCRYPT' header in a small unencrypted chunk; the content is AES-encrypted "
            "and opened with the password or the RSA private key (certificate) chosen at "
            "acquisition time.",
            "AccessData AD Encryption (ADCRYPT)",
        ),
        "platforms": ALL_PLATFORMS,
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
                "PRONOM fmt/843 — AccessData Custom Content Image (Encrypted)",
                "https://www.nationalarchives.gov.uk/PRONOM/fmt/843",
            ),
            (
                "abrignoni/ewfprobe — pure-Python reader for EWF (E01, S01, Ex01, L01), AFF/AFF4, AD1 and virtual/Apple disk images",
                "https://github.com/abrignoni/ewfprobe",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
    },
    {
        "name": "Cellebrite UFDR",
        "short_name": "UFDR",
        "category": "logical_image",
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
                "UFDR2DIR — UFDR structure and report.xml path mapping (DFIR Science)",
                "https://github.com/DFIRScience/UFDR2DIR",
            ),
            (
                "pg_dump custom archive format (PostgreSQL documentation)",
                "https://www.postgresql.org/docs/current/app-pgdump.html",
            ),
            (
                "ForensicsWiki — Cellebrite (UFED extraction devices)",
                "https://forensics.wiki/cellebrite/",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
    },
    {
        "name": "Android logcat (text)",
        "short_name": "logcat",
        "category": "log",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Text output of Android's logcat: one line per log message with date and time "
            "(device local time, no year in the default format; other output formats add "
            "the year or use UTC or epoch time), PID, TID, priority, tag and message. "
            "Found in bug reports, ADB extractions and app support exports. The binary log "
            "buffers on the device (main, system, crash, radio, events) are ring buffers, "
            "so a capture only reaches back as far as the buffer did.",
            "Android logcat (text)",
        ),
        "platforms": ["Android"],
        "parser_class": "LogParser",
        "magic": [],
        "extensions": [".txt", ".log"],
        "links": [
            (
                "Logcat command-line tool — output formats and buffers (Android developers)",
                "https://developer.android.com/tools/logcat",
            ),
            (
                "Understand logging — log levels and logging APIs (Android Open Source Project)",
                "https://source.android.com/docs/core/tests/debug/understanding-logging",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
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
            "timestamps with offset. Files written by the local syslog daemon usually omit "
            "the priority, and many current distributions write RFC 3339 timestamps with "
            "sub-second precision. Found in /var/log on Linux (messages, syslog, auth.log, "
            "secure — often without extension) and in exports from routers, firewalls and "
            "appliances.",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
    },
    {
        "name": "SQLCipher Encrypted Database",
        "short_name": "SQLCipher",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "An SQLite database with every page AES-256 encrypted, used by messengers and "
            "other apps (Signal, WeChat, many Android apps). The first 16 bytes hold the "
            "random key-derivation salt in place of the SQLite header, so the file looks "
            "random and has no signature. Each page carries an IV and an HMAC; with the "
            "right key and settings (SQLCipher 4 defaults: AES-256-CBC, HMAC-SHA512, "
            "PBKDF2-HMAC-SHA512 with 256,000 iterations) it decrypts to an ordinary SQLite "
            "database. Apps can keep a plaintext header instead (cipher_plaintext_header_size, "
            "mainly for WAL databases in iOS shared containers): the file then begins "
            "'SQLite format 3' but will not open as plain SQLite, and the salt is stored "
            "outside the file.",
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
            (
                "SQLCipher 4, plaintext header and key salt (Zetetic discussion forum)",
                "https://discuss.zetetic.net/t/sqlcipher-4-plaintext-header-and-key-salt-problem/3282",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
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
            "information (company, product, original file name) and icons. The link "
            "timestamp is not always a date: reproducibly built binaries (including "
            "Windows 10+ system files) store a hash there, and 0 or 0xFFFFFFFF mean no "
            "timestamp. An undocumented Rich header lists the compiler and linker versions "
            "used. An Authenticode signature, if present, names the signer. Relevant for "
            "malware analysis and for linking a binary to its origin.",
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
            {
                "offset": None,
                "value": b"PE\x00\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "PE signature at the file offset stored in e_lfanew (0x3C)",
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
            (
                "Why are the module timestamps in Windows 10 so nonsensical? (Raymond Chen, The Old New Thing)",
                "https://devblogs.microsoft.com/oldnewthing/20180103-00/?p=97705",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
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
            "type, network share names and often, in the distributed link tracker block, "
            "the NetBIOS name of the machine and its MAC address (in the version-1 GUIDs). "
            "Evidence of files and volumes that may no longer exist.",
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
                "[MS-SHLLINK]: Shell Link (.LNK) Binary File Format, v10.0 (Microsoft)",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
    },
    {
        "name": "Windows Jump Lists",
        "short_name": "Jump List",
        "category": "execution",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Per-application lists of recently and frequently used items, keyed by an "
            "AppID, stored under %APPDATA%\\Microsoft\\Windows\\Recent\\ in "
            "AutomaticDestinations and CustomDestinations. AutomaticDestinations-ms files "
            "are OLE compound files holding one LNK stream per item and a DestList stream "
            "with access counts, last-access times, pin status and the host name; "
            "CustomDestinations-ms files hold categories of LNK records pinned or provided "
            "by the application, closed by a footer signature. They persist after the "
            "referenced files are gone.",
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
            {
                "offset": None,
                "value": b"\xab\xfb\xbf\xba",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "CustomDestinations-ms footer signature 0xBABFFBAB at the end of the file",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
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
        "platforms": ALL_PLATFORMS,
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
            {
                "offset": 0,
                "value": b"\x0e\x11\xfc\x0d\xd0\xcf\x11\x0e",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Signature of early beta OLE2 compound files",
                    "OLE Compound File (CFB)",
                ),
            },
        ],
        "extensions": [".doc", ".xls", ".ppt", ".msg", ".msi"],
        "links": [
            (
                "[MS-CFB]: Compound File Binary File Format, v12.0 (Microsoft)",
                "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/53989ce4-7b05-4f8d-829b-d08d6148375b",
            ),
            (
                "OLE Compound File format (libyal/libolecf)",
                "https://github.com/libyal/libolecf/blob/main/documentation/OLE%20Compound%20File%20format.asciidoc",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
    },
    {
        "name": "Extensible Storage Engine (ESE) Database",
        "short_name": "ESE",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Microsoft's embedded database engine (JET Blue). Used by SRUM (SRUDB.dat — "
            "per-app network and energy usage), Windows Search up to Windows 10 "
            "(Windows.edb; Windows 11 uses SQLite instead), Internet Explorer/Edge legacy "
            "WebCache, Active Directory (ntds.dit) and Exchange. Pages are written through "
            "transaction logs (.log/.jrs), and a database copied from a live system may be "
            "in a 'dirty shutdown' state (recorded in the file header) with changes still "
            "only in the logs.",
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
            (
                "Windows Search Index: the forensic artifact you've been searching for — ESE vs. SQLite in Windows 11 (LevelBlue/Stroz Friedberg, 2023)",
                "https://www.levelblue.com/blogs/spiderlabs-blog/windows-search-index-the-forensic-artifact-youve-been-searching-for/",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
    },
    {
        "name": "Windows Event Log (EVT, legacy)",
        "short_name": "EVT",
        "category": "log",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The binary event log of Windows NT to XP/2003 (AppEvent.Evt, SecEvent.Evt, "
            "SysEvent.Evt): a circular buffer of event records with record number, "
            "generated and written times (POSIX time, UTC), event ID, source and strings. "
            "Records from before a wrap can remain in the file's free space, and since "
            "every record carries the 'LfLe' signature, records can also be carved from "
            "unallocated space or memory. Superseded by EVTX from Windows Vista on.",
            "Windows Event Log (EVT, legacy)",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"\x30\x00\x00\x00LfLe",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "File header: size 0x30 followed by signature 'LfLe' at offset 4",
                    "Windows Event Log (EVT, legacy)",
                ),
            },
            {
                "offset": None,
                "value": b"LfLe",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Event record signature 'LfLe' at offset 4 of every record",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
    },
    {
        "name": "Windows Thumbnail Cache",
        "short_name": "Thumbcache",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Explorer's thumbnail databases (thumbcache_*.db with an index file "
            "thumbcache_idx.db under %LOCALAPPDATA%\\Microsoft\\Windows\\Explorer\\, "
            "Windows Vista to Windows 11). Each entry holds a thumbnail image keyed by a "
            "cache ID but no file name; the original path can be recovered by matching the "
            "ThumbnailCacheId against the Windows Search index. Thumbnails can remain after "
            "the original pictures, videos or documents were deleted or were on a "
            "removable or network drive.",
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
                "ForensicsWiki — Windows thumbcache",
                "https://forensics.wiki/windows_thumbcache/",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
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
            "reused. A stand-alone $MFT contains resident data only; non-resident file "
            "content and the rest of the filesystem are not included.",
            "NTFS Master File Table ($MFT)",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"FILE0\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "MFT entry signature 'FILE' with fixup offset 0x30 (NTFS 3.1, Windows XP and later)",
                    "NTFS Master File Table ($MFT)",
                ),
            },
            {
                "offset": 0,
                "value": b"FILE*\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "MFT entry signature 'FILE' with fixup offset 0x2A (NTFS 3.0 and earlier)",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
    },
    {
        "name": "NTFS Transaction Log ($LogFile)",
        "short_name": "$LogFile",
        "category": "log",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The NTFS metadata journal: restart pages ('RSTR') followed by log record "
            "pages ('RCRD') describing redo and undo operations on MFT entries, indexes "
            "and bitmaps. Covers the most recent minutes to hours of file system activity, "
            "including creations, renames and deletions.",
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
            {
                "offset": None,
                "value": b"RCRD",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Log record page signature 'RCRD' (pages after the restart area)",
                    "NTFS Transaction Log ($LogFile)",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "NTFS $LogFile structures — fs/ntfs3/fslog.c (Linux kernel source)",
                "https://github.com/torvalds/linux/blob/master/fs/ntfs3/fslog.c",
            ),
            (
                "Finding Forensic Information on Creating a Folder in $LogFile of NTFS (Cho, Rogers — ICDF2C 2011)",
                "https://doi.org/10.1007/978-3-642-35515-8_18",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
    },
    {
        "name": "NTFS Change Journal ($UsnJrnl:$J)",
        "short_name": "$UsnJrnl",
        "category": "log",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The update sequence number journal in the $J stream of $Extend\\$UsnJrnl: one "
            "record per change with file reference, parent reference, timestamp, reason "
            "flags (create, rename, delete, data overwrite …) and file name. Records are "
            "version 2 by default; version 3 (128-bit file IDs, ReFS, or NTFS with range "
            "tracking) and version 4 also occur. It often reaches back days or weeks and "
            "names files that no longer exist. The stream is sparse; only its end holds "
            "records.",
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
                "USN_RECORD_V3 structure — 128-bit file IDs, range tracking (Microsoft)",
                "https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v3",
            ),
            (
                "New Technologies File System (NTFS) — format documentation, USN change journal (libyal/libfsntfs)",
                "https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
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
            (
                "Forensic Analysis of the Microsoft Windows Vista Recycle Bin (Mitchell Machor, Forensic Focus, 2008)",
                "https://www.forensicfocus.com/articles/forensic-analysis-of-the-microsoft-windows-vista-recycle-bin/",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
    },
    {
        "name": "Volume Shadow Copy (VSS)",
        "short_name": "VSS",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Copy-on-write snapshots of an NTFS volume (System Restore, backups, previous "
            "versions). Changed 16 KiB blocks are kept in store files named "
            "{GUID}{3808876B-C176-4E48-B7AE-04046E6CC752} under System Volume Information "
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
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
    },
    {
        "name": "Outlook Personal Folders (PST / OST)",
        "short_name": "PST",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Outlook's mailbox file: e-mails, attachments, calendar, contacts and tasks in "
            "a B-tree based node database (.pst for archives and POP accounts, .ost as the "
            "offline cache of Exchange/Microsoft 365). Exists as 32-bit ANSI (older "
            "Outlook, 2 GB limit), 64-bit Unicode and Unicode with 4 KiB pages. Deleted "
            "items can remain in unallocated blocks. Optional 'compressible' or 'high' "
            "encoding obscures but does not protect the content.",
            "Outlook Personal Folders (PST / OST)",
        ),
        "platforms": ["Windows"],
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
            {
                "offset": 8,
                "value": b"SM",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Content type 'SM' — Personal Storage Table (.pst)",
                    "Outlook Personal Folders (PST / OST)",
                ),
            },
            {
                "offset": 8,
                "value": b"SO",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Content type 'SO' — Offline Storage Table (.ost)",
                    "Outlook Personal Folders (PST / OST)",
                ),
            },
        ],
        "extensions": [".pst", ".ost"],
        "links": [
            (
                "[MS-PST]: Outlook Personal Folders (.pst) File Format, v11.2 (Microsoft)",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
    },
    {
        "name": "Windows Minidump",
        "short_name": "MDMP",
        "category": "memory",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "A partial user-mode process memory dump written on application crashes "
            "(Windows Error Reporting, e.g. %LOCALAPPDATA%\\CrashDumps) or on demand. "
            "Streams describe the threads, loaded modules with versions and timestamps, "
            "exception record, system information and selected memory ranges of the "
            "process; the header records when the dump was written. Dumps of lsass.exe "
            "are a common sign of credential theft. Kernel crash dumps (MEMORY.DMP, "
            "%SystemRoot%\\Minidump) use a different format.",
            "Windows Minidump",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"MDMP\x93\xa7",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Signature 'MDMP' followed by format version 0xA793",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
    },
    {
        "name": "Windows Hibernation File (hiberfil.sys)",
        "short_name": "hiberfil",
        "category": "memory",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The compressed copy of physical memory Windows writes on hibernation and, with "
            "Fast Startup, on every shutdown (kernel session only). Contains processes, "
            "network state and decrypted keys as they were in RAM. Windows 8 and later "
            "compress with Xpress or Xpress Huffman and, after resume, keep the header but "
            "zero everything after the first 4 KiB, so the content is only available "
            "between hibernation and the next power-on; up to Windows 7 only the first "
            "page is wiped and compressed memory pages can remain.",
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
                    "Header signature 'hibr' (Windows XP and earlier)",
                    "Windows Hibernation File (hiberfil.sys)",
                ),
            },
            {
                "offset": 0,
                "value": b"HIBR",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Header signature 'HIBR' (Windows Vista and later)",
                    "Windows Hibernation File (hiberfil.sys)",
                ),
            },
            {
                "offset": 0,
                "value": b"wake",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Header signature 'wake' after resume (Windows XP and earlier)",
                    "Windows Hibernation File (hiberfil.sys)",
                ),
            },
            {
                "offset": 0,
                "value": b"WAKE",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Header signature 'WAKE' after resume (Windows Vista and later)",
                    "Windows Hibernation File (hiberfil.sys)",
                ),
            },
            {
                "offset": None,
                "value": b"RSTR",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Header signature 'RSTR' at offset 0 during restore; the same bytes "
                    "start an NTFS $LogFile restart page",
                    "Windows Hibernation File (hiberfil.sys)",
                ),
            },
        ],
        "extensions": [".sys"],
        "links": [
            (
                "Windows Hibernation File (hiberfil.sys) format, up to Windows 7 (libyal/libhibr)",
                "https://github.com/libyal/libhibr/blob/main/documentation/Windows%20Hibernation%20File%20(hiberfil.sys)%20format.asciidoc",
            ),
            (
                "Modern Windows Hibernation File Analysis (Sylve, Marziale, Richard — Digital Investigation, 2016)",
                "https://cct.lsu.edu/~golden/Papers/modern-windows-hibernation-2017.pdf",
            ),
            (
                "ForensicsWiki — Hiberfil.sys",
                "https://forensics.wiki/hiberfil.sys/",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
    },
    {
        "name": "Resilient File System (ReFS)",
        "short_name": "ReFS",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Microsoft's copy-on-write filesystem for Windows Server and Dev Drives on "
            "Windows 11, in two incompatible format generations (1.x from Windows 8/Server "
            "2012, 3.x from Windows 10/Server 2016). Metadata is held in B+ trees that are "
            "written to new locations on every change, so older tree pages can remain. "
            "Supports integrity streams (checksums) and block cloning.",
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
            {
                "offset": 16,
                "value": b"FSRS",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "File system recognition structure signature 'FSRS'",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-04"
    },
{
        "name": "macOS Keychain (file-based)",
        "short_name": "kych",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The legacy file-based macOS Keychain format used by files such as login.keychain-db and System.keychain. "
            "The file starts with the ASCII signature 'kych' and contains a CSSM-style database with tables for "
            "keychain items such as generic and internet passwords, certificates and cryptographic keys. "
            "Many item attributes, including account, service/server information and metadata, are stored separately "
            "from the protected secret data. Secret data is encrypted (3DES-CBC) with item keys wrapped by a "
            "database key, which is protected by a master key derived from the keychain password "
            "(PBKDF2-HMAC-SHA1); System.keychain is unlocked via /var/db/SystemKey. For forensic analysis, the "
            "database can contain credentials, certificates, private keys and other authentication material, while "
            "metadata can remain useful even when secrets cannot be decrypted. "
            "This file-based format is distinct from the SQLite-based data protection keychain (for example "
            "keychain-2.db), which uses a different implementation and format.",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "Apple File System Events (FSEvents)",
        "short_name": "FSEvents",
        "category": "log",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Persistent file system event logs stored in /.fseventsd on macOS volumes and also "
            "encountered in forensic extractions from iOS and other Apple devices. Each log file is a "
            "multi-member gzip stream; the decompressed data consists of pages starting with a "
            "'1SLD' (Mac OS X 10.5 to macOS 10.12), '2SLD' (macOS 10.13 and later) or '3SLD' "
            "(macOS 14 and later) signature. The records contain an event ID, path, and event "
            "flags such as created, modified, renamed, removed, metadata or permission changes; "
            "version 2 records add a file system node ID, version 3 records additionally a user ID. "
            "FSEvents are primarily directory/file activity indicators rather than a complete audit "
            "trail: events can be coalesced, and an event does not necessarily prove that a file was "
            "opened or read. The on-disk event records do not provide a conventional per-record "
            "timestamp; forensic timelines therefore require correlation with the log files' file "
            "system timestamps and other evidence. Log file names are hexadecimal event IDs that "
            "provide ordering, not time. FSEvents can preserve evidence of paths and file system "
            "activity after the corresponding files or directories have been deleted or are otherwise "
            "no longer present.",
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
                    "Page signature '1SLD' at offset 0 of the decompressed (gzip) stream",
                    "Apple File System Events (FSEvents)",
                ),
            },
            {
                "offset": None,
                "value": b"2SLD",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Page signature '2SLD' at offset 0 of the decompressed (gzip) stream",
                    "Apple File System Events (FSEvents)",
                ),
            },
            {
                "offset": None,
                "value": b"3SLD",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Page signature '3SLD' at offset 0 of the decompressed (gzip) stream",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "Apple Spotlight Store",
        "short_name": "Spotlight",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Apple Spotlight metadata indexes used by macOS and iOS. On macOS, stores are typically "
            "found below /.Spotlight-V100/Store-V2/<UUID>/ and can contain store.db and .store.db files; "
            "on iOS, CoreSpotlight indexes are found below .../Library/Spotlight/CoreSpotlight/ "
            "(index.spotlightV2). Other Spotlight/CoreSpotlight indexes can exist in user and "
            "application-specific locations. "
            "The store contains metadata records associated with indexed file-system objects, including "
            "file names, paths or path-related information, content types, creation and modification "
            "dates, last-used dates, authors, download/source information, URLs and other metadata; "
            "depending on the item and index, textual content or searchable content metadata may also "
            "be present. Spotlight data is therefore valuable for reconstructing the existence and "
            "metadata of files that are no longer present on the live file system, although the presence "
            "of an index record does not by itself prove that the corresponding file still existed at "
            "the time of acquisition or establish how the file was accessed. Spotlight stores are "
            "proprietary databases and their exact contents vary with macOS/iOS versions and the type "
            "of index.",
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
                    "Signature '8tsd' at the beginning of a Spotlight store database",
                    "Apple Spotlight Store",
                ),
            },
        ],
        "extensions": [],
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "Apple System Log (ASL)",
        "short_name": "ASL",
        "category": "log",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The binary Apple System Log database format used by Mac OS X/macOS up to 10.11 and by "
            "early iOS versions. On macOS, persistent ASL databases are commonly found below "
            "/private/var/log/asl/. Records can contain timestamps, host, sender, facility, "
            "process ID, user/group IDs, severity level and message text, together with additional "
            "free-form key-value attributes. ASL can preserve valuable historical evidence of "
            "system, application and security-related activity, including events that are no "
            "longer reflected in the current system state. Retention is controlled by the ASL "
            "configuration (/etc/asl.conf and /etc/asl/), which often keeps only a limited period; "
            "missing time ranges may therefore reflect rotation rather than inactivity. "
            "Starting with macOS 10.12, Apple superseded ASL with the Unified Logging system, "
            "although legacy ASL databases and ASL-compatible logging may still be encountered "
            "on later systems.",
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
                    "ASL database signature",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "macOS Finder .DS_Store",
        "short_name": ".DS_Store",
        "category": "configuration",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Hidden Finder files storing per-directory metadata and view settings in a B-tree "
            "database. Records are keyed by file or directory name and can contain information "
            "such as icon position, Finder view style, display settings, Spotlight comments and, "
            "for directories, timestamps (modD/moDD). Records "
            "may persist after the corresponding file has been removed from the directory, making "
            ".DS_Store files potentially useful for recovering names and other historical evidence "
            "of directory contents. .DS_Store files can also be found outside the original macOS "
            "volume, for example on network shares, removable media and in extracted archive "
            "contents, because Finder may create them when browsing those locations.",
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
                    "Initial alignment value 1 followed by buddy-allocator magic 'Bud1'",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "AppleDouble / AppleSingle",
        "short_name": "AppleDouble",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Containers for Macintosh file metadata and resource forks when the underlying "
            "filesystem or transport cannot preserve them natively. AppleDouble stores the "
            "metadata in a separate header file, commonly named '._<filename>', alongside the "
            "data file; AppleSingle stores the data fork and metadata in a single container. "
            "AppleDouble files can contain Finder information, a resource fork and extended "
            "attributes; macOS stores extended attributes in an Apple-specific 'ATTR' structure "
            "following the Finder Info entry. Modern macOS AppleDouble files can therefore preserve "
            "forensic metadata such as com.apple.quarantine, Finder tags and other extended attributes, "
            "including download or provenance information where present. They are commonly encountered on "
            "non-Mac filesystems and transports and inside ZIP archives, where Finder-created "
            "AppleDouble files may occur below __MACOSX/. The containers can preserve metadata "
            "that is otherwise absent from the corresponding data file and can therefore provide "
            "valuable evidence about file provenance, Finder state and historical file attributes.",
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
            (
                "copyfile.c — AppleDouble '._' layout with ATTR extended attributes (Apple OSS)",
                "https://github.com/apple-oss-distributions/copyfile/blob/main/copyfile.c",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "Apple Bill of Materials (BOM)",
        "short_name": "BOM",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Apple's BOMStore container format used for installer Bill of Materials files and "
            "also as the underlying container for compiled asset catalogs such as Assets.car. "
            "macOS installer receipts in /var/db/receipts/*.bom contain file records with "
            "metadata such as path, mode, owner, group, size and checksum, making them useful "
            "for establishing which files a package installed and for comparing an installed "
            "file set with the expected package contents. Installer packages (.pkg, xar) also "
            "contain an internal 'Bom' file. Assets.car files use the BOMStore "
            "container together with CoreUI-specific structures for compiled asset catalogs; "
            "they should therefore be treated as a distinct higher-level format rather than as "
            "ordinary BOM receipt files. BOMStore data consists of named blocks, variables and "
            "B-tree structures.",
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
                    "BOMStore signature 'BOMStore'",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
{
        "name": "XAR Archive",
        "short_name": "XAR",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The eXtensible ARchive format used by macOS flat installer packages (.pkg), XIP archives "
            "and some other Apple software distribution artifacts; older bundle-style .pkg packages are "
            "directories instead. An XAR archive consists of a big-endian binary header, a "
            "zlib-compressed XML table of contents (TOC) and a heap containing the archived file data. "
            "The TOC can contain paths, file types, ownership, permissions, timestamps, sizes and "
            "per-file archived and extracted checksums, providing useful metadata for forensic analysis "
            "and integrity comparisons. Signed XAR archives reference the signature data stored in the "
            "heap from the TOC, which also embeds the associated X.509 certificate chain. For installer "
            "packages, the TOC can therefore provide both metadata about package contents and "
            "information useful for validating the integrity and provenance of the package.",
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
                    "XAR signature 'xar!'",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "Apple Encrypted Archive (AEA)",
        "short_name": "AEA",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Apple's archive container providing signing and/or encryption, selected by a profile ID in "
            "the header (signed-only, symmetric, ECDHE-based and password/scrypt-based variants). The "
            "payload is typically compressed and can be an Apple Archive or other data such as disk "
            "images. Signed-only archives (profile 0) are not encrypted; this profile is used, for "
            "example, for shared Shortcuts (.shortcut) since iOS 15. Encrypted archives are used for "
            "Apple software distribution, including root filesystem images in IPSWs (.dmg.aea) since "
            "iOS 18 / macOS 15; the header's authentication data contains the parameters needed to "
            "obtain the decryption key. Without the key, encrypted archives still establish presence, "
            "profile and provenance metadata, but not their contents.",
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
                    "AEA format signature 'AEA1'",
                    "Apple Encrypted Archive (AEA)",
                ),
            },
        ],
        "extensions": [".aea", ".shortcut"],
        "links": [
            (
                "Apple Encrypted Archive (The Apple Wiki)",
                "https://theapplewiki.com/wiki/Apple_Encrypted_Archive",
            ),
            (
                "AEA guide (blacktop/ipsw documentation)",
                "https://blacktop.github.io/ipsw/docs/guides/aea",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "Apple Partition Map (APM)",
        "short_name": "APM",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The Apple Partition Map partitioning scheme used by classic Macintosh systems and "
            "PowerPC-based Macs, and also encountered on some older Apple media and disk images. "
            "The partition map begins with a driver descriptor record in block 0, which also states "
            "the block size, followed by partition map entries starting in block 1 (512-byte entries, "
            "or 2048-byte entries on media such as CD-ROMs). Each entry contains the partition name, "
            "partition type, starting block, partition size and additional metadata. The map describes "
            "itself as a partition of type Apple_partition_map; other common partition types include "
            "Apple_HFS, Apple_Driver43 and Apple_Free. The partition map is forensically important "
            "because it defines the original partition layout and boundaries, allowing individual "
            "partitions to be located and interpreted correctly in a disk image, including partitions "
            "that may not currently be mounted or recognized by a modern operating system.",
            "Apple Partition Map (APM)",
        ),
        "platforms": ["macOS"],
        "parser_class": None,
        "magic": [
            {
                "offset": None,
                "value": b"ER",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Driver descriptor signature 'ER' in block 0 (too short to identify on its own)",
                    "Apple Partition Map (APM)",
                ),
            },
            {
                "offset": 512,
                "value": b"PM",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Partition map entry signature 'PM' in block 1",
                    "Apple Partition Map (APM)",
                ),
            },
            {
                "offset": 2048,
                "value": b"PM",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Partition map entry signature 'PM' in block 1 on 2048-byte block media (e.g. CD-ROM)",
                    "Apple Partition Map (APM)",
                ),
            },
            {
                "offset": 560,
                "value": b"Apple_partition_map",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Partition type 'Apple_partition_map' of the first map entry, which describes the map itself",
                    "Apple Partition Map (APM)",
                ),
            },
            {
                "offset": 2096,
                "value": b"Apple_partition_map",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Partition type 'Apple_partition_map' of the first map entry on 2048-byte block media",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "Android Boot Image",
        "short_name": "Boot image",
        "category": "disk_image",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Android boot partition images (boot, recovery, init_boot, vendor_boot) consisting of a "
            "header followed by page-aligned kernel, ramdisk and, depending on the header version, "
            "further components. Header versions 0-2 (up to Android 10) can contain a second-stage "
            "loader, recovery DTBO (v1+) and DTB (v2); version 3 (Android 11) moves DTB and vendor "
            "ramdisk to the separate vendor_boot image ('VNDRBOOT'); version 4 (Android 12) adds a "
            "boot signature. The header contains the kernel command line and an OS version/security "
            "patch level field, which is zero on Android 13+ GKI devices. Boot images reveal the "
            "kernel and early init configuration a device boots with and can show modifications such "
            "as patched ramdisks used for rooting. On A/B devices, images exist per slot (_a/_b).",
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
        "extensions": [],
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
{
        "name": "systemd Journal",
        "short_name": "journal",
        "category": "log",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The binary log of systemd-journald, stored persistently below "
            "/var/log/journal/<machine-id>/ or volatile below /run/log/journal/ (lost on reboot). "
            "Entries consist of key-value fields (MESSAGE, _PID, _UID, _COMM, _BOOT_ID, …) with "
            "realtime and monotonic timestamps; field data can be XZ-, LZ4- or ZSTD-compressed. "
            "If Forward Secure Sealing is enabled, tag objects containing an SHA-256 HMAC are "
            "appended at regular intervals, allowing later detection of tampering. The header "
            "state marks files as offline, online (open for writing, e.g. not closed cleanly) or "
            "archived; rotated files keep older entries, and files found corrupted or unclean are "
            "renamed with a '~' suffix.",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "LUKS Encrypted Volume",
        "short_name": "LUKS",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Linux Unified Key Setup, the standard Linux disk encryption format. A header "
            "with cipher, UUID and up to 8 (LUKS1) or 32 (LUKS2) key slots, each holding "
            "the volume key encrypted with a passphrase or key file; LUKS2 adds a JSON "
            "metadata area and a secondary header copy. Key slot material is stored using an "
            "anti-forensic splitter, so a wiped key slot is practically unrecoverable. The header "
            "can also be detached and stored separately; the encrypted volume then shows no "
            "signature and appears as random data, and a header backup may be required for "
            "decryption. Without a slot's secret the data area is ciphertext.",
            "LUKS Encrypted Volume",
        ),
        "platforms": ["Linux"],
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
                "offset": 16384,
                "value": b"SKUL\xba\xbe",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "LUKS2 secondary header magic 'SKUL' 0xBA 0xBE at default offset 0x4000 "
                    "(other fixed offsets up to 4 MiB possible)",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
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
            "logical volumes can be traced. On the host system, further metadata history is kept "
            "as text files below /etc/lvm/archive/ and /etc/lvm/backup/, which can reach further "
            "back than the on-disk ring buffer.",
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
            {
                "offset": 536,
                "value": b"LVM2 001",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Label type indicator 'LVM2 001' (offset 24 within the label)",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "utmp / wtmp / btmp Login Records",
        "short_name": "utmp",
        "category": "log",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Binary login records on Linux and other Unix systems: utmp (current sessions, "
            "/run/utmp or /var/run/utmp), wtmp (login/logout, boot and shutdown history, "
            "/var/log/wtmp) and btmp (failed logins, /var/log/btmp). Each record has type, PID, "
            "terminal, user name, remote host or IP and a timestamp. Record layouts differ between "
            "operating systems and architectures (glibc: 384 bytes). No header or signature; records "
            "are recognised by size and layout. The files carry no integrity protection and can be "
            "edited or truncated. btmp may contain passwords mistakenly entered as user names. Some "
            "distributions (e.g. openSUSE since 2023) replaced utmp/wtmp/lastlog with the Y2038-safe "
            "SQLite-based wtmpdb and lastlog2.",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
{
        "name": "LiME Memory Image",
        "short_name": "LiME",
        "category": "memory",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Physical memory captured from Linux and Android devices with the LiME kernel "
            "module; Microsoft's AVML also writes this format. In 'lime' format each captured "
            "memory range is preceded by a 32-byte header with magic, version and its start and "
            "end physical address; gaps between ranges are not stored. 'padded' format fills "
            "gaps with zeros, 'raw' format concatenates the ranges without headers, losing the "
            "physical address information. AVML can additionally write a Snappy-compressed "
            "variant with 'AVML' range headers.",
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
            {
                "offset": 0,
                "value": b"AVML",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "AVML compressed range header magic 0x4C4D5641 (little-endian 'AVML', version 2)",
                    "LiME Memory Image",
                ),
            },
        ],
        "extensions": [".lime"],
        "links": [
            (
                "LiME — Linux Memory Extractor",
                "https://github.com/jtsylve/LiME",
            ),
            (
                "AVML — Acquire Volatile Memory for Linux (Microsoft)",
                "https://github.com/microsoft/avml",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
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
            "and, on v5 filesystems, a creation time. Newer filesystems can use the bigtime "
            "feature (Y2038-safe timestamps with a different epoch and encoding), which must "
            "be taken into account when interpreting timestamps.",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
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
            "contents can hold previous versions of files. The superblock additionally keeps "
            "four backup roots referencing earlier tree generations, and superblock mirrors "
            "exist at 64 MiB and 256 GiB where the device is large enough.",
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
            {
                "offset": None,
                "value": b"_BHRfS_M",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Superblock mirror magic at 64 MiB + 0x40 and 256 GiB + 0x40 (if present)",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "PCAP Packet Capture",
        "short_name": "PCAP",
        "category": "network",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The classic libpcap capture format written by tcpdump, Wireshark and many "
            "network devices: a global header with link type and snapshot length, then one "
            "record per packet with a timestamp (microsecond or nanosecond resolution, UTC), "
            "the captured length, the original packet length and the captured bytes. Packets "
            "longer than the snapshot length are truncated; the differing lengths make such "
            "truncation visible.",
            "PCAP Packet Capture",
        ),
        "platforms": ALL_PLATFORMS,
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "PCAPNG Packet Capture",
        "short_name": "PCAPNG",
        "category": "network",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The block-based successor of PCAP and Wireshark's default: section header, "
            "interface descriptions with names and per-interface time resolution, enhanced "
            "packet blocks, name resolution blocks, and comments. Can hold captures from several "
            "interfaces and link types in one file and records capture hardware, OS and "
            "application. Decryption Secrets Blocks can embed key material such as TLS session "
            "keys, allowing encrypted traffic in the same file to be decrypted.",
            "PCAPNG Packet Capture",
        ),
        "platforms": ALL_PLATFORMS,
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
            {
                "offset": 8,
                "value": b"\x1a\x2b\x3c\x4d",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Byte-order magic 0x1A2B3C4D (big-endian)",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
{
        "name": "RAR Archive",
        "short_name": "RAR",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The RAR archive format (versions 1.5–4.x and 5.0): headers with file names, "
            "sizes, modification (and optionally creation and access) times and attributes; "
            "RAR 5.0 stores times as Unix time (optionally with nanoseconds) or Windows FILETIME. "
            "Supports solid compression, multi-volume sets and recovery records. RAR 5.0 uses "
            "AES-256 with PBKDF2, RAR 3.x–4.x AES-128, while RAR 2.x used a proprietary cipher; "
            "encryption can cover the data or the headers too. With encrypted headers even the "
            "file names are hidden. Self-extracting (SFX) archives carry the RAR signature not at "
            "offset 0 but after an executable module and are therefore initially identified as "
            "executables.",
            "RAR Archive",
        ),
        "platforms": ALL_PLATFORMS,
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
            {
                "offset": None,
                "value": b"RE~^",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Signature of RAR versions before 1.5 (sparsely documented)",
                    "RAR Archive",
                ),
            },
        ],
        "extensions": [".rar", ".r00"],
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "bzip2 Compressed Data",
        "short_name": "bzip2",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Block-sorting compressed stream holding a single file, often a TAR archive "
            "(.tar.bz2) or a log/disk image. No file name or timestamp is stored. Each block "
            "(up to 900 kB uncompressed) carries its own CRC and starts with a 48-bit block "
            "magic; since blocks are bit-aligned, recovering undamaged blocks from truncated or "
            "carved streams requires a bit-level search (e.g. bzip2recover). Multiple streams "
            "may be concatenated.",
            "bzip2 Compressed Data",
        ),
        "platforms": ALL_PLATFORMS,
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
            {
                "offset": 4,
                "value": b"1AY&SY",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "First block magic 0x314159265359 (BCD pi)",
                    "bzip2 Compressed Data",
                ),
            },
            {
                "offset": 4,
                "value": b"\x17rE8P\x90",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Stream footer magic 0x177245385090 (BCD sqrt(pi)) of an empty stream",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "XZ Compressed Data",
        "short_name": "XZ",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "LZMA2-based compressed stream holding a single file, often a TAR archive "
            "(.tar.xz), Linux packages, kernel modules or firmware. Streams consist of "
            "blocks with integrity checks (CRC32, CRC64, SHA-256 or none) and an index, and "
            "end with the footer magic 'YZ'; multiple streams may be concatenated. No file "
            "name or timestamp is stored.",
            "XZ Compressed Data",
        ),
        "platforms": ALL_PLATFORMS,
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "Zstandard Compressed Data",
        "short_name": "zstd",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Zstandard frames as used for .zst files, Linux packages (e.g. Arch Linux "
            ".pkg.tar.zst), initramfs and kernel modules, and as HTTP content encoding stored "
            "in browser caches. A frame header may record the content size, a checksum flag and "
            "a dictionary ID; data compressed with a dictionary cannot be decompressed without "
            "that dictionary. Skippable frames (magic 0x184D2A50–0x184D2A5F) can carry arbitrary "
            "other data.",
            "Zstandard Compressed Data",
        ),
        "platforms": ALL_PLATFORMS,
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
            {
                "offset": None,
                "value": b"\x50\x2a\x4d\x18",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Skippable frame magic 0x184D2A50–0x184D2A5F (low nibble of first byte varies)",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "LZ4 Frame",
        "short_name": "LZ4",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The LZ4 frame format for .lz4 files and LZ4-compressed data in apps, kernels "
            "and databases. The frame descriptor records block size, checksums and "
            "optionally the content size. The older legacy frame format (fixed 8 MB blocks, no "
            "checksum) is still used by the Linux kernel for LZ4-compressed kernel images and "
            "initramfs. (Mozilla's jsonlz4 and Apple's LZ4 variants use other headers.)",
            "LZ4 Frame",
        ),
        "platforms": ALL_PLATFORMS,
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
            {
                "offset": 0,
                "value": b"\x02\x21\x4c\x18",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Legacy frame magic 0x184C2102",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "Mozilla LZ4 (jsonlz4)",
        "short_name": "jsonlz4",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Firefox's LZ4-compressed JSON files: session store (sessionstore.jsonlz4, "
            "recovery.jsonlz4 — open tabs, history per tab, form data, cookies), bookmark "
            "backups, search engine configuration (search.json.mozlz4), add-on startup data "
            "(addonStartup.json.lz4) and other add-on data. A custom header 'mozLz40\\0' and the "
            "decompressed size (4 bytes, little-endian) precede a raw LZ4 block without frame.",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
{
        "name": "Microsoft Cabinet (CAB)",
        "short_name": "CAB",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Microsoft's compressed archive format for installers, Windows updates and "
            "drivers. Holds file names, sizes, DOS date/time stamps and attributes for each "
            "file; the DOS timestamps have a 2-second resolution and no time zone and usually "
            "reflect the creator's local time. Data is stored uncompressed or compressed with "
            "MSZIP or LZX. Cabinets can be split across several files, each recording the names "
            "of the previous and next cabinet in the set, and can be signed with Authenticode, "
            "the signature being referenced from the reserved header area.",
            "Microsoft Cabinet (CAB)",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"MSCF\x00\x00\x00\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Signature 'MSCF' followed by the zeroed reserved1 field",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "ISO 9660 Optical Disc Image",
        "short_name": "ISO",
        "category": "disk_image",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The CD/DVD filesystem image format, also used to deliver software and malware "
            "(mounted by a double-click on Windows); on older Windows versions, files inside "
            "mounted images did not inherit the Mark-of-the-Web, which made the format popular "
            "for phishing. Volume descriptors from sector 16 on carry the volume name, creating "
            "application and separate creation, modification, expiration and effective dates "
            "including a time zone offset (in 15-minute steps); Joliet and Rock Ridge extensions "
            "add long names and Unix attributes. UDF images may coexist in the same file. Raw "
            "images with 2352-byte sectors (.bin/.cue) store the signature at a different offset.",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "KeePass Database (KDBX)",
        "short_name": "KDBX",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The password database of KeePass, KeePassXC and compatible apps. Outside the "
            "encrypted payload only the header is readable: format version (offset 8), cipher, "
            "compression, master seed and IV; from KDBX 4 on also the key derivation function "
            "and its parameters (e.g. AES-KDF or Argon2 with rounds/memory), protected by an "
            "HMAC-SHA-256. The KDF parameters determine the effort of password attacks. Entries "
            "with titles, user names, passwords, URLs, notes and history are encrypted with a "
            "key derived from the master password and/or key file. Signature 1 is shared with "
            "the older KeePass 1.x format (.kdb); only signature 2 distinguishes them.",
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
                    "Signature 1 0x9AA2D903 (shared with KeePass 1.x)",
                    "KeePass Database (KDBX)",
                ),
            },
            {
                "offset": 4,
                "value": b"g\xfbK\xb5",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Signature 2 0xB54BFB67 (KeePass 2.x / KDBX)",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "VeraCrypt / TrueCrypt Volume",
        "short_name": "VeraCrypt",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Encrypted containers and partitions of VeraCrypt and its predecessor "
            "TrueCrypt. The volume header is itself encrypted with a key derived from the "
            "password (and optional key files/PIM), so a volume has no signature and is "
            "indistinguishable from random data; a hidden volume can sit inside the free "
            "space of an outer one. The first 64 bytes hold the salt; a hidden volume's header "
            "is located at byte 65536, and backup headers encrypted with a different salt are "
            "stored at the end of the volume. Indicators are a size divisible by 512, high "
            "entropy throughout and the absence of any file signature.",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
{
        "name": "Mbox Mailbox",
        "short_name": "mbox",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "A mailbox stored as one text file of concatenated e-mail messages, each "
            "starting with a 'From ' separator line (sender and UTC date). Used by Thunderbird "
            "(folder files without extension, e.g. 'Inbox', 'Sent'), Apple Mail exports "
            "(.mbox package containing an 'mbox' file), Google Takeout and Unix mail spools. "
            "Variants (mboxo, mboxrd, mboxcl, mboxcl2) differ in how body lines starting with "
            "'From ' are escaped ('>From ') or whether Content-Length headers delimit messages; "
            "mboxo escaping is irreversible. Messages deleted in the client can remain in the "
            "file until it is compacted.",
            "Mbox Mailbox",
        ),
        "platforms": ALL_PLATFORMS,
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "E-mail Message (EML / RFC 5322)",
        "short_name": "EML",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "A single e-mail message as text: header fields (From, To, Date, Subject, "
            "Message-ID) and the Received chain, which records each server that handled the "
            "message with time and addresses (newest on top; only entries added by trusted "
            "servers are reliable, lower entries can be forged), followed by the MIME body and "
            "attachments. Authentication results (SPF, DKIM, DMARC) in the headers help judge "
            "whether a message is genuine. No signature; recognised by its header lines.",
            "E-mail Message (EML / RFC 5322)",
        ),
        "platforms": ALL_PLATFORMS,
        "parser_class": None,
        "magic": [],
        "extensions": [".eml"],
        "links": [
            (
                "Internet Message Format (RFC 5322)",
                "https://www.rfc-editor.org/rfc/rfc5322.html",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "Chromium Disk Cache",
        "short_name": "Chrome cache",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The HTTP cache of Chrome, Edge and other Chromium browsers and Electron apps. "
            "The blockfile backend (default on Windows) uses an index file and data_0..3 block "
            "files; the simple backend (default on all other platforms) stores one file per "
            "entry. Entries hold the URL, response headers with server dates and the cached "
            "content (pages, images, scripts), also for sites no longer in history. With cache "
            "partitioning, keys are prefixed with '_dk_' and the site that loaded the resource, "
            "revealing the context in which it was requested. Content is stored as transferred, "
            "so it may be gzip-, Brotli- or Zstandard-encoded.",
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
            {
                "offset": None,
                "value": b"\xd8\x41\x0d\x97\x45\x6f\xfa\xf4",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Simple cache end-of-stream magic 0xF4FA6F45970D41D8 (EOF records within entry files)",
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
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "Microsoft Access Database (MDB / ACCDB)",
        "short_name": "MDB",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The Jet / ACE database format of Microsoft Access: .mdb (Jet 3 for Access 97, Jet 4 "
            "for Access 2000–2003) and .accdb (ACE, Access 2007 and later); the variant "
            "'MSISAM Database' is used by Microsoft Money. Data is stored in pages of 2048 (Jet 3) "
            "or 4096 bytes (Jet 4/ACE). The first page names the database engine at offset 4 and "
            "holds the format version at offset 0x14; it is obfuscated with a fixed RC4 key and "
            "contains the database password (offset 0x42), in Jet 4 additionally masked with a "
            "value derived from the database creation date stored on the same page. Deleted rows "
            "are only flagged in the row offset table of their data page, so their content can "
            "remain until the database is compacted. Such databases are common in business, "
            "accounting and administrative applications.",
            "Microsoft Access Database (MDB / ACCDB)",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 4,
                "value": b"Standard Jet DB",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Engine name 'Standard Jet DB' (Jet 3 / Jet 4, .mdb)",
                    "Microsoft Access Database (MDB / ACCDB)",
                ),
            },
            {
                "offset": 4,
                "value": b"Standard ACE DB",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Engine name 'Standard ACE DB' (Access 2007 and later, .accdb)",
                    "Microsoft Access Database (MDB / ACCDB)",
                ),
            },
            {
                "offset": 4,
                "value": b"MSISAM Database",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Engine name 'MSISAM Database' (Microsoft Money variant)",
                    "Microsoft Access Database (MDB / ACCDB)",
                ),
            },
        ],
        "extensions": [".mdb", ".accdb", ".mny"],
        "links": [
            (
                "MDB file format notes (mdbtools HACKING.md)",
                "https://github.com/mdbtools/mdbtools/blob/dev/HACKING.md",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "Windows Kernel Crash Dump",
        "short_name": "Kernel dump",
        "category": "memory",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Kernel-mode crash dumps written by Windows after a bug check, by default as "
            "%SystemRoot%\\MEMORY.DMP. Depending on the configuration they contain the complete "
            "physical memory (complete dump), most of it (active dump) or only kernel memory "
            "(kernel and automatic dump); small memory dumps in %SystemRoot%\\Minidump\\ use the "
            "same kernel dump format and are distinct from user-mode minidumps ('MDMP'). The "
            "header records the dump type, bug check code and parameters and the physical memory "
            "layout; complete and bitmap-based variants allow memory analysis of processes, "
            "network connections and other volatile state at the time of the crash.",
            "Windows Kernel Crash Dump",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"PAGEDUMP",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Signature 'PAGE' + valid dump marker 'DUMP' (32-bit)",
                    "Windows Kernel Crash Dump",
                ),
            },
            {
                "offset": 0,
                "value": b"PAGEDU64",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Signature 'PAGE' + valid dump marker 'DU64' (64-bit)",
                    "Windows Kernel Crash Dump",
                ),
            },
        ],
        "extensions": [".dmp"],
        "links": [
            (
                "Varieties of Kernel-Mode Dump Files (Microsoft)",
                "https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/varieties-of-kernel-mode-dump-files",
            ),
            (
                "Windows crash dump layer (Volatility 3 source)",
                "https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/layers/crash.py",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "KeePass 1.x Database (KDB)",
        "short_name": "KDB",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The password database format of KeePass 1.x and KeePassX. The fixed-size header is "
            "readable without the key: encryption flags (AES or Twofish), format version, master "
            "seed, IV, the number of groups and entries, a content hash, the transform seed and "
            "the number of key transformation rounds, which determines the effort of password "
            "attacks. Groups and entries with titles, user names, passwords, URLs and notes are "
            "encrypted with a key derived from the master password and/or key file. Signature 1 "
            "is shared with the newer KDBX format; only signature 2 distinguishes them.",
            "KeePass 1.x Database (KDB)",
        ),
        "platforms": ["Windows", "macOS", "Linux", "Android", "iOS"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"\x03\xd9\xa2\x9a",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Signature 1 0x9AA2D903 (shared with KDBX)",
                    "KeePass 1.x Database (KDB)",
                ),
            },
            {
                "offset": 4,
                "value": b"e\xfbK\xb5",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Signature 2 0xB54BFB65 (KeePass 1.x)",
                    "KeePass 1.x Database (KDB)",
                ),
            },
        ],
        "extensions": [".kdb"],
        "links": [
            (
                "KeePass1.h — format constants (KeePassXC)",
                "https://github.com/keepassxreboot/keepassxc/blob/develop/src/format/KeePass1.h",
            ),
            (
                "KeePass1Reader.cpp — header layout (KeePassXC)",
                "https://github.com/keepassxreboot/keepassxc/blob/develop/src/format/KeePass1Reader.cpp",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "Outlook Item (MSG)",
        "short_name": "MSG",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "A single Outlook item (e-mail, appointment, contact, task) stored in a Compound File "
            "Binary container. Properties are stored as streams named '__substg1.0_<tag><type>' "
            "and in a '__properties_version1.0' stream; recipients and attachments are kept in "
            "sub-storages, embedded items as nested storages. Messages contain sender, recipients, "
            "subject, body (plain text, compressed RTF and/or HTML) and timestamps such as "
            "submit, delivery, creation and last modification time; received mail usually "
            "retains the original transport headers including the Received chain. The file "
            "carries the CFB signature and is identified by its stream names.",
            "Outlook Item (MSG)",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": None,
                "value": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "CFB signature at offset 0 (shared with all CFB files); identified by "
                    "'__substg1.0_' / '__properties_version1.0' stream names",
                    "Outlook Item (MSG)",
                ),
            },
        ],
        "extensions": [".msg"],
        "links": [
            (
                "[MS-OXMSG]: Outlook Item (.msg) File Format (Microsoft)",
                "https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxmsg/b046868c-9fbf-41ae-9ffb-8de2bd4eec82",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "Apple Mail Message (EMLX)",
        "short_name": "EMLX",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Apple Mail's per-message storage on macOS, typically below ~/Library/Mail/V<n>/ in "
            "the Messages subfolders of .mbox mailbox directories, with numeric file names. A "
            "file starts with a line holding a decimal byte count, followed by the message in "
            "RFC 5322 / MIME form and an XML property list with Apple Mail metadata such as flags "
            "(read, replied/forwarded, flagged, junk) and the receipt date. '.partial.emlx' files "
            "hold messages whose attachments are stored separately in an Attachments folder. No "
            "signature; recognised by the byte count line and the trailing property list.",
            "Apple Mail Message (EMLX)",
        ),
        "platforms": ["macOS"],
        "parser_class": None,
        "magic": [],
        "extensions": [".emlx"],
        "links": [
            (
                "Apple Mail Email Format (EMLX) (Library of Congress)",
                "https://www.loc.gov/preservation/digital/formats/fdd/fdd000615.shtml",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "Apple Binary Cookies",
        "short_name": "binarycookies",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Cookie store of Safari and WebKit-based apps (Cookies.binarycookies) on macOS and "
            "iOS, found in the user's and in app-specific Library/Cookies directories. A "
            "big-endian file header lists the page sizes; each page holds little-endian cookie "
            "records with domain, name, path, value, flags (secure, HTTP-only) and expiration and "
            "creation times as Cocoa timestamps (seconds since 2001-01-01 UTC). Cookies reveal "
            "visited services, logged-in accounts and their creation time, also for apps with "
            "embedded web views.",
            "Apple Binary Cookies",
        ),
        "platforms": ["macOS", "iOS"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"cook",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Signature 'cook'",
                    "Apple Binary Cookies",
                ),
            },
        ],
        "extensions": [".binarycookies"],
        "links": [
            (
                "Safari cookies file format (libyal/dtformats)",
                "https://github.com/libyal/dtformats/blob/main/documentation/Safari%20Cookies.asciidoc",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "Chromium Session File (SNSS)",
        "short_name": "SNSS",
        "category": "log",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Session restore files of Chrome, Edge and other Chromium browsers in the profile's "
            "Sessions folder (Session_<time>, Tabs_<time>, Apps_<time>; older versions used "
            "'Current Session' / 'Last Session' and 'Current Tabs' / 'Last Tabs'). A header with "
            "the signature and a version is followed by a sequence of commands describing "
            "windows, tabs and their navigation entries with URL, title, referrer and timestamp. "
            "They show open tabs and per-tab back/forward history, including recently closed "
            "tabs, independent of the browsing history database. Format version 5 files are "
            "encrypted with the operating system's credential protection and are kept in a "
            "separate Sessions_Encrypted folder.",
            "Chromium Session File (SNSS)",
        ),
        "platforms": ["Windows", "macOS", "Linux"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"SNSS",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Signature 'SNSS' (0x53534E53)",
                    "Chromium Session File (SNSS)",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "command_storage_backend.cc (Chromium source)",
                "https://github.com/chromium/chromium/blob/main/components/sessions/core/command_storage_backend.cc",
            ),
            (
                "session_constants.cc (Chromium source)",
                "https://github.com/chromium/chromium/blob/main/components/sessions/core/session_constants.cc",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "Android Super Partition (Dynamic Partitions)",
        "short_name": "super",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The 'super' partition of Android devices with dynamic partitions, holding logical "
            "partitions such as system, vendor and product (per slot on A/B devices). After 4096 "
            "reserved bytes it contains the partition geometry and a backup copy, followed by "
            "the partition metadata (with backup copies per slot) describing each logical "
            "partition's name, attributes and extents. The metadata is needed to locate and "
            "extract the individual partition images. Images from factory or update packages are "
            "often stored as Android sparse images and must be expanded first.",
            "Android Super Partition (Dynamic Partitions)",
        ),
        "platforms": ["Android"],
        "parser_class": None,
        "magic": [
            {
                "offset": 4096,
                "value": b"gDla",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Geometry magic 0x616C4467 (after 4096 reserved bytes)",
                    "Android Super Partition (Dynamic Partitions)",
                ),
            },
            {
                "offset": 12288,
                "value": b"0PLA",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Primary metadata header magic 0x414C5030 (after geometry and its backup)",
                    "Android Super Partition (Dynamic Partitions)",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "Dynamic partitions (Android Open Source Project)",
                "https://source.android.com/docs/core/ota/dynamic_partitions",
            ),
            (
                "liblp metadata_format.h (AOSP, GitHub mirror)",
                "https://github.com/aosp-mirror/platform_system_core/blob/main/fs_mgr/liblp/include/liblp/metadata_format.h",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "Android OTA Update Payload (payload.bin)",
        "short_name": "payload.bin",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The update payload of Android A/B (seamless) updates, usually named payload.bin "
            "inside an OTA ZIP. A big-endian header with major version and manifest size (and, "
            "in version 2, the metadata signature size) is followed by a protobuf manifest that "
            "describes target partitions and install operations, and by the operation data. Full "
            "payloads contain complete partition images; delta payloads only differences to a "
            "specific source build. Payloads are used to obtain partition images and to identify "
            "the exact firmware build of a device.",
            "Android OTA Update Payload (payload.bin)",
        ),
        "platforms": ["Android"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"CrAU",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Payload magic 'CrAU'",
                    "Android OTA Update Payload (payload.bin)",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "update_engine README — update payload file specification (AOSP)",
                "https://android.googlesource.com/platform/system/update_engine/+/HEAD/README.md",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "VirtualBox Disk Image (VDI)",
        "short_name": "VDI",
        "category": "disk_image",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Virtual disk format of Oracle VirtualBox. A 64-byte text header (e.g. '<<< Oracle VM "
            "VirtualBox Disk Image >>>', older 'innotek' or 'Sun' variants) is followed by the "
            "signature and a header with image type, disk geometry, a block map and the UUIDs of "
            "the image, its last snapshot, link and parent. Dynamic images only allocate blocks "
            "that were written; snapshots are stored as differencing images that reference their "
            "parent by UUID, so a complete disk state may require the whole image chain.",
            "VirtualBox Disk Image (VDI)",
        ),
        "platforms": ["Windows", "macOS", "Linux"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"<<< ",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Start of the text header '<<< … VirtualBox Disk Image >>>'",
                    "VirtualBox Disk Image (VDI)",
                ),
            },
            {
                "offset": 64,
                "value": b"\x7f\x10\xda\xbe",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Image signature 0xBEDA107F (little-endian)",
                    "VirtualBox Disk Image (VDI)",
                ),
            },
        ],
        "extensions": [".vdi"],
        "links": [
            (
                "QEMU VDI block driver (source with header layout)",
                "https://github.com/qemu/qemu/blob/master/block/vdi.c",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "Berkeley DB Database",
        "short_name": "BDB",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Embedded key-value database library format with Btree, Hash and Queue access "
            "methods. The first page is a metadata page whose magic number at offset 12 identifies "
            "the access method; its byte order shows the endianness of the creating system. "
            "Commonly encountered as legacy Bitcoin Core wallets (wallet.dat, Btree), which "
            "contain keys, addresses and transaction data; newer Bitcoin Core versions use "
            "SQLite-based wallets and only migrate legacy files. Also used by older Linux package "
            "databases and various Unix services. Freed pages can retain previous records.",
            "Berkeley DB Database",
        ),
        "platforms": ["Windows", "macOS", "Linux"],
        "parser_class": None,
        "magic": [
            {
                "offset": 12,
                "value": b"\x62\x31\x05\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Btree metadata magic 0x00053162 (little-endian)",
                    "Berkeley DB Database",
                ),
            },
            {
                "offset": 12,
                "value": b"\x00\x05\x31\x62",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Btree metadata magic 0x00053162 (big-endian)",
                    "Berkeley DB Database",
                ),
            },
            {
                "offset": 12,
                "value": b"\x61\x15\x06\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Hash metadata magic 0x00061561 (little-endian)",
                    "Berkeley DB Database",
                ),
            },
            {
                "offset": 12,
                "value": b"\x00\x06\x15\x61",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Hash metadata magic 0x00061561 (big-endian)",
                    "Berkeley DB Database",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "Berkeley DB magic definitions (file/libmagic)",
                "https://github.com/file/file/blob/master/magic/Magdir/database",
            ),
            (
                "migrate.cpp — Berkeley DB parser for legacy wallets (Bitcoin Core)",
                "https://github.com/bitcoin/bitcoin/blob/master/src/wallet/migrate.cpp",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "WMV Video (ASF)",
        "short_name": "WMV",
        "category": "media",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Windows Media Video in the Advanced Systems Format (ASF) container, which is also "
            "used for WMA audio. The file is a sequence of GUID-identified objects: the header "
            "object holds the File Properties Object (file ID, creation date, play duration, "
            "packet count), stream properties and optional metadata such as title and author, "
            "followed by the data object and optional index objects. WMV is still encountered in "
            "older camera, screen recording and video surveillance exports. Audio-only and video "
            "files share the same header signature and are distinguished by their stream types.",
            "WMV Video (ASF)",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "ASF header object GUID 75B22630-668E-11CF-A6D9-00AA0062CE6C at offset 0 "
                    "(shared with WMA; distinguished by stream type)",
                    "WMV Video (ASF)",
                ),
            },
        ],
        "extensions": [".wmv", ".asf"],
        "links": [
            (
                "ASF File Structure (Microsoft)",
                "https://learn.microsoft.com/en-us/windows/win32/medfound/asf-file-structure",
            ),
            (
                "Advanced Systems Format (PRONOM fmt/131)",
                "https://www.nationalarchives.gov.uk/pronom/fmt/131",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "MPEG Transport Stream (TS / M2TS)",
        "short_name": "MPEG-TS",
        "category": "media",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Packet-based MPEG-2 systems container of fixed 188-byte packets, each starting with "
            "the sync byte 0x47; the M2TS variant (Blu-ray, AVCHD camcorders, .mts) prefixes each "
            "packet with a 4-byte timestamp (192-byte packets). Used for broadcast recordings, "
            "streaming segments, camcorder recordings and video surveillance exports. Because "
            "packets are self-contained, damaged or carved streams can often still be decoded. "
            "Timing information (PCR/PTS) is relative to the stream; wall-clock time is only "
            "present if the stream or the recording system adds it.",
            "MPEG Transport Stream (TS / M2TS)",
        ),
        "platforms": ALL_PLATFORMS,
        "parser_class": None,
        "magic": [
            {
                "offset": None,
                "value": b"\x47",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "TS: sync byte 0x47 at offsets 0, 188, 376, … (188-byte packets); "
                    "too short to identify on its own",
                    "MPEG Transport Stream (TS / M2TS)",
                ),
            },
            {
                "offset": None,
                "value": b"\x47",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "M2TS: sync byte 0x47 at offsets 4, 196, 388, … (192-byte packets); "
                    "too short to identify on its own",
                    "MPEG Transport Stream (TS / M2TS)",
                ),
            },
        ],
        "extensions": [".ts", ".m2ts", ".mts"],
        "links": [
            (
                "ITU-T H.222.0 | ISO/IEC 13818-1 — MPEG-2 Systems",
                "https://www.itu.int/rec/T-REC-H.222.0",
            ),
            (
                "MPEG transport stream magic definitions (file/libmagic)",
                "https://github.com/file/file/blob/master/magic/Magdir/animation",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "Dahua Video (DAV / DHAV)",
        "short_name": "DAV",
        "category": "media",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Proprietary recording and export format of Dahua video surveillance recorders and "
            "cameras (and OEM devices). The stream consists of frames that each start with a "
            "'DHAV' header (frame type, channel, frame number, length and a packed recording "
            "date/time) and end with a 'dhav' trailer; files may start with an additional "
            "'DAHUA' header. Video is usually H.264 or H.265. The per-frame date/time reflects the "
            "recorder's clock, so the clock offset of the device must be verified before "
            "relying on it; the channel number links footage to a specific camera.",
            "Dahua Video (DAV / DHAV)",
        ),
        "platforms": ALL_PLATFORMS,
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"DHAV",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Frame header 'DHAV'",
                    "Dahua Video (DAV / DHAV)",
                ),
            },
            {
                "offset": 0,
                "value": b"DAHUA",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "File header 'DAHUA'",
                    "Dahua Video (DAV / DHAV)",
                ),
            },
        ],
        "extensions": [".dav"],
        "links": [
            (
                "DHAV demuxer (FFmpeg source)",
                "https://github.com/FFmpeg/FFmpeg/blob/master/libavformat/dhav.c",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "vCard Contact",
        "short_name": "vCard",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Text format for contact data (versions 2.1, 3.0 and 4.0), used for contact exports "
            "and synchronisation by phones, mail clients and address books. A file can contain "
            "many contacts, each between BEGIN:VCARD and END:VCARD, with names, phone numbers, "
            "e-mail and postal addresses, organisation, notes, embedded photos (PHOTO) and "
            "optionally a last revision time (REV). Exports can preserve contacts that were later "
            "deleted on the device.",
            "vCard Contact",
        ),
        "platforms": ALL_PLATFORMS,
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"BEGIN:VCARD",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Start line 'BEGIN:VCARD' (may be preceded by a byte order mark)",
                    "vCard Contact",
                ),
            },
        ],
        "extensions": [".vcf", ".vcard"],
        "links": [
            (
                "vCard Format Specification (RFC 6350)",
                "https://www.rfc-editor.org/rfc/rfc6350.html",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "iCalendar",
        "short_name": "iCal",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Text format for calendar data used for calendar exports, invitations sent as e-mail "
            "attachments and synchronisation. A VCALENDAR object contains events, to-dos, journal "
            "entries and alarms with start/end times, location, description, organizer and "
            "attendees, time zone definitions (TZID) and change tracking timestamps (DTSTAMP, "
            "CREATED, LAST-MODIFIED). Times may be given in UTC, with a time zone reference or "
            "as floating local time, which must be considered when building timelines.",
            "iCalendar",
        ),
        "platforms": ALL_PLATFORMS,
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"BEGIN:VCALENDAR",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Start line 'BEGIN:VCALENDAR' (may be preceded by a byte order mark)",
                    "iCalendar",
                ),
            },
        ],
        "extensions": [".ics", ".ical", ".ifb"],
        "links": [
            (
                "Internet Calendaring and Scheduling Core Object Specification (RFC 5545)",
                "https://www.rfc-editor.org/rfc/rfc5545.html",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "Apple Core Audio Format (CAF)",
        "short_name": "CAF",
        "category": "media",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Apple's chunk-based audio container on macOS and iOS. A big-endian file header "
            "('caff', version 1) is followed by chunks such as 'desc' (audio format), 'data' "
            "(audio data with an edit count), 'pakt' (packet table for variable bit rates) and "
            "optional metadata chunks; the 'info' chunk can contain text metadata such as a "
            "recording date. Audio messages in Apple Messages are stored as 'Audio Message.caf' "
            "attachments, making the format relevant for messaging analysis.",
            "Apple Core Audio Format (CAF)",
        ),
        "platforms": ["macOS", "iOS"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"caff\x00\x01\x00\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "File type 'caff', version 1, flags 0",
                    "Apple Core Audio Format (CAF)",
                ),
            },
        ],
        "extensions": [".caf"],
        "links": [
            (
                "Core Audio Format Specification (Apple)",
                "https://developer.apple.com/library/archive/documentation/MusicAudio/Reference/CAFSpec/CAF_spec/CAF_spec.html",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "Windows Event Trace Log (ETL)",
        "short_name": "ETL",
        "category": "log",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The file format of Event Tracing for Windows (ETW) sessions, including the kernel "
            "logger. The undocumented container consists of fixed-size buffers, each with a "
            "buffer header, holding events of different providers (manifest-based, TraceLogging "
            "or MOF); decoding events requires the provider's schema. AutoLogger sessions write "
            "by default to %SystemRoot%\\System32\\LogFiles\\WMI\\<session>.etl (optionally "
            "with a per-boot counter). ETL files are also produced by diagnostic and network "
            "tracing (e.g. network captures recorded with netsh trace) and can contain system, "
            "network and application activity not recorded in the event logs. No fixed file "
            "signature.",
            "Windows Event Trace Log (ETL)",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [],
        "extensions": [".etl"],
        "links": [
            (
                "Configuring and Starting an AutoLogger Session (Microsoft)",
                "https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-autologger-session",
            ),
            (
                "etl-parser — Event Trace Log reader (Airbus CERT)",
                "https://github.com/airbus-cert/etl-parser",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "RDP Bitmap Cache",
        "short_name": "RDP cache",
        "category": "media",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Persistent bitmap cache of the Windows Remote Desktop client, stored in the user "
            "profile (Terminal Server Client cache folder) as bcache*.bmc (older clients) or "
            "Cache????.bin files ('RDP8bmp' header, RDP 8 and later). The files contain small "
            "bitmap tiles (typically 64×64 pixels) of the remote screen; reassembled, they can "
            "show fragments of what a user saw during RDP sessions, such as windows, file names "
            "or typed text, on the connecting system.",
            "RDP Bitmap Cache",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"RDP8bmp\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Header 'RDP8bmp' of Cache????.bin files (bcache*.bmc files have no signature)",
                    "RDP Bitmap Cache",
                ),
            },
        ],
        "extensions": [".bmc"],
        "links": [
            (
                "bmc-tools — RDP Bitmap Cache parser (ANSSI)",
                "https://github.com/ANSSI-FR/bmc-tools",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "OneNote Revision Store (ONE)",
        "short_name": "OneNote",
        "category": "document",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The OneNote revision store format of section files (.one) and table-of-contents "
            "files (.onetoc2). The header identifies the file type and format by GUIDs; content "
            "is stored as revisions of object spaces, so earlier page versions and removed "
            "content can remain in the file. Sections can embed arbitrary files, which has also "
            "been used to deliver malware via OneNote attachments.",
            "OneNote Revision Store (ONE)",
        ),
        "platforms": ["Windows", "macOS"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d\xae\xb1\x53\x78\xd0\x29\x96\xd3",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "guidFileType {7B5C52E4-D88C-4DA7-AEB1-5378D02996D3} (.one section)",
                    "OneNote Revision Store (ONE)",
                ),
            },
            {
                "offset": 0,
                "value": b"\xa1\x2f\xff\x43\xd9\xef\x76\x4c\x9e\xe2\x10\xea\x57\x22\x76\x5f",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "guidFileType {43FF2FA1-EFD9-4C76-9EE2-10EA5722765F} (.onetoc2)",
                    "OneNote Revision Store (ONE)",
                ),
            },
            {
                "offset": 48,
                "value": b"\x3f\xdd\x9a\x10\x1b\x91\xf5\x49\xa5\xd0\x17\x91\xed\xc8\xae\xd8",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "guidFileFormat {109ADD3F-911B-49F5-A5D0-1791EDC8AED8}",
                    "OneNote Revision Store (ONE)",
                ),
            },
        ],
        "extensions": [".one", ".onetoc2"],
        "links": [
            (
                "[MS-ONESTORE]: OneNote Revision Store File Format (Microsoft)",
                "https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-onestore/ae670cd2-4b38-4b24-82d1-87cfb2cc3725",
            ),
            (
                "pyOneNote — header GUIDs (DissectMalware)",
                "https://github.com/DissectMalware/pyOneNote/blob/main/pyOneNote/Header.py",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "Windows Imaging Format (WIM / ESD)",
        "short_name": "WIM",
        "category": "archive",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "File-based image format for Windows installation media, deployment and backup "
            "images. A WIM can hold several images, each a complete directory tree with NTFS "
            "metadata such as timestamps, security descriptors and named data streams, plus XML "
            "metadata per image; identical content is stored only once. ESD files use the same "
            "format with solid LZMS compression. With WIMBoot (Windows 8.1 and later), files on "
            "a volume can be pointer files backed by a WIM.",
            "Windows Imaging Format (WIM / ESD)",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"MSWIM\x00\x00\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Header magic 'MSWIM'",
                    "Windows Imaging Format (WIM / ESD)",
                ),
            },
        ],
        "extensions": [".wim", ".esd", ".swm"],
        "links": [
            (
                "wimlib documentation",
                "https://wimlib.net/man1/wimlib-imagex.html",
            ),
            (
                "wimlib header.h (source with header layout)",
                "https://github.com/ebiggers/wimlib/blob/master/include/wimlib/header.h",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "Firefox Cache (cache2)",
        "short_name": "cache2",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The HTTP cache of Firefox and other Gecko-based browsers in the profile's cache2 "
            "folder: an index file and one file per entry below entries/, named by a hash of "
            "the key. Each entry file holds the cached content followed by metadata; the last "
            "4 bytes point to the metadata, which contains a version, fetch count, last fetched, "
            "last modified and expiration times, the key (URL with context prefixes) and "
            "elements such as the response headers. Cached content can show visited pages and "
            "loaded resources independent of the browsing history. Entry format version 4 "
            "supports at-rest encryption of the metadata.",
            "Firefox Cache (cache2)",
        ),
        "platforms": ["Windows", "macOS", "Linux"],
        "parser_class": None,
        "magic": [],
        "extensions": [],
        "links": [
            (
                "CacheFileMetadata.h (Firefox source)",
                "https://github.com/mozilla-firefox/firefox/blob/main/netwerk/cache2/CacheFileMetadata.h",
            ),
            (
                "Firefox cache file format (libyal/dtformats)",
                "https://github.com/libyal/dtformats/blob/main/documentation/Firefox%20cache%20file%20format.asciidoc",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "Java KeyStore (JKS / JCEKS)",
        "short_name": "JKS",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Key and certificate containers of the Java platform. Entries carry an alias and "
            "a creation date in cleartext; certificates are stored unencrypted, while private "
            "and secret keys are protected with an entry password (JKS uses a proprietary "
            "SHA-1/XOR scheme, JCEKS a stronger password-based encryption). The whole store "
            "ends with a keyed SHA-1 digest derived from the store password. Since Java 9 the "
            "default keystore type is PKCS#12, which has no fixed signature.",
            "Java KeyStore (JKS / JCEKS)",
        ),
        "platforms": ["Windows", "macOS", "Linux"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"\xfe\xed\xfe\xed",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "JKS magic 0xFEEDFEED",
                    "Java KeyStore (JKS / JCEKS)",
                ),
            },
            {
                "offset": 0,
                "value": b"\xce\xce\xce\xce",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "JCEKS magic 0xCECECECE",
                    "Java KeyStore (JKS / JCEKS)",
                ),
            },
        ],
        "extensions": [".jks", ".keystore", ".jceks", ".ks"],
        "links": [
            (
                "JavaKeyStore.java (OpenJDK source)",
                "https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/sun/security/provider/JavaKeyStore.java",
            ),
            (
                "JceKeyStore.java (OpenJDK source)",
                "https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/com/sun/crypto/provider/JceKeyStore.java",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "Java Class File",
        "short_name": "class",
        "category": "execution",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Compiled Java bytecode, usually packaged in JAR, WAR or similar ZIP-based archives. "
            "The header holds the magic 0xCAFEBABE followed by minor and major version; the "
            "major version identifies the targeted Java release (45 = Java 1.0/1.1 … 65 = Java "
            "21). The constant pool contains class, method and string names, which can reveal "
            "functionality, embedded URLs or credentials. The magic is shared with Mach-O "
            "universal binaries; they are distinguished by the value at offset 4 (a small "
            "architecture count in Mach-O, the class file version in Java).",
            "Java Class File",
        ),
        "platforms": ["Windows", "macOS", "Linux"],
        "parser_class": None,
        "magic": [
            {
                "offset": None,
                "value": b"\xca\xfe\xba\xbe",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Magic 0xCAFEBABE at offset 0 (shared with Mach-O universal binaries; "
                    "major version at offset 6 is 45 or higher)",
                    "Java Class File",
                ),
            },
        ],
        "extensions": [".class"],
        "links": [
            (
                "The class File Format (Java Virtual Machine Specification, Java SE 21)",
                "https://docs.oracle.com/javase/specs/jvms/se21/html/jvms-4.html",
            ),
            (
                "CAFEBABE disambiguation (file/libmagic)",
                "https://github.com/file/file/blob/master/magic/Magdir/cafebabe",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "Android Verified Boot Metadata (vbmeta)",
        "short_name": "vbmeta",
        "category": "disk_image",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Signed metadata of Android Verified Boot 2.0, stored in the vbmeta partition or "
            "embedded in other partitions, which then carry a 64-byte 'AVBf' footer at their "
            "end. The vbmeta image contains the rollback index, flags, the public key and "
            "descriptors (hash, hashtree, chain partition and property descriptors) with the "
            "expected digests of the verified partitions. Flags such as disabled hashtree or "
            "disabled verification indicate a modified boot chain, as commonly set on unlocked "
            "or rooted devices.",
            "Android Verified Boot Metadata (vbmeta)",
        ),
        "platforms": ["Android"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"AVB0",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "vbmeta image magic 'AVB0'",
                    "Android Verified Boot Metadata (vbmeta)",
                ),
            },
            {
                "offset": None,
                "value": b"AVBf",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Footer magic 'AVBf' in the last 64 bytes of a partition with embedded vbmeta",
                    "Android Verified Boot Metadata (vbmeta)",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "Android Verified Boot 2.0 README (AOSP)",
                "https://android.googlesource.com/platform/external/avb/+/refs/heads/main/README.md",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "ZFS",
        "short_name": "ZFS",
        "category": "filesystem",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Copy-on-write filesystem and volume manager (OpenZFS), common on NAS and server "
            "systems. Each device carries four 256 KiB labels (two at the start, two at the end), "
            "each with a name/value list describing the pool and device configuration and a "
            "ring of uberblocks pointing to the current and recent transaction groups. Because "
            "blocks are never overwritten in place, earlier transaction groups and snapshots can "
            "preserve previous file versions. No signature at offset 0; uberblocks are found in "
            "the ring starting 128 KiB into each label.",
            "ZFS",
        ),
        "platforms": ["Linux"],
        "parser_class": None,
        "magic": [
            {
                "offset": None,
                "value": b"\x0c\xb1\xba\x00\x00\x00\x00\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Uberblock magic 0x00BAB10C (little-endian) in the uberblock ring at "
                    "128 KiB into each label",
                    "ZFS",
                ),
            },
            {
                "offset": None,
                "value": b"\x00\x00\x00\x00\x00\xba\xb1\x0c",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Uberblock magic 0x00BAB10C (big-endian)",
                    "ZFS",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "uberblock_impl.h (OpenZFS source)",
                "https://github.com/openzfs/zfs/blob/master/include/sys/uberblock_impl.h",
            ),
            (
                "vdev_impl.h — vdev label layout (OpenZFS source)",
                "https://github.com/openzfs/zfs/blob/master/include/sys/vdev_impl.h",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "WMI Repository (CIM)",
        "short_name": "WMI repository",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "The Common Information Model repository of Windows Management Instrumentation in "
            "%SystemRoot%\\System32\\wbem\\Repository\\ (Windows Vista and later): INDEX.BTR "
            "(index B-tree), OBJECTS.DATA (object records) and MAPPING1–3.MAP (mapping of "
            "logical to physical pages), with 8192-byte pages. The repository stores class "
            "definitions and instances, including event filters, consumers and bindings used "
            "for WMI-based persistence. Unreferenced pages in OBJECTS.DATA can retain deleted "
            "objects. Mapping files start with the signature 0x0000ABCD.",
            "WMI Repository (CIM)",
        ),
        "platforms": ["Windows"],
        "parser_class": None,
        "magic": [
            {
                "offset": 0,
                "value": b"\xcd\xab\x00\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "Mapping file header signature 0x0000ABCD (MAPPING*.MAP)",
                    "WMI Repository (CIM)",
                ),
            },
        ],
        "extensions": [],
        "links": [
            (
                "WMI repository file format (libyal/dtformats)",
                "https://github.com/libyal/dtformats/blob/main/documentation/WMI%20repository%20file%20format.asciidoc",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-05",
    },
    {
        "name": "Hive Database (Dart / Flutter)",
        "short_name": "Hive",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Append-only key-value store of the Dart/Flutter Hive library (Hive 2.x and its "
            "Hive CE continuation). Each box is one <name>.hive file, the box name in lower case, "
            "next to a <name>.lock file; a <name>.hivec file is the intermediate result of a "
            "compaction. Has no magic bytes: the file is a plain sequence of frames, each made of "
            "a little-endian uint32 frame length, the key (type 0: uint32, type 1: UTF-8 string "
            "of up to 255 bytes), the value (a type ID byte followed by the data, absent for a "
            "deletion) and a CRC32 over the frame. Every write or delete appends a new frame, so "
            "earlier values and deleted keys remain in the file until a compaction rewrites only "
            "the live frames (automatically once more than 60 obsolete frames make up over 15 % "
            "of the entries, or when the app requests it). With encryption only the value is "
            "encrypted (AES-256-CBC, random 16-byte IV in front, PKCS7 padding); keys stay in "
            "plain text and the CRC is seeded with a checksum of the key. Integers are stored as "
            "64-bit floats. Custom objects carry an app-defined type ID (stored as ID + 32) and "
            "store their fields by numeric index, not by name. Hive CE adds value types such as "
            "sets, DateTime, BigInt and Duration plus 16-bit type IDs, but keeps the frame layout. "
            "Opening a box whose last frame is damaged truncates the file at the last valid frame "
            "by default. The Hive 4 development versions store boxes as Isar databases instead "
            "(see Isar Database). Depending on the app, boxes hold settings, cached content, "
            "session state such as account IDs or tokens, histories or the app's main records. "
            "Found in the app data directories of Flutter apps on Android, iOS and desktop "
            "systems.",
            "Hive Database (Dart / Flutter)",
        ),
        "platforms": ["Windows", "macOS", "Linux", "iOS", "Android"],
        "parser_class": None,
        "magic": [],
        "extensions": [".hive", ".hivec"],
        "links": [
            (
                "Hive 2.2.3 frame writer (source)",
                "https://github.com/isar/hive/blob/v2.2.3/hive/lib/src/binary/binary_writer_impl.dart",
            ),
            (
                "Hive 2.2.3 storage backend: lock file, recovery, compaction (source)",
                "https://github.com/isar/hive/blob/v2.2.3/hive/lib/src/backend/vm/storage_backend_vm.dart",
            ),
            (
                "Hive CE (Hive Community Edition)",
                "https://github.com/IO-Design-Team/hive_ce",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-06",
    },
    {
        "name": "Isar Database (Dart / Flutter)",
        "short_name": "Isar",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Embedded object database of the Dart/Flutter Isar library. Isar 3.x and its "
            "community fork store each instance in a single libmdbx file named <name>.isar "
            "(default.isar for the default instance) with a <name>.isar-lck lock file next to it. "
            "The file is a libmdbx database and carries the libmdbx meta page signature (see LMDB "
            "/ libmdbx Database); only the name and its sub-databases tell it apart. Each "
            "collection is a named sub-database keyed by the 64-bit object ID, accompanied by "
            "sub-databases for indexes (_i_<collection>_<index>) and links (_l_ and _b_ "
            "prefixes). The _info sub-database holds the collection schemas as JSON, which gives "
            "the property names and types needed to decode the binary objects. Collections hold "
            "the app's structured records, for example libraries, histories, download lists or "
            "account data, depending on the app. Objects use a "
            "compact little-endian layout of a static part followed by dynamic data; DateTime "
            "values are stored as UTC microseconds since the Unix epoch. As in any libmdbx file, "
            "freed pages can retain deleted or earlier versions of objects until they are reused "
            "or the file is compacted (rewritten as <name>.isar.compact and renamed, only when "
            "the app enables compaction on open). Isar 3 has no encryption. Isar 4 (development "
            "releases and forks) can use this native engine or SQLite; with SQLite the instance "
            "is a <name>.sqlite file in WAL mode, optionally encrypted with SQLCipher. Found in "
            "the app data directories of Flutter apps on Android, iOS and desktop systems.",
            "Isar Database (Dart / Flutter)",
        ),
        "platforms": ["Windows", "macOS", "Linux", "iOS", "Android"],
        "parser_class": None,
        "magic": [
            {
                "offset": None,
                "value": b"\x03\x11\x4c\xef\xbd\x9d\x65\x59",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "libmdbx meta page signature at offset 20, shared with every libmdbx file "
                    "(see LMDB / libmdbx Database); identifies the storage engine, not Isar",
                    "Isar Database (Dart / Flutter)",
                ),
            },
        ],
        "extensions": [".isar"],
        "links": [
            (
                "Isar 3.1.0+1 instance: file name, sub-databases, compaction (source)",
                "https://github.com/isar/isar/blob/3.1.0%2B1/packages/isar_core/src/instance.rs",
            ),
            (
                "Isar 3.1.0+1 libmdbx environment flags (source)",
                "https://github.com/isar/isar/blob/3.1.0%2B1/packages/isar_core/src/mdbx/env.rs",
            ),
            (
                "Isar 4 SQLite engine: file name, WAL, encryption (source)",
                "https://github.com/isar/isar/blob/main/packages/isar_core/src/sqlite/sqlite_open.rs",
            ),
            (
                "Isar Community (maintained fork of Isar 3)",
                "https://github.com/isar-community/isar-community",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-06",
    },
    {
        "name": "LMDB / libmdbx Database",
        "short_name": "LMDB",
        "category": "database",
        "forensic_relevance": QT_TRANSLATE_NOOP(
            "FormatKnowledge",
            "Memory-mapped key-value store built as a copy-on-write B+tree. LMDB and its "
            "derivative libmdbx share the design but are not file-compatible. An environment "
            "consists of a data file and a lock file: data.mdb and lock.mdb in a directory "
            "(LMDB), mdbx.dat and mdbx.lck (libmdbx), or in single-file mode any file name with a "
            "lock file carrying the suffix -lock (LMDB) or -lck (libmdbx). In single-file mode "
            "the data file often has no extension at all, so the meta page signature is the "
            "reliable indicator. The data file starts "
            "with two (LMDB) or three (libmdbx) meta pages holding the signature, the last "
            "committed transaction ID and the roots of the free-page tree and the main tree; "
            "named sub-databases are entries of the main tree. Pages released by a transaction "
            "are tracked in the free-page tree and reused later, so deleted and overwritten "
            "records can survive in pages no longer referenced, and the older meta pages point "
            "to earlier committed states. The lock file only holds the reader table and no "
            "records. Header fields use the byte order of the creating system (little-endian "
            "on common platforms). In LMDB 0.9 the signature "
            "offset depends on the page number size of the build: 16 on 64-bit, 12 on 32-bit. "
            "Used by OpenLDAP and many embedded applications, for example Monero node data "
            "(lmdb/data.mdb), Ethereum clients such as Erigon and Reth (libmdbx), and Flutter "
            "apps using Isar (see Isar Database).",
            "LMDB / libmdbx Database",
        ),
        "platforms": ["Windows", "macOS", "Linux", "iOS", "Android"],
        "parser_class": None,
        "magic": [
            {
                "offset": 16,
                "value": b"\xde\xc0\xef\xbe\x01\x00\x00\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "LMDB 0.9 meta page: magic 0xBEEFC0DE and data version 1 (little-endian, "
                    "64-bit build)",
                    "LMDB / libmdbx Database",
                ),
            },
            {
                "offset": 12,
                "value": b"\xde\xc0\xef\xbe\x01\x00\x00\x00",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "LMDB 0.9 meta page: magic 0xBEEFC0DE and data version 1 (little-endian, "
                    "32-bit build)",
                    "LMDB / libmdbx Database",
                ),
            },
            {
                "offset": 20,
                "value": b"\x03\x11\x4c\xef\xbd\x9d\x65\x59",
                "description": QT_TRANSLATE_NOOP(
                    "FormatKnowledge",
                    "libmdbx meta page: 56-bit magic 0x59659DBDEF4C11 with data version 3 "
                    "(little-endian)",
                    "LMDB / libmdbx Database",
                ),
            },
        ],
        "extensions": [".mdb", ".dat"],
        "links": [
            (
                "LMDB 0.9 source: meta page, magic, file names (mdb.c)",
                "https://github.com/LMDB/lmdb/blob/mdb.RE/0.9/libraries/liblmdb/mdb.c",
            ),
            (
                "libmdbx 0.12.4 internals: magic, data version, page header (source)",
                "https://github.com/isar/libmdbx/blob/v0.12.4/src/internals.h",
            ),
            (
                "libmdbx (GitHub mirror)",
                "https://github.com/erthink/libmdbx",
            ),
        ],
        "status": "reviewed",
        "last_reviewed": "2026-10-06",
    },
]


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def url_slug(short_name: str) -> str:
    """The entry's address on the format reference site: short_name in
    lower case, every run of characters other than a-z/0-9 as one '-'."""
    return re.sub(r"[^a-z0-9]+", "-", short_name.lower()).strip("-")


def entry(fmt: dict[str, Any]) -> dict[str, Any]:
    """One FORMATS entry with every field present and normalised exactly as
    it is written to formats.db (platforms in PLATFORMS order, lower-case
    extensions, empty text for a missing one). build() and the format
    reference site both read the entries through this, so they can't
    differ."""
    platforms = fmt.get("platforms", [])
    return {
        "name": fmt["name"],
        "short_name": fmt.get("short_name", ""),
        "category": fmt.get("category", ""),
        "forensic_relevance": fmt.get("forensic_relevance", ""),
        "platforms": [p for p in PLATFORMS if p in platforms],
        "parser_class": fmt.get("parser_class"),
        "magic": [
            {
                "offset": m.get("offset"),
                "value": m["value"],
                "description": m.get("description", ""),
            }
            for m in fmt.get("magic", [])
        ],
        "extensions": [ext.lower() for ext in fmt.get("extensions", [])],
        "links": [(label, url) for label, url in fmt.get("links", [])],
        "status": fmt.get("status"),
        "last_reviewed": fmt.get("last_reviewed"),
    }


def check_slugs(formats: list[dict[str, Any]]) -> None:
    """Every entry needs a short_name, and no two may share an address."""
    seen: dict[str, str] = {}
    for fmt in formats:
        slug = url_slug(fmt.get("short_name", ""))
        if not slug:
            raise ValueError(f"{fmt['name']}: short_name is missing or has no a-z/0-9")
        if slug in seen:
            raise ValueError(
                f"{fmt['name']}: short_name gives the same site address {slug!r} as "
                f"{seen[slug]}"
            )
        seen[slug] = fmt["name"]


def _check_entry(fmt: dict[str, Any]) -> None:
    """Reject values outside the declared sets, before anything is written."""
    unknown =[p for p in fmt.get("platforms", []) if p not in PLATFORMS]
    if unknown:
        raise ValueError(f"{fmt['name']}: unknown platform(s) {unknown}, allowed {PLATFORMS}")
    reviewed_on = fmt.get("last_reviewed")
    if reviewed_on is not None:
        try:
            date.fromisoformat(reviewed_on)
        except (TypeError, ValueError):
            raise ValueError(
                f"{fmt['name']}: last_reviewed {reviewed_on!r} is not an ISO date (YYYY-MM-DD)"
            ) from None


def build(out_path: Path = _OUT) -> None:
    for fmt in FORMATS:
        _check_entry(fmt)
    check_slugs(FORMATS)

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
            parser_class        TEXT,
            last_reviewed       TEXT
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
    undated = [f["name"] for f in reviewed if f.get("last_reviewed") is None]
    if undated:
        print(f"WARNING: {len(undated)} reviewed format(s) without last_reviewed: {', '.join(undated)}")

    for fmt in map(entry, reviewed):
        cur = conn.execute(
            "INSERT INTO formats (name, short_name, category, forensic_relevance, "
            "platforms, parser_class, last_reviewed) VALUES (?,?,?,?,?,?,?)",
            (
                fmt["name"],
                fmt["short_name"],
                fmt["category"],
                fmt["forensic_relevance"],
                ",".join(fmt["platforms"]),
                fmt["parser_class"],
                fmt["last_reviewed"],
            ),
        )
        fid = cur.lastrowid
        for m in fmt["magic"]:
            conn.execute(
                "INSERT INTO magic_bytes (format_id, offset, pattern, description) VALUES (?,?,?,?)",
                (fid, m["offset"], m["value"], m["description"]),
            )
        for ext in fmt["extensions"]:
            conn.execute(
                "INSERT INTO extensions (format_id, extension) VALUES (?,?)",
                (fid, ext),
            )
        for label, url in fmt["links"]:
            conn.execute(
                "INSERT INTO links (format_id, label, url) VALUES (?,?,?)",
                (fid, label, url),
            )

    conn.commit()
    conn.close()
    print(f"Built {out_path}  ({len(reviewed)} reviewed formats, {len(FORMATS)} total)")


if __name__ == "__main__":
    build()
