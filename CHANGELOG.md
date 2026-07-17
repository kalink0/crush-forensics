# Changelog

All notable changes to Crush will be documented in this file.

## Unreleased

### New Features

- **Properties panel shows the original iTunes backup file ID** — the raw `fileID`-named path (e.g. `ab/ab54f7c9...e1`) is now shown alongside the resolved `domain/relativePath`, for files only. Addresses [#41](https://github.com/kalink0/crush-forensics/issues/41).
- **PDF viewer renders pages, not just text** — double-clicking a PDF now shows a "Pages" tab with page-by-page rendering (via `pypdfium2`) and navigation/zoom (also via Ctrl+scroll wheel, same as the Image viewer), alongside the existing extracted-text "Text" tab. Password-protected PDFs are supported via **Open as → PDF (Encrypted)…**.
- **PDF: extended metadata, attachments, and revision history** — Properties panel gains PDF version, XMP metadata, and always-shown JavaScript/Signatures/Attachments/Revisions fields; embedded files get their own **Attachments** tab. PDFs saved multiple times get a **History** tab exposing every revision (including content/JS/attachments since removed from the current one), with **Text Diff** and **Visual Diff** (pixel-level page comparison) between any two revisions.
- **Blob Inspector: schema-based Protobuf decode** — selecting **Protobuf (schema-less)** now reveals a **Load .proto schema…** toolbar; loading a `.proto`/`.pb`/`.desc`/`.fds` file and picking a message type decodes the blob with real field names, using the same schema loader the standalone Protobuf Viewer already had.

### Bug Fixes

- **Rainbow/'Merica theme: dialog buttons stopped responding to clicks** — the animated-theme timer's stylesheet refresh already skipped open menus to avoid a re-polish flicker, but not open modal dialogs (`QMessageBox` etc.), where the same re-polish could eat a button click. Now skipped for both.
- **Protobuf Viewer's schema-based decode was broken on current protobuf versions** — `MessageFactory.GetPrototype` was removed in protobuf 6.x and `including_default_value_fields` was renamed to `always_print_fields_with_no_presence`; both call sites now use the current API.
- **Opening a moved/deleted file from Open Recent showed "Unsupported source type"** — `open_vfs()` fell through to that generic error whenever a path didn't exist instead of checking existence first; now raises a clear "File no longer exists" error.

## v0.14.0 - 2026-07-12

**Focus: SQLCipher-encrypted SQLite support (raw key and Signal-style custom cipher parameters included); Realm viewer overhaul — rewritten B+-tree-correct parser, AES-256 file encryption, Dictionary/nested-Mixed decoding, and a new Views tab resolving multi-hop Link/LinkList relationships into a queryable result;**

### New Features

- **SQLCipher-encrypted SQLite database support** — right-click a file → **Open as** → **SQLite DB (SQLCipher)…**; a wrong password/key re-prompts instead of failing silently. Unlike `.realm` encryption, this opens the real SQLCipher engine (`sqlcipher3`) rather than a custom decryptor, so page and WAL-frame decryption/checkpointing are handled natively — including data still only in a `-wal` companion, never checkpointed into the main file (the realistic forensic case: seized mid-session). By default, opening tries the linked library's current cipher settings first, then each legacy `cipher_compatibility` preset (SQLCipher 4 down to 1) — each a real, cryptographically-verified pass/fail via the engine's own per-page HMAC check, not a guess. As with encrypted `.realm` files, a normal double-click open never auto-prompts, since ciphertext can't be told apart from corrupt/other binary data. The dialog also has a **Raw key** option (SQLCipher's own recommended approach for a key "managed externally," e.g. an Android Keystore-derived key, rather than a user-typed passphrase — applies independently of Advanced, since page size/HMAC algorithm still matter for a raw key too) and an **Advanced** section for explicit cipher parameters (page size, KDF iterations, KDF/HMAC digest, plaintext header size) covering apps whose settings don't match any standard preset — notably Signal and its forks (Session, Molly), which set `kdf_iter = 1` since their key is already full-entropy from the platform keystore.
- **Image rotation** — the image viewer now has rotate-left and rotate-right buttons (90° steps), useful for photos with incorrect orientation metadata.
- **Copy Path / Copy File Name** — the filesystem panel's context menu gained a "Copy" submenu with "Copy Path" (full virtual path) and "Copy File Name" entries, grouped under one submenu rather than two more top-level items to keep the already-long menu manageable.
- **Filesystem panel: hover tooltips for truncated names/paths** — the tree view's Name column and the search results' Name and Path columns now show the full value as a tooltip on hover, so you no longer have to widen the column to read a long file name or path.
- **Realm viewer: new Views tab resolves Link/LinkList relationships, including multi-hop chains, into a queryable result** — the Schema tab shows each Link/LinkList column's target table (e.g. `attachments: linklist → class_AttachmentLocalDto`). The new **Views** tab lets you pick a table and, per Link/LinkList column, choose which columns of the linked table to pull in; a chosen target column that's itself a Link/LinkList expands into its own checklist (lazily, capped at 8 hops, never revisiting a table already on the chain), so a relationship spanning several tables (e.g. `message.attachments → attachment.uploader → participant`) resolves in one view instead of stopping after the first hop. A resolved to-one Link lands in its own named column per selected field (e.g. `messageAttributes.subject`, `messageAttributes.spamInfo.category`) instead of every field being crammed into one flattened text cell; a to-many LinkList still collapses into one combined text cell, since a variable-length list of targets can't become a fixed set of columns without multiplying rows. The opened tab is backed by a real temp SQLite file, so its own SQL box can further pick/reorder/filter columns for display or CSV export (`SELECT col_a, col_c FROM ...`), independently of the Views tab's own configuration. Every table with a Link/LinkList column also gets a matching single-hop `v_<table>` SQL view (`SELECT * FROM v_class_MessageAttributesLocalDto`) for scripted queries, alongside `json_each()` support for exact per-element matching and hand-written multi-hop joins. Table-grid cells holding a List/Set/LinkList value are now colour-flagged with an explanatory tooltip instead of looking like plain text.
- **Realm viewer: Dictionary columns and nested Mixed collections now decode** — `Dictionary<K,Mixed>` columns, previously left as an undecoded placeholder, now decode fully (the Schema tab shows the declared key type, e.g. `dictionary<string, mixed>`); a Mixed value that itself holds a nested List/Set/Dictionary is now expanded recursively too instead of showing a placeholder, with a depth cap against a corrupt/malicious reference chain (surfaced visibly, never silently truncated). Both were derived directly from the Realm Core C++ source (Apache-2.0) — Dictionary's per-row 2-slot key/value BPlusTree structure (`dictionary.cpp`), and nested-in-Mixed collections via `array_mixed.hpp`'s `m_refs` payload array — following the same spec-driven, no-shape-guessing approach as the rest of the parser. A nested Dictionary is always treated as String-keyed, since `dictionary.cpp`'s ref-only constructor hardcodes that when there's no owning Spec column to read a key type from.
- **Encrypted `.realm` file support** — Realm's built-in AES-256-CBC + HMAC-SHA224 per-page database encryption is now supported when the 64-byte encryption key is known (a raw key the app itself generates and stores, e.g. Keychain/Keystore — not a password, no key derivation). Right-click a file → **Open as** → **Realm DB (Encrypted)…**, enter the key as a hex string; a wrong key re-prompts instead of failing silently. A normal double-click open still never auto-prompts for a key, since a header that fails to decode is equally consistent with "encrypted" and "corrupt/non-standard" and the two can't be told apart from content alone — an encrypted file therefore still needs its `.realm` extension to be recognized at all.
- **Filesystem panel: "Open as" submenu** — "Open in Hex", "Open as Plain Text", and "Open as Protobuf Viewer" are now grouped under a single **Open as** submenu (Hex / Text / Protobuf) instead of three separate top-level context-menu entries, keeping the already-long menu manageable; the new "Realm DB (Encrypted)…" and "SQLite DB (SQLCipher)…" actions live there too.
- **Properties panel: "Open Format Info…" button** — replaces the single reference URL that used to be shown directly in the Properties panel (hardcoded to whichever link happened to be first for that format, not necessarily the most relevant one — some formats have half a dozen: spec, general overview, forensic write-ups, …). The button appears at a fixed position right after Path — not after the parser metadata, whose length varies — and only when a format was actually identified. It opens the existing Format Info dialog, which already lists every known reference link with its own label, so there's no more guessing which single URL to surface.
- **Drag and drop** — files, archives, and folders can now be dropped straight onto the Crush window instead of going through the File menu, on Windows, macOS, and Linux alike. Follows the same append-vs-replace rule as **Open file…**/**Open folder…**: a dropped file appends to the current tree, a dropped folder or archive replaces it.

### Bug Fixes

- **Checkboxes and radio buttons were nearly invisible in every theme** — the Fusion style's built-in indicator painting shades its border from palette roles (Light/Midlight/Mid/Dark/Shadow) that Crush's theme palettes leave mostly unset; measured directly (rendered to an offscreen pixmap, sampled the indicator's border vs. fill pixels), border-vs-fill contrast came out to only ~60/255 in the Light theme and ~1-8/255 in Dark/Geek — i.e. an unchecked box was close to invisible everywhere, worst in Light (noticed first in the new SQLCipher dialog's several checkboxes, but affects every checkbox/radio button in the app). Fixed with a targeted stylesheet, generated from each theme's own palette, that gives the indicator an explicit bordered box (unchecked) vs. a solid Highlight-filled box (checked) — verified to bring border-vs-fill contrast up to 190-230/255 across Light, Dark, and Geek.
- **RealmDB parsing was fundamentally wrong for real-world files** — the parser guessed at each column's shape instead of reading its declared type, and any table split across multiple internal B+-tree clusters (i.e. any table with enough rows, including the message/conversation tables in a real mail app) had its rows silently misread as tree bookkeeping data, truncating hundreds of rows down to single digits. Rewritten from scratch against the real Realm Core C++ source (Apache-2.0), with every column type now dispatched deterministically from its declared type instead of guessed. Closes [#38](https://github.com/kalink0/crush-forensics/issues/38).
- **Parser-wide audit for the same class of bug: silently guessing structure instead of reading it** — every parser in `crush/parsers/` was reviewed for shape-based guessing that could silently produce wrong or missing data. Fixed: `abx_decoder` (an unrecognized ABX value type was silently treated as a string, desyncing every field after it — now surfaces as a decode error instead); `segb_parser` (undecodable protobuf blobs disappeared from the readable Payload column instead of showing a hex preview; a Cocoa-range timestamp field silently overwrote the raw number, including in the SQL-queryable JSON column, breaking type-consistent comparisons); `realm_parser` (dead, never-matched millisecond/nanosecond timestamp-unit guessing removed; the row-count fallback used only when a Cluster leaf is corrupted is now labeled "estimated" in the Schema/Summary tabs instead of shown as a normal count); `unified_log_parser` (timestamps before 2000 — which can also mean a tampered device clock, not just a boot-relative artifact — were discarded instead of kept visible); `log_parser` (JSON field-priority lookup used a `set`, whose iteration order isn't guaranteed, so the same file could resolve a different timestamp/level field between runs); `protobuf_parser`/`segb_parser` (a field shown as a nested message now always carries a "raw bytes" hint alongside it, since the wire format never actually guarantees the bytes are a submessage).
- **Frozen builds could fail to start entirely if `cryptography` failed to load** — `crush.core.vfs` imported `android_backup_crypto`/`ios_keybag` (and therefore `cryptography`) at module load time, so if `cryptography`'s compiled extension failed to load in a packaged build (observed on macOS: a PyInstaller dylib version mismatch — see below), the whole app crashed on startup for every user on that build, not just when opening an Android/iTunes backup. Both are now imported lazily, inside only the methods that actually need them, so a broken `cryptography` load degrades to a normal "Load error" dialog when opening a password-protected mobile backup instead of preventing the app from starting at all.
- **macOS Intel build: app failed to start (`dlopen` symbol not found in `libssl.3.dylib`)** — under investigation; PyInstaller appears to bundle a stale system/interpreter-provided `libssl.3.dylib` instead of the one `cryptography`'s wheel ships, based on a [known PyInstaller issue pattern](https://github.com/pyinstaller/pyinstaller/issues/8797). The lazy-import fix above contains the blast radius in the meantime; the root cause in the build pipeline is not yet fixed.
- **SEGB v1 supported iOS range corrected** — the Format Reference entry stated iOS 15-16; SEGB v1 is actually used from iOS 14.
- **Wrong password on a header-encrypted 7z archive could raise an unhandled error instead of the password dialog** — `py7zr` has no reliable way to distinguish "wrong password" from "corrupt file" for header encryption (decrypting with the wrong key just yields garbage that fails to parse), and *which* parse step trips first — and so which exception type surfaces — isn't stable across `py7zr` versions or platforms: observed as a bare `TypeError` on Linux and a `Bad7zFile` on Windows CI for the same fixture. `SevenZipVFS` now catches both and reports it as a wrong password.
- **Hex viewer's toolbar forced an oversized minimum window width, most visible in the Realm viewer** — all ~15 toolbar widgets (search, match navigation, page navigation, copy actions) lived in a single non-wrapping row, whose combined minimum width (~1177px) a `QTabWidget` then adopts as its own minimum even for tabs that never show that hex view at all (Qt sizes a tab widget from its largest page, not just the current one) — so opening any Realm file pinned the window near ~1200px wide and blocked shrinking, because both its "Hex Preview" and "Freed Data" tabs embed a hex view alongside much narrower ones. Split into two rows; the Realm viewer's minimum width drops from ~1200px to ~690px.

## v0.13.0 - 2026-07-04

**Focus: Mobile backup support (Android `.ab` / iTunes) with full password/encryption handling extended to ZIP and 7z archives; Apple ATX image decoding; hex/text search overhaul; Value Inspector expansion.**

### New Features

- **7z archive support** — `.7z` files now open as browsable trees, same as ZIP and TAR, via a new `SevenZipVFS` backed by `py7zr`. Type-detection scanning batch-extracts the whole archive in one pass (archives up to 1 GiB) instead of re-decompressing shared solid-compression blocks once per file — ~13x faster in testing on a 40-file archive; larger archives fall back to the previous per-file extraction. Addresses [#28](https://github.com/kalink0/crush-forensics/issues/28).
- **Mobile backup support (Android `.ab` / iTunes backup)** — two new VFS backends reconstruct the original device filesystem instead of just listing the raw container layout. `AndroidBackupVFS` unpacks an `adb backup` container (header + deflate-compressed tar) and shows it like any other TAR. `ITunesBackupVFS` reads a Finder/iTunes backup folder's `Manifest.db` and rebuilds the `domain/relativePath` tree so files appear under paths like `HomeDomain/Library/SMS/sms.db` instead of the flat, fileID-named layout on disk. Since iOS 10.2, `Manifest.db` is always KeyBag/AES encrypted regardless of whether the backup itself has a password — `crush.core.ios_keybag` implements that unwrap/decrypt (PBKDF2 + RFC 3394 AES key-unwrap + AES-CBC, via `cryptography`) so this works transparently for the common no-password case. Opening a `.zip` that contains a wrapped iTunes backup now prompts the user ("open as iTunes backup?") instead of silently reinterpreting an otherwise ordinary ZIP; detection requires all three backup metadata files (`Info.plist`, `Manifest.plist`, `Status.plist`) alongside `Manifest.db`, a hex-sharded fileID subdirectory as an immediate sibling, and `Manifest.plist` actually containing a `BackupKeyBag` — filename matching alone (the initial version) produced false positives on full filesystem extractions, where an unrelated app's own `Manifest.db` sitting next to the `Info.plist` every app bundle has was enough to trigger it. Password-protected backups (iTunes `IsEncrypted=True`, or an Android backup encrypted via `adb backup`'s on-device password prompt) now prompt for a password via the GUI (and re-prompt on a wrong one) instead of just failing — `crush.core.android_backup_crypto` implements Android's PBKDF2/AES-256 master-key-unwrap scheme (verified against the Android Backup Extractor reference implementation), reusing the same generic `password_required` signal already wired up for iTunes backups, so no GUI changes were needed to support it. Individual file contents in password-protected iTunes backups are additionally per-file encrypted (protection-class keys derived from the same KeyBag) and are now transparently decrypted on read, using the existing NSKeyedArchiver decoder already vendored for plist parsing to read each file's `ProtectionClass`/`EncryptionKey` metadata. Verified end-to-end against a real password-protected iOS 14.3 backup. `crush.core.passwords` holds the shared `PasswordRequiredError`/`WrongPasswordError` types so encrypted ZIP/TAR/7z support can reuse the same password flow later.
- **Encrypted ZIP and 7z archive support** — both password-protection schemes for each format now open transparently via the same GUI password prompt already built for mobile backups. For 7z, `py7zr` already does the AES/PBKDF2 work internally; `SevenZipVFS` just passes the password through and translates `py7zr`'s exceptions, including proactively test-decrypting one entry at open time for content-only-encrypted archives (archives with header encryption enabled fail immediately when listing, so without this check a missing/wrong password on a content-only-encrypted archive would otherwise only surface later — confusingly, from a background type-detection scan or when opening a specific file). For ZIP, legacy ZipCrypto is handled by stdlib `zipfile`'s own built-in password support (unchanged, no new dependency); WinZip AES entries (`compress_type == 99`, which stdlib can list but never decompress) are routed to a lazily-constructed `pyzipper.AESZipFile` handle instead — `ZipVFS` itself still uses stdlib zipfile as its primary backend, since it's by far the most heavily used VFS backend in the app and swapping its foundation wholesale for a less battle-tested third-party library was judged not worth the risk for what only a minority of archives need.
- **Apple ATX image support** — `.atx` texture archive files (used by iOS PosterBoard and similar system UI caches) now decode and display as images. Some samples store ASTC blocks with ambiguous Morton-order tile addressing, so the parser decodes both plausible orientations and picks whichever leaves the smaller brightness discontinuity across macro-tile boundaries. ([@JamesHabben](https://github.com/JamesHabben), [#29](https://github.com/kalink0/crush-forensics/pull/29))
- **Value Inspector: 9 new timestamp formats and Base64 decoding** — added Cocoa/Apple (ns), .NET Ticks, OLE Automation Date, Twitter/X Snowflake ID, FAT/exFAT MS-DOS, BCD (7-byte YYYYMMDDHHMMSS), UUID v1 Timestamp, GPS Time (s/ns), and Windows SYSTEMTIME interpretations. A new Encoding group decodes Base64/Base64url, showing the result as hex and, where valid, UTF-8; a guard skips strings made up only of hex/decimal digits to avoid false positives.
- **Search overhaul for the hex and text viewers** — the hex viewer replaces single-shot find with find-next/prev navigation, yellow/orange match highlights in both the hex and ASCII columns, a "Show all" results panel (offset · hex · ASCII preview), and a right-click context menu to search a selected byte range as ASCII or hex. The text viewer gets a matching "Show all" results panel (line · column · preview) with click-to-jump, synced to find-next/prev. Addresses [#30](https://github.com/kalink0/crush-forensics/issues/30).

### Improvements

- **"Open as Hex" fallback on load error** — when a source fails to load (e.g. a corrupt or truncated ZIP), the error dialog now offers an "Open as Hex" button that opens the raw file bytes in the hex viewer instead of leaving the file completely inaccessible. Addresses [#31](https://github.com/kalink0/crush-forensics/issues/31).
- **Format Reference / Format Info accuracy** — ZIP, TAR, 7z, Android Backup Archive, and iOS Backup (iTunes/Finder) now correctly show as "Supported" instead of "Not yet supported": these are handled by VFS backends rather than a `crush/parsers/` parser class, and the format database's `parser_class` field previously only recognized the latter. The field's scope was broadened to cover both. Also corrected an outdated claim in the iOS Backup entry — it read "unencrypted backups: all files directly accessible," which is wrong since iOS 10.2 (`Manifest.db` is always KeyBag-encrypted regardless of backup password; only individual file contents stay in the clear when unencrypted).
- **Shift+wheel horizontal scrolling** — hex, text, tree, table, LevelDB, Realm, protobuf, and image viewers, the BLOB inspector, and the filesystem/properties/search panels now scroll horizontally on Shift + mouse wheel. ([@JamesHabben](https://github.com/JamesHabben), [#27](https://github.com/kalink0/crush-forensics/pull/27))

### Bug Fixes

- **SQLite temp companion files not deleted on close** — when a SQLite database with WAL or SHM companions was opened, `SQLiteParser` correctly extracted all three files (`-wal`, `-shm`) to the OS temp directory, but `TableViewer.closeEvent` only deleted the main `.db` file. The companion files are now also deleted on close.
- **"Open in New Window" missing inside archives** — the context menu entry only appeared for files with a real path on disk, so a SQLite database or nested archive found inside an opened ZIP/TAR was stuck without it. The file is now extracted to a temp file and loaded into the new window regardless of source type; the extracted file's cleanup is now owned by the new window rather than the source window, so closing the archive window first no longer deletes the file out from under the still-open new window. If Integrity Mode is on, the original archive-relative path is hashed and logged before extraction, so the chain-of-custody log still reflects where the file actually came from. Re-addresses [#15](https://github.com/kalink0/crush-forensics/issues/15).

## v0.12.1 - 2026-06-22

**Focus: Audio/video playback fix in distributed builds; format knowledge base corrections; format identification accuracy.**

### Bug Fixes

- **Audio/video playback broken in all distributed builds** — `PySide6.QtMultimedia` and `PySide6.QtMultimediaWidgets` were accidentally excluded from all PyInstaller builds (Linux, macOS, Windows) since the May 10 size-reduction commit. All audio and video playback in the `.AppImage`, `.app`, and `.exe` releases was non-functional. The exclusion lines have been removed and `QtMultimedia` is now bundled correctly; the macOS post-build framework-strip step no longer removes the `QtMultimedia.framework`.
- **Audio formats not linked to MediaParser in Format Reference** — MP3, WAV, M4A, AAC, FLAC, OGG, Opus, WMA, and AMR entries in the format knowledge base had `parser_class = None`, causing the Format Reference panel to show no associated viewer for these formats. All nine audio entries now correctly reference `MediaParser`.
- **Format identification — WAV misidentified as AVI** — `FormatDatabase.identify()` scored magic byte patterns individually; formats with a shared container prefix (WAV and AVI both start with `RIFF` at offset 0) were resolved by query order rather than specificity. The scorer now accumulates the total matched bytes across all patterns for each format: a WAV file matches both `RIFF` (offset 0, 4 bytes) and `WAVE` (offset 8, 4 bytes) for a combined score of 8, while AVI only matches `RIFF` (4 bytes) — so WAV wins. The same logic correctly disambiguates MOV from MP4 via the `qt  ` QuickTime brand, and MKV/WebM via their respective EBML DocType patterns.

## v0.12.0 - 2026-06-21

**Focus: Value Inspector, extended BLOB decode pipeline, multiple windows, welcome screen, and SQLite query performance.**

### New Features

- **Value Inspector** — *Tools → Value Inspector…* opens a persistent non-modal window that shows all plausible interpretations of any text value. On Linux/X11 the window auto-updates whenever text is selected anywhere within Crush (via X11 PRIMARY clipboard); on other platforms enter or paste a value manually. Interpretation groups: *Integer* (decimal, hex, signed/unsigned 32 & 64-bit, big-endian and little-endian variants for hex-byte input), *Float* (64-bit double, Float32 and Double reinterpret as BE and LE), *Timestamp* (Unix s/ms/µs, Cocoa/Apple, Chrome/WebKit, Windows FILETIME, HFS+), *UUID*, *Network* (IPv4 BE/LE, MAC address), *Text* (ASCII and UTF-8 rendering of hex bytes). All cells show a tooltip with the full text on hover.
- **'Merica theme** — a deliberately over-the-top red-white-blue U-S-A intro settles into a calmer hold-and-fade patriotic palette, with a status-bar button to replay the show. The intro uses an accessibility-conscious cadence below three colour changes per second.
- **Open in New Window** — right-clicking any file in a folder source now shows *Open in New Window*; the file is loaded into a fresh Crush window without affecting the current session. Addresses [#15](https://github.com/kalink0/crush-forensics/issues/15).
- **Multiple windows** — *File → New Window* (Ctrl+N) opens an additional Crush window; *File → Close Window* (Ctrl+W) closes the current window without exiting the application. The window title shows the loaded source name to help distinguish windows. ([@JamesHabben](https://github.com/JamesHabben), [#17](https://github.com/kalink0/crush-forensics/pull/17))
- **Welcome screen** — an *Open something to begin* screen with *Open File* and *Open Folder* buttons is shown when no source is loaded. ([@JamesHabben](https://github.com/JamesHabben), [#18](https://github.com/kalink0/crush-forensics/pull/18))
- **Recent files on welcome screen** — the last 10 recently opened sources are listed on the welcome screen for quick access.

### Improvements

- **BLOB Inspector — extended decode pipeline** — three new byte→byte transform steps: *Base64url (decode)* (URL-safe alphabet, padding added automatically), *lzfse decompress* (Apple LZFSE; new dependency `lzfse>=0.4.2`), and the panel layout is now a reusable `_BlobPanel` widget shared with Paste & Decode. The auto-selection logic restores the previous format only when it still produces output after a pipeline change.
- **Paste & Decode — redesigned as BLOB Inspector entry point** — the *Tools → Paste & Decode…* dialog now embeds the full BLOB Inspector panel directly below the input field. Paste hex, base64, or text; the panel updates live as you type. All decode steps and interpretations available in the BLOB Inspector are automatically available here too.
- **Unified Open dialog** — *File → Open ZIP archive…* and *File → Open TAR archive…* are replaced by a single *File → Open file…* entry; Crush detects the format automatically from file content.
- **SQLite query improvements** — virtual table model replaces cell objects for significantly faster rendering; background type indexing paused during queries and table interaction; default result limit of 10 000 rows with option to load full results; per-query timing display with detailed breakdown tooltip; Cmd+Enter shortcut added alongside F5. A 55 MB single-table database returning 200 000 rows improved from >15 s to ~1.4 s. ([@JamesHabben](https://github.com/JamesHabben), [#22](https://github.com/kalink0/crush-forensics/pull/22))
- **About dialog — Contributors section** — the Acknowledgements tab now has a *Contributors* heading with a short thank-you to the open-source and DFIR community ahead of the third-party library list.

### Bug Fixes

- **LevelDB log offset double-multiplication** — `LogFile._get_batches()` yielded `start_block_offset * LOG_BLOCK_SIZE` as the batch offset, but `start_block_offset` already included the `idx * LOG_BLOCK_SIZE` factor. The extra multiplication produced wrong byte offsets for multi-block log records. Fix ported from upstream `ccl_chromium_reader` (PR #41 by RyanDFIR).
- **About dialog — ccl_segb link** — the link in the Acknowledgements tab pointed to `cclgroupltd/ccl_segb` (underscore); the correct repository name is `cclgroupltd/ccl-segb` (hyphen).
- **Dangling content view and stale properties after source change** — opening a folder or archive while files were already open left the previous file's content and metadata visible. The content tabs and properties panel are now cleared whenever a source replaces the current one; closing the last source returns to the welcome screen. Closes [#16](https://github.com/kalink0/crush-forensics/issues/16). ([#20](https://github.com/kalink0/crush-forensics/pull/20))
- **Theme switching broken with multiple windows** — each new window started its own rainbow timer; switching the theme in one window stopped only that window's timer while the others kept overwriting the application palette every 50 ms. Animated theme cleanup now stops timers in all open windows.
- **Ctrl+Q exits the application** — previously called `close()` on the current window only; now calls `QApplication.quit()` so all open windows are closed.
- **macOS build — app bundle not launching** — `--collect-all PySide6` caused a `pkg_resources.NullProvider` error at startup; removed in favour of PyInstaller's built-in PySide6 hook. The `ditto` packaging step now passes `--keepParent` so the `.app` bundle is preserved inside the ZIP. ([@JamesHabben](https://github.com/JamesHabben), [#14](https://github.com/kalink0/crush-forensics/pull/14), closes [#8](https://github.com/kalink0/crush-forensics/issues/8))

## v0.11.0 - 2026-06-07

**Focus: Protobuf decoding improvements**

### Bug Fixes

- **Search — negation filter (`-type:`, `-name:`)** — `-type:segb` was silently parsed as `type=segb` plus `name=-`, so it matched nothing instead of excluding the given type. The filter parser now recognises a leading `-` as a negation prefix; `-type:segb` returns all files that are *not* SEGB, and `-name:foo` excludes files whose name contains `foo`.
- **Protobuf rendering fixes** — the BlobInspector's Protobuf decode mode incorrectly compared `wire_type` against `"message"` instead of inspecting `value.type`; nested messages now render as indented blocks (`field { … }`). Plain strings now display as `field: "text"` and raw bytes as `field: <hex>`; both previously showed unformatted dict reprs. The nested-first heuristic in `_decode_message` was also inverted: a length-delimited payload is now tried as a nested message first and falls back to UTF-8 string or hex bytes only if that yields no entries.

### Improvements

**Protobuf viewer**
- **Multi-interpretation display** — every numeric field in the schema-less viewer now shows all plausible type readings as dimmed child rows: `uint64`, `int64`, `sint64 (zigzag)`, `bool`, Unix/Cocoa/Chrome timestamps, `double`, and `float` — each only when the value falls within a plausible range. The same hints appear in the BlobInspector as `# label: value` lines; `uint64` and `uint32` are suppressed there since they equal the primary value. Parse warnings are prepended as `# Warning:` headers.
- **Shared varint primitive** — the duplicate `_read_varint` implementations in `protobuf_parser` and `segb_parser` are replaced by a single `read_varint` in `crush/parsers/proto_wire.py`, following the Protobuf spec (max 10 bytes for a 64-bit varint).
- **Group wire types skipped gracefully** — wire types 3 (start-group) and 4 (end-group) previously aborted the entire parse. The decoder now skips group fields — including nested groups — and continues with subsequent fields. Truncated groups or unexpected end-group tags at the top level produce a parse warning.

## v0.10.0 - 2026-05-28

**Focus: Extended image support, cross-platform audio playback, and plist/NSKeyedArchiver improvements.**

### New Features

- **HEIC / HEIF / AVIF / JPEG XL image support** — the image viewer now renders HEIC, HEIF, AVIF, and JPEG XL files. Qt's native decoder is tried first; if it cannot handle the format, Pillow decodes to raw pixels directly — no intermediate encode. EXIF metadata (GPS, device make/model, timestamp, ISO, aperture) is extracted and shown in the Properties panel. **Known limitation:** HEIC/HEIF multi-image containers (burst frames, HDR layers, depth maps, Live Photo previews) — only the primary image is currently shown.
- **Plist tree viewer — BLOB Inspector** — right-clicking any field in the plist tree now shows *Inspect BLOB…*: raw `bytes` values passed through directly, dicts/lists serialised to XML plist, scalars wrapped in a plist envelope — consistent with SQLite, Realm, SEGB, and LevelDB viewers.

### Improvements

**Image / Media**
- **OGG / Opus / AMR playback** — decoded via PyAV (bundled FFmpeg) and played through Qt's `QAudioSink`, bypassing codec gaps on macOS (AVFoundation) and Windows (Media Foundation). WhatsApp (`.opus`) and Telegram (`.ogg`) voice notes now play on all platforms.
- **OGG / Opus / AMR metadata** — Properties panel shows codec, sample rate, channels, duration, and Vorbis comment tags. The `Encoder` field identifies the originating app (e.g. `libopus` version from WhatsApp / Signal).
- **Magic-byte fallback for renamed audio** — OGG and AMR files with non-standard extensions (e.g. `.bin`) open in the media viewer based on content (`OggS` / `#!AMR`) rather than extension.
- **Type detection** — `HEIC`, `HEIF`, `AVIF`, `JXL` detected from ISOBMFF `ftyp` brand and JXL signatures before falling through to the `filetype` library; content wins over extension for misnamed files. `OGG` / `Opus` detected from Ogg page codec bytes (`\x01vorbis` / `OpusHead`).
- **`type:image` filter** — now category-aware; matches all image formats including HEIC, AVIF, and JXL even when the type label does not contain the word `image`. Use `type:heic`, `type:avif`, or `type:jxl` to narrow to a specific format.
- **Format knowledge base** — AVIF added with forensic context and ISOBMFF magic bytes. HEIC/HEIF and JPEG XL entries corrected (`parser_class` was missing, causing fallback to hex viewer).
- **Magic match — most-specific wins** — `identify()` now returns the format with the longest matching magic pattern; prevents generic container signatures (e.g. `OggS`) from shadowing specific codec identifiers (e.g. `OpusHead`).

**Plist / NSKeyedArchiver**
- **Extended type converter** — `NSData`/`NSMutableData` (→ `bytes`), `NSNull` (→ `None`), `NSDateComponents` (→ readable string) added; implemented as a wrapper around the vendored ccl_bplist converter.
- **Unknown custom classes** — unhandled `$class`/`$classname` metadata now shows the class name in the Type column; internal `$class`/`$classes`/`$classname` keys hidden, only data fields visible.
- **NSKeyedArchiver in BLOB Inspector** — the *Plist / bplist* decode mode now goes through the full `deserialise_NsKeyedArchiver` path, matching the file parser. SQLite BLOBs containing NSKeyedArchiver payloads show the decoded object graph instead of raw `$objects`/`$top` internals.
- **Deserialization failure surfaced** — a failed `deserialise_NsKeyedArchiver` was previously swallowed silently; Properties panel now reads `binary (NSKeyedArchiver — deserialization failed)` and logs a warning, while the raw plist structure remains visible.
- **Additional supported extensions** — `.sfl` and `.archive` added to `PlistParser`'s extension list (already handled via magic-byte detection; list now reflects reality).

### Bug Fixes

- **Wayland — floating dock panels** — `Qt::Tool` window type drew without resize handles on KDE/GNOME Wayland; switched to `Qt::Window` when floating.
- **Wayland — move/resize broken after first interaction** — `startSystemMove()` fails after a resize because no active button press is tracked by the compositor; replaced with manual delta-based dragging. Wayland/XWayland detection now covers `XDG_SESSION_TYPE` and `WAYLAND_DISPLAY`.
- **XML plist — DOCTYPE files opened in hex viewer** — parser registry peeked only 64 bytes; Apple's standard DOCTYPE declaration is ~150 bytes, so `<plist>` was not reached. Peek size raised to 256 bytes.
- **XML plist — root-tag detection** — previous logic navigated past `<?…?>` and `<!…>` blocks by searching for `>`; failed when blocks extended past the peek window. Replaced with direct `<plist` substring search.
- **Format label — XML files misidentified as "XML plist"** — `FormatDatabase.identify()` matched any `<?xml` file against the plist entry without verifying the root tag; `_looks_like_plist_xml()` is now called as an additional guard.

## [0.9.0] — 2026-05-16

### New Features

- **SEGB / Biome viewer** — complete forensic overhaul of the SEGB v1/v2 parser:
  - Protobuf payloads decoded automatically: Cocoa timestamps shown as ISO datetimes, nested messages expanded inline, full field-number range supported (up to 2²⁹−1), repeated fields collected into arrays.
  - Backing SQLite database created on open with autocomplete-enabled SQL editor. `Payload` column shows human-readable text; `Payload JSON` column enables `json_extract("Payload JSON", '$.N')` field queries (nested: `$.N.M`, repeated: `$.N[i]`).
  - Raw protobuf bytes always accessible via Blob Inspector on double-click.
- **New themes** — *Geek* (phosphor-green terminal), *Purple* (synthwave), and *Ocean* (cyan/navy) added under *View → Theme*; all persist across sessions.
- **Rainbow theme + custom snapshot** — *View → Theme → Rainbow* cycles the UI palette through the full colour spectrum; a *⏸ Snapshot* button in the status bar lets you pause, name, and save the current hue as a permanent custom theme entry.

### Improvements

- **Table viewers — cell detail panel** — a collapsible pane below the table shows the full content of the currently selected cell and updates live on click or keyboard navigation. Decoded text (e.g. SEGB protobuf payload) is shown where available; binary BLOBs fall back to a UTF-8 decode or a hex preview with a byte-count hint. Applies to SQLite, SEGB, and Realm viewers.
- **Table viewers — wide-column usability** — columns are now capped at 400 px after auto-sizing so a single long cell can no longer force the table far off-screen; holding **Shift** while scrolling moves the table horizontally. Applies to SQLite, SEGB, and Realm viewers.
- **BLOB Inspector — "Decoded (from table)" view** — when opening the BLOB Inspector on a cell that has a decoded display (e.g. SEGB protobuf payload), a *Decoded (from table)* option is inserted at the top of the format dropdown and selected by default, showing the human-readable content immediately. Raw bytes are always preserved, so switching to *Protobuf (schema-less)*, *Hex*, or any other format mode continues to work correctly on the original binary data.
- **SQLite viewer — SQL autocomplete** — context-aware completion for table/view names after `FROM`/`JOIN` and column names after dot notation; aliases resolved automatically.
- **SQLite viewer — summary navigation** — double-clicking a table row in the Summary tab jumps directly to that table.
- **Realm / SQLite viewers** — BLOB cells now expose raw bytes to the Blob Inspector on double-click; SQL autocomplete and summary-tab navigation work in the Realm viewer.

### Bug Fixes

**SEGB / Biome**

- **SEGB viewer — spurious Bundle ID / Stream ID / Payload Timestamp columns removed** — these columns appeared empty for most entries because the field number mapping was based on incorrect assumptions about the SEGB protobuf schema; removed to avoid misleading analysts. The full protobuf payload remains accessible via the `Payload` and `Payload JSON` columns.
- **SEGB — Inspect Cell / double-click inconsistency on decoded columns** — double-clicking a payload cell sent raw bytes to the BLOB Inspector while right-click *Inspect Cell…* sent the decoded text string; choosing *Protobuf (schema-less)* in the inspector then produced garbage because it tried to parse the text as wire format. Both paths now always send raw bytes and pass the decoded text separately as the *Decoded (from table)* default view.
- **Show Format Info — SEGB files reported as Unknown** — right-clicking a SEGB file and choosing *Show Format Info* always reported "Unknown format": (a) the format lookup only peeked 32 bytes, too few to reach the SEGB v1 magic at offset 52; (b) SEGB v2 (magic at offset 0) had no entry in `formats.db`. Both are fixed; a `detect_fast_label` fallback is also applied so format detection is consistent with the filesystem panel.

**SQL Editor**

- **SQL editor — run selected query** — running a selection was rejected with *"Only SELECT queries allowed"* due to a Unicode paragraph-separator stripping bug; fixed. Affects SQLite, SEGB, and Realm viewers.
- **SQL editor — fixed height** — the SQL input could not grow when the panel below was resized; now expands freely with a 6-line minimum.

**Realm**

- **Realm viewer — summary double-click navigation** — double-clicking a table row in the Summary tab did not navigate to that table; fixed (the "Row" prefix column shifted the name to column 1 while the handler always read column 0).

**Platform / UI**

- **macOS rendering** — tab close buttons, tab colours, and file-tree expand arrows all rendered incorrectly with the native Qt style; switching to Fusion style (already used on Windows) fixes all three.
- **Linux / Wayland — floating dock panels could not be resized** — undocking a panel on Wayland triggered a *"mouse grab only for popup windows"* warning and the panel had no resize handles; caused by the custom dock title bar added in a previous release, which prevents the Wayland compositor from providing its own decorations. On Wayland the custom title bar is now skipped so the window manager handles move and resize natively.
- **Filter history — Enter key** — pressing Enter committed the top history suggestion instead of the typed text; fixed by switching completion mode.

**AppImage**

- **AppImage — missing execute permission** — the nightly CI pipeline uploaded the AppImage as an artifact and re-downloaded it without restoring the execute bit, causing file managers to open it as a disk image instead of running it; fixed by adding `chmod +x` in the release job.
- **AppImage — Open External broken** — `xdg-open` failed silently because AppImage environment variables leaked into the subprocess; stripped before invocation.

### Build / Distribution

- **Native packages** — Linux AppImage, macOS ZIP (Apple Silicon + Intel), Windows ZIP produced by CI.
- **Bundle size** — unused Qt modules stripped; macOS artifacts use `ditto` to preserve framework symlinks.
- **Application icon** — window icon set at runtime on all platforms; Wayland app-id registered via `setDesktopFileName`.

---

## [0.8.0] — 2026-05-10

### New Features

- **Recent files menu** — *File → Open Recent* lists the last 10 opened files, archives, and folders (full path shown, persisted across sessions); includes a *Clear Recent* option.
- **Filter history*b* — the filesystem panel filter field remembers the last 30 used filters (persisted across sessions); click the field to browse history, or type to narrow by substring. Filter applies on Enter; picking from the dropdown applies immediately.
- **LevelDB viewer** — LevelDB databases are parsed in a dedicated viewer:
  - *Overview* — all `MANIFEST-*` files (active one labelled *(current)*), comparator, sequence number, and files by level.
  - *Files* — per-file summary with size, key ranges, and live/deleted/unknown counts; deleted files highlighted red.
  - *Records* — all records with live/deleted state, sortable *Offset* (byte position in source file), split *Key* / *Value* hex pane, state filter, free-text search, and *Export CSV…*.
  - *Forensic columns* — full *Internal Key* (user key + 8-byte sequence/type suffix) for `.ldb`/`.sst` files; CSV exports include complete hex-encoded key and value bytes.
  - *Cell inspector* — right-click any row for *Inspect Key…*, *Inspect Value…*, or *Inspect Internal Key…* in the BLOB Inspector.
  - *LOG tabs* — `LOG` and `LOG.old` shown in dedicated read-only tabs with a *Find* toolbar.
- **Realm Freed Data — cell inspector** — right-clicking a freed block now offers *Inspect Block…* in the BLOB Inspector.
- **BLOB Inspector — new decode modes** — *Protobuf (schema-less)*, *Android Binary XML (ABX)*, *Image (PNG / JPEG / GIF)*, and *JSON* modes added; all auto-detected in Auto mode where applicable.

### Improvements

- **atime preservation** — `DirectoryVFS` and `FileVFS` no longer update the access time of source evidence files (Linux: `O_NOATIME`; Windows: atime restored after read; macOS: not yet implemented).
- **BLOB Inspector — non-blocking** — opens as a non-modal window; multiple inspectors can be open simultaneously.
- **Paste & Decode — inline result** — decoded output appears in the same window instead of a separate tab.
- **macOS badge** — README updated to reflect source-only macOS support (no working pre-built executable).

### Testing

- **Forensic timestamp/atime preservation** — new tests verify that `DirectoryVFS`, `ZipVFS`, `TarVFS`, `SQLiteParser`, `RealmParser`, and `LeveldbParser` do not modify mtime, ctime, or atime of source evidence files.

---

## [0.7.0] — 2026-05-04

### Bug Fixes

- **SQLite WAL support from ZIP** — fixed incorrect path resolution preventing WAL from loading correctly.
- **Realm table viewer crash (OverflowError)** — fixed Qt overflow when decoding invalid >64B integer widths; unsupported scheme=1 widths are now rejected.
- **Realm schema mapping (BackLink issue)** — replaced heuristic column mapping with explicit `spec→child[5]` colkey mapping; BackLink (type 14) excluded.
- **Realm timestamp decoding** — fixed type-8 decoding where nanoseconds were misinterpreted as a null bitmap.
- **Realm row count mismatch** — row count now derived from ObjKey array instead of heuristic, fixing sparse table issues.
- **Realm nullable booleans** — correct decoding of 2-bit values (True / False / None instead of raw integers).
- **Realm NULL-only columns missing** — now preserved and displayed as all-`None` columns.

---

### Improvements

- **Realm Freed Data tab** — added view of free-space entries with offset, size, source refs, decoded content, and hex view. Entries are color-coded by source ref state.
- **Realm Top Refs diff** — added child-level comparison of root structure (count, width, flags); offset diff removed as non-informative.
- **Dual Top Ref decoding** — active and previous snapshots are now both parsed and available for comparison.
- **Top Refs schema diff** — added detection of added/removed tables and row-count changes between snapshots.
- **Realm file labeling** — `.realm` files now correctly identified in the VFS tree.
- **Schema tab overhaul** — real column names and types are now displayed instead of generic `col_N`.
- **Format 24 decoding fixes**
  - correct string decoding (fixed-width inline entries)
  - correct column ordering (last-N user columns)
  - correct link column handling (ObjKey refs)
- **Type system improvements** — column types now parsed from schema and shown consistently across Schema and Tables tabs.
- **SQL support in Tables tab** — in-memory SQLite database enables full querying, including JOINs.
- **Cross-table joins** — link columns can be joined directly via ObjKey-based mapping.

---

### Testing

- **Realm forensic test suite**
  - immutability check (no modification of source file)
  - no side effects (no sibling files created)
  - read-only media support
  - deterministic output validation
  - known fixture validation (`minimal.realm`)
- **Corpus integrity expansion** — Realm added to existing SQLite/plist/ZIP/TAR test coverage with SHA-256 verified fixture.

## [0.6.0] — 2026-05-01

### New Features

- **Export as .logarchive** — iOS diagnostics nodes (`diagnostics/`) now have an "Export as .logarchive…" right-click action. Crush assembles the logarchive (diagnostics tree + uuidtext sibling) in a temporary directory and copies the result to a user-chosen location, producing a standard `.logarchive` folder that can be opened in other tools.
- **SQLite timestamp column decoding** — right-clicking a column header in the SQLite / table viewer now offers a "Decode column as timestamp" submenu. Supported formats: Unix seconds, Unix milliseconds, Unix microseconds, Mac Absolute Time (seconds since 2001-01-01), Windows FILETIME (100 ns since 1601-01-01), and Chrome / WebKit time (µs since 1601-01-01). The decoded values are displayed as `YYYY-MM-DD HH:MM:SS UTC`; the column header shows the active format as a suffix (e.g. `created_at [unix ms]`). Sorting remains chronologically correct because the raw numeric value is preserved internally. Select "Clear timestamp format" to revert.
- **Parallel Apple Unified Log conversion** — Multi-Log Studio now splits large logarchives and iOS diagnostics across multiple `unifiedlog_iterator` processes (one per physical core by default). Entries stream into the viewer as each chunk finishes rather than waiting for the full conversion. On a typical 200 MB acquisition this yields a ~25 % wall-time reduction; the speedup scales with the number of tracev3 files and available cores.
- **Paste & Decode** — **Tools → Paste & Decode…** opens a dialog where you can paste raw hex, base64, or plain text and open it immediately in any supported viewer. The input encoding is auto-detected (or can be forced), and the target format is chosen from a dropdown (Auto-detect, Binary plist, XML plist, JSON, XML, SQLite, Realm, Android Binary XML, SEGB / Biome, Protobuf, or raw Hex view). Useful for inspecting data copied out of a hex editor, BLOB cell, or network capture without saving it to disk first.

### Bug Fixes

- **Paste & Decode: Protobuf option silently fell back to auto-detect** — the Protobuf parser was not registered in the parser registry, so selecting "Protobuf (schema-less)" in the Paste & Decode dialog had no effect and auto-detection was used instead. The parser is now registered (explicit-only: it never wins in auto-detection but is reachable by name).
- **Multi-Log Studio hang on close during unified log conversion** — closing the Multi-Log Studio window while Apple Unified Log data was still being converted caused the whole application to freeze until the conversion finished (potentially many minutes). The underlying `unifiedlog_iterator` subprocess is now killed immediately when the window is closed, and the worker thread exits within milliseconds.
- **Apple Unified Log timestamps missing in Multi-Log Studio** — when loading an iOS full-filesystem acquisition directly, all log entries showed "—" in the Timestamp column. The root cause was that `unifiedlog_iterator` does not follow symbolic links for `timesync/` directories; the parallel mini-archive setup now copies `timesync/` and `Special/` into each chunk instead of symlinking them. Additionally, the CSV timestamp format emitted by the binary (`2024-01-15 10:23:45.123456789 +0000`, with a space before the timezone offset) was not handled by the timestamp parser; this is now fixed.

### Improvements

- **SQLite WAL forensic analysis:**
  - *WAL Frames (generated)* — new combo entry appears whenever a `-wal` companion is present. Shows a full frame inventory (Frame / Page / Transaction / Status / Table / Offset) with every frame classified as **Active**, **Superseded**, **Uncommitted**, or **WAL slack** (salt-mismatch frames from a previous WAL cycle, per Sanderson's terminology). Superseded and uncommitted frames are colour-coded amber and blue respectively so the examiner immediately sees whether overwritten or in-flight data exists. The Table column shows which schema object owns each page, resolved by walking the B-tree from `sqlite_master` root pages.
  - *Show WAL history toggle* — a **Show WAL history** checkbox appears in the table toolbar whenever the active table has non-Active frames in the WAL. When enabled, the table gains a **WAL Source** column and rows decoded from Superseded, Uncommitted, and WAL-slack frames are appended below the current data with colour coding (amber / blue / gray). The row count label shows how many additional rows were recovered from WAL history.
  - *DB Info WAL summary* — when a WAL is present, six WAL metrics (file size, total frames, active / superseded / uncommitted / WAL-slack counts) are prepended to the DB Info view above the PRAGMA list, with amber/blue highlights on non-zero forensic counts.
  - *Raw page access* — double-clicking any WAL frame row extracts the raw page bytes (frame offset + 24 to skip the frame header) and opens them in the hex viewer, labelled `WAL frame N — page M`.
  - *WAL discovery for single-file open* — when a `.db` file is opened directly (not from inside a ZIP or folder), the parser now also checks the real filesystem for a `-wal` / `-shm` companion next to the file. Previously `FileVFS` scoped to the single file only, so companions were silently skipped.
  - *Parser read-only connection* — the SQLite parser now opens its internal connection with `mode=ro` (URI flag), preventing the automatic WAL checkpoint that previously destroyed the WAL companion before the viewer could read it.
- **SQLite / Table viewer — schema and settings inspection:**
  - *Summary view* now shows tables and views with row counts; the status label reports the full schema object count (tables, views, indexes, triggers) at a glance.
  - *DB Structure (generated)* — new combo entry listing all schema objects (tables, views, indexes, triggers) with structural details: column list for tables, CREATE SQL for views, `ON table (columns)` for indexes, and the first line of CREATE TRIGGER for triggers.
  - *DB Info (generated)* — new combo entry showing 28 PRAGMA settings in a three-column layout (Setting / Value / Description), styled after the DB Browser for SQLite "Edit Pragma" view. Enum values are decoded to their named constant (e.g. `2 — FULL` for auto_vacuum), booleans show as `1 — ON` / `0 — OFF`. The integrity_check hint pre-fills the SQL bar for on-demand use.
  - *Views in the selector* — database views are added to the combo box (below a separator) and are fully browsable like tables.
  - *SQL bar enhancements* — `PRAGMA` statements are now accepted alongside `SELECT`/`WITH`. Status feedback appears below the input field in red on error and default color on success. Selected text only: if a query fragment is highlighted, F5 / Run executes only that selection, enabling step-by-step debugging of complex queries.
  - *SQL syntax highlighting* — keywords, strings/identifiers, numbers, and comments are highlighted; colors adapt to light and dark palette.
  - *Resizable panes* — a splitter between the SQL bar and the results table lets the examiner maximise the data area.
- **Theme moved to View menu** — the Theme submenu (System default / Light / Dark) has been moved from **Tools** to **View**, where display-related settings belong.
- **Refinement of File Format Database entries** - all entries were double checked, the descriptions refined and relevant URLs added.

### Testing

- **Forensic integrity test suite** — added `crush/tests/test_forensic.py` with 14 tests that verify the tool is safe to run on real evidence. Tests are grouped into five categories and each carries a human-readable description of the forensic property it checks:
  - *Source Immutability* — DirectoryVFS, ZipVFS, and TarVFS must leave every source file or archive byte-identical after a full read.
  - *No Side Effects* — SQLiteParser must not create WAL, journal, or any other sibling file next to the evidence.
  - *Read-only Media* — all three VFS types and SQLiteParser must work correctly when the evidence file and its directory are `chmod 0o444 / 0o555`, simulating write-protected forensic media.
  - *Known-output Verification* — four committed reference artifacts (SQLite, binary plist, ZIP, TAR) must always parse to their exact pre-computed values.
  - *Reproducibility* — parsing the same artifact twice must produce structurally identical results.
- **WAL preservation test** — `test_sqlite_parser_preserves_wal_companion` verifies that parsing a WAL-mode database leaves the `-wal` companion byte-identical in the temporary working copy. The test simulates a live acquisition: a writer commits data to the WAL while a reader holds an open transaction (preventing auto-checkpoint), and the parser is run in that window. This test would have caught the read-write connection bug that silently checkpointed the WAL before the viewer could read it.
- **Reference corpus with checksum guard** — `crush/tests/fixtures/` contains four committed binary test-evidence files (`minimal.sqlite`, `minimal_binary.plist`, `minimal.zip`, `minimal.tar.gz`) with a `checksums.json` of their SHA-256 digests. `conftest.py` verifies every checksum before the first test runs and aborts the session with a clear `TAMPERED` message if any file has changed.
- **Forensic audit report** — every test run automatically generates `reports/forensic_audit.html`: a self-contained, printable HTML document structured by forensic category with intro text per section and a Reference Corpus table showing file names, SHA-256 hashes, and sizes. In CI the report is uploaded as the `forensic-test-report` artifact (90-day retention).

## [0.5.0] — 2026-04-25

### New Features

- **macOS support** — portable builds are now available for Apple Silicon (arm64). Nightly and release builds include a `crush-macos.tar.gz` artifact alongside the existing Linux and Windows builds. Running from source on macOS has always worked; this adds an official build and support badge.

### Performance

- **ZIP pre-scan** — file-type indexing now reads ZIP entries in physical storage order instead of alphabetical order, eliminating random seeks and significantly reducing scan time on large archives

### Improvements

- **Multi-Log Studio column filters** — added a persistent text-input row above the log table with one field per filterable column (Level, Process, PID, Subsystem, Category, Message); typing performs a live contains-match filter, complementing the existing right-click exact-value filter
- **Forensic Mode renamed to Integrity Mode** — the feature previously called "Forensic Mode" is now called "Integrity Mode" throughout the UI (status badge, Tools menu, tooltips, and log messages). Behaviour is unchanged; the new name better reflects that the feature is about integrity verification (hashing) rather than implying a specific legal or procedural context.
- **Nightly build identifier** — the build stamp shown in **Help → About** now includes the short commit SHA (e.g. `20260425-nightly-a3f9c12`) so nightly builds are precisely traceable.
- **About dialog** — added a direct link to the issue tracker; corrected CCL third-party attribution.
- **Bug reporting** — issue tracker link added to the README, user handbook, and About dialog.

### Documentation

- Added `CONTRIBUTING.md` with development setup, checks, and build process.
- Added `SECURITY.md` with vulnerability reporting instructions.
- JSON Viewer, XML Viewer, and LevelDB Viewer added to the README feature list (these viewers were already present but not documented).

## [0.4.1] — 2026-04-21

### Performance

- **File type indexing** — Multi-thread support for directories. Minimized the necessary unpacking of files for ZIP/Tar.
- **Apple Unified Log** — removed the hard 600-second subprocess timeout; large logarchives (1 GB+) no longer abort mid-conversion

## [0.4.0] — 2026-04-19

### New Features

- **Multi-Log Studio** — dedicated viewer for large and multi-source log analysis, replacing the old Log Viewer:
  - Load multiple log files simultaneously into a shared, merged timeline; each source is colour-coded and can be toggled on/off independently
  - Level toggles, free-text search (message, process, PID, subsystem, category), and time-range filter with calendar pickers
  - **Apple Unified Log support** — `.tra## [0.3.0] — 2026-04-03cev3` files and `.logarchive` bundles are parsed directly; extracts subsystem, category, event type, euid, and message entries; `lossEvent` gaps and Private/Sensitive entries are clearly annotated
  - **Column filters** — right-click any cell to pin an exact-match filter for that column; active filters shown as removable chips below the toolbar
  - **Custom format profiles** — define arbitrary log formats via a named-group regex with live preview; profiles saved and reloaded automatically
  - Background loading and sorting — the UI stays responsive at all times; a progress bar shows sort activity on large datasets
  - **Folder log discovery** — right-click a folder to open all recognised log files at once via a checklist dialog
- **Realm Database Viewer** — multi-tab viewer for `.realm` files: header decode, schema/class extraction, top-ref comparison, and table/column data decoding

### Improvements

- **Log Viewer retired** — replaced by Multi-Log Studio; "Open in Multi-Log Studio" is the new entry point for all log analysis
- **Hex viewer** — right-click a selection to copy as hex bytes or ASCII
- **BLOB Inspector** — same copy-as-hex / copy-as-ASCII actions available inside the inline hex view

### Fixes

- **Multi-Log Studio source bar** — adding a second source no longer causes the window to grow wider than the screen
- **SEGB v1 detection** — SEGB v1 files without a recognised extension are now auto-detected correctly
- **Realm format identification** — `.realm` files are now reliably identified by magic bytes
- **Magic-byte sniffing** — increased peek size to cover offset-based signatures beyond the first 16 bytes

## [0.3.0] — 2026-04-03

### New Features

- **Log Viewer** — open any file as structured logs with auto-detection (JSON Lines, logcat, syslog, timestamped, plain text), level/time/text filtering, timezone control, and a detail panel for full events (including multiline).
- **Protobuf Viewer** — explicit “Open as Protobuf Viewer” with schema-less wire decoding and optional schema-based decoding via `.proto` or descriptor sets.

### Improvements

- **Filesystem panel search overhaul** — flat results view, typed filters, context menu shortcuts, size sorting, type labels, and background type indexing with status spinner.
- **Forensic mode enhancements** — status badge toggle (with context menu), source hashing on ZIP/TAR/file open, and export hash manifests.
- **Tree viewer: expand/collapse all** — added toolbar buttons to expand or collapse the entire hierarchy at once.
- **Nightly builds** — automated prereleases plus build identifier display across the UI.
- **Format identification & reference** — magic-byte detection improvements and a curated, link-rich format reference.

### Fixes

- **Export: crash when re-exporting after a prior export** — export now safely handles a finished/cleared worker thread.

### Documentation

- User handbook updated with filter/search syntax, type indexing explanation, and forensic mode notes.

## [0.2.1] — 2026-03-25

### Fixes

- **Windows theme inversion** — menus and context menus were unreadable on Windows because the native Windows style partially ignores the application QPalette; the Fusion style is now applied on Windows so all palette colours are honoured correctly
- **SQLite viewer: numeric column sorting treated as string sort** — columns with integer or real values (including TEXT columns storing numeric strings) now sort numerically when clicking the column header
- **SQLite viewer: summary "Rows" column sorted as string** — row counts in the summary view now sort numerically
- **Properties panel: name and path not selectable** — file name and path labels now have text selection enabled; all property values can be marked and copied via right-click

## [0.2.0] — 2026-03-24 (updated)

### Fixes (post-release)

- **Portable build: `formats.db` not found** — corrected `--add-data` destination path in PyInstaller build and added `sys._MEIPASS` path resolution for frozen executables
- **Portable build: `libmagic` missing on Windows** — Windows build now installs `python-magic-bin` which bundles the required `magic1.dll`
- **About dialog unreadable in dark mode** — acknowledgements table now uses palette colours instead of hardcoded light-mode values
- **`MediaViewer` import failure on systems without PulseAudio** — guarded with `try/except ImportError`; app starts cleanly without audio support

### New Features

- **TAR archive support** — open `.tar`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tar.xz` acquisitions directly
- **PDF viewer** — extracts and displays text content; falls back to hex if pypdf is not installed
- **EXIF metadata** — camera make/model, GPS coordinates, timestamp, ISO, aperture extracted from JPEG/TIFF/PNG images and shown in the Properties panel
- **Artifact chaining** — SQLite BLOB cells can be opened as a new viewer tab (right-click → Open as new tab), enabling inspection of embedded plists, images, and other binary data
- **Format Knowledge Base** — bundled `formats.db` identifies 33 forensic file formats by magic bytes and extension; format name, platforms, and forensic relevance shown in the Properties panel for every opened file, including unsupported formats
- **Format Info popup** — right-click any file → Show Format Info for an instant format summary without opening a viewer tab
- **Help → Format Reference** — searchable table of all known formats with reference links
- **Hex viewer pagination** — navigate files larger than 256 KB with Prev/Next page buttons; search now jumps to the correct page automatically
- **Text viewer encoding detection** — automatically detects UTF-8, UTF-16 LE/BE (with and without BOM); detected encoding shown in toolbar
- **SQLite WAL/SHM support** — companion `-wal` and `-shm` files are automatically included when opening a database, providing the most current view of the data
- **SQLite row limit notice** — tables truncated at the display limit show a clear notice; full data accessible via SQL query

### Improvements

- Properties panel always shows all four MACB timestamp fields; unavailable fields (e.g. from ZIP/TAR sources) display `—` with an explanatory note
- Per-table and per-record error handling in SQLite, plist, SEGB, and LevelDB parsers — partial results shown instead of crashes on malformed data
- LevelDB parser now correctly cleans up temporary files after parsing
- Hex fallback parser identifies unknown formats by magic bytes and surfaces forensic context

### Documentation

- `crush/docs/handbook.md` — user handbook covering all features and forensic workflow tips
- `crush/admin/format_knowledge_base.md` — admin guide for maintaining the format knowledge base
