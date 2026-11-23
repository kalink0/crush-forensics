## Filesystem Panel

The left panel shows the loaded archive or folder as a tree.

- **Double-click** a file to open it in a viewer tab
- **Single-click** selects a file and updates the Properties panel
- **Right-click** a file or folder for options:
  - **Open** — best viewer for the format
  - **Open in New Window** — loads the file into a fresh Crush window without affecting the current session. Works for any file, including ones nested inside an already-open ZIP/TAR/7z/gzip archive, Android/iTunes backup, or raw disk image/EWF acquisition — the file is extracted to the [temp directory](opening-evidence.md#large-files-memory-and-the-temp-directory) for the new window, behind a progress dialog with **Cancel** (free space is checked first). The new window's title names where it came from, and its temp copy is deleted when that window closes. A ZIP that follows other data in a file (a self-extracting executable, a ZIP appended to an image) is only noted in the status bar when the file itself is opened; **Open in New Window** opens that ZIP
  - **Open Disk Image in New Window** — the same, but reads the file as a disk image (see [Raw Disk Images & Forensic Acquisitions](raw-disk-images-ewf-acquisitions.md)); the only way to open a disk image that sits inside an opened folder, archive or image.
  - **Open as** — submenu to force a specific viewer regardless of auto-detection:
    - **Hex** — force raw hex view
    - **Text** — force text view
    - **Protobuf** — schema-less Protobuf decode (optionally load a `.proto` schema)
    - **FlatBuffers** — schema-less FlatBuffers decode (optionally load a `.fbs` or `.bfbs` schema)
    - **MMKV** — open a Tencent MMKV key-value store. MMKV has no magic bytes at all, so — unlike every other format — it can never be auto-detected from content; this is the only way to open one
    - **Realm DB (Encrypted)…** — decrypt and open a Realm database given its 64-byte encryption key (as a hex string). This is the only way to open an encrypted `.realm` file — a normal double-click never prompts for a key, since a header that fails to decode is equally consistent with "encrypted" and "corrupt/non-standard" and can't be told apart from content alone
    - **SQLite DB (Encrypted)…** — open a SQLCipher-encrypted SQLite database given its password or raw key, with optional advanced cipher parameters. Same no-auto-prompt rule as Realm above
    - **PDF (Encrypted)…** — open a password-protected PDF; a wrong password re-prompts instead of failing silently. Same no-auto-prompt rule as Realm above
    - **MMKV (Encrypted)…** — decrypt and open an AES-CFB-encrypted MMKV store, given the key as text or hex, and AES-128/256. An MMKV store's encryption status comes from its `.crc` meta file's AES vector (a non-zero vector is cross-checked against a plaintext read before it is believed), so a wrong key re-prompts rather than the tool guessing "encrypted vs. corrupt". A key given for a store that isn't encrypted is ignored, and the metadata says so rather than claiming it was decrypted
  - **Open in Multi-Log Studio** — structured log viewer with level/time/text filtering and multi-source support
  - **Add to Multi-Log Studio** — adds the file as an additional source to the currently open studio tab
  - **Open External (Default)** — hand off to the OS default application
  - **Open External (Choose App…)** — pick an application
  - **Show Format Info** — opens a popup showing the identified format name, category, platforms, parser support status, signatures, forensic relevance, reference links (opened in your browser) and the date of the last review. When the signatures match several formats equally, it lists those candidates instead of picking one. Also updates the Properties panel. Works for unsupported formats — useful for quickly understanding what a file is before deciding how to examine it
  - **Compute Hash** — submenu: **MD5**, **SHA-1**, **SHA-256** or **All** (all three in one read pass). Hashes the file, or every file in the folder and its subfolders, over its content as Crush reads it — for an archive member, its unpacked content; the same bytes the [integrity](integrity-mode.md) hashes cover. Runs behind a progress dialog with **Cancel**. The result lists each file with its source (what it was opened from — paths are within it), its path, the bytes read, the hashes, the result and its entry status; a file that couldn't be read is listed with the reason, a file whose entry status says no content is read or stored (a special file, a link whose target isn't decoded, an entry with no content in a backup …) is listed as **Not hashed: no content read** rather than with the hash of no bytes, a folder with an entry status (e.g. one that couldn't be listed) is listed too, and a cancelled run says the list is incomplete. **Copy All** and **Save As…** (CSV or tab-separated text, with that summary on top) take the whole list; right-clicking a cell offers **Copy cell** (its full text, e.g. one hash), **Copy row (TSV)** and **Copy selection (TSV)**, as in the table viewers. Every value is also written to the log and shown in the [Properties panel](properties-panel.md) while the source is open. Right-clicking inside a selection of two or more entries — files, folders or both — offers **Compute Hash of N selected entries** for all of them (folders all the way down)
  - **Export…** — extract the file or folder to disk

**Column widths:** the **Name** column widens to fit the names shown as folders are expanded, scrolled or the panel is resized — up to the room the other columns leave, so Size, Files, Total Size and Type stay in view; widen the panel to give it more. It doesn't shrink again when a folder is collapsed. A name that still doesn't fit is shortened in the middle (`IMG_2024…_edited.jpg.exe`), so its start and extension stay visible; the full name is in the tooltip. Dragging the column by hand turns the automatic width off until the next source is loaded. The search results list does the same for **Name** and **Path**.

**iOS container folders:** iOS names the folders of apps, app groups, extensions and system containers by a GUID. A folder that directly holds a `.com.apple.mobile_container_manager.metadata.plist` is shown by the identifier of its owner from that plist (`MCMMetadataIdentifier`, e.g. `com.apple.mobilesafari`), wherever the folder is. The identifier is shown in italics, as it is not the folder's name; the tooltip shows the GUID folder name. A folder whose plist can't be read or holds no identifier keeps its GUID name, and the [Properties panel](properties-panel.md) says why. Paths, **Copy Path**, **Copy File Name** and exports keep the GUID folder name. The filter finds a container folder by either name. **View → Show iOS Container Identifiers** (on by default, remembered) switches back to the GUID names.

**Filtering:** type in the filter box at the top of the panel to search across the entire loaded tree. All searches are case-insensitive and match anywhere in the value.

While the filter is active, the tree is replaced by a **flat search results list** showing every match with its full path — no need to navigate through parent folders. Clear the filter (or click the **×** button) to return to the normal tree.

**Search syntax**

| Input | Behaviour |
|---|---|
| `rubin` | Plain text — matches all files and folders whose name contains `rubin` |
| `name:rubin` | Explicit name filter — identical to plain text |
| `type:sqlite` | Matches all files whose detected type is SQLite (by magic bytes, regardless of extension) |
| `type:image` | Matches **all** image files — JPEG, PNG, HEIC, HEIF, AVIF, JXL, WebP, TIFF, GIF, BMP |
| `type:heic` | Matches only files identified as HEIC containers — including those with a `.mp4` or `.jpeg` extension |
| `type:avif` | Matches AVIF image files |
| `type:jxl` | Matches JPEG XL image files |
| `type:media` | Matches **all** audio and video files — MP4, MOV, MP3, WAV, OGG, Opus, and more |
| `type:opus` | Matches Opus voice notes (WhatsApp `.opus`, Telegram `.ogg`) detected by codec header |
| `type:ogg` | Matches OGG Vorbis audio files |
| `name:rubin type:sqlite` | AND — only files whose name contains `rubin` **and** whose type is SQLite |
| `hash:2c1743a391305fbf367df8e4f069f9f9` | Files with this hash among those already computed in this window — the length says the algorithm: 32 hex digits MD5, 40 SHA-1, 64 SHA-256 |
| `hash:2c17` | Shorter: files with a computed hash (any algorithm) that starts with `2c17` |

Multiple tokens are always AND-combined. The `type:` token matches against the format label in the Type column, which is detected from file content (magic bytes) — not from the file extension. This means a HEIC image named `photo.jpeg` will still match `type:heic`.

The `hash:` token matches only hashes already computed in this window — by **Compute Hash**, or the SHA-256 of [integrity mode](integrity-mode.md) — every value of an entry, including a differing later one; the filter itself hashes nothing. It is case-insensitive and lists files only. With every `hash:` search, a line above the results says what it was matched against, e.g. `Matched against computed MD5 hashes: 1,204 of 12,500 files have one — files without one can't match.` (the files counted are those the other filter terms let through). A file without a computed hash — never hashed, unreadable, or with no content read — is counted there and never treated as not matching. `-hash:` (negation) is not supported, as a file without a computed hash would read as not matching; it lists nothing and says so, as does a value that isn't hexadecimal or is longer than 64 digits.

**Interacting with results**

- **Double-click a file** — opens it directly in a viewer tab
- **Double-click a folder** — clears the filter and navigates the tree to that folder, expanding and selecting it automatically
- **Single-click** — selects the item and updates the Properties panel
- **Right-click** — same context menu as the tree (Open, Hex, Export, etc.)

**Type indexing**

When an archive or folder is opened, Crush starts a background type scan that reads the first bytes of every file to detect its format. While this is running, a spinner and `Indexing types` message appear in the status bar, with how many files are indexed of all there are to index (e.g. `Indexing types 1,500 / 40,000`). Once complete, `type:` searches are instant. The scan typically takes a few seconds to a minute depending on archive size — for a 45 GB archive with 162,000 files, expect around 10 seconds. The small stop button beside the message stops the scan; the status bar then says `Type indexing stopped: 1,500 of 40,000 files` until the play button in the same place resumes it (types already found are kept). While it is stopped, the **Type** column of the rows shown still gets filled in, file by file, and a `type:` search reads the types it needs itself, so it stays complete, only slower.

---

