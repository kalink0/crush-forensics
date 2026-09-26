## Filesystem Panel

The left panel shows the loaded archive or folder as a tree.

- **Double-click** a file to open it in a viewer tab
- **Single-click** selects a file and updates the Properties panel
- **Right-click** a file or folder for options:
  - **Open** — best viewer for the format
  - **Open in New Window** — loads the file into a fresh Crush window without affecting the current session. Works for any file, including ones nested inside an already-open ZIP/TAR/7z/gzip archive, Android/iTunes backup, or raw disk image/EWF acquisition — the file is extracted to the [temp directory](opening-evidence.md#large-files-memory-and-the-temp-directory) for the new window, behind a progress dialog with **Cancel** (free space is checked first). The new window's title names where it came from, and its temp copy is deleted when that window closes. A ZIP that follows other data in a file (a self-extracting executable, a ZIP appended to an image) is only noted in the status bar when the file itself is opened; **Open in New Window** opens that ZIP
  - **Open Disk Image in New Window** — the same, but reads the file as a disk image (see [Raw Disk Images & EWF Acquisitions](raw-disk-images-ewf-acquisitions.md)); the only way to open a disk image that sits inside an opened folder, archive or image.
  - **Open as** — submenu to force a specific viewer regardless of auto-detection:
    - **Hex** — force raw hex view
    - **Text** — force text view
    - **Protobuf** — schema-less Protobuf decode (optionally load a `.proto` schema)
    - **MMKV** — open a Tencent MMKV key-value store. MMKV has no magic bytes at all, so — unlike every other format — it can never be auto-detected from content; this is the only way to open one
    - **Realm DB (Encrypted)…** — decrypt and open a Realm database given its 64-byte encryption key (as a hex string). This is the only way to open an encrypted `.realm` file — a normal double-click never prompts for a key, since a header that fails to decode is equally consistent with "encrypted" and "corrupt/non-standard" and can't be told apart from content alone
    - **SQLite DB (Encrypted)…** — open a SQLCipher-encrypted SQLite database given its password or raw key, with optional advanced cipher parameters. Same no-auto-prompt rule as Realm above
    - **PDF (Encrypted)…** — open a password-protected PDF; a wrong password re-prompts instead of failing silently. Same no-auto-prompt rule as Realm above
    - **MMKV (Encrypted)…** — decrypt and open an AES-CFB-encrypted MMKV store, given the key as text or hex, and AES-128/256. An MMKV store's encryption status comes from its `.crc` meta file's AES vector (a non-zero vector is cross-checked against a plaintext read before it is believed), so a wrong key re-prompts rather than the tool guessing "encrypted vs. corrupt". A key given for a store that isn't encrypted is ignored, and the metadata says so rather than claiming it was decrypted
  - **Open in Multi-Log Studio** — structured log viewer with level/time/text filtering and multi-source support
  - **Add to Multi-Log Studio** — adds the file as an additional source to the currently open studio tab
  - **Open External (Default)** — hand off to the OS default application
  - **Open External (Choose App…)** — pick an application
  - **Show Format Info** — opens a popup showing the identified format name, category, platforms, parser support status, and forensic relevance. For known formats an **Open Reference…** button links to the format specification. Also updates the Properties panel. Works for unsupported formats — useful for quickly understanding what a file is before deciding how to examine it
  - **Export…** — extract the file or folder to disk

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

Multiple tokens are always AND-combined. The `type:` token matches against the format label in the Type column, which is detected from file content (magic bytes) — not from the file extension. This means a HEIC image named `photo.jpeg` will still match `type:heic`.

**Interacting with results**

- **Double-click a file** — opens it directly in a viewer tab
- **Double-click a folder** — clears the filter and navigates the tree to that folder, expanding and selecting it automatically
- **Single-click** — selects the item and updates the Properties panel
- **Right-click** — same context menu as the tree (Open, Hex, Export, etc.)

**Type indexing**

When an archive or folder is opened, Crush starts a background type scan that reads the first bytes of every file to detect its format. While this is running, a spinner and `Indexing types` message appear in the status bar. Once complete, `type:` searches are instant. The scan typically takes a few seconds to a minute depending on archive size — for a 45 GB archive with 162,000 files, expect around 10 seconds.

---

