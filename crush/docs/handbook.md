# Crush — User Handbook

## What is Crush?

Crush is a Digital Forensic Analysis Workbench for examining iOS and Android acquisitions. It lets you open archives (ZIP, TAR, 7z), folders, and individual files, then navigate and inspect their contents using format-aware viewers — without extracting anything to disk first.

Crush includes a built-in **file format database** covering forensically relevant formats across iOS and Android. For every file you select or open, Crush identifies the format by magic bytes (not by extension), then shows its name, platform, forensic relevance, and a link to the format specification — even for formats that have no dedicated viewer yet. The database is a work in progress — more formats and references will be added over time.

---

## Opening Evidence

Use the **File** menu to load a source:

| Menu item | When to use |
|---|---|
| **Open file…** | Any single file — image, database, plist, ZIP, TAR, 7z, etc. Crush detects the type automatically. ZIP, TAR, and 7z archives are opened as browsable trees; other files open directly in a viewer tab. |
| **Open folder…** | Already-extracted acquisition or any folder of files on disk |

Opening a file (**Open file…**) appends it to the existing tree as a new root node, so multiple files can be open side by side. Opening a folder replaces the current tree.

---

## The Interface

```
┌─────────────────┬──────────────────────────────────┬───────────────┐
│  Filesystem     │         Viewer tabs               │  Properties   │
│  panel (left)   │                                   │  panel (right)│
│                 │                                   │               │
│                 │                                   │               │
└─────────────────┴──────────────────────────────────┴───────────────┘
│  Log panel (bottom, hidden by default)                              │
└─────────────────────────────────────────────────────────────────────┘
```

All panels are dockable and can be floated, resized, or hidden via **View** menu. Use **View → Reset Panel Layout** to restore defaults.

---

## Themes

Choose a colour theme under **View → Theme**. The selection persists across sessions.

| Theme | Description |
|---|---|
| **Light** | Default light palette |
| **Dark** | Default dark palette |
| **Geek** | Phosphor-green on black — terminal aesthetic |
| **Purple** | Synthwave lavender on deep purple |
| **Ocean** | Cyan on deep navy |
| **Rainbow** | Animates the full colour spectrum continuously |
| **'Merica** | Opens with a brief red-white-blue U-S-A show, then holds and fades between patriotic colours; use the status-bar button to replay the show |

**Custom theme snapshot:** while Rainbow is running, a *⏸ Snapshot* button appears in the status bar. Click it to pause the animation, enter a name, and save the current hue as a named custom theme entry in *View → Theme*. The saved theme persists across restarts.

---

## Filesystem Panel

The left panel shows the loaded archive or folder as a tree.

- **Double-click** a file to open it in a viewer tab
- **Single-click** selects a file and updates the Properties panel
- **Right-click** a file or folder for options:
  - **Open** — best viewer for the format
  - **Open in New Window** — loads the file into a fresh Crush window without affecting the current session. Works for any file, including ones nested inside an already-open ZIP/TAR/7z archive — the file is transparently extracted to a temp location for the new window
  - **Open in Hex** — force raw hex view
  - **Open as Plain Text** — force text view
  - **Open in Multi-Log Studio** — structured log viewer with level/time/text filtering and multi-source support
  - **Add to Multi-Log Studio** — adds the file as an additional source to the currently open studio tab
  - **Open as Protobuf Viewer** — schema-less Protobuf decode (optionally load a `.proto` schema)
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

## Viewer Tabs

Each opened file gets its own tab. Tabs can be:
- Closed with the **×** button or middle-click
- Kept open while you navigate elsewhere — useful for comparing files
- Closed all at once via **View → Close all tabs**

### SQLite / Database Viewer

The table dropdown at the top switches between database tables, views, and four generated analysis pages. All generated entries are labelled `(generated)` to make clear they are computed by Crush rather than read directly from the database.

#### Generated views

**Summary (generated)** — the default view when a database is opened. Lists every table and view with its row count. The status line shows the full schema object count (tables, views, indexes, triggers) at a glance. Double-click any row to navigate directly to that table.

**DB Structure (generated)** — lists all schema objects (tables, views, indexes, triggers) with structural details:

| Object type | Info column |
|---|---|
| Table | Column list, e.g. `(id, name, created_at)` |
| View | Full `CREATE VIEW` SQL on one line |
| Index | `ON table (column, …)` — shows which table and columns are indexed |
| Trigger | First line of `CREATE TRIGGER …` |

**DB Info (generated)** — shows 28 PRAGMA settings in a three-column layout (Setting / Value / Description), styled after the *Edit Pragma* view of DB Browser for SQLite. Enum values are decoded to their named constant (e.g. `2 — FULL` for `auto_vacuum`), booleans show as `1 — ON` / `0 — OFF`. When a WAL companion is present, six WAL forensic metrics appear at the top of this view before the PRAGMA list (see *WAL forensic analysis* below).

**WAL Frames (generated)** — appears when a `-wal` companion file is present. Shows a full frame inventory (Frame / Page / Transaction / Status / Table / Offset) with every frame classified by forensic status:

| Status | Colour | Meaning |
|---|---|---|
| **Active** | Default | Newest occurrence of this page within the last committed transaction — what SQLite currently reads |
| **Superseded** | Amber | An older version of a page that was later overwritten by a newer frame; may contain previously committed data |
| **Uncommitted** | Blue | Frames beyond the last commit marker, written during an incomplete transaction |
| **WAL slack** | Grey | Salt-mismatch frames from a previous WAL generation cycle (Sanderson's term); these pages predate the current WAL cycle and are not read by SQLite |

The **Table** column shows which database table owns each page, resolved by tracing the B-tree structure from `sqlite_master`. Double-click any frame row to open its raw page bytes in the hex viewer, labelled `WAL frame N — page M`.

#### WAL forensic analysis

When a `-wal` companion is present, Crush automatically reads and classifies every WAL frame. This gives the examiner three complementary views of any past database state:

1. **DB Info WAL summary** — six metrics (WAL file size, total frames, active / superseded / uncommitted / WAL-slack counts) with amber and blue highlights on non-zero forensic counts.
2. **WAL Frames inventory** — full frame list with table attribution and double-click raw page access (see above).
3. **Show WAL history toggle** — a **Show WAL history** checkbox appears in the table toolbar whenever the currently selected table has Superseded, Uncommitted, or WAL-slack frames in the WAL. When enabled:
   - A **WAL Source** column is added to the right of the table.
   - Rows decoded from historical WAL frames are appended below the current data, with the WAL Source cell identifying the frame status and frame number (e.g. `WAL Superseded (frame 3)`).
   - Row text is colour-coded: amber for Superseded, blue for Uncommitted, grey for WAL slack.
   - The row count label shows how many additional rows were recovered, e.g. `(42 rows)  +7 from WAL`.

This lets you answer questions such as: *what rows existed in this table before the last UPDATE or DELETE?* — without any specialist carving tool.

> **Tip:** An empty WAL history for a table does not mean the data was never modified — it only means there are no current non-Active frames for that table's pages. For a complete picture, also check the Superseded and Uncommitted counts in DB Info.

#### SQL bar

The SQL bar below the toolbar accepts any `SELECT`, `WITH`, or `PRAGMA` statement.

| Action | How |
|---|---|
| Execute query | Click **Run** or press **F5** |
| Execute selected text only | Highlight a fragment in the SQL editor and press **F5** or click **Run** — only the selection is sent |
| Syntax highlighting | Keywords, strings, numbers, and comments are highlighted; colours adapt to the active light/dark theme |
| Autocomplete | Press **Tab** or **Ctrl+Space** — table and view names are suggested after `FROM`/`JOIN`; column names are suggested after `table.` dot notation; aliases are resolved automatically |
| Resize SQL vs. results | Drag the splitter between the SQL editor and the results table |

Status feedback appears below the input field: red on error (with the error message), default colour on success.

#### Table controls

| Control | Action |
|---|---|
| **Table** dropdown | Switch between tables, views, and generated pages |
| **Search** field | Filter visible rows — matches any column |
| **Show WAL history** | Reveal historical rows from WAL frames (shown only when WAL data is available for the current table) |
| **Run / F5** | Execute the SQL query |
| **Export CSV…** | Export the current view (filtered or query result) to a CSV file |

**Row limit notice:** if a table has more rows than the display limit, a notice appears in the row count. Use a SQL query with `LIMIT` / `WHERE` to load a specific subset.

**Timestamp column decoding:** right-click any column header to decode integer/real values as timestamps. Choose a format from the **Decode column as timestamp** submenu:

| Format | Epoch | Unit |
|---|---|---|
| Unix — seconds | 1970-01-01 | s |
| Unix — milliseconds | 1970-01-01 | ms |
| Unix — microseconds | 1970-01-01 | µs |
| Mac Absolute Time | 2001-01-01 | s |
| Windows FILETIME | 1601-01-01 | 100 ns |
| Chrome / WebKit | 1601-01-01 | µs |

Values are displayed as `YYYY-MM-DD HH:MM:SS UTC`. The column header shows the active format as a suffix (e.g. `created_at [unix ms]`). Sorting remains chronologically correct. Select **Clear timestamp format** to revert to the raw values.

**Cell inspection:** right-click any cell for options including:
- **Inspect Cell…** — preview the raw value, attempt base64/plist/XML decode
- **Open in Hex** — view cell bytes as hex
- **Open as new tab** — parse a BLOB cell as a new artifact (e.g. a plist stored inside a SQLite column)
- **Export…** — save the cell value to disk
- **Copy cell / Copy row / Copy selection**

### Hex Viewer

Displays raw bytes as offset + hex + ASCII. 256 KB is shown per page.

| Control | Action |
|---|---|
| **◀ Prev / Next ▶** | Navigate pages for files larger than 256 KB |
| **Page N / M** | Shows current position and total pages |
| **Search as:** dropdown | Choose between **ASCII** (text string) and **Hex** (byte pattern, e.g. `FF D8 FF`) |
| **Find** button / Enter | Run search — collects all matches, jumps to first hit. All matches are highlighted in yellow, the current match in orange. |
| **↑ / ↓** | Navigate to previous / next match |
| **N / M** counter | Shows current match position and total count |
| **Show all** | Toggle a result panel below showing every match with its offset, hex bytes, and ASCII preview. Click a row to jump to it. |
| **Copy Hex** | Copy current page as space-separated hex bytes |
| **Copy ASCII** | Copy current page as ASCII (non-printable → `.`) |

**Right-click on a selection:**
- **Search Selected as ASCII** — uses the bytes covered by the selection as a text search pattern
- **Search Selected as Hex** — uses the same bytes as a hex byte-pattern search
- **Copy Selected Hex / ASCII** — copies only the selected region

### Text Viewer

Displays text files with line numbers, syntax highlighting, and search.

**Encoding detection** is automatic — the detected encoding is shown in the top-right corner of the toolbar. Supported: UTF-8, UTF-8 BOM, UTF-16 LE, UTF-16 BE, and UTF-16 LE without BOM (common in iOS preference files).

**Highlighting** is applied automatically based on content. You can override it with the **Highlight** dropdown: JSON, XML, SQL, INI/CONF, YAML, LOG, CSV, or None.

**Search:**
- Type in the search bar — matches are highlighted inline as you type
- Press Enter or **Down** to jump to the next hit; **Up** for the previous
- The match counter shows the total number of hits
- Enable **Regex** for regular expression patterns
- Enable **Case** for case-sensitive matching
- `*` wildcard is supported in non-regex mode
- **Show all** opens a result panel listing every match with its line, column, and a line preview — click a row to jump to it

### Image Viewer

Displays JPEG, PNG, GIF, BMP, WebP, TIFF, HEIC, HEIF, AVIF, and JPEG XL images. EXIF metadata (camera make/model, GPS coordinates, timestamp, ISO, aperture) is shown in the Properties panel when available.

> **Forensic note — HEIC/HEIF:** Common on iOS devices (default since iOS 11). A file labelled `HEIC` in the filesystem panel is identified by its ISOBMFF `ftyp` container brand — not by its extension. A `.mp4` or `.jpeg` file can be a HEIC container; Crush will detect and display it correctly regardless. Use `type:heic` in the filter field to find all HEIC files across an acquisition, including any with misleading extensions.
>
> **Current limitation:** HEIC/HEIF is a container format and can hold multiple images in a single file — burst frames, HDR primary + gain map, depth maps, and Live Photo previews. Crush currently displays only the primary image. Embedded secondary images (depth maps, HDR layers, burst frames) are not yet accessible.
>
> **Forensic note — AVIF:** Used by social media platforms (Netflix, YouTube, Discord) and increasingly on Android and modern browsers. AVIF files downloaded from social platforms frequently have EXIF metadata stripped server-side — the absence of GPS or device metadata in an AVIF is therefore a provenance indicator rather than a sign of camera origin. Like HEIC, AVIF is detected from the ISOBMFF `ftyp` brand (`avif` or `avis`), so `type:avif` finds AVIF content regardless of file extension.

### Media Viewer

Plays audio and video files (MP4, MOV, MP3, M4A, AAC, WAV, etc.) using the system multimedia backend.

### Plist / Tree Viewer

Displays binary and XML property lists as a collapsible tree. Supports nested structures including arrays, dictionaries, data blobs, dates, and NSKeyedArchiver objects.

### JSON Viewer

Displays JSON files as a collapsible, searchable tree. Arrays and objects can be expanded or collapsed individually. Copy a node value via right-click.

### XML Viewer

Parses XML into a collapsible tree. Android `<map>`-style preference files are flattened for easier reading. Malformed XML shows an error node rather than crashing.

### PDF Viewer

Extracts and displays the text content of PDF files in the Text Viewer. Scanned or protected PDFs with no extractable text show a notice.

### LevelDB Viewer

Opens LevelDB database directories (used by Chrome, Android apps, and iOS apps) in a tabbed viewer.

**Overview tab** — MANIFEST metadata for the database:
- All `MANIFEST-*` files in the directory are parsed; the active one (pointed to by `CURRENT`) is labelled *(current)*. Older manifests expose compaction history from before the last recovery and may reference file numbers no longer on disk.
- Comparator name, last sequence number, log number, and prev log number (when present).
- Files grouped by compaction level.

**Files tab** — one row per data file (`.ldb` / `.sst`) and WAL log file:

| Column | Content |
|---|---|
| Filename | File name in the database directory |
| Type | `Ldb` / `Log` |
| Level | Compaction level (data files only) |
| Size (B) | On-disk size from the MANIFEST (`—` for log files) |
| Smallest Key / Largest Key | Inclusive key-range boundaries decoded as UTF-8 or hex |
| Live / Deleted / Unknown | Record counts; rows with deleted records are highlighted red |

**Records tab** — all records across all files in a single table. Deleted records are shown inline in red alongside live records so the examiner sees the full write history.

| Column | Content |
|---|---|
| File | Source file |
| Seq | LevelDB sequence number |
| Type | `Live`, `Deleted`, or `Unknown` |
| Offset | Byte offset of the record within the source file (hex) |
| User Key (text) / (hex) | Key decoded as UTF-8 and as hex |
| Value (text) / (hex) | Value decoded as UTF-8 and as hex |
| Internal Key (hex) | Full internal key (user key + 8-byte sequence/type suffix) for `.ldb`/`.sst` records |

Toolbar controls:

| Control | Action |
|---|---|
| **All / Live / Deleted / Unknown** | Filter records by state |
| **Search** | Case-insensitive filter across all columns; combines with the state filter |
| **Export CSV…** | Save currently visible rows to a UTF-8 CSV file; includes full-length hex columns and the Internal Key |

Selecting a row feeds the raw bytes into a tabbed *Key* / *Value* hex pane below the table. A third *Internal Key* tab shows the full internal key for `.ldb`/`.sst` records.

Right-click any record row to open the [BLOB Inspector](#blob-inspector) for the key, value, or internal key of that record.

**LOG tabs** — if `LOG` or `LOG.old` files exist in the directory, each gets a dedicated read-only tab showing the complete file content with a *Find* toolbar.

### BLOB Inspector

The BLOB Inspector is a shared decode dialog for examining raw binary fields. It opens as a non-modal window — the rest of the UI stays fully accessible and multiple inspector windows can be open at the same time.

**How to open it:**
- **SQLite viewer** — right-click any cell → **Inspect Cell…**
- **LevelDB viewer** — right-click any record row → **Inspect Key…**, **Inspect Value…**, or **Inspect Internal Key…**
- **Realm viewer** — right-click any freed block in the Freed Data tab → **Inspect Block…**
- **Tools → Paste & Decode…** — paste hex, base64, or text directly into the inspector without a source file

---

#### Layout — three columns

| Column | Purpose |
|---|---|
| **Decode pipeline** (left) | Chain of byte→byte transform steps applied before interpretation. Click **＋ Add step** to append a step; click **×** to remove one. Steps run top-to-bottom; if a step fails the pipeline stops there and the error is shown inline. |
| **Interpretations** (middle) | All available display formats for the bytes produced by the pipeline, grouped by confidence. Click any entry to switch the content view instantly — no second click needed. |
| **Content view** (right) | The rendered output for the selected interpretation. **Copy** copies the full content to the clipboard. Right-click in hex view for per-selection copy options. |

---

#### Decode pipeline steps

Pipeline steps are byte→byte transforms that pre-process the raw bytes before the interpretations are evaluated. Steps are chained: the output of step 1 is the input of step 2, and so on. The byte count after each step is shown inline.

| Step | What it does | Typical source |
|---|---|---|
| **Base64 (decode)** | Decodes standard Base64 with `+`/`/` charset and `=` padding | iOS/Android SQLite BLOBs, email attachments |
| **Base64url (decode)** | Decodes URL-safe Base64 with `-`/`_` charset; padding optional | JWT payloads, web API tokens, OAuth parameters |
| **Hex → Bytes** | Converts hex strings with any separator (space, colon, none) to raw bytes | Database hex columns, copy-pasted hex dumps |
| **zlib decompress** | Decompresses zlib data (deflate stream with zlib header, `0x78 …`) | Chrome LevelDB values, iOS WebKit caches |
| **gzip decompress** | Decompresses gzip data (magic `1f 8b`) | HTTP response bodies, server-side log archives |
| **lzfse decompress** | Decompresses Apple LZFSE data (magic `bvx2` / `bvxn` / `bvxx`) | iOS backups, iCloud sync blobs, macOS system caches, APFS metadata |

Steps can be combined freely. To decode a value that is Base64url-encoded and then lzfse-compressed, add **Base64url** as step 1 and **lzfse decompress** as step 2.

---

#### Interpretations

After the pipeline runs, the resulting bytes are tested against all available interpretations. The list is grouped into three tiers:

| Marker | Meaning |
|---|---|
| *(no marker)* | **Hex view** — always available as the baseline |
| **✓** | Confident — format positively identified (magic bytes, strict parse, valid structure) |
| **~** | Permissive — format almost always succeeds regardless of content; treat as a fallback, not a confirmation |
| *(gray, no marker)* | Failed — bytes did not match this format |

**Available interpretations:**

| Interpretation | Tier | Notes |
|---|---|---|
| **Hex view** | baseline | Annotated hex dump with address / hex / ASCII columns |
| **UTF-8 text** | ✓ | Only ✓ when all bytes are valid UTF-8; strict decode |
| **JSON** | ✓ | Pretty-prints valid JSON; also detects escaped JSON embedded in a string |
| **Plist / bplist** | ✓ | Decodes binary (`bplist00`) or XML property list. NSKeyedArchiver payloads are automatically deserialised and the object graph is rendered as a Python pprint |
| **XML** | ✓ | Parses and pretty-prints well-formed XML (via lxml) |
| **Android Binary XML (ABX)** | ✓ | Reconstructs XML from Android's compact binary XML format |
| **Image** | ✓ | Renders the image inline — PNG, JPEG, GIF, BMP, WebP, HEIC, AVIF |
| **Protobuf (schema-less)** | ~ | Wire-format decode. Numeric fields include `# label: value` hints for int64, sint64 (zigzag), bool, Unix/Cocoa/Chrome timestamps, double, and float; a field shown as a nested message also gets a `# raw bytes: ...` hint, since wire type 2 doesn't actually declare whether the bytes are a submessage. A `# Warning:` header appears if the parse was truncated or malformed. Shown as **~** because Protobuf's wire format accepts most byte sequences. |
| **Latin-1 text** | ~ | ISO-8859-1 — always succeeds since every byte is a valid Latin-1 character; useful as a last resort for mixed binary/text data |

**Auto-selection:** when the inspector opens or the pipeline changes, the best ✓-tier interpretation is selected automatically. If the previously selected format still produces output after a pipeline change, the selection is preserved.

---

#### Forensic examples

**iOS app database — Base64-encoded binary plist**

Many iOS apps store serialised objects as Base64-encoded bplist BLOBs in SQLite. To inspect:
1. Right-click the cell → *Inspect Cell…*
2. Add step: **Base64 (decode)**
3. The Interpretations list shows **✓ Plist / bplist** — click it to read the deserialised object graph, including NSKeyedArchiver structures.

**JWT / OAuth token stored in a database**

Web-facing apps (and some native apps) store JWT tokens in SQLite. The token payload is the second dot-separated segment, Base64url-encoded without padding:
1. Copy the middle segment (between the first and second `.`)
2. Open *Tools → Paste & Decode…*, paste the segment
3. Set *Input encoding* to **Auto** (it recognises Base64url) or force **Base64**
4. Add step: **Base64url (decode)** — the payload JSON appears in the Interpretations list.

**iOS backup / iCloud sync blob — lzfse-compressed plist**

Apple uses LZFSE compression extensively in iOS backups, iCloud sync metadata, and macOS system caches. The magic bytes `62 76 78 32` (`bvx2`) identify lzfse data:
1. Right-click the cell → *Inspect Cell…*
2. Add step: **lzfse decompress**
3. If the decompressed result is a plist, **✓ Plist / bplist** appears automatically.

**Multi-layer encoding (Base64url → lzfse → JSON)**

Some modern mobile backends layer encodings. Add steps in order and the pipeline resolves them one by one:
1. Add **Base64url (decode)** — converts the token to compressed bytes
2. Add **lzfse decompress** — decompresses to JSON
3. Click **✓ JSON** to read the payload

**Protobuf inside a bplist**

iOS apps sometimes store Protobuf bytes as a `<data>` field inside an NSKeyedArchiver bplist:
1. Add step: **Base64 (decode)** if the outer BLOB is Base64-encoded
2. Select **✓ Plist / bplist** — the NSKeyedArchiver is deserialised; note the field that holds raw bytes
3. To inspect the inner Protobuf, copy its hex from the plist view, open a new inspector via *Paste & Decode…*, add **Hex → Bytes**, then select **~ Protobuf (schema-less)**.

### ABX Viewer

Decodes Android Binary XML (ABX) format used in Android system and app settings directories.

### SEGB / Biome Viewer

Decodes Apple SEGB v1 and v2 files from the Biome framework. Shows timestamped records from app usage, screen time, Siri interaction, and location-adjacent signals.

Protobuf payloads are decoded automatically: double fields in the plausible Cocoa-timestamp range get a `[possible Cocoa timestamp: ...]` hint next to the raw number (the value itself is never replaced — there is no schema to confirm the field really is a date), nested messages are expanded inline with a `[raw: N B: hex…]` hint alongside them (wire type 2 doesn't declare that the bytes really are a submessage), and repeated fields are collected into arrays. Double-clicking a Payload cell opens the raw protobuf bytes in the Blob Inspector.

A backing SQLite database is created on open so you can query records using the built-in SQL editor (with autocomplete). Two payload columns are available:

| Column | Content |
|---|---|
| `Payload` | Human-readable rendered text |
| `Payload JSON` | Protobuf fields as JSON for `json_extract` queries |

Example queries:

```sql
-- All records where field 2 (bundle ID) matches
SELECT * FROM SEGB WHERE json_extract("Payload JSON", '$.2') = 'com.apple.Preferences';

-- Extract timestamp (field 1) and type (field 2) for every record
SELECT "Index", json_extract("Payload JSON", '$.1') AS ts,
                json_extract("Payload JSON", '$.2') AS type
FROM SEGB;

-- Nested field (field 6, sub-field 1)
SELECT json_extract("Payload JSON", '$.6.1') FROM SEGB;

-- Repeated field — first occurrence of field 9
SELECT json_extract("Payload JSON", '$.9[0]') FROM SEGB;
```

### Realm Database Viewer

Opens `.realm` files in a tabbed view. Column decoding is spec-driven — dispatched from each column's actual declared type/nullability/collection flags (read from its ColKey), not guessed from the data's shape — so it does not depend on the specific app that created the file.

| Tab | Content |
|---|---|
| **Header** | File metadata decoded from the Realm file header |
| **Schema** | All classes/tables with their columns and declared types (expand a table to see each field). A Link/LinkList column also shows which table it points to, e.g. `attachments: linklist → class_AttachmentLocalDto` |
| **Top Refs** | Comparison of top-ref pointers across header slots (useful for detecting corruption or versioning) |
| **Tables** | Decoded column data for each table; SQL queries run against a temporary SQLite representation of the data. Cells holding a List/Set/LinkList value are colour-flagged (grey when empty) with a tooltip, since they otherwise look like plain bracketed text |
| **Views** | Pick a table, choose per Link/LinkList column which columns of the linked table to pull in, and open the fully resolved result as a new tab — see below |
| **Freed Data** | Blocks from the file's internal free-space list (both the active and inactive top-ref), colour-coded by which ref they were freed in; right-click → **Inspect Block…** opens the raw bytes in the BLOB Inspector |
| **Strings** | String values extracted from the file |
| **Hex Preview** | Raw hex of the first bytes of the file |

**Views tab — resolving links without SQL**

A raw Link/LinkList column only holds internal object-key numbers (e.g. `[2]`), meaningless at a glance. The Views tab resolves them: select a table on the left, and every one of its Link/LinkList columns appears on the right as its own checklist of the linked table's columns (all checked by default; leave a column's whole checklist empty to leave it raw). **Open View** resolves every configured column at once and opens the table as a new tab, e.g. showing `from`/`to` as `email=...` instead of an object-key list.

**SQL queries in the Tables tab**

The decoded table data is loaded into a temporary SQLite file when the Tables tab is opened. Every table includes a leading `_objkey` column populated from the Realm ObjKey array. This allows cross-table JOINs using the same link-column values Realm stores internally:

```sql
SELECT a.title, e.name
FROM class_Article a
JOIN class_ArticleEDP e ON a.edp = e._objkey
```

List/Set/LinkList columns are stored as JSON text (e.g. `attachments` → `"[1, 2, 3]"`) — `LIKE` against them only does a text-substring match. For exact per-element matching, use SQLite's `json_each()`:

```sql
SELECT m._objkey, je.value AS attachment_objkey
FROM class_MessageAttributesLocalDto m, json_each(m.attachments) je
WHERE je.value = 2;
```

For every table with at least one Link/LinkList column, a matching `v_<table>` view is created automatically, with those columns already resolved to every column of the linked row (`col=val, col=val, ...` — deterministic, not a guess at which one column matters):

```sql
SELECT * FROM v_class_MessageAttributesLocalDto;
```

The SQL editor supports autocomplete (table, view, and column names, aliases). Double-clicking a row in the Summary view navigates directly to that table. BLOB column cells expose raw bytes in the Blob Inspector on double-click.

The temporary file is deleted automatically when the viewer is closed.

### Protobuf Viewer

Opens via right-click → **Open as Protobuf Viewer**. Performs a schema-less wire-format decode showing field numbers, wire types, and values.

**Multi-interpretation display** — because the wire format carries no type information, every numeric field shows all plausible readings as dimmed child rows. An interpretation is only shown when the value falls within a plausible range; out-of-range candidates are suppressed silently.

**varint (wire type 0)**

| Interpretation | Condition |
|---|---|
| `uint64` | always |
| `int64` | only if value ≥ 2⁶³ (i.e. negative as signed) |
| `sint64 (zigzag)` | always |
| `bool` | only if value = 0 or 1 |
| `Unix timestamp (s)` | 946 684 800 ≤ value ≤ 4 102 444 800 (2000–2100) |
| `Chrome/WebKit timestamp (µs)` | 12 591 158 400 000 000 ≤ value ≤ 15 778 800 000 000 000 (µs since 1601-01-01) |

**fixed64 (wire type 1)**

| Interpretation | Condition |
|---|---|
| `uint64` | always |
| `int64` | only if negative |
| `double` | always, unless NaN or ±inf |
| `Cocoa timestamp` | double is finite AND 0 < double ≤ 3 155 673 600 (seconds since 2001-01-01) |
| `Unix timestamp (double, s)` | double is finite AND 946 684 800 ≤ double ≤ 4 102 444 800 |
| `Unix timestamp (uint64, s)` | 946 684 800 ≤ uint64 ≤ 4 102 444 800 |
| `Chrome/WebKit timestamp (µs)` | 12 591 158 400 000 000 ≤ uint64 ≤ 15 778 800 000 000 000 |

**fixed32 (wire type 5)**

| Interpretation | Condition |
|---|---|
| `uint32` | always |
| `int32` | only if negative |
| `float` | always, unless NaN or ±inf |
| `Unix timestamp (uint32, s)` | 946 684 800 ≤ uint32 ≤ 4 102 444 800 |

**length-delimited (wire type 2)** — decoded as nested message, UTF-8 string, or hex bytes; no interpretation child rows.

**start-group (3) / end-group (4)** — deprecated wire type; the group and its contents are silently skipped and parsing continues with the next field. A truncated group or an end-group tag at the top level produces a parse warning shown in the Properties panel.

In the **Blob Inspector** (Protobuf mode), `uint64` and `uint32` are additionally suppressed from the hint lines since they equal the primary value already shown on the field line.

**Schema-based decode** — click **Load .proto / descriptor…** to load a `.proto` source file or a compiled FileDescriptorSet (`.pb`, `.fds`, `.desc`). Select the root message type from the dropdown and click **Decode**. Field names and types are then resolved from the schema; the raw wire-format view remains available via **Show Raw Decode**.

### Multi-Log Studio

A high-performance log viewer for large files and multi-source correlation. Open it via right-click → **Open in Multi-Log Studio**; add further files at any time with **Add to Multi-Log Studio** or the **+ Add Source** button inside the viewer.

**Toolbar filters** (apply across all sources simultaneously):

| Control | Action |
|---|---|
| Level buttons | Toggle ERROR / WARN / INFO / DEBUG / TRACE / UNKNOWN on or off |
| **Search** field | Filter by message, process, PID, subsystem, or category |
| **Format…** | Define or load a custom log format profile |

**Source bar** — one colour-coded chip per loaded file. Click a chip to hide or show that source. Chips scroll horizontally if many sources are loaded.

**Time-range filter** — appears after the first file with timestamps finishes loading. Check **Time range:** to enable the from/to pickers; **Reset** restores the full range. The **Display TZ** dropdown toggles between UTC and local time.

**Column filter inputs** — a persistent row of text fields above the log table, one per filterable column (Level, Process, PID, Subsystem, Category, Message). Type in any field to live-filter the table by a contains-match on that column. Multiple fields are AND-combined.

**Column filter bar** — appears below the toolbar when a right-click exact-value filter is active. Each active filter is shown as a chip (e.g. `subsystem = com.apple.security`). Click a chip's **×** to remove that filter, or **Clear all** to remove all at once.

**Detail panel** — selecting a row shows the raw original line(s). If the parser extracted extra fields (e.g. `subsystem`, `category`, `event_type`, `euid`, `thread_id` from Apple Unified Log entries), they appear below a separator.

**Apple Unified Log specifics** — `.tracev3` and `.logarchive` files are parsed via the bundled `unifiedlog_iterator` binary. Columns **Subsystem** and **Category** are populated directly. The detail panel also shows `event_type` (e.g. `logEvent`, `activityCreateEvent`, `lossEvent`), `euid`, `thread_id`, and `activity_id`. `lossEvent` entries — indicating missing log entries due to buffer overflow — are shown at WARN level with a descriptive message. `message_entries` of type Private or Sensitive are annotated `[private]` / `[sensitive]`; these may contain data that is redacted in live system logs but preserved in an offline acquisition.

**iOS full-filesystem acquisition** — right-clicking a `diagnostics/` directory (i.e. a node that contains `Persist/`, `timesync/`, `Special/`, or `Signpost/` as direct children) offers two additional actions:

- **Open in Multi-Log Studio** — Crush assembles a temporary logarchive from the diagnostics subtree and the sibling `uuidtext/` directory (needed for full message-string resolution), then converts all tracev3 files using parallel `unifiedlog_iterator` processes. Timestamps are correctly resolved as long as the acquisition includes `timesync/` files; if `timesync/` is absent or empty the Timestamp column will show "—".
- **Export as .logarchive…** — saves the assembled logarchive to a user-chosen folder so it can be examined in other tools (e.g. `log` on macOS).

**Parallel conversion** — when loading a `.logarchive` or iOS diagnostics directory, Crush splits the `Persist/*.tracev3` files across multiple `unifiedlog_iterator` processes (one per physical CPU core by default). Results appear in the viewer as each chunk finishes. The benchmark script `scripts/benchmark_unified_log.py` can be used to measure throughput and tune the worker count with `--workers N`.

**Context menu** (right-click any row):

| Option | Action |
|---|---|
| Copy message | Copies the parsed message text |
| Copy raw line | Copies the original unparsed line(s) |
| Copy selection (TSV) | Copies all selected rows as tab-separated values |
| Filter: [Column] = [value] | Pins an exact-match filter for the clicked cell; filter chip appears in the column filter bar |

**Custom format profiles**

For log files not auto-detected, click **Format…** to open the format dialog:

1. Enter a **Profile Name** and a **Parse Pattern** — a Python regex with named groups. The groups `timestamp`, `level`, `process`, `pid`, and `message` map to the corresponding columns; any other named group is stored as an extra field and shown in the detail panel.
2. Set **Timestamp Format** to a `strptime` string (e.g. `%d/%b/%Y:%H:%M:%S`). Leave empty to auto-detect ISO 8601 / epoch timestamps.
3. Optionally set **Line-Start Regex** to identify the first line of a multiline event (e.g. `^\d{4}-\d{2}-\d{2}`).
4. Optionally set **Level Map** as a JSON object to translate raw values to standard levels (e.g. `{"GET": "INFO", "500": "ERROR"}`).
5. The **Live Preview** panel highlights each named group in a distinct colour on the actual file content.
6. Click **Save Profile** to persist the profile for future use, then **Apply** to re-parse the selected source with this format.

Saved profiles are stored in `~/.config/crush/log_profiles/` and are available in the **Saved profiles** dropdown on the next start.

---

## Parsers & Viewers

Crush includes a growing set of parsers and viewers, with documented limitations for transparency. For the full, detailed list of what is supported and where the current gaps are, see `crush/docs/format-support.md`.

---

## Properties Panel

The right panel updates whenever you select or open a file. It shows:

- **File name and path**
- **MACB timestamps** — Modified, Accessed, Changed, Birth. Fields unavailable in the source format (ZIP, TAR, and 7z only store a single timestamp) are shown as **—** with an explanatory note
- **Format** — identified format name from the knowledge base (e.g. "SQLite Database", "Android Binary XML")
- **Forensic relevance** — what kind of data this format typically contains
- **Platforms** — which platforms this format originates from
- **Reference** — link to the format specification
- **Parser-specific metadata** — EXIF fields, page counts, parse errors, etc.

---

## Format Reference

**Help → Format Reference…** opens a searchable table of all formats known to Crush — both supported (with a parser) and unsupported (identified only).

- Supported formats appear in normal text
- Unsupported formats appear in grey — Crush will show forensic context in the Properties panel but display raw hex
- Select a row and click **Open Reference…** to open the format specification in your browser

---

## Exporting Files

Right-click any file or folder in the Filesystem panel and choose **Export…**. For folders, the entire subtree is exported preserving the directory structure.

---

## Value Inspector

**Tools → Value Inspector…** opens a persistent, non-modal window that shows every plausible interpretation of a single value — numeric, timestamp, UUID, network address, or raw hex bytes.

### Opening the inspector

Open it once from the *Tools* menu. The window stays on screen while you work; use the **X** button to close it when you are done.

### Updating the value

**Linux / X11 (automatic):** Highlight any text within Crush — a cell value in a SQLite table, a field in the plist viewer, a hex dump, a JSON string — and the inspector updates immediately. No copy, no click required. Selections in other applications (browser, terminal) are ignored.

**All platforms (manual):** Type or paste a value directly into the *Value* field at the top of the inspector window.

### Interpretation groups

| Group | What is shown |
|---|---|
| **Integer** | Decimal, hex, signed/unsigned 32-bit and 64-bit. For hex-byte input (e.g. `c0 a8 01 01`) both big-endian (BE) and little-endian (LE) variants are shown. |
| **Float** | 64-bit double (if input is a decimal float). Float32 and Double reinterpreted as raw bytes, in both BE and LE byte order (only for hex-byte input of exactly 4 or 8 bytes). |
| **Timestamp** | Unix (s / ms / µs), Cocoa/Apple (s and ns since 2001-01-01), Chrome/WebKit (µs since 1601-01-01), Windows FILETIME / NTFS (100 ns since 1601-01-01), HFS+ / Mac OS (s since 1904-01-01), Microsoft .NET Ticks (100 ns since 0001-01-01), OLE Automation Date (days since 1899-12-30), Twitter / X Snowflake ID, FAT / exFAT MS-DOS (32-bit packed, 2 s resolution, epoch 1980-01-01), BCD (7 hex bytes `YYYY MM DD HH mm SS`), UUID v1 Timestamp (Gregorian epoch 1582-10-15), GPS Time (s and ns since 1980-01-06, no leap-second correction — GPS is currently ~18 s ahead of UTC), Windows SYSTEMTIME (16 hex bytes, millisecond precision). |
| **UUID** | Formatted as `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` if input is a 32-digit hex string or already a UUID. |
| **Network** | IPv4 big-endian and little-endian (4-byte values), MAC address (6-byte hex values). |
| **Text** | ASCII rendering of hex bytes (non-printable shown as `.`); UTF-8 decoding if the bytes are valid UTF-8. |
| **Encoding** | Base64 and Base64url decode — shown as raw bytes (hex) and as UTF-8 text if the decoded payload is valid UTF-8. Only attempted when the input contains characters outside the hex alphabet (`G–Z`, `g–z`, `+`, `/`, `=`, `-`, `_`) to avoid false positives on plain numbers and hex strings. |

Rows with no plausible value show `—` in grey. Hover over any label or value to see the full text in a tooltip — useful for long float representations or truncated timestamps.

### Copying a result

Select any value row and click **Copy value** to put the interpreted value on the clipboard.

---

## Paste & Decode

**Tools → Paste & Decode…** is an alternative entry point to the [BLOB Inspector](#blob-inspector). It lets you paste raw binary data — copied from a hex editor, a SQLite BLOB cell, a network capture, or any other source — and inspect it directly in Crush without saving it to disk first.

1. Paste hex, base64, or plain text into the input area at the top.
2. Set **Input encoding** to **Auto** (default) or force a specific encoding if auto-detection picks the wrong one:
   - **Auto** — detects hex strings, Base64, and plain text automatically
   - **Hex** — treats the input as a hex string regardless of content
   - **Base64** — decodes as Base64 regardless of content
   - **UTF-8 text** — treats the input as UTF-8 text and passes the raw bytes through
3. The status line shows the detected encoding and decoded byte count as you type. If it stays grey, the input could not be decoded with the current encoding setting.
4. The full BLOB Inspector panel — three columns: *Decode pipeline*, *Interpretations*, *Content view* — appears directly below and updates live as you type.

All pipeline steps and interpretations available in the BLOB Inspector (Base64, zlib, gzip, …) are also available here. New decode steps added to the inspector appear automatically in Paste & Decode as well.

> **Tip:** The dialog is non-modal — you can keep it open and paste new data at any time while working in the main window.

---

## Integrity Mode

Integrity mode adds hashing and traceability to file access:

- When enabled, files opened or exported are hashed (SHA-256) and written to the log.
- Opening a ZIP/TAR/7z/file triggers the calculation of the hash (SHA-256) of the file.
- Opening a folder does not hash the full directory.
- Exports also create a `crush-export-hashes.txt` file next to the exported data.
- The bottom-right status badge shows the current mode. Click the badge to toggle it, or right-click it for a quick menu and a short explanation.

---

## Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+Q` | Quit |
| `Ctrl+F` | Focus the search bar in the Text viewer (when a text tab is active) |
| Middle-click tab | Close tab |

---

## Tips for Forensic Workflows

- **Large archives:** Crush loads ZIP, TAR, and 7z indexes immediately and reads file content on demand — you do not need to wait for a full extraction before browsing. 7z's solid compression blocks multiple files together, so reading any single file from a solid 7z can be slower than the equivalent ZIP/TAR read.
- **SQLite WAL files:** if a `-wal` or `-shm` companion file is present alongside a `.db`, Crush automatically includes it so you see the most recent state of the database. Use **WAL Frames (generated)** for a full frame inventory with forensic classification (Active / Superseded / Uncommitted / WAL slack), and enable **Show WAL history** in any table view to surface rows from historical frames — potentially recovering data from before the last UPDATE or DELETE.
- **BLOB chaining:** SQLite cells containing embedded plists, images, or other binary data can be opened directly as a new viewer tab via right-click → **Open as new tab**.
- **Unknown files:** even if Crush cannot parse a file, the Properties panel will show the identified format name and forensic relevance based on magic bytes — so you know what you are looking at before deciding to export and open it externally.

---

## Bugs and feature requests

Found a bug or have a suggestion? Open an issue on [GitHub](https://github.com/kalink0/crush-forensics/issues). Please include the Crush version (shown in **Help → About**), your OS, and steps to reproduce.
