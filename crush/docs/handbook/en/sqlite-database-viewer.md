### SQLite / Database Viewer

The table dropdown at the top switches between database tables, views, and seven always-shown generated analysis pages (plus WAL Frames, an eighth, when a `-wal` companion file is present). All generated entries are labelled `(generated)` to make clear they are computed by Crush rather than read directly from the database.

#### Generated views

**Summary (generated)** — the default view when a database is opened. Lists every table and view with its row count. The status line shows the full schema object count (tables, views, indexes, triggers) at a glance. Double-click any row to navigate directly to that table.

**DB Structure (generated)** — lists all schema objects (tables, views, indexes, triggers) with structural details:

| Object type | Info column |
|---|---|
| Table | Column list, e.g. `(id, name, created_at)` |
| View | Full `CREATE VIEW` SQL on one line |
| Index | `ON table (column, …)` — shows which table and columns are indexed |
| Trigger | First line of `CREATE TRIGGER …` |

**DB Info (generated)** — shows 9 PRAGMA settings in a three-column layout (Setting / Value / Description), styled after the *Edit Pragma* view of DB Browser for SQLite. Only PRAGMAs actually persisted in the SQLite file header are shown (`application_id`, `user_version`, `schema_version`, `encoding`, `page_size`, `page_count`, `freelist_count`, `journal_mode`, `auto_vacuum`) — most other PRAGMAs are per-connection settings that reset to the linked SQLite library's own default on every new connection, so displaying them would show Crush's own runtime environment rather than anything about the examined file's history. Enum values are decoded to their named constant (e.g. `2 — FULL` for `auto_vacuum`), booleans show as `1 — ON` / `0 — OFF`. When a WAL companion is present, six WAL forensic metrics appear at the top of this view before the PRAGMA list (see *WAL forensic analysis* below).

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

#### Freelist Recovery

Appears when `PRAGMA freelist_count` is greater than zero. SQLite doesn't zero a page's content when it's freed by `DELETE`/`DROP` — only when a later allocation actually reuses it — so a freed page can still hold its original table-leaf cells intact. This tab walks the freelist trunk chain and carves any leftover rows it finds.

Recovered rows show generic column headers (`col0`, `col1`, …) rather than the original column names — a freed page is no longer referenced by any table's B-tree, so the source table can't be determined with certainty. A **Candidate Tables** column lists every table whose column count matches, as a heuristic hint, not a definitive attribution. Values whose payload spilled onto overflow pages are reconstructed by following the overflow chain, but only through pages still confirmed unmodified on the freelist — a chain that steps onto a reused or trunk page (trunk pages are overwritten with the freelist's own bookkeeping the moment they become a trunk) is left as `<OVERFLOW>` rather than risk splicing in unrelated data. Double-click a row to open its raw page in the Hex Viewer.

#### Freeblocks

Always shown. Catches the far more common case Freelist Recovery can't: an ordinary single-row `DELETE` that never frees a whole page. SQLite splices the deleted cell into the page's own in-page freeblock list instead of zeroing it. Since the page is still part of a live table's B-tree, the **Table** column here is a definite match, not a heuristic guess. Cell content is shown raw rather than decoded into columns, since the freeblock's own 4-byte header overwrites the start of the original cell.

#### Unallocated Space

Always shown. Displays the raw bytes sitting in the gap between a page's cell-pointer array and its cell-content area, for manual review. Unlike Freeblocks, SQLite makes no guarantee anything meaningful survives here — it's often all-zero, or stale 2-byte pointer values left over from a shrunk pointer array, rather than recoverable row text. All-zero gaps aren't shown at all; only non-empty ones are, so you can judge each entry yourself.

Freeblocks and Unallocated Space rows can also be double-clicked to open that row's whole containing page as an isolated tab in the Hex Viewer, same as Freelist Recovery above.

#### File Structure (generated)

Always shown. A physical, page-by-page view of the database file itself — header fields, B-tree page headers, cell-pointer arrays, individual cells, freeblocks, and unallocated space — independent of the logical table/row view the other generated pages give you. Each page's own row/column detail is decoded lazily, only the first time you expand it, so opening a database with many rows stays responsive instead of decoding everything up front. Selecting a structure item and the embedded Show Hex pane (see below) stay in sync in both directions.

There is no text/content search across the whole structure tree — full search would mean decoding every page up front, reintroducing the exact hang lazy loading exists to avoid, and searching only already-expanded pages would be a silently incomplete search, unacceptable for a forensic tool. To find specific content: run a SQL query against the table itself (works for any value, including numeric ones an on-disk byte search never can), use a cell's **Open in Hex** action, or search directly in the Hex pane below — hex search hits sync back into the structure tree the same way tree selections sync into hex.

#### Show Hex pane

The table view, WAL Frames, and File Structure pages all have a **Show Hex** toggle button that opens an embedded hex pane alongside the current view, bidirectionally synced with it: selecting a row/cell/structure item highlights its exact on-disk bytes, and clicking a highlighted byte in the hex pane selects the matching row/cell/item back.

- **Table view:** selecting a cell highlights its whole row (pale) and that column's own bytes (stronger, drawn on top). A row whose current version is only in a not-yet-checkpointed `-wal` frame switches the pane to that file instead of the base file's stale bytes. A **Show WAL history** row (see above) gets the same column-precise treatment, keyed by its own frame bytes rather than a rowid.
- **WAL Frames:** selecting a frame highlights its exact header+page bytes in the `-wal` file.
- **File Structure:** selecting any structure item — a header field, a page, a cell, a freeblock, an unallocated-space gap — highlights its exact bytes, across whichever of the base file or `-wal` file it actually lives in.

Freelist Recovery does not have the embedded Show Hex pane (its rows use double-click to open the whole containing page in an isolated tab instead, see above).

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

**Timestamp column decoding:** right-click any column header to decode integer/real values as timestamps — including numbers stored as text (`'1713884690406'`; only plain decimal numbers, nothing else is guessed). Choose a format from the **Decode column as timestamp** submenu:

| Format | Epoch | Unit |
|---|---|---|
| Unix — seconds | 1970-01-01 | s |
| Unix — milliseconds | 1970-01-01 | ms |
| Unix — microseconds | 1970-01-01 | µs |
| Mac Absolute Time | 2001-01-01 | s |
| Windows FILETIME | 1601-01-01 | 100 ns |
| Chrome / WebKit | 1601-01-01 | µs |

Values are displayed as `YYYY-MM-DD HH:MM:SS UTC`. The column header shows the active format as a suffix (e.g. `created_at [unix ms]`). Sorting remains chronologically correct. A cell that can't be decoded (non-numeric text, or a value out of range for the chosen format) is shown as stored, in orange, with the reason in its tooltip; the header tooltip says how many values were affected, and the header reads `[… : none decodable]` if nothing in the column decoded. Empty and `NULL` cells are left alone. Select **Clear timestamp format** to revert to the raw values.

**Cell inspection:** right-click any cell for options including:
- **Inspect Cell…** — preview the raw value, attempt base64/plist/XML decode
- **Open in Hex** — view cell bytes as hex
- **Open as new tab** — submenu: **Auto-detect** (best-guess parser, e.g. a plist stored inside a SQLite column), or force **Hex** / **Text** / **Protobuf**. Each cell opens in its own tab — opening several cells from the same column (or from different rows of an ad-hoc SQL query) never collides into one shared tab. The tab tooltip and Properties panel show where the artifact came from: source table or full query text, column, row, and the originating database file
- **Export…** — save the cell value to disk
- **Copy cell / Copy row / Copy selection**

