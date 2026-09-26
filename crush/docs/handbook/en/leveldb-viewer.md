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

Right-click any record row to open the [BLOB Inspector](blob-inspector.md) for the key, value, or internal key of that record.

**LOG tabs** — if `LOG` or `LOG.old` files exist in the directory, each gets a dedicated read-only tab showing the complete file content with a *Find* toolbar.

