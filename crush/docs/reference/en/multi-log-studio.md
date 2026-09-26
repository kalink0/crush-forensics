### Multi-Log Studio

A high-performance log viewer for large files and multi-source correlation. Open it via right-click → **Open in Multi-Log Studio**; add further files at any time with **Add to Multi-Log Studio** or the **+ Add Source** button inside the viewer.

**Toolbar filters** (apply across all sources simultaneously):

| Control | Action |
|---|---|
| Level buttons | Toggle ERROR / WARN / INFO / DEBUG / TRACE / UNKNOWN on or off |
| **Search** field | Filter by message, process, PID, subsystem, or category |
| **Format** | **Re-parse *source* as** a specific built-in format (overrides the detection), or **Define custom format…** |

**Source bar** — one colour-coded chip per loaded file. Click a chip to hide or show that source. Chips scroll horizontally if many sources are loaded.

**Time-range filter** — appears after the first file with timestamps finishes loading. Check **Time range:** to enable the from/to pickers; **Reset** restores the full range. The **Display TZ** dropdown toggles between UTC and local time. Times the log recorded without a zone are shown as recorded with "(no zone)" and never converted; a missing year (Syslog, logcat) is shown as `????`.

**Guessed levels** — Syslog, generic and plain-text logs have no level field; their level is guessed from a keyword in the message and shown as e.g. `ERROR (guessed)` (tooltip: every keyword found). The level buttons filter guessed levels too.

**Format label** — next to the toolbar, one entry per source: its format, marked "(heuristic)" when detected rather than chosen. Click **ⓘ** for everything the parser reported: all candidate formats with how many lines each matched, the detection rule, lines that didn't match the format, timestamp notes and encoding problems.

**Column filter inputs** — a persistent row of text fields above the log table, one per filterable column (Level, Process, PID, Subsystem, Category, Message). Type in any field to live-filter the table by a contains-match on that column. Multiple fields are AND-combined.

**Column filter bar** — appears below the toolbar when a right-click exact-value filter is active. Each active filter is shown as a chip (e.g. `subsystem = com.apple.security`). Click a chip's **×** to remove that filter, or **Clear all** to remove all at once.

**Detail panel** — selecting a row shows the raw original line(s). If the parser extracted extra fields (e.g. `subsystem`, `category`, `event_type`, `euid`, `thread_id` from Apple Unified Log entries), they appear below a separator.

**Apple Unified Log specifics** — `.tracev3` and `.logarchive` files are parsed via the bundled `unifiedlog_iterator` binary. Columns **Subsystem** and **Category** are populated directly. The detail panel also shows `event_type` (e.g. `logEvent`, `activityCreateEvent`, `lossEvent`), `euid`, `thread_id`, and `activity_id`. `lossEvent` entries — indicating missing log entries due to buffer overflow — are shown at WARN level with a descriptive message. `message_entries` of type Private or Sensitive are annotated `[private]` / `[sensitive]`; these may contain data that is redacted in live system logs but preserved in an offline acquisition.

**iOS full-filesystem acquisition** — right-clicking a `diagnostics/` directory (i.e. a node that contains `Persist/`, `timesync/`, `Special/`, or `Signpost/` as direct children) offers three additional actions:

- **Open in Multi-Log Studio** — Crush assembles a temporary logarchive from the diagnostics subtree and the sibling `uuidtext/` directory (needed for full message-string resolution), then converts all tracev3 files using parallel `unifiedlog_iterator` processes. Timestamps are correctly resolved as long as the acquisition includes `timesync/` files; if `timesync/` is absent or empty the Timestamp column will show "—".
- **Export as .logarchive…** — saves the assembled logarchive to a user-chosen folder so it can be examined in other tools (e.g. `log` on macOS).
- **Send to Peach** — see below.

**Parallel conversion** — when loading a `.logarchive` or iOS diagnostics directory, Crush splits the `Persist/*.tracev3` files across multiple `unifiedlog_iterator` processes (one per physical CPU core by default). Results appear in the viewer as each chunk finishes. The benchmark script `scripts/benchmark_unified_log.py` can be used to measure throughput and tune the worker count with `--workers N`.

Log conversion's intermediate files (extracted archive contents, per-worker mini-logarchives, and the converter's output CSVs for `.tracev3`/`.logarchive` sources) go to **Tools → Temp Directory…** — the same setting every other temporary file uses; see [Large files, memory and the temp directory](opening-evidence.md#large-files-memory-and-the-temp-directory). Useful when the OS default temp location is on a small or slow disk.

**Context menu** (right-click any row):

| Option | Action |
|---|---|
| Copy message | Copies the full parsed message text, all lines |
| Copy raw line | Copies the original unparsed line(s) |
| Copy selection (TSV) | Copies all selected rows as tab-separated values; tabs, line breaks and backslashes inside a field are escaped (`\t`, `\n`, `\\`), never cut |
| Filter: [Column] = [value] | Pins an exact-match filter for the clicked cell; filter chip appears in the column filter bar |

**Custom format profiles**

For log files not auto-detected, click **Format → Define custom format…** to open the format dialog:

1. Enter a **Profile Name** and a **Parse Pattern** — a Python regex with named groups. The groups `timestamp`, `level`, `process`, `pid`, and `message` map to the corresponding columns; any other named group is stored as an extra field and shown in the detail panel.
2. Set **Timestamp Format** to a `strptime` string (e.g. `%d/%b/%Y:%H:%M:%S`). Leave empty to auto-detect ISO 8601 / epoch timestamps.
3. Optionally set **Line-Start Regex** to identify the first line of a multiline event (e.g. `^\d{4}-\d{2}-\d{2}`).
4. Optionally set **Level Map** as a JSON object to translate raw values to standard levels (e.g. `{"GET": "INFO", "500": "ERROR"}`).
5. The **Live Preview** panel highlights each named group in a distinct colour on the actual file content.
6. Click **Save Profile** to persist the profile for future use, then **Apply** to re-parse the selected source with this format.

Saved profiles are stored in `~/.config/crush/log_profiles/` and are available in the **Saved profiles** dropdown on the next start.

**Send to Peach**

Right-click a `.logarchive` bundle, an iOS full-FS acquisition's `diagnostics/` folder, or **any other file** → **Send to Peach** hands the source off to [peach-forensics](https://github.com/kalink0/peach-forensics), a sibling forensic log viewer with tagging and Splunk-style search. This is a one-shot handoff, not an embedded view — peach launches as its own window and keeps running fully independently afterward, even after Crush itself is closed; there's no connection back to Crush once it's started.

- Offered on any file, not just recognized AUL sources — the same "offer it, let the tool itself be the real test" approach **Open in Multi-Log Studio** already uses, since peach's own TOML text-log configs live in its per-user data directory and Crush has no way to check a file against them. Peach never auto-loads a source anyway — you always confirm the sourcetype and click **Load** yourself, so an unrelated file just gets dismissed there rather than silently misinterpreted.
- The peach binary ships bundled with Crush (same mechanism as `unifiedlog_iterator`) — nothing to install separately in a portable build. Running from source needs `python scripts/download_peach_binaries.py` once. Both tools' bundled versions — including in nightly builds — are shown in **Help → About Crush → Acknowledgements**.
- **Tools → Peach → Binary Path…** points at a different peach executable instead of the bundled one — useful if Crush hasn't been updated in a while but a newer peach build is available. Leave blank to use the bundled version.
- **Tools → Peach → Open Peach** launches a plain, empty peach instance with no source pre-filled — for when you just want to work in peach directly (e.g. loading further sources from its own file picker) without sending anything from Crush first.
- A `.logarchive` bundle is handed to peach as-is. An iOS diagnostics folder is recreated as a temporary `diagnostics/` + `uuidtext/` sibling pair (peach's own raw-acquisition layout) rather than the flattened bundle format `unifiedlog_iterator` needs — the two tools expect different input shapes. Any other file is passed through unchanged (or extracted from an archive/backup first, if needed).

**Sending multiple sources at once**

Every "Send to Peach" click starts a completely new, independent peach process — peach deliberately has no IPC, so a second click never joins an already-open peach window. To correlate several sources in one peach session, send them together in a single click instead:

- **Multi-select** several files in the tree (Ctrl/Shift-click, same as any file manager) and right-click → **Send N files to Peach**. All selected files go to one new peach instance as multiple pre-filled sources.
- **A plain folder** (not a `.logarchive` or diagnostics folder) → right-click → **Send Logs to Peach…** recursively scans the folder for log-looking files, shows a checklist to confirm which ones (same picker "Open Logs in Multi-Log Studio" uses), and sends the selected ones together.
- **Any folder** → right-click → **Send Biome Streams to Peach…** recursively scans for SEGB-format files (detected by content, not by directory-naming convention, so it works under any Biome root — macOS's `.../private/var/db/biome/streams`, iOS's per-app `Library/Biome/streams`, or anywhere else), shows a checklist to confirm which ones (same picker "Send Logs to Peach…" uses), then hands the selected files to peach as a single source with their original directory structure preserved — the parent-directory names peach (and Crush's own Stream field) derives each file's Biome stream name from. **Requires peach v0.7.0 or newer** for Biome/SEGB support — sending to an older peach build just opens an unrecognized source.

Once peach is already open, you can also just keep adding sources directly in peach's own UI (its file picker) — that works the same regardless of how the session got started.

