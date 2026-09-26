### MMKV Viewer

Opens a Tencent MMKV key-value store (used by many Android/iOS apps in place of `SharedPreferences`/`NSUserDefaults`) via right-click → **Open as** → **MMKV** or **MMKV (Encrypted)…** — see the [Filesystem Panel](filesystem-panel.md) section above. MMKV has no magic bytes, so it's never opened by double-click/auto-detection.

**Overview tab** — the store's `.crc` meta file fields (when that companion file is found next to the main file): meta version, sequence (full write-back count), CRC-32 of the data region as recorded, and whether the store is AES-encrypted. Also shows total entry counts by state.

**Records tab** — every entry in file order (not collapsed to one row per key), since MMKV is append-only between rewrites — a changed key appends a new entry rather than editing the old one, so superseded values remain physically present and readable until the next full rewrite:

| Column | Content |
|---|---|
| Index | Position of this write in the file |
| Key | The key string |
| State | **Live** (the last write for this key), **Superseded** (an earlier write of a key later overwritten), or **Removed** (this write's value container is zero-length, MMKV's own way of representing a removal) |
| Type | `string`, `int`, `bytes`, or `empty`, from how the value's container decodes — MMKV records a value's type in the app's own code, not in the file, so a container that's exactly a length-prefixed string decodes as text and anything else as a scalar varint |
| Size (B) | Byte size of the value's complete container |
| Value | The decoded value, truncated on-screen for very large values (real stores can hold multi-megabyte values, e.g. a cached JSON blob) — the complete value stays reachable via search, CSV export, and **Copy Value** |

Toolbar controls:

| Control | Action |
|---|---|
| **All / Live / Superseded / Removed** | Filter records by state |
| **Search** | Case-insensitive filter across all columns, matching a large value's complete text even where the Value cell shows it truncated |
| **Export CSV…** | Save currently visible rows, including the value's complete text and complete raw container as hex |

Selecting a row shows the store's real file in the hex pane below the table, with that entry's own on-disk bytes highlighted (key and value container together, the value container itself highlighted on top) — real byte provenance, not just the value's own bytes copied out in isolation. Works the same way for AES-encrypted stores: the highlighted bytes are the genuine ciphertext at that file position, since AES-CFB doesn't shift byte positions between plaintext and ciphertext. Falls back to showing just the value's own raw container bytes (untouched, including MMKV's own internal length-prefix byte(s) for a string value) when its on-disk span couldn't be determined. The complete decoded value text is shown in the **Value:** field beneath the hex pane.

Right-click a row for:
- **Inspect Value…** — opens the [BLOB Inspector](blob-inspector.md) on the value's own bytes, with MMKV's internal length-prefix already removed (unlike the hex pane above, which always shows the complete untouched container) — so a value that's itself JSON/XML/etc. can actually be re-parsed as such, defaulting to the already-decoded text view
- **Copy Key** / **Copy Value** — copies the key, or the value's complete decoded text, to the clipboard

