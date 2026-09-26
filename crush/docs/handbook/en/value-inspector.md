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

