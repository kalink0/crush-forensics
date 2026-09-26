## Properties Panel

The right panel updates whenever you select or open a file. It shows:

- **File name and path**
- **MACB timestamps** — Modified, Accessed, Changed, Birth. Fields unavailable in the source format (ZIP, TAR, and 7z only store a single timestamp) are shown as **—** with an explanatory note
- **Entry status** — what the entry's name and bytes don't show, for every source type: a **symbolic link** (shown with its target, whose text is the entry's content; links are never followed, so a link to a parent folder can't loop and a broken link doesn't stop a folder from opening), a **hard link**, a **special file** (device, FIFO — never read), one of **several entries stored under the same name** in an archive (each is shown — `name`, `name (2)` … in archive order — with its own content), a folder that **could not be listed**, or an iTunes-backup entry with **no content stored** in the backup
- **Format** — identified format name from the knowledge base (e.g. "SQLite Database", "Android Binary XML")
- **Forensic relevance** — what kind of data this format typically contains
- **Platforms** — which platforms this format originates from
- **Reference** — link to the format specification
- **Parser-specific metadata** — EXIF fields, page counts, parse errors, etc.
- **SQLite blob provenance** — a cell opened via the Table Viewer's **Open as new tab** additionally shows the source table (or the full, untruncated SQL query text if it came from an ad-hoc query), column, row, originating database file, and the chosen display format

The panel refreshes automatically whenever you switch between already-open viewer tabs, not just when a new one is opened.

---

