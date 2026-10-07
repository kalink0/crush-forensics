## Properties Panel

The right panel updates whenever you select or open a file. It shows:

- **File name and path**
- **MACB timestamps** — Modified, Accessed, Changed, Birth. A time the source doesn't store is shown as **—**; a folder that only exists as part of its members' paths in an archive has no time. Each kind is one row: every value of it is shown with its zone (`UTC`, or **as stored, no time zone**), and below it, in small grey text, where it is stored and anything else to know about it. Where a source stores times in several places, every one is shown with where it comes from:
  - **ZIP** — the DOS date/time and the times in the extra fields (Info-ZIP extended timestamp `0x5455`, Info-ZIP Unix `0x5855`, NTFS `0x000a`, PKWARE Unix `0x000d`), from the central directory and the member's local header. A DOS date/time has no time zone: it is shown **as stored, no time zone** and never converted, so it reads the same on every analysis machine; one that is not a valid date shows its stored values and says so. The extra fields hold UTC times.
  - **FAT/exFAT** in a disk image — the directory entry's date/time as stored, with no time zone (FAT stores the last access as a date only); exFAT's stored UTC offset is shown and not applied.
- **Entry status** — what the entry's name and bytes don't show, for every source type: a **symbolic link** (shown with its target, whose text is the entry's content; links are never followed, so a link to a parent folder can't loop and a broken link doesn't stop a folder from opening), a **hard link**, a **special file** (device, FIFO — never read), one of **several entries stored under the same name** in an archive (each is shown — `name`, `name (2)` … in archive order — with its own content), a folder that **could not be listed**, or an iTunes-backup entry with **no content stored** in the backup
- **Format** — identified format name from the knowledge base (e.g. "SQLite Database", "Android Binary XML")
- **Forensic relevance** — what kind of data this format typically contains
- **Platforms** — which platforms this format originates from
- **Reference** — link to the format specification
- **Parser-specific metadata** — EXIF fields, page counts, parse errors, etc.
- **SQLite blob provenance** — a cell opened via the Table Viewer's **Open as new tab** additionally shows the source table (or the full, untruncated SQL query text if it came from an ad-hoc query), column, row, originating database file, and the chosen display format

The panel refreshes automatically whenever you switch between already-open viewer tabs, not just when a new one is opened.

---

