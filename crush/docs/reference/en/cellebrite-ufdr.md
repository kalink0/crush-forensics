## Cellebrite UFDR

**Open file…** also accepts a Cellebrite Physical Analyzer report container (`.ufdr`), opened in place — the archive isn't extracted first. The tree shows the files the UFDR holds under their original device paths, e.g. `/data/app/...`, `/data/data/com.example.app/...`, reconstructed from the container's embedded PostgreSQL dump rather than the container's own internal, type-bucketed storage layout (Cellebrite's `files/Application/...`, `files/Image/...`, and so on). Selecting a file shows Cellebrite's own recorded MD5/SHA-256 and category in the Properties panel.

**A UFDR holds only the files Physical Analyzer exported into it, not the whole extraction** — in one real UFDR, about a third of the extraction's files. The root's **Entry status** says so. A folder's Properties show **Extraction files (Cellebrite count)**, the number of files below it in the whole extraction as Cellebrite counted them, and **Extraction files in this UFDR**; when files are missing, **Missing from this UFDR** says how many. Those files aren't listed: the UFDR records nothing about them but this count.

Only UFDR 10.x is supported (the version that embeds the actual database — earlier UFDR 7 exports do not and aren't covered). A file's bytes are checked against Cellebrite's recorded MD5 when they are first read or shown in the Properties panel; a file over 64 MB is matched by its category, name and size only, without the hash check. If a file's bytes can't be located in the container, it still appears in the tree with an explicit "not located in container" status rather than opening as empty or wrong content. A file Cellebrite records as 0 bytes opens as empty: the container stores no bytes for it.

- **Items Cellebrite derived from a file** — e.g. the decrypted copy of an app database (`signal.db.decrypted` and `signal.db.decrypted-wal` for Signal; likewise Threema, Wickr and vault apps), an `AndroidManifest.xml` from an APK, images embedded in a PDF or a cached web page. A file's only derived item is shown next to it in the same folder; several (or one whose name is already taken there) are in a folder `<file> (derived)` next to it. The Properties panel's **Derived from** names the file; such a folder's **Entry status** says what it holds. Neither is a file or folder of the device's filesystem.
- **A file the UFDR doesn't hold, whose derived items it does** — common for images carved from fonts, binaries and cache entries: the file is shown as a placeholder at its path, with the size Cellebrite recorded and no content; its **Entry status** says so. Its derived items are placed beside it like any file's, and **Derived from** says the UFDR doesn't contain the file.
- **Several catalog entries under one path** are each shown, numbered `name`, `name (2)` …, with an **Entry status** saying so.

### Known limitations

- **Filesystem browsing only** — Cellebrite's own decoded forensic tables (contacts, calls, chats, locations, and the rest of Physical Analyzer's ~185 other tables) are not read or shown; use Cellebrite Reader for those.
- **Folders are taken from Cellebrite's paths** — a derived item's path runs through the file it came from. When the UFDR records nothing about that file, not even a placeholder's path and size, the file shows as a folder.
- **No split/segmented UFDR exports** — a case exported as multiple `.ufdr` parts is not supported; open a single, complete `.ufdr`.
- **UFDR 10.x only** — UFDR 7 containers (no embedded database) are not supported.
- **No encrypted UFDR containers** — not yet supported.

---

