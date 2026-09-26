## Tips for Forensic Workflows

- **Large archives:** Crush loads ZIP and plain (uncompressed) TAR indexes almost immediately and reads file content on demand — you do not need to wait for a full extraction before browsing. Compressed archives are slower, because the format has no index: a **`.tar.gz`/`.tar.xz`/`.tar.bz2`** has to be read through once before its tree appears (minutes for tens of GB, at the speed of the disk), and reading any single file from it, like from a solid 7z (multiple files compressed together in one block), means decompressing everything before it. For evidence you choose the format of, prefer ZIP or an uncompressed TAR.
- **SQLite WAL files:** if a `-wal` or `-shm` companion file is present alongside a `.db`, Crush automatically includes it so you see the most recent state of the database. Use **WAL Frames (generated)** for a full frame inventory with forensic classification (Active / Superseded / Uncommitted / WAL slack), and enable **Show WAL history** in any table view to surface rows from historical frames — potentially recovering data from before the last UPDATE or DELETE.
- **BLOB chaining:** SQLite cells containing embedded plists, images, or other binary data can be opened directly as a new viewer tab via right-click → **Open as new tab**, forcing a specific format (Hex/Text/Protobuf) if needed. The Properties panel keeps track of exactly which table/query, column, and row each opened cell came from.
- **Unknown files:** even if Crush cannot parse a file, the Properties panel will show the identified format name and forensic relevance based on magic bytes — so you know what you are looking at before deciding to export and open it externally.

---

