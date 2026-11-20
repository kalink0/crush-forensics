## Exporting Files

Right-click any file or folder in the Filesystem panel and choose **Export…**. For folders, the entire subtree is exported preserving the directory structure. If the destination folder already has a same-named file or folder, you're asked to confirm before it's overwritten.

A file whose bytes can't be read from the evidence (for example, one a disk image's reader returns shorter than its recorded size) is not exported, and nothing is left under its name; the export goes on with the other files. When it's done, the message says how many files were not exported, and `crush-export-failed.txt`, next to the exported data, lists each one's path in the evidence and the reason; with integrity mode on, `crush-export-hashes.txt` notes the count too. Exporting a single file that can't be read fails, with the reason, and puts nothing into the destination folder.

**Cancel** in the export dialog (or Esc) stops the export before the next file, or mid-file. The file being copied is removed, so no file is left partly written under its name. What was exported until then stays, and `crush-export-cancelled.txt` next to it says the export is incomplete and how many files were exported; with integrity mode on, `crush-export-hashes.txt` lists those files and starts with the same note. A cancelled single-file export leaves nothing. **Export as .logarchive…** can be cancelled too: nothing is saved, and the message says if an existing `.logarchive` of that name had already been removed to be replaced.

---

### Export to a ZIP archive

Right-click a file or folder and choose **Export to ZIP…** to export it into a ZIP archive instead of a folder. Choose a file name; `.zip` is added if missing. If the archive doesn't exist yet, it is created. If it exists, you choose:

- **Add to Archive** — the export is added and the archive's entries are kept. A name the archive already holds gets a number (`case (2)/`, `report (2).pdf`), so nothing is overwritten and no name appears twice; the rename is listed in `crush-export-renames.txt`.
- **Replace Archive** — a new archive replaces it.

A file that isn't a ZIP archive can only be replaced. A folder is stored with its structure under its own name; a single file is stored at the top of the archive. Entries are compressed (Deflate; ZIP64 for large files) and carry the source's modification time in UTC (also as an Info-ZIP extended timestamp). Names are made Windows-safe as for a folder export.

The same lists as a folder export go into the archive: for a folder inside it (`case/crush-export-hashes.txt`, `case/crush-export-failed.txt`, `case/crush-export-renames.txt`), for a single file next to it, named after it (`report.pdf.crush-export-hashes.txt`). With integrity mode on, the hash list holds each file's SHA-256 with its path in the archive, and the log records the SHA-256 of the finished archive. A file that can't be read is left out — no entry holds part of it — and listed in `crush-export-failed.txt`; a single file that can't be read fails the export.

The archive is written to a temporary file beside it and only moved into place when complete. **Cancel**, an error or a crash therefore never leaves a partly written archive under its name, and an archive you were adding to stays exactly as it was. Adding to an archive needs free space for a copy of it in the same folder.

#### Several entries at once

Select several files and folders in the tree (Ctrl/Shift-click), right-click one of them and choose **Export N selected entries to ZIP…**. Each entry is stored under its full path from the root of its source, starting with the source's own name, so entries from different levels keep where they came from:

```
case/private/var/mobile/a.db      ← a file, deep down
case/private/var/logs/x.log       ← a folder, one level higher, with its content
case/top.txt                      ← a file at the top
```

The folders on the way are stored as (empty) folder entries. An entry inside a selected folder is not stored twice: the folder brings it along. When adding to an archive, folders the archive already holds are shared; only a selected file or folder whose path is already in the archive gets a number (`case/top (2).txt`). The lists (`crush-export-hashes.txt`, `crush-export-failed.txt`, `crush-export-renames.txt`) go to the top of the archive, numbered too if the archive already has them. A file that can't be read is left out and listed; the export still completes.
