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
