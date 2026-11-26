## Exporting Files

Right-click any file or folder in the Filesystem panel and choose **Export…**. For folders, the entire subtree is exported preserving the directory structure. If the destination folder already has a same-named file or folder, you're asked to confirm before it's overwritten.

A file whose bytes can't be read from the evidence (for example, one a disk image's reader returns shorter than its recorded size) is not exported, and nothing is left under its name; the export goes on with the other files. When it's done, the message says how many files were not exported, and `crush-export-failed.txt`, next to the exported data, lists each one's path in the evidence and the reason; with integrity mode on, `crush-export-hashes.txt` notes the count too. Exporting a single file that can't be read fails, with the reason, and puts nothing into the destination folder.

**Cancel** in the export dialog (or Esc) stops the export before the next file, or mid-file. The file being copied is removed, so no file is left partly written under its name. What was exported until then stays, and `crush-export-cancelled.txt` next to it says the export is incomplete and how many files were exported; with integrity mode on, `crush-export-hashes.txt` lists those files and starts with the same note. A cancelled single-file export leaves nothing. **Export as .logarchive…** can be cancelled too: nothing is saved, and the message says if an existing `.logarchive` of that name had already been removed to be replaced.

---

### Export to a ZIP archive

Right-click a file or folder and choose **Export to ZIP…** to export it into a ZIP archive instead of a folder. A dialog asks where the archive goes (`.zip` is added if missing) and how it is written:

- **Structure in the archive** — where each entry goes:
  - *Only the file or folder itself, at the top* — `index.html`, or a folder as `www/…`.
  - *With its source path* — under the folders above it, from the root of its source: `var/www/index.html`, `var/www/…`. Those folders are stored as (empty) folder entries.

  and, for a folder, what happens with its contents:
  - *Folder contents in their folder structure* — `www/css/style.css`, `www/img/logo.png`.
  - *All files of a folder in one folder* — `www/style.css`, `www/logo.png`, from any depth; subfolders (empty ones too) aren't stored. A name the folder already holds gets a number (`style (2).css`), and each such file is listed in the renames list beside the archive with its path in the evidence, so where it came from stays on record.

  The dialog shows an example of where an entry goes with the choices made.
- **Compression** — *Deflate* (the standard; every tool opens it, Windows Explorer included), *No compression* (store), *BZIP2* or *LZMA* (smaller, but not opened by Windows Explorer). Deflate and BZIP2 take a **level** from 1 (fastest) to 9 (smallest).
- **Encrypt with a password (AES-256)** — the files' contents are encrypted (WinZip AES, 256-bit key). The names of files and folders, their sizes and times stay readable: the ZIP format can't hide them. Folder entries hold no data and are left unencrypted. Opens in 7-Zip, WinRAR, WinZip and others; Windows Explorer can't reliably open AES-encrypted archives, nor can Info-ZIP's `unzip` 6. The password is typed twice and never written to the log; the log records only that the archive is encrypted.
- **Split into parts of** N MB or GB — the archive is cut byte for byte into parts `name.zip.001`, `name.zip.002` …, each N in size but the last (1 MB = 1,000,000 bytes, so 4 GB parts fit on FAT32). 7-Zip opens `.001` directly; for other tools put the parts together first (`copy /b name.zip.001+name.zip.002 name.zip` on Windows, `cat name.zip.0* > name.zip` elsewhere). A split archive is always written new: if parts by that name are already there, you're asked before they are all replaced (left-over parts beyond the new last one are removed, so none reads as part of the new archive). Splitting and encryption can be combined.

The options are kept for the next ZIP export in the same window, but not the password.

If the archive doesn't exist yet, it is created. If it exists (and isn't split), you choose:

- **Add to Archive** — the export is added and the archive's other entries are kept.
- **Replace Archive** — a new archive replaces it.

When adding, and the archive already holds an entry under the same path, you're asked what to do with it (the dialog lists those entries):

- **Replace** — the entry in the archive is taken out and the export takes its place; for a folder, the folder with everything in it, so no file from the earlier export stays mixed in. Each replaced entry is named in the log.
- **Add Beside** — the export is stored next to it under a numbered name (`case (2)/`, `report (2).pdf`), so nothing is overwritten and no name appears twice; the new name is listed in the renames list beside the archive.

Replacing rebuilds the archive: its other entries are copied over as they are stored — still compressed, still encrypted, byte for byte — so it needs no password, even for entries encrypted with another one. Entries added to an existing archive are compressed and encrypted as the dialog says; the archive's other entries keep theirs, so an archive can end up with encrypted and unencrypted entries side by side.

A file that isn't a ZIP archive can only be replaced. Whether an entry is already in the archive is checked where the chosen structure puts it. Entries are compressed as chosen (ZIP64 for large files). Names are made Windows-safe as for a folder export.

**Entry times.** Each entry carries the source's modification time in UTC — in the DOS date fields and, where it fits (1901–2038), to the second in an Info-ZIP extended timestamp, which 7-Zip and `unzip` prefer. The time of the export is never used. Where the time comes from is listed for **every** entry in `www.zip.crush-export-times.txt` beside the archive, with the source time and the DOS time stored:

- `source` — the source's own time. DOS times count 2-second steps, so an odd second is stored one second earlier.
- `clamped` — the source's time is outside what the DOS fields hold (1980–2107): they hold the nearest they can, and the extended timestamp keeps the exact second where it fits.
- `none` — the source gives no time, or it can't be converted: the DOS fields hold the placeholder 1980-01-01 00:00:00 and there is no extended timestamp, so no tool shows it as a real time.

Folders on a source path carry their own times too — from search results as from the tree, as both take the path from the source's own nodes — and with entries from several sources, each source's folder carries the time of the source's root.

**How the export is documented.** With integrity mode on, a hash list goes **beside the archive**, named after it: `www.zip.crush-export-hashes.txt`. A split archive's lists are named `www.zip.split.crush-export-…`, so an archive and a split archive of the same name never overwrite or remove each other's lists. It starts with the time (UTC), how many files were written or added, the options (never the password) and the SHA-256 and size of the finished archive — for a split one, of each part and of the parts put together, which a hash list inside the archive couldn't hold. Then follows each file's SHA-256, size and path in the archive. Adding to an archive appends a section for that export, with the archive's new hash and any entries replaced; the earlier sections stay, their archive hash being of the archive as it was then. Replacing the whole archive writes a new list. Without integrity mode no list is written; one already beside the archive gets a note that the files added weren't hashed, or is removed when the archive it described is replaced.

**The archive holds only the exported files.** Two more lists go beside it, named after it, whenever there is something to list (with or without integrity mode): `www.zip.crush-export-renames.txt` (names changed: Windows-safe names, numbered clashes, files put into one folder — each with its path in the evidence) and `www.zip.crush-export-failed.txt` (files that couldn't be read, with the reason). Like the hash list, each starts with the time and the archive, gets a section appended when adding to the archive, and is replaced — or removed, if this export has nothing to list — when the archive is written anew. A file that can't be read is left out — no entry holds part of it; a single file that can't be read fails the export. The Crush log records the same: the options, each renamed, replaced or unreadable file, each file's SHA-256 and the archive's.

The archive is written to a temporary file beside it and only moved into place when complete. **Cancel**, an error or a crash therefore never leaves a partly written archive under its name, and an archive you were adding to (or replacing entries in) stays exactly as it was. Adding to an archive needs free space for a copy of it in the same folder.

#### Several entries at once

Select several files and folders in the tree (Ctrl/Shift-click), right-click one of them and choose **Export N selected entries to ZIP…**. The same dialog and choices apply to each entry. With the source path, entries from different levels keep where they came from:

```
private/var/mobile/a.db    ← a file, deep down
private/var/logs/x.log     ← a folder, one level higher, with its content
top.txt                    ← a file at the top
```

If the selection comes from several opened sources, each source's name comes first (`case/private/…`, `phone/…`), so their entries don't mix. An entry inside a selected folder is not stored twice: the folder brings it along. When adding to an archive, folders the archive already holds are shared; only a selected file or folder whose path is already in the archive is replaced or stored beside it, as you choose. A file that can't be read is left out and listed; the export still completes.
