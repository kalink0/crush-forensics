## Exporting Files

Right-click any file or folder in the Filesystem panel and choose **Export…**. For folders, the entire subtree is exported preserving the directory structure. If the destination folder already has a same-named file or folder, you're asked to confirm before it's overwritten.

A file whose bytes can't be read from the evidence (for example, one a disk image's reader returns shorter than its recorded size) is not exported, and nothing is left under its name; the export goes on with the other files. When it's done, the message says how many files were not exported, and `crush-export-failed.txt`, next to the exported data, lists each one's path in the evidence and the reason; with integrity mode on, `crush-export-hashes.txt` notes the count too. Exporting a single file that can't be read fails, with the reason, and puts nothing into the destination folder.

**Cancel** in the export dialog (or Esc) stops the export before the next file, or mid-file. The file being copied is removed, so no file is left partly written under its name. What was exported until then stays, and `crush-export-cancelled.txt` next to it says the export is incomplete and how many files were exported; with integrity mode on, `crush-export-hashes.txt` lists those files and starts with the same note. A cancelled single-file export leaves nothing. **Export as .logarchive…** can be cancelled too: nothing is saved, and the message says if an existing `.logarchive` of that name had already been removed to be replaced.

---

