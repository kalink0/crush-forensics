## Exporting Files

Right-click any file or folder in the Filesystem panel and choose **Export…**. For folders, the entire subtree is exported preserving the directory structure. If the destination folder already has a same-named file or folder, you're asked to confirm before it's overwritten.

A file whose bytes can't be read from the evidence (for example, one a disk image's reader returns shorter than its recorded size) is not exported, and nothing is left under its name; the export goes on with the other files. When it's done, the message says how many files were not exported, and `crush-export-failed.txt`, next to the exported data, lists each one's path in the evidence and the reason.

---

