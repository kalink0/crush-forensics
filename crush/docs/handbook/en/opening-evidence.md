## Opening Evidence

Use the **File** menu to load a source:

| Menu item | When to use |
|---|---|
| **Open file…** | Any single file — image, database, plist, ZIP, TAR, 7z, etc. Crush detects the type automatically. ZIP, TAR, and 7z archives are opened as browsable trees; other files open directly in a viewer tab. Archives are recognised by their content, not their name: a ZIP named `.bin`, `.apk`, `.ipa` or `.docx` opens as a ZIP, and a UFDR opens as a UFDR whatever it is called. A file named like an archive whose content isn't one opens as a single file, and the status bar says so. |
| **Open folder…** | Already-extracted acquisition or any folder of files on disk |

Opening a file (**Open file…**) appends it to the existing tree as a new root node, so multiple files can be open side by side. Opening a folder replaces the current tree.

You can also **drag and drop** files, archives, or folders straight onto the Crush window instead of using the File menu — it follows the exact same rule: a dropped file appends, a dropped folder or archive (anything that opens as its own browsable tree) replaces. Dropping several items at once loads them one after another. Works the same on Windows, macOS, and Linux.

A third way: pass paths on the command line — `crush /path/to/evidence.zip /path/to/case_folder` or `crush --open /path/to/evidence.zip` (repeatable) — to have Crush open them on startup instead of loading manually. Each invocation opens a fresh window. Useful for launching Crush from another tool with evidence already queued up.

Add `--focus REL_PATH` (only valid with exactly one file/folder to open) to also select and open one specific file inside it on startup — e.g. `crush /path/to/evidence.zip --focus Documents/chat.db` opens the archive and jumps straight to that file, instead of just showing the tree. `REL_PATH` is relative to the opened target's own root. A single file passed directly (not a folder/archive) already opens itself regardless of `--focus`.

### Large files, memory and the temp directory

Most viewers need a file's bytes in memory — often several times over (raw bytes, decoded structures, widgets). Crush therefore checks a file's size against the memory that is free right now before it loads one (double-click, or any **Open as** mode):

- Up to about a quarter of free memory it just opens.
- Above that it asks what to do: **Open anyway**, **Open in New Window** (opens the file as a source of its own, so an archive or backup becomes browsable; not offered for a file on disk whose content holds nothing to browse, but always offered for a member of an archive or image, since only extracting it would tell; a disk image opens via right-click → **Open Disk Image in New Window** instead), **Export…**, or **Cancel**. **Open anyway** is not offered once the file is more than about 80 % of free memory — it could not realistically fit.
- Nothing is ever cut short: a file is opened whole or not at all.

**Compressed tar archives** (`.tar.gz`, `.tar.xz`, `.tar.bz2`) have no index. Crush reads the whole stream once to build the tree — the loading dialog stays up until that pass ends — and keeps the first bytes of every file during it, so browsing and type detection afterwards need no further reading. Opening one file's content still decompresses everything before it, behind a wait dialog. For big compressed tars, extract once to a fast disk or ask for ZIP/plain TAR.

Archive members, disk-image files and backups are streamed rather than unpacked into memory, so hex-viewing, hashing, exporting and **Open in New Window** work on multi-gigabyte members without exhausting RAM. Reading, hashing and searching larger files runs behind a wait dialog so the window keeps responding.

**Tools → Temp Directory…** sets where Crush puts every temporary file: extracted archive members, database copies, log conversion. Leave it blank to use the OS default — but on many Linux systems `/tmp` is a RAM-backed *tmpfs*, so extracting a large member there fills memory instead of disk. Point it at a disk with plenty of free space. Before a large extraction Crush checks the free space and warns if the location is too small or RAM-backed, and lets you pick another directory on the spot.

---

