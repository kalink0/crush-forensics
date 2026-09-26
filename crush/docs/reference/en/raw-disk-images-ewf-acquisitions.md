## Raw Disk Images & EWF Acquisitions

**Open Disk Image…** (File menu and start screen; `crush --image PATH` on the command line) opens raw disk images (a whole disk, a single partition/filesystem dump or a flash dump, or a numbered `.001` segment of a split set) and EWF (Expert Witness Format, `.E01` + segments) acquisitions — in place, without mounting and without administrator rights. Only the bytes an examiner actually opens ever leave the image. A disk image found inside a folder, archive or another image opens the same way via right-click → **Open Disk Image in New Window**.

Supported filesystems: NTFS, FAT32, exFAT, ext2/3/4, F2FS, HFS+, APFS, QNX6, QNX4, ETFS, EFS, QNX IFS boot images, and the flash filesystems of embedded Linux devices: SquashFS 4.0, JFFS2, UBI/UBIFS, YAFFS1 and YAFFS2. MBR and GPT partition tables are read, GPT on disks with 512- and 4096-byte logical sectors (4Kn drives, UFS storage in current smartphones). A split `.001..NNN` dd set is joined automatically from whichever segment is opened; an `.E01` acquisition joins its own numbered segments the same way. Built on [abrignoni/qnxprobe](https://github.com/abrignoni/qnxprobe) and [abrignoni/ewfprobe](https://github.com/abrignoni/ewfprobe).

A disk image is only read as one when opened this way. **Open file…**, drag & drop and Open Recent (for a file not opened as an image before) never probe a file for a disk image: recognising one means reading its partition table and filesystems, and for a file without either, scanning up to all of it for flash filesystems — a cost every other file opened would pay. Such a file opens as an ordinary file; when its name or signature suggests an image (`.img`, `.dd`, `.raw`, `.E01`, a numbered segment `.001`–`.999`, the flash dump names `.nand`, `.ubi`, `.ubifs`, `.squashfs`, `.sqsh`, `.jffs2`, `.yaffs2`, or the EWF signature), the status bar says to use Open Disk Image… — the same when such a file is selected inside an opened folder, archive or image. `.bin` gets no such hint: too many other files carry it. Open Recent remembers which entries were opened as disk images and reopens them the same way.

Once opened as a disk image, what it holds is recognised by its content — an MBR/GPT partition table or a filesystem it can read — not by its file name, so `.bin` or extensionless images open the same way as `.img`/`.dd`. If no readable filesystem is found, a dialog says why (e.g. a split set with a missing segment) and the file opens as an ordinary file (Hex View) instead. EWF acquisitions and split sets are the exception to name-independence: their segments are found by name, so they must keep their `.E01`/`.001` extensions.

A GPT is used only when its header passes the checks in UEFI 2.10 section 5.3.2 (signature, header CRC32, MyLBA, CRC32 of the partition entry array); when the primary header fails, the backup header in the last block is read. A disk whose primary and backup GPT headers both fail these checks shows no partitions from that table.

A **flash dump** (e.g. a `nanddump` of a router, camera or older Android phone) usually has no partition table. It is recognised by the SquashFS, UBI, JFFS2 or YAFFS structures it holds; NAND spare (OOB) bytes in the dump are detected and stripped by the reader, and the YAFFS page/spare layout is found by trying the common geometries.

**zstd-compressed SquashFS/UBIFS** can only be read on Python 3.14 or newer, which current Crush builds don't use. Such a volume is identified but lists nothing; the volume's **Entry status** says so, so it doesn't look like an empty filesystem.

### Volume tree

Each partition or bare filesystem qnxprobe finds becomes one top-level node, named after its LBA offset (e.g. `p3_lba239616_basic_data_partition`, or `lba0` for an unpartitioned image) so two volumes can never collide. This mirrors the naming a report from the underlying reader itself would use, so it's recognizable if cross-referenced against another tool's output (e.g. `mmls`).

**Nothing is hidden**, in keeping with this project's general rule that a forensic tool must never make part of the source look less accessible than it actually is:

- **Unallocated space** — the bytes before, between, and after partition table entries (alignment padding, trailing slack) are not something the underlying reader reports on its own; Crush computes these gaps itself and lists them as their own readable leaf nodes.
- **A partition with an unsupported filesystem** — one qnxprobe's partition-table parsing finds but has no reader for (or doesn't recognize the filesystem inside at all) — is still listed, as a plain file rather than a folder, and is fully readable as the raw bytes of that region (opens in Hex View via the normal "no parser matched" fallback).
- In both cases, selecting the node shows an explicit **Filesystem** / **Status** entry in the Properties panel explaining what it is and why it isn't parsed, instead of just an unremarkable file size.

### Deleted files

For **NTFS, FAT32, exFAT, YAFFS2, JFFS2 and UBIFS** volumes (the filesystems the underlying reader has this for), a `$Recovered` folder appears alongside the live files. On NTFS/FAT32/exFAT it contains every directory/MFT record still on disk whose entry is marked free but hasn't yet been overwritten — this is filesystem-level deletion, not the Recycle Bin. A file sitting in `$Recycle.Bin` (NTFS) is a completely ordinary, live file from the filesystem's point of view and already appears in the normal tree; `$Recovered` is a level below that: records for files already removed from (or bypassing) the Recycle Bin, recoverable only because the filesystem hasn't reused that specific record/directory slot for something else yet.

- Every entry is listed, including ones judged **not recoverable** (data clusters already reused, attributes overflowed the record, or it's a deleted directory — recursing into a deleted directory's own contents isn't attempted). The Properties panel states the reason; attempting to open one of these shows a clear error rather than wrong or partial bytes.
- Recovered files are placed **flat** under `$Recovered`, not reassembled into the folder structure they were originally deleted from.
- **FAT32 specifically** cannot recover a deleted file's first character — the delete operation overwrites exactly that byte on disk. Such a name is shown with a leading `_` in place of the lost character (the same convention long used by DOS/Windows undelete tools), e.g. a deleted `one.jpg` reappears as `_ne.jpg`. The file's **content** is unaffected by this and is recovered exactly. exFAT does not have this limitation.

**YAFFS2, JFFS2 and UBIFS** never overwrite in place: a change is written to a new page or node and the old one stays until garbage collection erases its block. A deleted file's last name, size, modification time and content can therefore outlive the deletion, and each one still on the flash is listed in `$Recovered`:

- A file is readable only when every page, node or block its recorded size needs is still on the flash; otherwise the Properties panel says how many are missing and opening it shows an error rather than a partial copy.
- The Properties panel shows the **Original folder** the file was deleted from, or says that folder no longer exists.
- Where the recovery had to decide something the flash doesn't record, the status says so. On YAFFS2, deleting a file first writes a size-0 header for it; a file truncated to 0 just before its deletion leaves the same header, so such a file is recovered as the header before that one describes it, with a **recovery note** saying this.
- A file whose last copy was superseded several times (e.g. rewritten, then deleted) can appear more than once, numbered like other same-named entries.
- YAFFS1 deleted files are not recovered: its chunks carry only a 2-bit serial number, which can't say which copy of a page a deleted file last held.

### Verifying an EWF acquisition

Right-click the root of an EWF-backed source and choose **Verify EWF Hash…** to recompute the acquisition's MD5/SHA1 over its full contents and compare against the hash the acquisition tool stored when it was created — the same check `ewfacquire`/`ewfverify`-style tooling performs, done entirely with Crush's own bundled reader (no external tool, no network). Not run automatically on opening: an acquisition can be very large, and re-reading all of it on every open would defeat the point of reading it on demand in the first place. An acquisition that recorded no hash at all says so explicitly rather than reporting a silent, meaningless "match".

### Known limitations

- **No other container formats yet** — AFF4, VMDK, VDI, and QCOW disk images are not supported; only raw/dd images and EWF (.E01).
- **No other filesystems yet** — notably Btrfs, XFS, and LittleFS (common on smartwatches and other small embedded/IoT devices) are not covered by the underlying reader.
- **No snapshot support** — NTFS Volume Shadow Copies and APFS snapshots are not read; only the filesystem's current, live state (plus the deleted-file recovery above) is available.
- **Deleted-file recovery is NTFS/FAT32/exFAT/YAFFS2/JFFS2/UBIFS only** — ext2/3/4, F2FS, HFS+, APFS, YAFFS1, SquashFS (read-only, nothing is deleted) and the QNX filesystems have no equivalent in the underlying reader.
- **Flash readers and real devices** — SquashFS and JFFS2 have been validated only against images written by their own tools and the Linux kernel; YAFFS2 and UBIFS have also been read off real device dumps (see the qnxprobe README).

---

