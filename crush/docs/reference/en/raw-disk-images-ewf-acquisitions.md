## Raw Disk Images & Forensic Acquisitions

**Open Disk Image…** (File menu and start screen; `crush --image PATH` on the command line) opens, in place, without mounting and without administrator rights:

- **raw disk images** — a whole disk, a single partition/filesystem dump or a flash dump, or a numbered `.001` segment of a split set;
- **forensic acquisitions** — EWF (Expert Witness Format, `.E01` + segments), SMART (`.s01`), EWF2 (`.Ex01`, EnCase 7), AFF (`.aff`, or an AFD: a `.afd` folder of `.aff` files) and AFF4 (`.aff4`);
- **Apple disk images** — UDIF (`.dmg`, also split into `.dmgpart` segments), sparse images (`.sparseimage`) and sparse bundles (a `.sparsebundle` folder);
- **virtual machine disks** — VHD, VHDX, VMDK and QCOW (versions 1 to 3), including a differencing disk, delta or overlay, read over its parent.

Only the bytes an examiner actually opens ever leave the image. A disk image found inside a folder, archive or another image opens the same way via right-click → **Open Disk Image in New Window**.

Supported filesystems: NTFS, FAT32, exFAT, ext2/3/4, F2FS, HFS+, APFS, QNX6, QNX4, ETFS, EFS, QNX IFS boot images, and the flash filesystems of embedded Linux devices: SquashFS 4.0, JFFS2, UBI/UBIFS, YAFFS1 and YAFFS2. MBR and GPT partition tables are read, GPT on disks with 512- and 4096-byte logical sectors (4Kn drives, UFS storage in current smartphones). A split `.001..NNN` dd set is joined automatically from whichever segment is opened; an acquisition joins its own numbered segments (`.E01`/`.E02`…, `.s01`…, `.Ex01`…) the same way, and an AFD opens whole from any `.aff` file in its folder. Built on [abrignoni/qnxprobe](https://github.com/abrignoni/qnxprobe) and [abrignoni/ewfprobe](https://github.com/abrignoni/ewfprobe).

A disk image is only read as one when opened this way. **Open file…**, drag & drop and Open Recent (for a file not opened as an image before) never probe a file for a disk image: recognising one means reading its partition table and filesystems, and for a file without either, scanning up to all of it for flash filesystems — a cost every other file opened would pay. Such a file opens as an ordinary file; when its content or name suggests an image, a banner above the opened file says so, with a button that opens it as a disk image (the status bar says the same) — the same when such a file is selected inside an opened folder, archive or image. The banner shows every note on how the opened file itself opens otherwise (also a ZIP after leading bytes, or a file that is itself an archive), with a button for each way Crush can open it. A note about a whole source (an AFF4 shown as its ZIP, a sparse bundle shown as its folder) is in the status bar with every file opened from it, not as a banner. A file on disk (opened directly, or in an opened folder) is checked with the image reader's own recognition, by content: every container listed above, including those whose only signature is not at the start (a fixed VHD's footer, a UDIF trailer, an AFF4's ZIP comment). A file inside an archive or image is checked by the signature in its first bytes. Either way the name counts too: `.img`, `.dd`, `.raw`, `.E01`, `.s01`, `.Ex01`, `.aff`, `.aff4`, `.dmg`, `.dmgpart`, `.sparseimage`, `.vhd`, `.vhdx`, `.vmdk`, `.qcow`, `.qcow2`, a numbered segment `.001`–`.999`, and the flash dump names `.nand`, `.ubi`, `.ubifs`, `.squashfs`, `.sqsh`, `.jffs2`, `.yaffs2`. `.bin` gets no such hint: too many other files carry it. Open Recent remembers which entries were opened as disk images and reopens them the same way.

**AFF4** is stored as a ZIP. Opening one normally asks, as for an iTunes backup inside a ZIP, whether to read it as a disk image; choosing "No" shows the ZIP's members (the container's own streams, maps and metadata), with a note saying it is an AFF4 container. A ZIP the ZIP reader refuses opens as a single file, with the reason and the same note.

An **Apple sparse bundle** is a folder (`Info.plist`, `token`, and a `bands/` folder of equal-sized band files that together hold the disk), recognised by its `Info.plist`, not its name. Typical places: Time Machine backups to a network share or Time Capsule, and encrypted containers made with Disk Utility or `hdiutil`. Opening such a folder asks whether to read it as a disk image; choosing "No" shows the folder's files, with a note saying it is a sparse bundle. Open Disk Image… on any file of a bundle (its `Info.plist`, a band — the file picker can't pick a folder) opens the whole bundle, and the status bar says which file it was opened from; a file of a bundle opened normally points at Open Disk Image…. The root note says how many band files were read; a band that isn't stored reads as zeros, as hdiutil reads it.

Logical evidence — EnCase `.L01` and FTK Imager `.ad1`, recognised by their signatures — is not a disk image: it holds copies of files and opens as a source of its own (see Logical Evidence), also when picked with Open Disk Image…. EnCase `.Lx01` is not read: the banner and the status bar say so (with no button), and Open Disk Image… refuses it with that reason.

Once opened as a disk image, what it holds is recognised by its content — an MBR/GPT partition table or a filesystem it can read — not by its file name, so `.bin` or extensionless images open the same way as `.img`/`.dd`. If no readable filesystem is found in a raw image, a dialog says why (e.g. a split set with a missing segment) and the file opens as an ordinary file (Hex View) instead — its own bytes are the disk. A container (acquisition, Apple disk image, virtual disk) stays open even then: its file holds the container (compressed chunks, headers, allocation tables), not the disk, so the disk is listed as one region that isn't recognised, readable in Hex View and verifiable. A container the reader refuses opens as an ordinary file with the reason — e.g. an encrypted Ex01, an encrypted AFF4, a QCOW encrypted with LUKS, an Ex01 or AFF compressed with bzip2, an AFF that records no image size (it may be incomplete), an AFD with a gap in its file numbering, or a differencing disk whose parent isn't beside it. Containers and split sets are the exception to name-independence: their other files are found by name — segments by their `.E01`/`.s01`/`.Ex01`/`.001`/`.dmgpart` extensions, an AFD by its `.afd` folder name, a VMDK's extents and a differencing disk's parent by the name the container records — so they must keep those names.

The root of an opened container says what the disk is read from, in the reader's words: the container, how many files were joined (first .. last), the parent a differencing disk, delta or overlay is read over, and what opened an encrypted one — e.g. *Read as a VHD virtual disk of one file, over its parent dynamic.vhd*. A differencing disk's files can come from its parent; the note is what tells which files the disk was read from.

### Encrypted containers

An encrypted Apple disk image (`hdiutil -encryption`, AES-128 or AES-256), an E01, SMART or raw (dd) set FTK Imager encrypted with AD encryption, and an AFF encrypted with AFFLIB open with their password. When the container is sealed to a certificate instead (or as well), it opens with that certificate's private key: an unencrypted RSA key file, PEM or DER. Crush asks for one when opening, with the reader's reason (e.g. *opens only with its password or its private key*); a container sealed only to a certificate is asked for the key file alone. A password or key that doesn't open it is refused with the reason and asked for again; a key file that can't be read as a key is asked for again too. The root note says what opened it. Reading these needs the pycryptodomex package, which Crush installs; without it the reader refuses with that reason.

A volume encrypted inside the disk (BitLocker, an encrypted APFS volume, FileVault) is a different thing: the container opens, and the volume is named with what would open it but not read — see Known limitations.

A GPT is used only when its header passes the checks in UEFI 2.10 section 5.3.2 (signature, header CRC32, MyLBA, CRC32 of the partition entry array); when the primary header fails, the backup header in the last block is read. A disk whose primary and backup GPT headers both fail these checks shows no partitions from that table.

A **flash dump** (e.g. a `nanddump` of a router, camera or older Android phone) usually has no partition table. It is recognised by the SquashFS, UBI, JFFS2 or YAFFS structures it holds; NAND spare (OOB) bytes in the dump are detected and stripped by the reader, and the YAFFS page/spare layout is found by trying the common geometries. A U-Boot environment or a Belkin NVRAM store in the dump, which has no filesystem around it, is found by its CRC-32 and shown as a volume holding one file with the store's bytes.

**zstd-compressed SquashFS/UBIFS** can only be read on Python 3.14 or newer, which current Crush builds don't use. Such a volume is identified but lists nothing; the volume's **Entry status** says so, so it doesn't look like an empty filesystem.

### Volume tree

Each partition or bare filesystem qnxprobe finds becomes one top-level node, named after its LBA offset (e.g. `p3_lba239616_basic_data_partition`, or `lba0` for an unpartitioned image) so two volumes can never collide. This mirrors the naming a report from the underlying reader itself would use, so it's recognizable if cross-referenced against another tool's output (e.g. `mmls`).

**Nothing is hidden**, in keeping with this project's general rule that a forensic tool must never make part of the source look less accessible than it actually is:

- **Unallocated space** — the bytes before, between, and after partition table entries (alignment padding, trailing slack) are not something the underlying reader reports on its own; Crush computes these gaps itself and lists them as their own readable leaf nodes.
- **A partition with an unsupported filesystem** — one qnxprobe's partition-table parsing finds but has no reader for (or doesn't recognize the filesystem inside at all) — is still listed, as a plain file rather than a folder, and is fully readable as the raw bytes of that region (opens in Hex View via the normal "no parser matched" fallback).
- In both cases, selecting the node shows an explicit **Filesystem** / **Status** entry in the Properties panel explaining what it is and why it isn't parsed, instead of just an unremarkable file size.

### Named streams

Content a file carries beside its own is listed as a node of its own, next to the file, named `file:stream` (a stream on the volume's root folder is `:stream`):

- **NTFS alternate data streams** — e.g. `report.pdf:Zone.Identifier`, the download origin Windows records. Readable like any file (Hex View, hash, export). A stream whose front is a hole (e.g. `$Extend/$UsnJrnl:$J`, whose freed front Windows leaves as a hole) is read from its first stored cluster; the node's **Entry status** says how many bytes of hole were left out, which is also how far an offset in the view is from the offset in the stream. A stream that stores nothing (every cluster a hole, e.g. `$BadClus:$Bad`) is listed with its recorded size in the status and no content.
- **HFS+ resource forks** and **APFS extended attributes kept in a stream of their own** are listed with their recorded size in the status, but not read: the underlying reader names them and has no reader for their content yet. APFS extended attributes stored inline, inside their record, are not listed.

A stream is not part of the file's size, content or hash.

### Files the volume does not hold in full

On NTFS, a file's recorded size is not always what the volume stores for it:

- **Online-only cloud placeholders** (e.g. OneDrive Files On-Demand) keep the file's name, size and dates on the volume and none of its content, which is with the provider. The file is listed at its recorded size, and reading it fails with the reader's reason instead of returning zeros of that size.
- **Files compressed by the Windows overlay filter** (WOF: `compact /exe`, CompactOS) keep their content in a `WofCompressedData` stream and leave the file's own data stream as a hole. With XPRESS compression (4K, 8K and 16K chunks) the file shows its content. With LZX it is not decoded, and reading it fails with that reason.
- **Sparse files** read at their recorded length, with zeros where the volume stores nothing, as the operating system would return them.

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

### Verifying an acquisition

Right-click the root of a container (an acquisition, Apple disk image or virtual disk) and choose **Verify Acquisition Hash…** to recompute its MD5/SHA1 over its full contents and compare against the hash the acquisition tool stored when it was created — the same check `ewfacquire`/`ewfverify`-style tooling performs, done entirely with Crush's own bundled reader (no external tool, no network). Not run automatically on opening: an acquisition can be very large, and re-reading all of it on every open would defeat the point of reading it on demand in the first place. A container that recorded no hash at all says so explicitly rather than reporting a silent, meaningless "match" — virtual disks never record one. Chunks that fail their own checksum and AFF pages the acquisition declares but doesn't hold are named in the result either way. Such a missing page reads as the image's bad-sector marker, not as data from the device; the source's **Entry status** and the status bar say so as soon as it is opened.

What a container records about its own data besides a hash of the disk is recomputed in the same pass and every check is listed with its stored and computed value: a UDIF image's data, block table and master checksums (CRC32 or MD5), and an AFF4's stream, chunk and map hashes. Any that doesn't match is named as a mismatch, also when the container recorded no hash of the whole disk.

### Known limitations

- **Containers not read** — VDI disk images, AFM, EnCase Lx01 logical evidence, encrypted Ex01, encrypted AFF4 and AFF4-L, an Apple disk image unlocked by a keybag or in the older version 1 encrypted format, a QCOW encrypted with LUKS, a VMDK SESPARSE extent, and a VHD split into `.v01` files. Each is refused with the reason.
- **Volumes encrypted inside the disk** — a locked BitLocker volume, an encrypted APFS volume and FileVault are named with what would open them, not read; Crush has no way to give the password, recovery password or key file for them yet.
- **Named streams of deleted files** are not listed in `$Recovered`.
- **No other filesystems yet** — notably Btrfs, XFS, and LittleFS (common on smartwatches and other small embedded/IoT devices) are not covered by the underlying reader.
- **No snapshot support** — NTFS Volume Shadow Copies and APFS snapshots are not read; only the filesystem's current, live state (plus the deleted-file recovery above) is available.
- **Deleted-file recovery is NTFS/FAT32/exFAT/YAFFS2/JFFS2/UBIFS only** — ext2/3/4, F2FS, HFS+, APFS, YAFFS1, SquashFS (read-only, nothing is deleted) and the QNX filesystems have no equivalent in the underlying reader.
- **Flash readers and real devices** — SquashFS and JFFS2 have been validated only against images written by their own tools and the Linux kernel; YAFFS2 and UBIFS have also been read off real device dumps (see the qnxprobe README).

---

