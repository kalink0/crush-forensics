## Logical Evidence (L01, AD1)

Logical evidence holds copies of the files and folders an examiner selected, not a disk: there is no partition table, no filesystem and no unallocated space. Crush opens **EnCase `.L01`** and **FTK Imager `.ad1`** (AD1 version 4) as a source of their own, read in place with [abrignoni/ewfprobe](https://github.com/abrignoni/ewfprobe). They are recognised by their signature on **Open file…**, drag & drop, and inside an opened folder, archive or image (right-click → **Open in New Window**). A set of several files (`.L01`/`.L02` …, `.ad1`/`.ad2` …) opens whole from any of its files; the root note names the files it was read from.

The tree is the set's own entry list, shown as stored:

- **An entry with data of its own and entries beneath it** — an L01 plist with its parsed children, an AD1 file with a named stream, an AD1 folder with its index data — is shown as a folder. Its own data is an entry inside that folder, under the same name, with an **Entry status** saying so. Nothing is hidden behind the entries beneath it.
- **AD1 entries FTK Imager marks as deleted** are listed with an Entry status saying so, and read like any other entry.
- **An L01 entry marked sparse** reads from the data its duplicate data offset points to (or as one stored byte repeated to its size); its Entry status says which.
- **Repeated names** are numbered like other same-named entries (`name`, `name (2)` …). Names can hold `\` and `:` (an AD1's top entries are named for their sources, e.g. `U:\:AD1LEAN [NTFS]`); a `/` in a name is shown as `∕`, and the Entry status says so.

The Properties panel shows each entry's **Recorded MD5** and **Recorded SHA-1** as the acquisition tool took them (or *(not recorded)*), and its times with where they come from: an AD1's `created`, `modified` and `accessed` records and an L01's `cr`, `ac`, `wr` and `mo` columns, in UTC. An L01's deletion (`dl`) and acquisition (`aq`) times are listed beside them; an AD1's item type and type record are shown as stored.

**Verify Acquisition Hash…** (right-click the root) recomputes the image hash and every entry's recorded MD5 (and an AD1's SHA-1), and lists every file whose hash doesn't match. It also says how many files have no recorded hash and so were not checked — often most of them in an L01 — and, for an L01, how many have a recorded SHA-1, which isn't checked (the reader checks an L01's MD5 only). An L01 records no hash of its whole data, only of its files. **An AD1 doesn't hold its image hash at all**: FTK Imager writes it to its log beside the image (`<name>.ad1.txt`), a separate text file; the result names the log it was read from, or says it wasn't found.

An **AD-encrypted AD1** (password or certificate) shows what it holds only once opened: opened normally it is a single file pointing at **Open Disk Image…**, which asks for the password or the certificate's private key and then opens it as logical evidence (see Encrypted containers under Raw Disk Images & Forensic Acquisitions).

### Known limitations

- **Lx01** (EnCase 7 logical evidence, EWF2) is not read; it opens as a single file and says so.
- **Segment names** — an L01's segments are found by their names (`.L01`, `.L02` …), as for an E01: an L01 renamed to anything else is recognised but opens as a single file, with the reader's reason.
- **AD1 versions** other than 4 are refused with the reason.

---

