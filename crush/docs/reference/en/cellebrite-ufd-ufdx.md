## Cellebrite UFD and UFDX

A `.ufd` is the small text file UFED writes beside an extraction; tools that rebuild UFED's layout, such as UFADE, write one too. It names the files the extraction consists of (usually a ZIP) and how to read them. A `.ufdx` lists several extractions of one device, each by its `.ufd`. **Open file…** accepts either and opens the extraction(s) they describe. Both are recognised by their content, whatever their name.

- **Each dump is a folder named as in the `.ufd`** — e.g. `FileDump` (the device's file system) and `KeyStore`, each holding the ZIP folder the `.ufd` names for it (`Dump`, `extra`, `iPhoneDump`). Its **Entry status** says which folder of which file it is.
- **A `.ufdx` gives each extraction a folder** named after the folder its `.ufd` is in (e.g. `EXTRACTION_FFS 01`), holding what that `.ufd` opens.
- **An iTunes backup inside a dump opens as the backup**, recognised by its content, not by its folder's name. The backup's tree replaces the folder that holds its stored files. If the `.ufd` records a `BackupPassword`, it is used. When that password doesn't open the backup, or none is recorded for an encrypted one, Crush asks for it. The folder's **Entry status** says which password opened it. The backup's own files are extracted to the temp directory first; to see the files the ZIP stores for it, open the ZIP on its own.
- **What the ZIP holds outside the dumps' folders** is shown in a folder `(other content of <zip>)`, never left out.
- **The Properties panel of the root** (and, in a `.ufdx`, of each extraction's folder) shows every value the `.ufd` records, as written — device, tool, case fields, start and end time with the UTC offset as the `.ufd` writes it, without conversion.
- **Verify Acquisition Hash…** on the root recomputes the SHA-256 the `.ufd` records for each of its files and compares them. A file it names that isn't there is a failed check. The HMAC UFED records is keyed with Cellebrite's key and can't be recomputed: the result names it as not checked.

Opening the ZIP on its own works as before: nothing is read from a `.ufd` beside it.

### Known limitations

- **ZIP dumps only** — a dump of another type (e.g. a physical image) is listed with a status saying it isn't read.
- **Only what the `.ufd` names** — files beside it that it doesn't name (a UFADE `.case.json`, `SummaryReport.pdf` when not listed) aren't opened.

---

