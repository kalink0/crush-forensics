## Integrity Mode

Integrity mode adds hashing and traceability to file access:

- When enabled, files opened or exported are hashed (SHA-256) and written to the log.
- Opening a ZIP/TAR/7z/file triggers the calculation of the hash (SHA-256) of the file.
- Opening a folder does not hash the full directory.
- **Open in New Window** hashes the member while it is being extracted (one pass) and logs it.
- Exports also create a `crush-export-hashes.txt` file next to the exported data.
- An entry whose entry status says no content is read or stored (a special file such as a FIFO or device, a link whose target isn't decoded, an entry with no content in a backup …) is not hashed: the SHA-256 of no bytes would pass for the hash of real content. On open and extraction the log records `INTEGRITY not hashed: no content read  path=…`; an export still writes its (empty) file, so the exported structure stays complete, and lists it in `crush-export-hashes.txt` as `not hashed: no content read (<entry status>)` instead of a digest, logging `INTEGRITY export not hashed: no content read`.
- The SHA-256 of a file opened, extracted or exported is also shown in the Properties panel as **SHA-256 (computed)** while its source is open. A later **Compute Hash** reads the file again and is compared against it: a different value is shown next to the first, with a warning. The hash of a source file itself (on open) is in the log only.
- Hashing a source or a file being opened can be cancelled in its dialog. The data still opens; the log records `INTEGRITY ... not hashed: hashing cancelled by the analyst` and the status bar says it was not hashed. A later export hashes what it writes as usual.
- The bottom-right status badge shows the current mode. Click the badge to toggle it, or right-click it for a quick menu and a short explanation.

---

