## Integrity Mode

Integrity mode adds hashing and traceability to file access:

- When enabled, files opened or exported are hashed (SHA-256) and written to the log.
- Opening a ZIP/TAR/7z/file triggers the calculation of the hash (SHA-256) of the file.
- Opening a folder does not hash the full directory.
- **Open in New Window** hashes the member while it is being extracted (one pass) and logs it.
- Exports also create a `crush-export-hashes.txt` file next to the exported data.
- The bottom-right status badge shows the current mode. Click the badge to toggle it, or right-click it for a quick menu and a short explanation.

---

