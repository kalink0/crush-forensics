## Cellebrite UFDR

**Open file…** also accepts a Cellebrite Physical Analyzer report container (`.ufdr`), opened in place — the archive isn't extracted first. The tree shown is the original device's own filesystem, e.g. `/data/app/...`, `/data/data/com.example.app/...`, reconstructed from the container's embedded PostgreSQL dump rather than the container's own internal, type-bucketed storage layout (Cellebrite's `files/Application/...`, `files/Image/...`, and so on). Selecting a file shows Cellebrite's own recorded MD5/SHA-256 and category in the Properties panel.

Only UFDR 10.x is supported (the version that embeds the actual database — earlier UFDR 7 exports do not and aren't covered). If a node's bytes can't be located in the container, it still appears in the tree with an explicit "not located in container" status rather than opening as empty or wrong content.

### Known limitations

- **Filesystem browsing only** — Cellebrite's own decoded forensic tables (contacts, calls, chats, locations, and the rest of Physical Analyzer's ~185 other tables) are not read or shown; use Cellebrite Reader for those.
- **No split/segmented UFDR exports** — a case exported as multiple `.ufdr` parts is not supported; open a single, complete `.ufdr`.
- **UFDR 10.x only** — UFDR 7 containers (no embedded database) are not supported.
- **No encrypted UFDR containers** — not yet supported.

---

