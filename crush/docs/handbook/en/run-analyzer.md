### Run Analyzer

Right-click a directory node → **Run Analyzer** runs a small, curated forensic analyzer module against it and shows the result as a typed table in a new tab — unlike **Send to Peach** above, this is an embedded view, not a handoff to another application. Modules are ported from [iLEAPP](https://github.com/abrignoni/iLEAPP)/[aLEAPP](https://github.com/abrignoni/aLEAPP) artifact scripts by [Alexis Brignoni](https://github.com/abrignoni) (MIT License), run through the sibling project [crush-analyze](https://github.com/kalink0/crush-analyze) — a normal pip dependency, no separate binary to download or install.

Currently available modules:

| Module | What it shows |
|---|---|
| Installed Applications (iOS) | From `applicationState.db`'s `compatibilityInfo` per app: bundle ID, bundle container path, and sandbox (data) path. Can retain an app's entry even after it was uninstalled. |
| Installed Applications (Android, System) | The OS's own package manager record (`/system/packages.xml`): install/update time, installer and install-originator package, on-disk code path, public/private flags. Present for every installed app regardless of install source. |
| Installed Applications (Android, Play Store Cache) | The Play Store client's own local record: package name, title, first download/last update time, install reason, auto-update setting, and the Google account that did the installing. Covers only apps Play Store itself tracked installing. |

- Only files matching the selected module's own declared patterns are extracted from the source, not the whole right-clicked subtree — so this works against a full disk image or backup without extracting everything first.
- The result table supports search (all columns), click-to-sort per column (numeric columns sort as numbers, not lexicographically), right-click copy (cell/row/selection as TSV), a read-only value bar for copying part of a long cell, and CSV export of whatever's currently visible (i.e. filtered by the search box).
- The **Properties panel** shows this result's provenance: which parser it's based on (a link pinned to the exact upstream commit the module was vendored from, not the repo's current default branch), every source file that matched the module's patterns, tool version, run duration, and status.

---

