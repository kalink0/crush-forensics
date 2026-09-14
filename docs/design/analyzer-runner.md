# Analyzer Runner (`crush-analyze`) — design

Status: **design only, nothing built yet.** This document is the frozen
starting point for implementation; see "Rollout order" at the end for the
intended build sequence.

## Motivation

Crush occasionally wants to run a small, focused parsing task that already
exists as a LEAPP (iLEAPP/aLEAPP/rLEAPP) artifact module — e.g. "installed
apps" — without pulling LEAPP's full suite, dependency tree, or its own
report/UI machinery into Crush's process.

Two related questions came up together and are answered by the same design:

1. How should Crush gain small, curated external parsing capabilities like
   this, without growing into a general-purpose forensic suite?
2. Should Crush expose a real plugin API (parsers *and* viewers) so third
   parties can extend it in-process?

**Decision on (2): no.** A full in-process plugin API is a much bigger,
open-ended commitment than the value it buys right now:

- Crush's internals still churn — there is no stable ABI to freeze.
- Third-party code running in-process with access to evidence data is a
  real concern for a forensics tool (chain-of-custody, trust boundary).
- Frozen-build packaging (PyInstaller) makes dynamically loading foreign
  code at runtime awkward.
- Qt widget APIs are far harder to keep stable across releases than a data
  contract.

**Decision on (1): a separate CLI sibling tool + a versioned JSON result
contract**, modeled on the already-shipped Peach handoff (`peach-launcher`):
own repo, own release pipeline, bundled into Crush's build exactly like
`peach-forensics` and `unifiedlog_iterator` are. This buys Crush a small,
curated set of "view kinds" (typed columns + rows) instead of real viewer
plugins, while adding the one leg Peach deliberately doesn't have: reading a
result back into Crush's UI.

## Non-goals

- No dynamic/user-installable plugin system.
- No arbitrary third-party code execution inside Crush's own process.
- No Qt widget plugin API.
- No systematic harvesting of LEAPP's whole module catalog — only the
  handful of modules Crush actually wants, ported one at a time.

## Naming

Working name: `crush-analyze`. Not finalized.

## Packaging (production path)

**Corrected during step 4 — does NOT mirror `peach-forensics`.** Peach
needs a compiled binary because it's Rust and Crush is Python; the two
can't share a runtime, so a subprocess spawn of a separately-built,
separately-versioned executable is the only option. `crush-analyze` is
pure Python with the same runtime as Crush itself, so building it as an
opaque platform binary (own PyInstaller build, 4-platform CI, a
`download_crush_analyze_binaries.py` script, `--add-data` bundling, the
Windows onefile cache-to-`%LOCALAPPDATA%` fix Peach needed) would solve a
cross-language interop problem that doesn't exist here — pure overhead,
not caution.

**What's actually done:**

- `crush-analyze` is a normal pinned pip dependency of crush-forensics
  (`pyproject.toml`, `crush-analyze @ git+https://github.com/kalink0/
  crush-analyze.git@<full-commit-sha>`). Every existing `pip install .`
  step in crush-forensics' `ci.yml`/`build.yml`/`nightly.yml` already
  resolves it — no new CI step, no separate release pipeline. Bumping to a
  newer crush-analyze commit is an ordinary dependency-pin edit, the same
  as bumping any other pinned package.
- crush-analyze ships its own PyInstaller hook
  (`crush_analyze/__pyinstaller/`, registered via the `pyinstaller40`
  entry-point group in its `pyproject.toml`) so any PyInstaller build that
  has it installed automatically bundles its non-`.py` data files
  (`vendored/leapp/*.toml`, `vendored/leapp/LICENSE` — plain package
  discovery already picks up the `.py` files). crush-forensics' own build
  needs zero awareness of crush-analyze's internal layout for this to
  work. Also ships a PEP 561 `py.typed` marker so crush-forensics' own
  `mypy --strict` sees it as typed rather than skipping it.
- **Invocation is still a real, isolated OS subprocess** — important
  especially for dev mode, which runs arbitrary unreviewed module code, so
  running crush-analyze in-process inside Crush was never on the table
  despite it being "just a pip dependency." But `sys.executable -m
  crush_analyze` — the obvious approach — breaks in a PyInstaller frozen
  build: `sys.executable` there is `crush.exe` itself, not a general
  `python.exe` with `crush_analyze` importable. Fixed with a **self-re-exec
  sentinel**: `crush/__main__.py` checks `sys.argv[1] ==
  "--internal-analyzer-cli"` before any Qt import and, if set, delegates
  straight to `crush_analyze.cli.main()` and exits — so Crush's own already
  -frozen executable acts as its own crush-analyze CLI subprocess when
  re-invoked with that flag (`crush/core/analyzer_launcher.py`'s
  `_self_command()`: `[sys.executable]` when frozen, `[sys.executable,
  "-m", "crush"]` in dev — both correctly resolve to "run this same
  package again" either way). One binary, no download script, still real
  process isolation.
- `crush/core/analyzer_launcher.py` — `list_analyzer_modules()` and
  `run_analyzer(input_path, module_id=..., module_path=...)`, both
  synchronous `subprocess.run()` calls with output capture (unlike Peach's
  fire-and-forget `Popen`, since crush-analyze must produce a JSON file
  Crush reads back before the caller can do anything useful — the same
  "spawn, wait, capture" shape `unified_log_parser.py` already uses for
  `unifiedlog_iterator`, not Peach's "hand off and forget" shape).
  `AnalyzerRunError` for a CLI-level failure (exit 2, no JSON at all) —
  distinct from a normal contract v1 result carrying `status: "error"`,
  which is returned, not raised, exactly so callers can check that field
  directly.

No Settings override / binary-path mechanism (nothing to point a
Settings-configured path at — it's a code dependency, not an
independently-updatable binary). Module *packs* still update independently
per "Update mechanism" below; that's unrelated to how crush-analyze's own
code is invoked.

## CLI surface

```
crush-analyze list-modules
    → JSON manifest of bundled modules: [{id, name, module_version, requires}]

crush-analyze run --module <id> --input <dir> --output <file>.json
    → runs a bundled, curated module. Exit 0/1/2.

crush-analyze run --module-path <file.py> --input <dir> --output <file>.json --dev
    → dev mode (see below): runs an arbitrary, non-vendored module file
      through the same shim and the same result contract.
```

Exit codes: `0` success, `1` module ran but reported `status: "error"` in
the JSON (a best-effort error JSON is still written so Crush has exactly one
read path regardless of exit code), `2` the CLI itself couldn't run at all
(bad args, module not found, output path not writable — no JSON to read).

## Module function signature: v2 (`Context`) only

iLEAPP artifact modules currently exist in two shapes, distinguished at
runtime by iLEAPP's own test harness via `len(sig.parameters)`:

- **v1** (declining): `func(files_found, report_folder, seeker, wrap_text,
  timezone_offset) -> (data_headers, data_list, source_path_or_None)`
- **v2** (current): `func(context: Context) -> ...`, result attached to
  `context` rather than returned as a tuple.

A **v3** format is reportedly already being sketched upstream but not
public/stable yet.

**Decision: target v2 (`Context`) only, both for curated bundled modules and
for dev mode.** v1 is on its way out; not worth building and maintaining a
second call shape for a declining format. Revisit if/when v3 lands and
stabilizes.

`Context` itself is **not** vendored from iLEAPP — see "Vendoring policy"
below. `crush-analyze` implements its own minimal `Context` covering only
the handful of calls a typical module actually makes: `get_files_found()`,
`get_relative_path(path)`, and walking a folder by glob pattern. Extend it
on demand as new ported/dev-mode modules turn out to need more.

**Correction, discovered while actually porting the first module (step 3):**
a real iLEAPP artifact file imports more than `Context` at its top —
`applicationStateDB.py` also does
`from scripts.ilapfuncs import open_sqlite_db_readonly, artifact_processor,
logfunc, get_file_path`. Since the vendored file must stay byte-identical
(see "Vendoring policy"), that import line can't be edited away. The compat
shim therefore also includes a from-scratch `scripts.ilapfuncs` — just
those four symbols, not iLEAPP's real 1900-line `ilapfuncs.py` (HTML/TSV/
KML/LAVA report generation, GUI log redirection, Windows extended-path
handling for iLEAPP's own extraction scheme — none of it needed here).
`artifact_processor` is a pure pass-through decorator: iLEAPP's real one
drives report generation around the wrapped function's return value, which
crush-analyze never does — it builds contract v1 directly from the
returned `(data_headers, data_list, source_path)` tuple instead. Registered
into `sys.modules['scripts.ilapfuncs']` right before a vendored *or*
dev-mode file is loaded (`leapp_compat.loader.install_scripts_shim()`), so
neither path needs a real iLEAPP install on the machine running
crush-analyze.

**Also discovered:** a single LEAPP artifact file commonly declares more
than one artifact function via `__artifacts_v2__` — `applicationStateDB.py`
declares three (`get_installed_apps`, `get_snapshot_creationDate`,
`get_snapshot_lastUsedDate`). Each becomes its own crush-analyze module id.
For dev mode this means `--module-path` alone is ambiguous whenever the
file declares more than one function; `--module <function-name>` selects
which one to run (an error listing the available names is returned if it's
omitted and the file isn't unambiguous). `runner.load_external_module()`
tries crush-analyze's own native `MODULE = ModuleInfo(...)` convention
first, then falls back to the `__artifacts_v2__` shape — so dev mode
transparently accepts both a from-scratch crush-analyze module in progress
and real, unmodified iLEAPP source.

**One more:** plist-parsed values routinely come back as real Python
`datetime` objects (or bytes), which aren't natively JSON-serializable.
Rather than special-case this per module, `json.dumps(..., default=...)`
uses a small shared fallback (`crush_analyze.json_safe.default`): datetimes
become ISO 8601 strings, bytes become hex, anything else falls back to
`str()` — never raises, matching the standing rule that one oddly-typed
value degrades gracefully rather than failing the whole run.

## Result contract v1

Every run — curated or dev-mode — produces exactly this JSON shape, whether
the CLI exits 0 or 1:

```json
{
  "contract_version": 1,
  "analyzer": {
    "id": "installed_apps",
    "name": "Installed Applications",
    "tool": "crush-analyze",
    "tool_version": "0.1.0",
    "module_version": "1"
  },
  "run": {
    "started_at": "2026-09-14T12:00:00Z",
    "duration_ms": 842,
    "input_path": "/path/to/extracted/data",
    "dev_mode": false,
    "module_source": "bundled"
  },
  "status": "ok",
  "warnings": [],
  "error": null,
  "columns": [
    {"key": "bundle_id", "label": "Bundle ID", "type": "string"},
    {"key": "install_date", "label": "Install Date", "type": "datetime"}
  ],
  "rows": [
    {"_row_status": "ok", "bundle_id": "com.example.app", "install_date": "2026-01-01T00:00:00Z"}
  ]
}
```

Field rules (all mandatory, not optional-with-defaults):

- `status`: `"ok" | "partial" | "error"` for the run as a whole. A failed or
  partial run must never render as a clean, empty-looking table — matches
  the standing rule that unsupported/unparsed content always gets an
  explicit status, never silent emptiness.
- `warnings[]`: run-level warnings (e.g. "3 rows skipped: malformed date").
- `error`: `null` on success, else `{"message": ..., "detail": ...}`.
- Every row carries its own `_row_status` (`"ok" | "partial" | "error"`) —
  one bad row must never silently drop, and must never fail the whole run.
  No arbitrary truncation of `rows[]` either — same standing rule.
- `run.dev_mode` / `run.module_source` let Crush's UI badge dev-mode results
  distinctly (e.g. "unvetted module" banner) without a second contract
  shape.

Crush-side: cache `list-modules` at startup, new dynamic "Run Analyzer"
context-menu entry; reuse `_materialize_directory_node_for_external` and the
existing busy-dialog wrapper (`run_with_busy_dialog`) around the subprocess
call; validate the JSON shape before trusting it even though it's Crush's
own sibling tool; one new generic result-table viewer tab (typed
`columns[]` + `rows[]`, one "view kind" reused for every module); clean up
temp output + extraction dir after read.

## Dev mode (James Habben's request)

Goal: let a module author have Crush open on real/synthetic data in one
window and a LEAPP module's source open in an editor in another, run that
*exact, unvendored* file against Crush's currently-open data, see the
result inside Crush, edit, re-run — without first curating/porting/vendoring
the module into `crush-analyze`.

- Same CLI (`--module-path` instead of `--module`), same `Context` shim,
  **same result contract v1** as curated runs — no second display path in
  Crush, and the mandatory `status`/`warnings`/`_row_status` fields apply
  here too, so a half-working module-in-progress still can't render as a
  clean empty table.
- `run.module_source` is set to `"external:<path>"` and `run.dev_mode:
  true`, so Crush's result-table tab can show an "unvetted external module"
  banner distinct from a curated result — a raw, arbitrary `.py` file is a
  materially different trust level from a bundled/reviewed module, even
  though the display path is shared.
- Needs a Settings-level opt-in ("Developer mode", off by default) plus the
  path to the module file — same shape as Peach's binary-path override, not
  a new mechanism.
- Prior art confirmed feasible: iLEAPP's own test harness
  (`admin/test/scripts/test_module_output.py`) already does "run exactly
  one module in isolation" via a `SingleModuleLoaderWrapper` that
  monkey-patches iLEAPP's plugin loader to load only that module plus two
  essentials, then drives the real `ileapp.main()`. `crush-analyze` doesn't
  reuse that approach directly (it never depends on the full iLEAPP suite,
  by design — see Vendoring policy), but it confirms the underlying idea —
  running a single artifact module in isolation against a folder — is a
  well-trodden path, not a novel risk.
- Explicitly **not** in scope for dev mode: live file-watching or
  auto-rerun-on-save. Manual re-run only, for the first version.

## Vendoring policy

Each ported curated module is a vendored, byte-identical copy of one
iLEAPP/aLEAPP/rLEAPP artifact script (its own business logic — the one unit
LEAPP's own architecture already treats as swappable/pluggable), plus a
small compat shim — never the surrounding LEAPP framework internals
(`scripts/context.py`, `scripts/search_files.py`, the plugin loader, etc.).
Tracked the same disciplined way as `qnxprobe`/`ewfprobe`: hash-pinned
manifest, upstream commit recorded, license file kept alongside.

This was corrected once already during design: an earlier draft planned to
also vendor iLEAPP's actual `Context`/`FileSeekerDir` classes verbatim.
Rejected — those are LEAPP's own internal framework plumbing, not a
separately-published reusable library the way `qnxprobe`/`ewfprobe` are;
vendoring them would read as "pulling core LEAPP internals into Crush"
rather than "reusing one community artifact module," a bad look toward the
LEAPP community/maintainers. `crush-analyze`'s own from-scratch `Context`
(see above) is cheaper anyway — a module only exercises a handful of a real
`Context`'s ~20 methods — and avoids coupling to LEAPP's internal API churn.

Before porting any given module, check whether it's actually
dependency-heavy/complex enough to justify this machinery at all, or simple
enough to just become an ordinary built-in Crush parser instead (some
LEAPP modules are ~100 lines with no real dependencies).

First candidate: `applicationStateDB.py` (iLEAPP, "installed apps",
SQLite+plist) — complex enough to be worth it, unlike e.g.
`appItunesmeta.py` which is simple enough it should probably just become
Crush's own 44th parser someday, independent of this whole effort.

## Update mechanism — separate module pack, decoupled from `crush-analyze`'s own release

`crush-analyze`'s curated module set updates independently of its own CLI
binary, the same way Peach's tagging rules do via **`peach-rules`** (a
dedicated repo, separate from `peach-forensics`). Confirmed by reading
Peach's actual implementation (`src/tagging/pack_update.rs`,
`scripts/publish_rule_pack.py`) rather than assumed:

- **Dedicated repo**, e.g. `crush-analyze-modules`, separate from
  `crush-analyze` itself. Every release there *is* a module pack — tag
  `v{N}`, a plain incrementing integer, never SemVer. Peach's own first
  draft shared its app repo's release list (disambiguated by a
  `peach-rules-` tag prefix) and hit a real problem: every rule-pack
  release risked being flagged as GitHub's "Latest" release ahead of the
  actual newest app version. A dedicated repo sidesteps this outright.
- **One full-snapshot bundle per release**, never a delta — asset name
  `crush-analyze-modules-v{N}.zip`, containing a `manifest.toml`:
  ```toml
  [pack]
  pack_version = 3
  released_at = "2026-09-14"
  min_analyzer_version = "0.2.0"

  [[modules]]
  name = "installed_apps.py"
  sha256 = "..."
  module_id = "installed_apps"
  module_version = "2"
  ```
  `sha256` per file for integrity, `module_version` per module so an
  individual module's own version history is visible without diffing code,
  `min_analyzer_version` as a compatibility gate against the installed
  `crush-analyze` binary.
- **Update check is user-initiated only** — a "Check for module updates"
  action (Tools menu, alongside the existing Peach binary-path pattern),
  never automatic or background. This isn't just style-matching Peach: it's
  the same "local-only" principle already applied there for a forensic
  tool that shouldn't be phoning home on its own. Fetch GitHub's release
  list for `crush-analyze-modules`, pick the highest `v{N}` with a matching
  asset name that's newer than the currently-applied `pack_version`,
  download only on explicit confirmation, verify each file's `sha256`
  against the manifest before trusting it (download code should not trust
  its own bytes — verification is a separate step, matching Peach's split
  between `download_update()` and the caller that checks the result).
- A `publish_module_pack.py` script (mirrors `publish_rule_pack.py`) builds
  the zip + manifest + a name→version release-notes table for
  `gh release create --notes-file`, run manually against a checkout of
  `crush-analyze-modules`.

## Testing

iLEAPP's own test harness (`admin/test/scripts/test_module.py`,
`test_module_output.py`, `make_test_data.py`) is a useful structural model
for testing *vendored* modules inside `crush-analyze`, independent of the
runner mechanism above:

- Record a baseline JSON snapshot (headers/columns + rows + a few run
  metrics) for a module against fixed test input, committed to the repo;
  CI re-runs the module and diffs against the snapshot. Recording must
  happen in UTC — a snapshot recorded in a non-UTC local timezone bakes
  that offset into every datetime-derived column, and CI runs UTC.
- Guard against accidentally recording a misleadingly "successful" empty
  snapshot when a module disabled itself due to a missing optional
  dependency.
- Adapt, don't vendor: `make_test_data.py`'s pattern (extract only the
  files a module's own declared paths match, out of a full test image, into
  a small fixture zip) is worth reusing conceptually for
  `crush-analyze`'s much smaller module set — no need for its interactive
  menu/image-manifest machinery at this scale.

## Rollout order

1. ✅ Freeze contract v1 (this document).
2. ✅ `crush-analyze` skeleton: CLI (`list-modules`, `run`), the from-scratch
   `Context` shim, one stub module that returns a fixed, tiny result.
   Local repo at `~/Documents/git/crush-analyze`, own GitHub repo under
   `kalink0`, CI (`ci.yml`: ruff/mypy lint job + 3-OS pytest matrix).
3. ✅ Port `installed_apps` for real (first real module) — vendored
   `applicationStateDB.py` byte-identical (hash-pinned manifest, upstream
   commit `b055398`), `leapp_compat` shim (`ilapfuncs.py` + `loader.py`),
   end-to-end verified against a synthetic `applicationState.db` fixture
   (real SQLite tables, a real binary-plist `compatibilityInfo` blob) —
   correct contract v1 output, correct exit code. All three of the file's
   artifact functions (`get_installed_apps`, `get_snapshot_creationDate`,
   `get_snapshot_lastUsedDate`) registered and reachable, in both the
   bundled and dev-mode (`--module-path` + `--module`) paths. See the
   corrections folded into "Module function signature" above — the actual
   shim surface, the multi-function-per-file case, and JSON-safety for
   `datetime`/`bytes` values all only became visible once a real module was
   ported, not from reading `__artifacts_v2__`'s shape alone.
4. ✅ Wire the Crush side (branch `feature/analyzer-runner-crush-side`) —
   done directly against the real `get_installed_apps` module, not just
   the stub, since step 3 already made it real:
   - `crush/core/analyzer_launcher.py` (self-re-exec, see "Packaging"
     above — this step is also where step 5 effectively got resolved,
     since pip-dependency packaging needed no separate build pipeline).
   - `crush/viewers/analyzer_result_viewer.py` — the generic result-table
     "view kind": `QAbstractTableModel` over `columns[]`/`rows[]`, a status/
     warnings/dev-mode banner (row background tint keyed to `_row_status`),
     added as an ordinary `_viewer_tabs` tab exactly like every other
     viewer.
   - `fs_panel.py`: "Run Analyzer…" context-menu entry for directory
     nodes (alongside "Send Logs to Peach…"), emits `open_requested(node,
     vfs, "run_analyzer")`.
   - `main_window.py`: `_run_analyzer()` — lazily fetches+caches the
     module list (one subprocess spawn on first use, not at startup, since
     most sessions never touch this), `QInputDialog.getItem` module
     picker, reuses `_materialize_directory_node_for_external` +
     `run_with_busy_dialog`, opens the result in a new tab.
   - Tests: `test_analyzer_launcher.py` (real subprocess round-trips,
     including the same synthetic `applicationState.db` fixture as
     crush-analyze's own tests), `test_analyzer_result_viewer.py`
     (ok/error/dev-mode/warnings banner states). Full suite green: 934
     tests (was 925), ruff, mypy (142 files) — verified against the real
     pinned git dependency, not a local editable override.
   - The dev-mode banner in the viewer is already implemented (reads
     `run.dev_mode`/`run.module_source` unconditionally) — step 6 below is
     now only the Settings opt-in + a `--module-path` file picker in the
     UI, not the banner itself.
5. ~~Packaging~~ — folded into step 4; no separate binary/build pipeline
   needed once crush-analyze was recognized as a pip dependency rather
   than a Peach-style compiled sibling. See "Packaging" above.
6. Dev mode Crush-side UI: Settings opt-in ("Developer mode"), a
   `--module-path` file picker wired to `_run_analyzer`'s existing
   `module_path` parameter (`run_analyzer()` and the result viewer's
   banner already support this end-to-end as of step 4 — only the
   Settings gate and file-picker UI are missing). **Next.**
7. Update mechanism: `crush-analyze-modules` repo, `publish_module_pack.py`,
   "Check for module updates" action.
8. Ship. Decide on module 2 from real use, not speculatively.
