# Crush — Developer Guide: Implementing Parsers and Viewers

This guide explains how to add support for a new file format to Crush.
Every format needs two things: a **parser** that reads the raw bytes and returns structured data,
and a **viewer** (or reuse of an existing one) that displays that data as a Qt widget.

---

## Architecture Overview

```
VFS (ZIP / TAR / directory / file)
       │
       ▼
ParserRegistry.best(node, vfs)          ← picks first matching parser
       │
       ▼
AbstractParser.parse(node, vfs)
       │  returns
       ▼
ParseResult(viewer_type, data, metadata, text_index)
       │
       ▼
ViewerRegistry.get(viewer_type)         ← factory lambda
       │
       ▼
QWidget (viewer shown in tab)
```

The parser and viewer are **decoupled**: the parser decides which viewer string to use, and the
viewer receives the opaque `data` object. You can reuse any existing viewer type if its expected
`data` shape matches what your parser produces.

---

## Step 1 — Write the Parser

Create `crush/parsers/myformat_parser.py`:

```python
from __future__ import annotations

from crush.core.vfs import VFS, VFSNode
from crush.parsers.base import AbstractParser, ParseResult


class MyFormatParser(AbstractParser):
    SUPPORTED_EXTENSIONS = [".myfmt", ".mf"]
    DISPLAY_NAME = "My Format"           # shown in the Properties panel and Format Reference

    def can_parse(self, path: str, peek_bytes: bytes) -> bool:
        # Prefer magic-byte sniffing — extensions lie.
        # peek_bytes is the first 64 bytes of the file.
        return peek_bytes[:4] == b"MYFM"

    def parse(self, node: VFSNode, vfs: VFS) -> ParseResult:
        raw = vfs.read(node)             # full file bytes; use vfs.open(node) for streaming
        data = _parse(raw)               # your own parsing logic

        return ParseResult(
            viewer_type="tree",          # which viewer to use — see Viewer Types below
            data=data,                   # passed as-is to the viewer
            metadata={
                "Format": "My Format",
                "File size": f"{node.size:,} B",
                "Records": str(len(data)),
            },
            text_index=" ".join(str(v) for v in data),   # plaintext for the filter search
        )
```

### `can_parse` rules

- **Magic bytes are authoritative** — always check `peek_bytes` when the format has a magic
  signature. Use `_ext_match(path)` as a secondary fallback only.
- Keep it fast — `can_parse` is called for every file during type indexing.
- Return `False` if uncertain; `HexFallbackParser` catches everything else.

### `parse` rules

- Use `vfs.read(node)` for small files. For large files use `vfs.open(node)` which returns an
  `IO[bytes]` stream.
- Wrap parsing in a broad `except Exception` and return a `ParseResult` with an error marker
  in `data` rather than letting the exception propagate — a crash in one parser should not
  abort the whole application.
- Populate `text_index` with a reasonable amount of extracted text (a few KB max) so the
  filesystem panel's filter works across content.

### Decoding internal structure: no shape-based guessing

Once a format is identified (`can_parse` has already decided that), decode its **internal**
structure — field types, record boundaries, row counts — deterministically from a spec-defined
tag, type byte, or schema. Never infer a field's type or meaning from what the bytes *look
like*: byte-length heuristics, magic-number thresholds not present in the actual format
documentation, try-this-then-that cascades used to *determine* structure, or "assume the most
plausible shape is right." This is how the Realm parser silently misread rows as tree
bookkeeping data for years — it guessed a column's shape instead of reading its declared type —
until it was rewritten from scratch against the real Realm Core source (see the CHANGELOG entry
for details). A parser audit that fixed the same failure pattern across the rest of
`crush/parsers/` is documented in the CHANGELOG too.

- Use a heuristic only when there genuinely is no declared type to dispatch from — an
  undocumented/reverse-engineered format, or a value the format itself doesn't tag (e.g.
  protobuf's wire-type-2 length-delimited fields, which are legitimately ambiguous between
  string/bytes/nested-message at the wire level).
- When a heuristic is unavoidable, it must never be presented as an authoritative decoded
  value. The reference pattern is `proto_interp.py` / the Protobuf Viewer: instead of silently
  picking one interpretation, it computes and shows *every* plausible reading side by side
  (dimmed "interpretations" rows), so nothing is hidden and nothing is asserted as fact.
  Apply the same shape to new heuristics — prefer showing all candidates. If only one value can
  be shown (e.g. a single rendered table cell), label it as inferred/possible and keep the raw
  bytes reachable alongside it.
- A heuristic used purely as **post-corruption recovery** (the spec-driven read already failed,
  e.g. a damaged file) is a different, more tolerable case than guessing on well-formed data —
  but still mark the recovered value as estimated in the UI/metadata rather than showing it like
  a normal, certain result.
- Genuine top-level format-detection heuristics (deciding *which* parser/branch applies to an
  already-unidentified blob, e.g. file-type sniffing) are out of scope for this rule — they're
  inherently probabilistic by nature of the problem. This rule is about decoding structure
  *within* a format that's already been identified.

### Directory-based formats (e.g. LevelDB)

If the format is detected from a directory rather than a single file, skip `can_parse` and
implement `can_parse_dir` instead:

```python
def can_parse(self, path: str, peek_bytes: bytes) -> bool:
    return False                         # never matches files

def can_parse_dir(self, node: VFSNode) -> bool:
    names = {c.name for c in node.children}
    return "CURRENT" in names or any(n.startswith("MANIFEST-") for n in names)
```

`ParserRegistry.candidates` checks for a `can_parse_dir` attribute and calls it when the node
is a directory.

---

## Step 2 — Register the Parser

Open `crush/parsers/__init__.py` and add your parser **before** `HexFallbackParser`:

```python
from crush.parsers.myformat_parser import MyFormatParser

ParserRegistry.register(MyFormatParser())
ParserRegistry.register(HexFallbackParser())   # must remain last
```

Registration order is priority order — if two parsers both return `True` for the same file,
the first one registered wins.

---

## Step 3 — Choose or Create a Viewer

### Reuse an existing viewer type

If your parsed `data` matches one of the shapes below, you can use an existing viewer without
writing any UI code.

| `viewer_type` | Expected `data` type | When to use |
|---|---|---|
| `"tree"` | any `dict`, `list`, or nested combination | key-value data, plists, JSON-like structures |
| `"table"` | `dict[str, {"columns": list[str], "rows": list[list], "truncated": bool}]` | tabular data with multiple named tables; also supports `"__db_path"` key for live SQL |
| `"hex"` | `bytes` | raw binary with no higher-level structure |
| `"text"` | `str` | plain or structured text, log lines |
| `"image"` | `bytes` | raw image bytes (JPEG, PNG, GIF, HEIC, …) |
| `"abx"` | `bytes` | Android Binary XML raw bytes |
| `"protobuf"` | `bytes` | raw Protobuf bytes for schema-less wire decode |

Example — reusing `"tree"` for a simple key-value format:

```python
return ParseResult(
    viewer_type="tree",
    data={"version": 3, "records": [{"id": 1, "name": "foo"}, ...]},
    ...
)
```

### Write a new viewer

If none of the existing types fit, create `crush/viewers/myformat_viewer.py`:

```python
from __future__ import annotations
from typing import Any

from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel


class MyFormatViewer(QWidget):
    def __init__(self, data: Any, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._data = data
        self._build_ui()
        self._load()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        # build toolbar, table, splitter, etc.

    def _load(self) -> None:
        # populate the UI from self._data
        pass
```

Then register the viewer in `crush/viewers/__init__.py` inside `_register_builtin_viewers()`:

```python
from crush.viewers.myformat_viewer import MyFormatViewer
ViewerRegistry.register("myformat", lambda r, n, v, p: MyFormatViewer(r.data, p))
```

And add the new type string to the `ViewerType` literal in `crush/parsers/base.py`:

```python
ViewerType = Literal[
    "table", "tree", "hex", "text", "media", "image",
    "abx", "log", "multi_log", "protobuf", "realm", "leveldb",
    "myformat",     # ← add here
]
```

---

## VFS API

Parsers must never touch the real filesystem directly — always go through `vfs`:

| Method | Returns | Use when |
|---|---|---|
| `vfs.read(node)` | `bytes` | file fits comfortably in memory |
| `vfs.open(node)` | `IO[bytes]` (context manager) | large file or streaming needed |
| `vfs.peek(node, n)` | `bytes` | sniff only the first `n` bytes |

`VFSNode` fields of interest:

| Field | Type | Description |
|---|---|---|
| `node.path` | `str` | full virtual path (e.g. `/var/mobile/Library/SMS/sms.db`) |
| `node.name` | `str` | file name only |
| `node.size` | `int` | file size in bytes |
| `node.is_dir` | `bool` | True for directories |
| `node.children` | `list[VFSNode]` | direct children (directories only) |
| `node.modified` | `float` | mtime as Unix timestamp |

---

## `ParseResult` Fields

```python
@dataclass
class ParseResult:
    viewer_type: ViewerType             # selects the viewer
    data: Any                           # passed directly to the viewer widget
    sub_nodes: list[VFSNode] = []       # additional nodes to expose (artifact chaining)
    metadata: dict[str, Any] = {}       # shown in the Properties panel
    text_index: str = ""                # text for the filesystem filter search
```

**`metadata` conventions** — use the following key names for consistency with existing parsers:

| Key | Example value |
|---|---|
| `"Format"` | `"SQLite Database"` |
| `"File size"` | `"1,234,567 B"` |
| `"Tables"` | `"12"` |
| `"Records"` | `"4,512"` |
| `"Version"` | `"3"` |
| `"Error"` | `"Unexpected EOF at offset 0x200"` |

---

## Checklist

- [ ] `crush/parsers/myformat_parser.py` — subclass `AbstractParser`, implement `can_parse` and `parse`
- [ ] `crush/parsers/__init__.py` — `ParserRegistry.register(MyFormatParser())` before `HexFallbackParser`
- [ ] `crush/viewers/myformat_viewer.py` — subclass `QWidget` (only if reusing an existing viewer type is not possible)
- [ ] `crush/viewers/__init__.py` — `ViewerRegistry.register("myformat", ...)` (only for new viewer types)
- [ ] `crush/parsers/base.py` — extend `ViewerType` literal (only for new viewer types)
- [ ] `crush/docs/format-support.md` — document the new format in the support matrix

---

## Key Files at a Glance

| File | Role |
|---|---|
| `crush/parsers/base.py` | `AbstractParser`, `ParseResult`, `ViewerType` |
| `crush/parsers/__init__.py` | parser registration (priority order) |
| `crush/core/registry.py` | `ParserRegistry` — `register`, `best`, `candidates` |
| `crush/core/vfs.py` | `VFSNode`, `VFS` ABC, `DirectoryVFS`, `ZipVFS`, `TarVFS`, `AndroidBackupVFS`, `ITunesBackupVFS`, `BytesVFS` |
| `crush/core/ios_keybag.py` | Apple backup KeyBag parsing + `Manifest.db`/per-file decrypt (iOS 10.2+) |
| `crush/core/android_backup_crypto.py` | Android `adb backup` master-key unwrap + payload decrypt (PBKDF2/AES-256) |
| `crush/core/passwords.py` | `PasswordRequiredError`, `WrongPasswordError` — shared contract for any password-protected source/parser |
| `crush/viewers/__init__.py` | viewer factory registration |
| `crush/core/viewer_registry.py` | `ViewerRegistry` — `register`, `get` |
| `crush/ui/viewer_factory.py` | `make_viewer()` — wires `ParseResult` to a viewer widget |
| `crush/parsers/json_parser.py` | simplest real parser example |
| `crush/parsers/leveldb_parser.py` | directory-based parser example |
| `crush/viewers/tree_viewer.py` | generic tree viewer (good UI pattern to follow) |
