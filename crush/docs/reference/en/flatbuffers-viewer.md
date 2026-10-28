### FlatBuffers Viewer

Opens via right-click → **Open as** → **FlatBuffers**, or for a table cell via **Open as new tab** → **FlatBuffers**. FlatBuffers has no reliable magic bytes (the 4-character `file_identifier` at bytes 4–7 is optional), so it is never chosen from a file's content. Files with a known identifier — `TFL3` (TensorFlow Lite models) and `BFBS` (binary schemas) — are named in the Properties panel's `Format (identified)` row, with **Open as → FlatBuffers** as the way to open them.

**Schema-less decode** — what the bytes record for certain is decoded and checked: the root offset (plain and size-prefixed layout are both tried; the Properties panel says which validates and why the other doesn't), each table's vtable (shown as stored: vtable size, table inline size, one row per field slot) and which slots are stored. A field's width and type are not recorded without a schema, so every reading that fits is shown as a candidate below the field, marked as a heuristic:

| Candidate | When it is offered |
|---|---|
| `N-byte scalar` | for every width N of 1, 2, 4 and 8 bytes that fits the gap to the next stored slot (or the table's end) and is aligned; with the same interpretations as the Protobuf viewer for 4 and 8 bytes (signed, float/double, timestamps), `bool` for 1 byte |
| `offset → string` | a 4-byte slot whose value points to a length, the string's bytes and its 0 terminator, all inside the buffer |
| `offset → vector` | a 4-byte slot pointing to a vector; the vector is read with 1-, 2-, 4- and 8-byte elements, as offsets to strings, as offsets to tables, and a byte vector also as a nested FlatBuffer |
| `offset → table` | a 4-byte slot pointing to a table whose vtable validates |
| `64-bit offset → string / vector` | an 8-byte slot read as a FlatBuffers 64-bit offset |
| `inline struct (N B)` | every gap of 2 bytes or more, the whole gap (at 1 byte a struct's bytes are the 1-byte scalar's) |

A slot that isn't stored is listed as *not stored (absent, or equal to its default)*. Offsets are followed as long as they validate, with no depth limit. A table reached a second time is decoded at the first place it is reached; the other place shows a row for it — double-click it to go there. Bytes that no structure and no candidate reading covers are listed under **unreferenced bytes** with their offsets (padding, or remnants of earlier data).

**Schema decode** — click **Load .fbs / .bfbs…**. A binary schema (`.bfbs`, recognised by its `BFBS` identifier, not by the file name) is read directly; a text schema (`.fbs`, with its includes next to it) is compiled by the bundled `flatc`. The **Root type** list preselects the schema's declared `root_type`; click **Decode**. Fields then show their schema names and types; a field equal to its default is shown with the default and marked *not stored*. Every disagreement between the schema and the bytes is shown on the field it concerns (in orange, with an *issue* row): an offset or vtable outside the buffer, a required field not stored, an enum value the schema doesn't declare, a stored slot the schema has no field for (its bytes up to the next slot are shown), bytes 4–7 that aren't the schema's `file_identifier`, a vector of unions whose `_type` vector holds a different number of entries. The status line says which root layout validates and why the other doesn't, as the Properties panel does for the schema-less decode. **Show Schema-less Decode** returns to the candidates.

The schema label's tooltip says how the schema was obtained: compiled by the bundled flatc (with its version), or read from a `.bfbs`, which doesn't record the flatc version that wrote it. A `.bfbs` written without `flatc --bfbs-builtins` doesn't record which enums are `bit_flags`; a combination of flags then shows as an undeclared value. Content declared as FlexBuffers is not decoded; its bytes are shown with that note.

**Hex provenance** — **Show Hex** opens the hex view; selecting a row highlights its exact bytes: a field's vtable slot together with its value, an offset together with the string, vector or table it points to, the vtable with the table's soffset.

**Value field, Copy and Export** — the value field holds the complete value: a string's original text, every byte of a vector reading or struct as hex, every element of a typed vector. **Export…** (text or JSON) starts with the buffer's bytes once, as hex; every row follows with its value — scalars, strings, headers and vtable entries directly, a vector, struct or unreferenced range by its byte range in that buffer. Large buffers are decoded and exported behind the wait dialog.
