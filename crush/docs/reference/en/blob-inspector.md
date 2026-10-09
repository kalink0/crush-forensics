### BLOB Inspector

The BLOB Inspector is a shared decode dialog for examining raw binary fields. It opens as a non-modal window — the rest of the UI stays fully accessible and multiple inspector windows can be open at the same time.

**How to open it:**
- **SQLite viewer** — right-click any cell → **Inspect Cell…**
- **LevelDB viewer** — right-click any record row → **Inspect Key…**, **Inspect Value…**, or **Inspect Internal Key…**
- **Realm viewer** — right-click any freed block in the Freed Data tab → **Inspect Block…**
- **Tools → BLOB Inspector…** — paste hex, base64, or text directly into the inspector without a source file (see [below](blob-inspector.md#opening-it-without-a-source-file))

---

#### Opening it without a source file

**Tools → BLOB Inspector…** opens the inspector with an input field above it. It lets you paste raw binary data — copied from a hex editor, a SQLite BLOB cell, a network capture, or any other source — and inspect it directly in Crush without saving it to disk first.

1. Paste hex, base64, or plain text into the input area at the top.
2. Set **Input encoding** to **Auto** (default) or force a specific encoding if auto-detection picks the wrong one:
   - **Auto** — detects hex strings, Base64, and plain text automatically
   - **Hex** — treats the input as a hex string regardless of content
   - **Base64** — decodes as Base64 regardless of content
   - **UTF-8 text** — treats the input as UTF-8 text and passes its bytes through as typed, leading and trailing whitespace included
3. The status line shows the detected encoding and decoded byte count as you type. If it stays grey, the input could not be decoded with the current encoding setting; with **Hex** or **Base64** forced it names the reason, such as the first character that doesn't belong. Hex and Base64 are decoded as strictly as the pipeline steps of the same name (see below).
4. The inspector — three columns: *Decode pipeline*, *Interpretations*, *Content view* — appears directly below and updates live as you type.

All pipeline steps and interpretations described below are available here as well.

> **Tip:** You can keep this window open and paste new data at any time while working in the main window.

---

#### Layout — three columns

| Column | Purpose |
|---|---|
| **Decode pipeline** (left) | Chain of byte→byte transform steps applied before interpretation. Click **＋ Add step** to append a step; click **×** to remove one. Steps run top-to-bottom; if a step fails the pipeline stops there and the reason is shown inline. Each step's list shows five entries and scrolls for the rest; many steps scroll in the column. |
| **Interpretations** (middle) | All available display formats for the bytes produced by the pipeline, grouped by confidence. Click any entry to switch the content view instantly — no second click needed. |
| **Content view** (right) | The rendered output for the selected interpretation, with **Copy**, **Export** and **Open in new tab** below it (see next section). Right-click in hex view for per-selection copy options. |

---

#### Copy, export and open the decoded bytes

Apart from **Copy → Shown text**, these take the **bytes after the decode pipeline**, whatever interpretation is selected (with no steps, the inspected bytes themselves). They are unavailable while a step fails.

- **Copy → Shown text** — the content view's text (the whole hex dump in hex view).
- **Copy → Bytes as hex / as Base64 / as Python literal** — the bytes, complete, in that notation.
- **Export → Bytes…** — writes the bytes unchanged to a file.
- **Export → Rendered image (PNG)…** — when the Image interpretation shows a decoded image: the image as Crush decoded it (first frame, without the viewer's rotation), as PNG. This is an image Crush made, not bytes from the evidence; the sidecar says so.
- **Open in new tab → Auto-detect / Hex / Text / Protobuf (schema-less)** — opens the bytes as a new tab, like a table cell's *Open as new tab*: the Properties panel shows where they came from (source file, table/column/row, record, key or field, and what exactly was inspected) and the **Decode pipeline**, each step with its input and output size and what it left undecoded. Not available where no main window is behind the inspector; the button says so.

Every export writes a **sidecar** next to the file, named after it plus `.crush.json` (e.g. `out.bin.crush.json`). It records:

| Field | Content |
|---|---|
| `schema_version` | Version of this layout (currently `1`) |
| `tool` | Crush and its version |
| `created_utc` | When the export was made (UTC) |
| `source` | Where the inspected bytes come from — the same fields the Properties panel shows |
| `inspected` | Size and SHA-256 of the inspected bytes |
| `pipeline` | Each step: name, output size and SHA-256, and bytes it left undecoded (offset, size, reason) |
| `output` | The exported file's name, what it holds (the bytes, or a rendered PNG), size and SHA-256 |
| `rendering` | For a rendered image only: how it was made (first frame, orientation, pixel format) |

If the sidecar already exists, Crush asks before overwriting it.

---

#### Decode pipeline steps

Pipeline steps are byte→byte transforms that pre-process the raw bytes before the interpretations are evaluated. Steps are chained: the output of step 1 is the input of step 2, and so on. The byte count after each step is shown inline.

Every step decodes strictly: it either decodes all of its input or fails with the reason (for example `invalid character 0x21 ('!') at offset 4` or `incomplete or truncated stream`). Nothing is skipped to make the input fit. A compressed stream can end before its input does; the step then decodes the stream and says below its byte count how many bytes follow the end of the stream and at which offset they start; those bytes are not decoded.

| Step | What it does | Typical source |
|---|---|---|
| **Base64 (decode)** | Decodes standard Base64 with `+`/`/` charset. Line breaks are ignored (MIME wraps Base64 into lines); any other character outside the alphabet, including a space, and data after `=` padding are errors. Missing padding is restored | iOS/Android SQLite BLOBs, email attachments |
| **Base64url (decode)** | Decodes URL-safe Base64 with `-`/`_` charset; padding optional. Same rules as Base64 | JWT payloads, web API tokens, OAuth parameters |
| **Hex → Bytes** | Converts hex digits to raw bytes. Whitespace, `:`, `_` and `-` may separate them; any other character and an odd number of digits are errors | Database hex columns, copy-pasted hex dumps |
| **zlib decompress** | Decompresses zlib data (deflate stream with zlib header, `0x78 …`); reports bytes after the end of the stream | Chrome LevelDB values, iOS WebKit caches |
| **gzip decompress** | Decompresses gzip data (magic `1f 8b`), every member of a multi-member file; reports bytes after the last member, and why a following member didn't decode | HTTP response bodies, server-side log archives |
| **lzfse decompress** | Decompresses Apple LZFSE data (blocks `bvx2` / `bvx1` / `bvxn` / `bvx-`, ended by `bvx$`); reports bytes after the end-of-stream block, or that the stream has none | iOS backups, iCloud sync blobs, macOS system caches, APFS metadata |

Steps can be combined freely. To decode a value that is Base64url-encoded and then lzfse-compressed, add **Base64url** as step 1 and **lzfse decompress** as step 2.

---

#### Interpretations

After the pipeline runs, the resulting bytes are tested against all available interpretations. The list is grouped into three tiers:

| Marker | Meaning |
|---|---|
| *(no marker)* | **Hex view** — always available as the baseline |
| **✓** | Confident — format positively identified (magic bytes, strict parse, valid structure) |
| **~** | Not a confirmation — the format almost always succeeds regardless of content, or the reading rests on an assumption its output states at the top |
| *(gray, no marker)* | Failed — bytes did not match this format; selecting it shows the reason |

**Available interpretations:**

| Interpretation | Tier | Notes |
|---|---|---|
| **Hex view** | baseline | Annotated hex dump with address / hex / ASCII columns |
| **UTF-8 text** | ✓ | Only ✓ when all bytes are valid UTF-8; strict decode |
| **JSON** | ✓ | Pretty-prints the bytes when they are valid JSON. Invalid or cut-off JSON fails with the parser's reason and position (**UTF-8 text** still shows the text) |
| **JSON (unescaped from a string)** | ~ | For JSON stored inside a JSON string (`{\"key\": …}`): reads the bytes as the content of a JSON string, resolves its escape sequences (`\"`, `\n`, `\uXXXX` …) as the JSON spec defines them, and pretty-prints the result. Shown as **~** because that the bytes come from a JSON string is an assumption; the output says so at the top, and the stored bytes keep the escaped form. Whitespace before and after the escaped text (e.g. a line break from the clipboard) is ignored, as JSON ignores it around a value, and the output says how much. Not offered when the bytes are JSON themselves |
| **Plist / bplist** | ✓ | Decodes binary (`bplist00`) or XML property list and shows it as in the [Plist / Tree Viewer](plist-tree-viewer.md): a tree (Decoded), the text, and for an NSKeyedArchiver archive a **Stored archive** tab, with Format, Status and the archive's object counts in a line above. **Copy** copies the decoded structure as text |
| **XML** | ✓ | Parses and pretty-prints well-formed XML (via lxml) |
| **Android Binary XML (ABX)** | ✓ | Reconstructs XML from Android's compact binary XML format |
| **Image** | ✓ | Recognised by the same signature bytes as an image file — JPEG, PNG, GIF, BMP, TIFF, WebP, HEIC/HEIF, AVIF, JPEG XL, Apple ATX and KTX textures — and shown in the [Image Viewer](image-viewer.md) (zoom, rotate, magnifier). Format, decode status and, for animated or multi-page images, that only the first frame is shown, are in a line above, followed by the rest of the image's metadata (EXIF, C2PA …). An image that is recognised but can't be decoded shows the decoder's reason |
| **Protobuf (schema-less)** | ~ | Wire-format decode. Numeric fields include `# label: value` hints for int64, sint64 (zigzag), bool, Unix/Cocoa/Chrome timestamps, double, and float; a field shown as a nested message also gets a `# raw bytes: ...` hint, since wire type 2 doesn't actually declare whether the bytes are a submessage. A `# Warning:` header appears if the parse was truncated or malformed, and a note above the fields when some were below the nesting limit (100 levels, the protobuf libraries' default) and are therefore shown as string/bytes. Shown as **~** because Protobuf's wire format accepts most byte sequences. |
| **Protobuf (schema: `<type>`)** | ✓ | Only appears once a schema is loaded (see below) — decodes using real field names and types instead of raw wire format. |
| **Latin-1 text** | ~ | ISO-8859-1 — always succeeds since every byte is a valid Latin-1 character; useful as a last resort for mixed binary/text data |

**Auto-selection:** when the inspector opens or the pipeline changes, the best ✓-tier interpretation is selected automatically. If the previously selected format still produces output after a pipeline change, the selection is preserved.

**Schema-based Protobuf decode:** select **Protobuf (schema-less)** first to confirm the bytes decode plausibly as Protobuf — a *Load .proto schema…* toolbar then appears above the content view. Load a `.proto` source file or a compiled FileDescriptorSet (`.pb`, `.fds`, `.desc`) and pick a message type from the dropdown; the view switches to a **Protobuf (schema: `<type>`)** entry decoded with real field names via that schema. The toolbar only shows while a Protobuf entry is selected — it stays out of the way for every other format. Uses the same schema loader as the standalone [Protobuf Viewer](protobuf-viewer.md); the loaded schema is kept only for this inspector window's lifetime.

---

#### Forensic examples

**iOS app database — Base64-encoded binary plist**

Many iOS apps store serialised objects as Base64-encoded bplist BLOBs in SQLite. To inspect:
1. Right-click the cell → *Inspect Cell…*
2. Add step: **Base64 (decode)**
3. The Interpretations list shows **✓ Plist / bplist** — click it to browse the deserialised object graph; for NSKeyedArchiver data, the **Stored archive** tab and the counts above show the archive as stored.

**JWT / OAuth token stored in a database**

Web-facing apps (and some native apps) store JWT tokens in SQLite. The token payload is the second dot-separated segment, Base64url-encoded without padding:
1. Copy the middle segment (between the first and second `.`)
2. Open *Tools → BLOB Inspector…*, paste the segment
3. Set *Input encoding* to **Auto** (it recognises Base64url) or force **Base64**
4. Add step: **Base64url (decode)** — the payload JSON appears in the Interpretations list.

**iOS backup / iCloud sync blob — lzfse-compressed plist**

Apple uses LZFSE compression extensively in iOS backups, iCloud sync metadata, and macOS system caches. The magic bytes `62 76 78 32` (`bvx2`) identify lzfse data:
1. Right-click the cell → *Inspect Cell…*
2. Add step: **lzfse decompress**
3. If the decompressed result is a plist, **✓ Plist / bplist** appears automatically.

**Multi-layer encoding (Base64url → lzfse → JSON)**

Some modern mobile backends layer encodings. Add steps in order and the pipeline resolves them one by one:
1. Add **Base64url (decode)** — converts the token to compressed bytes
2. Add **lzfse decompress** — decompresses to JSON
3. Click **✓ JSON** to read the payload

**Protobuf inside a bplist**

iOS apps sometimes store Protobuf bytes as a `<data>` field inside an NSKeyedArchiver bplist:
1. Add step: **Base64 (decode)** if the outer BLOB is Base64-encoded
2. Select **✓ Plist / bplist** — the NSKeyedArchiver is deserialised; note the field that holds raw bytes
3. To inspect the inner Protobuf, copy its hex from the plist view, open a new inspector via *Tools → BLOB Inspector…*, add **Hex → Bytes**, then select **~ Protobuf (schema-less)**.

