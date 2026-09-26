### BLOB Inspector

The BLOB Inspector is a shared decode dialog for examining raw binary fields. It opens as a non-modal window — the rest of the UI stays fully accessible and multiple inspector windows can be open at the same time.

**How to open it:**
- **SQLite viewer** — right-click any cell → **Inspect Cell…**
- **LevelDB viewer** — right-click any record row → **Inspect Key…**, **Inspect Value…**, or **Inspect Internal Key…**
- **Realm viewer** — right-click any freed block in the Freed Data tab → **Inspect Block…**
- **Tools → Paste & Decode…** — paste hex, base64, or text directly into the inspector without a source file

---

#### Layout — three columns

| Column | Purpose |
|---|---|
| **Decode pipeline** (left) | Chain of byte→byte transform steps applied before interpretation. Click **＋ Add step** to append a step; click **×** to remove one. Steps run top-to-bottom; if a step fails the pipeline stops there and the error is shown inline. |
| **Interpretations** (middle) | All available display formats for the bytes produced by the pipeline, grouped by confidence. Click any entry to switch the content view instantly — no second click needed. |
| **Content view** (right) | The rendered output for the selected interpretation. **Copy** copies the full content to the clipboard. Right-click in hex view for per-selection copy options. |

---

#### Decode pipeline steps

Pipeline steps are byte→byte transforms that pre-process the raw bytes before the interpretations are evaluated. Steps are chained: the output of step 1 is the input of step 2, and so on. The byte count after each step is shown inline.

| Step | What it does | Typical source |
|---|---|---|
| **Base64 (decode)** | Decodes standard Base64 with `+`/`/` charset and `=` padding | iOS/Android SQLite BLOBs, email attachments |
| **Base64url (decode)** | Decodes URL-safe Base64 with `-`/`_` charset; padding optional | JWT payloads, web API tokens, OAuth parameters |
| **Hex → Bytes** | Converts hex strings with any separator (space, colon, none) to raw bytes | Database hex columns, copy-pasted hex dumps |
| **zlib decompress** | Decompresses zlib data (deflate stream with zlib header, `0x78 …`) | Chrome LevelDB values, iOS WebKit caches |
| **gzip decompress** | Decompresses gzip data (magic `1f 8b`) | HTTP response bodies, server-side log archives |
| **lzfse decompress** | Decompresses Apple LZFSE data (magic `bvx2` / `bvxn` / `bvxx`) | iOS backups, iCloud sync blobs, macOS system caches, APFS metadata |

Steps can be combined freely. To decode a value that is Base64url-encoded and then lzfse-compressed, add **Base64url** as step 1 and **lzfse decompress** as step 2.

---

#### Interpretations

After the pipeline runs, the resulting bytes are tested against all available interpretations. The list is grouped into three tiers:

| Marker | Meaning |
|---|---|
| *(no marker)* | **Hex view** — always available as the baseline |
| **✓** | Confident — format positively identified (magic bytes, strict parse, valid structure) |
| **~** | Permissive — format almost always succeeds regardless of content; treat as a fallback, not a confirmation |
| *(gray, no marker)* | Failed — bytes did not match this format |

**Available interpretations:**

| Interpretation | Tier | Notes |
|---|---|---|
| **Hex view** | baseline | Annotated hex dump with address / hex / ASCII columns |
| **UTF-8 text** | ✓ | Only ✓ when all bytes are valid UTF-8; strict decode |
| **JSON** | ✓ | Pretty-prints valid JSON; also detects escaped JSON embedded in a string |
| **Plist / bplist** | ✓ | Decodes binary (`bplist00`) or XML property list. NSKeyedArchiver payloads are automatically deserialised and the object graph is rendered as a Python pprint |
| **XML** | ✓ | Parses and pretty-prints well-formed XML (via lxml) |
| **Android Binary XML (ABX)** | ✓ | Reconstructs XML from Android's compact binary XML format |
| **Image** | ✓ | Renders the image inline — PNG, JPEG, GIF, BMP, WebP, HEIC, AVIF |
| **Protobuf (schema-less)** | ~ | Wire-format decode. Numeric fields include `# label: value` hints for int64, sint64 (zigzag), bool, Unix/Cocoa/Chrome timestamps, double, and float; a field shown as a nested message also gets a `# raw bytes: ...` hint, since wire type 2 doesn't actually declare whether the bytes are a submessage. A `# Warning:` header appears if the parse was truncated or malformed. Shown as **~** because Protobuf's wire format accepts most byte sequences. |
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
3. The Interpretations list shows **✓ Plist / bplist** — click it to read the deserialised object graph, including NSKeyedArchiver structures.

**JWT / OAuth token stored in a database**

Web-facing apps (and some native apps) store JWT tokens in SQLite. The token payload is the second dot-separated segment, Base64url-encoded without padding:
1. Copy the middle segment (between the first and second `.`)
2. Open *Tools → Paste & Decode…*, paste the segment
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
3. To inspect the inner Protobuf, copy its hex from the plist view, open a new inspector via *Paste & Decode…*, add **Hex → Bytes**, then select **~ Protobuf (schema-less)**.

