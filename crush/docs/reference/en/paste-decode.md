## Paste & Decode

**Tools → Paste & Decode…** is an alternative entry point to the [BLOB Inspector](blob-inspector.md). It lets you paste raw binary data — copied from a hex editor, a SQLite BLOB cell, a network capture, or any other source — and inspect it directly in Crush without saving it to disk first.

1. Paste hex, base64, or plain text into the input area at the top.
2. Set **Input encoding** to **Auto** (default) or force a specific encoding if auto-detection picks the wrong one:
   - **Auto** — detects hex strings, Base64, and plain text automatically
   - **Hex** — treats the input as a hex string regardless of content
   - **Base64** — decodes as Base64 regardless of content
   - **UTF-8 text** — treats the input as UTF-8 text and passes the raw bytes through
3. The status line shows the detected encoding and decoded byte count as you type. If it stays grey, the input could not be decoded with the current encoding setting.
4. The full BLOB Inspector panel — three columns: *Decode pipeline*, *Interpretations*, *Content view* — appears directly below and updates live as you type.

All pipeline steps and interpretations available in the BLOB Inspector (Base64, zlib, gzip, …) are also available here. New decode steps added to the inspector appear automatically in Paste & Decode as well.

> **Tip:** The dialog is non-modal — you can keep it open and paste new data at any time while working in the main window.

---

