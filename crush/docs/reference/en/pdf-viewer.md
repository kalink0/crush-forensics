### PDF Viewer

**Pages** renders each page as an image, with prev/next navigation and a zoom slider (also Ctrl+scroll wheel), so layout, images, and form fields are visible — not just extractable text. **Text** shows the text extracted from the PDF. Password-protected PDFs open via right-click → **Open as** → **PDF (Encrypted)…**.

The Properties panel additionally shows the PDF version, XMP metadata, and always-visible JavaScript/Signatures/Attachments/Revisions fields (shown as "not present"/"none"/"0" rather than omitted, so it's clear these were actually checked, not skipped).

If the PDF has embedded files, an **Attachments** tab lists them — double-click (or right-click → **Open as New Tab**) to open one through the normal viewer pipeline, or **Export…** to save it to disk.

If the PDF was saved more than once without a full rewrite (an "incremental update" — very common, since most PDF editors default to this), a **History** tab appears with one entry per revision, oldest to newest:

- **Browse** — full Pages/Text/Attachments for a single revision at a time. A revision containing JavaScript, a signature field, or an attachment is marked with a ⚠ on its selector button, so you don't have to click into every revision to spot one that matters.
- **Text Diff** — a line-level diff (like `git diff`) between any two revisions, defaulting to the last two.
- **Visual Diff** — a pixel-level comparison of the same page across two revisions, with differing regions highlighted in red. Catches changes a text diff can't see, e.g. a black box drawn *over* text without touching the underlying content stream (the text is still there, just visually covered) — the classic "redaction that isn't."

