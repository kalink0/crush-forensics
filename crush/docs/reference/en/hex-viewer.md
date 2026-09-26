### Hex Viewer

Displays raw bytes as offset + hex + ASCII. The whole file is loaded; 256 KB is shown per page. Searching a large file (over 8 MB) runs behind a wait dialog.

| Control | Action |
|---|---|
| **◀ Prev / Next ▶** | Navigate pages for files larger than 256 KB |
| **Page N / M** | Shows current position and total pages |
| **Search as:** dropdown | Choose between **ASCII** (text string) and **Hex** (byte pattern, e.g. `FF D8 FF`) |
| **Find** button / Enter | Run search — collects all matches, jumps to first hit. All matches are highlighted in yellow, the current match in orange. |
| **↑ / ↓** | Navigate to previous / next match |
| **N / M** counter | Shows current match position and total count |
| **Show all** | Toggle a result panel below showing every match with its offset, hex bytes, and ASCII preview. Click a row to jump to it. |
| **Copy Hex** | Copy current page as space-separated hex bytes |
| **Copy ASCII** | Copy current page as ASCII (non-printable → `.`) |
| **Offset: Hex / Dec** | Toggle the left-hand offset gutter between hex and decimal. The status line and the "Show all" result panel's offset column switch with it. |
| **Go to offset: / Length: / Go** | Jump to a specific byte offset (parsed in whatever base the toggle above is set to). Fill in Length too to highlight that byte range instead of just scrolling to it. |

**Right-click on a selection:**
- **Search Selected as ASCII** — uses the bytes covered by the selection as a text search pattern
- **Search Selected as Hex** — uses the same bytes as a hex byte-pattern search
- **Copy Selected Hex / ASCII** — copies only the selected region

