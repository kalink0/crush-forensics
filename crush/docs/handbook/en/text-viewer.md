### Text Viewer

Displays text files with line numbers, syntax highlighting, and search.

**Encoding detection** is automatic — the detected encoding is shown in the top-right corner of the toolbar. Supported: UTF-8, UTF-8 BOM, UTF-16 LE, UTF-16 BE, and UTF-16 LE without BOM (common in iOS preference files).

**Highlighting** is applied automatically based on content. You can override it with the **Highlight** dropdown: JSON, XML, SQL, INI/CONF, YAML, LOG, CSV, or None.

**Search:**
- Type in the search bar — matches are highlighted inline as you type
- Press Enter or **Down** to jump to the next hit; **Up** for the previous
- The match counter shows the total number of hits
- Enable **Regex** for regular expression patterns
- Enable **Case** for case-sensitive matching
- `*` wildcard is supported in non-regex mode
- **Show all** opens a result panel listing every match with its line, column, and a line preview — click a row to jump to it

