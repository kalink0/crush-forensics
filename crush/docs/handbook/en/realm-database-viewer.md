### Realm Database Viewer

Opens `.realm` files in a tabbed view. Column decoding is spec-driven — dispatched from each column's actual declared type/nullability/collection flags (read from its ColKey), not guessed from the data's shape — so it does not depend on the specific app that created the file.

| Tab | Content |
|---|---|
| **Header** | File metadata decoded from the Realm file header |
| **Schema** | All classes/tables with their columns and declared types (expand a table to see each field). A Link/LinkList column also shows which table it points to, e.g. `attachments: linklist → class_AttachmentLocalDto` |
| **Top Refs** | Comparison of top-ref pointers across header slots (useful for detecting corruption or versioning) |
| **File Structure** | The file's own physical array/reference-graph layout — file header, streaming-form footer where applicable, the Group top array and its children (table names/refs, free list), and per-table Spec/row storage — independent of the decoded Tables view below. Has the same embedded **Show Hex** byte-provenance pane, selecting a structure item highlights its exact bytes and vice versa. Covers both the modern Cluster format and legacy pre-Cluster files (row storage shown as "Column B+-Trees" instead of "ClusterTree", since pre-Cluster has no single shared row tree) |
| **Tables** | Decoded column data for each table; SQL queries run against a temporary SQLite representation of the data. Cells holding a List/Set/LinkList value are colour-flagged (grey when empty) with a tooltip, since they otherwise look like plain bracketed text. Has an embedded **Show Hex** pane too — selecting a cell highlights its real bytes in the actual `.realm` file, not the temporary SQLite copy |
| **Views** | Pick a table, choose per Link/LinkList column which columns of the linked table to pull in, and open the fully resolved result as a new tab — see below |
| **Freed Data** | Blocks from the file's internal free-space list (both the active and inactive top-ref), colour-coded by which ref they were freed in; right-click → **Inspect Block…** opens the raw bytes in the BLOB Inspector |
| **Strings** | String values extracted from the file |
| **Hex Preview** | Raw hex of the first bytes of the file |

**Views tab — resolving links without SQL**

A raw Link/LinkList column only holds internal object-key numbers (e.g. `[2]`), meaningless at a glance. The Views tab resolves them: select a table on the left, and every one of its Link/LinkList columns appears on the right as its own checklist of the linked table's columns (all checked by default; leave a column's whole checklist empty to leave it raw). **Open View** resolves every configured column at once and opens the table as a new tab, e.g. showing `from`/`to` as `email=...` instead of an object-key list.

**SQL queries in the Tables tab**

The decoded table data is loaded into a temporary SQLite file when the Tables tab is opened. Every table includes a leading `_objkey` column populated from the Realm ObjKey array. This allows cross-table JOINs using the same link-column values Realm stores internally:

```sql
SELECT a.title, e.name
FROM class_Article a
JOIN class_ArticleEDP e ON a.edp = e._objkey
```

List/Set/LinkList columns are stored as JSON text (e.g. `attachments` → `"[1, 2, 3]"`) — `LIKE` against them only does a text-substring match. For exact per-element matching, use SQLite's `json_each()`:

```sql
SELECT m._objkey, je.value AS attachment_objkey
FROM class_MessageAttributesLocalDto m, json_each(m.attachments) je
WHERE je.value = 2;
```

For every table with at least one Link/LinkList column, a matching `v_<table>` view is created automatically, with those columns already resolved to every column of the linked row (`col=val, col=val, ...` — deterministic, not a guess at which one column matters):

```sql
SELECT * FROM v_class_MessageAttributesLocalDto;
```

The SQL editor supports autocomplete (table, view, and column names, aliases). Double-clicking a row in the Summary view navigates directly to that table. BLOB column cells expose raw bytes in the Blob Inspector on double-click.

The temporary file is deleted automatically when the viewer is closed.

