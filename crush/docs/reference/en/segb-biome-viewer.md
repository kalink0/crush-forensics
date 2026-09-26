### SEGB / Biome Viewer

Decodes Apple SEGB v1 and v2 files from the Biome framework. Shows timestamped records from app usage, screen time, Siri interaction, and location-adjacent signals.

The Properties panel shows a **Stream** field — the Biome stream name (e.g. `Device.Wireless.Bluetooth`), derived from the file's own path (the directory named after the stream, one level above its `local`/`remote` leaf) rather than from the payload, so it's shown even for streams whose field-level meaning isn't otherwise decoded.

Protobuf payloads are decoded automatically: double fields in the plausible Cocoa-timestamp range get a `[possible Cocoa timestamp: ...]` hint next to the raw number (the value itself is never replaced — there is no schema to confirm the field really is a date), nested messages are expanded inline with a `[raw: N B: hex…]` hint alongside them (wire type 2 doesn't declare that the bytes really are a submessage), and repeated fields are collected into arrays. Double-clicking a Payload cell opens the raw protobuf bytes in the Blob Inspector.

The table has an embedded **Show Hex** pane: selecting a row highlights its exact on-disk bytes (for v2, the trailer entry too, even though it physically lives at the end of the file), and selecting a specific column narrows the highlight to that field's own bytes where one exists (State, Timestamp/Creation, CRC Stored, Payload, and v2's Trailer Offset/Entry End Offset).

A backing SQLite database is created on open so you can query records using the built-in SQL editor (with autocomplete). Two payload columns are available:

| Column | Content |
|---|---|
| `Payload` | Human-readable rendered text |
| `Payload JSON` | Protobuf fields as JSON for `json_extract` queries |

Example queries:

```sql
-- All records where field 2 (bundle ID) matches
SELECT * FROM SEGB WHERE json_extract("Payload JSON", '$.2') = 'com.apple.Preferences';

-- Extract timestamp (field 1) and type (field 2) for every record
SELECT "Index", json_extract("Payload JSON", '$.1') AS ts,
                json_extract("Payload JSON", '$.2') AS type
FROM SEGB;

-- Nested field (field 6, sub-field 1)
SELECT json_extract("Payload JSON", '$.6.1') FROM SEGB;

-- Repeated field — first occurrence of field 9
SELECT json_extract("Payload JSON", '$.9[0]') FROM SEGB;
```

