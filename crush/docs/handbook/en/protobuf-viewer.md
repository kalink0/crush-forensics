### Protobuf Viewer

Opens via right-click → **Open as** → **Protobuf**. Performs a schema-less wire-format decode showing field numbers, wire types, and values.

**Multi-interpretation display** — because the wire format carries no type information, every numeric field shows all plausible readings as dimmed child rows. An interpretation is only shown when the value falls within a plausible range; out-of-range candidates are suppressed silently.

**varint (wire type 0)**

| Interpretation | Condition |
|---|---|
| `uint64` | always |
| `int64` | only if value ≥ 2⁶³ (i.e. negative as signed) |
| `sint64 (zigzag)` | always |
| `bool` | only if value = 0 or 1 |
| `Unix timestamp (s)` | 946 684 800 ≤ value ≤ 4 102 444 800 (2000–2100) |
| `Chrome/WebKit timestamp (µs)` | 12 591 158 400 000 000 ≤ value ≤ 15 778 800 000 000 000 (µs since 1601-01-01) |

**fixed64 (wire type 1)**

| Interpretation | Condition |
|---|---|
| `uint64` | always |
| `int64` | only if negative |
| `double` | always, unless NaN or ±inf |
| `Cocoa timestamp` | double is finite AND 0 < double ≤ 3 155 673 600 (seconds since 2001-01-01) |
| `Unix timestamp (double, s)` | double is finite AND 946 684 800 ≤ double ≤ 4 102 444 800 |
| `Unix timestamp (uint64, s)` | 946 684 800 ≤ uint64 ≤ 4 102 444 800 |
| `Chrome/WebKit timestamp (µs)` | 12 591 158 400 000 000 ≤ uint64 ≤ 15 778 800 000 000 000 |

**fixed32 (wire type 5)**

| Interpretation | Condition |
|---|---|
| `uint32` | always |
| `int32` | only if negative |
| `float` | always, unless NaN or ±inf |
| `Unix timestamp (uint32, s)` | 946 684 800 ≤ uint32 ≤ 4 102 444 800 |

**length-delimited (wire type 2)** — decoded as nested message, UTF-8 string, or hex bytes; no interpretation child rows.

**start-group (3) / end-group (4)** — deprecated wire type; the group and its contents are silently skipped and parsing continues with the next field. A truncated group or an end-group tag at the top level produces a parse warning shown in the Properties panel.

In the **Blob Inspector** (Protobuf mode), `uint64` and `uint32` are additionally suppressed from the hint lines since they equal the primary value already shown on the field line.

**Schema-based decode** — click **Load .proto / descriptor…** to load a `.proto` source file or a compiled FileDescriptorSet (`.pb`, `.fds`, `.desc`). Select the root message type from the dropdown and click **Decode**. Field names and types are then resolved from the schema; the raw wire-format view remains available via **Show Raw Decode**.

