### Chromium Disk Cache Viewer

Opens a Chromium disk cache folder — browser HTTP caches, app WebView caches, Cronet, Service Worker CacheStorage and script caches, Code Cache, GPU/shader caches — in both on-disk formats (Simple, Blockfile). Right-click the folder → **Open**; the folder is recognised by its files' bytes, not their names. A Simple entry file or `the-real-index` double-clicked on its own opens here too and says what it can't show without its folder. What is decoded and how: `crush/docs/format-support.md`, section *Chromium Disk Cache*.

**Overview tab** — format and versions, cache kind with entry counts, entry counts by state, the CacheStorage index entry naming this folder (cache name, storage key), how the index's first record field is read (last-used time, trailer prefetch size, or both as a heuristic), the Simple index or Blockfile index header, every file with its role (unrecognised files included), **Status** (e.g. a file the cache addresses that isn't there) and **Read problems**.

**Entries tab** — one row per entry:

| Column | Content |
|---|---|
| # | Entry number in this view |
| State | *normal*, *evicted* or *doomed* |
| Kind | HTTP cache, Code Cache, Code Cache data, CacheStorage, *HTTP cache or CacheStorage (heuristic: the key is a URL)*, or *not determined from the key* |
| URL / Top-frame site | The key's URL and, for a partitioned key, the site that loaded it |
| HTTP status / Content type / Content encoding | From the response headers |
| Body size (B) | Bytes stored for the body (stream 1, or the sparse ranges' total) |
| Request time / Response time (UTC) | From the response info (CacheStorage and Code Cache: response time) |
| Last used (UTC) | Simple index record (when it holds a time) or Blockfile rankings node |
| Entry created (UTC) | Blockfile creation time; CacheStorage entry time |
| Server / Protocol | Server IP and port; connection info or ALPN protocol |
| Key / Hash | The whole key; the Simple entry hash or Blockfile key hash |
| Stored in | The entry's files (Simple) or its record's address (Blockfile) |
| Note | Everything the analyst must know about the entry: heuristic readings, checks that failed, why content isn't decoded |

**Orphans / Recovered tab** — Simple index records whose entry file isn't in the folder (hash, last-used time or prefetch size, size), and Blockfile entry records found in free blocks (marked *free block (heuristic)*, with why each was taken and what else holds). A tab with nothing in it says why.

Toolbar controls (both tabs): **State** filter, **Search** (case-insensitive across all columns), **Export CSV…** (visible rows, English values).

Selecting a row reads that entry and fills the tabbed pane below:

| Tab | Content |
|---|---|
| **Summary** | Kind and what determined it, the key's parts (for a heuristic kind the candidate kinds, each with why), every note |
| **Structure: \<file\>** | One per file the entry is stored in: its decoded fields as a tree next to the file's hex; selecting a field highlights its bytes (header, key, streams, EOF records with their CRC check, stream 0 decoded, index record, rankings node) |
| **Headers** | Status line and every response header in stored order; CacheStorage also the request headers |
| **Certificates** | Each certificate's subject, issuer, serial number, validity, fingerprints and SANs; **Open certificate n (DER)** opens it in a new tab |
| **Body** | RAW as stored, the derived (decompressed) body where the declared Content-Encoding applies (labelled *candidate* where it holds only under one reading of a heuristic kind), sparse ranges with their gaps; **Open … in new tab** hands the bytes to whichever viewer their content calls for |
| **Streams** | Each stream's RAW bytes with where they are stored; **Open in new tab** |
