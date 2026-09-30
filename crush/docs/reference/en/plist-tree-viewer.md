### Plist / Tree Viewer

Displays binary and XML property lists as a collapsible tree. Supports nested structures including arrays, dictionaries, data blobs, dates, and NSKeyedArchiver objects.

For an NSKeyedArchiver archive (recognised by its `$archiver` key, binary or XML), **Decoded** shows the object graph resolved from `$top`'s `root` (from all of `$top` when it has no `root`); the **Object table** tab shows the archive as stored — every `$top` key and every `$objects` entry by index, with references as UIDs. The Properties panel counts the archive's objects, those referenced more than once (class definitions counted separately), those no reference from `$top` reaches, and references to objects that don't exist, and lists `$top`'s keys.

