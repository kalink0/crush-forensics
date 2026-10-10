### Plist / Tree Viewer

Displays binary and XML property lists as a collapsible tree. Supports nested structures including arrays, dictionaries, data blobs, dates, and NSKeyedArchiver objects.

For an NSKeyedArchiver archive (recognised by its `$archiver` key, binary or XML), **Decoded** shows the object graph resolved from `$top`'s `root` (from all of `$top` when it has no `root`); the **Stored archive** tab shows the archive as stored — every `$top` key and every `$objects` entry by index, with references as UIDs. The Properties panel names the root object's class and counts the archive's objects, those referenced more than once (class definitions counted separately), those no reference from `$top` reaches, and references to objects that don't exist, and lists `$top`'s keys.

When an archive isn't resolved (XML form, references to objects that don't exist, a cycle, or resolving failed), **Decoded** shows the archive as stored, and a line above the tabs says why. An `NSDictionary` whose keys can't form a plain dictionary (a key that is itself an object such as another dictionary, or keys equal once resolved) keeps its `NS.keys` and `NS.objects` lists, paired by position; the rest of the archive is resolved.

