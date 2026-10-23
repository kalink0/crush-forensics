### Plist / Tree Viewer

Displays binary and XML property lists as a collapsible tree. Supports nested structures including arrays, dictionaries, data blobs, dates, and NSKeyedArchiver objects. An XML plist is recognised by its content, also with a BOM or whitespace before it or without an XML declaration.

For an NSKeyedArchiver archive (recognised by its `$archiver` key, binary or XML), **Decoded** shows the object graph resolved from `$top`: the root object when `$top` holds only `root`, otherwise `$top` itself with every key resolved under its name. The **Stored archive** tab shows the archive as stored — every `$top` key and every `$objects` entry by index, with references as UIDs. The Properties panel names the root object's class and counts the archive's objects, those referenced more than once (class definitions counted separately), those no reference from `$top` reaches, and references to objects that don't exist, and lists `$top`'s keys.

When an archive isn't resolved (references to objects that don't exist, a cycle, or resolving failed), **Decoded** shows the archive as stored, and a line above the tabs says why. An `NSDictionary` whose keys can't form a plain dictionary (a key that is itself an object such as another dictionary, or keys equal once resolved), an `NSUUID` whose bytes aren't 16, and an `NSDate` whose time isn't a representable date keep their stored keys; the rest of the archive is resolved, and the Properties panel counts such dates.

A bytes value that holds a plist — binary or XML, an archive or not — keeps its bytes as the value and gets a child row **decoded (plist)** or **decoded (NSKeyedArchiver)** with what Crush decoded from them; when they can't be decoded, the child row says why.

