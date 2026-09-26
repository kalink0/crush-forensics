### ABX Viewer

Decodes Android Binary XML (ABX) format used in Android system and app settings directories. The reconstructed-XML pane is pretty-printed and has a Ctrl+F search bar (regex/case options, hit navigation). Files with multiple top-level elements and no enclosing root (e.g. `settings_secure.xml`) are wrapped in a synthetic `<abx-root>` so they still resolve to a tree.

