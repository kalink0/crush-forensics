# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""About dialog — version info and third-party acknowledgements."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QPalette
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

import crush
from crush.core.peach_launcher import get_bundled_peach_version
from crush.parsers.unified_log_parser import get_bundled_ul_version
from crush.ui import open_url as _open_link

_ABOUT_HTML = f"""\
<h2>Crush {crush.display_version()}</h2>
<p><b>Digital Forensic Analysis Workbench</b> &nbsp;·&nbsp; © {crush.__release_year__} Marco Neumann</p>
<p>Open-source desktop workbench for digital forensic analysis. Inspect ZIP/TAR acquisitions
and parse ABX, SQLite, SEGB, PLIST, hex, JSON, XML, and media files — all in one GUI.</p>
<p>Licensed under the <b>Apache License 2.0</b></p>
<p><a href="https://github.com/kalink0/crush-forensics">
github.com/kalink0/crush-forensics</a></p>
<p><a href="https://github.com/kalink0/crush-forensics/issues">Report a bug or request a feature</a></p>
"""

def _ack_body() -> str:
    ul_version = get_bundled_ul_version()
    ul_label = f"unifiedlog_iterator {ul_version}" if ul_version else "unifiedlog_iterator"
    peach_version = get_bundled_peach_version()
    peach_label = f"peach {peach_version}" if peach_version else "peach"
    return f"""\
<h3>Contributors</h3>
<p>Crush is built on the shoulders of the open-source and DFIR community.
A huge thank you to everyone who contributed code, ideas, or feedback —
your support makes this project possible.</p>

<h3>Bundled third-party code</h3>
<table>
  <tr>
    <td><b>ccl_bplist</b></td>
    <td>Binary plist parser</td>
    <td class="lic">BSD 3-Clause</td>
    <td><a href="https://github.com/cclgroupltd/ccl-bplist">CCL Forensics</a></td>
  </tr>
  <tr class="alt">
    <td><b>ccl_segb</b></td>
    <td>SEGB (Significant Energy Bearer) parser</td>
    <td class="lic">MIT</td>
    <td><a href="https://github.com/cclgroupltd/ccl-segb">CCL Forensics</a></td>
  </tr>
  <tr>
    <td><b>ccl_leveldb</b></td>
    <td>LevelDB / Chrome LevelDB parser</td>
    <td class="lic">MIT</td>
    <td><a href="https://github.com/cclgroupltd/ccl-leveldb">CCL Forensics</a></td>
  </tr>
  <tr class="alt">
    <td><b>{ul_label}</b></td>
    <td>Apple Unified Log (.tracev3 / .logarchive) converter — bundled in portable builds; when running from source, place the binary under <code>crush/bin/unifiedlog_iterator/</code></td>
    <td class="lic">Apache 2.0</td>
    <td><a href="https://github.com/mandiant/macos-UnifiedLogs">Mandiant</a></td>
  </tr>
  <tr>
    <td><b>{peach_label}</b></td>
    <td>Sibling forensic multi-log viewer — bundled in portable builds for "Send to Peach"; when running from source, place the binary under <code>crush/bin/peach/</code></td>
    <td class="lic">Apache 2.0</td>
    <td><a href="https://github.com/kalink0/peach-forensics">kalink0</a></td>
  </tr>
</table>

<h3>Python package dependencies</h3>
<table>
  <tr>
    <td><b>PySide6</b></td>
    <td>Qt for Python — GUI framework</td>
    <td class="lic">LGPL v3</td>
    <td><a href="https://doc.qt.io/qtforpython/">qt.io</a></td>
  </tr>
  <tr class="alt">
    <td><b>biplist</b></td>
    <td>Binary plist read/write</td>
    <td class="lic">BSD</td>
    <td><a href="https://github.com/wooster/biplist">wooster/biplist</a></td>
  </tr>
  <tr>
    <td><b>lxml</b></td>
    <td>XML and HTML processing</td>
    <td class="lic">BSD</td>
    <td><a href="https://lxml.de/">lxml.de</a></td>
  </tr>
  <tr class="alt">
    <td><b>construct</b></td>
    <td>Binary data structure parsing</td>
    <td class="lic">MIT</td>
    <td><a href="https://construct.readthedocs.io/">construct</a></td>
  </tr>
  <tr>
    <td><b>python-magic</b></td>
    <td>File type detection via libmagic</td>
    <td class="lic">MIT</td>
    <td><a href="https://github.com/ahupp/python-magic">ahupp/python-magic</a></td>
  </tr>
  <tr class="alt">
    <td><b>filetype</b></td>
    <td>File type and MIME detection</td>
    <td class="lic">MIT</td>
    <td><a href="https://github.com/h2non/filetype.py">h2non/filetype.py</a></td>
  </tr>
  <tr>
    <td><b>pypdf</b></td>
    <td>PDF reading and text extraction</td>
    <td class="lic">BSD 3-Clause</td>
    <td><a href="https://pypdf.readthedocs.io/">pypdf</a></td>
  </tr>
  <tr class="alt">
    <td><b>pypdfium2</b></td>
    <td>PDF page rendering (PDF viewer)</td>
    <td class="lic">Apache 2.0 / BSD 3-Clause</td>
    <td><a href="https://pypdfium2.readthedocs.io/">pypdfium2</a></td>
  </tr>
  <tr>
    <td><b>grpcio-tools</b></td>
    <td>Protobuf / .proto schema compilation (optional, used by Protobuf viewer)</td>
    <td class="lic">Apache 2.0</td>
    <td><a href="https://grpc.io">grpc.io</a></td>
  </tr>
</table>

<h3>Development tools</h3>
<table>
  <tr>
    <td><b>Claude / Claude Code</b></td>
    <td>AI assistant used during development</td>
    <td class="lic"></td>
    <td><a href="https://claude.ai">Anthropic</a></td>
  </tr>
</table>
"""


def _styled_html(browser: QTextBrowser, body: str) -> str:
    """Wrap *body* in a palette-aware stylesheet."""
    pal = browser.palette()
    text = pal.color(QPalette.ColorRole.Text).name()
    muted = pal.color(QPalette.ColorRole.PlaceholderText).name()
    alt_bg = pal.color(QPalette.ColorRole.AlternateBase).name()
    return f"""\
<style>
  body  {{ font-family: sans-serif; font-size: 13px; color: {text}; }}
  h3    {{ margin-top: 16px; margin-bottom: 4px; }}
  table {{ border-collapse: collapse; width: 100%; }}
  td    {{ padding: 4px 8px; vertical-align: top; }}
  tr.alt td {{ background: {alt_bg}; }}
  .lic  {{ color: {muted}; font-size: 12px; }}
  a     {{ color: {text}; }}
</style>
{body}"""


def _ack_html(browser: QTextBrowser) -> str:
    return _styled_html(browser, _ack_body())



class AboutDialog(QDialog):
    """Tabbed About dialog with version info and third-party acknowledgements."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("About Crush")
        self.resize(620, 420)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        tabs = QTabWidget()

        # --- About tab ---
        about_widget = QWidget()
        about_layout = QVBoxLayout(about_widget)
        about_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        about_label = QLabel(_ABOUT_HTML)
        about_label.setWordWrap(True)
        about_label.linkActivated.connect(_open_link)
        about_label.setTextFormat(Qt.TextFormat.RichText)
        about_layout.addWidget(about_label)
        about_layout.addStretch()
        tabs.addTab(about_widget, "About")

        # --- Acknowledgements tab ---
        ack_browser = QTextBrowser()
        ack_browser.setOpenExternalLinks(False)
        ack_browser.anchorClicked.connect(lambda url: _open_link(url.toString()))
        ack_browser.setHtml(_ack_html(ack_browser))
        tabs.addTab(ack_browser, "Acknowledgements")

        layout.addWidget(tabs)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
