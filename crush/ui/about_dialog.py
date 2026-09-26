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
from crush.ui.i18n import translate

def _about_html() -> str:
    tagline = translate("AboutDialog", "Digital Forensic Analysis Workbench")
    description = translate(
        "AboutDialog",
        "Open-source desktop workbench for digital forensic analysis. Inspect ZIP/TAR/7z/UFDR\n"
        "archives, raw disk images/EWF, and iTunes/Android backups. Parse and view ABX, SQLite, "
        "SEGB,\n(B)PLIST, REALM, Protobuf, MMKV, Logs, hex, JSON, XML, images, audio/video, "
        "PDF, and more —\nall in one GUI.",
    )
    thanks = translate(
        "AboutDialog",
        "Thank you to someone special — for every word of encouragement, for believing\n"
        "in me, for motivating me, and for the inspiration.",
    )
    license_line = translate("AboutDialog", "Licensed under the <b>Apache License 2.0</b>")
    report = translate("AboutDialog", "Report a bug or request a feature")
    return f"""\
<h2>Crush {crush.display_version()}</h2>
<p><b>{tagline}</b> &nbsp;·&nbsp; © {crush.__release_year__} Marco Neumann</p>
<p>{description}</p>
<p><i><small>{thanks}</small></i></p>
<p>{license_line}</p>
<p><a href="https://github.com/kalink0/crush-forensics">
github.com/kalink0/crush-forensics</a></p>
<p><a href="https://github.com/kalink0/crush-forensics/issues">{report}</a></p>
"""


def _ack_body() -> str:
    ul_version = get_bundled_ul_version()
    ul_label = f"unifiedlog_iterator {ul_version}" if ul_version else "unifiedlog_iterator"
    peach_version = get_bundled_peach_version()
    peach_label = f"peach {peach_version}" if peach_version else "peach"
    h_contributors = translate("AboutDialog", "Contributors")
    h_bundled = translate("AboutDialog", "Bundled third-party code")
    h_python = translate("AboutDialog", "Python package dependencies")
    h_tools = translate("AboutDialog", "Development tools")
    intro = translate(
        "AboutDialog",
        "Crush is built on the shoulders of the open-source and DFIR community.\n"
        "A huge thank you to everyone who contributed code, ideas, or feedback —\n"
        "your support makes this project possible."
    )
    # Package names, licenses and link labels stay as they are; the
    # descriptions are translated.
    desc = {
        'ccl_bplist': translate("AboutDialog", "Binary plist parser"),
        'ccl_segb': translate("AboutDialog", "SEGB (Significant Energy Bearer) parser"),
        'ccl_leveldb': translate("AboutDialog", "LevelDB / Chrome LevelDB parser"),
        'mmkv-parser': translate("AboutDialog", "MMKV key-value store reader"),
        'qnxprobe': translate(
            "AboutDialog",
            "Raw disk image / partition reader (NTFS, FAT32, exFAT, ext2/3/4, F2FS, HFS+, APFS, QNX6, QNX4, ETFS, EFS, QNX IFS, SquashFS, JFFS2, UBI/UBIFS, YAFFS)",
        ),
        'ewfprobe': translate(
            "AboutDialog",
            "EWF (Expert Witness Format, .E01) acquisition reader",
        ),
        'unifiedlog_iterator': translate(
            "AboutDialog",
            "Apple Unified Log (.tracev3 / .logarchive) converter — bundled in portable builds; when running from source, place the binary under <code>crush/bin/unifiedlog_iterator/</code>",
        ),
        'peach': translate(
            "AboutDialog",
            "Sibling forensic multi-log viewer — bundled in portable builds for \"Send to Peach\"; when running from source, place the binary under <code>crush/bin/peach/</code>",
        ),
        'crush-analyze': translate(
            "AboutDialog",
            "Sibling analyzer-module runner for \"Run Analyzer\" — individual modules ported from <a href=\"https://github.com/abrignoni/iLEAPP\">iLEAPP</a>/<a href=\"https://github.com/abrignoni/aLEAPP\">aLEAPP</a> artifact scripts by Alexis Brignoni (MIT); a normal pip dependency, not a bundled binary",
        ),
        'PySide6': translate("AboutDialog", "Qt for Python — GUI framework"),
        'biplist': translate("AboutDialog", "Binary plist read/write"),
        'lxml': translate("AboutDialog", "XML and HTML processing"),
        'construct': translate("AboutDialog", "Binary data structure parsing"),
        'python-magic': translate("AboutDialog", "File type detection via libmagic"),
        'filetype': translate("AboutDialog", "File type and MIME detection"),
        'pypdf': translate("AboutDialog", "PDF reading and text extraction"),
        'pypdfium2': translate("AboutDialog", "PDF page rendering (PDF viewer)"),
        'grpcio-tools': translate(
            "AboutDialog",
            "Protobuf / .proto schema compilation (optional, used by Protobuf viewer)",
        ),
        'Claude / Claude Code': translate("AboutDialog", "AI assistant used during development"),
    }
    return f"""\
<h3>{h_contributors}</h3>
<p>{intro}</p>

<h3>{h_bundled}</h3>
<table>
  <tr>
    <td><b>ccl_bplist</b></td>
    <td>{desc['ccl_bplist']}</td>
    <td class="lic">BSD 3-Clause</td>
    <td><a href="https://github.com/cclgroupltd/ccl-bplist">CCL Forensics</a></td>
  </tr>
  <tr class="alt">
    <td><b>ccl_segb</b></td>
    <td>{desc['ccl_segb']}</td>
    <td class="lic">MIT</td>
    <td><a href="https://github.com/cclgroupltd/ccl-segb">CCL Forensics</a></td>
  </tr>
  <tr>
    <td><b>ccl_leveldb</b></td>
    <td>{desc['ccl_leveldb']}</td>
    <td class="lic">MIT</td>
    <td><a href="https://github.com/cclgroupltd/ccl-leveldb">CCL Forensics</a></td>
  </tr>
  <tr class="alt">
    <td><b>mmkv-parser</b></td>
    <td>{desc['mmkv-parser']}</td>
    <td class="lic">MIT</td>
    <td><a href="https://github.com/abrignoni/mmkv-parser">Alexis Brignoni</a></td>
  </tr>
  <tr>
    <td><b>qnxprobe</b></td>
    <td>{desc['qnxprobe']}</td>
    <td class="lic">MIT</td>
    <td><a href="https://github.com/abrignoni/qnxprobe">Alexis Brignoni</a></td>
  </tr>
  <tr class="alt">
    <td><b>ewfprobe</b></td>
    <td>{desc['ewfprobe']}</td>
    <td class="lic">MIT</td>
    <td><a href="https://github.com/abrignoni/ewfprobe">Alexis Brignoni</a></td>
  </tr>
  <tr>
    <td><b>{ul_label}</b></td>
    <td>{desc['unifiedlog_iterator']}</td>
    <td class="lic">Apache 2.0</td>
    <td><a href="https://github.com/mandiant/macos-UnifiedLogs">Mandiant</a></td>
  </tr>
  <tr>
    <td><b>{peach_label}</b></td>
    <td>{desc['peach']}</td>
    <td class="lic">Apache 2.0</td>
    <td><a href="https://github.com/kalink0/peach-forensics">kalink0</a></td>
  </tr>
  <tr class="alt">
    <td><b>crush-analyze</b></td>
    <td>{desc['crush-analyze']}</td>
    <td class="lic">Apache 2.0</td>
    <td><a href="https://github.com/kalink0/crush-analyze">kalink0</a></td>
  </tr>
</table>

<h3>{h_python}</h3>
<table>
  <tr>
    <td><b>PySide6</b></td>
    <td>{desc['PySide6']}</td>
    <td class="lic">LGPL v3</td>
    <td><a href="https://doc.qt.io/qtforpython/">qt.io</a></td>
  </tr>
  <tr class="alt">
    <td><b>biplist</b></td>
    <td>{desc['biplist']}</td>
    <td class="lic">BSD</td>
    <td><a href="https://github.com/wooster/biplist">wooster/biplist</a></td>
  </tr>
  <tr>
    <td><b>lxml</b></td>
    <td>{desc['lxml']}</td>
    <td class="lic">BSD</td>
    <td><a href="https://lxml.de/">lxml.de</a></td>
  </tr>
  <tr class="alt">
    <td><b>construct</b></td>
    <td>{desc['construct']}</td>
    <td class="lic">MIT</td>
    <td><a href="https://construct.readthedocs.io/">construct</a></td>
  </tr>
  <tr>
    <td><b>python-magic</b></td>
    <td>{desc['python-magic']}</td>
    <td class="lic">MIT</td>
    <td><a href="https://github.com/ahupp/python-magic">ahupp/python-magic</a></td>
  </tr>
  <tr class="alt">
    <td><b>filetype</b></td>
    <td>{desc['filetype']}</td>
    <td class="lic">MIT</td>
    <td><a href="https://github.com/h2non/filetype.py">h2non/filetype.py</a></td>
  </tr>
  <tr>
    <td><b>pypdf</b></td>
    <td>{desc['pypdf']}</td>
    <td class="lic">BSD 3-Clause</td>
    <td><a href="https://pypdf.readthedocs.io/">pypdf</a></td>
  </tr>
  <tr class="alt">
    <td><b>pypdfium2</b></td>
    <td>{desc['pypdfium2']}</td>
    <td class="lic">Apache 2.0 / BSD 3-Clause</td>
    <td><a href="https://pypdfium2.readthedocs.io/">pypdfium2</a></td>
  </tr>
  <tr>
    <td><b>grpcio-tools</b></td>
    <td>{desc['grpcio-tools']}</td>
    <td class="lic">Apache 2.0</td>
    <td><a href="https://grpc.io">grpc.io</a></td>
  </tr>
</table>

<h3>{h_tools}</h3>
<table>
  <tr>
    <td><b>Claude / Claude Code</b></td>
    <td>{desc['Claude / Claude Code']}</td>
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
        self.setWindowTitle(translate("AboutDialog", "About Crush"))
        self.resize(620, 420)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        tabs = QTabWidget()

        # --- About tab ---
        about_widget = QWidget()
        about_layout = QVBoxLayout(about_widget)
        about_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        about_label = QLabel(_about_html())
        about_label.setWordWrap(True)
        about_label.linkActivated.connect(_open_link)
        about_label.setTextFormat(Qt.TextFormat.RichText)
        about_layout.addWidget(about_label)
        about_layout.addStretch()
        tabs.addTab(about_widget, translate("AboutDialog", "About"))

        # --- Acknowledgements tab ---
        ack_browser = QTextBrowser()
        ack_browser.setOpenExternalLinks(False)
        ack_browser.anchorClicked.connect(lambda url: _open_link(url.toString()))
        ack_browser.setHtml(_ack_html(ack_browser))
        tabs.addTab(ack_browser, translate("AboutDialog", "Acknowledgements"))

        layout.addWidget(tabs)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
