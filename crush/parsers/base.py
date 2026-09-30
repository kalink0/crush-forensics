"""Abstract parser base — all format parsers implement this interface."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Literal

from crush.core.vfs import VFS, VFSNode

ViewerType = Literal[
    "table",
    "tree",
    "tree_text",
    "hex",
    "text",
    "media",
    "image",
    "abx",
    "log",
    "multi_log",
    "protobuf",
    "realm",
    "leveldb",
    "pdf",
    "mmkv",
]


@dataclass
class ParseResult:
    """Result returned by every parser."""
    viewer_type: ViewerType
    data: Any                          # Passed directly to the matching viewer widget
    sub_nodes: list[VFSNode] = field(default_factory=list)   # Enables cascading
    metadata: dict[str, Any] = field(default_factory=dict)   # Shown in properties panel
    text_index: str = ""               # Plaintext for the search index
    viewer_hints: dict[str, Any] = field(default_factory=dict)  # Kwargs forwarded to viewer constructor


class AbstractParser(ABC):
    """Base class for all Crush parsers.

    To add support for a new data type:
    1. Subclass AbstractParser in crush/parsers/your_parser.py
    2. Set SUPPORTED_EXTENSIONS, DISPLAY_NAME
    3. Implement can_parse() and parse()
    4. Register in crush/parsers/__init__.py
    """

    SUPPORTED_EXTENSIONS: list[str] = []
    SUPPORTED_MIME_TYPES: list[str] = []
    DISPLAY_NAME: str = ""

    # Set True on a parser whose parse() accepts an optional `password`
    # kwarg for content that's encrypted at the file level (as opposed to
    # a whole VFS source being password-protected, handled separately via
    # crush.core.passwords at the VFS layer). The UI only passes `password`
    # to parsers that declare this, so it stays opt-in per format and the
    # base parse() signature doesn't force every parser to accept it.
    SUPPORTS_PASSWORD: bool = False

    # Set True on a parser whose parse() only reads bytes and builds plain
    # Python data -- no Qt objects, no thread-bound handles (sqlite
    # connections, open files kept in the result). The UI then runs it on a
    # background thread behind a "please wait" dialog for a large file,
    # instead of freezing the window while it parses.
    PARSE_OFF_UI_THREAD: bool = False

    @abstractmethod
    def can_parse(self, path: str, peek_bytes: bytes) -> bool:
        """Return True if this parser can handle the file.

        Prefer magic-byte sniffing over extension checks — extensions lie.
        peek_bytes contains the first 16 bytes of the file.
        """
        ...

    @abstractmethod
    def parse(self, node: VFSNode, vfs: VFS) -> ParseResult:
        """Parse the file and return a ParseResult.

        Implementations that set SUPPORTS_PASSWORD = True should additionally
        accept an optional `password: str | None = None` kwarg, and raise
        crush.core.passwords.WrongPasswordError if it fails to unlock the
        content (crush.core.passwords.PasswordRequiredError is for the VFS
        layer's whole-source case and does not apply here — a per-file
        "Open as <Format> (Encrypted)…" action always prompts before
        calling parse(), so there is no password=None-but-needed case to
        signal).
        """
        ...

    def _ext_match(self, path: str) -> bool:
        """Helper: check if the file extension matches SUPPORTED_EXTENSIONS."""
        from pathlib import Path
        return Path(path).suffix.lower() in self.SUPPORTED_EXTENSIONS
