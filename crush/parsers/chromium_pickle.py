# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Chromium base::Pickle and the HttpResponseInfo stored in it.

Written from the Chromium source at revision 278016c7cf72 (2026-10-28):
base/pickle.cc, net/http/http_response_info.cc, net/http/http_response_headers.cc,
net/http/http_vary_data.cc, net/cert/x509_certificate.cc, net/base/proxy_chain.cc,
net/base/proxy_server.cc, net/ssl/ssl_connection_status_flags.h,
net/http/http_connection_info.cc.

Every decoded field keeps the byte range it was read from (absolute offsets
in the file the pickle sits in), for the structure view's hex highlighting.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

from crush.core.issues import QT_TRANSLATE_NOOP, ParseIssue
from crush.core.ts_decode import decode_ts

# Path into a decoded structure (dict keys, list indices as str) -> its bytes,
# as TreeViewer(byte_ranges_by_path=...) takes them.
Ranges = dict[tuple[str, ...], dict[str, Any]]

# net/http/http_response_info.cc
_VERSION_MASK = 0xFF
_RESPONSE_INFO_VERSION = 3
_MINIMUM_VERSION = 3
_HAS_CERT = 1 << 8
_HAS_SECURITY_BITS = 1 << 9
_HAS_CERT_STATUS = 1 << 10
_HAS_VARY_DATA = 1 << 11
_TRUNCATED = 1 << 12
_WAS_SPDY = 1 << 13
_WAS_ALPN = 1 << 14
_WAS_PROXY = 1 << 15
_HAS_SSL_CONNECTION_STATUS = 1 << 16
_HAS_ALPN_NEGOTIATED_PROTOCOL = 1 << 17
_HAS_CONNECTION_INFO = 1 << 18
_USE_SERVER_HTTP_AUTHENTICATION = 1 << 19
_HAS_SIGNED_CERTIFICATE_TIMESTAMPS = 1 << 20
_UNUSED_SINCE_PREFETCH = 1 << 21
_HAS_KEY_EXCHANGE_GROUP = 1 << 22
_PKP_BYPASSED = 1 << 23
_HAS_STALENESS = 1 << 24
_HAS_PEER_SIGNATURE_ALGORITHM = 1 << 25
_RESTRICTED_PREFETCH = 1 << 26
_HAS_DNS_ALIASES = 1 << 27
_UNUSED_SINGLE_KEYED = 1 << 28
_ENCRYPTED_CLIENT_HELLO = 1 << 29
_BROWSER_RUN_ID = 1 << 30
_HAS_EXTRA_FLAGS = 1 << 31

_EXTRA_DID_USE_SHARED_DICTIONARY = 1
_EXTRA_HAS_PROXY_CHAIN = 1 << 1
_EXTRA_HAS_ORIGINAL_RESPONSE_TIME = 1 << 2
_EXTRA_HAS_ENCODED_BODY_SIZE = 1 << 3
_EXTRA_HAS_ZSTD_UNCOMPRESSED_BODY_SIZE = 1 << 4

# Flag bits that only say something (no field follows), by name.
_FLAG_NAMES = (
    (_HAS_CERT, "HAS_CERT"),
    (_HAS_SECURITY_BITS, "HAS_SECURITY_BITS"),
    (_HAS_CERT_STATUS, "HAS_CERT_STATUS"),
    (_HAS_VARY_DATA, "HAS_VARY_DATA"),
    (_TRUNCATED, "TRUNCATED"),
    (_WAS_SPDY, "WAS_SPDY"),
    (_WAS_ALPN, "WAS_ALPN"),
    (_WAS_PROXY, "WAS_PROXY"),
    (_HAS_SSL_CONNECTION_STATUS, "HAS_SSL_CONNECTION_STATUS"),
    (_HAS_ALPN_NEGOTIATED_PROTOCOL, "HAS_ALPN_NEGOTIATED_PROTOCOL"),
    (_HAS_CONNECTION_INFO, "HAS_CONNECTION_INFO"),
    (_USE_SERVER_HTTP_AUTHENTICATION, "USE_SERVER_HTTP_AUTHENTICATION"),
    (_HAS_SIGNED_CERTIFICATE_TIMESTAMPS, "HAS_SIGNED_CERTIFICATE_TIMESTAMPS"),
    (_UNUSED_SINCE_PREFETCH, "UNUSED_SINCE_PREFETCH"),
    (_HAS_KEY_EXCHANGE_GROUP, "HAS_KEY_EXCHANGE_GROUP"),
    (_PKP_BYPASSED, "PKP_BYPASSED"),
    (_HAS_STALENESS, "HAS_STALENESS"),
    (_HAS_PEER_SIGNATURE_ALGORITHM, "HAS_PEER_SIGNATURE_ALGORITHM"),
    (_RESTRICTED_PREFETCH, "RESTRICTED_PREFETCH"),
    (_HAS_DNS_ALIASES, "HAS_DNS_ALIASES"),
    (_UNUSED_SINGLE_KEYED, "UNUSED_WAS_SINGLE_KEYED_CACHE_ENTRY_UNUSABLE"),
    (_ENCRYPTED_CLIENT_HELLO, "ENCRYPTED_CLIENT_HELLO"),
    (_BROWSER_RUN_ID, "BROWSER_RUN_ID"),
    (_HAS_EXTRA_FLAGS, "HAS_EXTRA_FLAGS"),
)
_EXTRA_FLAG_NAMES = (
    (_EXTRA_DID_USE_SHARED_DICTIONARY, "DID_USE_SHARED_DICTIONARY"),
    (_EXTRA_HAS_PROXY_CHAIN, "HAS_PROXY_CHAIN"),
    (_EXTRA_HAS_ORIGINAL_RESPONSE_TIME, "HAS_ORIGINAL_RESPONSE_TIME"),
    (_EXTRA_HAS_ENCODED_BODY_SIZE, "HAS_ENCODED_BODY_SIZE"),
    (_EXTRA_HAS_ZSTD_UNCOMPRESSED_BODY_SIZE, "HAS_ZSTD_UNCOMPRESSED_BODY_SIZE"),
)

# net/ssl/ssl_connection_status_flags.h
_SSL_VERSIONS = {
    0: "unknown", 1: "SSL 2", 2: "SSL 3", 3: "TLS 1.0", 4: "TLS 1.1",
    5: "TLS 1.2", 6: "TLS 1.3", 7: "QUIC",
}

# net/http/http_connection_info.cc HttpConnectionInfoToString
_CONNECTION_INFO = {
    0: "unknown", 1: "http/1.1", 2: "spdy/2", 3: "spdy/3", 4: "h2",
    5: "http/2+quic", 6: "h2", 7: "h2", 8: "http/0.9", 9: "http/1.0",
    10: "http/2+quic/32", 11: "http/2+quic/33", 12: "http/2+quic/34",
    13: "http/2+quic/35", 14: "http/2+quic/36", 15: "http/2+quic/37",
    16: "http/2+quic/38", 17: "http/2+quic/39", 18: "http/2+quic/40",
    19: "http/2+quic/41", 20: "http/2+quic/42", 21: "http/2+quic/43",
    22: "h3-Q099", 23: "http/2+quic/44", 24: "http/2+quic/45",
    25: "http/2+quic/46", 26: "http/2+quic/47", 27: "http2+quic/999",
    28: "h3-Q048", 29: "h3-Q049", 30: "h3-Q050", 31: "h3-T048", 32: "h3-T049",
    33: "h3-T050", 34: "h3-T099", 35: "h3-25", 36: "h3-27", 37: "h3-28",
    38: "h3-29", 39: "h3-T051", 40: "h3", 41: "h3/quic2draft01", 42: "h3/quic2draft08",
}

# net/http/http_vary_data.h HashType
_VARY_HASH = {0: ("MD5", 16), 1: ("SHA-256", 32)}


class PickleError(Exception):
    """Reading ran past the pickle's end or met an invalid value."""

    def __init__(self, issue: ParseIssue) -> None:
        super().__init__(str(issue))
        self.issue = issue


def chrome_time(value: int) -> str:
    """A base::Time internal value (µs since 1601-01-01 UTC) as shown:
    the UTC time and the stored number. 0 is base::Time's null value."""
    if value == 0:
        return QT_TRANSLATE_NOOP("GeneratedView", "not set (0)")
    text = decode_ts(value, "chrome")
    return f"{text} ({value})" if text else str(value)


def chrome_time_utc(value: int | None) -> str:
    """Only the UTC text of a base::Time internal value ("" for null or
    out of range): for a table column that sorts by the number."""
    if not value:
        return ""
    return decode_ts(value, "chrome") or ""


class ChromeTime:
    """A base::Time value in a structure tree, shown as chrome_time() --
    formatted when displayed, not when the tree is built."""

    __slots__ = ("value",)

    def __init__(self, value: int) -> None:
        self.value = value

    def __str__(self) -> str:
        return chrome_time(self.value)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ChromeTime) and other.value == self.value

    def __hash__(self) -> int:
        return hash(self.value)


@dataclass
class Tree:
    """A decoded structure being built: nested dicts (str keys) and the byte
    range of each path in it."""

    root: dict[str, Any] = field(default_factory=dict)
    ranges: Ranges = field(default_factory=dict)

    def put(
        self, path: tuple[str, ...], value: Any, start: int | None = None, end: int | None = None
    ) -> None:
        node = self.root
        for part in path[:-1]:
            child = node.get(part)
            if not isinstance(child, dict):
                child = node[part] = {}
            node = child
        node[path[-1]] = value
        if start is not None and end is not None:
            self.mark(path, start, end)

    def mark(self, path: tuple[str, ...], start: int, end: int) -> None:
        self.ranges[path] = {"byte_range": (start, end), "highlight_ranges": [(start, end)]}

    def graft(self, path: tuple[str, ...], other: Tree) -> None:
        """Put *other*'s structure at *path*, with its ranges."""
        self.put(path, other.root)
        for sub, rng in other.ranges.items():
            self.ranges[path + sub] = rng


class NullTree(Tree):
    """A Tree that keeps nothing: for reading only the facts (the entry
    table while parsing) without building the structure view's tree."""

    def put(
        self, path: tuple[str, ...], value: Any, start: int | None = None, end: int | None = None
    ) -> None:
        return None

    def mark(self, path: tuple[str, ...], start: int, end: int) -> None:
        return None

    def graft(self, path: tuple[str, ...], other: Tree) -> None:
        return None


class Pickle:
    """Reads a base::Pickle: a uint32 payload size first (more header
    fields after it for some pickles), then the payload, every read
    aligned to 4 bytes (base/pickle.cc).

    *base* is where *data* starts in its file; read() returns absolute
    offsets."""

    def __init__(self, data: bytes, base: int = 0, header_size: int = 4) -> None:
        if len(data) < header_size:
            raise PickleError(ParseIssue("chromium_cache.pickle_short", {"size": len(data)}))
        payload_size = int(struct.unpack_from("<I", data)[0])
        self.data = data
        self.base = base
        self.payload_size = payload_size
        self.header_size = header_size
        # base::Pickle derives the header size from the payload size; a
        # pickle whose stored payload size doesn't leave exactly the header
        # before it is read only up to what is there.
        self.end = min(len(data), header_size + payload_size)
        self.pos = header_size

    @property
    def size_matches(self) -> bool:
        """Header size + stored payload size is exactly the data's length."""
        return self.header_size + self.payload_size == len(self.data)

    def _take(self, n: int, what: str) -> tuple[bytes, int, int]:
        if n < 0 or self.pos + n > self.end:
            raise PickleError(ParseIssue(
                "chromium_cache.pickle_past_end",
                {"what": what, "offset": self.base + self.pos, "size": n},
            ))
        start = self.pos
        raw = self.data[start:start + n]
        # AlignAfterRead: the next read starts at a multiple of 4.
        self.pos = start + ((n + 3) & ~3)
        return raw, self.base + start, self.base + start + n

    def _number(self, fmt: str, size: int, what: str) -> tuple[int, int, int]:
        raw, s, e = self._take(size, what)
        return int(struct.unpack(fmt, raw)[0]), s, e

    def int32(self, what: str) -> tuple[int, int, int]:
        return self._number("<i", 4, what)

    def uint32(self, what: str) -> tuple[int, int, int]:
        return self._number("<I", 4, what)

    def uint16(self, what: str) -> tuple[int, int, int]:
        return self._number("<H", 2, what)

    def int64(self, what: str) -> tuple[int, int, int]:
        return self._number("<q", 8, what)

    def uint64(self, what: str) -> tuple[int, int, int]:
        return self._number("<Q", 8, what)

    def length(self, what: str) -> tuple[int, int, int]:
        value, s, e = self.int32(what)
        if value < 0:
            raise PickleError(ParseIssue(
                "chromium_cache.pickle_negative_length", {"what": what, "offset": s}
            ))
        return value, s, e

    def raw(self, n: int, what: str) -> tuple[bytes, int, int]:
        return self._take(n, what)

    def string(self, what: str) -> tuple[bytes, int, int]:
        """A length-prefixed string: (bytes, start of the length, end of the bytes)."""
        n, s, _e = self.length(what)
        raw, _s2, e = self._take(n, what)
        return raw, s, e

    @property
    def remaining(self) -> int:
        return self.end - self.pos


def _text(raw: bytes) -> str:
    """Bytes from the file as text: UTF-8, invalid bytes escaped (the RAW
    bytes stay visible in the hex view)."""
    return raw.decode("utf-8", errors="backslashreplace")


def split_headers(raw: bytes) -> tuple[str, list[tuple[str, str]]]:
    """HttpResponseHeaders' raw form: the status line and every header
    line, each ended by a NUL, the block ended by a second NUL. Header
    lines are split at their first ':' (as HttpResponseHeaders::Parse);
    a line without one is kept whole as the name with an empty value."""
    parts = raw.split(b"\0")
    status = _text(parts[0]) if parts else ""
    headers: list[tuple[str, str]] = []
    for line in parts[1:]:
        if not line:
            continue
        name, sep, value = line.partition(b":")
        headers.append((_text(name), _text(value.strip(b" \t")) if sep else ""))
    return status, headers


@dataclass
class ResponseInfo:
    """What decode_response_info() read: the structure (for the tree), the
    facts the entry table shows, and why reading stopped early (None: read
    to the end)."""

    tree: Tree
    version: int | None = None
    request_time: int | None = None
    response_time: int | None = None
    original_response_time: int | None = None
    status_line: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    certificates: list[bytes] = field(default_factory=list)
    certificate_ranges: list[tuple[int, int]] = field(default_factory=list)
    socket_host: str | None = None
    socket_port: int | None = None
    alpn: str | None = None
    connection_info: str | None = None
    tls_version: str | None = None
    cipher_suite: int | None = None
    truncated: bool = False
    # Set when the cache stored the body zstd-compressed itself
    # (RESPONSE_EXTRA_INFO_HAS_ZSTD_UNCOMPRESSED_BODY_SIZE).
    zstd_uncompressed_size: int | None = None
    stopped: ParseIssue | None = None
    size_matches: bool = False
    fully_read: bool = False

    def header(self, name: str) -> str | None:
        """The first header named *name* (case-insensitive)."""
        lower = name.lower()
        for key, value in self.headers:
            if key.lower() == lower:
                return value
        return None

    @property
    def protocol(self) -> str:
        """The protocol as stored: the connection info, else the ALPN
        protocol, else the status line's HTTP version."""
        if self.connection_info:
            return self.connection_info
        if self.alpn:
            return self.alpn
        return self.status_line.split(" ", 1)[0] if self.status_line.startswith("HTTP/") else ""


def _flag_list(value: int, names: tuple[tuple[int, str], ...]) -> list[str]:
    return [name for bit, name in names if value & bit]


def decode_response_info(data: bytes, base: int = 0, *, with_tree: bool = True) -> ResponseInfo:
    """HttpResponseInfo::InitFromPickle on *data* (stream 0 of an HTTP
    cache entry): every field it reads, in its order. Reading stops at the
    first field that can't be read; what came before stays. Without
    *with_tree* only the facts are kept, not the structure view's tree."""
    info = ResponseInfo(tree=Tree() if with_tree else NullTree())
    t = info.tree
    try:
        p = Pickle(data, base)
    except PickleError as exc:
        info.stopped = exc.issue
        return info
    info.size_matches = p.size_matches
    t.put(("Pickle payload size",), p.payload_size, base, base + 4)
    if not p.size_matches:
        t.put(("Pickle note",), ParseIssue(
            "chromium_cache.pickle_size_mismatch",
            {"payload": p.payload_size, "size": len(data) - p.header_size},
        ))
    try:
        _read_response_info(p, info)
    except PickleError as exc:
        info.stopped = exc.issue
        t.put(("Stopped",), exc.issue)
    else:
        info.fully_read = True
        if p.remaining:
            t.put(
                ("Unread bytes after the last field",), p.remaining,
                base + p.pos, base + p.end,
            )
    return info


def _read_response_info(p: Pickle, info: ResponseInfo) -> None:
    t = info.tree
    flags, s, e = p.int32("flags")
    t.put(("Flags", "Value"), f"0x{flags & 0xFFFFFFFF:08x}", s, e)
    t.put(("Flags", "Set"), ", ".join(_flag_list(flags & 0xFFFFFFFF, _FLAG_NAMES)) or "-")
    t.mark(("Flags",), s, e)
    extra = 0
    if flags & _HAS_EXTRA_FLAGS:
        extra, s, e = p.int32("extra flags")
        t.put(("Extra flags", "Value"), f"0x{extra & 0xFFFFFFFF:08x}", s, e)
        t.put(("Extra flags", "Set"), ", ".join(_flag_list(extra, _EXTRA_FLAG_NAMES)) or "-")
        t.mark(("Extra flags",), s, e)
    version = flags & _VERSION_MASK
    info.version = version
    t.put(("Version",), version)
    if version < _MINIMUM_VERSION or version > _RESPONSE_INFO_VERSION:
        raise PickleError(ParseIssue(
            "chromium_cache.response_info_version",
            {"version": version, "supported": _RESPONSE_INFO_VERSION},
        ))
    info.truncated = bool(flags & _TRUNCATED)

    value, s, e = p.int64("request time")
    info.request_time = value
    t.put(("Request time",), ChromeTime(value), s, e)
    value, s, e = p.int64("response time")
    info.response_time = value
    t.put(("Response time",), ChromeTime(value), s, e)
    if extra & _EXTRA_HAS_ORIGINAL_RESPONSE_TIME:
        value, s, e = p.int64("original response time")
        info.original_response_time = value
        t.put(("Original response time",), ChromeTime(value), s, e)

    raw, s, e = p.string("response headers")
    status, headers = split_headers(raw)
    info.status_line, info.headers = status, headers
    lines = raw.split(b"\0")
    pos = s + 4
    t.put(("Response headers", "Status line"), status, pos, pos + len(lines[0]))
    pos += len(lines[0]) + 1
    shown = 0
    for line in lines[1:]:
        if line:
            name, value_text = headers[shown]
            shown += 1
            # Numbered: a header may occur more than once.
            t.put(("Response headers", f"{shown} {name}"), value_text, pos, pos + len(line))
        pos += len(line) + 1
    t.mark(("Response headers",), s, e)
    if not status.startswith("HTTP/"):
        # HttpResponseHeaders normalises a status line it doesn't recognise;
        # the stored one is shown as it is.
        t.put(("Response headers note",), ParseIssue("chromium_cache.status_line_not_http"))

    if flags & _HAS_CERT:
        count, s, e = p.length("certificate chain length")
        t.put(("Certificates", "Count"), count, s, e)
        for i in range(count):
            der, cs, ce = p.string(f"certificate {i}")
            info.certificates.append(der)
            info.certificate_ranges.append((cs + 4, ce))
            t.put(("Certificates", str(i)), f"DER, {len(der):,} B", cs, ce)
        t.mark(("Certificates",), s, p.base + p.pos)
    if flags & _HAS_CERT_STATUS:
        value, s, e = p.uint32("certificate status")
        t.put(("Certificate status",), f"0x{value:08x}", s, e)
    if flags & _HAS_SECURITY_BITS:
        value, s, e = p.int32("security bits")
        t.put(("Security bits",), value, s, e)
    if flags & _HAS_SSL_CONNECTION_STATUS:
        value, s, e = p.int32("SSL connection status")
        info.tls_version = _SSL_VERSIONS.get((value >> 20) & 7, str((value >> 20) & 7))
        info.cipher_suite = value & 0xFFFF
        t.put(("SSL connection status", "Value"), f"0x{value & 0xFFFFFFFF:08x}", s, e)
        t.put(("SSL connection status", "Version"), info.tls_version)
        t.put(("SSL connection status", "Cipher suite"), f"0x{info.cipher_suite:04x}")
        t.mark(("SSL connection status",), s, e)
    if flags & _HAS_SIGNED_CERTIFICATE_TIMESTAMPS:
        # Chromium stopped persisting SCTs; it still reads past old ones,
        # whose layout (ct::SignedCertificateTimestamp::Persist) isn't
        # decoded here -- reading stops.
        count, s, e = p.int32("SCT count")
        t.put(("Signed certificate timestamps",), count, s, e)
        if count:
            raise PickleError(ParseIssue("chromium_cache.scts_not_decoded", {"count": count}))
    if flags & _HAS_VARY_DATA:
        _read_vary(p, t)

    raw_host, s, e = p.string("socket address host")
    info.socket_host = _text(raw_host)
    t.put(("Socket address", "Host"), info.socket_host, s, e)
    port, s2, e2 = p.uint16("socket address port")
    info.socket_port = port
    t.put(("Socket address", "Port"), port, s2, e2)
    t.mark(("Socket address",), s, e2)

    if flags & _HAS_ALPN_NEGOTIATED_PROTOCOL:
        raw, s, e = p.string("ALPN protocol")
        info.alpn = _text(raw)
        t.put(("ALPN negotiated protocol",), info.alpn, s, e)
    if flags & _HAS_CONNECTION_INFO:
        value, s, e = p.int32("connection info")
        info.connection_info = _CONNECTION_INFO.get(value, f"unknown value {value}")
        t.put(("Connection info",), f"{info.connection_info} ({value})", s, e)
    if flags & _HAS_KEY_EXCHANGE_GROUP:
        value, s, e = p.int32("key exchange group")
        t.put(("Key exchange group",), value, s, e)
    if flags & _HAS_STALENESS:
        value, s, e = p.int64("stale revalidate timeout")
        t.put(("Stale revalidate timeout",), ChromeTime(value), s, e)
    if flags & _HAS_PEER_SIGNATURE_ALGORITHM:
        value, s, e = p.int32("peer signature algorithm")
        t.put(("Peer signature algorithm",), f"0x{value & 0xFFFF:04x}", s, e)
    if flags & _HAS_DNS_ALIASES:
        count, s, e = p.int32("DNS alias count")
        t.put(("DNS aliases", "Count"), count, s, e)
        for i in range(max(count, 0)):
            raw, as_, ae = p.string(f"DNS alias {i}")
            t.put(("DNS aliases", str(i)), _text(raw), as_, ae)
    if flags & _BROWSER_RUN_ID:
        value, s, e = p.int64("browser run id")
        t.put(("Browser run id",), value, s, e)
    if extra & _EXTRA_HAS_PROXY_CHAIN:
        _read_proxy_chain(p, t)
    if extra & _EXTRA_HAS_ENCODED_BODY_SIZE:
        value, s, e = p.int64("encoded body size")
        t.put(("Encoded body size",), value, s, e)
    if extra & _EXTRA_HAS_ZSTD_UNCOMPRESSED_BODY_SIZE:
        value, s, e = p.int64("zstd uncompressed body size")
        info.zstd_uncompressed_size = value
        t.put(("Zstd uncompressed body size",), value, s, e)
        t.put(("Body storage",), ParseIssue("chromium_cache.body_zstd_by_cache"))


def _read_vary(p: Pickle, t: Tree) -> None:
    """HttpVaryData::Persist: the hash type, then the digest. Earlier
    Chromium wrote the 16-byte MD5 digest alone; a type value that is
    neither MD5 (0) nor SHA-256 (1) is read that way, and said so."""
    start_pos = p.pos
    hash_type, s, e = p.int32("vary hash type")
    known = _VARY_HASH.get(hash_type)
    if known is not None:
        name, size = known
        digest, ds, de = p.raw(size, "vary digest")
        t.put(("Vary data", "Hash type"), f"{name} ({hash_type})", s, e)
        t.put(("Vary data", "Digest"), digest.hex(), ds, de)
        t.mark(("Vary data",), s, de)
        return
    p.pos = start_pos
    digest, ds, de = p.raw(16, "vary digest")
    t.put(("Vary data", "Digest"), digest.hex(), ds, de)
    t.put(("Vary data", "Note"), ParseIssue("chromium_cache.vary_earlier_layout"))
    t.mark(("Vary data",), ds, de)


def _read_proxy_chain(p: Pickle, t: Tree) -> None:
    """ProxyChain::Persist: the IP protection chain id, the number of
    proxies, then each ProxyServer (scheme, "host:port")."""
    value, s, e = p.int32("IP protection chain id")
    t.put(("Proxy chain", "IP protection chain id"), value, s, e)
    count, s2, e2 = p.length("proxy chain length")
    t.put(("Proxy chain", "Count"), count, s2, e2)
    for i in range(count):
        scheme, ss, se = p.int32(f"proxy {i} scheme")
        raw, hs, he = p.string(f"proxy {i} host and port")
        t.put(("Proxy chain", str(i), "Scheme"), scheme, ss, se)
        t.put(("Proxy chain", str(i), "Host and port"), _text(raw), hs, he)
    t.mark(("Proxy chain",), s, p.base + p.pos)


def strictly_valid(info: ResponseInfo) -> bool:
    """Whether stream 0 is an HttpResponseInfo beyond doubt, for an entry
    whose cache kind its key doesn't show (a heuristic reading): the pickle's
    stored size is exactly the stream's, the version is 3, the status line
    is an HTTP status line, and every field was read."""
    return (
        info.size_matches
        and info.version == _RESPONSE_INFO_VERSION
        and info.fully_read
        and info.status_line.startswith("HTTP/")
    )
