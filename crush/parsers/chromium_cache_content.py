# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""What a Chromium disk cache entry holds, independent of the backend:
the key's parts, the cache kind the key shows, stream 0 of CacheStorage and
Code Cache entries, and the body's declared Content-Encoding.

Written from the Chromium source at revision 278016c7cf72 (2026-10-28):
net/http/http_cache.cc (GenerateCacheKey), net/base/network_isolation_key.cc,
content/browser/code_cache/generated_code_cache.cc,
third_party/blink/common/loader/code_cache_util.cc,
content/browser/cache_storage/cache_storage.proto and cache_storage_cache.cc.
The HTTP cache key before Chromium 95 from GenerateCacheKey at tag
90.0.4430.91 and 94.0.4606.81; commit 54013f2a5d6c ("Split cache per
request's includeCredentials", main@{#918101}, first in 95.0.4638.0) put the
credential and upload id parts in front.
"""
from __future__ import annotations

import hashlib
import re
import struct
import zlib
from dataclasses import dataclass, field
from typing import Any, cast

from crush.core.issues import QT_TRANSLATE_NOOP, ParseIssue
from crush.parsers.chromium_pickle import Tree, chrome_time

# Cache kinds, as the parser determines them (see key_kind).
KIND_HTTP = QT_TRANSLATE_NOOP("GeneratedView", "HTTP cache")
KIND_CODE = QT_TRANSLATE_NOOP("GeneratedView", "Code Cache")
KIND_CODE_DATA = QT_TRANSLATE_NOOP("GeneratedView", "Code Cache (data keyed by its SHA-256)")
KIND_CACHE_STORAGE = QT_TRANSLATE_NOOP("GeneratedView", "CacheStorage")
KIND_UNDETERMINED = QT_TRANSLATE_NOOP("GeneratedView", "not determined from the key")
# A key that is a URL alone: two kinds write such keys (see split_key).
KIND_URL_KEY = QT_TRANSLATE_NOOP("GeneratedView", "HTTP cache or CacheStorage (heuristic: the key is a URL)")

# net/http/http_cache.cc
_DOUBLE_KEY_PREFIX = "_dk_"
_SUBFRAME_PREFIX = "s_"
_CROSS_SITE_PREFIX = "cn_"
# credential_key/upload_data_identifier/ -- keys since Chromium 95 always start so.
_HTTP_KEY_RE = re.compile(r"^([01])/(\d+)/")
# Before Chromium 95: [<upload_data_identifier>/][_dk_…]<url>, the identifier
# only for a request with an upload ("No valid URL can begin with numerals").
# A URL here is what GURL::spec() writes: scheme "://" …
_URL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")
_LEGACY_UPLOAD_RE = re.compile(r"^(\d+)/(?=_dk_|[A-Za-z][A-Za-z0-9+.\-]*://)")
# blink::kCodeCacheKeyPrefix and GeneratedCodeCache's separator.
_CODE_KEY_PREFIX = "_key"
_CODE_SEPARATOR = " \n"
# GeneratedCodeCache: the key of de-duplicated code data is the SHA-256 of
# the data as upper-case hex (base::HexEncode).
_SHA_KEY_RE = re.compile(r"^[0-9A-F]{64}$")

# generated_code_cache.cc
_CODE_HEADER_SIZE = 12
_CODE_INLINE_LIMIT = 4096
_CODE_DEDICATED_LIMIT = 16384
_CODE_SHA_KEY_SIZE = 64


@dataclass
class KeyParts:
    """The parts of an entry's key; *form* names which grammar matched."""

    raw: bytes
    text: str
    kind: str
    form: str
    url: str = ""
    credential: str = ""
    upload_id: str = ""
    top_frame_site: str = ""
    frame_site: str = ""
    partition: str = ""
    subframe_document: bool = False
    cross_site_navigation: bool = False
    context: str = ""
    # A heuristic kind: each cache kind that writes such a key -> why.
    candidates: dict[str, str] = field(default_factory=dict)
    # Why the key gives its kind, where "key grammar" alone doesn't say it.
    basis: str = ""

    def tree(self) -> dict[str, Any]:
        out: dict[str, Any] = {"Key form": self.form}
        if self.candidates:
            out["Candidates (heuristic)"] = dict(self.candidates)
        for label, value in (
            ("URL", self.url),
            ("Credentials", self.credential),
            ("Upload data identifier", self.upload_id),
            ("Top-frame site", self.top_frame_site),
            ("Frame site", self.frame_site),
            ("Isolation partition", self.partition),
            ("Origin lock / context", self.context),
        ):
            if value:
                out[label] = value
        if self.subframe_document:
            out["Subframe document resource"] = QT_TRANSLATE_NOOP(
                "GeneratedView", "yes (prefix s_)"
            )
        if self.cross_site_navigation:
            out["Cross-site main-frame navigation"] = QT_TRANSLATE_NOOP(
                "GeneratedView", "yes (prefix cn_)"
            )
        return out


def _credential_text(flag: str) -> str:
    # GenerateCacheKey: "0/" when the request may not send credentials
    # (LOAD_DO_NOT_SAVE_COOKIES with SplitCacheByIncludeCredentials), else "1/".
    if flag == "0":
        return QT_TRANSLATE_NOOP("GeneratedView", "0 (request without credentials)")
    return QT_TRANSLATE_NOOP("GeneratedView", "1 (credentials allowed)")


def split_key(raw: bytes, *, blockfile: bool = False) -> KeyParts:
    """Split *raw* by the key grammars Chromium defines; KIND_UNDETERMINED
    when none matches (the key is then shown whole).

    A key that is a URL alone is written by two kinds: the HTTP cache
    before Chromium 95 (a request without upload and without split cache)
    and CacheStorage (its request URL). The key doesn't tell them apart:
    KIND_URL_KEY with both candidates -- except in a Blockfile cache
    (*blockfile*), as CacheStorage only creates Simple caches
    (cache_storage_cache.cc: CACHE_BACKEND_SIMPLE)."""
    text = raw.decode("utf-8", errors="backslashreplace")
    match = _HTTP_KEY_RE.match(text)
    if match:
        parts = KeyParts(
            raw, text, KIND_HTTP,
            QT_TRANSLATE_NOOP("GeneratedView", "HTTP cache key (credentials/upload id/…)"),
            credential=_credential_text(match.group(1)), upload_id=match.group(2),
        )
        _split_isolation(text[match.end():], parts)
        return parts
    match = _LEGACY_UPLOAD_RE.match(text)
    if match:
        parts = KeyParts(
            raw, text, KIND_HTTP,
            QT_TRANSLATE_NOOP("GeneratedView", "HTTP cache key before Chromium 95 (upload id/…, no credential part)"),
            upload_id=match.group(1),
        )
        _split_isolation(text[match.end():], parts)
        return parts
    if text.startswith(_DOUBLE_KEY_PREFIX):
        parts = KeyParts(
            raw, text, KIND_HTTP,
            QT_TRANSLATE_NOOP("GeneratedView", "HTTP cache key before Chromium 95, double-keyed (no credential/upload part)"),
        )
        _split_isolation(text, parts)
        return parts
    if _URL_RE.match(text):
        if blockfile:
            return KeyParts(
                raw, text, KIND_HTTP,
                QT_TRANSLATE_NOOP("GeneratedView", "HTTP cache key before Chromium 95 (the URL alone)"),
                url=text, basis=QT_TRANSLATE_NOOP(
                    "GeneratedView",
                    "key grammar: a URL alone in a Blockfile cache (CacheStorage creates Simple caches only)",
                ),
            )
        return KeyParts(
            raw, text, KIND_URL_KEY,
            QT_TRANSLATE_NOOP("GeneratedView", "the URL alone (heuristic: two cache kinds write such keys)"),
            url=text, candidates={
                KIND_HTTP: QT_TRANSLATE_NOOP(
                    "GeneratedView",
                    "before Chromium 95 the HTTP cache keyed a request without upload and without "
                    "split cache by its URL alone",
                ),
                KIND_CACHE_STORAGE: QT_TRANSLATE_NOOP(
                    "GeneratedView",
                    "CacheStorage keys an entry by its request URL; known for sure only from an "
                    "index.txt in the parent folder naming the cache's folder",
                ),
            },
        )
    if text.startswith(_CODE_KEY_PREFIX):
        rest = text[len(_CODE_KEY_PREFIX):]
        url, sep, context = rest.partition(_CODE_SEPARATOR)
        return KeyParts(
            raw, text, KIND_CODE,
            QT_TRANSLATE_NOOP("GeneratedView", "Code Cache key (_key<URL> \\n<context>)"),
            url=url, context=context.replace(_CODE_SEPARATOR, " | ") if sep else "",
        )
    return KeyParts(raw, text, KIND_UNDETERMINED, QT_TRANSLATE_NOOP("GeneratedView", "no Chromium key grammar"))


def _split_isolation(rest: str, parts: KeyParts) -> None:
    """[_dk_[s_][cn_]<top-frame site> <frame site>[ <partition>] ]<url>:
    the URL follows the last space (HttpCache::GetResourceURLFromHttpCacheKey)."""
    if not rest.startswith(_DOUBLE_KEY_PREFIX):
        parts.url = rest
        return
    body = rest[len(_DOUBLE_KEY_PREFIX):]
    if body.startswith(_SUBFRAME_PREFIX):
        parts.subframe_document = True
        body = body[len(_SUBFRAME_PREFIX):]
    if body.startswith(_CROSS_SITE_PREFIX):
        parts.cross_site_navigation = True
        body = body[len(_CROSS_SITE_PREFIX):]
    isolation, sep, url = body.rpartition(" ")
    if not sep:
        parts.url = body
        return
    parts.url = url
    sites = isolation.split(" ")
    parts.top_frame_site = sites[0]
    if len(sites) > 1:
        parts.frame_site = sites[1]
    if len(sites) > 2:
        parts.partition = " ".join(sites[2:])


def is_sha_key(text: str) -> bool:
    return bool(_SHA_KEY_RE.match(text))


def sha_key_matches(key_text: str, data: bytes) -> bool:
    """A de-duplicated Code Cache entry: its key is the SHA-256 of its data."""
    return hashlib.sha256(data).hexdigest().upper() == key_text


# -- Code Cache stream 0 ---------------------------------------------------------


@dataclass
class CodeHeader:
    tree: Tree
    response_time: int | None = None
    data_size: int | None = None
    layout: str = ""
    inline_data: tuple[int, int] | None = None
    sha_key: str = ""
    status: ParseIssue | None = None


def decode_code_header(data: bytes, base: int = 0) -> CodeHeader:
    """GeneratedCodeCache's stream 0: the response time (µs since 1601),
    the code's size, then the code itself (up to 4,096 B), nothing (the
    code is in stream 1), or the SHA-256 key of the entry holding it."""
    out = CodeHeader(tree=Tree())
    t = out.tree
    if len(data) < _CODE_HEADER_SIZE:
        out.status = ParseIssue("chromium_cache.code_header_short", {"size": len(data)})
        t.put(("Status",), out.status)
        return out
    time_value, size = struct.unpack_from("<qI", data)
    out.response_time, out.data_size = time_value, size
    t.put(("Response time",), chrome_time(time_value), base, base + 8)
    t.put(("Code size",), size, base + 8, base + 12)
    if size <= _CODE_INLINE_LIMIT:
        out.layout = QT_TRANSLATE_NOOP("GeneratedView", "code in stream 0 after the header")
        expected = _CODE_HEADER_SIZE + size
        out.inline_data = (base + _CODE_HEADER_SIZE, base + min(len(data), expected))
        t.put(("Code (V8 data)",), f"{min(len(data), expected) - _CODE_HEADER_SIZE:,} B", *out.inline_data)
    elif size <= _CODE_DEDICATED_LIMIT:
        out.layout = QT_TRANSLATE_NOOP("GeneratedView", "code in stream 1")
        expected = _CODE_HEADER_SIZE
    else:
        out.layout = QT_TRANSLATE_NOOP("GeneratedView", "code in the entry keyed by its SHA-256")
        expected = _CODE_HEADER_SIZE + _CODE_SHA_KEY_SIZE
        raw = data[_CODE_HEADER_SIZE:expected]
        out.sha_key = raw.decode("ascii", errors="backslashreplace")
        t.put(("SHA-256 key of the code entry",), out.sha_key, base + 12, base + 12 + len(raw))
    t.put(("Layout",), out.layout)
    if len(data) != expected:
        # GeneratedCodeCache::IsValidHeader rejects such an entry.
        out.status = ParseIssue(
            "chromium_cache.code_header_size", {"size": len(data), "expected": expected}
        )
        t.put(("Status",), out.status)
    return out


# -- CacheStorage (content/browser/cache_storage/cache_storage.proto) -------------

_PROTO_TYPES = {"string": 9, "bytes": 12, "int32": 5, "int64": 3, "bool": 8, "enum": 14, "message": 11}
_OPTIONAL, _REQUIRED, _REPEATED = 1, 2, 3

# (message, [(field, number, type, label, type name)]) -- cache_storage.proto.
_MESSAGES: list[tuple[str, list[tuple[str, int, str, int, str]]]] = [
    ("CacheStorageIndex", [
        ("cache", 1, "message", _REPEATED, ".content.proto.CacheStorageIndex.Cache"),
        ("origin", 2, "string", _OPTIONAL, ""),
        ("storage_key", 3, "string", _OPTIONAL, ""),
        ("bucket_id", 4, "int64", _OPTIONAL, ""),
        ("bucket_is_default", 5, "bool", _OPTIONAL, ""),
    ]),
    ("CacheStorageIndex.Cache", [
        ("name", 1, "string", _REQUIRED, ""),
        ("cache_dir", 2, "string", _OPTIONAL, ""),
        ("size", 3, "int64", _OPTIONAL, ""),
        ("padding_key", 4, "string", _OPTIONAL, ""),
        ("padding", 5, "int64", _OPTIONAL, ""),
        ("padding_version", 6, "int32", _OPTIONAL, ""),
        ("u16string_name", 7, "bytes", _OPTIONAL, ""),
    ]),
    ("CacheHeaderMap", [
        ("name", 1, "string", _REQUIRED, ""),
        ("value", 2, "string", _REQUIRED, ""),
    ]),
    ("CacheRequest", [
        ("method", 1, "string", _REQUIRED, ""),
        ("headers", 2, "message", _REPEATED, ".content.proto.CacheHeaderMap"),
        ("fragment", 3, "string", _OPTIONAL, ""),
        ("is_reload_navigation", 4, "bool", _OPTIONAL, ""),
        ("is_history_navigation", 5, "bool", _OPTIONAL, ""),
    ]),
    ("CacheResponse", [
        ("status_code", 1, "int32", _REQUIRED, ""),
        ("status_text", 2, "string", _REQUIRED, ""),
        ("response_type", 3, "enum", _REQUIRED, ".content.proto.CacheResponse.ResponseType"),
        ("headers", 4, "message", _REPEATED, ".content.proto.CacheHeaderMap"),
        ("url", 5, "string", _OPTIONAL, ""),
        ("response_time", 6, "int64", _OPTIONAL, ""),
        ("cors_exposed_header_names", 7, "string", _REPEATED, ""),
        ("url_list", 8, "string", _REPEATED, ""),
        ("loaded_with_credentials", 9, "bool", _OPTIONAL, ""),
        ("connection_info", 10, "int32", _OPTIONAL, ""),
        ("alpn_negotiated_protocol", 11, "string", _OPTIONAL, ""),
        ("was_fetched_via_spdy", 12, "bool", _OPTIONAL, ""),
        ("mime_type", 13, "string", _OPTIONAL, ""),
        ("request_method", 14, "string", _OPTIONAL, ""),
        ("padding", 15, "int64", _OPTIONAL, ""),
        ("side_data_padding", 16, "int64", _OPTIONAL, ""),
        ("request_include_credentials", 17, "bool", _OPTIONAL, ""),
        ("timing_allow_passed", 18, "bool", _OPTIONAL, ""),
        ("has_range_requested", 19, "bool", _OPTIONAL, ""),
    ]),
    ("CacheMetadata", [
        ("request", 1, "message", _REQUIRED, ".content.proto.CacheRequest"),
        ("response", 2, "message", _REQUIRED, ".content.proto.CacheResponse"),
        ("entry_time", 3, "int64", _OPTIONAL, ""),
    ]),
]
_RESPONSE_TYPES = [
    ("BASIC_TYPE", 0), ("CORS_TYPE", 1), ("DEFAULT_TYPE", 2), ("ERROR_TYPE", 3),
    ("OPAQUE_TYPE", 4), ("OPAQUE_REDIRECT_TYPE", 5),
]
_pool: Any = None


def _schema_pool() -> Any:
    """cache_storage.proto as a descriptor pool, built once."""
    global _pool
    if _pool is not None:
        return _pool
    from google.protobuf import descriptor_pb2, descriptor_pool

    fdp = descriptor_pb2.FileDescriptorProto(
        name="cache_storage.proto", package="content.proto", syntax="proto2"
    )
    built: dict[str, Any] = {}
    for full, fields in _MESSAGES:
        outer, _, inner = full.partition(".")
        if inner:
            msg = built[outer].nested_type.add(name=inner)
        else:
            msg = fdp.message_type.add(name=outer)
            built[outer] = msg
        for name, number, kind, label, type_name in fields:
            f = msg.field.add(name=name, number=number, type=_PROTO_TYPES[kind], label=label)
            if type_name:
                f.type_name = type_name
        if full == "CacheResponse":
            enum = msg.enum_type.add(name="ResponseType")
            for name, number in _RESPONSE_TYPES:
                enum.value.add(name=name, number=number)
    pool = descriptor_pool.DescriptorPool()
    pool.Add(fdp)
    _pool = pool
    return pool


def _unknown_numbers(msg: Any) -> list[int]:
    """Field numbers in *msg* (and the messages in it) that the schema
    doesn't define."""
    from google.protobuf import unknown_fields

    found = [u.field_number for u in unknown_fields.UnknownFieldSet(msg)]
    for desc, value in msg.ListFields():
        if desc.message_type is None:
            continue
        values = value if desc.is_repeated else [value]
        for sub in values:
            found.extend(_unknown_numbers(sub))
    return found


@dataclass
class ProtoDecode:
    decoded: dict[str, Any] = field(default_factory=dict)
    ranges: dict[tuple[str, ...], dict[str, Any]] = field(default_factory=dict)
    missing: list[str] = field(default_factory=list)
    unknown: list[int] = field(default_factory=list)
    error: ParseIssue | None = None

    @property
    def strictly_valid(self) -> bool:
        """Parsed, every required field present, no field the schema lacks."""
        return self.error is None and not self.missing and not self.unknown

    def notes(self) -> list[ParseIssue]:
        out = []
        if self.error is not None:
            out.append(self.error)
        if self.missing:
            out.append(ParseIssue(
                "chromium_cache.proto_missing_required", {"fields": ", ".join(self.missing)}
            ))
        if self.unknown:
            out.append(ParseIssue(
                "chromium_cache.proto_unknown_fields",
                {"numbers": ", ".join(str(n) for n in sorted(set(self.unknown)))},
            ))
        return out


def decode_proto(message: str, data: bytes, base: int = 0, *, with_ranges: bool = True) -> ProtoDecode:
    """*data* as content.proto.*message* (cache_storage.proto), with every
    field's byte range (absolute: *base* is where *data* starts) unless
    *with_ranges* is off."""
    from google.protobuf import json_format

    from crush.parsers.protobuf_schema import decode_message_with_schema, schema_byte_ranges

    out = ProtoDecode()
    pool = _schema_pool()
    name = f"content.proto.{message}"
    try:
        msg = decode_message_with_schema(pool, name, data)
    except Exception as exc:  # noqa: BLE001 -- the library's own diagnosis is kept
        out.error = ParseIssue("chromium_cache.proto_failed", {"message": message}, detail=str(exc))
        return out
    out.decoded = json_format.MessageToDict(
        msg, preserving_proto_field_name=True, always_print_fields_with_no_presence=False,
    )
    out.missing = list(msg.FindInitializationErrors())
    out.unknown = _unknown_numbers(msg)
    if not with_ranges:
        return out
    for path, rng in schema_byte_ranges(pool, name, data).items():
        start, end = cast(tuple[int, int], rng["byte_range"])
        highlights = cast(list[tuple[int, int]], rng["highlight_ranges"])
        out.ranges[path] = {
            "byte_range": (base + start, base + end),
            "highlight_ranges": [(base + s, base + e) for s, e in highlights],
        }
    return out


@dataclass
class CacheMetadataView:
    """The CacheMetadata facts the entry table shows."""

    method: str = ""
    status_code: int | None = None
    status_text: str = ""
    response_type: str = ""
    response_time: int | None = None
    entry_time: int | None = None
    url_list: list[str] = field(default_factory=list)
    headers: list[tuple[str, str]] = field(default_factory=list)
    request_headers: list[tuple[str, str]] = field(default_factory=list)
    mime_type: str = ""
    alpn: str = ""
    connection_info: int | None = None


def cache_metadata_view(decoded: dict[str, Any]) -> CacheMetadataView:
    request = decoded.get("request") or {}
    response = decoded.get("response") or {}

    def pairs(items: Any) -> list[tuple[str, str]]:
        return [(str(h.get("name", "")), str(h.get("value", ""))) for h in items or []]

    def as_int(value: Any) -> int | None:
        # json_format writes int64 values as strings.
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    return CacheMetadataView(
        method=str(request.get("method", "")),
        status_code=as_int(response.get("status_code")),
        status_text=str(response.get("status_text", "")),
        response_type=str(response.get("response_type", "")),
        response_time=as_int(response.get("response_time")),
        entry_time=as_int(decoded.get("entry_time")),
        url_list=[str(u) for u in response.get("url_list") or []],
        headers=pairs(response.get("headers")),
        request_headers=pairs(request.get("headers")),
        mime_type=str(response.get("mime_type", "")),
        alpn=str(response.get("alpn_negotiated_protocol", "")),
        connection_info=as_int(response.get("connection_info")),
    )


def with_times(decoded: dict[str, Any]) -> dict[str, Any]:
    """*decoded* (a CacheMetadata as a dict) with its base::Time fields
    shown as times; the dict's paths stay those of the byte ranges."""
    out = dict(decoded)
    if "entry_time" in out:
        out["entry_time"] = chrome_time(int(out["entry_time"]))
    response = out.get("response")
    if isinstance(response, dict) and "response_time" in response:
        response = dict(response)
        response["response_time"] = chrome_time(int(response["response_time"]))
        out["response"] = response
    return out


# -- Body ------------------------------------------------------------------------


def content_codings(header_value: str | None) -> list[str]:
    """The codings a Content-Encoding header lists, in the order applied."""
    if not header_value:
        return []
    return [c.strip().lower() for c in header_value.split(",") if c.strip()]


_DECODERS = ("gzip", "x-gzip", "deflate", "br", "zstd", "identity")


def decode_body(
    raw: bytes, codings: list[str], cache_zstd: bool = False
) -> tuple[bytes | None, ParseIssue | None, bool]:
    """*raw* with what was declared undone: first the cache's own zstd
    compression (*cache_zstd*, from the response info's extra flags), then
    the Content-Encoding codings, last applied first -- as (derived, note,
    partial).

    Each step decodes as Chromium's source streams do (net/filter): gzip
    and deflate one stream, br one stream, zstd one or more frames in a
    row. A step whose stream ends is complete; bytes after the end are
    ignored by Chromium -- not in the derived body, kept in RAW, the note
    says how many and where. A step whose stream doesn't end (the data runs
    out or breaks off) gives the bytes it decoded up to there: the result
    is marked partial and the note says why; the steps after it decode
    that part the same way. No derived body when a coding isn't supported
    or a step decodes nothing. (None, None, False) when nothing was
    declared or the body is empty (e.g. a redirect with Content-Encoding:
    there is nothing to decode, and Chromium decodes nothing either)."""
    pending = [c for c in codings if c != "identity"]
    if (not pending and not cache_zstd) or not raw:
        return None, None, False
    steps = [("zstd", True)] if cache_zstd else []
    steps += [(c, False) for c in reversed(pending)]
    data = raw
    notes: list[ParseIssue] = []
    partial = False
    for coding, by_cache in steps:
        if coding not in _DECODERS:
            return None, ParseIssue("chromium_cache.coding_unsupported", {"coding": coding}), False
        out, end, error = _stream_decode(data, coding)
        if end is not None:
            if end < len(data):
                notes.append(ParseIssue("chromium_cache.coding_trailing_ignored", {
                    "coding": coding, "count": len(data) - end, "offset": end,
                }))
            data = out
            continue
        prefix = "chromium_cache.cache_zstd" if by_cache else "chromium_cache.coding"
        if not out:
            if error is None:
                return None, ParseIssue(f"{prefix}_short", {"coding": coding, "input": len(data)}), False
            if by_cache:
                return None, ParseIssue("chromium_cache.cache_zstd_failed", detail=error), False
            return None, ParseIssue("chromium_cache.coding_failed", {"coding": coding}, detail=error), False
        params = {"coding": coding, "size": len(out), "input": len(data)}
        notes.append(
            ParseIssue(f"{prefix}_partial_short", params) if error is None
            else ParseIssue(f"{prefix}_partial", params, detail=error)
        )
        partial = True
        data = out
    if not notes:
        return data, None, False
    note = notes[0] if len(notes) == 1 else ParseIssue("common.notes", {"notes": notes})
    return data, note, partial


# Input is fed to a decoder in pieces of this size; a piece the decoder
# rejects is fed again byte by byte, to find the last byte it accepts and
# where its stream ended. A step size only -- all input is fed.
_PIECE = 64 * 1024


def _stream_decode(data: bytes, coding: str) -> tuple[bytes, int | None, str | None]:
    """*coding*'s decoder over *data*: its output, the offset where its
    stream ended (None when it didn't), and the decoder's error, if any."""
    dec = _Stream(coding, data[:2])
    out = bytearray()
    pos = 0
    while pos < len(data) and dec.end is None:
        piece = data[pos:pos + _PIECE]
        try:
            out += dec.feed(piece)
        except Exception as exc:  # noqa: BLE001 -- the library's own diagnosis is kept
            error = str(exc) or type(exc).__name__
            dec = _Stream(coding, data[:2])
            out = bytearray(dec.feed(data[:pos]))
            for i in range(pos, pos + len(piece)):
                if dec.end is not None:
                    break
                try:
                    out += dec.feed(data[i:i + 1])
                except Exception:  # noqa: BLE001
                    break
            return bytes(out), dec.end, None if dec.end is not None else error
        pos += len(piece)
    if coding == "zstd" and data and dec.frame_done:
        dec.end = len(data)
    return bytes(out), dec.end, None


class _Stream:
    """A coding's decoder as Chromium's source stream reads it: one gzip,
    deflate or brotli stream (what follows is ignored), or zstd frames in a
    row (net/filter/{gzip,brotli,zstd}_source_stream.cc). *end* is the
    offset in the fed input where the stream ended."""

    def __init__(self, coding: str, head: bytes) -> None:
        self.coding = coding
        self.head = head
        self.fed = 0
        self.end: int | None = None
        self.cur = self._new()

    def _new(self) -> Any:
        if self.coding in ("gzip", "x-gzip"):
            return zlib.decompressobj(16 + zlib.MAX_WBITS)
        if self.coding == "deflate":
            # RFC 9110: "deflate" is the zlib format; some servers send raw
            # DEFLATE, which Chromium's GzipSourceStream also accepts. The
            # zlib header (RFC 1950: CM 8 and the CMF/FLG check) says which.
            h = self.head
            zlib_header = len(h) >= 2 and (h[0] & 0x0F) == 8 and ((h[0] << 8) | h[1]) % 31 == 0
            return zlib.decompressobj(zlib.MAX_WBITS if zlib_header else -zlib.MAX_WBITS)
        if self.coding == "br":
            import brotli

            return brotli.Decompressor()
        try:
            from compression import zstd  # type: ignore[import-not-found]
        except ImportError:
            from backports import zstd
        return zstd.ZstdDecompressor()

    @property
    def frame_done(self) -> bool:
        """zstd: the last frame fed so far is complete."""
        return bool(self.cur.eof)

    def feed(self, piece: bytes) -> bytes:
        self.fed += len(piece)
        if self.coding == "br":
            # The brotli decoder rejects input after its stream's end, so
            # an end is only seen where a piece finishes it exactly.
            decoded = bytes(self.cur.process(piece))
            if self.cur.is_finished():
                self.end = self.fed
            return decoded
        if self.coding == "zstd":
            # Frames in a row; whether the last one ends is known only at
            # the end of the input (_stream_decode).
            frames = bytearray()
            while piece:
                if self.cur.eof:
                    self.cur = self._new()
                frames += self.cur.decompress(piece)
                piece = bytes(self.cur.unused_data) if self.cur.eof else b""
            return bytes(frames)
        decoded = bytes(self.cur.decompress(piece))
        if self.cur.eof:
            self.end = self.fed - len(self.cur.unused_data)
        return decoded
