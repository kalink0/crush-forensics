"""XML and JSON are recognised by how a document can start (XML 1.0 §2.1,
RFC 8259), not by a single leading "<", "{" or "[" byte."""
from __future__ import annotations

from pathlib import Path

import pytest

from crush.core.registry import ParserRegistry
from crush.core.vfs import DirectoryVFS
from crush.parsers.json_parser import JsonParser
from crush.parsers.xml_parser import XmlParser

# A Hive box frame: little-endian length 0x3C ("<") then key type and name,
# as in a real Flutter app's lastviewedproducts.hive.
_HIVE_FRAME_LT = b"<\x00\x00\x00\x01\x12lastViewedProducts\xb6\xefp9M(P"


@pytest.mark.parametrize("doc", [
    b"<?xml version='1.0'?><a/>",
    b"\xef\xbb\xbf<?xml version='1.0'?><a/>",
    b"\xef\xbb\xbf\r\n  <a/>",
    b"<!-- comment --><a/>",
    b"<!DOCTYPE html><html/>",
    b"<?xml-stylesheet href='x'?><a/>",
    b"<map><string name='k'>v</string></map>",
    b"<_x/>",
    b"<ns:root/>",
    "<Élément/>".encode(),
    "<数据/>".encode(),
])
def test_xml_document_starts_are_xml(doc: bytes) -> None:
    assert XmlParser().can_parse("noext", doc)


@pytest.mark.parametrize("data", [
    _HIVE_FRAME_LT,
    b"<\x00",
    b"<",
    b"< a/>",
    b"<1a/>",
    b"<-a/>",
    b"<\xff\xfe",
    "<×/>".encode(),  # U+00D7 is excluded from NameStartChar
    b"\x0c<a/>",  # form feed is not XML whitespace
])
def test_lone_less_than_is_not_xml(data: bytes) -> None:
    assert not XmlParser().can_parse("noext", data)


@pytest.mark.parametrize("doc", [
    b'{"a": 1}',
    b"{}",
    b"{ \n }",
    b'\r\n\t[ "x" ]',
    b"[]",
    b"[1, 2]",
    b"[-1]",
    b"[true]",
    b"[false]",
    b"[null]",
    b"[[1]]",
    b"[{}]",
    b"{" + b" " * 100,  # nothing but whitespace in the peek: can't be ruled out
])
def test_json_container_starts_are_json(doc: bytes) -> None:
    assert JsonParser().can_parse("noext", doc)


@pytest.mark.parametrize("data", [
    b"{\x00\x00\x00\x01\x05items",
    b"[\x00\x00\x00",
    b"{a: 1}",
    b"{'a': 1}",
    b"[x]",
    b"[+1]",
    b"[\x01",
])
def test_lone_bracket_is_not_json(data: bytes) -> None:
    assert not JsonParser().can_parse("noext", data)


def test_json_extension_still_opens_as_json() -> None:
    assert JsonParser().can_parse("broken.json", b"\x00\x01")


def test_binary_starting_with_lt_falls_back_to_hex(tmp_path: Path) -> None:
    (tmp_path / "lastviewedproducts.hive").write_bytes(_HIVE_FRAME_LT * 4)
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name.endswith(".hive"))
    best = ParserRegistry.best(node, vfs)
    assert best is not None and type(best).__name__ == "HexFallbackParser"
