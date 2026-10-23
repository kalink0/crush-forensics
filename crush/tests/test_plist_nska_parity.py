# SPDX-License-Identifier: Apache-2.0
"""NSKeyedArchiver resolving shared by the plist parser and the BLOB
Inspector's text (NSUUID, unconvertible NSDate, $top beyond root, XML
archives), plists embedded in bytes values, and XML plist detection."""
from __future__ import annotations

import datetime
import math
import plistlib
from pathlib import Path

from crush.core.derived_bytes import DerivedBytes
from crush.core.issues import ParseIssue
from crush.core.magic import detect_fast_label
from crush.core.vfs import DirectoryVFS
from crush.parsers.plist_parser import PlistParser
from crush.parsers.xml_parser import XmlParser

UID = plistlib.UID


def _archive(objects: list, top: dict | None = None) -> dict:
    return {
        "$archiver": "NSKeyedArchiver",
        "$version": 100000,
        "$top": top if top is not None else {"root": UID(1)},
        "$objects": objects,
    }


def _cls(name: str) -> dict:
    return {"$classname": name, "$classes": [name, "NSObject"]}


def _binary(value: object) -> bytes:
    return plistlib.dumps(value, fmt=plistlib.FMT_BINARY)


def _xml(archive: dict) -> bytes:
    """*archive* as an XML plist, UIDs in their XML form {"CF$UID": n}."""
    def convert(value):  # noqa: ANN001, ANN202
        if isinstance(value, UID):
            return {"CF$UID": value.data}
        if isinstance(value, dict):
            return {k: convert(v) for k, v in value.items()}
        if isinstance(value, list):
            return [convert(v) for v in value]
        return value

    return plistlib.dumps(convert(archive), fmt=plistlib.FMT_XML)


def _parse(tmp_path: Path, name: str, payload: bytes):  # noqa: ANN202
    (tmp_path / name).write_bytes(payload)
    vfs = DirectoryVFS(tmp_path)
    node = next(c for c in vfs.root().children if c.name == name)
    return PlistParser().parse(node, vfs)


def _chat() -> dict:
    return _archive(["$null", {"body": UID(2), "$class": UID(3)}, "see you at 9", _cls("ChatMessage")])


def _cyclic() -> dict:
    return _archive(["$null", {"$class": UID(3), "child": UID(2)},
                     {"$class": UID(3), "parent": UID(1)}, _cls("Node")])


# --- NSUUID ---


def test_nsuuid_of_16_bytes_becomes_its_uuid_string(tmp_path: Path) -> None:
    archive = _archive(["$null", {"$class": UID(2), "NS.uuidbytes": bytes(range(16))}, _cls("NSUUID")])
    result = _parse(tmp_path, "a.plist", _binary(archive))

    assert result.data == "00010203-0405-0607-0809-0A0B0C0D0E0F"
    # The bytes stay visible as stored.
    stored = result.viewer_hints["archive"]["$objects"][1]
    assert stored["NS.uuidbytes"] == bytes(range(16))


def test_nsuuid_of_another_length_stays_as_stored(tmp_path: Path) -> None:
    archive = _archive(["$null", {"$class": UID(2), "NS.uuidbytes": bytes(15)}, _cls("NSUUID")])
    result = _parse(tmp_path, "a.plist", _binary(archive))

    assert result.metadata["Format"] == "binary (NSKeyedArchiver)"
    assert result.data["NS.uuidbytes"] == bytes(15)
    assert result.data["$class"]["$classname"] == "NSUUID"


# --- NSDate ---


def _dates_archive() -> dict:
    return _archive([
        "$null",
        {"NS.keys": [UID(2), UID(3), UID(4)], "NS.objects": [UID(5), UID(6), UID(7)], "$class": UID(8)},
        "good", "huge", "nan",
        {"NS.time": 3600.0, "$class": UID(9)},
        {"NS.time": 1e300, "$class": UID(9)},
        {"NS.time": float("nan"), "$class": UID(9)},
        _cls("NSDictionary"),
        _cls("NSDate"),
    ])


def test_unconvertible_nsdate_is_kept_as_stored_and_counted(tmp_path: Path) -> None:
    """Regression: one NS.time out of range or NaN failed the whole archive."""
    result = _parse(tmp_path, "a.plist", _binary(_dates_archive()))

    meta = result.metadata
    assert meta["Format"] == "binary (NSKeyedArchiver)"
    assert "Status" not in meta
    assert meta["NSDate kept as stored"] == ParseIssue("plist.nska_dates_kept", {"count": 2})
    data = result.data
    assert data["good"] == datetime.datetime(2001, 1, 1, 1, 0)
    assert data["huge"]["NS.time"] == 1e300
    assert data["huge"]["$class"]["$classname"] == "NSDate"
    assert math.isnan(data["nan"]["NS.time"])


def test_distant_past_is_not_special_cased(tmp_path: Path) -> None:
    """NSDate.distantPast (-63114076800 s) is 0001-01-01 in Apple's calendar
    (Julian before 1582), two days before Python's (proleptic Gregorian)
    datetime.min: kept as stored like any other value outside the range,
    not mapped to a placeholder. Two days later converts."""
    archive = _archive([
        "$null",
        {"NS.objects": [UID(2), UID(3)], "$class": UID(4)},
        {"NS.time": -63114076800.0, "$class": UID(5)},
        {"NS.time": -63113904000.0, "$class": UID(5)},
        _cls("NSArray"),
        _cls("NSDate"),
    ])
    result = _parse(tmp_path, "a.plist", _binary(archive))

    distant, later = result.data
    assert distant["NS.time"] == -63114076800.0
    assert later == datetime.datetime(1, 1, 1)
    assert result.metadata["NSDate kept as stored"] == ParseIssue("plist.nska_dates_kept", {"count": 1})


def test_unresolved_archive_has_no_date_row(tmp_path: Path) -> None:
    archive = _dates_archive()
    archive["$objects"][1]["gone"] = UID(99)
    result = _parse(tmp_path, "a.plist", _binary(archive))
    assert "NSDate kept as stored" not in result.metadata


# --- $top ---


def test_top_with_root_only_resolves_to_the_root_object(tmp_path: Path) -> None:
    result = _parse(tmp_path, "a.plist", _binary(_chat()))
    assert result.data["body"] == "see you at 9"
    assert "root" not in result.data


def test_top_without_root_resolves_every_key(tmp_path: Path) -> None:
    archive = _archive(["$null", "x", "y"], top={"a": UID(1), "b": UID(2)})
    result = _parse(tmp_path, "a.plist", _binary(archive))
    assert result.data == {"a": "x", "b": "y"}
    assert result.metadata["Root class"] == ParseIssue("plist.nska_root_none")


def test_top_with_root_and_more_keys_resolves_each_under_its_name(tmp_path: Path) -> None:
    archive = _chat()
    archive["$top"] = {"root": UID(1), "version": UID(2)}
    result = _parse(tmp_path, "a.plist", _binary(archive))

    assert set(result.data) == {"root", "version"}
    assert result.data["root"]["body"] == "see you at 9"
    assert result.data["version"] == "see you at 9"
    assert result.metadata["Root class"] == "ChatMessage"


# --- XML archives ---


def test_xml_archive_is_resolved(tmp_path: Path) -> None:
    raw = _xml(_dates_archive())
    result = _parse(tmp_path, "a.plist", raw)

    assert result.metadata["Format"] == "XML (NSKeyedArchiver)"
    assert result.data["good"] == datetime.datetime(2001, 1, 1, 1, 0)
    assert result.metadata["NSDate kept as stored"] == ParseIssue("plist.nska_dates_kept", {"count": 2})
    assert result.viewer_hints["raw_text"] == raw


def test_xml_archive_with_a_missing_reference_is_not_resolved(tmp_path: Path) -> None:
    archive = _chat()
    archive["$objects"][1]["gone"] = UID(99)
    result = _parse(tmp_path, "a.plist", _xml(archive))

    assert result.metadata["Format"] == ParseIssue("plist.format_nska_xml")
    assert result.metadata["Status"] == ParseIssue("plist.nska_missing_refs", {"count": 1})
    assert result.data is result.viewer_hints["archive"]


def test_xml_archive_with_a_cycle_is_not_resolved(tmp_path: Path) -> None:
    result = _parse(tmp_path, "a.plist", _xml(_cyclic()))

    assert result.metadata["Format"] == ParseIssue("plist.format_nska_xml")
    assert result.metadata["Status"] == ParseIssue("plist.nska_cycle")


def test_xml_archive_whose_resolving_fails_says_so(tmp_path: Path) -> None:
    archive = _chat()
    archive["$version"] = 1
    result = _parse(tmp_path, "a.plist", _xml(archive))

    assert result.metadata["Format"] == ParseIssue("plist.format_nska_xml_failed")
    assert result.metadata["Status"].code == "plist.nska_failed"


# --- plist_text (BLOB Inspector) uses the same guards ---


def test_plist_text_names_a_cycle() -> None:
    from crush.core.formatters import plist_text

    text = plist_text(_binary(_cyclic()))
    assert text.startswith("# Not resolved: an object reaches itself")
    assert "recursion" not in text


def test_plist_text_names_a_missing_reference() -> None:
    from crush.core.formatters import plist_text

    archive = _chat()
    archive["$top"] = {"root": UID(99)}
    text = plist_text(_binary(archive))
    assert text.startswith("# Not resolved: 1 reference(s) point past the end of $objects")
    assert "index out of range" not in text


def test_plist_text_resolves_xml_archives_and_embedded_plists() -> None:
    from crush.core.formatters import plist_text

    text = plist_text(_binary({"blob": _binary(_chat())}))
    assert "decoded (NSKeyedArchiver)" in text
    assert "see you at 9" in text
    assert "see you at 9" in plist_text(_xml(_chat()))


# --- embedded plists ---


def _derived(value: object) -> DerivedBytes:
    assert isinstance(value, DerivedBytes)
    return value


def test_archive_bytes_in_a_plain_plist_are_decoded_next_to_them(tmp_path: Path) -> None:
    inner = _binary(_chat())
    result = _parse(tmp_path, "a.plist", _binary({"blob": inner, "n": 1}))

    blob = _derived(result.data["blob"])
    assert bytes(blob) == inner
    assert blob.kind == "NSKeyedArchiver"
    assert blob.resolved_archive
    assert blob.derived["body"] == "see you at 9"


def test_nsdata_holding_an_archive_is_decoded(tmp_path: Path) -> None:
    inner = _binary(_chat())
    archive = _archive(["$null", {"$class": UID(2), "NS.data": inner}, _cls("NSData")])
    result = _parse(tmp_path, "a.plist", _binary(archive))

    root = _derived(result.data)
    assert bytes(root) == inner
    assert root.derived["body"] == "see you at 9"
    # The Stored archive tab keeps the bytes as stored.
    assert not isinstance(result.viewer_hints["archive"]["$objects"][1]["NS.data"], DerivedBytes)


def test_plist_whose_root_is_bytes(tmp_path: Path) -> None:
    inner = _binary({"k": "v"})
    result = _parse(tmp_path, "a.plist", _binary(inner))

    root = _derived(result.data)
    assert bytes(root) == inner
    assert (root.kind, root.derived) == ("plist", {"k": "v"})


def test_embedded_xml_and_plain_binary_plists(tmp_path: Path) -> None:
    xml_inner = plistlib.dumps({"x": "from xml"}, fmt=plistlib.FMT_XML)
    bin_inner = _binary({"b": "from binary"})
    result = _parse(tmp_path, "a.plist", _binary({"xml": xml_inner, "bin": bin_inner}))

    assert _derived(result.data["xml"]).derived == {"x": "from xml"}
    assert _derived(result.data["bin"]).derived == {"b": "from binary"}
    assert bytes(result.data["xml"]) == xml_inner
    assert not _derived(result.data["xml"]).resolved_archive


def test_embedded_plists_two_levels_deep(tmp_path: Path) -> None:
    level2 = _binary({"deep": "yes"})
    level1 = _binary({"inner": level2})
    result = _parse(tmp_path, "a.plist", _binary({"outer": level1}))

    outer = _derived(result.data["outer"])
    inner = _derived(outer.derived["inner"])
    assert bytes(inner) == level2
    assert inner.derived == {"deep": "yes"}


def test_bytes_starting_like_a_plist_that_isnt_one_say_why(tmp_path: Path) -> None:
    garbage = b"bplist00" + bytes(40)
    result = _parse(tmp_path, "a.plist", _binary({"g": garbage, "t": b"plain bytes"}))

    g = _derived(result.data["g"])
    assert bytes(g) == garbage
    assert isinstance(g.derived, ParseIssue) and g.derived.code == "plist.embedded_failed"
    assert not isinstance(result.data["t"], DerivedBytes)
    assert result.data["t"] == b"plain bytes"


def test_unresolved_archive_decodes_embedded_plists_in_decoded_only(qapp, tmp_path: Path) -> None:  # noqa: ARG001
    from crush.viewers.tree_text_viewer import TreeTextViewer

    inner = _binary(_chat())
    archive = _archive(["$null", {"$class": UID(2), "NS.data": UID(3), "gone": UID(99)},
                        _cls("Holder"), inner])
    result = _parse(tmp_path, "a.plist", _binary(archive))

    assert result.metadata["Status"] == ParseIssue("plist.nska_missing_refs", {"count": 1})
    blob = _derived(result.data["$objects"][3])
    assert blob.derived["body"] == "see you at 9"
    stored = result.viewer_hints["archive"]["$objects"][3]
    assert stored == inner and not isinstance(stored, DerivedBytes)
    assert result.viewer_hints["resolved"] is False

    # Decoded is the stored table: its class rows stay rows, not folded.
    viewer = TreeTextViewer(result.data, **result.viewer_hints)
    decoded = viewer._tabs.widget(0)
    model = decoded._model
    top = {model.index(r, 0).data(): model.index(r, 0) for r in range(model.rowCount())}
    decoded._populate_children(model.itemFromIndex(top["$objects"]))
    holder = model.index(1, 0, top["$objects"])
    decoded._populate_children(model.itemFromIndex(holder))
    keys = {model.index(r, 0, holder).data() for r in range(model.rowCount(holder))}
    assert "$class" in keys


def test_loaded_stays_as_stored_for_a_plain_plist() -> None:
    from crush.parsers.plist_parser import read_plist

    inner = _binary({"k": "v"})
    reading = read_plist(_binary({"blob": inner, "nested": [inner]}))
    assert isinstance(reading.data["blob"], DerivedBytes)
    assert isinstance(reading.data["nested"][0], DerivedBytes)
    assert type(reading.loaded["blob"]) is bytes
    assert type(reading.loaded["nested"][0]) is bytes

    unchanged = read_plist(_binary({"n": 1, "b": b"plain"}))
    assert unchanged.data is unchanged.loaded  # nothing decoded: nothing copied


def test_embedded_archive_that_cant_be_resolved_says_why(tmp_path: Path) -> None:
    result = _parse(tmp_path, "a.plist", _binary({"c": _binary(_cyclic())}))
    c = _derived(result.data["c"])
    assert c.derived == ParseIssue("plist.embedded_nska_cycle")


def test_text_tab_writes_the_bytes_and_their_decoded_form(tmp_path: Path) -> None:
    import json

    inner = _binary({"k": "v"})
    result = _parse(tmp_path, "a.plist", _binary({"blob": inner}))
    text = json.loads(result.viewer_hints["raw_text"])
    assert text["blob"]["decoded (plist)"] == {"k": "v"}
    assert text["blob"]["bytes"] == str(inner)


def test_tree_shows_the_decoded_form_as_a_child_of_the_bytes(qapp, tmp_path: Path) -> None:  # noqa: ARG001
    from crush.viewers.tree_viewer import TreeViewer

    # An embedded plain plist with a "$class" key inside a resolved archive:
    # data there, so shown -- while the archive's own class metadata is folded.
    inner = _binary({"$class": "Evidence", "k": "v"})
    archive = _archive(["$null", {"$class": UID(2), "payload": UID(3)}, _cls("Holder"),
                        {"$class": UID(4), "NS.data": inner}, _cls("NSData")])
    result = _parse(tmp_path, "a.plist", _binary(archive))
    tree = TreeViewer(result.data, fold_class_meta=True)
    model = tree._model

    payload = model.index(0, 0)
    assert payload.data() == "payload"
    assert payload.siblingAtColumn(1).data() == f"<BLOB {len(inner):,} B>"
    assert payload.siblingAtColumn(2).data() == "bytes"
    tree._populate_children(model.itemFromIndex(payload))
    decoded = model.index(0, 0, payload)
    assert decoded.data() == "decoded (plist)"
    tree._populate_children(model.itemFromIndex(decoded))
    keys = {model.index(r, 0, decoded).data() for r in range(model.rowCount(decoded))}
    assert keys == {"$class", "k"}
    assert tree._make_blob(result.data["payload"]) == inner
    assert type(tree._make_blob(result.data["payload"])) is bytes


# --- XML plist detection ---


_XML_PLIST = plistlib.dumps({"k": "v"}, fmt=plistlib.FMT_XML)
_BODY = _XML_PLIST[_XML_PLIST.index(b"<!DOCTYPE"):]


def _variants() -> dict[str, bytes]:
    return {
        "whitespace": b"\n  \t" + _XML_PLIST,
        "bom": b"\xef\xbb\xbf" + _XML_PLIST,
        "bom + whitespace": b"\xef\xbb\xbf\r\n" + _XML_PLIST,
        "doctype, no declaration": _BODY,
        "plist element only": _BODY[_BODY.index(b"<plist"):],
    }


def test_xml_plist_variants_are_detected_and_parsed(tmp_path: Path) -> None:
    for name, raw in _variants().items():
        assert detect_fast_label(raw[:2048], "x") == "plist", name
        assert PlistParser().can_parse("x", raw[:2048]), name
        assert not XmlParser().can_parse("x.xml", raw[:2048]), name
        result = _parse(tmp_path, "a.plist", raw)
        assert result.viewer_type == "tree_text", name
        assert result.metadata["Format"] == "XML", name
        assert result.data == {"k": "v"}, name
        assert result.viewer_hints["raw_text"] == raw, name  # Text tab: as stored


def test_format_db_identifies_xml_plist_variants_as_the_parser_does() -> None:
    from crush.core.format_db import FormatDatabase

    db = FormatDatabase.get()
    for name, raw in {**_variants(), "plain": _XML_PLIST}.items():
        match = db.identify(raw[:2048], "")
        assert match is not None, name
        assert match.parser_class == "PlistParser", name
    for doc in (b"<?xml version='1.0'?><notes/>", b"\xef\xbb\xbf<?xml version='1.0'?><notes/>"):
        match = db.identify(doc, "")
        assert match is not None and match.parser_class == "XmlParser", doc


def test_xml_that_doesnt_start_like_a_plist_is_xml() -> None:
    other = b"<notes>see <plist> docs</notes>"
    assert XmlParser().can_parse("x.xml", other)
    assert not PlistParser().can_parse("x", other)
