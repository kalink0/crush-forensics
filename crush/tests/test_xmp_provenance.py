# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for IPTC/XMP Digital Source Type detection."""
from __future__ import annotations

from crush.core.issues import ParseIssue
from crush.parsers.xmp_provenance import classify_digital_source_type, extract_xmp_provenance

_XMP_PACKET = b"""<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description xmlns:Iptc4xmpExt="http://iptc.org/std/Iptc4xmpExt/2008-02-29/"
  xmlns:xmp="http://ns.adobe.com/xap/1.0/"
  xmlns:photoshop="http://ns.adobe.com/photoshop/1.0/"
  xmlns:dc="http://purl.org/dc/elements/1.1/"
  Iptc4xmpExt:DigitalSourceType="http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"
  xmp:CreatorTool="Google Gemini"
  photoshop:Credit="Generated with Gemini">
  <dc:creator><rdf:Seq><rdf:li>Jane Doe</rdf:li></rdf:Seq></dc:creator>
</rdf:Description>
</rdf:RDF>
</x:xmpmeta>"""


def test_classify_known_code_via_uri() -> None:
    result = classify_digital_source_type(
        "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"
    )
    assert result == "Created using Generative AI (trainedAlgorithmicMedia)"


def test_classify_known_code_bare() -> None:
    assert classify_digital_source_type("humanEdits") == "Human-edited media (humanEdits)"


def test_classify_unknown_code_shown_as_is_not_dropped() -> None:
    unknown = "http://cv.iptc.org/newscodes/digitalsourcetype/somethingNew"
    assert classify_digital_source_type(unknown) == unknown


def test_extract_xmp_provenance_finds_packet_anywhere_in_file() -> None:
    fake_file = b"\xFF\xD8" + b"leading noise" + _XMP_PACKET + b"trailing noise"
    result = extract_xmp_provenance(fake_file)

    assert result["XMP Digital Source Type"] == "Created using Generative AI (trainedAlgorithmicMedia)"
    assert result["XMP Creator Tool"] == "Google Gemini"
    assert result["XMP Credit"] == "Generated with Gemini"
    assert result["XMP Creator(s)"] == "Jane Doe"
    assert result["XMP"] == ParseIssue("xmp.present")


def test_extract_xmp_provenance_says_not_present_without_packet() -> None:
    assert extract_xmp_provenance(b"\xFF\xD8\xFF\xDA\x00\x02\x00") == {
        "XMP": ParseIssue("xmp.not_present"),
    }


def test_extract_xmp_provenance_reports_malformed_xml_with_parser_message() -> None:
    broken = b"<x:xmpmeta><rdf:RDF>not valid xml</x:xmpmeta>"
    result = extract_xmp_provenance(broken)
    assert list(result) == ["XMP"]
    assert result["XMP"].code == "xmp.parse_failed"
    assert result["XMP"].detail  # the XML parser's own message, verbatim


def test_extract_xmp_provenance_reports_packet_without_closing_tag() -> None:
    result = extract_xmp_provenance(b"noise<x:xmpmeta>cut off here")
    assert result == {"XMP": ParseIssue("xmp.unclosed", {"offset": 5})}


def test_extract_xmp_provenance_says_when_more_than_one_packet_exists() -> None:
    result = extract_xmp_provenance(_XMP_PACKET + b"gap" + _XMP_PACKET)
    assert result["XMP"] == ParseIssue("xmp.present_multiple", {"count": 2})


def test_extract_xmp_provenance_ignores_packet_without_relevant_fields() -> None:
    packet = (
        b'<x:xmpmeta xmlns:x="adobe:ns:meta/">'
        b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        b'<rdf:Description/>'
        b'</rdf:RDF></x:xmpmeta>'
    )
    assert extract_xmp_provenance(packet) == {"XMP": ParseIssue("xmp.present_no_listed_fields")}
