# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""IPTC/XMP Digital Source Type detection.

Many tools (Google/Gemini among others) embed the IPTC Digital Source Type
directly in XMP with no C2PA manifest at all -- this is a second,
independent provenance signal alongside crush/parsers/c2pa_reader.py's
C2PA-actions-derived one, not a replacement for it.

Detection is container-agnostic: an XMP packet is self-delimited XML
(wrapped in <x:xmpmeta>...</x:xmpmeta>, itself normally containing an
<rdf:RDF>), findable anywhere in the raw bytes regardless of which format
(JPEG APP1, PNG iTXt, TIFF tag 700, WebP XMP chunk, ...) wraps it -- so a
single byte-level search covers every container without per-format code.

Vocabulary names below are verbatim from the official IPTC NewsCodes
scheme, fetched via curl from https://cv.iptc.org/newscodes/digitalsourcetype/
on 2026-09-18 (current as of the vocabulary's 2024-09-17 revision) --
not copied from a third party's possibly-stale or approximated table.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from crush.core.issues import ParseIssue

_DIGITAL_SOURCE_TYPES: dict[str, str] = {
    "digitalCapture": "Digital capture sampled from real life",
    "computationalCapture": "Multi-frame computational capture sampled from real life",
    "negativeFilm": "Digitised from a transparent negative",
    "positiveFilm": "Digitised from a transparent positive",
    "print": "Digitised from a non-transparent medium",
    "minorHumanEdits": "Original media with minor human edits (retired, see humanEdits)",
    "humanEdits": "Human-edited media",
    "compositeWithTrainedAlgorithmicMedia": "Edited using Generative AI",
    "algorithmicallyEnhanced": "Algorithmically-altered media",
    "softwareImage": "Created by software (retired)",
    "digitalArt": "Digital art (retired, see digitalCreation)",
    "digitalCreation": "Digital creation",
    "dataDrivenMedia": "Data-driven media",
    "trainedAlgorithmicMedia": "Created using Generative AI",
    "algorithmicMedia": "Pure algorithmic media (not trained on sampled data)",
    "screenCapture": "Screen capture",
    "virtualRecording": "Virtual event recording",
    "composite": "Composite of elements",
    "compositeCapture": "Composite of captured elements",
    "compositeSynthetic": "Composite including generative AI elements",
}


def classify_digital_source_type(uri_or_code: str) -> str:
    """"<official IPTC name> (<code>)", or the value as-is if it isn't a
    recognized code -- shown, not dropped, per house rule against hiding
    unrecognized values."""
    code = uri_or_code.rstrip("/").rsplit("/", 1)[-1]
    name = _DIGITAL_SOURCE_TYPES.get(code)
    return f"{name} ({code})" if name else uri_or_code


def find_xmp_packet(raw: bytes) -> bytes | None:
    start = raw.find(b"<x:xmpmeta")
    if start != -1:
        end = raw.find(b"</x:xmpmeta>", start)
        if end != -1:
            return raw[start:end + len(b"</x:xmpmeta>")]
    start = raw.find(b"<rdf:RDF")
    if start != -1:
        end = raw.find(b"</rdf:RDF>", start)
        if end != -1:
            return raw[start:end + len(b"</rdf:RDF>")]
    return None


def _packet_count(raw: bytes) -> int:
    count = raw.count(b"<x:xmpmeta")
    return count if count else raw.count(b"<rdf:RDF")


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _rdf_list_values(el: ET.Element) -> list[str]:
    values = [
        (li.text or "").strip()
        for li in el.iter()
        if _local_name(li.tag) == "li" and (li.text or "").strip()
    ]
    if not values and (el.text or "").strip():
        values.append((el.text or "").strip())
    return values


def extract_xmp_provenance(raw: bytes) -> dict[str, Any]:
    """Properties-panel-ready fields from an embedded XMP packet. Always
    includes an "XMP" status row: not present, present but not parseable
    (with the XML parser's message), present without any of the fields
    this looks for, or present (noting how many packets exist when there
    is more than one -- the fields come from the first)."""
    packet = find_xmp_packet(raw)
    if packet is None:
        for start_tag in (b"<x:xmpmeta", b"<rdf:RDF"):
            offset = raw.find(start_tag)
            if offset != -1:
                return {"XMP": ParseIssue("xmp.unclosed", {"offset": offset})}
        return {"XMP": ParseIssue("xmp.not_present")}
    try:
        root = ET.fromstring(packet)
    except ET.ParseError as exc:
        return {"XMP": ParseIssue("xmp.parse_failed", detail=str(exc))}

    digital_source: str | None = None
    creator_tool: str | None = None
    credit: str | None = None
    creators: list[str] = []
    rights: str | None = None

    for el in root.iter():
        for attr_name, attr_value in el.attrib.items():
            local = _local_name(attr_name)
            if local == "DigitalSourceType" and attr_value:
                digital_source = attr_value
            elif local == "CreatorTool" and attr_value:
                creator_tool = attr_value
            elif local == "Credit" and attr_value:
                credit = attr_value
        local = _local_name(el.tag)
        text = (el.text or "").strip()
        if local == "DigitalSourceType" and text:
            digital_source = text
        elif local == "CreatorTool" and text:
            creator_tool = text
        elif local == "Credit" and text:
            credit = text
        elif local == "creator":
            creators.extend(_rdf_list_values(el))
        elif local == "rights" and rights is None:
            values = _rdf_list_values(el)
            if values:
                rights = values[0]

    out: dict[str, Any] = {}
    if digital_source:
        out["XMP Digital Source Type"] = classify_digital_source_type(digital_source)
    if creator_tool:
        out["XMP Creator Tool"] = creator_tool
    if creators:
        out["XMP Creator(s)"] = ", ".join(creators)
    if credit:
        out["XMP Credit"] = credit
    if rights:
        out["XMP Rights"] = rights
    count = _packet_count(raw)
    if not out:
        status = ParseIssue("xmp.present_no_listed_fields")
    elif count > 1:
        status = ParseIssue("xmp.present_multiple", {"count": count})
    else:
        status = ParseIssue("xmp.present")
    return {"XMP": status, **out}
