# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""C2PA (Content Credentials) manifest detection and summary.

Reads the C2PA Manifest Store from every image, audio and video container
the C2PA spec (2.4, Annex A) defines an embedding for, recognised by
content: JPEG (APP11), PNG (caBX chunk), GIF (Application Extension), RIFF
-- WebP, WAV, AVI and other RIFF forms -- ('C2PA' chunk), TIFF and BigTIFF
(tag 0xCD41), every BMFF file with an 'ftyp' box -- HEIC/HEIF/AVIF, MP4,
MOV, M4A, 3GP ... -- ('uuid' box), box-form JPEG XL (top-level JUMBF
superbox), an ID3v2 tag at the start of the file -- MP3, FLAC with a
prepended tag -- (GEOB frame), and Ogg (dedicated logical bitstream).

The spec defines no embedding for BMP, bare JPEG XL codestreams, native
FLAC, Matroska/WebM, ASF (WMA/WMV) or AMR; ATX/KTX texture archives are
Apple/Khronos-specific and outside its scope. Anything else is reported as
not checked, never as "Not present".

Structure only: manifest generator, actions (including each action's
softwareAgent and any IPTC digitalSourceType -- the actual "was this
AI-generated/-edited" signal, classified via the official vocabulary in
crush/parsers/xmp_provenance.py), ingredients (prior assets this one was
derived from), and the claim signature's leaf certificate identity
(Subject/Issuer/validity, parsed but NOT cryptographically verified
against a trust store or checked for revocation). See
crush/parsers/xmp_provenance.py for the second, C2PA-independent
provenance signal: an IPTC Digital Source Type embedded directly in XMP,
which some tools (e.g. Google/Gemini) use without a full C2PA manifest.

Every UUID/label below is taken verbatim from the C2PA Technical
Specification 2.4 (Section 11.1.4) and cross-checked against real sample
files published by the C2PA org (github.com/contentauth/c2pa-rs), not
guessed from the box shape -- see crush/parsers/jumbf.py.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from crush.core.issues import ParseIssue
from crush.core.magic import ASF_HEADER_GUID
from crush.parsers import jumbf
from crush.parsers.apple_atx import AAPL_MAGIC
from crush.parsers.apple_ktx import KTX11_MAGIC
from crush.parsers.cbor_lite import cbor_decode
from crush.parsers.xmp_provenance import classify_digital_source_type

_ASSERTIONS_LABEL = "c2pa.assertions"
_CLAIM_LABELS = ("c2pa.claim.v2", "c2pa.claim")
_SIGNATURE_LABEL = "c2pa.signature"

_MANIFEST_UUIDS = frozenset(
    bytes.fromhex(u.replace("-", "")) for u in (
        "63326D61-0011-0010-8000-00AA00389B71",  # c2ma -- standard manifest
        "6332636D-0011-0010-8000-00AA00389B71",  # c2cm -- compressed manifest
        "6332756D-0011-0010-8000-00AA00389B71",  # c2um -- update manifest
        "63326D64-0011-0010-8000-00AA00389B71",  # c2md -- deprecated, read-only
        "6332746D-0011-0010-8000-00AA00389B71",  # c2tm -- time-stamp manifest
    )
)

_COSE_ALGORITHMS = {
    -7: "ES256", -35: "ES384", -36: "ES512",
    -37: "PS256", -38: "PS384", -39: "PS512",
    -257: "RS256", -258: "RS384", -259: "RS512",
    -8: "EdDSA",
}


def summarize_c2pa(raw: bytes) -> dict[str, Any]:
    """Return Properties-panel-ready fields. Always includes a "C2PA" status
    field, explicit even when nothing was found or the format isn't checked
    -- never silently omitted (a missing row is indistinguishable from
    "not looked for").

    One Manifest Store: its rows are "C2PA ...". More than one: the "C2PA"
    row names them by offset and each store's rows are numbered in file
    order ("C2PA #1 Actions", "C2PA #2 Actions"). C2PA data that was found
    but not evaluated, and a structure that ends early, are listed under
    "C2PA scan notes"; with no store found, a single such note is the
    "C2PA" status itself, so "Not present" only ever means the whole
    structure was read and holds no C2PA data."""
    extract = _extractor(raw)
    if extract is None:
        return {"C2PA": _not_defined_or_not_checked(raw)}
    scan = extract(raw)
    notes = _scan_notes(scan)

    out: dict[str, Any] = {}
    if not scan.stores:
        if len(notes) == 1 and scan.stopped_at is not None:
            code = "c2pa.not_found_truncated" if scan.truncated else "c2pa.not_found_invalid"
            out["C2PA"] = ParseIssue(code, {"offset": scan.stopped_at})
        elif len(notes) == 1:
            out["C2PA"] = notes[0]
        elif notes:
            out["C2PA"] = ParseIssue("c2pa.not_found_see_notes", {"count": len(notes)})
            out["C2PA scan notes"] = notes
        else:
            out["C2PA"] = ParseIssue("c2pa.not_present")
        return out

    if len(scan.stores) == 1:
        _summarize_into(scan.stores[0].data, out, "C2PA")
    else:
        out["C2PA"] = _stores_status(scan.stores)
        for number, hit in enumerate(scan.stores, 1):
            _summarize_into(hit.data, out, f"C2PA #{number}")
    if notes:
        out["C2PA scan notes"] = notes
    return out


def _summarize_into(store: bytes, out: dict[str, Any], prefix: str) -> None:
    """One store's rows, their "C2PA" prefix replaced by *prefix*."""
    rows: dict[str, Any] = {}
    try:
        _summarize_store(store, rows)
    except Exception as exc:
        rows.setdefault("C2PA", ParseIssue("c2pa.parse_failed", detail=str(exc)))
    for key, value in rows.items():
        out[prefix + key[len("C2PA"):]] = value


def _stores_status(stores: list[jumbf.StoreHit]) -> ParseIssue:
    purposes = [hit.purpose for hit in stores]
    if sorted(purposes) == ["original", "update"]:
        # C2PA spec A.5.3: an update manifest chain keeps the previous store
        # as "original" and adds the update store as the file's last box.
        original = purposes.index("original")
        update = purposes.index("update")
        return ParseIssue("c2pa.stores_original_update", {
            "original": original + 1, "original_offset": stores[original].offset,
            "update": update + 1, "update_offset": stores[update].offset,
        })
    return ParseIssue("c2pa.stores_multiple", {
        "count": len(stores),
        "offsets": ", ".join(f"{hit.offset:,}" for hit in stores),
    })


def _scan_notes(scan: jumbf.ScanResult) -> list[ParseIssue]:
    notes = list(scan.notes)
    if len(scan.merkle_offsets) == 1:
        notes.append(ParseIssue("c2pa.bmff_merkle", {"offset": scan.merkle_offsets[0]}))
    elif scan.merkle_offsets:
        notes.append(ParseIssue("c2pa.bmff_merkle_boxes", {
            "count": len(scan.merkle_offsets),
            "first": scan.merkle_offsets[0], "last": scan.merkle_offsets[-1],
        }))
    purposes = {hit.purpose for hit in scan.stores}
    for hit in scan.stores:
        missing = {"original": "update", "update": "original"}.get(hit.purpose)
        if missing is not None and missing not in purposes:
            notes.append(ParseIssue("c2pa.bmff_unpaired", {
                "purpose": hit.purpose, "missing": missing, "offset": hit.offset,
            }))
    if scan.stopped_at is not None:
        code = "c2pa.scan_truncated" if scan.truncated else "c2pa.scan_invalid"
        notes.append(ParseIssue(code, {"offset": scan.stopped_at}))
    return notes


_JXL_BOX_CONTAINER_SIG = bytes.fromhex("0000000c4a584c200d0a870a")  # ISO/IEC 18181-2
_TIFF_SIGNATURES = (b"II*\x00", b"MM\x00*", b"II+\x00", b"MM\x00+")  # TIFF, BigTIFF


def _extractor(raw: bytes) -> Callable[[bytes], jumbf.ScanResult] | None:
    """The container's C2PA extractor, chosen by the file's first bytes."""
    if raw[:2] == b"\xFF\xD8":
        return jumbf.extract_from_jpeg
    if raw[:8] == b"\x89PNG\r\n\x1a\n":
        return jumbf.extract_from_png
    if raw[:6] in (b"GIF87a", b"GIF89a"):
        return jumbf.extract_from_gif
    if raw[:4] == b"RIFF":
        return jumbf.extract_from_riff
    if raw[:4] in _TIFF_SIGNATURES:
        return jumbf.extract_from_tiff
    if raw[4:8] == b"ftyp":  # ISO/IEC 14496-12, any brand
        return jumbf.extract_from_bmff
    if raw[:12] == _JXL_BOX_CONTAINER_SIG:
        return jumbf.extract_from_jpeg_xl
    if raw[:3] == b"ID3":
        return jumbf.extract_from_id3
    if raw[:4] == b"OggS":
        return jumbf.extract_from_ogg
    return None


def _not_defined_or_not_checked(raw: bytes) -> ParseIssue:
    if (
        raw[:2] == b"BM"
        or raw[:len(AAPL_MAGIC)] == AAPL_MAGIC
        or raw[:len(KTX11_MAGIC)] == KTX11_MAGIC
        or raw[:2] == b"\xFF\x0A"  # bare JPEG XL codestream -- structurally cannot carry a manifest
        or raw[:4] == b"fLaC"
        or raw[:4] == b"\x1a\x45\xdf\xa3"
        or raw[:16] == ASF_HEADER_GUID
        or raw[:5] == b"#!AMR"
    ):
        # BMP, Matroska/WebM (EBML), ASF (WMA/WMV), AMR: no embedding
        # defined anywhere in the C2PA spec.
        # ATX/KTX: Apple/Khronos texture-archive formats, outside the C2PA
        # spec's scope entirely -- not an image format it addresses at all.
        # Bare JPEG XL codestream: the spec explicitly says only the box-form
        # container can carry a manifest, so this isn't "checked and found
        # none" -- no bare-codestream JXL file could ever have one.
        # FLAC starting with its own "fLaC" marker: the spec embeds into
        # FLAC only through a prepended ID3v2 tag (A.3.4); native FLAC is
        # listed as "being considered" (A.1).
        # Not a gap in this reader: the spec (Annex A) defines no
        # embedding mechanism for these formats at all.
        return ParseIssue("c2pa.not_defined")
    return ParseIssue("c2pa.not_checked")


def _summarize_store(store: bytes, out: dict[str, Any]) -> None:
    root = jumbf.read_box_header(store, 0)
    if root is None or root.box_type != b"jumb":
        out["C2PA"] = ParseIssue("c2pa.unparseable")
        return
    jumd = jumbf.read_box_header(store, root.content_start)
    if jumd is None:
        out["C2PA"] = ParseIssue("c2pa.unparseable")
        return

    manifests = [
        box for box in jumbf.iter_children(store, jumd.content_end, root.content_end)
        if box.box_type == b"jumb"
        and (m := jumbf.read_box_header(store, box.content_start)) is not None
        and m.box_type == b"jumd"
        and jumbf.read_description(store, m.content_start)[0] in _MANIFEST_UUIDS
    ]
    if not manifests:
        out["C2PA"] = ParseIssue("c2pa.store_empty")
        return

    out["C2PA"] = (
        ParseIssue("c2pa.manifests_found", {"count": len(manifests)}) if len(manifests) > 1
        else ParseIssue("c2pa.manifest_found")
    )

    active = manifests[-1]  # C2PA spec: the last manifest is the active one
    active_jumd = jumbf.read_box_header(store, active.content_start)
    if active_jumd is not None:
        _uuid, label = jumbf.read_description(store, active_jumd.content_start)
        if label:
            out["C2PA Manifest ID"] = label

    _summarize_claim(store, active, out)
    _summarize_actions(store, active, out)
    _summarize_ingredients(store, active, out)
    _summarize_signature(store, active, out)


def _find_labeled_content(
    store: bytes, parent: jumbf.JumbfBox, label: str,
) -> Any | None:
    box = jumbf.find_superbox_by_label(store, parent.content_start, parent.content_end, label)
    if box is None:
        return None
    content = jumbf.first_content_box(store, box)
    if content is None or content.box_type != b"cbor":
        return None
    value, _ = cbor_decode(store, content.content_start)
    return value


def _summarize_claim(store: bytes, manifest: jumbf.JumbfBox, out: dict[str, Any]) -> None:
    for label in _CLAIM_LABELS:
        claim = _find_labeled_content(store, manifest, label)
        if isinstance(claim, dict):
            generator = _generator_string(claim)
            if generator:
                out["C2PA Generator"] = generator
            return


def _generator_string(claim: dict[str, Any]) -> str | None:
    generator = claim.get("claim_generator")
    if isinstance(generator, str):
        return generator
    # Claim v2 dropped the flat string in favor of structured
    # claim_generator_info -- either a single object or a list of them.
    info = claim.get("claim_generator_info")
    entries = info if isinstance(info, list) else [info] if isinstance(info, dict) else []
    parts = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        version = entry.get("version")
        if isinstance(name, str):
            parts.append(f"{name}/{version}" if version else name)
    return " ".join(parts) or None


def _summarize_actions(store: bytes, manifest: jumbf.JumbfBox, out: dict[str, Any]) -> None:
    assertions_box = jumbf.find_superbox_by_label(
        store, manifest.content_start, manifest.content_end, _ASSERTIONS_LABEL,
    )
    if assertions_box is None:
        return
    actions_data = None
    for box in jumbf.iter_children(store, assertions_box.content_start, assertions_box.content_end):
        jumd = jumbf.read_box_header(store, box.content_start)
        if jumd is None:
            continue
        _uuid, label = jumbf.read_description(store, jumd.content_start)
        if label.startswith("c2pa.actions"):
            content = jumbf.read_box_header(store, jumd.content_end)
            if content is not None and content.box_type == b"cbor":
                actions_data, _ = cbor_decode(store, content.content_start)
            break
    if not isinstance(actions_data, dict):
        return
    actions = actions_data.get("actions")
    if not isinstance(actions, list):
        return

    labels: list[str] = []
    source_types: list[str] = []
    agents: list[str] = []
    for action in actions:
        if not isinstance(action, dict):
            continue
        name = action.get("action")
        if isinstance(name, str):
            labels.append(name)
        source_type = action.get("digitalSourceType")
        if isinstance(source_type, str) and source_type not in source_types:
            source_types.append(source_type)
        agent = action.get("softwareAgent")
        agent_name = agent if isinstance(agent, str) else (
            agent.get("name") if isinstance(agent, dict) else None
        )
        if isinstance(agent_name, str) and agent_name not in agents:
            agents.append(agent_name)
    if labels:
        out["C2PA Actions"] = ", ".join(labels)
    if source_types:
        out["C2PA Digital Source Type"] = ", ".join(
            classify_digital_source_type(s) for s in source_types
        )
    if agents:
        out["C2PA Software Agent(s)"] = ", ".join(agents)


def _summarize_ingredients(store: bytes, manifest: jumbf.JumbfBox, out: dict[str, Any]) -> None:
    """Prior assets this one was derived from (c2pa.ingredient assertions) --
    the provenance chain, not just this manifest's own claims."""
    assertions_box = jumbf.find_superbox_by_label(
        store, manifest.content_start, manifest.content_end, _ASSERTIONS_LABEL,
    )
    if assertions_box is None:
        return
    titles: list[str | ParseIssue] = []
    for box in jumbf.iter_children(store, assertions_box.content_start, assertions_box.content_end):
        jumd = jumbf.read_box_header(store, box.content_start)
        if jumd is None:
            continue
        _uuid, label = jumbf.read_description(store, jumd.content_start)
        if not label.startswith("c2pa.ingredient"):
            continue
        content = jumbf.read_box_header(store, jumd.content_end)
        if content is None or content.box_type != b"cbor":
            continue
        ingredient, _ = cbor_decode(store, content.content_start)
        if isinstance(ingredient, dict):
            title = ingredient.get("title") or ingredient.get("dc:title")
            titles.append(
                title if isinstance(title, str) and title
                else ParseIssue("c2pa.ingredient_untitled")
            )
    if titles:
        out["C2PA Ingredients"] = ", ".join(str(t) for t in titles)


def _summarize_signature(store: bytes, manifest: jumbf.JumbfBox, out: dict[str, Any]) -> None:
    sig = _find_labeled_content(store, manifest, _SIGNATURE_LABEL)
    if not (isinstance(sig, list) and len(sig) == 4):
        return
    protected_bstr, unprotected, _payload, _signature = sig
    protected: dict[Any, Any] = {}
    if isinstance(protected_bstr, bytes) and protected_bstr:
        decoded, _ = cbor_decode(protected_bstr, 0)
        if isinstance(decoded, dict):
            protected = decoded

    alg = protected.get(1)
    if isinstance(alg, int):
        out["C2PA Signature Algorithm"] = _COSE_ALGORITHMS.get(alg, str(alg))

    x5chain = protected.get(33)
    if x5chain is None and isinstance(unprotected, dict):
        x5chain = unprotected.get(33)
    leaf_der = x5chain[0] if isinstance(x5chain, list) and x5chain else (
        x5chain if isinstance(x5chain, bytes) else None
    )
    if leaf_der is not None:
        _summarize_certificate(leaf_der, out)

    out["C2PA Signature"] = ParseIssue("c2pa.signature_present")


def _summarize_certificate(der: bytes, out: dict[str, Any]) -> None:
    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der)
    except Exception as exc:
        out["C2PA Signed By"] = ParseIssue("c2pa.cert_unparseable", detail=str(exc))
        return
    def _cn(name: x509.Name, fallback: str) -> str:
        attrs = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if not attrs:
            return fallback
        value = attrs[0].value
        return value if isinstance(value, str) else value.decode("utf-8", errors="replace")

    out["C2PA Signed By"] = _cn(cert.subject, cert.subject.rfc4514_string())
    out["C2PA Cert Issuer"] = _cn(cert.issuer, cert.issuer.rfc4514_string())
    try:
        out["C2PA Cert Valid"] = (
            f"{cert.not_valid_before_utc:%Y-%m-%d} to {cert.not_valid_after_utc:%Y-%m-%d}"
        )
    except AttributeError:
        out["C2PA Cert Valid"] = f"{cert.not_valid_before:%Y-%m-%d} to {cert.not_valid_after:%Y-%m-%d}"
