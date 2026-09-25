# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""C2PA (Content Credentials) manifest detection and summary.

Reads the C2PA Manifest Store embedded in every image container Crush's
ImageViewer opens that the C2PA spec actually defines an embedding for:
JPEG (APP11), PNG (caBX chunk), GIF (Application Extension), WebP (RIFF
'C2PA' chunk), TIFF (tag 0xCD41), HEIC/HEIF/AVIF (BMFF 'uuid' box), and
box-form JPEG XL (top-level JUMBF superbox) -- matching the same format
breadth as EXIF extraction (crush/parsers/exif_reader.py). BMP and bare
JPEG XL codestreams have no embedding defined by the spec at all; ATX/KTX
texture archives are Apple/Khronos-specific and outside the spec's scope.

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

from typing import Any

from crush.core.issues import ParseIssue
from crush.parsers import jumbf
from crush.parsers.apple_atx import AAPL_MAGIC
from crush.parsers.apple_ktx import KTX11_MAGIC
from crush.parsers.cbor_lite import cbor_decode
from crush.parsers.xmp_provenance import classify_digital_source_type

_MANIFEST_STORE_LABEL = "c2pa"
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
    yet -- never silently omitted (a missing row is indistinguishable from
    "not looked for")."""
    store = _extract_manifest_store(raw)
    if store is None:
        return {"C2PA": _not_found_status(raw)}

    out: dict[str, Any] = {}
    try:
        _summarize_store(store, out)
    except Exception as exc:
        out.setdefault("C2PA", ParseIssue("c2pa.parse_failed", detail=str(exc)))
    return out


# ISOBMFF brands the C2PA spec's BMFF 'uuid'-box embedding (Annex A.5) covers
# and that Crush's ImageViewer actually opens -- same set image_parser.py and
# exif_reader.py sniff for HEIC/HEIF/AVIF.
_BMFF_IMAGE_BRANDS = frozenset({
    b"heic", b"heix", b"hevc", b"hevx",
    b"heim", b"heis", b"hevm", b"hevs",
    b"mif1", b"msf1",
    b"avif", b"avis",
})

_JXL_BOX_CONTAINER_SIG = bytes.fromhex("0000000c4a584c200d0a870a")  # ISO/IEC 18181-2


def _is_bmff_image(raw: bytes) -> bool:
    return len(raw) >= 12 and raw[4:8] == b"ftyp" and raw[8:12] in _BMFF_IMAGE_BRANDS


def _is_webp(raw: bytes) -> bool:
    return len(raw) >= 12 and raw[:4] == b"RIFF" and raw[8:12] == b"WEBP"


def _not_found_status(raw: bytes) -> ParseIssue:
    if (
        raw[:2] == b"\xFF\xD8"
        or raw[:8] == b"\x89PNG\r\n\x1a\n"
        or raw[:6] in (b"GIF87a", b"GIF89a")
        or raw[:2] in (b"II", b"MM")
        or _is_bmff_image(raw)
        or _is_webp(raw)
        or raw[:12] == _JXL_BOX_CONTAINER_SIG
    ):
        return ParseIssue("c2pa.not_present")
    if (
        raw[:2] == b"BM"
        or raw[:len(AAPL_MAGIC)] == AAPL_MAGIC
        or raw[:len(KTX11_MAGIC)] == KTX11_MAGIC
        or raw[:2] == b"\xFF\x0A"  # bare JPEG XL codestream -- structurally cannot carry a manifest
    ):
        # BMP: no embedding defined anywhere in the C2PA spec.
        # ATX/KTX: Apple/Khronos texture-archive formats, outside the C2PA
        # spec's scope entirely -- not an image format it addresses at all.
        # Bare JPEG XL codestream: the spec explicitly says only the box-form
        # container can carry a manifest, so this isn't "checked and found
        # none" -- no bare-codestream JXL file could ever have one.
        # Not a gap in this reader: the spec (Annex A) defines no
        # embedding mechanism for these formats at all.
        return ParseIssue("c2pa.not_defined")
    return ParseIssue("c2pa.not_checked")


def _extract_manifest_store(raw: bytes) -> bytes | None:
    if raw[:2] == b"\xFF\xD8":
        return jumbf.extract_from_jpeg(raw)
    if raw[:8] == b"\x89PNG\r\n\x1a\n":
        return jumbf.extract_from_png(raw)
    if raw[:6] in (b"GIF87a", b"GIF89a"):
        return jumbf.extract_from_gif(raw)
    if _is_webp(raw):
        return jumbf.extract_from_riff(raw)
    if raw[:2] in (b"II", b"MM"):
        return jumbf.extract_from_tiff(raw)
    if _is_bmff_image(raw):
        return jumbf.extract_from_bmff(raw)
    if raw[:12] == _JXL_BOX_CONTAINER_SIG:
        return jumbf.extract_from_jpeg_xl(raw)
    return None


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
