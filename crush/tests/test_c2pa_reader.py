# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Tests for C2PA manifest detection and summarization.

Box/CBOR layouts here were verified against real C2PA-org sample files
during development (see crush/parsers/jumbf.py, c2pa_reader.py); these
tests build small synthetic manifests with the same layout so the suite
doesn't need to bundle third-party binaries.
"""
from __future__ import annotations

import struct
from datetime import datetime, timedelta, timezone

from crush.parsers.c2pa_reader import summarize_c2pa

_MANIFEST_STORE_UUID = bytes.fromhex("63327061001100108000" "00AA00389B71")
_MANIFEST_UUID = bytes.fromhex("63326D61001100108000" "00AA00389B71")
_ASSERTIONS_UUID = bytes.fromhex("63326173001100108000" "00AA00389B71")
_CLAIM_UUID = bytes.fromhex("6332636C001100108000" "00AA00389B71")
_SIGNATURE_UUID = bytes.fromhex("63326373001100108000" "00AA00389B71")


# ---------------------------------------------------------------------------
# JUMBF box builders
# ---------------------------------------------------------------------------

def _box(tbox: bytes, content: bytes) -> bytes:
    return struct.pack(">I", 8 + len(content)) + tbox + content


def _jumd(uuid: bytes, label: str) -> bytes:
    return _box(b"jumd", uuid + bytes([0x03]) + label.encode("utf-8") + b"\x00")


def _superbox(uuid: bytes, label: str, children: bytes = b"") -> bytes:
    return _box(b"jumb", _jumd(uuid, label) + children)


def _to_jpeg(manifest_store: bytes) -> bytes:
    payload = b"JP" + b"\x02\x11" + struct.pack(">I", 1) + manifest_store
    app11 = b"\xFF\xEB" + struct.pack(">H", len(payload) + 2) + payload
    return b"\xFF\xD8" + app11 + b"\xFF\xDA\x00\x02\x00"


# ---------------------------------------------------------------------------
# Minimal CBOR encoder (test-only -- production code only ever decodes)
# ---------------------------------------------------------------------------

def _major(major: int, n: int) -> bytes:
    prefix = major << 5
    if n < 24:
        return bytes([prefix | n])
    if n < 256:
        return bytes([prefix | 24, n])
    if n < 65536:
        return bytes([prefix | 25]) + struct.pack(">H", n)
    return bytes([prefix | 26]) + struct.pack(">I", n)


def _tstr(s: str) -> bytes:
    b = s.encode("utf-8")
    return _major(3, len(b)) + b


def _bstr(b: bytes) -> bytes:
    return _major(2, len(b)) + b


def _uint(n: int) -> bytes:
    return _major(0, n)


def _negint(v: int) -> bytes:
    return _major(1, -1 - v)


def _array(items: list[bytes]) -> bytes:
    return _major(4, len(items)) + b"".join(items)


def _map(pairs: list[tuple[bytes, bytes]]) -> bytes:
    return _major(5, len(pairs)) + b"".join(k + v for k, v in pairs)


_NULL = bytes([0xF6])


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_no_manifest_in_plain_jpeg() -> None:
    jpeg = b"\xFF\xD8\xFF\xDA\x00\x02\x00"
    assert summarize_c2pa(jpeg) == {"C2PA": "Not present"}


def test_unrecognized_container_is_explicitly_marked_not_silently_omitted() -> None:
    unknown = b"NOT_A_KNOWN_IMAGE_FORMAT" + b"\x00" * 20
    result = summarize_c2pa(unknown)
    assert result["C2PA"].startswith("Not checked")


def test_bmp_reports_spec_has_no_embedding_defined() -> None:
    bmp = b"BM" + b"\x00" * 20
    assert summarize_c2pa(bmp)["C2PA"] == "Not defined by the C2PA spec for this format"


def test_atx_reports_spec_has_no_embedding_defined() -> None:
    from crush.parsers.apple_atx import AAPL_MAGIC

    atx = AAPL_MAGIC + b"\x00" * 40
    assert summarize_c2pa(atx)["C2PA"] == "Not defined by the C2PA spec for this format"


def test_ktx_reports_spec_has_no_embedding_defined() -> None:
    from crush.parsers.apple_ktx import KTX11_MAGIC

    ktx = KTX11_MAGIC + b"\x00" * 40
    assert summarize_c2pa(ktx)["C2PA"] == "Not defined by the C2PA spec for this format"


def test_manifest_free_gif_reports_not_present() -> None:
    gif = b"GIF89a" + struct.pack("<HH", 1, 1) + bytes([0, 0, 0]) + b"\x3B"
    assert summarize_c2pa(gif)["C2PA"] == "Not present"


def test_manifest_free_webp_reports_not_present() -> None:
    body = b"WEBP" + b"VP8 " + struct.pack("<I", 4) + b"\x00\x00\x00\x00"
    webp = b"RIFF" + struct.pack("<I", len(body)) + body
    assert summarize_c2pa(webp)["C2PA"] == "Not present"


def test_manifest_free_heic_reports_not_present() -> None:
    def box(tbox: bytes, content: bytes) -> bytes:
        return struct.pack(">I", 8 + len(content)) + tbox + content

    heic = box(b"ftyp", b"heic" + b"\x00" * 4 + b"heic" + b"mif1")
    assert summarize_c2pa(heic)["C2PA"] == "Not present"


def test_bare_jpeg_xl_codestream_reports_spec_has_no_embedding_defined() -> None:
    # Only the box-form JPEG XL container can carry a C2PA manifest at all --
    # a bare codestream isn't "checked and found none", it structurally can't
    # have one, same bucket as BMP/ATX/KTX.
    codestream = b"\xFF\x0A" + b"\x00" * 20
    assert summarize_c2pa(codestream)["C2PA"] == "Not defined by the C2PA spec for this format"


def test_claim_generator_and_actions_with_digital_source_type() -> None:
    claim_cbor = _map([(_tstr("claim_generator"), _tstr("acme/1.0"))])
    claim_box = _superbox(_CLAIM_UUID, "c2pa.claim", _box(b"cbor", claim_cbor))

    action_entry = _map([
        (_tstr("action"), _tstr("c2pa.created")),
        (_tstr("digitalSourceType"),
         _tstr("http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia")),
    ])
    actions_cbor = _map([(_tstr("actions"), _array([action_entry]))])
    actions_box = _superbox(b"\x00" * 16, "c2pa.actions", _box(b"cbor", actions_cbor))
    assertions_box = _superbox(_ASSERTIONS_UUID, "c2pa.assertions", actions_box)

    manifest = _superbox(_MANIFEST_UUID, "acme:urn:uuid:test", assertions_box + claim_box)
    manifest_store = _superbox(_MANIFEST_STORE_UUID, "c2pa", manifest)

    result = summarize_c2pa(_to_jpeg(manifest_store))

    assert result["C2PA"] == "Manifest found"
    assert result["C2PA Manifest ID"] == "acme:urn:uuid:test"
    assert result["C2PA Generator"] == "acme/1.0"
    assert result["C2PA Actions"] == "c2pa.created"
    assert result["C2PA Digital Source Type"] == (
        "Created using Generative AI (trainedAlgorithmicMedia)"
    )
    assert "C2PA Signature" not in result  # none present in this synthetic manifest


def test_action_software_agent_is_reported() -> None:
    action_entry = _map([
        (_tstr("action"), _tstr("c2pa.created")),
        (_tstr("softwareAgent"), _tstr("Acme AI Studio 2.0")),
    ])
    actions_cbor = _map([(_tstr("actions"), _array([action_entry]))])
    actions_box = _superbox(b"\x00" * 16, "c2pa.actions", _box(b"cbor", actions_cbor))
    assertions_box = _superbox(_ASSERTIONS_UUID, "c2pa.assertions", actions_box)
    manifest = _superbox(_MANIFEST_UUID, "test", assertions_box)
    manifest_store = _superbox(_MANIFEST_STORE_UUID, "c2pa", manifest)

    result = summarize_c2pa(_to_jpeg(manifest_store))
    assert result["C2PA Software Agent(s)"] == "Acme AI Studio 2.0"


def test_action_software_agent_as_object_uses_name_field() -> None:
    agent_obj = _map([(_tstr("name"), _tstr("Acme AI Studio")), (_tstr("version"), _tstr("2.0"))])
    action_entry = _map([
        (_tstr("action"), _tstr("c2pa.created")),
        (_tstr("softwareAgent"), agent_obj),
    ])
    actions_cbor = _map([(_tstr("actions"), _array([action_entry]))])
    actions_box = _superbox(b"\x00" * 16, "c2pa.actions", _box(b"cbor", actions_cbor))
    assertions_box = _superbox(_ASSERTIONS_UUID, "c2pa.assertions", actions_box)
    manifest = _superbox(_MANIFEST_UUID, "test", assertions_box)
    manifest_store = _superbox(_MANIFEST_STORE_UUID, "c2pa", manifest)

    result = summarize_c2pa(_to_jpeg(manifest_store))
    assert result["C2PA Software Agent(s)"] == "Acme AI Studio"


def test_ingredients_are_reported_by_title() -> None:
    ingredient = _map([(_tstr("title"), _tstr("original.jpg"))])
    ingredient_box = _superbox(b"\x00" * 16, "c2pa.ingredient", _box(b"cbor", ingredient))
    assertions_box = _superbox(_ASSERTIONS_UUID, "c2pa.assertions", ingredient_box)
    manifest = _superbox(_MANIFEST_UUID, "test", assertions_box)
    manifest_store = _superbox(_MANIFEST_STORE_UUID, "c2pa", manifest)

    result = summarize_c2pa(_to_jpeg(manifest_store))
    assert result["C2PA Ingredients"] == "original.jpg"


def test_ingredient_without_title_shows_placeholder_not_silently_dropped() -> None:
    ingredient = _map([(_tstr("format"), _tstr("image/jpeg"))])
    ingredient_box = _superbox(b"\x00" * 16, "c2pa.ingredient.v2", _box(b"cbor", ingredient))
    assertions_box = _superbox(_ASSERTIONS_UUID, "c2pa.assertions", ingredient_box)
    manifest = _superbox(_MANIFEST_UUID, "test", assertions_box)
    manifest_store = _superbox(_MANIFEST_STORE_UUID, "c2pa", manifest)

    result = summarize_c2pa(_to_jpeg(manifest_store))
    assert result["C2PA Ingredients"] == "(untitled)"


def test_claim_generator_info_fallback_when_flat_field_missing() -> None:
    # Claim v2 shape: structured claim_generator_info instead of a flat string.
    generator_info = _map([
        (_tstr("name"), _tstr("make_test_images")),
        (_tstr("version"), _tstr("0.67.1")),
    ])
    claim_cbor = _map([(_tstr("claim_generator_info"), generator_info)])
    claim_box = _superbox(_CLAIM_UUID, "c2pa.claim.v2", _box(b"cbor", claim_cbor))
    manifest = _superbox(_MANIFEST_UUID, "test", claim_box)
    manifest_store = _superbox(_MANIFEST_STORE_UUID, "c2pa", manifest)

    result = summarize_c2pa(_to_jpeg(manifest_store))
    assert result["C2PA Generator"] == "make_test_images/0.67.1"


def test_multiple_manifests_uses_last_as_active() -> None:
    first = _superbox(_MANIFEST_UUID, "first-manifest")
    second_claim = _superbox(
        _CLAIM_UUID, "c2pa.claim",
        _box(b"cbor", _map([(_tstr("claim_generator"), _tstr("second/1.0"))])),
    )
    second = _superbox(_MANIFEST_UUID, "second-manifest", second_claim)
    manifest_store = _superbox(_MANIFEST_STORE_UUID, "c2pa", first + second)

    result = summarize_c2pa(_to_jpeg(manifest_store))
    assert result["C2PA"] == "2 manifest(s) found"
    assert result["C2PA Manifest ID"] == "second-manifest"
    assert result["C2PA Generator"] == "second/1.0"


def test_signature_summarizes_leaf_certificate_without_verifying_trust() -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test C2PA Signer"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    cert_der = cert.public_bytes(encoding=serialization.Encoding.DER)

    protected = _bstr(_map([(_uint(1), _negint(-7)), (_uint(33), _array([_bstr(cert_der)]))]))
    sig_array = _array([protected, _map([]), _NULL, _bstr(b"fake-signature")])
    signature_box = _superbox(_SIGNATURE_UUID, "c2pa.signature", _box(b"cbor", sig_array))

    manifest = _superbox(_MANIFEST_UUID, "test", signature_box)
    manifest_store = _superbox(_MANIFEST_STORE_UUID, "c2pa", manifest)

    result = summarize_c2pa(_to_jpeg(manifest_store))

    assert result["C2PA Signature Algorithm"] == "ES256"
    assert result["C2PA Signed By"] == "Test C2PA Signer"
    assert result["C2PA Cert Issuer"] == "Test C2PA Signer"
    assert result["C2PA Signature"] == "Present (structure parsed, not cryptographically verified)"
