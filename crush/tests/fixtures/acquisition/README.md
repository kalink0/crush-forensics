# Acquisition fixtures

Copied unmodified from [abrignoni/ewfprobe](https://github.com/abrignoni/ewfprobe)
`tests/fixtures/` at commit `2a40257d83de69b01566dd0f0b0dfe7b6ad33bd7` (tag v0.2.0),
MIT License.

| File | Container | Written by |
|---|---|---|
| `ex01-fast.Ex01` | EWF2 (EnCase 7 Ex01) | libewf `ewfacquire` |
| `smart-fast.s01` | SMART (EWF-S01) | libewf `ewfacquire` |
| `aff-zlib.aff` | AFF, zlib pages | AFFLIB `affconvert` |
| `aff-afd.afd/` | AFD (AFF split over five files) | AFFLIB `affconvert` |

All four hold the same generated source disk, not evidence: 3,145,728 bytes,
512-byte sectors, SHA-256
`770be732aafc4962c6940a2076c35471419621d9d6ca57cda60cbd6e82a8b36f` (from ewfprobe's
`tests/fixtures/manifest.json`). It holds image files at fixed offsets and no
partition table or filesystem. Each container stores its own MD5 (the AFF and
Ex01 ones a SHA-1 as well) of that disk.

`aff-afd.afd/file_004.aff` is the member that records the image size: opened on
its own, outside its folder, it is an AFF whose other pages are missing.

## From ewfprobe v0.12.0

Copied from the same repository at commit `34c34b8496f0f3d57450d77b7f27a3247f4b08aa`
(tag v0.12.0), at the same paths below `tests/fixtures/`, MIT License. The disk
each one holds is recorded in ewfprobe's `tests/fixtures/manifest.json` and
`tests/fixtures/virtual/manifest.json`.

| File(s) | Container | Written by | Opens with |
|---|---|---|---|
| `dmg-udzo.dmg` | UDIF, zlib | hdiutil, macOS 26.6.2 | — |
| `dmg-gpt-segmented.dmg`, `.002`–`.005.dmgpart` | UDIF in five segments | hdiutil, macOS 26.6.2 | — |
| `dmg-enc-sparse-aes128.sparseimage` | sparse image, AES-128 | hdiutil, macOS 26.6.2 | password `ewfprobe-test-password` |
| `dmg-cert-only-udzo-aes256.dmg` | UDIF, AES-256, certificate only | hdiutil, macOS 26.6.2 | `dmg-cert-test-key-2048.pem` |
| `dmg-sparsebundle.sparsebundle/` | sparse bundle | hdiutil, macOS 26.6.2 | — |
| `dmg-enc-sparsebundle-aes256.sparsebundle/` | sparse bundle, AES-256; band 0 removed and band 1 cut to 32 KiB upstream, hdiutil reads the same disk | hdiutil, macOS 26.6.2 | password `ewfprobe-test-password` |
| `pyaff4-zlib.aff4` | AFF4, zlib | pyaff4 | — |
| `aff-enc-pass.aff` | AFF, AES-256 | AFFLIB 3.7.22 | password `ewfprobe-aff-password` |
| `ftk-ad-e01.E01`, `.E02` | EWF-E01, AD encryption | FTK Imager 4.7.3.61 | password `ewfprobe-ad-test` |
| `virtual/windows/*.gz` | VHD, VHDX: dynamic, and differencing over it | Windows 11 diskpart | — |
| `virtual/qemu-compact/*.gz` | VHD, VHDX, VMDK, QCOW (one LUKS-encrypted) | qemu-img 10.2.1 | — |

`dmg-sparsebundle.sparsebundle/bands/*.gz` are gzip-compressed here; the tests
decompress them into a copy of the bundle.

## Logical evidence (`logical/`), from ewfprobe v0.12.0

Copied from the same repository and commit (`34c34b8`, tag v0.12.0): `tests/fixtures/ad1/`
and `tests/fixtures/` (the certificate set, its key and the L01). MIT License; the L01 is
Digital Corpora scenario data, CC0.

| File(s) | Container | Written by | Opens with |
|---|---|---|---|
| `lean-multi-ntfs-c9.ad1` | AD1 v4, two sources (an NTFS volume, a folder), compression 9 | FTK Imager 4.7.3.61 | — |
| `lean-src-c0-1mb.ad1.gz`–`.ad4.gz` | AD1 v4 in four 1 MB files, compression 0 | FTK Imager 4.7.3.61 | — |
| `lean-src-c6-1mb-adcrypt.ad1`, `.ad2` | the same folder, compression 6, AD encryption | FTK Imager 4.7.3.61 | password `Ad1Test-2026!` |
| `ftk-ad-cert-ad1.ad1` | AD1, AD encryption sealed to a 2048-bit test certificate | FTK Imager 4.7.3.61 | `ad-cert-test-key-2048.pem` |
| `tracy-phone-2012-07-05-1640.L01.gz` | EWF-L01 of an iPhone, 9,951 entries | EnCase 7.2.4.2 | — |

Beside each AD1: FTK Imager's own log (`*.ad1.txt`, holding the image hash, which an AD1
doesn't store itself) and its file listing (`*.ad1.csv`, UTF-16: path, size, times,
deleted flag, MD5, SHA-1). `lean_manifest.txt` records the folder imaged, file by file
(size, MD5, SHA-1, UTC times), before imaging. The `.gz` files are gzip-compressed here;
the tests decompress them.
