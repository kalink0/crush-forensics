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
