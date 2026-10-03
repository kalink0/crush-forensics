# raw_ntfs_windows.img.gz

Copied unmodified from [abrignoni/qnxprobe](https://github.com/abrignoni/qnxprobe)
`tests/fixtures/ntfs-windows.img.gz` and `ntfs-windows.known.tsv` (here
`raw_ntfs_windows.known.tsv`) at commit `8d530e92f9d7cc3b9e744cde07ea3381b589fe1f`
(tag v1.56), MIT License. Written by qnxprobe's `tools/make_ntfs_windows_fixture.cmd`
and `.ps1` on Windows 11, then `tools/finish_ntfs_windows_fixture.py`.

A 40 MiB NTFS volume Windows itself wrote, holding the kinds of file whose
recorded size is not what the volume stores for them:

- `wof/xpress4k`, `wof/xpress8k`, `wof/xpress16k`, `wof/lzx`: five files each,
  compressed by the Windows overlay filter (`compact /exe:...`). Their unnamed
  data stream is all hole and the content is in a `WofCompressedData` stream.
- `lznt1/`: two files with NTFS compression.
- `sparse/` and `Pictures/sparse_photo.jpg`: sparse files, with holes at the
  start, at the end, at both ends, and one that is all hole.
- `Pictures/plain.jpg` and `Pictures/hardlink.jpg`: one file under two names.
- `CloudRoot/`: three online-only cloud placeholders written through the
  Windows Cloud Files API (a size, and nothing stored), and one hydrated file.

`raw_ntfs_windows.known.tsv` is what Windows reported for each of the 35 files:
length, attributes, size on disk, SHA-256, and whether it could read the file
at all with no cloud provider running. Those are the known answers. Windows
refused the three placeholders and read the rest.

The volume holds no personal data: every file is generated, and the machine
SID in its security descriptors was replaced before it was published.

# raw_bitlocker_locked.img.gz

Copied unmodified from the same repository and commit,
`tests/fixtures/bitlocker-xts128.img.gz`, built by qnxprobe's
`tools/make_bitlocker_fixtures.py`: a small BitLocker volume (AES-128-XTS)
with no key given, so the reader names it and cannot read it.
