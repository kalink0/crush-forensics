# raw_ntfs_streams.img.gz

Copied unmodified from [abrignoni/qnxprobe](https://github.com/abrignoni/qnxprobe)
`tests/fixtures/ntfs-streams.img.gz` and `ntfs-streams.sha256` (here
`raw_ntfs_streams.sha256`) at commit `b3e5bb3131ed3960234eace5de8ed0e3de7ff5b2`
(tag v1.38), MIT License. Written by qnxprobe's `tools/make_ntfs_streams_fixture.sh`.

A generated NTFS volume whose files and folders carry alternate data streams:
Zone.Identifier streams, a stream on the root folder and on a folder, a stream
whose front is a hole (like `$UsnJrnl:$J`), a compressed stream, a stream of no
bytes, streams that store nothing at all, twelve streams on one file, a hard
link's shared stream, and a stream with a non-ASCII name.

`raw_ntfs_streams.sha256` gives, for every stream that stores a cluster, the
SHA-256 The Sleuth Kit's `icat` reads from its first stored cluster on — the
known answers. Its header names the streams left out because every cluster is
sparse.
