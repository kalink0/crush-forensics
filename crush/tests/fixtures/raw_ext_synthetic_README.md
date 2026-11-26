# raw_ext4_encrypt_flag.img.gz, raw_ext_indirect_lost.img.gz

Synthetic ext volumes built with e2fsprogs 1.47.4 (`mkfs.ext4`, `debugfs`),
no root and no mount. Neither holds real encrypted content or real damage: each
sets the one on-disk field a reader decides on.

**raw_ext4_encrypt_flag.img.gz**: ext4, 4 KiB blocks, `encrypt` feature.
`enc.bin` (5,000 bytes, blocks 8 and 9 by `debugfs bmap`) carries
`EXT4_ENCRYPT_FL` (0x800) beside `EXTENTS_FL`. No key exists and nothing is
encrypted: the bytes are a counting pattern with the flag set. The rest of block
9 after byte 5,000 holds a second pattern, so a read that stops at the recorded
size or pads with zeros is told apart. `plain.bin` (3,000 bytes) has no flag.

**raw_ext_indirect_lost.img.gz**: ext2-style block map (no extents, no journal,
1 KiB blocks). `ind.bin` (20,480 bytes) needs its single indirect block for file
blocks 12 to 19; that pointer is set to block 999,999, past the end of the
volume. The data blocks are still in the image, but nothing on the volume maps
them.

Known answers (from the raw image and the source files, not from qnxprobe):

| File | Expected |
|---|---|
| `enc.bin` | 8,192 bytes = image bytes 32,768 to 40,959 (blocks 8 and 9), SHA-256 `c1e438609e5753955eff80081105e29c68351969de17cc94f575d06a8202f373`; its first 5,000 bytes are the source file, SHA-256 `6accb52144b47d1fbf464e13b7c12bfde77c6ad04a0037bcbb892bee8b086693` |
| `plain.bin` | 3,000 bytes, SHA-256 `6df4eaea8badf499539677363872162877a1ffe9ad46d60e5b0b917eac4c7b36` |
| `ind.bin` | refused: file blocks 0 to 11 (12,288 bytes) are mapped, 12 to 19 are not |

Build script (run in an empty folder; the images are then gzipped with
`gzip -n -9`):

```bash
set -e
python3 -c "open('enc.bin','wb').write(bytes((i*13+1)&0xff for i in range(5000)))"
python3 -c "open('plain.bin','wb').write(bytes((i*17+2)&0xff for i in range(3000)))"
mkfs.ext4 -q -F -b 4096 -O encrypt -E root_owner=0:0 -L enc raw_ext4_encrypt_flag.img 4M
debugfs -w -R "write enc.bin enc.bin" raw_ext4_encrypt_flag.img
debugfs -w -R "write plain.bin plain.bin" raw_ext4_encrypt_flag.img
debugfs -w -R "set_inode_field enc.bin flags 0x80800" raw_ext4_encrypt_flag.img
last=$(debugfs -R "bmap enc.bin 1" raw_ext4_encrypt_flag.img 2>/dev/null)
python3 - "$last" <<'EOF'
import sys
last = int(sys.argv[1])
with open("raw_ext4_encrypt_flag.img", "r+b") as f:
    f.seek(last * 4096 + 904)
    f.write(bytes((i * 7 + 3) & 0xFF for i in range(4096 - 904)))
EOF

python3 -c "open('ind.bin','wb').write(bytes((i*31+7)&0xff for i in range(20*1024)))"
mkfs.ext4 -q -F -b 1024 -O ^extents,^has_journal,^64bit -L ind raw_ext_indirect_lost.img 2M
debugfs -w -R "write ind.bin ind.bin" raw_ext_indirect_lost.img
debugfs -w -R "set_inode_field ind.bin block[IND] 999999" raw_ext_indirect_lost.img
```

`mkfs.ext4` writes a random UUID and the build time, so a rebuild gives other
image bytes; the known answers above stay the same.
