# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Raw block decompressors without a container format of their own:

- lz77_decompress: plain LZ77 ("Xpress", no Huffman stage), as specified in
  [MS-XCA] section 2.4 (LZ77 Decompression Algorithm). The Huffman variant
  used elsewhere (e.g. by qnxprobe) is a different format.
- lz4_block_decompress: one LZ4 block (the LZ4 Block Format, without the
  LZ4 Frame wrapper).

Used by the ESE (Extensible Storage Engine) parser: ESE stores compressed
column values and long-value chunks in these formats (see
crush/parsers/ese_reader.py).
"""
from __future__ import annotations


class BlockCompressionError(ValueError):
    """The compressed data is not valid for the format it was decoded as."""




def lz77_decompress(data: bytes, out_size: int) -> bytes:
    """Decompress *data* and return exactly *out_size* bytes.

    Raises BlockCompressionError if the data ends early, refers back before the start
    of the output, or does not produce *out_size* bytes.
    """
    out = bytearray()
    n = len(data)
    pos = 0
    flags = 0
    flag_count = 0
    last_length_half_byte = 0  # position of a shared length nibble, 0 if none

    while len(out) < out_size:
        if flag_count == 0:
            if pos + 4 > n:
                raise BlockCompressionError("flag word cut off")
            flags = int.from_bytes(data[pos:pos + 4], "little")
            pos += 4
            flag_count = 32
        flag_count -= 1
        if not flags & (1 << flag_count):
            if pos >= n:
                raise BlockCompressionError("literal cut off")
            out.append(data[pos])
            pos += 1
            continue

        if pos + 2 > n:
            raise BlockCompressionError("match cut off")
        match = int.from_bytes(data[pos:pos + 2], "little")
        pos += 2
        length = match & 7
        offset = (match >> 3) + 1
        if length == 7:
            if last_length_half_byte == 0:
                if pos >= n:
                    raise BlockCompressionError("length cut off")
                length = data[pos] & 0x0F
                last_length_half_byte = pos
                pos += 1
            else:
                length = data[last_length_half_byte] >> 4
                last_length_half_byte = 0
            if length == 15:
                if pos >= n:
                    raise BlockCompressionError("length cut off")
                length = data[pos]
                pos += 1
                if length == 255:
                    if pos + 2 > n:
                        raise BlockCompressionError("length cut off")
                    length = int.from_bytes(data[pos:pos + 2], "little")
                    pos += 2
                    if length == 0:
                        if pos + 4 > n:
                            raise BlockCompressionError("length cut off")
                        length = int.from_bytes(data[pos:pos + 4], "little")
                        pos += 4
                    if length < 15 + 7:
                        raise BlockCompressionError("invalid match length")
                    length -= 15 + 7
                length += 15
            length += 7
        length += 3

        start = len(out) - offset
        if start < 0:
            raise BlockCompressionError("match refers before the start of the output")
        if offset >= length:
            out += out[start:start + length]
        else:
            # Overlapping copy: byte by byte, the source grows as it's copied.
            for i in range(length):
                out.append(out[start + i])

    if len(out) != out_size:
        raise BlockCompressionError(f"produced {len(out)} bytes, expected {out_size}")
    return bytes(out)


def lz4_block_decompress(data: bytes, out_size: int) -> bytes:
    """Decompress one LZ4 block (LZ4 Block Format) to exactly *out_size* bytes.

    Raises BlockCompressionError if a sequence runs past the input, a match
    refers before the start of the output, or the output size differs.
    """
    out = bytearray()
    n = len(data)
    pos = 0
    while pos < n:
        token = data[pos]
        pos += 1
        literal_len = token >> 4
        if literal_len == 15:
            while True:
                if pos >= n:
                    raise BlockCompressionError("literal length cut off")
                b = data[pos]
                pos += 1
                literal_len += b
                if b != 255:
                    break
        if pos + literal_len > n:
            raise BlockCompressionError("literals cut off")
        out += data[pos:pos + literal_len]
        pos += literal_len
        if pos >= n:
            break  # the last sequence has literals only
        if pos + 2 > n:
            raise BlockCompressionError("match offset cut off")
        offset = data[pos] | (data[pos + 1] << 8)
        pos += 2
        if offset == 0:
            raise BlockCompressionError("match offset 0")
        match_len = token & 0x0F
        if match_len == 15:
            while True:
                if pos >= n:
                    raise BlockCompressionError("match length cut off")
                b = data[pos]
                pos += 1
                match_len += b
                if b != 255:
                    break
        match_len += 4
        start = len(out) - offset
        if start < 0:
            raise BlockCompressionError("match refers before the start of the output")
        if offset >= match_len:
            out += out[start:start + match_len]
        else:
            for i in range(match_len):
                out.append(out[start + i])
        if len(out) > out_size:
            raise BlockCompressionError(f"output exceeds the expected {out_size} bytes")
    if len(out) != out_size:
        raise BlockCompressionError(f"produced {len(out)} bytes, expected {out_size}")
    return bytes(out)
