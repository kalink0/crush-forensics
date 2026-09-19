# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""Streaming building blocks for VFS backends.

VFS.open() used to be `BytesIO(self.read(node))` for every archive-like
backend, which decompresses the *entire* member into RAM even when the
caller wants 32 bytes for a magic sniff or 256 KB for a hex pane. On a
17 GB TAR inside a ZIP that is an out-of-memory kill. The helpers here let a
backend hand out a real stream instead, and let callers copy a member to disk
in bounded chunks.
"""
from __future__ import annotations

import io
import threading
from collections.abc import Callable, Iterator
from typing import IO, Any, cast

# Members up to this size keep the old fully-buffered BytesIO behaviour: it is
# O(1) to seek, has no locking subtleties and costs at most this much memory.
# Larger members are streamed.
STREAM_THRESHOLD = 64 * 1024 * 1024

COPY_CHUNK = 1024 * 1024


class CopyCancelledError(Exception):
    """A chunked copy was stopped by the caller before it finished."""


class LockedStream(io.RawIOBase):
    """Serialises every access to a shared, stateful underlying stream.

    ZipExtFile / tarfile ExFileObject objects read through a file handle the
    whole archive shares, so two threads reading different members at once
    must not interleave. The lock is taken per read/seek, never held between
    calls, so a slow consumer does not block other members.
    """

    def __init__(self, inner: IO[bytes], lock: Any) -> None:
        super().__init__()
        self._inner = inner
        self._lock = lock

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return bool(self._inner.seekable())

    def readinto(self, b: Any) -> int:
        with self._lock:
            data = self._inner.read(len(b))
        n = len(data)
        b[:n] = data
        return n

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        with self._lock:
            return self._inner.seek(offset, whence)

    def tell(self) -> int:
        with self._lock:
            return self._inner.tell()

    def close(self) -> None:
        # Deliberately lock-free: close() also runs from the garbage
        # collector's finalizer, possibly in a thread that already holds this
        # (non-reentrant) lock, and closing a ZipExtFile/ExFileObject only
        # touches that object's own state.
        if not self.closed:
            try:
                self._inner.close()
            finally:
                super().close()


class IterStream(io.RawIOBase):
    """Seekable read-only stream over a restartable chunk generator.

    For sources that can only produce their bytes as a forward generator
    (filesystem walkers inside a disk image). Seeking forward discards
    chunks; seeking backward restarts the generator, so it is correct but
    O(size) -- fine for the sequential reads streaming is meant for.
    """

    def __init__(
        self,
        make_iter: Callable[[], Iterator[bytes]],
        size: int,
        lock: Any = None,
    ) -> None:
        super().__init__()
        self._make_iter = make_iter
        self._size = size
        self._lock = lock if lock is not None else threading.Lock()
        self._it: Iterator[bytes] | None = None
        self._buf = b""
        self._pos = 0  # logical position of the next byte handed to the caller

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def _restart(self) -> None:
        self._it = self._make_iter()
        self._buf = b""
        self._pos = 0

    def _next_chunk(self) -> bytes:
        if self._it is None:
            self._restart()
        assert self._it is not None
        with self._lock:
            return next(self._it, b"")

    def readinto(self, b: Any) -> int:
        want = len(b)
        if want == 0:
            return 0
        if not self._buf:
            self._buf = self._next_chunk()
            if not self._buf:
                return 0
        n = min(want, len(self._buf))
        b[:n] = self._buf[:n]
        self._buf = self._buf[n:]
        self._pos += n
        return n

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_CUR:
            target = self._pos + offset
        elif whence == io.SEEK_END:
            target = self._size + offset
        else:
            target = offset
        if target < 0:
            raise ValueError("negative seek position")
        if self._it is None or target < self._pos:
            self._restart()
        while self._pos < target:
            if not self._buf:
                self._buf = self._next_chunk()
                if not self._buf:
                    break
            skip = min(target - self._pos, len(self._buf))
            self._buf = self._buf[skip:]
            self._pos += skip
        return self._pos


def buffered(raw: io.RawIOBase, buffer_size: int = COPY_CHUNK) -> IO[bytes]:
    """Wrap a raw stream so callers get read(n)/peek/readline semantics."""
    return cast(IO[bytes], io.BufferedReader(raw, buffer_size=buffer_size))


class HashingWriter:
    """Write-through wrapper that hashes the bytes it forwards, so a copy and
    its integrity hash are one pass over the source instead of two."""

    def __init__(self, dst: IO[bytes], hasher: Any) -> None:
        self._dst = dst
        self._hasher = hasher

    def write(self, data: bytes) -> int:
        self._hasher.update(data)
        return self._dst.write(data)


def copy_stream(
    src: IO[bytes],
    dst: IO[bytes],
    *,
    total: int | None = None,
    progress: Callable[[int, int | None], None] | None = None,
    cancelled: Callable[[], bool] | None = None,
    chunk_size: int = COPY_CHUNK,
) -> int:
    """Copy *src* to *dst* in bounded chunks; returns the bytes copied.

    Raises CopyCancelledError as soon as *cancelled()* is true, so a caller
    can stop a multi-GB copy promptly without leaving the decision to the
    OS. Memory use is one chunk regardless of the source size.
    """
    done = 0
    while True:
        if cancelled is not None and cancelled():
            raise CopyCancelledError()
        chunk = src.read(chunk_size)
        if not chunk:
            break
        dst.write(chunk)
        done += len(chunk)
        if progress is not None:
            progress(done, total)
    return done
