"""Coordinate latency-sensitive foreground I/O with background scanning."""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import threading


_condition = threading.Condition()
_foreground_count = 0
_background_active = 0


def acquire_foreground_io() -> None:
    """Pause new background I/O and wait for current operations to finish."""
    global _foreground_count
    with _condition:
        _foreground_count += 1
        while _background_active:
            _condition.wait()


def release_foreground_io() -> None:
    """Release one foreground I/O claim."""
    global _foreground_count
    with _condition:
        if _foreground_count == 0:
            return
        _foreground_count -= 1
        if _foreground_count == 0:
            _condition.notify_all()


@contextmanager
def foreground_io() -> Iterator[None]:
    """Pause new background I/O and wait for current operations to finish."""
    acquire_foreground_io()
    try:
        yield
    finally:
        release_foreground_io()


@contextmanager
def background_io() -> Iterator[None]:
    """Yield to foreground I/O between small background operations."""
    global _background_active
    with _condition:
        while _foreground_count:
            _condition.wait()
        _background_active += 1
    try:
        yield
    finally:
        with _condition:
            _background_active -= 1
            if _background_active == 0:
                _condition.notify_all()
