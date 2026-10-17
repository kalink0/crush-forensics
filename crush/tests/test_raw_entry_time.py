# SPDX-License-Identifier: Apache-2.0
"""A raw image walker's time of 0 is "no time" only where qnxprobe's own
conversion defines 0 that way (NTFS, ReFS, F2FS, APFS, HFS+; FAT/exFAT,
whose entries store a reading, always give 0). Everywhere else a 0 is the
stored time 1970-01-01 00:00:00 UTC, e.g. on an image built with a fixed
timestamp."""
from __future__ import annotations

import pytest

from crush.core.raw_image import _entry_time
from crush.third_party.qnxprobe import qnxprobe as qp


def _walker(cls: type) -> object:
    return cls.__new__(cls)  # the type is all _entry_time looks at


@pytest.mark.parametrize("cls", [
    qp.NtfsWalker, qp.RefsWalker, qp.F2fsWalker, qp.ApfsWalker, qp.HfsPlusWalker,
    qp.Fat32Walker, qp.Fat16Walker, qp.Fat12Walker, qp.ExfatWalker,
])
def test_zero_is_no_time_where_the_walker_defines_it(cls: type) -> None:
    walker = _walker(cls)
    assert _entry_time(walker, 0) is None
    assert _entry_time(walker, 1_700_000_000) == 1_700_000_000.0


@pytest.mark.parametrize("cls", [
    qp.ExtWalker, qp.XfsWalker, qp.BtrfsWalker, qp.Qnx6Walker, qp.Qnx4Walker,
    qp.SquashfsWalker, qp.YaffsWalker, qp.Jffs2Walker, qp.UbifsWalker, qp.EfsWalker,
])
def test_zero_is_the_epoch_everywhere_else(cls: type) -> None:
    walker = _walker(cls)
    assert _entry_time(walker, 0) == 0.0
    assert _entry_time(walker, -1) == -1.0  # before 1970, as stored
    assert _entry_time(walker, None) is None
