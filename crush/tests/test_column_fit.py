# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 - now Marco Neumann (kalink0)
"""ColumnFitter: tree columns follow their content within the free room."""
from __future__ import annotations

import time

from PySide6.QtCore import QSortFilterProxyModel
from PySide6.QtGui import QStandardItem, QStandardItemModel
from PySide6.QtWidgets import QApplication, QTreeView

from crush.ui.column_fit import ColumnFitter, distribute_widths


def _settle(ms: int = 200) -> None:
    deadline = time.monotonic() + ms / 1000
    while time.monotonic() < deadline:
        QApplication.processEvents()


def _tree(widgets, child_name: str, view_width: int = 600):  # noqa: ANN001, ANN202
    model = QStandardItemModel()
    model.setHorizontalHeaderLabels(["Name", "Size", "Type"])
    root = QStandardItem("root")
    root.appendRow([QStandardItem(child_name), QStandardItem("1 B"), QStandardItem("x")])
    model.appendRow([root, QStandardItem(""), QStandardItem("DIR")])
    proxy = QSortFilterProxyModel()
    proxy.setSourceModel(model)
    view = widgets(QTreeView())
    view.setModel(proxy)
    view._keep = (model, proxy)  # noqa: SLF001 -- keep the models alive with the view
    fitter = ColumnFitter(view, {0: 160})
    view.setColumnWidth(1, 60)
    view.setColumnWidth(2, 80)
    view.resize(view_width, 300)
    view.show()
    _settle()
    return view, fitter


def test_distribute_keeps_wanted_widths_that_fit() -> None:
    assert distribute_widths({0: 300, 1: 250}, {0: 160, 1: 200}, 1000) == {0: 300, 1: 250}


def test_distribute_never_below_minimum() -> None:
    assert distribute_widths({0: 50}, {0: 160}, 1000) == {0: 160}
    assert distribute_widths({0: 900}, {0: 160}, 100) == {0: 160}


def test_distribute_shares_room_and_keeps_small_columns() -> None:
    # Column 0 wants less than half of 600, so it keeps its width; column 1 gets the rest.
    assert distribute_widths({0: 200, 1: 900}, {0: 160, 1: 160}, 600) == {0: 200, 1: 400}
    assert distribute_widths({0: 800, 1: 900}, {0: 160, 1: 160}, 600) == {0: 300, 1: 300}


def test_name_column_grows_on_expand(qapp, widgets) -> None:  # noqa: ANN001
    view, _ = _tree(widgets, "a_rather_long_file_name_for_testing_the_column.sqlite-wal")
    assert view.columnWidth(0) == 160
    view.expand(view.model().index(0, 0))
    _settle()
    assert view.columnWidth(0) > 160
    # As wide as the name needs, or as the room the other columns leave -- which
    # one applies depends on the platform's font metrics (Windows measures wider).
    available = view.viewport().width() - view.columnWidth(1) - view.columnWidth(2)
    assert view.columnWidth(0) == min(view.sizeHintForColumn(0), available)


def test_name_column_leaves_room_for_other_columns(qapp, widgets) -> None:  # noqa: ANN001
    view, _ = _tree(widgets, "x" * 400, view_width=500)
    view.expand(view.model().index(0, 0))
    _settle()
    others = view.columnWidth(1) + view.columnWidth(2)
    assert view.columnWidth(0) == view.viewport().width() - others


def test_collapse_does_not_shrink(qapp, widgets) -> None:  # noqa: ANN001
    view, _ = _tree(widgets, "a_rather_long_file_name_for_testing_the_column.sqlite-wal")
    index = view.model().index(0, 0)
    view.expand(index)
    _settle()
    grown = view.columnWidth(0)
    view.collapse(index)
    _settle()
    assert view.columnWidth(0) == grown


def test_manual_sizing_stops_fitting_until_reset(qapp, widgets) -> None:  # noqa: ANN001
    view, fitter = _tree(widgets, "a_rather_long_file_name_for_testing_the_column.sqlite-wal")
    view.header().sectionHandleDoubleClicked.emit(0)
    view.setColumnWidth(0, 170)
    view.expand(view.model().index(0, 0))
    _settle()
    assert view.columnWidth(0) == 170
    fitter.reset()
    _settle()
    assert view.columnWidth(0) > 170


def test_reset_returns_to_minimum_for_short_content(qapp, widgets) -> None:  # noqa: ANN001
    view, fitter = _tree(widgets, "a_rather_long_file_name_for_testing_the_column.sqlite-wal")
    index = view.model().index(0, 0)
    view.expand(index)
    _settle()
    view.collapse(index)
    fitter.reset()
    _settle()
    assert view.columnWidth(0) == 160
