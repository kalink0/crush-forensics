# SPDX-License-Identifier: Apache-2.0
"""Text viewer search finds, counts and reaches every hit. It used to stop
after 5,000 hits: later ones weren't highlighted, listed or reachable with
Up/Down, and the count only said "5000+"."""
from __future__ import annotations

from crush.viewers.text_viewer import TextView

_HITS = 6_000  # past the old 5,000 cut


def _viewer(qapp) -> TextView:
    text = "".join(f"line {i} needle\n" for i in range(_HITS)) + "the end\n"
    view = TextView(text)
    view.resize(800, 400)
    view.show()
    qapp.processEvents()
    return view


def _current_line(view: TextView) -> int:
    return view._editor.textCursor().block().blockNumber() + 1


def test_every_hit_is_counted_and_listed(qapp) -> None:
    view = _viewer(qapp)
    view._search_input.setText("needle")
    view._refresh_search()
    assert view._search_count.text() == str(_HITS)
    assert view._result_model.rowCount() == _HITS
    last = view._result_model.index(_HITS - 1, 0).data()
    assert last == str(_HITS)


def test_up_and_down_reach_every_hit(qapp) -> None:
    view = _viewer(qapp)
    view._search_input.setText("needle")
    view._refresh_search()
    view._find_prev()  # from the top: wraps to the very last hit
    assert _current_line(view) == _HITS
    view._find_next()  # past the last: wraps to the first
    assert _current_line(view) == 1


def test_only_visible_hits_are_drawn(qapp) -> None:
    view = _viewer(qapp)
    view._search_input.setText("needle")
    view._refresh_search()
    drawn = len(view._editor.extraSelections())
    assert 0 < drawn < _HITS


def test_enter_right_after_typing_uses_the_new_search(qapp) -> None:
    view = _viewer(qapp)
    view._search_input.setText("the end")  # search is still waiting (debounce)
    view._find_next()
    assert view._editor.textCursor().selectedText() == "the end"
