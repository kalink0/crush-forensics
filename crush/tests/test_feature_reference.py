# SPDX-License-Identifier: Apache-2.0
"""The Feature Reference's section files (crush/docs/reference/) and
scripts/reference.py: the generated single page, links in every language,
and which translated sections are outdated."""
from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load_script():
    spec = importlib.util.spec_from_file_location("reference_script", ROOT / "scripts" / "reference.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ref = _load_script()


# -- The real reference ---------------------------------------------------------------

def test_generated_reference_is_up_to_date() -> None:
    assert ref.OUTPUT.read_text(encoding="utf-8") == ref.Reference().build(), (
        "crush/docs/feature-reference.md is out of date -- edit the section files in "
        "crush/docs/reference/en/, then run: python scripts/reference.py build"
    )


def test_reference_links_and_files() -> None:
    assert ref.Reference().check() == []


def test_every_section_starts_with_its_heading() -> None:
    reference = ref.Reference()
    for name in reference.sections():
        first = reference.english(name).split("\n", 1)[0]
        assert first.startswith(("## ", "### ")), name


# -- Anchors --------------------------------------------------------------------------

@pytest.mark.parametrize(("heading", "anchor"), [
    ("Raw Disk Images & EWF Acquisitions", "raw-disk-images--ewf-acquisitions"),
    ("SQLite / Database Viewer", "sqlite--database-viewer"),
    ("What is Crush?", "what-is-crush"),
    ("Übersicht der Viewer", "übersicht-der-viewer"),
])
def test_anchor_like_github(heading: str, anchor: str) -> None:
    assert ref.base_anchor(heading) == anchor


def test_repeated_heading_gets_suffix_and_code_blocks_are_skipped() -> None:
    text = "## A\n### Known limitations\n```\n# not a heading\n```\n## B\n### Known limitations\n"
    assert ref.anchors(text) == ["a", "known-limitations", "b", "known-limitations-1"]


# -- A reference with a translation -----------------------------------------------

def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.fixture
def book(tmp_path: Path):
    en = tmp_path / "en"
    _write(en / "index.md", "# Reference\n\n- [One](one.md)\n- [Two](two.md)\n")
    _write(en / "one.md", "## One\n\nSee [the details](two.md#details).\n\n")
    _write(en / "two.md", "## Two\n\n### Details\n\nBack to [one](one.md).\n")
    return ref.Reference(tmp_path)


def test_build_turns_file_links_into_anchors(book) -> None:
    assert book.build() == (
        ref.GENERATED_NOTE + "# Reference\n\n"
        "## One\n\nSee [the details](#details).\n\n"
        "## Two\n\n### Details\n\nBack to [one](#one).\n"
    )


def test_status_missing_current_outdated(book) -> None:
    _write(book.directory / "de" / "one.md", "## Eins\n\nSiehe [Details](two.md#details).\n\n")
    assert book.status("de")["one.md"] == "unstamped"
    book.stamp("de", "one.md")
    assert book.status("de") == {"index.md": "missing", "one.md": "current", "two.md": "missing"}
    # The stamp line doesn't reach the text.
    assert book.text("de", "one.md").startswith("## Eins")

    _write(book.directory / "en" / "one.md", "## One\n\nSee [the details](two.md#details), now.\n")
    assert book.status("de")["one.md"] == "outdated"


def test_line_endings_dont_make_a_translation_outdated(book) -> None:
    _write(book.directory / "de" / "one.md", "## Eins\n")
    book.stamp("de", "one.md")
    english = book.directory / "en" / "one.md"
    # From the text, not the bytes: on Windows write_text already wrote CRLF.
    english.write_bytes(english.read_text(encoding="utf-8").replace("\n", "\r\n").encode())
    assert book.status("de")["one.md"] == "current"


def test_stamp_refuses_english(book) -> None:
    with pytest.raises(ValueError):
        book.stamp("en", "one.md")


def test_check_follows_translated_headings(book) -> None:
    # two.md in German: its heading "Details" is now "Einzelheiten", so the
    # English anchor #details no longer exists in German.
    _write(book.directory / "de" / "two.md", "## Zwei\n\n### Einzelheiten\n\nZurück zu [eins](one.md).\n")
    problems = book.check()
    assert problems == [
        "de/one.md:3: two.md#details -- no such heading in two.md",
    ]
    _write(book.directory / "de" / "one.md", "## Eins\n\nSiehe [Einzelheiten](two.md#einzelheiten).\n")
    assert book.check() == []


def test_check_reports_unlisted_orphaned_and_broken(book) -> None:
    _write(book.directory / "en" / "three.md", "## Three\n")
    _write(book.directory / "de" / "gone.md", "## Weg\n")
    _write(book.directory / "de" / "index.md", "# Referenz\n\n- [Zwei](two.md)\n- [Eins](one.md)\n")
    _write(book.directory / "en" / "two.md", "## Two\n\n### Details\n\n[x](#nowhere) [y](four.md)\n")
    problems = book.check()
    assert "en/three.md is not listed in en/index.md" in problems
    assert "de/gone.md has no English original" in problems
    assert "de/index.md doesn't list the sections of en/index.md" in problems
    assert "en/two.md:5: #nowhere -- no such heading in this file" in problems
    assert "en/two.md:5: four.md -- no such section file" in problems


def test_real_reference_splits_back_to_the_same_page(tmp_path: Path) -> None:
    """The committed reference round-trips through a copy (build is pure)."""
    shutil.copytree(ref.REFERENCE_DIR, tmp_path / "reference")
    assert ref.Reference(tmp_path / "reference").build() == ref.Reference().build()
