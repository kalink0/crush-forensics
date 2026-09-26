# Contributing to Crush

Thanks for your interest in contributing. This document covers how to set up a development environment, run the test suite, and submit changes.

## Development setup

```bash
git clone https://github.com/kalink0/crush-forensics.git
cd crush-forensics
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python scripts/download_unifiedlog_binaries.py
```

System dependencies (Qt, libmagic, GStreamer) are listed in the [README](README.md#system-dependencies).

## Running the checks

```bash
python -m pytest -q          # tests
python -m ruff check .       # linting
python -m mypy crush         # type checking
```

CI runs all three on every push. A pull request should pass all three before review.

## Builds

**Stable releases** are tagged and built manually via `build.yml`.

**Nightly builds** run automatically at 02:00 UTC via `nightly.yml` and produce pre-release artifacts for Linux, Windows and MacOS. The `__build__` field in `crush/__init__.py` is stamped by CI with the date and short commit SHA (e.g. `20260425-nightly-a3f9c12`); this string appears in **Help → About**. The field is empty in source checkouts — that is intentional.

## Adding a parser or viewer

To add support for a new file format, see the [Developer Guide](crush/docs/developer-guide.md).
It covers the full parser and viewer architecture, step-by-step implementation, the `VFS` API,
the `ParseResult` contract, registration, and a checklist of every file you need to touch.

## Translating

To translate Crush's user interface into another language, see [TRANSLATING.md](TRANSLATING.md).

## Submitting changes

- Open an issue first for significant changes so we can agree on the approach before you write code.
- Keep pull requests focused — one feature or fix per PR.
- Add or update tests for any changed parser or core logic.
- Follow the existing code style (line length 100, ruff-enforced).

## Forensic data

Do **not** include real device acquisitions, case data, or personal information in tests or examples. Use synthetic or purpose-built test fixtures only.

## Reporting bugs

Use [GitHub Issues](https://github.com/kalink0/crush-forensics/issues). Include the Crush version (shown in Help → About), OS, and steps to reproduce.
