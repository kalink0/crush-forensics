"""SQLite parser — reads tables, columns, and row data."""
from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from crush.core import sqlite_journal, tempdir
from crush.core.issues import ParseIssue
from crush.core.vfs import VFS, VFSNode, find_sibling
from crush.parsers.base import AbstractParser, ParseResult

_SQLITE_MAGIC = b"SQLite format 3\x00"
_ROW_LIMIT = 10_000
_logger = logging.getLogger(__name__)


def _lenient_text_factory(raw: bytes) -> str | bytes:
    """SQLite is dynamically typed: a column declared TEXT can still hold
    bytes an app wrote that aren't valid UTF-8 (e.g. a generic key/value
    "meta" table whose "value" column mixes real text and serialized
    binary data). The sqlite3 driver's default text_factory decodes every
    fetched TEXT value as UTF-8 and raises on the first one that isn't,
    which previously failed the *entire* table's read -- every other row,
    including ones with no problem at all, was lost along with it. Falling
    back to the exact original bytes (not a lossy decode) for just that
    one value keeps the rest of the table readable and lets the table
    viewer's existing BLOB handling (hex view, "Inspect Cell") show it,
    rather than losing or corrupting the data.
    """
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw

# SQLCipher's legacy compatibility presets (page size / KDF iteration count /
# KDF+HMAC digest algorithm), tried in order after the linked library's own
# current default. An older/legacy app frequently keeps an older SQLCipher
# library's defaults even after later updates, and the encrypted file gives
# no signal of which version wrote it -- the entire file, including what
# would be the plaintext SQLite magic header, is ciphertext. Each attempt is
# a real, cryptographically-verified pass/fail via the linked SQLCipher
# engine's own per-page HMAC check (not a guess): a SELECT forces it to
# actually decrypt page 1 against sqlite_master.
_CIPHER_COMPATIBILITY_PRESETS: tuple[int | None, ...] = (None, 4, 3, 2, 1)

# Digest choices exposed in the "Advanced" UI, mapped to the PRAGMA value
# tokens SQLCipher actually expects (different prefix for KDF vs. HMAC).
# A fixed whitelist -- never interpolate a user-supplied digest string
# directly into the PRAGMA -- since both PRAGMAs are built via f-string,
# not parameter binding (PRAGMA doesn't support it for these settings).
_KDF_ALGORITHMS = {
    "SHA1": "PBKDF2_HMAC_SHA1",
    "SHA256": "PBKDF2_HMAC_SHA256",
    "SHA512": "PBKDF2_HMAC_SHA512",
}
_HMAC_ALGORITHMS = {
    "SHA1": "HMAC_SHA1",
    "SHA256": "HMAC_SHA256",
    "SHA512": "HMAC_SHA512",
}


@dataclass
class SQLCipherParams:
    """Explicit SQLCipher cipher parameters for the "Advanced" open path.

    Some real-world apps don't match any of SQLCipher's own
    cipher_compatibility presets -- notably Signal and its forks (Session,
    Molly), which manage a high-entropy key via the platform keystore and
    set kdf_iter=1 to skip the (now pointless) passphrase-stretching cost,
    alongside page_size=4096 and SHA512 for both KDF and HMAC. There's no
    way to detect this from the ciphertext, so when the caller supplies
    these (e.g. from reverse-engineering the app, or a Frida dump), they're
    applied exactly as given in a single attempt -- no auto-try guessing.

    Deliberately does NOT include raw_key -- whether the key is a raw hex
    blob (skipping the KDF, SQLCipher's own recommended approach for a key
    "managed externally", e.g. an Android Keystore-derived key) or a text
    passphrase is orthogonal to these tuning parameters: page_size and
    cipher_hmac_algorithm still matter for a raw key too, so raw_key must
    stay in effect during the compatibility-preset auto-try, not only when
    the caller also opts into fully custom parameters.
    """

    page_size: int = 4096
    kdf_iter: int = 256_000
    kdf_algorithm: str = "SHA512"
    hmac_algorithm: str = "SHA512"
    plaintext_header_size: int = 0


def _connect_sqlcipher(
    tmp_path: str,
    password: str,
    *,
    raw_key: bool = False,
    params: SQLCipherParams | None = None,
) -> Any:
    """Open *tmp_path* as a SQLCipher-encrypted database with *password*
    (a raw hex key if *raw_key*, otherwise a text passphrase).

    With *params* omitted, tries the linked library's current default then
    each cipher_compatibility preset in turn (see _CIPHER_COMPATIBILITY_PRESETS).
    With *params* given, applies exactly those cipher settings in one
    attempt -- see SQLCipherParams.

    Returns a sqlcipher3 connection (drop-in API-compatible with
    sqlite3.Connection) already verified to decrypt correctly. Raises
    WrongPasswordError if the key/parameters don't work.
    """
    from sqlcipher3 import dbapi2 as sqlcipher

    from crush.core.passwords import WrongPasswordError

    def _apply_key(conn: Any) -> None:
        if raw_key:
            hex_key = password.strip().lower().removeprefix("0x")
            try:
                bytes.fromhex(hex_key)
            except ValueError as exc:
                raise WrongPasswordError(
                    ParseIssue("sqlite.invalid_hex_key", detail=str(exc))
                ) from exc
            conn.execute(f"PRAGMA key = \"x'{hex_key}'\"")
        else:
            escaped = password.replace("'", "''")
            conn.execute(f"PRAGMA key = '{escaped}'")

    def _try_open(compat: int | None, custom: SQLCipherParams | None) -> Any:
        conn = sqlcipher.connect(f"file:{tmp_path}?mode=ro", uri=True)
        conn.text_factory = _lenient_text_factory
        try:
            _apply_key(conn)
            if compat is not None:
                conn.execute(f"PRAGMA cipher_compatibility = {compat}")
            if custom is not None:
                conn.execute(f"PRAGMA cipher_page_size = {int(custom.page_size)}")
                conn.execute(f"PRAGMA kdf_iter = {int(custom.kdf_iter)}")
                conn.execute(
                    f"PRAGMA cipher_kdf_algorithm = {_KDF_ALGORITHMS[custom.kdf_algorithm]}"
                )
                conn.execute(
                    f"PRAGMA cipher_hmac_algorithm = {_HMAC_ALGORITHMS[custom.hmac_algorithm]}"
                )
                conn.execute(
                    f"PRAGMA cipher_plaintext_header_size = {int(custom.plaintext_header_size)}"
                )
            conn.execute("SELECT count(*) FROM sqlite_master")
            return conn
        except sqlcipher.DatabaseError:
            conn.close()
            raise

    if params is not None:
        try:
            return _try_open(None, params)
        except sqlcipher.DatabaseError as exc:
            issue = ParseIssue("sqlite.custom_params_rejected", detail=str(exc))
            _logger.info("%s (SQLCipher: %s)", issue, issue.detail)
            raise WrongPasswordError(issue) from exc

    last_exc: Exception | None = None
    for compat in _CIPHER_COMPATIBILITY_PRESETS:
        try:
            return _try_open(compat, None)
        except sqlcipher.DatabaseError as exc:
            last_exc = exc
            continue
    issue = ParseIssue("sqlite.password_rejected", detail=str(last_exc))
    _logger.info("%s (SQLCipher: %s)", issue, issue.detail)
    raise WrongPasswordError(issue)


def _journal_mode_fact(pragma_value: str | None) -> str | ParseIssue:
    """What the file itself records about its journal mode.

    The header (bytes 18/19) only stores WAL vs. rollback journal.
    PRAGMA journal_mode reads that for "wal"; any other value ("delete",
    "truncate", "persist" …) is the connection's default, not something
    the file recorded -- so only the WAL/rollback distinction is shown.
    Works for SQLCipher too, where the raw header bytes are ciphertext.
    """
    if pragma_value is None:
        return "?"
    if pragma_value.lower() == "wal":
        return "WAL"
    return ParseIssue("sqlite.journal_mode_rollback")


class SQLiteParser(AbstractParser):
    SUPPORTED_EXTENSIONS = [".db", ".sqlite", ".sqlite3", ".db3"]
    DISPLAY_NAME = "SQLite database"
    SUPPORTS_PASSWORD = True

    def can_parse(self, path: str, peek_bytes: bytes) -> bool:
        return peek_bytes[:16] == _SQLITE_MAGIC

    def parse(
        self,
        node: VFSNode,
        vfs: VFS,
        password: str | None = None,
        raw_key: bool = False,
        cipher_params: SQLCipherParams | None = None,
    ) -> ParseResult:
        raw = vfs.read(node)

        with tempdir.named_temporary_file(prefix="crush-sqlite-", suffix=".db") as tmp:
            tmp.write(raw)
            tmp_path = tmp.name

        # Copy WAL and SHM companion files if present
        companions: list[str] = []
        _wal_diag_lines: list[ParseIssue] = []
        # Companions that exist but couldn't be read -- without this the
        # database would silently open without its WAL/journal layer.
        companion_failures: list[ParseIssue] = []
        for suffix in ("-wal", "-shm"):
            sibling = find_sibling(node, vfs, suffix)
            if sibling is not None:
                try:
                    sib_bytes = vfs.read(sibling)
                    if not sib_bytes:
                        issue = ParseIssue("sqlite.companion_empty", {
                            "name": sibling.name, "path": repr(sibling.path),
                            "size": sibling.size,
                        })
                        _logger.warning("%s", issue)
                        if suffix == "-wal":
                            _wal_diag_lines.append(issue)
                    else:
                        sib_path = tmp_path + suffix
                        with open(sib_path, "wb") as f:
                            f.write(sib_bytes)
                        companions.append(sibling.name)
                        _logger.debug("Copied companion file: %s (%d B)", sibling.name, len(sib_bytes))
                        if suffix == "-wal":
                            _wal_diag_lines.append(ParseIssue("sqlite.companion_copied", {
                                "name": sibling.name, "size": len(sib_bytes),
                                "path": repr(sibling.path),
                            }))
                except Exception as exc:
                    issue = ParseIssue(
                        "sqlite.companion_read_failed", {"name": sibling.name}, detail=str(exc),
                    )
                    _logger.warning("%s", issue)
                    companion_failures.append(issue)
                    if suffix == "-wal":
                        _wal_diag_lines.append(issue)
            else:
                if suffix == "-wal":
                    _wal_diag_lines.append(
                        ParseIssue("sqlite.companion_not_in_vfs", {"path": repr(node.path)})
                    )
                # FileVFS: node.path is an absolute filesystem path — check for the
                # companion directly on disk (find_sibling only searches the VFS tree)
                fs_companion = Path(node.path + suffix)
                if fs_companion.is_file():
                    try:
                        sib_path = tmp_path + suffix
                        fs_bytes = fs_companion.read_bytes()
                        with open(sib_path, "wb") as f:
                            f.write(fs_bytes)
                        companions.append(fs_companion.name)
                        _logger.debug("Loaded filesystem companion: %s", fs_companion.name)
                        if suffix == "-wal":
                            _wal_diag_lines.append(ParseIssue("sqlite.companion_loaded_fs", {
                                "name": fs_companion.name, "size": len(fs_bytes),
                            }))
                    except Exception as exc:
                        issue = ParseIssue(
                            "sqlite.companion_fs_read_failed", {"name": fs_companion.name},
                            detail=str(exc),
                        )
                        _logger.warning("%s", issue)
                        companion_failures.append(issue)

        # Copy a rollback-journal (-journal) companion if present, for
        # provenance/analysis only (crush.core.sqlite_journal + table_viewer's
        # "Rollback Journal" tab). Deliberately NOT written as
        # "<tmp_path>-journal" -- the exact filename SQLite's own engine
        # auto-detects and would try to roll back against on open -- and NOT
        # added to the loop above: a rollback journal's pages are the *old*,
        # pre-transaction content, the opposite of a -wal frame's
        # legitimately-current one, so letting any real sqlite3 connection
        # see it would silently auto-recover (mutate the working copy and
        # delete the journal) with the examiner never seeing what changed.
        # See MEMORY feedback_forensic_cleanliness and the "No Side Effects"
        # case in crush/tests/test_forensic.py.
        journal_result: sqlite_journal.JournalParseResult | None = None
        journal_copy_path: str | None = None
        journal_bytes: bytes | None = None
        journal_name: str | None = None
        journal_sibling = find_sibling(node, vfs, "-journal")
        if journal_sibling is not None:
            try:
                journal_bytes = vfs.read(journal_sibling)
                journal_name = journal_sibling.name
            except Exception as exc:
                issue = ParseIssue(
                    "sqlite.companion_read_failed", {"name": journal_sibling.name},
                    detail=str(exc),
                )
                _logger.warning("%s", issue)
                companion_failures.append(issue)
        else:
            fs_journal = Path(node.path + "-journal")
            if fs_journal.is_file():
                try:
                    journal_bytes = fs_journal.read_bytes()
                    journal_name = fs_journal.name
                except OSError as exc:
                    issue = ParseIssue(
                        "sqlite.companion_fs_read_failed", {"name": fs_journal.name},
                        detail=str(exc),
                    )
                    _logger.warning("%s", issue)
                    companion_failures.append(issue)

        recovered_db_path: str | None = None
        journal_skip_reason: ParseIssue | None = None
        if journal_bytes:
            journal_copy_path = tmp_path + "-journal.raw"
            with open(journal_copy_path, "wb") as f:
                f.write(journal_bytes)
            if journal_name:
                companions.append(journal_name)
            journal_result = sqlite_journal.parse_rollback_journal(journal_bytes)

            # Only a plaintext DB whose journal validates completely (every
            # segment's header + every page checksum) is reconstructed into
            # a "current" view -- see the AskUserQuestion-confirmed ground
            # rule: never present a guessed/partial recovery as the default
            # view. SQLCipher pages are ciphertext here, so a byte-level
            # journal overlay can't be applied without the key context;
            # encrypted DBs only get the raw, unmerged Rollback Journal tab.
            #
            # A database is, per its own header (bytes 18/19), in exactly one
            # journaling mode at a time -- WAL (2,2) or rollback-journal
            # (anything else) -- never both at once. A "hot" journal is only
            # something SQLite's own engine would actually roll back if the
            # header currently says rollback-journal mode; if the header
            # says WAL instead, this -journal predates the switch to WAL and
            # is a stale leftover, not "current". A -wal found alongside a
            # mergeable journal is, symmetrically, the stale leftover of the
            # reverse switch -- never a legitimately current layer to merge.
            wal_flag_set = len(raw) >= 20 and raw[18] == 2 and raw[19] == 2
            if journal_result.mergeable and password is None:
                if wal_flag_set:
                    journal_skip_reason = ParseIssue("sqlite.journal_stale_wal_mode")
                else:
                    if Path(tmp_path + "-wal").exists():
                        _logger.debug(
                            "Ignoring -wal companion alongside a valid/hot -journal for "
                            "%s -- not in WAL mode per its own header, so the -wal is "
                            "the stale file here, not the journal",
                            node.path,
                        )
                    page_size_hdr = sqlite_journal.read_db_header_page_size(raw)
                    image = sqlite_journal.reconstruct_post_rollback_image(
                        raw, page_size_hdr, journal_result,
                    )
                    if image is not None:
                        recovered_db_path = tmp_path + ".recovered.db"
                        with open(recovered_db_path, "wb") as f:
                            f.write(image)

        if password is not None:
            # Explicit "Open as -> SQLite DB (Encrypted)…" path only -- the
            # normal open flow never passes a password, since an encrypted
            # file's content (including what would be the plaintext magic
            # header) is ciphertext, indistinguishable from corrupt/other
            # binary data without a key to try. Left outside the broad
            # try/except below so a wrong password raises WrongPasswordError
            # and reaches the caller's retry-prompt loop instead of being
            # swallowed into a "parse failed, showing hex" fallback.
            conn = _connect_sqlcipher(tmp_path, password, raw_key=raw_key, params=cipher_params)
        else:
            conn = None

        try:
            if conn is None:
                open_path = recovered_db_path or tmp_path
                conn = sqlite3.connect(f"file:{open_path}?mode=ro", uri=True)
                conn.row_factory = sqlite3.Row
                conn.text_factory = _lenient_text_factory
            else:
                # sqlcipher3's Cursor type isn't accepted by stdlib
                # sqlite3.Row's constructor -- use the matching Row class
                # from the same dbapi2 module instead.
                from sqlcipher3 import dbapi2 as sqlcipher

                conn.row_factory = sqlcipher.Row
            cursor = conn.cursor()

            tables = [
                r[0]
                for r in cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                ).fetchall()
            ]

            data: dict[str, Any] = {
                "__db_path": tmp_path,
                "__wal_diag": _wal_diag_lines,
            }
            if journal_copy_path:
                data["__journal_path"] = journal_copy_path
            if recovered_db_path:
                # table_viewer._ensure_db() opens this instead of __db_path
                # so the main table grid, SQL bar, and DB Info PRAGMAs all
                # consistently reflect the post-rollback "current" state --
                # the raw/physical tabs (File Structure, Freelist,
                # Freeblocks, Unallocated Space, WAL Frames) keep reading
                # __db_path directly, unaffected, since their whole purpose
                # is examining actual on-disk physical layout.
                data["__recovered_db_path"] = recovered_db_path
            text_parts: list[str] = []
            truncated_tables: list[str] = []

            for table in tables:
                try:
                    # Fetch each row's rowid alongside its columns -- needed
                    # by the table viewer's "Locate in Hex" action to find
                    # the row's exact on-disk bytes later. WITHOUT ROWID
                    # tables and views raise "no such column: rowid"; fall
                    # back to the plain query for those, with rowids=None
                    # (the action simply isn't offered for such rows).
                    rowids: list[int] | None
                    try:
                        cursor.execute(
                            f"SELECT rowid, * FROM [{table}] LIMIT {_ROW_LIMIT + 1}"  # noqa: S608
                        )
                        raw_rows = cursor.fetchall()
                        rowids = [r[0] for r in raw_rows[:_ROW_LIMIT]]
                        rows = [list(r)[1:] for r in raw_rows[:_ROW_LIMIT]]
                        columns = [desc[0] for desc in cursor.description or []][1:]
                    except Exception:
                        cursor.execute(f"SELECT * FROM [{table}] LIMIT {_ROW_LIMIT + 1}")  # noqa: S608
                        raw_rows = cursor.fetchall()
                        rowids = None
                        rows = [list(r) for r in raw_rows[:_ROW_LIMIT]]
                        columns = [desc[0] for desc in cursor.description or []]
                    was_truncated = len(raw_rows) > _ROW_LIMIT
                    data[table] = {
                        "columns": columns,
                        "rows": rows,
                        "truncated": was_truncated,
                        "rowids": rowids,
                    }
                    if was_truncated:
                        truncated_tables.append(table)
                    for row in rows:
                        for val in row:
                            if isinstance(val, str) and val.strip():
                                text_parts.append(val)
                except Exception as exc:
                    _logger.warning("Error reading table %r: %s", table, exc)
                    data[table] = {
                        "columns": ["(error)"],
                        "rows": [[str(exc)]],
                        "truncated": False,
                    }

            pragma_issue: ParseIssue | None = None
            try:
                pragma_rows = cursor.execute("PRAGMA page_size").fetchone()
                page_size = pragma_rows[0] if pragma_rows else "?"
                wal = cursor.execute("PRAGMA journal_mode").fetchone()
                encoding = cursor.execute("PRAGMA encoding").fetchone()
            except Exception as exc:
                page_size, wal, encoding = "?", None, None
                pragma_issue = ParseIssue("sqlite.pragma_read_failed", detail=str(exc))

            meta: dict[str, Any] = {
                "Tables": str(len(tables)),
                "Page size": f"{page_size} B",
                "Journal mode": _journal_mode_fact(wal[0] if wal else None),
                "Encoding": encoding[0] if encoding else "?",
                "File size": f"{node.size:,} B",
            }
            if pragma_issue is not None:
                meta["Header values"] = pragma_issue
            if companions:
                meta["Companion files"] = ", ".join(companions)
            if companion_failures:
                meta["Companion files not loaded"] = companion_failures
            if journal_result is not None:
                n_records = sum(len(s.records) for s in journal_result.segments)
                counts = {"segments": len(journal_result.segments), "records": n_records}
                if journal_result.mergeable and journal_skip_reason:
                    status = ParseIssue(
                        "sqlite.journal_valid_not_merged",
                        {**counts, "reason": journal_skip_reason},
                    )
                elif journal_result.mergeable:
                    status = ParseIssue("sqlite.journal_merged", counts)
                else:
                    status = ParseIssue("sqlite.journal_not_merged", {
                        "reason": journal_result.error
                        or ParseIssue("sqlite.journal_checksum_mismatch"),
                    })
                meta["Rollback journal"] = ParseIssue("sqlite.journal_present", {
                    "size": len(journal_bytes or b""), "status": status,
                })
            if truncated_tables:
                meta["Row limit"] = ParseIssue("sqlite.row_limit", {
                    "limit": _ROW_LIMIT, "tables": ", ".join(truncated_tables),
                })
            if password is not None:
                meta["Encrypted"] = ParseIssue(
                    "sqlite.encrypted_raw_key" if raw_key else "sqlite.encrypted_password"
                )
                if cipher_params is not None:
                    meta["Cipher parameters"] = (
                        f"custom: page_size={cipher_params.page_size}, "
                        f"kdf_iter={cipher_params.kdf_iter}, kdf={cipher_params.kdf_algorithm}, "
                        f"hmac={cipher_params.hmac_algorithm}, "
                        f"plaintext_header_size={cipher_params.plaintext_header_size}"
                    )

            conn.close()
        except Exception as exc:
            _logger.warning("SQLite parse error for %s: %s", node.path, exc)
            return ParseResult(
                viewer_type="hex",
                data=raw,
                metadata={
                    "Parse error": ParseIssue("sqlite.parse_failed", detail=str(exc)),
                    "Format": "SQLite (parse failed)",
                    "File size": f"{node.size:,} B",
                },
            )

        return ParseResult(
            viewer_type="table",
            data=data,
            metadata=meta,
            text_index=" ".join(text_parts[:2000]),
        )
