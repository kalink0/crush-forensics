"""SQLite parser — reads tables, columns, and row data."""
from __future__ import annotations

import logging
import sqlite3
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from crush.core.vfs import VFS, VFSNode, find_sibling
from crush.parsers.base import AbstractParser, ParseResult

_SQLITE_MAGIC = b"SQLite format 3\x00"
_ROW_LIMIT = 10_000
_logger = logging.getLogger(__name__)

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
                raise WrongPasswordError(f"Not a valid hex key: {exc}") from exc
            conn.execute(f"PRAGMA key = \"x'{hex_key}'\"")
        else:
            escaped = password.replace("'", "''")
            conn.execute(f"PRAGMA key = '{escaped}'")

    def _try_open(compat: int | None, custom: SQLCipherParams | None) -> Any:
        conn = sqlcipher.connect(f"file:{tmp_path}?mode=ro", uri=True)
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
            raise WrongPasswordError(
                f"Incorrect key, or the given parameters don't match this file ({exc})"
            ) from exc

    last_exc: Exception | None = None
    for compat in _CIPHER_COMPATIBILITY_PRESETS:
        try:
            return _try_open(compat, None)
        except sqlcipher.DatabaseError as exc:
            last_exc = exc
            continue
    raise WrongPasswordError(
        f"Incorrect password, or an unsupported SQLCipher version/parameters ({last_exc})"
    )


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

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp.write(raw)
            tmp_path = tmp.name

        # Copy WAL and SHM companion files if present
        companions: list[str] = []
        _wal_diag_lines: list[str] = []
        for suffix in ("-wal", "-shm"):
            sibling = find_sibling(node, vfs, suffix)
            if sibling is not None:
                try:
                    sib_bytes = vfs.read(sibling)
                    if not sib_bytes:
                        msg = (
                            f"VFS found {sibling.name} (path={sibling.path!r}, "
                            f"vfs_size={sibling.size} B) but read returned 0 bytes — "
                            f"ZIP entry may be empty in the archive"
                        )
                        _logger.warning(msg)
                        if suffix == "-wal":
                            _wal_diag_lines.append(msg)
                    else:
                        sib_path = tmp_path + suffix
                        with open(sib_path, "wb") as f:
                            f.write(sib_bytes)
                        companions.append(sibling.name)
                        _logger.debug("Copied companion file: %s (%d B)", sibling.name, len(sib_bytes))
                        if suffix == "-wal":
                            _wal_diag_lines.append(
                                f"Copied {sibling.name} ({len(sib_bytes):,} B) from {sibling.path!r}"
                            )
                except Exception as exc:
                    msg = f"VFS found {sibling.name} but read raised: {exc}"
                    _logger.warning(msg)
                    if suffix == "-wal":
                        _wal_diag_lines.append(msg)
            else:
                if suffix == "-wal":
                    _wal_diag_lines.append(
                        f"find_sibling returned None for db_node.path={node.path!r}"
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
                            _wal_diag_lines.append(
                                f"Loaded filesystem companion {fs_companion.name} ({len(fs_bytes):,} B)"
                            )
                    except Exception as exc:
                        _logger.debug("Could not load filesystem companion %s: %s", fs_companion.name, exc)

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
                conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
                conn.row_factory = sqlite3.Row
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
                "__wal_diag": " | ".join(_wal_diag_lines) if _wal_diag_lines else "",
            }
            text_parts: list[str] = []
            truncated_tables: list[str] = []

            for table in tables:
                try:
                    cursor.execute(f"SELECT * FROM [{table}] LIMIT {_ROW_LIMIT + 1}")  # noqa: S608
                    raw_rows = cursor.fetchall()
                    was_truncated = len(raw_rows) > _ROW_LIMIT
                    rows = [list(r) for r in raw_rows[:_ROW_LIMIT]]
                    columns = [desc[0] for desc in cursor.description or []]
                    data[table] = {
                        "columns": columns,
                        "rows": rows,
                        "truncated": was_truncated,
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

            try:
                pragma_rows = cursor.execute("PRAGMA page_size").fetchone()
                page_size = pragma_rows[0] if pragma_rows else "?"
                wal = cursor.execute("PRAGMA journal_mode").fetchone()
                encoding = cursor.execute("PRAGMA encoding").fetchone()
            except Exception:
                page_size, wal, encoding = "?", None, None

            meta: dict[str, Any] = {
                "Tables": str(len(tables)),
                "Page size": f"{page_size} B",
                "Journal mode": wal[0] if wal else "?",
                "Encoding": encoding[0] if encoding else "?",
                "File size": f"{node.size:,} B",
            }
            if companions:
                meta["Companion files"] = ", ".join(companions)
            if truncated_tables:
                meta["Row limit"] = f"First {_ROW_LIMIT:,} rows shown for: {', '.join(truncated_tables)}"
            if password is not None:
                key_kind = "raw key" if raw_key else "password"
                meta["Encrypted"] = f"Yes (SQLCipher, {key_kind} supplied)"
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
                    "Parse error": str(exc),
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
