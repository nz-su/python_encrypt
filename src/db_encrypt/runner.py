"""Batch encrypt/decrypt using a pluggable :class:`db_encrypt.db.Database`."""

from __future__ import annotations

import logging
from typing import Literal

from db_encrypt import crypto
from db_encrypt.db import Database, connect_database
from db_encrypt.manifest import Manifest, TableConfig
from db_encrypt.sqlutil import quote_ident, quote_table

log = logging.getLogger(__name__)

Mode = Literal["encrypt", "decrypt"]


def _cell_to_str(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _transform_row(
    mode: Mode,
    row: tuple,
    n_keys: int,
    encrypt_cols: list[str],
    key: bytes,
) -> tuple[list[object], bool]:
    """Build new encrypt-column values; True if UPDATE should run."""
    enc_vals = list(row[n_keys:])
    new_enc: list[object] = []
    any_change = False

    for i, col in enumerate(encrypt_cols):
        raw = enc_vals[i]
        s = _cell_to_str(raw)
        if s is None:
            new_enc.append(None)
            continue

        if mode == "encrypt":
            if crypto.try_decrypt_field(s, key) is not None:
                new_enc.append(s)
                continue
            new_s = crypto.encrypt_field(s, key)
            new_enc.append(new_s)
            if new_s != s:
                any_change = True
        else:
            dec = crypto.try_decrypt_field(s, key)
            if dec is None:
                new_enc.append(raw)
                continue
            plain = dec.decode("utf-8")
            new_enc.append(plain)
            if plain != s:
                any_change = True

    return new_enc, any_change


def _process_table(
    db: Database,
    table: TableConfig,
    manifest: Manifest,
    mode: Mode,
    dry_run: bool,
) -> tuple[int, int]:
    key = manifest.resolved_key()
    opts = manifest.options
    dialect = opts.dialect
    n_keys = len(table.key_columns)
    qtable = quote_table(table.name, dialect)
    cols = [quote_ident(c, dialect) for c in table.key_columns + table.encrypt_columns]
    select_sql = f"SELECT {', '.join(cols)} FROM {qtable}"

    set_parts = [f"{quote_ident(c, dialect)} = ?" for c in table.encrypt_columns]
    where_parts = [f"{quote_ident(c, dialect)} = ?" for c in table.key_columns]
    update_sql = (
        f"UPDATE {qtable} SET {', '.join(set_parts)} WHERE {' AND '.join(where_parts)}"
    )

    processed = 0
    updated = 0
    batch_size = opts.batch_size

    select_cur = db.cursor()
    select_cur.arraysize = batch_size
    update_cur = db.cursor()
    try:
        select_cur.execute(select_sql)
        while True:
            rows = select_cur.fetchmany(batch_size)
            if not rows:
                break
            for row in rows:
                processed += 1
                new_enc, should_update = _transform_row(
                    mode,
                    row,
                    n_keys,
                    table.encrypt_columns,
                    key,
                )
                if not should_update:
                    continue
                if dry_run:
                    updated += 1
                    continue
                params = list(new_enc) + list(row[:n_keys])
                update_cur.execute(update_sql, params)
                updated += 1
    finally:
        select_cur.close()
        update_cur.close()

    return processed, updated


def run_manifest(
    manifest: Manifest,
    mode: Mode,
    *,
    dry_run: bool,
    database: Database | None = None,
) -> None:
    """Run encrypt/decrypt. If ``database`` is None, ``connect_database(manifest)`` is used."""
    db = database if database is not None else connect_database(manifest)
    own_connection = database is None
    try:
        db.set_autocommit(False)
        for tbl in manifest.tables:
            log.info(
                "Table %s: %s (%s)",
                tbl.name,
                mode,
                "dry-run" if dry_run else "live",
            )
            processed, n_updated = _process_table(db, tbl, manifest, mode, dry_run)
            log.info(
                "  rows scanned: %d, %s: %d",
                processed,
                "rows to update" if dry_run else "rows updated",
                n_updated,
            )
            if not dry_run:
                db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        raise
    finally:
        if own_connection:
            db.close()
