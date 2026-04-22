"""Batch encrypt/decrypt using a pluggable :class:`db_encrypt.db.Database`."""

from __future__ import annotations

import json
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


def _cell_to_payload(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    return _cell_to_str(value)


def _transform_row(
    mode: Mode,
    row: tuple,
    encrypt_col_indexes: list[int],
    keyring: dict[str, bytes],
    primary_key_id: str,
    primary_key: bytes,
) -> tuple[list[object], bool]:
    """Return a transformed copy of ``row`` and whether any encrypted field changed."""
    new_row = list(row)
    any_change = False

    for idx in encrypt_col_indexes:
        raw = row[idx]
        s = _cell_to_payload(raw)
        if s is None:
            new_row[idx] = None
            continue

        if mode == "encrypt":
            if crypto.try_decrypt_field(s, keyring) is not None:
                new_row[idx] = s
                continue
            new_s = crypto.encrypt_field(s, primary_key_id, primary_key)
            new_row[idx] = new_s
            if new_s != s:
                any_change = True
        else:
            dec = crypto.try_decrypt_field(s, keyring)
            if dec is None:
                new_row[idx] = raw
                continue
            plain = dec.decode("utf-8")
            new_row[idx] = plain
            if plain != s:
                any_change = True

    return new_row, any_change


def _destination_table_name(source_table: str) -> str:
    if "." in source_table:
        schema, table = source_table.rsplit(".", 1)
        return f"{schema}.{table}_encrypted"
    return f"{source_table}_encrypted"


def _decrypt_source_table_name(manifest_table: str) -> str:
    return _destination_table_name(manifest_table)


def _process_table(
    db: Database,
    table: TableConfig,
    manifest: Manifest,
    mode: Mode,
    dry_run: bool,
) -> tuple[int, int]:
    keyring = manifest.resolved_keyring()
    primary_key_id, primary_key = manifest.resolved_primary_key()
    opts = manifest.options
    dialect = opts.dialect
    source_table = table.name if mode == "encrypt" else _decrypt_source_table_name(table.name)
    source_qtable = quote_table(source_table, dialect)
    destination_table = _destination_table_name(table.name)
    destination_qtable = quote_table(destination_table, dialect)
    select_sql = f"SELECT * FROM {source_qtable}"

    processed = 0
    result_count = 0
    batch_size = opts.batch_size

    select_cur = db.cursor()
    select_cur.arraysize = batch_size
    write_cur = db.cursor() if mode == "encrypt" else None
    try:
        select_cur.execute(select_sql)
        source_columns = select_cur.column_names()
        if not source_columns:
            raise ValueError(f"Could not read columns for table {table.name!r}")

        missing = [c for c in table.encrypt_columns if c not in source_columns]
        if missing:
            missing_csv = ", ".join(missing)
            raise ValueError(
                f"Table {table.name!r} is missing encrypt_columns: {missing_csv}"
            )
        missing_keys = [c for c in table.key_columns if c not in source_columns]
        if missing_keys:
            missing_keys_csv = ", ".join(missing_keys)
            raise ValueError(
                f"Table {table.name!r} is missing key_columns: {missing_keys_csv}"
            )

        encrypt_indexes = [source_columns.index(c) for c in table.encrypt_columns]
        insert_sql = ""
        if mode == "encrypt":
            insert_cols = ", ".join(quote_ident(c, dialect) for c in source_columns)
            insert_placeholders = ", ".join("?" for _ in source_columns)
            insert_sql = (
                f"INSERT INTO {destination_qtable} ({insert_cols}) "
                f"VALUES ({insert_placeholders})"
            )

        if mode == "encrypt" and not dry_run:
            assert write_cur is not None
            create_sql = (
                f"CREATE TABLE IF NOT EXISTS {destination_qtable} AS "
                f"SELECT * FROM {source_qtable} WHERE 1=0"
            )
            write_cur.execute(create_sql)
            for col in table.encrypt_columns:
                qcol = quote_ident(col, dialect)
                write_cur.execute(
                    f"ALTER TABLE {destination_qtable} ALTER COLUMN {qcol} TYPE TEXT"
                )
            write_cur.execute(f"TRUNCATE TABLE {destination_qtable}")

        while True:
            rows = select_cur.fetchmany(batch_size)
            if not rows:
                break
            for row in rows:
                processed += 1
                new_row, _changed = _transform_row(
                    mode,
                    row,
                    encrypt_indexes,
                    keyring,
                    primary_key_id,
                    primary_key,
                )
                if mode == "decrypt":
                    obj = {col: val for col, val in zip(source_columns, new_row)}
                    print(json.dumps(obj, ensure_ascii=False))
                    result_count += 1
                    continue

                if dry_run:
                    result_count += 1
                    continue
                assert write_cur is not None
                write_cur.execute(insert_sql, new_row)
                result_count += 1
    finally:
        select_cur.close()
        if write_cur is not None:
            write_cur.close()

    return processed, result_count


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
            destination_table = _destination_table_name(tbl.name)
            decrypt_source_table = _decrypt_source_table_name(tbl.name)
            log.info(
                "Table %s: %s (%s)",
                (
                    f"{tbl.name} -> {destination_table}"
                    if mode == "encrypt"
                    else f"{decrypt_source_table} -> stdout"
                ),
                mode,
                "dry-run" if dry_run else "live",
            )
            processed, n_result = _process_table(db, tbl, manifest, mode, dry_run)
            log.info(
                "  rows scanned: %d, %s: %d",
                processed,
                (
                    "rows emitted"
                    if mode == "decrypt"
                    else ("rows to insert" if dry_run else "rows inserted")
                ),
                n_result,
            )
            if mode == "encrypt" and not dry_run:
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
