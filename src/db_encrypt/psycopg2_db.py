"""psycopg2 implementation of :class:`db_encrypt.db.Database`."""

from __future__ import annotations

import logging
from typing import Any

import psycopg2

from db_encrypt.db import Database, DatabaseCursor
from db_encrypt.manifest import PostgresConfig

log = logging.getLogger(__name__)


def _sql_qmark_to_psycopg2(operation: str) -> str:
    """The runner uses ``?``; psycopg2 expects ``%s`` for bound parameters."""
    return operation.replace("?", "%s")


class _Psycopg2Cursor(DatabaseCursor):
    def __init__(self, raw: Any) -> None:
        self._raw = raw
        self._arraysize = 1

    @property
    def arraysize(self) -> int:
        return self._arraysize

    @arraysize.setter
    def arraysize(self, value: int) -> None:
        self._arraysize = int(value)

    def execute(
        self,
        operation: str,
        parameters: tuple[object, ...] | list[object] | None = None,
    ) -> None:
        op = _sql_qmark_to_psycopg2(operation)
        if parameters is None:
            self._raw.execute(op)
        else:
            self._raw.execute(op, parameters)

    def fetchmany(self, size: int | None = None) -> list[tuple]:
        n = self._arraysize if size is None else int(size)
        rows = self._raw.fetchmany(n)
        return list(rows) if rows else []

    def close(self) -> None:
        self._raw.close()


class Psycopg2Database(Database):
    """psycopg2-backed :class:`Database` for PostgreSQL."""

    def __init__(self, conn: Any) -> None:
        self._conn = conn

    @classmethod
    def connect(cls, cfg: PostgresConfig) -> Psycopg2Database:
        log.info("Connecting with psycopg2")
        conn = psycopg2.connect(cfg.dsn, **(cfg.connect_kwargs or {}))
        return cls(conn)

    def cursor(self) -> DatabaseCursor:
        return _Psycopg2Cursor(self._conn.cursor())

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    def close(self) -> None:
        self._conn.close()

    def set_autocommit(self, enabled: bool) -> None:
        self._conn.autocommit = bool(enabled)

