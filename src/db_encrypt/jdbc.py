"""JDBC implementation of :class:`Database` (JayDeBeApi)."""

from __future__ import annotations

import logging
from typing import Any

import jaydebeapi

from db_encrypt.db import Database, DatabaseCursor
from db_encrypt.manifest import JdbcConfig, Options

log = logging.getLogger(__name__)


def driver_args(jdbc: JdbcConfig, options: Options) -> list[Any]:
    props: dict[str, str] = {}
    if jdbc.user is not None:
        props["user"] = str(jdbc.user)
    if jdbc.password is not None:
        props["password"] = str(jdbc.password)
    props.update({k: str(v) for k, v in options.connection_props.items()})
    if not props:
        return []
    return [props]


class _JayDeBeApiCursor(DatabaseCursor):
    def __init__(self, raw: Any) -> None:
        self._raw = raw

    @property
    def arraysize(self) -> int:
        return int(self._raw.arraysize)

    @arraysize.setter
    def arraysize(self, value: int) -> None:
        self._raw.arraysize = value

    def execute(
        self,
        operation: str,
        parameters: tuple[object, ...] | list[object] | None = None,
    ) -> None:
        if parameters is None:
            self._raw.execute(operation)
        else:
            self._raw.execute(operation, parameters)

    def fetchmany(self, size: int | None = None) -> list[tuple]:
        rows = self._raw.fetchmany(size)
        return list(rows) if rows else []

    def close(self) -> None:
        self._raw.close()


class JdbcDatabase(Database):
    """JayDeBeApi / JDBC-backed :class:`Database`."""

    def __init__(self, conn: Any) -> None:
        self._conn = conn

    @classmethod
    def connect(cls, jdbc: JdbcConfig, options: Options) -> JdbcDatabase:
        jars = jdbc.classpath
        if not jars:
            raise ValueError("jdbc.classpath must list at least one JAR path")
        args = driver_args(jdbc, options)
        log.info(
            "Connecting with driver %s (classpath: %d jar(s))",
            jdbc.driver_class,
            len(jars),
        )
        raw = jaydebeapi.connect(
            jdbc.driver_class,
            jdbc.url,
            args if args else None,
            jars,
        )
        return cls(raw)

    def cursor(self) -> DatabaseCursor:
        return _JayDeBeApiCursor(self._conn.cursor())

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    def close(self) -> None:
        self._conn.close()

    def set_autocommit(self, enabled: bool) -> None:
        try:
            self._conn.jconn.setAutoCommit(enabled)
        except Exception:
            log.debug("setAutoCommit(%s) not applied", enabled, exc_info=True)
