"""Abstract database API for encrypt/decrypt runners (pluggable backends).

This module defines the *minimum* surface the :mod:`db_encrypt.runner` needs so
different drivers (JDBC via JayDeBeApi, psycopg2, etc.) can be swapped without
changing encryption logic.

**Contract (what implementors must honor)**

- **Cursors**: The runner opens *two* cursors on the same connection: one for
  a long-lived ``SELECT`` (batched ``fetchmany``), one for repeated ``UPDATE``
  statements.
  Implementations must allow that pattern (JayDeBeApi requires distinct
  cursors; psycopg2 does too if you avoid using a named server-side cursor for
  the select without care).
- **Parameters**: The runner uses *positional* ``?`` placeholders in SQL.
  Each backend must ensure the underlying driver accepts that SQL (e.g. JDBC
  ``PreparedStatement`` often does), or **rewrite** placeholders to the driver’s
  native form before executing.
- **Rows**: ``fetchmany`` returns a list of tuples (possibly empty when exhausted).
- **Transactions**: The runner calls ``set_autocommit(False)``, performs work,
  then ``commit()`` or ``rollback()`` on failure. Implementations must expose
  real transaction semantics when autocommit is off.

See also :func:`connect_database` for how a manifest selects a concrete backend.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from db_encrypt.manifest import Manifest


class DatabaseCursor(ABC):
    """A thin, DB-API-shaped cursor used only for batch read/write in the runner.

    This is intentionally smaller than PEP 249: no ``fetchone``/``fetchall``
    required by the runner today—only ``fetchmany`` for bounded memory use.
    """

    @property
    @abstractmethod
    def arraysize(self) -> int:
        """Hint for ``fetchmany`` when *size* is omitted (DB-API style)."""

    @arraysize.setter
    @abstractmethod
    def arraysize(self, value: int) -> None:
        """Set the default batch size for ``fetchmany``."""

    @abstractmethod
    def execute(
        self,
        operation: str,
        parameters: tuple[object, ...] | list[object] | None = None,
    ) -> None:
        """Run ``operation``, optionally with positional bound parameters.

        When ``parameters`` is ``None``, run a parameterless statement.
        The runner emits SQL with ``?`` placeholders; if the driver does not
        accept ``?`` (common for some native drivers), the adapter must rewrite
        the statement or use an API that binds by position equivalently.
        """

    @abstractmethod
    def fetchmany(self, size: int | None = None) -> list[tuple]:
        """Return up to *size* rows; if *size* is ``None``, use ``arraysize``.

        Must return an empty list when no more rows (not ``None``).
        Each row is a tuple of column values (driver-native types are OK).
        """

    @abstractmethod
    def close(self) -> None:
        """Release server/client resources for this cursor."""


class Database(ABC):
    """Connection-like object: cursors, transaction boundaries, close.

    **Lifecycle**: Typically constructed via a backend ``connect`` classmethod,
    used under ``run_manifest``, then closed in a ``finally`` block.

    **Threading**: Not required to be thread-safe; the runner uses one
    connection from a single thread.
    """

    @abstractmethod
    def cursor(self) -> DatabaseCursor:
        """Return a new cursor tied to this connection (independent of others)."""

    @abstractmethod
    def commit(self) -> None:
        """Commit the current transaction."""

    @abstractmethod
    def rollback(self) -> None:
        """Roll back the current transaction (e.g. after an error)."""

    @abstractmethod
    def close(self) -> None:
        """Close the connection and release underlying resources."""

    @abstractmethod
    def set_autocommit(self, enabled: bool) -> None:
        """Enable or disable autocommit.

        The runner disables autocommit so that multiple ``UPDATE`` statements and
        an optional final ``commit`` are atomic per its transaction policy.
        Implementations should map this to the driver’s real flag (e.g.
        ``Connection.autocommit`` or ``setAutoCommit`` on the JDBC bridge).
        """


def connect_database(manifest: Manifest) -> Database:
    """Build a concrete :class:`Database` from ``manifest.database_backend``.

    Uses lazy imports per concrete backend to avoid circular dependencies and
    to skip loading JDBC/psycopg2 stacks unless that backend is selected.

    Raises:
        ValueError: If the backend is unknown or required manifest sections are
            missing (detailed message from each branch).

    """
    b = manifest.database_backend
    if b == "jdbc":
        from db_encrypt.jdbc import JdbcDatabase

        if manifest.jdbc is None:
            raise ValueError("jdbc block is required for backend=jdbc")
        return JdbcDatabase.connect(manifest.jdbc, manifest.options)
    if b == "psycopg2":
        from db_encrypt.psycopg2_db import Psycopg2Database

        if manifest.postgres is None:
            raise ValueError("postgres block is required for backend=psycopg2")
        return Psycopg2Database.connect(manifest.postgres)
    raise ValueError(f"Unknown database backend: {b!r}")
