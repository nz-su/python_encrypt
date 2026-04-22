"""Load and validate encrypt/decrypt manifest (YAML or JSON)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from db_encrypt.crypto import CryptoError, load_key

_SUPPORTED_DATABASE_BACKENDS = frozenset({"jdbc", "psycopg2"})


@dataclass
class PostgresConfig:
    """psycopg2 connection configuration.

    Prefer a DSN string (e.g. postgresql://user:pass@host:5432/dbname).
    """

    dsn: str
    connect_kwargs: dict[str, Any] = field(default_factory=dict)


@dataclass
class JdbcConfig:
    url: str
    driver_class: str
    classpath: list[str]
    user: str | None = None
    password: str | None = None


@dataclass
class EncryptionConfig:
    key_env: str | None = None
    key_file: str | None = None
    key_encoding: str = "raw32"


@dataclass
class TableConfig:
    name: str
    key_columns: list[str]
    encrypt_columns: list[str]


@dataclass
class Options:
    batch_size: int = 500
    dry_run: bool = False
    skip_nulls: bool = True
    connection_props: dict[str, str] = field(default_factory=dict)
    dialect: str = "ansi"


@dataclass
class Manifest:
    """Manifest for encrypt/decrypt; ``database_backend`` selects the :class:`db_encrypt.db.Database` impl."""

    encryption: EncryptionConfig
    tables: list[TableConfig]
    jdbc: JdbcConfig | None = None
    postgres: PostgresConfig | None = None
    options: Options = field(default_factory=Options)
    database_backend: str = "jdbc"

    def resolved_key(self) -> bytes:
        return load_key(
            key_env=self.encryption.key_env,
            key_file=self.encryption.key_file,
            key_encoding=self.encryption.key_encoding,
        )


def _normalize_classpath(cp: Any) -> list[str]:
    if cp is None:
        return []
    if isinstance(cp, str):
        parts = [p.strip() for p in cp.replace(":", os.pathsep).split(os.pathsep)]
        return [p for p in parts if p]
    if isinstance(cp, list):
        return [str(p) for p in cp]
    raise ValueError("jdbc.classpath must be a string or list of paths")


def load_manifest(path: str | Path) -> Manifest:
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix in (".yaml", ".yml"):
        data: dict[str, Any] = yaml.safe_load(text)
    elif suffix == ".json":
        data = json.loads(text)
    else:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError:
            data = json.loads(text)

    if not isinstance(data, dict):
        raise ValueError("Manifest root must be a mapping")

    jdbc: JdbcConfig | None = None
    if "jdbc" in data:
        j = data.get("jdbc") or {}
        jdbc = JdbcConfig(
            url=str(j.get("url", "")),
            driver_class=str(j.get("driver_class", "")),
            classpath=_normalize_classpath(j.get("classpath")),
            user=j.get("user"),
            password=j.get("password"),
        )

    p = data.get("postgres")
    postgres: PostgresConfig | None = None
    if p is not None:
        if not isinstance(p, dict):
            raise ValueError("postgres must be a mapping")
        dsn = p.get("dsn")
        if not dsn:
            raise ValueError("postgres.dsn is required when postgres is present")
        connect_kwargs = p.get("connect_kwargs") or {}
        if not isinstance(connect_kwargs, dict):
            raise ValueError("postgres.connect_kwargs must be a mapping")
        postgres = PostgresConfig(
            dsn=str(dsn),
            connect_kwargs={str(k): v for k, v in connect_kwargs.items()},
        )

    e = data.get("encryption") or {}
    encryption = EncryptionConfig(
        key_env=e.get("key_env"),
        key_file=e.get("key_file"),
        key_encoding=str(e.get("key_encoding", "raw32")),
    )
    if not encryption.key_env and not encryption.key_file:
        raise CryptoError("encryption.key_env or encryption.key_file is required")
    if encryption.key_encoding not in ("raw32", "hex64"):
        raise CryptoError("encryption.key_encoding must be raw32 or hex64")

    o = data.get("options") or {}
    options = Options(
        batch_size=int(o.get("batch_size", 500)),
        dry_run=bool(o.get("dry_run", False)),
        skip_nulls=bool(o.get("skip_nulls", True)),
        connection_props=dict(o.get("connection_props") or {}),
        dialect=str(o.get("dialect", "ansi")).lower(),
    )
    if options.dialect not in ("ansi", "mysql"):
        raise ValueError("options.dialect must be ansi or mysql")
    if options.batch_size < 1:
        raise ValueError("options.batch_size must be >= 1")

    db_block = data.get("database") or {}
    database_backend = str(db_block.get("backend", "jdbc")).lower().strip()
    if database_backend not in _SUPPORTED_DATABASE_BACKENDS:
        raise ValueError(
            f"database.backend must be one of {sorted(_SUPPORTED_DATABASE_BACKENDS)!r}, "
            f"got {database_backend!r}"
        )

    tables_raw = data.get("tables")
    if not tables_raw or not isinstance(tables_raw, list):
        raise ValueError("tables must be a non-empty list")
    tables: list[TableConfig] = []
    for i, t in enumerate(tables_raw):
        if not isinstance(t, dict):
            raise ValueError(f"tables[{i}] must be a mapping")
        name = t.get("name")
        keys = t.get("key_columns")
        enc = t.get("encrypt_columns")
        if not name or not keys or not enc:
            raise ValueError(
                f"tables[{i}] needs name, key_columns, and encrypt_columns"
            )
        tables.append(
            TableConfig(
                name=str(name),
                key_columns=[str(c) for c in keys],
                encrypt_columns=[str(c) for c in enc],
            )
        )

    if database_backend == "jdbc":
        if jdbc is None:
            raise ValueError("jdbc block is required for backend=jdbc")
        if not jdbc.url or not jdbc.driver_class:
            raise ValueError("jdbc.url and jdbc.driver_class are required for backend=jdbc")
    elif database_backend == "psycopg2":
        if postgres is None:
            raise ValueError("postgres block is required for backend=psycopg2")

    return Manifest(
        jdbc=jdbc,
        postgres=postgres,
        encryption=encryption,
        tables=tables,
        options=options,
        database_backend=database_backend,
    )
