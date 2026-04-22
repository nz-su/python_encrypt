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
class EncryptionKeyConfig:
    id: str
    key_env: str | None = None
    key_file: str | None = None
    key_encoding: str = "raw32"


@dataclass
class EncryptionConfig:
    primary_key_id: str
    keys: list[EncryptionKeyConfig]


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

    def resolved_keyring(self) -> dict[str, bytes]:
        out: dict[str, bytes] = {}
        for k in self.encryption.keys:
            out[k.id] = load_key(
                key_env=k.key_env,
                key_file=k.key_file,
                key_encoding=k.key_encoding,
            )
        return out

    def resolved_primary_key(self) -> tuple[str, bytes]:
        keyring = self.resolved_keyring()
        key_id = self.encryption.primary_key_id
        if key_id not in keyring:
            raise CryptoError(f"primary_key_id {key_id!r} not found in keys")
        return key_id, keyring[key_id]


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
    if not isinstance(e, dict):
        raise CryptoError("encryption must be a mapping")
    primary_key_id = str(e.get("primary_key_id", "")).strip()
    if not primary_key_id:
        raise CryptoError("encryption.primary_key_id is required")
    keys_raw = e.get("keys")
    if not isinstance(keys_raw, list) or not keys_raw:
        raise CryptoError("encryption.keys must be a non-empty list")
    key_entries: list[EncryptionKeyConfig] = []
    seen_ids: set[str] = set()
    for i, item in enumerate(keys_raw):
        if not isinstance(item, dict):
            raise CryptoError(f"encryption.keys[{i}] must be a mapping")
        key_id = str(item.get("id", "")).strip()
        if not key_id:
            raise CryptoError(f"encryption.keys[{i}].id is required")
        if key_id in seen_ids:
            raise CryptoError(f"Duplicate encryption key id: {key_id!r}")
        seen_ids.add(key_id)
        key_env = item.get("key_env")
        key_file = item.get("key_file")
        if bool(key_env) == bool(key_file):
            raise CryptoError(
                f"encryption.keys[{i}] must define exactly one of key_env or key_file"
            )
        key_encoding = str(item.get("key_encoding", "raw32"))
        if key_encoding not in ("raw32", "hex64"):
            raise CryptoError(
                f"encryption.keys[{i}].key_encoding must be raw32 or hex64"
            )
        key_entries.append(
            EncryptionKeyConfig(
                id=key_id,
                key_env=str(key_env) if key_env is not None else None,
                key_file=str(key_file) if key_file is not None else None,
                key_encoding=key_encoding,
            )
        )
    if primary_key_id not in seen_ids:
        raise CryptoError("encryption.primary_key_id must match one configured key id")
    encryption = EncryptionConfig(primary_key_id=primary_key_id, keys=key_entries)

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
