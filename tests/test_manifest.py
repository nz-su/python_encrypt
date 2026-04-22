"""Manifest loading tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from db_encrypt.crypto import CryptoError
from db_encrypt.manifest import load_manifest


def _write(tmp: Path, name: str, data: dict) -> Path:
    p = tmp / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


@pytest.fixture
def tiny_manifest(tmp_path: Path) -> Path:
    key1 = tmp_path / "k1.bin"
    key2 = tmp_path / "k2.hex"
    key1.write_bytes(b"x" * 32)
    key2.write_text(("ab" * 32), encoding="ascii")
    return _write(
        tmp_path,
        "m.json",
        {
            "jdbc": {
                "url": "jdbc:postgresql://localhost/db",
                "driver_class": "org.postgresql.Driver",
                "classpath": ["/opt/jdbc/postgresql.jar"],
            },
            "encryption": {
                "primary_key_id": "k1",
                "keys": [
                    {"id": "k1", "key_file": str(key1), "key_encoding": "raw32"},
                    {"id": "k2", "key_file": str(key2), "key_encoding": "hex64"},
                ],
            },
            "tables": [
                {
                    "name": "public.users",
                    "key_columns": ["id"],
                    "encrypt_columns": ["email"],
                }
            ],
        },
    )


def test_load_manifest_json(tiny_manifest: Path) -> None:
    m = load_manifest(tiny_manifest)
    assert m.jdbc.url.startswith("jdbc:")
    assert m.tables[0].encrypt_columns == ["email"]
    assert m.encryption.primary_key_id == "k1"
    assert sorted(m.resolved_keyring().keys()) == ["k1", "k2"]


def test_database_backend_default(tiny_manifest: Path) -> None:
    m = load_manifest(tiny_manifest)
    assert m.database_backend == "jdbc"


def test_unknown_database_backend(tmp_path: Path) -> None:
    key = tmp_path / "k.bin"
    key.write_bytes(b"x" * 32)
    p = _write(
        tmp_path,
        "m.json",
        {
            "database": {"backend": "nosuch"},
            "jdbc": {
                "url": "jdbc:x",
                "driver_class": "x.Driver",
                "classpath": ["x.jar"],
            },
            "encryption": {
                "primary_key_id": "k1",
                "keys": [{"id": "k1", "key_file": str(key), "key_encoding": "raw32"}],
            },
            "tables": [
                {"name": "t", "key_columns": ["id"], "encrypt_columns": ["c"]}
            ],
        },
    )
    with pytest.raises(ValueError, match="database.backend"):
        load_manifest(p)


def test_load_manifest_requires_encryption_block(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        "bad.json",
        {
            "jdbc": {
                "url": "jdbc:x",
                "driver_class": "x.Driver",
                "classpath": ["x.jar"],
            },
            "tables": [
                {"name": "t", "key_columns": ["id"], "encrypt_columns": ["c"]}
            ],
        },
    )
    with pytest.raises(CryptoError):
        load_manifest(p)


def test_manifest_rejects_duplicate_key_ids(tmp_path: Path) -> None:
    key = tmp_path / "k.bin"
    key.write_bytes(b"x" * 32)
    p = _write(
        tmp_path,
        "dup.json",
        {
            "jdbc": {"url": "jdbc:x", "driver_class": "x.Driver", "classpath": ["x.jar"]},
            "encryption": {
                "primary_key_id": "k1",
                "keys": [
                    {"id": "k1", "key_file": str(key), "key_encoding": "raw32"},
                    {"id": "k1", "key_file": str(key), "key_encoding": "raw32"},
                ],
            },
            "tables": [{"name": "t", "key_columns": ["id"], "encrypt_columns": ["c"]}],
        },
    )
    with pytest.raises(CryptoError, match="Duplicate encryption key id"):
        load_manifest(p)


def test_manifest_rejects_missing_primary_key(tmp_path: Path) -> None:
    key = tmp_path / "k.bin"
    key.write_bytes(b"x" * 32)
    p = _write(
        tmp_path,
        "primary.json",
        {
            "jdbc": {"url": "jdbc:x", "driver_class": "x.Driver", "classpath": ["x.jar"]},
            "encryption": {
                "primary_key_id": "missing",
                "keys": [{"id": "k1", "key_file": str(key), "key_encoding": "raw32"}],
            },
            "tables": [{"name": "t", "key_columns": ["id"], "encrypt_columns": ["c"]}],
        },
    )
    with pytest.raises(CryptoError, match="primary_key_id"):
        load_manifest(p)
