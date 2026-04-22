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
    key = tmp_path / "k.bin"
    key.write_bytes(b"x" * 32)
    return _write(
        tmp_path,
        "m.json",
        {
            "jdbc": {
                "url": "jdbc:postgresql://localhost/db",
                "driver_class": "org.postgresql.Driver",
                "classpath": ["/opt/jdbc/postgresql.jar"],
            },
            "encryption": {"key_file": str(key)},
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
            "encryption": {"key_file": str(key)},
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
