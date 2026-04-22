"""Unit tests for AES-256-CBC field crypto (no JVM)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from db_encrypt import crypto


def test_encrypt_decrypt_round_trip() -> None:
    key = {"v1": os.urandom(32)}
    plain = "hello 世界"
    ct = crypto.encrypt_field(plain, "v1", key["v1"])
    assert ct != plain
    out = crypto.decrypt_field(ct, key)
    assert out == plain
    assert ct.startswith("v1:")


def test_wrong_key_fails() -> None:
    key = os.urandom(32)
    ct = crypto.encrypt_field("x", "v1", key)
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt_field(ct, {"v1": os.urandom(32)})


def test_load_key_raw32_from_file(tmp_path: Path) -> None:
    key = os.urandom(32)
    p = tmp_path / "k.bin"
    p.write_bytes(key)
    loaded = crypto.load_key(key_env=None, key_file=str(p), key_encoding="raw32")
    assert loaded == key


def test_load_key_hex64_from_file(tmp_path: Path) -> None:
    key = os.urandom(32)
    p = tmp_path / "k.hex"
    p.write_text(key.hex(), encoding="ascii")
    loaded = crypto.load_key(key_env=None, key_file=str(p), key_encoding="hex64")
    assert loaded == key


def test_load_key_raw32_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    key = bytes((i % 255) + 1 for i in range(32))  # no NUL — setenv rejects \\0
    monkeypatch.setenv("K", key.decode("latin-1"))
    loaded = crypto.load_key(key_env="K", key_file=None, key_encoding="raw32")
    assert loaded == key


def test_load_key_wrong_length(tmp_path: Path) -> None:
    p = tmp_path / "k.bin"
    p.write_bytes(b"short")
    with pytest.raises(crypto.CryptoError, match="32-byte"):
        crypto.load_key(key_env=None, key_file=str(p), key_encoding="raw32")


def test_try_decrypt_garbage() -> None:
    assert crypto.try_decrypt_field("not-valid-token", {"v1": os.urandom(32)}) is None


def test_try_decrypt_unknown_key_id() -> None:
    key = os.urandom(32)
    ct = crypto.encrypt_field("abc", "v1", key)
    assert crypto.try_decrypt_field(ct, {"v2": key}) is None


def test_try_decrypt_bad_hex_parts() -> None:
    assert crypto.try_decrypt_field("v1:nothex:abcd", {"v1": os.urandom(32)}) is None
    assert crypto.try_decrypt_field("v1:0011:zz", {"v1": os.urandom(32)}) is None
