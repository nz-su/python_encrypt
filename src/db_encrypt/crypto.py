"""AES-256-GCM helpers: wire format is base64(nonce || ciphertext+tag)."""

from __future__ import annotations

import base64
import binascii
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12
KEY_LEN_BYTES = 32


class CryptoError(Exception):
    pass


def load_key(*, key_env: str | None, key_file: str | None, key_encoding: str) -> bytes:
    raw: bytes | None = None
    if key_file:
        raw = Path(key_file).read_bytes()
        if key_encoding == "hex64":
            raw = raw.decode("ascii").strip()
            raw = binascii.unhexlify(raw)
        elif key_encoding == "raw32":
            pass
        else:
            raise CryptoError(f"Unknown key_encoding: {key_encoding}")
    elif key_env:
        import os as _os

        val = _os.environ.get(key_env)
        if val is None:
            raise CryptoError(f"Environment variable {key_env!r} is not set")
        if key_encoding == "hex64":
            raw = binascii.unhexlify(val.strip())
        elif key_encoding == "raw32":
            raw = val.encode("latin-1")
        else:
            raise CryptoError(f"Unknown key_encoding: {key_encoding}")
    else:
        raise CryptoError("Specify encryption.key_env or encryption.key_file")

    if len(raw) != KEY_LEN_BYTES:
        raise CryptoError(
            f"AES-256 requires a {KEY_LEN_BYTES}-byte key; got {len(raw)} bytes"
        )
    return raw


def encrypt_field(plaintext: str, key: bytes) -> str:
    data = plaintext.encode("utf-8")
    aes = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)
    ct = aes.encrypt(nonce, data, associated_data=None)
    return base64.b64encode(nonce + ct).decode("ascii")


def try_decrypt_field(ciphertext: str, key: bytes) -> bytes | None:
    try:
        raw = base64.b64decode(ciphertext, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) < NONCE_LEN + 16:
        return None
    nonce = raw[:NONCE_LEN]
    ct = raw[NONCE_LEN:]
    aes = AESGCM(key)
    try:
        return aes.decrypt(nonce, ct, associated_data=None)
    except Exception:
        return None


def decrypt_field(ciphertext: str, key: bytes) -> str:
    plain = try_decrypt_field(ciphertext, key)
    if plain is None:
        raise CryptoError("Invalid ciphertext or authentication failed")
    return plain.decode("utf-8")
