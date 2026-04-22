# db-encrypt

Python CLI that connects to a database and **encrypts or decrypts** configured string columns in place using **AES-256-GCM**. Backends are pluggable via a small abstract DB adapter:

- **JDBC** (JayDeBeApi + JPype; loads JDBC driver JARs)
- **psycopg2** (native PostgreSQL driver)

## Requirements

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) (recommended) or another PEP 517 installer
- For **JDBC**: a **Java runtime** on `PATH` (JPype starts a JVM) and JDBC driver **JAR** files
- For **psycopg2**: network access to PostgreSQL (no JVM/JARs)

## Quick start with uv

Generate your key

```bash
python -c "import secrets, pathlib; pathlib.Path(r'C:\path\aes256.hex').write_text(secrets.token_hex(32), encoding='ascii')"

```

```bash
cd /path/to/python-encryption
uv sync
uv run db-encrypt encrypt --manifest examples/encrypt-manifest.example.yaml
```

Run a dry run (no writes) if the manifest sets `options.dry_run: true` **or** you pass `--dry-run`:

```bash
uv run db-encrypt encrypt --manifest my-manifest.yaml --dry-run
```

Decrypt (inverse operation; skips values that are not valid payloads for this key):

```bash
uv run db-encrypt decrypt --manifest my-manifest.yaml
```

Tests:

```bash
uv run pytest
```

## Encryption format

- 32-byte key (AES-256).
- Each value is stored as **Base64**(`nonce` || `ciphertext` || `tag`) with a random 12-byte nonce per encryption.
- **Encrypt** skips values that already decrypt successfully with the same key (avoids double encryption).
- **Decrypt** leaves cells unchanged if they are not valid ciphertexts for this key.

## Operational notes

- **Backup the database** before running live encrypt/decrypt.
- **Column width**: ciphertext is longer than plaintext. Prefer `TEXT` / `CLOB` or widen `VARCHAR` enough to hold Base64 output.
- **Identifier quoting**: use `options.dialect: ansi` (double quotes) for PostgreSQL and similar; use `mysql` for MySQL-style backticks.
- **Keys**: `key_encoding: raw32` means the key file must be exactly 32 bytes. For `key_env` with `raw32`, the value must be exactly 32 characters interpreted as Latin-1 (one byte per character). Prefer `hex64` in environment variables (64 hex characters).

## JDBC driver hints

| Database   | Typical driver class                     | JAR (example) |
|-----------|-------------------------------------------|---------------|
| PostgreSQL | `org.postgresql.Driver`                | [PostgreSQL JDBC](https://jdbc.postgresql.org/download/) |
| MySQL      | `com.mysql.cj.jdbc.Driver`              | [MySQL Connector/J](https://dev.mysql.com/downloads/connector/j/) |

Set `jdbc.classpath` to the absolute path(s) of the driver JAR(s). Multiple JARs can be listed; they are passed to the JVM classpath.

## Manifest schema (summary)

- **database** (optional): `backend` — `jdbc` (default) or `psycopg2`.
- **jdbc**: `url`, `driver_class`, `classpath`, optional `user` / `password`
- **postgres** (only for `backend: psycopg2`): `dsn`, optional `connect_kwargs`
- **encryption**: `key_file` or `key_env`, optional `key_encoding` (`raw32` | `hex64`)
- **options**: `batch_size`, `dry_run`, `skip_nulls`, `dialect` (`ansi` | `mysql`), optional `connection_props` map
- **tables**: list of `name`, `key_columns`, `encrypt_columns`

See [examples/encrypt-manifest.example.yaml](examples/encrypt-manifest.example.yaml).

## License

Depends on project metadata; cryptography stack is subject to their respective licenses.
