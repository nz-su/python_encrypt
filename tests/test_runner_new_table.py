from __future__ import annotations

from pathlib import Path

from db_encrypt.manifest import (
    EncryptionConfig,
    EncryptionKeyConfig,
    Manifest,
    Options,
    TableConfig,
)
from db_encrypt.runner import run_manifest


class _FakeCursor:
    def __init__(
        self,
        *,
        column_names: list[str] | None = None,
        rows: list[tuple] | None = None,
    ) -> None:
        self._column_names = column_names or []
        self._rows = list(rows or [])
        self._pos = 0
        self.arraysize = 1
        self.executed: list[tuple[str, list[object] | None]] = []

    def execute(
        self,
        operation: str,
        parameters: tuple[object, ...] | list[object] | None = None,
    ) -> None:
        params = None if parameters is None else list(parameters)
        self.executed.append((operation, params))

    def fetchmany(self, size: int | None = None) -> list[tuple]:
        n = self.arraysize if size is None else int(size)
        if self._pos >= len(self._rows):
            return []
        chunk = self._rows[self._pos : self._pos + n]
        self._pos += n
        return chunk

    def column_names(self) -> list[str]:
        return list(self._column_names)

    def close(self) -> None:
        return None


class _FakeDb:
    def __init__(self, cursors: list[_FakeCursor]) -> None:
        self._cursors = list(cursors)
        self.commits = 0
        self.rollbacks = 0
        self.autocommit_calls: list[bool] = []

    def cursor(self) -> _FakeCursor:
        if not self._cursors:
            raise AssertionError("No more cursors available")
        return self._cursors.pop(0)

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        return None

    def set_autocommit(self, enabled: bool) -> None:
        self.autocommit_calls.append(enabled)


def _manifest(tmp_path: Path) -> Manifest:
    key_file = tmp_path / "k.bin"
    key_file.write_bytes(b"x" * 32)
    return Manifest(
        encryption=EncryptionConfig(
            primary_key_id="k1",
            keys=[
                EncryptionKeyConfig(
                    id="k1",
                    key_file=str(key_file),
                    key_encoding="raw32",
                )
            ],
        ),
        tables=[
            TableConfig(
                name="northwind.employees",
                key_columns=["employee_id"],
                encrypt_columns=["address", "city", "region", "postal_code", "phone"],
            )
        ],
        options=Options(batch_size=50, dialect="ansi"),
        database_backend="psycopg2",
    )


def test_run_manifest_writes_into_destination_table(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        "db_encrypt.runner.crypto.try_decrypt_field", lambda s, keyring: None
    )
    monkeypatch.setattr(
        "db_encrypt.runner.crypto.encrypt_field",
        lambda s, key_id, key: f"{key_id}:iv:{s}",
    )

    select_cur = _FakeCursor(
        column_names=[
            "employee_id",
            "address",
            "city",
            "region",
            "postal_code",
            "phone",
            "title",
        ],
        rows=[
            (1, "A St", "Seattle", "WA", "98101", "555", "Manager"),
        ],
    )
    write_cur = _FakeCursor()
    db = _FakeDb([select_cur, write_cur])

    run_manifest(_manifest(tmp_path), "encrypt", dry_run=False, database=db)

    sql_ops = [op for op, _ in write_cur.executed]
    assert sql_ops[0].startswith(
        'CREATE TABLE IF NOT EXISTS "northwind"."employees_encrypted" AS SELECT *'
    )
    assert (
        sql_ops[1]
        == 'ALTER TABLE "northwind"."employees_encrypted" ALTER COLUMN "address" TYPE TEXT'
    )
    assert (
        sql_ops[2]
        == 'ALTER TABLE "northwind"."employees_encrypted" ALTER COLUMN "city" TYPE TEXT'
    )
    assert (
        sql_ops[3]
        == 'ALTER TABLE "northwind"."employees_encrypted" ALTER COLUMN "region" TYPE TEXT'
    )
    assert (
        sql_ops[4]
        == 'ALTER TABLE "northwind"."employees_encrypted" ALTER COLUMN "postal_code" TYPE TEXT'
    )
    assert (
        sql_ops[5]
        == 'ALTER TABLE "northwind"."employees_encrypted" ALTER COLUMN "phone" TYPE TEXT'
    )
    assert sql_ops[6] == 'TRUNCATE TABLE "northwind"."employees_encrypted"'
    assert sql_ops[7].startswith('INSERT INTO "northwind"."employees_encrypted"')

    _, insert_params = write_cur.executed[7]
    assert insert_params == [
        1,
        "k1:iv:A St",
        "k1:iv:Seattle",
        "k1:iv:WA",
        "k1:iv:98101",
        "k1:iv:555",
        "Manager",
    ]
    assert db.commits == 1
    assert db.autocommit_calls == [False]


def test_run_manifest_dry_run_avoids_write_sql(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        "db_encrypt.runner.crypto.try_decrypt_field", lambda s, keyring: None
    )
    monkeypatch.setattr(
        "db_encrypt.runner.crypto.encrypt_field",
        lambda s, key_id, key: f"{key_id}:iv:{s}",
    )

    select_cur = _FakeCursor(
        column_names=[
            "employee_id",
            "address",
            "city",
            "region",
            "postal_code",
            "phone",
        ],
        rows=[(1, "A St", "Seattle", "WA", "98101", "555")],
    )
    write_cur = _FakeCursor()
    db = _FakeDb([select_cur, write_cur])

    run_manifest(_manifest(tmp_path), "encrypt", dry_run=True, database=db)

    assert write_cur.executed == []
    assert db.commits == 0


def test_run_manifest_decrypt_reads_suffix_and_prints_jsonl(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setattr(
        "db_encrypt.runner.crypto.try_decrypt_field",
        lambda s, keyring: b"plain" if isinstance(s, str) and s.startswith("k1:") else None,
    )

    select_cur = _FakeCursor(
        column_names=[
            "employee_id",
            "address",
            "city",
            "region",
            "postal_code",
            "phone",
        ],
        rows=[(1, "k1:abcd:beef", "k1:abcd:beef", None, "k1:abcd:beef", "raw-phone")],
    )
    write_cur = _FakeCursor()
    db = _FakeDb([select_cur, write_cur])

    run_manifest(_manifest(tmp_path), "decrypt", dry_run=False, database=db)

    assert select_cur.executed[0][0] == 'SELECT * FROM "northwind"."employees_encrypted"'
    assert write_cur.executed == []
    assert db.commits == 0

    out = capsys.readouterr().out.strip()
    assert out == (
        '{"employee_id": 1, "address": "plain", "city": "plain", '
        '"region": null, "postal_code": "plain", "phone": "raw-phone"}'
    )
