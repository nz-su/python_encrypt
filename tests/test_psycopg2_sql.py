"""psycopg2 adapter SQL placeholder translation (no live DB)."""

from db_encrypt.psycopg2_db import _sql_qmark_to_psycopg2


def test_qmark_to_percent_s() -> None:
    assert (
        _sql_qmark_to_psycopg2("UPDATE t SET a = ?, b = ? WHERE id = ?")
        == "UPDATE t SET a = %s, b = %s WHERE id = %s"
    )
