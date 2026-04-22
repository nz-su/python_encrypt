"""SQL identifier quoting."""

from __future__ import annotations


def quote_ident(name: str, dialect: str) -> str:
    if dialect == "mysql":
        return "`" + name.replace("`", "``") + "`"
    return '"' + name.replace('"', '""') + '"'


def quote_table(name: str, dialect: str) -> str:
    parts = name.split(".")
    return ".".join(quote_ident(p, dialect) for p in parts)
