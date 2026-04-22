"""CLI: db-encrypt encrypt|decrypt."""

from __future__ import annotations

import argparse
import logging
import sys

from db_encrypt.crypto import CryptoError
from db_encrypt.manifest import load_manifest
from db_encrypt.runner import run_manifest


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="db-encrypt",
        description="Encrypt or decrypt database columns via JDBC (AES-256-GCM).",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Log SQL driver details at DEBUG level.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encrypt", help="Encrypt configured columns in place.")
    enc.add_argument(
        "--manifest",
        "-m",
        required=True,
        help="Path to YAML or JSON manifest.",
    )
    enc.add_argument(
        "--dry-run",
        action="store_true",
        help="Scan rows and count updates without writing (also if set in manifest).",
    )

    dec = sub.add_parser("decrypt", help="Decrypt configured columns in place.")
    dec.add_argument("--manifest", "-m", required=True)
    dec.add_argument("--dry-run", action="store_true")

    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )
    try:
        manifest = load_manifest(args.manifest)
    except (OSError, ValueError, CryptoError) as e:
        logging.error("%s", e)
        return 1

    dry_run = bool(manifest.options.dry_run or args.dry_run)

    try:
        if args.command == "encrypt":
            run_manifest(manifest, "encrypt", dry_run=dry_run)
        elif args.command == "decrypt":
            run_manifest(manifest, "decrypt", dry_run=dry_run)
        else:
            parser.error("unknown command")
            return 2
    except Exception as e:
        logging.error("%s", e, exc_info=args.verbose)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
