import argparse
import json
import sys
from pathlib import Path

from ai_sentinel.db.json_repository import JsonRepository
from ai_sentinel.db.repository import PersistenceError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate, back up, or restore the local AI Sentinel JSON store."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate", help="validate or initialize a store")
    validate.add_argument("--data-file", type=Path, required=True)

    backup = commands.add_parser("backup", help="create a validated store backup")
    backup.add_argument("--data-file", type=Path, required=True)
    backup.add_argument("--destination", type=Path, required=True)

    restore = commands.add_parser(
        "restore", help="replace a store using a validated backup"
    )
    restore.add_argument("--data-file", type=Path, required=True)
    restore.add_argument("--source", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    repository = JsonRepository(args.data_file)
    try:
        if args.command == "validate":
            repository.check_ready()
            result = {"status": "valid", "schema_version": 1}
        elif args.command == "backup":
            repository.backup_to(args.destination)
            result = {"status": "backed_up"}
        else:
            repository.restore_from(args.source)
            result = {"status": "restored", "schema_version": 1}
    except PersistenceError as exc:
        print(
            json.dumps({"status": "error", "message": str(exc)}),
            file=sys.stderr,
        )
        return 1

    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
