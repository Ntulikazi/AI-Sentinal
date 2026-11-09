import sys

from alembic.config import main as alembic_main


def main() -> None:
    alembic_main(argv=sys.argv[1:])
