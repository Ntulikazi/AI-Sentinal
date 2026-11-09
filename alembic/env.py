import os
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from dotenv import load_dotenv
from sqlalchemy import engine_from_config, pool

from ai_sentinel.db.models import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)
project_root = Path(__file__).resolve().parent.parent
load_dotenv(project_root / ".env", override=False)
database_url = os.getenv("DATABASE_URL")
if database_url:
    database_url = database_url.replace("postgresql://", "postgresql+psycopg://", 1)
    scheme_separator = "://"
    if scheme_separator in database_url:
        scheme, remainder = database_url.split(scheme_separator, 1)
        if "@" in remainder:
            credentials, separator, location = remainder.rpartition("@")
            if separator:
                credentials = credentials.replace("@", "%40")
                remainder = f"{credentials}@{location}"
        database_url = f"{scheme}{scheme_separator}{remainder}"
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
elif config.get_main_option("sqlalchemy.url", "").endswith("USER@localhost:5432/ai_sentinel"):
    raise RuntimeError(
        "DATABASE_URL is not configured. Set it in the environment or local .env file."
    )
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
