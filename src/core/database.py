import os

from sqlalchemy import create_engine
from sqlalchemy.orm import registry, scoped_session, sessionmaker

SCHEMA = "api"


def build_database_uri(
    username: str = None,
    password: str = None,
    host: str = None,
    database: str = None,
    port: int = None,
) -> str:
    return "postgresql://%s:%s@%s:%s/%s" % (
        username or os.getenv("DB_USERNAME", "root"),
        password or os.getenv("DB_PASSWORD", "test"),
        host or os.getenv("DB_HOST", "localhost"),
        port or os.getenv("DB_PORT", 5432),
        database or os.getenv("DB_DATABASE", "eqrx-local"),
    )


engine = create_engine(build_database_uri(), pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

mapper_registry = registry()
Base = mapper_registry.generate_base()
Base.query = scoped_session(SessionLocal).query_property()
