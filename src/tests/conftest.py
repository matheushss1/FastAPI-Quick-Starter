from typing import Generator

from fastapi.testclient import TestClient
from pytest import fixture
from sqlalchemy import create_engine, sql
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy_utils import create_database, database_exists, drop_database
from src.config.settings import Settings
from src.core.database import SCHEMA, Base, build_database_uri
from src.core.dependencies import get_db, get_settings
from src.main import app


@fixture(name="engine", scope="session")
def engine_fixture() -> Engine:
    return create_engine(build_database_uri(database="test"))


@fixture(scope="session", autouse=True)
def create_test_database(engine: Engine):
    if database_exists(engine.url):
        drop_database(engine.url)

    create_database(engine.url)

    with engine.connect() as connection:
        with connection.begin():
            # NOTICE: we aren't granting roles to objects but I don't think pytest is going to care. # noqa
            seed = 'CREATE EXTENSION IF NOT EXISTS "uuid-ossp" SCHEMA public;'
            seed += f"CREATE SCHEMA {SCHEMA};"
            query = sql.text(seed)
            connection.execute(query)

    Base.metadata.create_all(engine)

    yield  # Run the tests.

    drop_database(engine.url)  # Drop the test database.


@fixture(name="session", scope="session")
def session_fixture(engine: Engine) -> Generator[Session, None, None]:
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


@fixture(name="settings", scope="module")
def settings_fixture() -> Settings:
    settings: Settings = get_settings()
    settings.API_NAME = "Test API"
    return settings


@fixture(name="client", scope="module")
def client_fixture(
    session: Session, settings: Settings
) -> Generator[TestClient, None, None]:
    def get_settings_override() -> Settings:
        return settings

    def get_session_override() -> Session:
        return session

    app.dependency_overrides[get_settings] = get_settings_override
    app.dependency_overrides[get_db] = get_session_override

    with TestClient(app) as client:
        yield client

    app.dependency_overrides.clear()
