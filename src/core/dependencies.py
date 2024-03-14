from typing import Generator

from sqlalchemy.orm import Session
from src.config.settings import Settings
from src.core.database import SessionLocal


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_settings() -> Settings:
    return Settings()
