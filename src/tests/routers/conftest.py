from typing import Generator

from fastapi.testclient import TestClient
from pytest import fixture
from sqlalchemy.orm import Session

from src.managers.users import UserManager
from src.models.orm.user import User

PASSWORD = "testpass"


@fixture(name="superuser")
def superuser_fixture(session: Session) -> Generator[User, None, None]:
    password_hash = UserManager(session).get_password_hash(PASSWORD)
    user = User(
        name="Test User",
        last_name="From Tests",
        email="testuser@test.com",
        hashed_password=password_hash,
        scopes=["users:self", "users:r", "users:rw", "users:all"],
    )
    session.add(user)
    session.commit()
    yield user
    session.delete(user)
    session.commit()

