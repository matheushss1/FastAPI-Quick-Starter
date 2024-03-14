from datetime import datetime, timedelta
from typing import Generator, List

from fastapi.testclient import TestClient
from pytest import fixture
from sqlalchemy import and_
from sqlalchemy.orm import Session
from src.core.utils import generate_role_description, generate_role_name
from src.managers.users import UserManager
from src.models.orm.user import MODES, MODULES, Role, User, UserInvited

PASSWORD = "testpass"


@fixture(name="superuser")
def superuser_fixture(session: Session) -> Generator[User, None, None]:
    password_hash = UserManager(session).get_password_hash(PASSWORD)
    user = User(
        name="Test User",
        email="testuser@test.com",
        hashed_password=password_hash,
        role="admin",
    )
    session.add(user)
    session.commit()
    yield user
    session.delete(user)
    session.commit()


@fixture(name="superuser_token")
def superuser_token_fixture(client: TestClient, superuser: User) -> str:
    response = client.post(
        "/user/token",
        data={
            "username": superuser.email,
            "password": PASSWORD,
            "scope": "users:self users:r users:rw users:all",
        },
    )
    return response.json().get("access_token")
