from typing import Generator

from pytest import fixture
from sqlalchemy.orm import Session

from src.managers.users import UserManager
from src.models.orm.user import User


@fixture(name="user")
def user_fixture(session: Session) -> Generator[User, None, None]:
    password_hash = UserManager(session).get_password_hash("testpass")
    user = User(
        name="Test",
        last_name="User",
        email="test@test.com",
        hashed_password=password_hash,
    )
    session.add(user)
    session.commit()
    yield user
