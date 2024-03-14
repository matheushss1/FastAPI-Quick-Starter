from typing import Generator

from pytest import fixture
from sqlalchemy.orm import Session
from src.managers.users import UserManager
from src.models.orm.user import Role, User


@fixture(name="member_users_role")
def member_users_role_fixture(session: Session) -> Role:
    role = Role(
        name="member",
        description="Read/Update self",
        module="users",
        mode="self",
    )
    session.add(role)
    session.commit()
    return role


@fixture(name="user")
def user_fixture(session: Session) -> Generator[User, None, None]:
    password_hash = UserManager(session).get_password_hash("testpass")
    user = User(
        name="Test",
        email="test@test.com",
        hashed_password=password_hash,
        role="member",
    )
    session.add(user)
    session.commit()
    yield user
    session.delete(user)
    session.commit()
