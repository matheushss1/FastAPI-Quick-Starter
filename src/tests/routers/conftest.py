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


@fixture(name="superuser_roles")
def superuser_roles_fixture(
    session: Session,
) -> List[Role]:
    roles = []
    for module in MODULES:
        for mode in MODES:
            role = Role(
                name=generate_role_name(mode),
                description=generate_role_description(module, mode),
                module=module,
                mode=mode,
            )
            session.add(role)
            roles.append(role)
    session.commit()
    return roles


@fixture(name="superuser")
def superuser_fixture(session: Session, superuser_roles: List[Role]) -> User:
    user_in_db = (
        session.query(User).where(User.email == "testuser@test.com").all()
    )
    if len(user_in_db):
        return user_in_db[0]
    password_hash = UserManager(session).get_password_hash(PASSWORD)
    user = User(
        name="Test User",
        email="testuser@test.com",
        hashed_password=password_hash,
    )
    for role in superuser_roles:
        user.roles.append(role)
    session.add(user)
    session.commit()
    return user


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
