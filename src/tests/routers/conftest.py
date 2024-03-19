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


@fixture(name="role_user_member")
def role_user_member_fixture(session: Session) -> Role:
    role_in_db = (
        session.query(Role)
        .where(and_(Role.module == "users", Role.mode == "self"))
        .all()
    )
    if len(role_in_db):
        return role_in_db[0]
    role = Role(
        name=generate_role_name(mode="self"),
        description=generate_role_description(module="users", mode="self"),
        module="users",
        mode="self",
    )
    session.add(role)
    session.commit()
    return role


@fixture(name="role_user_manager")
def role_user_manager_fixture(session: Session) -> Role:
    manager_mode = "rw"
    role_in_db = (
        session.query(Role)
        .where(and_(Role.module == "users", Role.mode == manager_mode))
        .all()
    )
    if len(role_in_db):
        return role_in_db[0]
    role = Role(
        name=generate_role_name(mode=manager_mode),
        description=generate_role_description(
            module="users", mode=manager_mode
        ),
        module="users",
        mode=manager_mode,
    )
    session.add(role)
    session.commit()
    return role


@fixture(name="user_invited")
def user_invited_fixture(
    session: Session, role_user_member: Role
) -> Generator[UserInvited, None, None]:
    user_invited = UserInvited(
        name="User Invited Fixture",
        email="user_invited@fixtures.com",
        invitation_link="https://fixtures.com",
        invitation_expires=datetime.now() + timedelta(days=1),
    )
    user_invited.roles.append(role_user_member)
    session.add(user_invited)
    session.commit()
    return user_invited


@fixture(name="user_member")
def user_member_fixture(session: Session, role_user_member: Role) -> User:
    user_in_db = (
        session.query(User)
        .where(User.email == "user_testing@fixture.com")
        .all()
    )
    if len(user_in_db):
        return user_in_db[0]
    password_hash = UserManager(session).get_password_hash(PASSWORD)
    user = User(
        name="User Testing Fixture",
        email="user_testing@fixture.com",
        hashed_password=password_hash,
    )
    user.roles.append(role_user_member)
    session.add(user)
    session.commit()
    return user


@fixture(name="user_member_token")
def user_member_token_fixture(client: TestClient, user_member: User) -> str:
    response = client.post(
        "/user/token",
        data={
            "username": user_member.email,
            "password": PASSWORD,
            "scope": "users:self",
        },
    )
    return response.json().get("access_token")
