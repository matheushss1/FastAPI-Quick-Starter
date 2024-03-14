from fastapi import status
from fastapi.testclient import TestClient
from src.config.settings import Settings
from src.core.email import get_fast_mail
from src.models.orm.user import Role


def test_create_user_directly(
    client: TestClient, superuser_token: str, role_user_member: Role
):
    user_info = {
        "name": "test",
        "email": "test_creating@test.com",
        "password": "testpass",
        "roles_ids": [role_user_member.id],
    }

    response = client.post(
        "/user/signup",
        json=user_info,
        headers={"Authorization": f"Bearer {superuser_token}"},
    )

    expected_response = {
        "name": "test",
        "email": "test_creating@test.com",
        "roles": [
            {
                "name": role_user_member.name,
                "description": role_user_member.description,
                "module": role_user_member.module,
                "mode": role_user_member.mode,
            }
        ],
    }
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json() == expected_response


def test_create_user_directly_fails_without_token(client: TestClient):
    user_info = {
        "name": "test",
        "email": "test_creating@test.com",
        "password": "testpass",
    }

    response = client.post(
        "/user/signup",
        json=user_info,
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_create_user_directly_fails_with_string_not_token(client: TestClient):
    user_info = {
        "name": "test",
        "email": "test_creating@test.com",
        "password": "testpass",
    }

    response = client.post(
        "/user/signup",
        json=user_info,
        headers={"Authorization": "Bearer NotAToken"},
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_create_user_directly_fails_not_enough_permissions(client: TestClient):
    user_credentials = {
        "username": "test_creating@test.com",
        "password": "testpass",
    }
    token_response = client.post("/user/token", data=user_credentials)
    token = token_response.json().get("access_token")
    user_info = {
        "name": "test",
        "email": "test_should_fail@test.com",
        "password": "testpass",
    }

    response = client.post(
        "/user/signup",
        json=user_info,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json().get("detail") == "Not enough permissions"


USER_INVITED_INFO = {
    "name": "test",
    "email": "user-invited@email.com",
}


def test_invite_user(
    client: TestClient,
    settings: Settings,
    superuser_token: str,
    role_user_member: Role,
):
    user_to_be_invited = USER_INVITED_INFO.copy()
    user_to_be_invited["roles_ids"] = [role_user_member.id]
    fast_mail = get_fast_mail()
    fast_mail.config.SUPPRESS_SEND = 1
    with fast_mail.record_messages() as outbox:
        response = client.post(
            "/user/invite",
            json=user_to_be_invited,
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
        assert response.status_code == 200
        assert len(outbox) == 1
        assert (
            outbox[0]["from"]
            == f"{settings.MAIL_FROM_NAME} <{settings.MAIL_FROM}>"
        )
        assert outbox[0]["To"] == user_to_be_invited["email"]


def test_invite_already_invited_user(
    client: TestClient, superuser_token: str, role_user_member: Role
):
    user_to_be_invited = USER_INVITED_INFO.copy()
    user_to_be_invited["roles_ids"] = [role_user_member.id]
    fast_mail = get_fast_mail()
    fast_mail.config.SUPPRESS_SEND = 1
    with fast_mail.record_messages() as _:
        response = client.post(
            "/user/invite",
            json=user_to_be_invited,
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
        assert response.status_code == 400
        assert response.json().get("detail") == "E-mail already registered"


def test_confirm_user_invitation(client: TestClient, role_user_member: Role):
    user_credentials = {
        "email": USER_INVITED_INFO.get("email"),
        "password": "testpass",
    }
    response = client.post("/user/confirm-invitation", json=user_credentials)
    assert response.status_code == 200
    user_with_roles = USER_INVITED_INFO.copy()
    user_role = {
        "name": role_user_member.name,
        "description": role_user_member.description,
        "module": role_user_member.module,
        "mode": role_user_member.mode,
    }
    user_with_roles["roles"] = [user_role]
    assert response.json() == user_with_roles


def test_get_auth_token(client: TestClient):
    user_credentials = {
        "username": USER_INVITED_INFO.get("email"),
        "password": "testpass",
    }
    response = client.post("/user/token", data=user_credentials)
    assert response.status_code == 200
    assert "access_token" and "token_type" in response.json()


def test_get_auth_token_with_wrong_credentials(client: TestClient):
    user_credentials = {
        "username": USER_INVITED_INFO.get("email"),
        "password": "wrongpass",
    }
    response = client.post("/user/token", data=user_credentials)
    assert response.status_code == 400


def test_get_logged_user(client: TestClient):
    user_credentials = {
        "username": USER_INVITED_INFO.get("email"),
        "password": "testpass",
    }
    token_response = client.post("/user/token", data=user_credentials)
    token = token_response.json().get("access_token")
    response = client.get(
        "/user/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    user_with_scopes = USER_INVITED_INFO.copy()
    user_with_scopes.update({"role": "member"})
    assert response.json() == user_with_scopes
