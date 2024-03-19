from base64 import b64encode

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from src.config.settings import Settings
from src.core.email import get_fast_mail
from src.models.orm.user import Role, User


def test_update_user_name(
    client: TestClient,
    user_member: User,
    user_member_token: str,
    role_user_member: Role,
):
    update_dict = {"name": "User Testing Fixture Name"}
    response = client.put(
        "/user/me",
        headers={"Authorization": f"Bearer {user_member_token}"},
        json=update_dict,
    )
    expected_response = {
        "name": "User Testing Fixture Name",
        "email": user_member.email,
        "roles": [
            {
                "name": role_user_member.name,
                "description": role_user_member.description,
                "module": role_user_member.module,
                "mode": role_user_member.mode,
            }
        ],
    }
    assert response.status_code == 200
    assert response.json() == expected_response


def test_delete_user(
    client: TestClient,
    session: Session,
    user_member: User,
    superuser_token: str,
):
    response = client.delete(
        f"/user/{user_member.id}",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    user_query = session.query(User).where(User.id == user_member.id).all()
    assert response.status_code == 204
    assert not len(user_query)


def test_delete_user_raising_404(client: TestClient, superuser_token: str):
    response = client.delete(
        "/user/1000",
        headers={"Authorization": f"Bearer {superuser_token}"},
    )
    assert response.status_code == 404
    assert response.json().get("detail") == "Couldn't find user."


def test_request_password_change(
    client: TestClient,
    settings: Settings,
    user_member: User,
):
    fast_mail = get_fast_mail()
    fast_mail.config.SUPPRESS_SEND = 1
    with fast_mail.record_messages() as outbox:
        email = str(user_member.email)
        email_encoded = b64encode(email.encode()).decode()
        response = client.put(
            "/user/me/forgot-password", json={"email": email_encoded}
        )
        assert response.status_code == 200
        assert (
            response.json().get("detail")
            == "Success! Link to change password sent to e-mail."
        )
        assert len(outbox) == 1
        assert (
            outbox[0]["from"]
            == f"{settings.MAIL_FROM_NAME} <{settings.MAIL_FROM}>"
        )
        assert outbox[0]["To"] == user_member.email


def test_resent_password_change_request_raises_error(
    client: TestClient,
    user_member: User,
):
    email = str(user_member.email)
    email_encoded = b64encode(email.encode()).decode()
    response = client.put(
        "/user/me/forgot-password", json={"email": email_encoded}
    )
    assert response.status_code == 400
    assert (
        response.json().get("detail")
        == "Password change already requested. Please check your e-mail."
    )


def test_request_password_change_with_wrong_email_raises_error(
    client: TestClient,
):
    wrong_email = "wrong_email@pytest.com"
    email_encoded = b64encode(wrong_email.encode()).decode()
    response = client.put(
        "/user/me/forgot-password", json={"email": email_encoded}
    )
    assert response.status_code == 500
    assert response.json().get("detail") == "Something is really wrong."


def test_request_password_change_with_non_base64_raises_error(
    client: TestClient,
):
    wrong_email = "this is not base64"
    response = client.put(
        "/user/me/forgot-password", json={"email": wrong_email}
    )
    assert response.status_code == 500
    assert response.json().get("detail") == "Something is really wrong!"
