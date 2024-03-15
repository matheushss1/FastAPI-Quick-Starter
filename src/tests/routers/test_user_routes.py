from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
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
