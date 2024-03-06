from src.models.orm.user import User


def test_user_exists(user: User):
    assert user
