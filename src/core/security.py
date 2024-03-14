from contextlib import closing
from typing import Annotated

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from sqlalchemy.orm import Session
from src.core.dependencies import get_db, get_settings
from src.core.utils import (
    check_if_user_has_permissions,
    get_all_roles,
    get_credentials_exceptions,
    get_email_by_decoded_jwt,
    get_user_by_email,
    get_user_scopes,
    parse_scopes,
)
from src.models.pydantic.user import User


def get_oauth2_scopes() -> dict[str, str]:
    with closing(get_db()) as db:
        roles = get_all_roles(next(db, None))
        return parse_scopes(roles)


OAUTH2_SCOPES = get_oauth2_scopes()

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/user/token", scopes=OAUTH2_SCOPES
)


def get_current_user(
    security_scopes: SecurityScopes,
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Session = Depends(get_db),
) -> User:
    """
    Decodes the JWT and checks for the authenticated
    user that is performing the request. Also checks the permission scopes.
    """
    SETTINGS = get_settings()
    SECRET_KEY = SETTINGS.SECRET_KEY
    ALGORITHM = SETTINGS.ALGORITHM

    credentials_exception = get_credentials_exceptions(security_scopes)

    email = get_email_by_decoded_jwt(
        token=token,
        secret_key=SECRET_KEY,
        algorithm=ALGORITHM,
        credentials_exception=credentials_exception,
    )

    user = get_user_by_email(
        db=db, email=email, credentials_exception=credentials_exception
    )

    user_scopes = get_user_scopes(roles=user.roles)

    user_has_permissions = check_if_user_has_permissions(
        user_scopes=user_scopes, requested_scopes=security_scopes.scopes
    )

    if not user_has_permissions:
        forbidden_exception = get_credentials_exceptions(
            security_scopes, forbidden=True
        )
        raise forbidden_exception

    return user
